//! The Aegis kernel model: the only code that may touch capability state.
//!
//! Everything outside this module (roles, agents, the shell) executes *against* the
//! kernel through the operations here and holds no private access to kernel state.
//! Rust's module privacy is the isolation boundary of the model (spec §5.1).
//!
//! The authority model is the CSpace model: a task names capabilities by index into its
//! own table; the kernel resolves the index against the *caller's* table only. Nothing
//! a task says (indices, labels, raw bytes) can name a capability it does not hold.
//!
//! Task identity is carried by an opaque `TaskHandle` that only the kernel can create,
//! so identity cannot be forged at the type level; the kernel additionally verifies the
//! handle resolves to a live task on every operation.

use crate::audit::{AuditLog, AuditRecord, OpKind};
use crate::cspace::{CapHandle, CapInstance, CSpace};
use crate::error::{KernelError, KernelResult};
use crate::objects::{
    CapId, CreatorObj, EndpointObj, GrantRootObj, MemRegionObj, Message, Object, ObjectId,
    ObjectKind, TaskObj,
};
use crate::rights::Rights;
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Opaque identity of an execution context. Only the kernel can fabricate one; a task
/// cannot name another task's identity any more than it can name another task's caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskHandle(ObjectId);

impl TaskHandle {
    /// The underlying object id — readable, not constructible (for audit queries).
    /// An id alone grants nothing: authority requires a live slot in your CSpace.
    pub fn id(self) -> ObjectId {
        self.0
    }
}

/// A snapshot of what a task can currently reach. Feeds the reachable-authority auditor
/// (design doc §10 [CLOSED] TCB-creep fix) and the grant verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedCap {
    pub slot: u32,
    pub kind: ObjectKind,
    pub rights: Rights,
    pub expires_at: Option<u64>,
}

/// One granted capability within an active grant; used by the grants layer to record
/// what the agent is actually allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapInfo {
    pub slot: u32,
    pub kind: ObjectKind,
    pub rights: Rights,
    /// Object identity of what the cap names — the stable, queryable audit key
    /// (design doc §9.4); the grants layer logs it so a grant is traceable to the
    /// exact object it authorized.
    pub obj: ObjectId,
}

/// A raw, read-only projection of one cap in a task's CSpace, keeping *object identity*
/// — the reachable-authority auditor needs to know which task a naming cap refers to
/// for the delegation closure (design doc §10 [CLOSED] TCB-creep fix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapView {
    pub obj: ObjectId,
    pub kind: ObjectKind,
    pub rights: Rights,
    pub expires_at: Option<u64>,
}

pub struct Kernel {
    now: u64,
    next_obj: u64,
    next_cap: u64,
    objects: HashMap<ObjectId, Object>,
    cspaces: HashMap<ObjectId, CSpace>,
    /// CapId -> the capability this one was derived from (derivation graph roots).
    parents: HashMap<CapId, Option<CapId>>,
    /// (task, slot) -> CapId, the reverse index for finding a cap's derivation id.
    capids: HashMap<(ObjectId, u32), CapId>,
    /// CapId -> where this capability instance physically lives.
    locations: HashMap<CapId, (ObjectId, u32)>,
    audit: AuditLog,
}

impl Default for Kernel {
    fn default() -> Self {
        Self::new()
    }
}

impl Kernel {
    /// Fresh kernel. The seed makes object ids unguessable across processes — a
    /// robustness nicety, not the security basis (spec §5.3).
    pub fn new() -> Kernel {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Kernel {
            now: 0,
            next_obj: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15),
            next_cap: seed ^ 0xDEAD_BEEF_CAFE_F00D,
            objects: HashMap::new(),
            cspaces: HashMap::new(),
            parents: HashMap::new(),
            capids: HashMap::new(),
            locations: HashMap::new(),
            audit: AuditLog::default(),
        }
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    /// Advance the kernel clock. The only authority-killing influence on a cap that
    /// never requires a capability: time (spec I5).
    pub fn advance(&mut self, ticks: u64) {
        self.now += ticks;
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    // ------------------------------------------------------------------ internals

    fn fresh_obj(&mut self) -> ObjectId {
        self.next_obj = self.next_obj.wrapping_add(0x9E37_79B9_7F4A_7C15);
        ObjectId::from_raw(self.next_obj)
    }

    fn fresh_cap(&mut self) -> CapId {
        self.next_cap = self.next_cap.wrapping_add(0x2545_F491_4F6C_DD1D);
        CapId::from_raw(self.next_cap)
    }

    fn ensure_task(&self, t: &TaskHandle) -> KernelResult<()> {
        match self.objects.get(&t.0) {
            Some(Object::Task(_)) => Ok(()),
            _ => Err(KernelError::NoSuchObject),
        }
    }

    /// Resolve `handle` against `caller`'s own CSpace, checking liveness and expiry.
    fn lookup(&self, caller: ObjectId, handle: CapHandle) -> KernelResult<(u32, CapInstance)> {
        let cspace = self.cspaces.get(&caller).ok_or(KernelError::NoSuchObject)?;
        let cap = cspace
            .get(handle.0)
            .ok_or(KernelError::NoCap)?
            .to_owned();
        if let Some(deadline) = cap.expires_at {
            if self.now > deadline {
                return Err(KernelError::CapExpired);
            }
        }
        Ok((handle.0, cap))
    }

    fn require_right(&self, cap: CapInstance, need: Rights) -> KernelResult<()> {
        if cap.rights.contains(need) {
            Ok(())
        } else {
            Err(KernelError::InsufficientRights(need))
        }
    }

    fn require_kind(&self, cap: CapInstance, kind: ObjectKind) -> KernelResult<()> {
        match self.objects.get(&cap.obj).map(Object::kind) {
            Some(a) if a == kind => Ok(()),
            _ => Err(KernelError::WrongObjectType),
        }
    }

    /// The definitive expiration rule (I5): a minted cap can die no later than its
    /// parent. `None` is +∞; the result is the minimum.
    fn clamp_expiry(requested: Option<u64>, parent: Option<u64>) -> Option<u64> {
        match (requested, parent) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    fn capid_of(&self, owner: ObjectId, slot: u32) -> Option<CapId> {
        self.capids.get(&(owner, slot)).copied()
    }

    /// Insert a capability instance into `dst`'s CSpace and record derivation metadata.
    /// `parent_exp` is the *authorizing* cap's expiry (the source for ordinary grants,
    /// the grant root for grant-mints — in both cases the one that limits this cap: I5).
    fn mint_into(
        &mut self,
        dst: ObjectId,
        obj: ObjectId,
        rights: Rights,
        parent_cid: Option<CapId>,
        parent_exp: Option<u64>,
        requested_expiry: Option<u64>,
    ) -> KernelResult<u32> {
        let expires = Self::clamp_expiry(requested_expiry, parent_exp);
        let cspace = self
            .cspaces
            .get_mut(&dst)
            .ok_or(KernelError::NoSuchObject)?;
        let slot = cspace
            .insert(CapInstance {
                obj,
                rights,
                parent: parent_cid,
                expires_at: expires,
            })
            .map_err(|_| KernelError::CspaceFull)?;
        let cid = self.fresh_cap();
        self.parents.insert(cid, parent_cid);
        self.capids.insert((dst, slot), cid);
        self.locations.insert(cid, (dst, slot));
        Ok(slot)
    }

    /// Remove the capability instance `cid` from wherever it lives (all bookkeeping).
    /// Leaves the object in place; a cap-less object is garbage the model never
    /// resurrects, which is harmless and honest (no dangling cap can ever survive a
    /// removal because caps are only reachable through slots).
    fn remove_cap(&mut self, cid: CapId) {
        if let Some((task, slot)) = self.locations.remove(&cid) {
            if let Some(cspace) = self.cspaces.get_mut(&task) {
                cspace.take(slot);
            }
            self.capids.remove(&(task, slot));
        }
        self.parents.remove(&cid);
    }

    fn audit_op(
        &mut self,
        caller: ObjectId,
        op: OpKind,
        authorizing_cap: Option<CapInstance>,
        ok: bool,
        detail: impl Into<String>,
    ) {
        let (target, kind) = match authorizing_cap {
            Some(c) => {
                let kind = self
                    .objects
                    .get(&c.obj)
                    .map(Object::kind)
                    .unwrap_or(ObjectKind::Task);
                (Some(c.obj), Some(kind))
            }
            None => (None, None),
        };
        self.audit.append(AuditRecord::new(
            self.now,
            caller,
            op,
            target,
            kind,
            authorizing_cap.map(|c| c.rights).unwrap_or(Rights::NONE),
            ok,
            detail,
        ));
    }

    /// Wrap an operation so that *failures* are recorded too (spec §2: every
    /// successful and every failed operation appends one line to G). Successes keep
    /// their rich per-op records; failures record the error, which is all there is.
    /// A failed op is guaranteed to leave no state behind in the model: every error
    /// path returns before any mutation, by construction of the op bodies.
    fn guarded<T>(
        &mut self,
        caller: ObjectId,
        op: OpKind,
        body: impl FnOnce(&mut Self) -> KernelResult<T>,
    ) -> KernelResult<T> {
        let before_ok = self.audit.len();
        let res = body(self);
        if let Err(e) = &res {
            if self.audit.len() == before_ok {
                self.audit_op(caller, op, None, false, format!("{e}"));
            }
        }
        res
    }

    // ------------------------------------------------------------- boot & creation

    /// Check that `creator` (in the caller's own CSpace) is a Creator cap.
    fn require_creator(&self, caller: ObjectId, creator: CapHandle) -> KernelResult<()> {
        let (_, cap) = self.lookup(caller, creator)?;
        match self.objects.get(&cap.obj).map(Object::kind) {
            Some(ObjectKind::Creator) => Ok(()),
            _ => Err(KernelError::NoCreationRight),
        }
    }

    /// Boot the root task (the session/orchestrator). The root task is where all
    /// authority in the system begins; everything any other task holds is a derived
    /// narrowing of something the root chain granted (I1). The root alone holds the
    /// initial Creator cap; it may delegate narrower copies of it, and only those can
    /// create new kernel objects.
    pub fn boot(&mut self, label: &str) -> KernelResult<(TaskHandle, CapHandle, CapHandle)> {
        let id = self.fresh_obj();
        self.cspaces.insert(id, CSpace::new());
        self.objects.insert(
            id,
            Object::Task(TaskObj {
                label: label.to_string(),
                running: true,
            }),
        );
        let self_slot = self.mint_into(id, id, Rights::ALL, None, None, None)?;
        // The Creator is a distinct object; ids never collide (a HashMap keyed by id
        // must have exactly one object per id — this is the invariant the demo caught).
        let creator_id = self.fresh_obj();
        self.objects.insert(creator_id, Object::Creator(CreatorObj));
        let creator_slot = self.mint_into(id, creator_id, Rights::ALL, None, None, None)?;
        let handle = TaskHandle(id);
        let self_cap = CapHandle(self_slot);
        let creator_cap = CapHandle(creator_slot);
        self.audit_op(id, OpKind::CreateTask, None, true, "boot root task");
        Ok((handle, self_cap, creator_cap))
    }

    /// Create a task (execution context) in a stopped state. The caller receives a cap
    /// with every right on it; from that cap all narrower caps derive (I2). The child's
    /// self-cap is derived from the creator's cap, so the creator can always revoke
    /// back everything the child ever touches. Creation requires a Creator cap.
    pub fn create_task(
        &mut self,
        caller: TaskHandle,
        creator: CapHandle,
        label: &str,
    ) -> KernelResult<(TaskHandle, CapHandle)> {
        self.guarded(caller.0, OpKind::CreateTask, |k| {
            k.ensure_task(&caller)?;
            k.require_creator(caller.0, creator)?;
            let id = k.fresh_obj();
            k.cspaces.insert(id, CSpace::new());
            k.objects.insert(
                id,
                Object::Task(TaskObj {
                    label: label.to_string(),
                    running: false,
                }),
            );
            // Creator's cap: a fresh root (no parent) with ALL rights.
            let creator_slot = k.mint_into(caller.0, id, Rights::ALL, None, None, None)?;
            // Child's self-cap: derived from the creator's cap.
            let child_cid = k.capid_of(caller.0, creator_slot).unwrap();
            let _ = k.mint_into(id, id, Rights::ALL, Some(child_cid), None, None)?;
            k.audit_op(caller.0, OpKind::CreateTask, None, true, label.to_string());
            Ok((TaskHandle(id), CapHandle(creator_slot)))
        })
    }

    /// Create an endpoint (mailbox). Creator cap carries SEND/RECV/GRANT.
    pub fn create_endpoint(
        &mut self,
        caller: TaskHandle,
        creator: CapHandle,
    ) -> KernelResult<CapHandle> {
        self.guarded(caller.0, OpKind::CreateEndpoint, |k| {
            k.ensure_task(&caller)?;
            k.require_creator(caller.0, creator)?;
            let id = k.fresh_obj();
            k.objects.insert(id, Object::Endpoint(EndpointObj {
                queue: VecDeque::new(),
            }));
            let rights = Rights::SEND.union(Rights::RECV).union(Rights::GRANT);
            let slot = k.mint_into(caller.0, id, rights, None, None, None)?;
            k.audit_op(caller.0, OpKind::CreateEndpoint, None, true, "created");
            Ok(CapHandle(slot))
        })
    }

    /// Create a memory region. Creator cap carries READ/WRITE/GRANT.
    pub fn create_mem(
        &mut self,
        caller: TaskHandle,
        creator: CapHandle,
        initial: Vec<u8>,
    ) -> KernelResult<CapHandle> {
        self.guarded(caller.0, OpKind::CreateMemRegion, |k| {
            k.ensure_task(&caller)?;
            k.require_creator(caller.0, creator)?;
            let id = k.fresh_obj();
            k.objects.insert(id, Object::MemRegion(MemRegionObj {
                data: initial,
            }));
            let rights = Rights::READ.union(Rights::WRITE).union(Rights::GRANT);
            let slot = k.mint_into(caller.0, id, rights, None, None, None)?;
            k.audit_op(caller.0, OpKind::CreateMemRegion, None, true, "created");
            Ok(CapHandle(slot))
        })
    }

    /// Create a grant root — the anchor of one grant. The creator's cap carries only
    /// GRANT: revoking it removes every cap minted under the grant, from every CSpace.
    pub fn create_grant_root(
        &mut self,
        caller: TaskHandle,
        creator: CapHandle,
    ) -> KernelResult<CapHandle> {
        self.guarded(caller.0, OpKind::CreateGrantRoot, |k| {
            k.ensure_task(&caller)?;
            k.require_creator(caller.0, creator)?;
            let id = k.fresh_obj();
            k.objects.insert(id, Object::GrantRoot(GrantRootObj));
            let slot = k.mint_into(caller.0, id, Rights::GRANT, None, None, None)?;
            k.audit_op(caller.0, OpKind::CreateGrantRoot, None, true, "created");
            Ok(CapHandle(slot))
        })
    }

    // ------------------------------------------------------------- derivation ops

    /// Copy: place a narrowed copy of one of the caller's caps into the caller's own
    /// CSpace. Requires GRANT on the source — you may only copy what you may grant away.
    /// Rights are clamped to the source's rights (I2); expiry is inherited (I5).
    pub fn copy(
        &mut self,
        caller: TaskHandle,
        source: CapHandle,
        rights: Rights,
    ) -> KernelResult<CapHandle> {
        self.guarded(caller.0, OpKind::Copy, |k| {
            k.ensure_task(&caller)?;
            let (slot, src) = k.lookup(caller.0, source)?;
            k.require_right(src, Rights::GRANT)?;
            let narrowed = rights.intersect(src.rights);
            let src_exp = src.expires_at;
            let src_cid = k.capid_of(caller.0, slot).unwrap();
            let new_slot =
                k.mint_into(caller.0, src.obj, narrowed, Some(src_cid), src_exp, None)?;
            k.audit_op(
                caller.0,
                OpKind::Copy,
                Some(src),
                true,
                format!("narrowed to {narrowed}"),
            );
            Ok(CapHandle(new_slot))
        })
    }

    /// Grant: mint a narrowed, possibly short-lived copy of one of the caller's caps
    /// into another task's CSpace. The target task is named by a Task capability the
    /// caller holds in its own CSpace (no one can name a task's table without holding a
    /// cap to that task). Requires GRANT on the source (I2), and requires the naming
    /// cap to carry RECEIVE (I6): pushing caps into a task's CSpace needs that task's
    /// consent as encoded in the cap — a bare naming reference is not a mailbox.
    pub fn grant(
        &mut self,
        caller: TaskHandle,
        source: CapHandle,
        into_task: CapHandle,
        rights: Rights,
        requested_expiry: Option<u64>,
    ) -> KernelResult<()> {
        self.guarded(caller.0, OpKind::Grant, |k| {
            k.ensure_task(&caller)?;
            let (src_slot, src) = k.lookup(caller.0, source)?;
            k.require_right(src, Rights::GRANT)?;
            let (_, task_cap) = k.lookup(caller.0, into_task)?;
            k.require_kind(task_cap, ObjectKind::Task)?;
            k.require_right(task_cap, Rights::RECEIVE)?;
            let narrowed = rights.intersect(src.rights);
            let src_exp = src.expires_at;
            let src_cid = k.capid_of(caller.0, src_slot).unwrap();
            k.mint_into(
                task_cap.obj,
                src.obj,
                narrowed,
                Some(src_cid),
                src_exp,
                requested_expiry,
            )?;
            k.audit_op(
                caller.0,
                OpKind::Grant,
                Some(src),
                true,
                format!("to task slot at cap {into_task:?} rights {narrowed}"),
            );
            Ok(())
        })
    }

    /// Grant-mint: like `grant`, but the new cap is derived from `grant_root` rather
    /// than from `source` — revoking the grant root removes every cap minted under the
    /// grant from every CSpace, while the grantor's own caps survive (spec §4, I4).
    /// Rights are still clamped by the source cap (I2); expiry is clamped by the
    /// source's remaining life (I5). This is the grant-service op, not a general tool.
    /// Also requires RECEIVE on the naming cap (I6), like `grant`.
    pub fn grant_mint(
        &mut self,
        caller: TaskHandle,
        grant_root: CapHandle,
        source: CapHandle,
        into_task: CapHandle,
        rights: Rights,
        requested_expiry: Option<u64>,
    ) -> KernelResult<CapHandle> {
        self.guarded(caller.0, OpKind::Grant, |k| {
            k.ensure_task(&caller)?;
            let (root_slot, root_cap) = k.lookup(caller.0, grant_root)?;
            k.require_kind(root_cap, ObjectKind::GrantRoot)?;
            k.require_right(root_cap, Rights::GRANT)?;
            let (_, src) = k.lookup(caller.0, source)?;
            k.require_right(src, Rights::GRANT)?;
            let (_, task_cap) = k.lookup(caller.0, into_task)?;
            k.require_kind(task_cap, ObjectKind::Task)?;
            k.require_right(task_cap, Rights::RECEIVE)?;
            let narrowed = rights.intersect(src.rights);
            let root_cid = k.capid_of(caller.0, root_slot).unwrap();
            // Expiry: clamp by the *source*'s life; derivation parent is the grant root.
            let src_exp = src.expires_at;
            let slot = k.mint_into(
                task_cap.obj,
                src.obj,
                narrowed,
                Some(root_cid),
                src_exp,
                requested_expiry,
            )?;
            k.audit_op(
                caller.0,
                OpKind::Grant,
                Some(src),
                true,
                format!("minted under grant root into task slot, rights {narrowed}"),
            );
            Ok(CapHandle(slot))
        })
    }

    /// Destroy: remove one of the caller's own caps (this instance only).
    pub fn destroy(&mut self, caller: TaskHandle, cap: CapHandle) -> KernelResult<()> {
        self.guarded(caller.0, OpKind::Destroy, |k| {
            k.ensure_task(&caller)?;
            let (_, inst) = k.lookup(caller.0, cap)?;
            if let Some(cid) = k.capid_of(caller.0, cap.0) {
                k.remove_cap(cid);
            }
            k.audit_op(caller.0, OpKind::Destroy, Some(inst), true, "destroyed");
            Ok(())
        })
    }

    /// Revoke: requires GRANT on the source cap. Removes the source instance *and every
    /// descendant* from every CSpace — including CSpace the caller cannot name (I4).
    /// This is the "grantor takes back everything it granted, everywhere" operation.
    pub fn revoke(&mut self, caller: TaskHandle, cap: CapHandle) -> KernelResult<()> {
        self.guarded(caller.0, OpKind::Revoke, |k| {
            k.ensure_task(&caller)?;
            let (_, inst) = k.lookup(caller.0, cap)?;
            k.require_right(inst, Rights::GRANT)?;
            let root = k.capid_of(caller.0, cap.0).unwrap();
            let mut doomed: Vec<CapId> = Vec::new();
            let mut stack = vec![root];
            while let Some(cid) = stack.pop() {
                doomed.push(cid);
                for (desc, par) in k.parents.iter() {
                    if *par == Some(cid) && !doomed.contains(desc) {
                        stack.push(*desc);
                    }
                }
            }
            for cid in doomed {
                k.remove_cap(cid);
            }
            k.audit_op(
                caller.0,
                OpKind::Revoke,
                Some(inst),
                true,
                "revoked derivation subtree",
            );
            Ok(())
        })
    }

    // ---------------------------------------------------------------- IPC (endpoints)

    /// Send a message on an endpoint. Requires SEND on the cap.
    pub fn ep_send(
        &mut self,
        caller: TaskHandle,
        ep: CapHandle,
        msg: Message,
    ) -> KernelResult<()> {
        self.guarded(caller.0, OpKind::Send, |k| {
            k.ensure_task(&caller)?;
            let (_, cap) = k.lookup(caller.0, ep)?;
            k.require_right(cap, Rights::SEND)?;
            k.require_kind(cap, ObjectKind::Endpoint)?;
            k.objects
                .get_mut(&cap.obj)
                .and_then(|o| match o {
                    Object::Endpoint(e) => Some(e),
                    _ => None,
                })
                .ok_or(KernelError::WrongObjectType)?
                .queue
                .push_back(msg);
            k.audit_op(caller.0, OpKind::Send, Some(cap), true, "message queued");
            Ok(())
        })
    }

    /// Receive one message, or None. Requires RECV on the cap. Non-blocking: scheduling
    /// is a userspace concern in Aegis, so blocking happens in the harness, not here.
    pub fn ep_recv(
        &mut self,
        caller: TaskHandle,
        ep: CapHandle,
    ) -> KernelResult<Option<Message>> {
        self.guarded(caller.0, OpKind::Recv, |k| {
            k.ensure_task(&caller)?;
            let (_, cap) = k.lookup(caller.0, ep)?;
            k.require_right(cap, Rights::RECV)?;
            k.require_kind(cap, ObjectKind::Endpoint)?;
            let msg = k
                .objects
                .get_mut(&cap.obj)
                .and_then(|o| match o {
                    Object::Endpoint(e) => Some(e),
                    _ => None,
                })
                .ok_or(KernelError::WrongObjectType)?
                .queue
                .pop_front();
            k.audit_op(
                caller.0,
                OpKind::Recv,
                Some(cap),
                true,
                if msg.is_some() {
                    "message received"
                } else {
                    "empty queue"
                },
            );
            Ok(msg)
        })
    }

    // --------------------------------------------------------------- memory regions

    /// Read `range` bytes from a region. Requires READ on the cap.
    pub fn mem_read(
        &mut self,
        caller: TaskHandle,
        mem: CapHandle,
        offset: usize,
        len: usize,
    ) -> KernelResult<Vec<u8>> {
        self.guarded(caller.0, OpKind::MemRead, |k| {
            k.ensure_task(&caller)?;
            let (_, cap) = k.lookup(caller.0, mem)?;
            k.require_right(cap, Rights::READ)?;
            match k.objects.get(&cap.obj) {
                Some(Object::MemRegion(r)) => {
                    let end = offset.checked_add(len).ok_or(KernelError::InvalidOperation)?;
                    r.data
                        .get(offset..end)
                        .ok_or(KernelError::InvalidOperation)
                        .map(|s| s.to_vec())
                }
                _ => Err(KernelError::WrongObjectType),
            }
        })
    }

    /// Write `bytes` at `offset` in a region. Requires WRITE on the cap.
    pub fn mem_write(
        &mut self,
        caller: TaskHandle,
        mem: CapHandle,
        offset: usize,
        bytes: Vec<u8>,
    ) -> KernelResult<()> {
        self.guarded(caller.0, OpKind::MemWrite, |k| {
            k.ensure_task(&caller)?;
            let (_, cap) = k.lookup(caller.0, mem)?;
            k.require_right(cap, Rights::WRITE)?;
            match k.objects.get_mut(&cap.obj) {
                Some(Object::MemRegion(r)) => {
                    let end = offset.checked_add(bytes.len()).ok_or(KernelError::InvalidOperation)?;
                    if end > r.data.len() {
                        return Err(KernelError::InvalidOperation);
                    }
                    r.data[offset..end].copy_from_slice(&bytes);
                    k.audit_op(
                        caller.0,
                        OpKind::MemWrite,
                        Some(cap),
                        true,
                        format!("{} bytes at {offset}", bytes.len()),
                    );
                    Ok(())
                }
                _ => Err(KernelError::WrongObjectType),
            }
        })
    }

    /// Length of a region. Requires READ on the cap.
    pub fn mem_len(&mut self, caller: TaskHandle, mem: CapHandle) -> KernelResult<usize> {
        self.guarded(caller.0, OpKind::MemRead, |k| {
            k.ensure_task(&caller)?;
            let (_, cap) = k.lookup(caller.0, mem)?;
            k.require_right(cap, Rights::READ)?;
            match k.objects.get(&cap.obj) {
                Some(Object::MemRegion(r)) => Ok(r.data.len()),
                _ => Err(KernelError::WrongObjectType),
            }
        })
    }

    // ------------------------------------------------------------- task lifecycle

    /// Observe a task's running state. Requires READ on the task capability.
    pub fn task_running(&mut self, caller: TaskHandle, task: CapHandle) -> KernelResult<bool> {
        self.guarded(caller.0, OpKind::TaskState, |k| {
            k.ensure_task(&caller)?;
            let (_, cap) = k.lookup(caller.0, task)?;
            k.require_right(cap, Rights::READ)?;
            match k.objects.get(&cap.obj) {
                Some(Object::Task(t)) => Ok(t.running),
                _ => Err(KernelError::WrongObjectType),
            }
        })
    }

    /// Stop a task. Requires CONTROL on the task capability.
    pub fn task_kill(&mut self, caller: TaskHandle, task: CapHandle) -> KernelResult<()> {
        self.guarded(caller.0, OpKind::TaskKill, |k| {
            k.ensure_task(&caller)?;
            let (_, cap) = k.lookup(caller.0, task)?;
            k.require_right(cap, Rights::CONTROL)?;
            let label = match k.objects.get_mut(&cap.obj) {
                Some(Object::Task(t)) => {
                    t.running = false;
                    t.label.clone()
                }
                _ => return Err(KernelError::WrongObjectType),
            };
            k.audit_op(caller.0, OpKind::TaskKill, Some(cap), true, format!("killed {label}"));
            Ok(())
        })
    }

    /// Start a task. Requires CONTROL on the task capability.
    pub fn task_spawn(&mut self, caller: TaskHandle, task: CapHandle) -> KernelResult<()> {
        self.guarded(caller.0, OpKind::TaskSpawn, |k| {
            k.ensure_task(&caller)?;
            let (_, cap) = k.lookup(caller.0, task)?;
            k.require_right(cap, Rights::CONTROL)?;
            let label = match k.objects.get_mut(&cap.obj) {
                Some(Object::Task(t)) => {
                    t.running = true;
                    t.label.clone()
                }
                _ => return Err(KernelError::WrongObjectType),
            };
            k.audit_op(caller.0, OpKind::TaskSpawn, Some(cap), true, format!("spawned {label}"));
            Ok(())
        })
    }

    // ------------------------------------------------------------- introspection

    /// The live authority of a task: every cap that currently passes lookup, sorted by
    /// slot. This is the input to the reachable-authority auditor: assert it equals the
    /// manifest and the build fails if it ever grows.
    pub fn authorized(&self, caller: TaskHandle) -> Vec<AuthorizedCap> {
        let mut out = Vec::new();
        if let Some(cspace) = self.cspaces.get(&caller.0) {
            for (slot, cap) in cspace.iter() {
                if cap.expires_at.map(|e| self.now > e).unwrap_or(false) {
                    continue;
                }
                let kind = self
                    .objects
                    .get(&cap.obj)
                    .map(Object::kind)
                    .unwrap_or(ObjectKind::Task);
                out.push(AuthorizedCap {
                    slot,
                    kind,
                    rights: cap.rights,
                    expires_at: cap.expires_at,
                });
            }
        }
        out.sort_by_key(|c| c.slot);
        out
    }

    /// The kind of object a cap in the caller's CSpace names (for grant bookkeeping).
    pub fn cap_info(&self, caller: TaskHandle, cap: CapHandle) -> KernelResult<CapInfo> {
        self.ensure_task(&caller)?;
        let (slot, inst) = self.lookup(caller.0, cap)?;
        let kind = self
            .objects
            .get(&inst.obj)
            .map(Object::kind)
            .ok_or(KernelError::NoSuchObject)?;
        Ok(CapInfo {
            slot,
            kind,
            rights: inst.rights,
            obj: inst.obj,
        })
    }

    /// Raw read-only projection of every live cap a task holds, including object
    /// identity (unlike [`Kernel::authorized`], which drops it). Same liveness rules
    /// as a lookup: expired caps are not shown. Feeds the reachable-authority auditor.
    pub fn caps_of(&self, caller: TaskHandle) -> Vec<CapView> {
        let mut out = Vec::new();
        if let Some(cspace) = self.cspaces.get(&caller.0) {
            for (_, cap) in cspace.iter() {
                if cap.expires_at.map(|e| self.now > e).unwrap_or(false) {
                    continue;
                }
                out.push(CapView {
                    obj: cap.obj,
                    kind: self
                        .objects
                        .get(&cap.obj)
                        .map(Object::kind)
                        .unwrap_or(ObjectKind::Task),
                    rights: cap.rights,
                    expires_at: cap.expires_at,
                });
            }
        }
        out.sort_by_key(|c| (c.kind, c.rights));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot_system() -> (Kernel, TaskHandle, CapHandle, CapHandle) {
        let mut k = Kernel::new();
        let (root, selfcap, creator) = k.boot("root").unwrap();
        (k, root, selfcap, creator)
    }

    #[test]
    fn boot_creates_root_with_full_self_authority() {
        let (k, root, _, _) = boot_system();
        let caps = k.authorized(root);
        assert_eq!(caps.len(), 2);
        assert!(caps.iter().all(|c| c.rights == Rights::ALL));
        // one self cap, one creator cap
        let kinds: Vec<_> = caps.iter().map(|c| c.kind).collect();
        assert!(kinds.contains(&ObjectKind::Creator));
        assert_eq!(caps.iter().filter(|c| c.kind == ObjectKind::Task).count(), 1);
    }

    #[test]
    fn child_self_cap_is_derived_from_creator_cap() {
        let (mut k, root, _, creator) = boot_system();
        let (child, _) = k.create_task(root, creator, "child").unwrap();
        // child's single cap is its self cap, rights ALL.
        let caps = k.authorized(child);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].rights, Rights::ALL);
    }

    #[test]
    fn creation_requires_a_creator_cap() {
        let (mut k, root, _selfcap, creator) = boot_system();
        let (plain, _) = k.create_task(root, creator, "plain").unwrap();
        // root still holds a creator cap and can create…
        let _ = k.create_task(root, creator, "another").unwrap();
        // …but `plain`, whose CSpace holds only a Task self-cap (its slot 0), cannot:
        // a self cap is a Task cap, not a Creator cap. (The cap handle root received
        // for `plain` is likewise unusable by anyone outside root's CSpace.)
        let err = k.create_task(plain, CapHandle(0), "grandchild").unwrap_err();
        assert_eq!(err, KernelError::NoCreationRight);
    }
}
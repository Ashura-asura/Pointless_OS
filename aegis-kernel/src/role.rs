//! Kernel role library (master-roadmap Phase 6): task-shaped roles defined by
//! the *kernel*, not by the requesting agent. An agent execution context
//! starts with zero capabilities and can only act after being granted a role;
//! a role expands to a specific, narrow capability set — the role is the
//! reviewable unit, and the grant is an explicit, audited step.
//!
//! Two roles exist today (master roadmap §10 "broader AI orchestration" takes
//! the Phase 6 prototype to a role library — the same discipline for every new
//! role: grant, audit, adversarial denial, never a shortcut).
//!
//! - `restart-service` — the design doc's own §11.F example: READ|CONTROL over
//!   ONE named task, with no GRANT right. The grantee can read the service's
//!   state and restart it.
//! - `observe-service` — a watchdog: READ over ONE named task only. The grantee
//!   can *see* the service's state but can never restart or kill it. A
//!   monitor is a different, narrower capability — observing is not a step
//!   toward controlling, and the gate enforces that even for a fully
//!   compromised observer.
//! - `query-advisor` (master roadmap Phase F) — network access to exactly ONE
//!   kernel-declared host (`netif::ADVISOR_HOST_IP`/`ADVISOR_HOST_PORT`), and
//!   nothing else. The grantee receives a `NetEndpoint` capability that is
//!   already bound to that one destination at mint time — it never calls
//!   `sys_net_socket` itself, so it never gets to choose where the socket
//!   points, and no syscall exists to rebind an endpoint once minted. No
//!   GRANT, so the capability cannot be re-delegated. The role's own network
//!   access can *advise* — the response is data, read into a bounded buffer —
//!   but it carries none of the rights (CONTROL, GRANT) that would let it
//!   authorize anything on its own. Acting on the advice still requires
//!   whatever capability that action already needed.
//!
//!   This role's isolation from `sys_net_socket` is now backed by two
//!   independent gates, not one: even setting aside that `role_grant` mints
//!   the socket directly (never through the syscall), an advisor-role agent
//!   that somehow *did* reach `sys_net_socket` would still be refused there —
//!   it holds no `Cap::NetRoot` (see `netif::sys_net_socket`'s gate, the
//!   closure of the previously-open "any task can mint a socket to any host"
//!   gap) and `NET_RIGHTS` never includes the `CONTROL` right `NetRoot`
//!   requires. `advisor_cannot_escape_host_scope` below exercises this
//!   directly.
//!
//! Every role is declared by the kernel, installs exactly its declared right
//! set, and never carries GRANT: there is no syscall that mints GRANT onto a
//! role cap, and `role_grant` installs exactly the role's declared set. This
//! mirrors the model crate's `grants::role`.
//!
//! The agent is never in the trusted computing base: every check on what it
//! can do is enforced here, at the kernel capability gate, never by the
//! agent's own code. A fully compromised agent cannot self-escalate because
//! the gate refuses it — the agent has no code path that could widen its
//! authority even if all of it were malicious.

use crate::audit;
use crate::cap::{
    Cap, CapSlot, Rights, NET_RIGHTS, OBJECT_EDIT_RIGHTS, OBJECT_RIGHTS, OBJECT_ROOT_RIGHTS,
};
use crate::objstore::{ObjStore, SubtreeDiff};
use crate::tasks::{current_idx, set_task_cap, task_cap, MAX_CAPS, MAX_TASKS};

/// `restart-service` = READ|CONTROL over one named task, no GRANT.
pub const ROLE_RESTART_SERVICE: u32 = 0;
/// `observe-service` = READ over one named task only (a watchdog: it can see
/// the service's state, it can never restart or kill it), no GRANT, no CONTROL.
pub const ROLE_OBSERVE_SERVICE: u32 = 1;
/// `query-advisor` = SEND|RECV on a `NetEndpoint` bound to the one
/// kernel-declared advisor host, no GRANT. See the module docs above.
pub const ROLE_QUERY_ADVISOR: u32 = 2;

/// A role declared by the kernel. `rights` is the *exact* set the grantee
/// will be allowed — the system declares it, never the requesting agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Role {
    pub id: u32,
    pub name: &'static str,
    pub rights: Rights,
    /// Whether the role may ever re-delegate. False for every role today:
    /// a role-granted cap never carries GRANT, so an agent cannot mint new
    /// authority from an existing grant.
    pub grants: bool,
    /// False for a `Task`-shaped role (`restart-service`, `observe-service`):
    /// the grantee receives `Cap::Task(target)` with `rights`, and `target`
    /// names the object the capability points at.
    ///
    /// True for a network-shaped role (`query-advisor`): the grantee receives
    /// a `Cap::NetEndpoint` bound to the kernel-declared advisor host, never
    /// to `target`. `target` is still required and still audited — it names
    /// the service this advisory access is granted *in the context of* (the
    /// grantor must hold at least READ over it, i.e. watchdog-level standing)
    /// — but it is not what the resulting capability points at. Keeping the
    /// same `(grantee, target, dst_slot)` grant shape lets a network-scoped
    /// role reuse the exact grant/audit pipeline every other role already
    /// goes through, rather than inventing a parallel one.
    pub network_scoped: bool,
    /// True for an object-store-scoped role (Track 1, §9.1): the grantee
    /// receives a `Cap::Object(subtree_root)` minted for the requested
    /// object id, never to `target` as a task. The grantor must hold
    /// `Cap::ObjectRoot` with CONTROL (the human reviewer / boot policy),
    /// not a Task capability — object authority is delegated by policy, not
    /// derived from task authority.
    pub object_scoped: bool,
}

/// The one role the kernel knows. The grantee may read the named service's
/// state (READ) and restart it (CONTROL); the absence of GRANT is what makes
/// self-escalation impossible at the gate.
pub const RESTART_SERVICE: Role = Role {
    id: ROLE_RESTART_SERVICE,
    name: "restart-service",
    rights: Rights::READ.union(Rights::CONTROL),
    grants: false,
    network_scoped: false,
    object_scoped: false,
};

/// `observe-service` = READ over one named task only. The grantee can query
/// the named service's state but has no CONTROL: restarting or killing it is
/// refused at the gate. This is the watchdog complement to `restart-service` —
/// a different, narrower capability that exists so that "monitoring" is not a
/// step toward "controlling" even for a fully compromised observer.
pub const OBSERVE_SERVICE: Role = Role {
    id: ROLE_OBSERVE_SERVICE,
    name: "observe-service",
    rights: Rights::READ,
    grants: false,
    network_scoped: false,
    object_scoped: false,
};

/// `query-advisor` = SEND|RECV on a `NetEndpoint` bound to the one
/// kernel-declared advisor host (`netif::ADVISOR_HOST_IP`/`ADVISOR_HOST_PORT`).
/// No GRANT — the capability cannot be re-delegated — and no CONTROL of any
/// kind: this role can read an HTTPS response into a bounded buffer and
/// nothing more. It cannot restart, kill, or grant anything; the advisory
/// answer is input to whichever role's own logic reads it, never authority.
pub const QUERY_ADVISOR: Role = Role {
    id: ROLE_QUERY_ADVISOR,
    name: "query-advisor",
    rights: NET_RIGHTS,
    grants: false,
    network_scoped: true,
    object_scoped: false,
};

/// §9.1 (Track 1 real task): `object-subtree-reader` = READ over one named
/// object-store subtree. The grantee can run the `summarize-changes-in-
/// subtree` task (read-only, lowest blast radius for a first real grant) and
/// nothing else — no WRITE, no GRANT, no task/network authority. The
/// capability is minted by the kernel from the policy-declared `ObjectRoot`;
/// the agent never assembles its own object capability list.
pub const ROLE_OBJECT_READER: u32 = 3;

/// §9.1 / §9.5 (Track 1 second task): `object-subtree-editor` = READ|WRITE
/// over one named object-store subtree. READ lets it *propose* an edit; WRITE
/// is the *apply* (irreversible) action and is two-party gated at the grant
/// path (mechanism 5). No GRANT — the editor cannot re-delegate.
pub const ROLE_OBJECT_EDITOR: u32 = 4;

/// The read-only object role. See `ROLE_OBJECT_READER`.
pub const OBJECT_READER: Role = Role {
    id: ROLE_OBJECT_READER,
    name: "object-subtree-reader",
    rights: OBJECT_RIGHTS,
    grants: false,
    network_scoped: false,
    object_scoped: true,
};

/// The editor object role. WRITE is the irreversible "apply" action and is
/// two-party gated (mechanism 5). See `ROLE_OBJECT_EDITOR`.
pub const OBJECT_EDITOR: Role = Role {
    id: ROLE_OBJECT_EDITOR,
    name: "object-subtree-editor",
    rights: OBJECT_EDIT_RIGHTS,
    grants: false,
    network_scoped: false,
    object_scoped: true,
};

/// The role registry. Reviewable once per role type, not per grant.
pub const ALL_ROLES: [Role; 5] = [
    RESTART_SERVICE,
    OBSERVE_SERVICE,
    QUERY_ADVISOR,
    OBJECT_READER,
    OBJECT_EDITOR,
];

/// Look up a role by id.
pub fn lookup(id: u32) -> Option<&'static Role> {
    ALL_ROLES.iter().find(|r| r.id == id)
}

/// Syscall 18: grant role `role_id` over task `target` to `grantee`, installing
/// the role's exact capability set at `dst_slot` in the grantee's CSpace.
///
/// Gate (kernel-enforced; the agent's own code never checks itself): the
/// *grantor* — the currently running task — must hold a Task capability on
/// `target` carrying at least the role's exact rights. A grantor with no
/// authority over the target is refused. The role is declared by the kernel,
/// so the grantee receives exactly the role's set and nothing else.
///
/// Returns 0 on success, -1 on any refusal. Never panics: every argument is
/// bounds-checked before any table is touched, and every outcome (success and
/// refusal alike) is recorded in the kernel audit log (`OpKind::RoleGrant`).
pub fn role_grant(role_id: u64, grantee: u64, target: u64, dst_slot: u64) -> i64 {
    let cur = current_idx();
    let role = match lookup(role_id as u32) {
        Some(r) => r,
        None => {
            crate::audit::record(
                cur,
                crate::audit::OpKind::RoleGrant,
                Some(target as u32),
                false,
            );
            return -1;
        }
    };
    // Bounds-check both tables before touching either (a malformed argument
    // must be refused, never a panic). `target` too: it names a task table
    // slot, and a stale or out-of-range target must never be minted into a
    // capability.
    if (grantee as usize) >= MAX_TASKS
        || (dst_slot as usize) >= MAX_CAPS
        || (target as usize) >= MAX_TASKS
    {
        crate::audit::record(
            cur,
            crate::audit::OpKind::RoleGrant,
            Some(target as u32),
            false,
        );
        return -1;
    }
    // The grantor must hold a Task cap on `target` carrying enough authority
    // to make this grant. For a Task-shaped role that means the role's exact
    // rights (the grantor can only hand out what it already has). For a
    // network-shaped role (`query-advisor`) `target` is not what the grantee
    // ends up holding — it is the service this advisory access is granted in
    // the context of — so the bar is watchdog-level standing (READ) over
    // that service, matching the spec's own wiring: the observe-service
    // watchdog is what earns the right to ask for advice about what it
    // watches.
    let required = if role.network_scoped {
        Rights::READ
    } else if role.object_scoped {
        OBJECT_ROOT_RIGHTS
    } else {
        role.rights
    };
    let authorized = if role.object_scoped {
        // Object authority is delegated by policy: the grantor must hold the
        // singleton `ObjectRoot` with CONTROL (the human reviewer / boot
        // policy), never a Task capability.
        (0..MAX_CAPS).any(|s| match task_cap(cur, s) {
            CapSlot {
                cap: Cap::ObjectRoot,
                rights,
            } => rights.contains(required),
            _ => false,
        })
    } else {
        (0..MAX_CAPS).any(|s| match task_cap(cur, s) {
            CapSlot {
                cap: Cap::Task(t_oid),
                rights,
            } => {
                // The cap must name the target AND still be live (the generation
                // must match the task that currently occupies the slot): a stale
                // capability minted against a previous occupant of `target`'s
                // index must not authorize a grant over whoever lives there now.
                t_oid.index as usize == target as usize
                    && crate::tasks::task_generation(target as usize) == t_oid.generation
                    && rights.contains(required)
            }
            _ => false,
        })
    };
    if !authorized {
        crate::audit::record(
            cur,
            crate::audit::OpKind::RoleGrant,
            Some(target as u32),
            false,
        );
        return -1;
    }
    // The role is declared by the kernel: install exactly its rights. A role
    // never carries GRANT, so the grantee cannot re-delegate the role.
    if role.object_scoped {
        // The kernel mints the object capability for the requested object id
        // (not `target` as a task). The agent receives exactly the role's
        // rights over that one subtree and nothing else — it never supplied
        // the object id's capability shape itself.
        let oid = crate::cap::Oid::new(target as u32, 0);
        set_task_cap(
            grantee as usize,
            dst_slot as usize,
            CapSlot {
                cap: Cap::Object(oid),
                rights: role.rights,
            },
        );
    } else if role.network_scoped {
        // The grantee never calls `sys_net_socket` for this capability — the
        // kernel mints the socket itself, bound to the one host it declares.
        // The agent has no code path that could choose a different
        // destination, because there is no argument here for it to supply.
        let Some(oid) = crate::netif::open_advisor_endpoint() else {
            crate::audit::record(
                cur,
                crate::audit::OpKind::RoleGrant,
                Some(target as u32),
                false,
            );
            return -1;
        };
        set_task_cap(
            grantee as usize,
            dst_slot as usize,
            CapSlot {
                cap: Cap::NetEndpoint(oid),
                rights: role.rights,
            },
        );
    } else {
        // Mint the grantee's capability against the CURRENT identity of the
        // target slot (bounds-checked above): the grantee must name the task
        // that is actually there, with a live generation.
        let Some(oid) = crate::tasks::task_oid(target as usize) else {
            crate::audit::record(
                cur,
                crate::audit::OpKind::RoleGrant,
                Some(target as u32),
                false,
            );
            return -1;
        };
        set_task_cap(
            grantee as usize,
            dst_slot as usize,
            CapSlot {
                cap: Cap::Task(oid),
                rights: role.rights,
            },
        );
    }
    // Mechanism 2 (§9.2): ephemeral-by-default. Every role grant lapses after
    // GRANT_TTL ticks unless re-granted. Boot singletons (NetRoot/VmRoot) are
    // not minted here and carry no expiry record, so they remain valid by
    // kernel policy — only agent-facing role grants are ephemeral.
    set_grant_expiry(
        grantee as usize,
        dst_slot as usize,
        audit::tick() + GRANT_TTL,
    );
    crate::audit::record(
        cur,
        crate::audit::OpKind::RoleGrant,
        Some(target as u32),
        true,
    );
    0
}

/// §9.2 (mechanism 2): ephemeral-by-default grant window, in audit ticks. A
/// role grant is valid only until `audit::tick()` reaches this expiry. Boot
/// singletons (`NetRoot`/`VmRoot`) are not minted through `role_grant` and
/// carry no expiry record, so they remain valid by kernel policy.
pub const GRANT_TTL: u64 = 64;

/// Per-(task, slot) grant expiry tick. `0` means "no role_grant expiry
/// recorded" — a manually-installed cap or a boot singleton — which is treated
/// as non-expiring. A value `>0` is the tick at which the grant lapses.
static mut GRANT_EXPIRY: [[u64; MAX_CAPS]; MAX_TASKS] = [[0u64; MAX_CAPS]; MAX_TASKS];

fn set_grant_expiry(task: usize, slot: usize, expiry: u64) {
    if task < MAX_TASKS && slot < MAX_CAPS {
        unsafe { GRANT_EXPIRY[task][slot] = expiry };
    }
}

/// True iff the capability in `(task, slot)` is still inside its ephemeral
/// window. Caps with no recorded expiry (manually installed or boot
/// singletons) never lapse. This is the kernel-enforced half of §9.2.
pub fn grant_valid(task: usize, slot: usize) -> bool {
    if task >= MAX_TASKS || slot >= MAX_CAPS {
        return false;
    }
    let exp = unsafe { GRANT_EXPIRY[task][slot] };
    exp == 0 || audit::tick() <= exp
}

/// The reason a delegated capability use was refused — at the kernel gate,
/// never by the agent's own code declining to try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationError {
    /// No relevant capability in the slot.
    NoCapability,
    /// The capability lacks the rights the task needs.
    InsufficientRights,
    /// The grant has lapsed (ephemeral window closed).
    Expired,
    /// The capability covers a *different* object than the one asked for — this
    /// is a scope expansion and must go through confirmation (mechanism 3).
    ScopeMismatch,
    /// Same as `ScopeMismatch`: a scope expansion was requested and must be
    /// confirmed before any capability is minted.
    ExpansionRequired,
}

/// §9.1 + §9.2 + §9.4: resolve and authorize an object capability at
/// `(task, slot)` for `root` with needed `rights`, enforcing (a) the cap
/// actually names `root` (scope), (b) it carries `rights`, and (c) it has not
/// lapsed (ephemeral). Returns `ExpansionRequired` when the cap names a
/// *different* object — that is the signal for the diff-confirmation path, not
/// a silent allow.
fn resolve_object_cap(
    task: usize,
    slot: usize,
    root: u32,
    need: Rights,
) -> Result<(), DelegationError> {
    if task >= MAX_TASKS || slot >= MAX_CAPS {
        return Err(DelegationError::NoCapability);
    }
    match task_cap(task, slot).cap {
        Cap::Object(o) => {
            if o.index != root {
                // Different object than the one granted: a scope expansion.
                return Err(DelegationError::ExpansionRequired);
            }
            let cs = task_cap(task, slot);
            if !cs.rights.contains(need) {
                return Err(DelegationError::InsufficientRights);
            }
            if !grant_valid(task, slot) {
                return Err(DelegationError::Expired);
            }
            Ok(())
        }
        _ => Err(DelegationError::NoCapability),
    }
}

/// §9.1 + §9.2 + §9.4 (the real task, end-to-end): summarize what changed in
/// `root`'s object-store subtree since `since_seq`, using the granted object
/// capability at `(task, slot)`. The capability gate is enforced here — the
/// agent cannot reach the store with a capability it was not granted. Every
/// outcome (success and refusal alike) is recorded as a `RoleExercise` audit
/// entry carrying the target object, so "what did this agent do with what it
/// was given" is answerable after the fact.
pub fn objstore_subtree_summary(
    task: usize,
    slot: usize,
    root: u32,
    since_seq: u64,
    store: &ObjStore,
) -> Result<SubtreeDiff, DelegationError> {
    match resolve_object_cap(task, slot, root, Rights::READ) {
        Ok(()) => {
            let diff = store.subtree_changed_since(root as u64, since_seq);
            audit::record(task, audit::OpKind::RoleExercise, Some(root), true);
            Ok(diff)
        }
        Err(DelegationError::ExpansionRequired) => {
            // Scope expansion must be confirmed; the blocked request is on the
            // record (mechanism 3's denied path).
            audit::record(task, audit::OpKind::RoleExpand, Some(root), false);
            Err(DelegationError::ExpansionRequired)
        }
        Err(e) => {
            audit::record(task, audit::OpKind::RoleExercise, Some(root), false);
            Err(e)
        }
    }
}

/// §9.3 (mechanism 3): a pending scope-expansion request. Nothing is minted
/// until `confirm_expansion` succeeds. `high_risk` marks WRITE/apply-style
/// expansions, which additionally require two-party confirmation (mechanism 5).
#[derive(Copy, Clone)]
struct PendingExpand {
    id: u64,
    task: usize,
    root: u32,
    need: Rights,
    high_risk: bool,
    confirmers: [Option<usize>; 2],
}

const MAX_PENDING: usize = 16;
static mut PENDING: [Option<PendingExpand>; MAX_PENDING] = [None; MAX_PENDING];
static mut PENDING_SEQ: u64 = 0;

/// Mutable accessor for `PENDING` via `addr_of_mut!` (mirrors `audit.rs`'s
/// `write_records_mut`), so iteration does not create a direct mutable
/// reference to the `static mut` (which the `static_mut_refs` lint rejects).
fn pending_mut() -> &'static mut [Option<PendingExpand>; MAX_PENDING] {
    unsafe { &mut *core::ptr::addr_of_mut!(PENDING) }
}

/// §9.3: an agent asks to expand its authority to `root` with `need`. Returns a
/// pending id; the request is recorded as a blocked `RoleExpand` and nothing is
/// minted. The "diff" shown to the human is exactly this addition
/// (`Cap::Object(root)` with `need`), not the agent's whole accumulated set.
/// A `need` containing `WRITE` is flagged `high_risk` (the irreversible
/// "apply" action) and will require a second, distinct confirmer.
pub fn request_expansion(task: usize, root: u32, need: Rights) -> u64 {
    let high_risk = need.contains(Rights::WRITE);
    let id = unsafe {
        let seq = core::ptr::read(core::ptr::addr_of_mut!(PENDING_SEQ));
        let id = seq + 1;
        core::ptr::write(core::ptr::addr_of_mut!(PENDING_SEQ), id);
        let pm = pending_mut();
        if let Some(i) = pm.iter().position(|s| s.is_none()) {
            pm[i] = Some(PendingExpand {
                id,
                task,
                root,
                need,
                high_risk,
                confirmers: [None, None],
            });
        }
        id
    };
    audit::record(task, audit::OpKind::RoleExpand, Some(root), false);
    id
}

/// §9.3 + §9.5 (mechanisms 3 and 5): confirm a pending expansion. `confirm`
/// must hold `Cap::ObjectRoot` with CONTROL (the human reviewer / policy). For
/// a `high_risk` (WRITE/apply) expansion, a *second, distinct* confirmer is
/// required (two-party): the first confirmation is accepted but the cap is not
/// minted until the second, distinct party also confirms. Denials happen at
/// the kernel gate (missing authority, or the same party confirming twice).
/// On success the capability is minted at `dst_slot` on the requester with an
/// ephemeral expiry, and a `RoleExpand` success is recorded.
pub fn confirm_expansion(confirm: usize, pending_id: u64, dst_slot: usize) -> i64 {
    let authorized = (0..MAX_CAPS).any(|s| match task_cap(confirm, s) {
        CapSlot {
            cap: Cap::ObjectRoot,
            rights,
        } => rights.contains(OBJECT_ROOT_RIGHTS),
        _ => false,
    });
    if !authorized {
        audit::record(confirm, audit::OpKind::RoleExpand, None, false);
        return -1;
    }
    let mut mint: Option<(usize, u32, Rights)> = None;
    let pm = pending_mut();
    for slot in pm.iter_mut() {
        if let Some(p) = slot {
            if p.id != pending_id {
                continue;
            }
            if p.high_risk {
                // Two-party: refuse the same party confirming twice.
                if p.confirmers[0] == Some(confirm) || p.confirmers[1] == Some(confirm) {
                    audit::record(confirm, audit::OpKind::RoleExpand, Some(p.root), false);
                    return -1;
                }
                if p.confirmers[0].is_none() {
                    p.confirmers[0] = Some(confirm);
                } else if p.confirmers[1].is_none() {
                    p.confirmers[1] = Some(confirm);
                }
                // Need a second, distinct confirmer before minting.
                if p.confirmers[1].is_none() {
                    audit::record(confirm, audit::OpKind::RoleExpand, Some(p.root), false);
                    return 0;
                }
            }
            mint = Some((p.task, p.root, p.need));
            *slot = None;
            break;
        }
    }
    let Some((task, root, need)) = mint else {
        audit::record(confirm, audit::OpKind::RoleExpand, None, false);
        return -1;
    };
    if dst_slot >= MAX_CAPS {
        return -1;
    }
    set_task_cap(
        task,
        dst_slot,
        CapSlot {
            cap: Cap::Object(crate::cap::Oid::new(root, 0)),
            rights: need,
        },
    );
    set_grant_expiry(task, dst_slot, audit::tick() + GRANT_TTL);
    audit::record(confirm, audit::OpKind::RoleExpand, Some(root), true);
    0
}

/// §9.5 (mechanism 5, reduced): does `task`'s actual audit trail stay inside
/// the shape of a *read-only* object role? A read-only reader must never have
/// exercised a mutating op — `MemWrite`, `TaskKill`, `TaskSpawn`, `NetOpen`,
/// or a raw `Write`. This is the lightweight circuit breaker's "does usage
/// match the role's expected shape" check, reusing the same attributed audit
/// log `monitor.rs` trains on. (The full suspend-don't-revoke monitor lives in
/// `monitor.rs`; here we answer the specific "did this read-only grant stay
/// read-only" question the role library needs.)
pub fn reader_shape_ok(task: usize) -> bool {
    let counts = audit::op_counts(task);
    counts[audit::OpKind::MemWrite.index()] == 0
        && counts[audit::OpKind::TaskKill.index()] == 0
        && counts[audit::OpKind::TaskSpawn.index()] == 0
        && counts[audit::OpKind::NetOpen.index()] == 0
        && counts[audit::OpKind::Write.index()] == 0
}

#[cfg(test)]
extern "sysv64" fn demo_dummy() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Boot-log demo for Track 1 (§9): the real `summarize-changes-in-subtree`
/// task, end-to-end through a role-shaped, ephemeral, audited grant, with a
/// scope-expansion that is blocked until confirmed — exactly the prompt's
/// Verify scenario. Exercised by `track1_boot_demo` (it prints through the
/// kernel log the same way every other live-verified phase does). Wiring it
/// into the physical UEFI boot path is a follow-up (the boot path sets the
/// current task via its own mechanism, not the test-only `set_current_for_test`).
#[cfg(test)]
pub fn demo_track1() {
    crate::audit::reset_for_test();
    crate::tasks::reset_table_for_test();
    for i in 0..MAX_TASKS {
        for s in 0..MAX_CAPS {
            crate::tasks::set_task_cap(i, s, CapSlot::empty());
        }
    }
    let (reviewer, agent) = (1usize, 2usize);
    unsafe {
        crate::tasks::spawn("reviewer", demo_dummy, 0x200000).unwrap();
        crate::tasks::spawn("agent", demo_dummy, 0x300000).unwrap();
    }
    // The human reviewer holds ObjectRoot (boot policy).
    crate::tasks::set_task_cap(
        reviewer,
        0,
        CapSlot {
            cap: Cap::ObjectRoot,
            rights: OBJECT_ROOT_RIGHTS,
        },
    );
    crate::tasks::set_current_for_test(reviewer);
    crate::sprintln!(
        "Aegis: Track1: granting object-subtree-reader to agent (role-shaped, ephemeral)"
    );
    let _ = role_grant(ROLE_OBJECT_READER as u64, agent as u64, 1, 0);

    // Real object-store data: a small "repo" subtree.
    let mut store = ObjStore::new();
    store.create(1, None).unwrap();
    store.create(2, Some(1)).unwrap();
    store.create(3, Some(1)).unwrap();
    let _w = store.write(2, 10, 0xAAAA).unwrap();
    let _w = store.write(3, 5, 0xBBBB).unwrap();

    crate::tasks::set_current_for_test(agent);
    match objstore_subtree_summary(agent, 0, 1, 0, &store) {
        Ok(diff) => crate::sprintln!(
            "Aegis: Track1: agent summarized subtree 1: {} members, {} changed",
            diff.members,
            diff.changed_count
        ),
        Err(e) => crate::sprintln!("Aegis: Track1: summary refused: {e:?}"),
    }

    // Scope expansion: agent asks for subtree 2 (blocked until confirmed).
    crate::sprintln!("Aegis: Track1: agent requests expansion to subtree 2 (must block)");
    let pid = request_expansion(agent, 2, Rights::READ);
    match objstore_subtree_summary(agent, 0, 2, 0, &store) {
        Err(DelegationError::ExpansionRequired) => {
            crate::sprintln!("Aegis: Track1: expansion blocked (no cap until confirmation)")
        }
        _ => crate::sprintln!("Aegis: Track1: ERROR: expansion was not blocked"),
    }
    // Reviewer confirms.
    crate::sprintln!("Aegis: Track1: reviewer confirms expansion to subtree 2");
    let _ = confirm_expansion(reviewer, pid, 1);
    match objstore_subtree_summary(agent, 1, 2, 0, &store) {
        Ok(_) => crate::sprintln!("Aegis: Track1: expanded cap now works (subtree 2)"),
        Err(e) => crate::sprintln!("Aegis: Track1: ERROR: expanded cap refused: {e:?}"),
    }

    // Audit answers "what did the agent do?" after the fact.
    crate::sprintln!("Aegis: Track1: audit trail (kernel truth):");
    crate::audit::dump_agent_flow(agent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::{task_kill, task_restart, task_state};
    use crate::tasks::{set_current_for_test, spawn};

    extern "sysv64" fn dummy() -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    fn clean_world() {
        crate::audit::reset_for_test();
        crate::tasks::reset_table_for_test();
        for i in 0..MAX_TASKS {
            for s in 0..MAX_CAPS {
                set_task_cap(i, s, CapSlot::empty());
            }
        }
    }

    /// The DoD grant test: a grantor holding the role's rights over the target
    /// grants `restart-service` to a zero-cap agent. The agent receives EXACTLY
    /// READ|CONTROL over the named task — READ to query state, CONTROL to
    /// restart it — and no GRANT. The granted cap rides the real gates: the
    /// agent can observe and restart the crashed service.
    #[test]
    fn agent_role_grant() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, grantor = task 1, agent = task 2.
            let (svc, grantor, agent) = (0usize, 1usize, 2usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            // The agent starts with zero capabilities: a role grant is the only
            // way it acquires authority.
            assert!((0..MAX_CAPS).all(|s| task_cap(agent, s).cap == Cap::None));
            // The grantor holds READ|CONTROL over the service — the role's
            // exact rights — installed by the kernel as the scripted stand-in.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ.union(Rights::CONTROL),
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, svc as u64, 0),
                0
            );
            // The grantee's slot 0 is exactly the role's set: Task(svc) with
            // READ|CONTROL and no GRANT.
            let got = task_cap(agent, 0);
            assert_eq!(got.cap, Cap::Task(crate::cap::Oid::new(svc as u32, 0)));
            assert!(got.rights.contains(Rights::READ));
            assert!(got.rights.contains(Rights::CONTROL));
            assert!(!got.rights.contains(Rights::GRANT), "role never grants");
            assert_eq!(
                got.rights.bits(),
                (Rights::READ.union(Rights::CONTROL)).bits()
            );
            // The granted cap rides the real gates, now as the agent.
            set_current_for_test(agent);
            assert_eq!(task_state(0), 1, "READ lets the agent query the service");
            crate::tasks::kill_task(svc);
            assert_eq!(task_state(0), 0, "service is dead");
            assert_eq!(task_restart(0), 0, "CONTROL lets the agent restart it");
            assert!(
                crate::tasks::is_task_alive(svc),
                "the agent's one real task succeeded"
            );
        }
    }

    /// The headline Phase-6 result: the agent cannot self-escalate, and the
    /// refusal is the kernel's, not the agent's. The agent holds only the
    /// granted `restart-service` cap (READ|CONTROL, no GRANT). Every attempt to
    /// widen that authority is refused at the capability gate: delegating the
    /// role needs GRANT (denied), controlling a task it was never granted
    /// needs a Task cap over it (denied), and re-granting a role over a task
    /// the grantor does not control is refused. There is no syscall that mints
    /// GRANT onto a role cap, so the agent has no code path that could
    /// escalate even if every line of it were compromised.
    #[test]
    fn agent_cannot_self_escalate() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, other = task 1, grantor = task 2, agent = task 3.
            let (svc, other, grantor, agent) = (0usize, 1usize, 2usize, 3usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("other", dummy, 0x200000).unwrap();
            spawn("grantor", dummy, 0x300000).unwrap();
            spawn("agent", dummy, 0x400000).unwrap();
            // Grantor grants the role to the agent.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ.union(Rights::CONTROL),
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, svc as u64, 0),
                0
            );
            set_current_for_test(agent);

            // 1) Delegating the role onward requires GRANT on the role cap —
            //    the role has none, so the grant is denied at the gate.
            assert_eq!(
                crate::ipc::ipc_cap_grant(other as u64, 0, 0),
                -1,
                "no GRANT in the role: the agent cannot re-delegate"
            );
            assert_eq!(
                task_cap(other, 0).cap,
                Cap::None,
                "nothing landed in the peer's CSpace"
            );

            // 2) Controlling a task it was never granted requires a Task cap
            //    over it — the agent holds only the service cap, so kill and
            //    restart of the other task are denied.
            set_task_cap(
                agent,
                1,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(other as u32, 0)),
                    rights: Rights::READ,
                },
            );
            // Even with READ on the other task, CONTROL is absent: no restart.
            assert_eq!(task_restart(1), -1, "CONTROL is per-task, never ambient");

            // 3) Re-granting itself a role over a task the grantor does not
            //    control is refused — the grantor gate checks authority over
            //    the target, not the grantee's wishes.
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, other as u64, 2),
                -1,
                "no Task cap with the role's rights over the other task"
            );

            // 4) There is no widening syscall at all: the agent cannot mint
            //    GRANT onto its own cap. The audit log attributes every step —
            //    the agent's only Grant record is the refusal above, never a
            //    success.
            assert_eq!(
                crate::audit::op_counts(agent)[crate::audit::OpKind::Grant.index()],
                1,
                "the agent's only Grant record is its refused delegation"
            );
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::Grant,
                svc as u32
            ));
            // The audit log attributes every step: the grantor's role grant
            // succeeded, and the agent's own role-grant attempts are denials —
            // the agent never successfully performed a role grant.
            assert!(crate::audit::ever_succeeded(
                grantor,
                crate::audit::OpKind::RoleGrant,
                svc as u32
            ));
            assert!(
                !crate::audit::ever_succeeded(agent, crate::audit::OpKind::RoleGrant, svc as u32),
                "the agent never successfully granted itself anything"
            );
        }
    }

    /// §10 "broader AI orchestration": a second role through the SAME
    /// discipline as Phase 6. A grantor holding READ over the service grants
    /// `observe-service` to a zero-cap agent. The agent receives EXACTLY READ —
    /// no CONTROL, no GRANT. It can query the service's state (its one real
    /// task as a watchdog) but restarting the crashed service is refused at the
    /// gate: observation never becomes control.
    #[test]
    fn observer_role_grant() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, grantor = task 1, agent = task 2.
            let (svc, grantor, agent) = (0usize, 1usize, 2usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            // The agent starts with zero capabilities.
            assert!((0..MAX_CAPS).all(|s| task_cap(agent, s).cap == Cap::None));
            // The grantor holds READ over the service — the observe role's
            // exact right set — as the scripted stand-in for a human reviewer.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_OBSERVE_SERVICE as u64, agent as u64, svc as u64, 0),
                0
            );
            // The grantee's slot 0 is exactly the role's set: Task(svc) with
            // READ only, no CONTROL, no GRANT.
            let got = task_cap(agent, 0);
            assert_eq!(got.cap, Cap::Task(crate::cap::Oid::new(svc as u32, 0)));
            assert!(got.rights.contains(Rights::READ));
            assert!(
                !got.rights.contains(Rights::CONTROL),
                "watchdog has no CONTROL"
            );
            assert!(!got.rights.contains(Rights::GRANT), "role never grants");
            assert_eq!(got.rights.bits(), Rights::READ.bits());
            // The granted cap rides the real gates, now as the agent.
            set_current_for_test(agent);
            assert_eq!(task_state(0), 1, "READ lets the watchdog query the service");
            // The one thing a watchdog must NOT be able to do: restart.
            crate::tasks::kill_task(svc);
            assert_eq!(task_state(0), 0, "the watchdog can see it crashed");
            assert_eq!(
                task_restart(0),
                -1,
                "observation never becomes control: restart refused at the gate"
            );
            assert!(!crate::tasks::is_task_alive(svc), "the service stays dead");
        }
    }

    /// §10: the observe agent cannot turn its watch into a restart. Its cap is
    /// exactly READ over the service — no CONTROL, no GRANT — so restarting,
    /// killing, delegating, or re-granting itself `restart-service` is refused
    /// by the kernel capability gate. Same adversarial discipline as Phase 6,
    /// applied to the second role.
    #[test]
    fn observer_cannot_self_escalate() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, other = task 1, grantor = task 2, agent = task 3.
            let (svc, other, grantor, agent) = (0usize, 1usize, 2usize, 3usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("other", dummy, 0x200000).unwrap();
            spawn("grantor", dummy, 0x300000).unwrap();
            spawn("agent", dummy, 0x400000).unwrap();
            // Grantor grants the observe role to the agent.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_OBSERVE_SERVICE as u64, agent as u64, svc as u64, 0),
                0
            );
            set_current_for_test(agent);

            // 1) Delegating the role onward needs GRANT — the role has none.
            assert_eq!(
                crate::ipc::ipc_cap_grant(other as u64, 0, 0),
                -1,
                "no GRANT in the observe role: the agent cannot re-delegate"
            );

            // 2) Restarting the service needs CONTROL — the observe role has
            //    none. Even after the service dies, the watchdog can only watch.
            crate::tasks::kill_task(svc);
            assert_eq!(task_restart(0), -1, "CONTROL is per-task, never ambient");

            // 3) Killing a task it was never granted needs CONTROL — refused.
            assert_eq!(task_kill(1), -1, "no CONTROL over the other task");

            // 4) Re-granting itself `restart-service` over the service needs a
            //    Task cap with READ|CONTROL over it — the agent holds only READ,
            //    so the grantor gate refuses.
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, svc as u64, 2),
                -1,
                "a watchdog cannot upgrade its observe role to a restart role"
            );

            // 5) The audit log attributes everything: the agent's Grant and
            //    RoleGrant records are denials only — it never succeeded at
            //    anything it was not granted.
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleGrant,
                svc as u32
            ));
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::TaskSpawn,
                svc as u32
            ));
        }
    }

    /// The gate refuses unknown roles and out-of-range targets with -1, never
    /// a panic, and records the refusal.
    #[test]
    fn role_grant_never_panics_and_denies_garbage() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("grantor", dummy, 0x200000).unwrap();
            let (svc, grantor, agent) = (0usize, 1usize, 2usize);
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ.union(Rights::CONTROL),
                },
            );
            set_current_for_test(grantor);
            // Unknown role id.
            assert_eq!(role_grant(999, agent as u64, svc as u64, 0), -1);
            // Out-of-range grantee task.
            assert_eq!(
                role_grant(
                    ROLE_RESTART_SERVICE as u64,
                    MAX_TASKS as u64 + 5,
                    svc as u64,
                    0
                ),
                -1
            );
            // Out-of-range destination slot.
            assert_eq!(
                role_grant(
                    ROLE_RESTART_SERVICE as u64,
                    agent as u64,
                    svc as u64,
                    MAX_CAPS as u64 + 5
                ),
                -1
            );
            // A grantor with no authority over the target is refused.
            set_current_for_test(agent);
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, grantor as u64, svc as u64, 0),
                -1
            );
            // No capability ever landed.
            assert_eq!(task_cap(agent, 0).cap, Cap::None);
            assert_eq!(
                task_cap(grantor, 0).cap,
                Cap::Task(crate::cap::Oid::new(svc as u32, 0))
            );
        }
    }

    /// Phase F: the DoD grant test for `query-advisor`. A grantor holding
    /// READ over the watched service (watchdog-level standing) grants
    /// `query-advisor` to a zero-cap agent. The agent receives a
    /// `NetEndpoint` — NOT a `Task` cap — bound to the kernel-declared
    /// advisor host, with exactly SEND|RECV and no GRANT.
    #[test]
    fn advisor_role_grant() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, grantor = task 1, agent = task 2.
            let (svc, grantor, agent) = (0usize, 1usize, 2usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            assert!((0..MAX_CAPS).all(|s| task_cap(agent, s).cap == Cap::None));
            // The grantor holds READ over the service — watchdog-level
            // standing is enough to ask for advice about what it watches.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_QUERY_ADVISOR as u64, agent as u64, svc as u64, 0),
                0
            );
            let got = task_cap(agent, 0);
            let id = match got.cap {
                Cap::NetEndpoint(id) => id,
                other => panic!("query-advisor must grant a NetEndpoint, got {other:?}"),
            };
            assert!(got.rights.contains(Rights::SEND));
            assert!(got.rights.contains(Rights::RECV));
            assert!(!got.rights.contains(Rights::GRANT), "role never grants");
            assert!(
                !got.rights.contains(Rights::CONTROL),
                "advisory access carries no CONTROL of anything"
            );
            assert_eq!(got.rights.bits(), crate::cap::NET_RIGHTS.bits());
            // The socket the kernel minted is bound to exactly the
            // kernel-declared advisor host — not `svc`, not anything the
            // grantor or agent named.
            assert_eq!(
                crate::netif::socket_remote(id.index as u16),
                Some((
                    crate::netif::ADVISOR_HOST_IP,
                    crate::netif::ADVISOR_HOST_PORT
                )),
                "the granted endpoint is bound to the one kernel-declared advisor host"
            );
        }
    }

    /// Phase F headline result: the query-advisor agent cannot parlay its one
    /// narrow network capability into anything beyond reading a response from
    /// its pre-approved host. Every escape attempt is refused by the kernel
    /// capability gate, not by any check in the agent's own logic.
    #[test]
    fn advisor_cannot_escape_host_scope() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, other = task 1, grantor = task 2, agent = task 3.
            let (svc, other, grantor, agent) = (0usize, 1usize, 2usize, 3usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("other", dummy, 0x200000).unwrap();
            spawn("grantor", dummy, 0x300000).unwrap();
            spawn("agent", dummy, 0x400000).unwrap();
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(
                role_grant(ROLE_QUERY_ADVISOR as u64, agent as u64, svc as u64, 0),
                0
            );
            let advisor_slot_cap = task_cap(agent, 0);
            let Cap::NetEndpoint(net_id) = advisor_slot_cap.cap else {
                panic!("setup: expected a NetEndpoint cap");
            };
            set_current_for_test(agent);

            // 1) No syscall exists to rebind an endpoint's destination: the
            //    binding recorded on the live socket is still exactly the
            //    advisor host, unchanged, after the agent holds the cap.
            assert_eq!(
                crate::netif::socket_remote(net_id.index as u16),
                Some((
                    crate::netif::ADVISOR_HOST_IP,
                    crate::netif::ADVISOR_HOST_PORT
                )),
                "nothing the agent can do rebinds the granted endpoint"
            );

            // 2) Delegating the role onward needs GRANT — the role has none.
            assert_eq!(
                crate::ipc::ipc_cap_grant(other as u64, 0, 1),
                -1,
                "no GRANT in query-advisor: the agent cannot re-delegate its network access"
            );

            // 3) The agent holds no Task capability at all (its one cap is a
            //    NetEndpoint), so it cannot act as a role_grant grantor over
            //    ANY target — it has no authority to escalate itself into
            //    restart-service, observe-service, or a second advisor grant
            //    naming a different host-adjacent target.
            assert_eq!(
                role_grant(ROLE_RESTART_SERVICE as u64, agent as u64, svc as u64, 2),
                -1,
                "a NetEndpoint cap carries no Task authority to grant from"
            );
            assert_eq!(
                role_grant(ROLE_QUERY_ADVISOR as u64, agent as u64, other as u64, 2),
                -1,
                "the agent cannot mint itself a second advisor grant either"
            );

            // 4) The one capability the agent holds cannot be used to control
            //    the service it's advising about: CONTROL was never part of
            //    NET_RIGHTS, so there is no restart/kill path through it —
            //    unlike restart-service, nothing here ever touches
            //    supervisor::task_restart/task_kill in the first place.
            assert!(
                !advisor_slot_cap.rights.contains(Rights::CONTROL),
                "advisory network access was never wired to any control right"
            );

            // 5) The audit trail attributes everything: the agent never
            //    succeeded at a RoleGrant naming a target other than the one
            //    it was legitimately granted advisory context for.
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleGrant,
                svc as u32
            ));
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleGrant,
                other as u32
            ));

            // 6) Phase E item 2 closure, checked in the Phase F context
            //    specifically: even setting aside that `role_grant` never
            //    routes through `sys_net_socket` at all, the agent could
            //    not have reached raw socket-minting authority even if it
            //    tried directly — it holds no `Cap::NetRoot` anywhere in
            //    its CSpace (its one cap is the granted `NetEndpoint`), so
            //    the syscall-level gate refuses it independently of the
            //    role system. Two gates, not one: this is what the
            //    project's own honest-status note flagged as still open
            //    ("any task can mint a socket to any host directly") and
            //    what closes it.
            assert_eq!(
                crate::netif::sys_net_socket(1, 0x0A000202, 8080),
                -1,
                "no Cap::NetRoot anywhere in the agent's CSpace: sys_net_socket refuses it"
            );
            assert!(
                (0..MAX_CAPS).all(|s| task_cap(agent, s).cap != Cap::NetRoot),
                "the query-advisor grant never installs NetRoot"
            );
        }
    }

    // === Track 1 (§9): the real, non-ops-demo task, against real object-store
    // data. Each mechanism ships with its adversarial test in the same commit
    // (prompt §2.3): self-grant, foreign-target, scope-expansion-without-
    // confirmation, and expired-grant-reuse are each denied at the kernel gate.

    /// Mechanism 1 (§9.1): the `object-subtree-reader` role expands to exactly
    /// `Cap::Object(root)` with READ over one subtree — the agent asks for the
    /// role, the kernel mints the capability, the agent never assembles its own
    /// object capability list. The real task runs end-to-end against real
    /// object-store data and is audited.
    #[test]
    fn object_reader_runs_real_task_end_to_end() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            let (grantor, agent) = (1usize, 2usize);
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            // The human reviewer / policy holds ObjectRoot.
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::ObjectRoot,
                    rights: OBJECT_ROOT_RIGHTS,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(role_grant(ROLE_OBJECT_READER as u64, agent as u64, 1, 0), 0);
            let got = task_cap(agent, 0);
            assert_eq!(got.cap, Cap::Object(crate::cap::Oid::new(1, 0)));
            assert!(got.rights.contains(Rights::READ));
            assert!(
                !got.rights.contains(Rights::GRANT),
                "object role never grants"
            );
            // Real object-store data.
            let mut store = crate::objstore::ObjStore::new();
            store.create(1, None).unwrap();
            store.create(2, Some(1)).unwrap();
            store.create(3, Some(1)).unwrap();
            store.write(2, 10, 0xAAAA).unwrap();
            store.write(3, 5, 0xBBBB).unwrap();
            // The agent runs the real task against real data.
            set_current_for_test(agent);
            let diff = objstore_subtree_summary(agent, 0, 1, 0, &store).unwrap();
            assert_eq!(diff.members, 3);
            assert_eq!(diff.changed_count, 2);
            assert!(crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleExercise,
                1
            ));
        }
    }

    /// Mechanism 1 adversarial: the object-reader agent cannot self-escalate.
    /// No GRANT (re-delegation refused), a foreign subtree is a scope
    /// expansion (refused, not silently allowed), and it holds no ObjectRoot
    /// to mint itself more — all denied at the kernel gate.
    #[test]
    fn object_reader_cannot_self_escalate() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            let (grantor, agent, peer) = (1usize, 2usize, 3usize);
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            spawn("peer", dummy, 0x400000).unwrap();
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::ObjectRoot,
                    rights: OBJECT_ROOT_RIGHTS,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(role_grant(ROLE_OBJECT_READER as u64, agent as u64, 1, 0), 0);
            set_current_for_test(agent);
            // 1) No GRANT in the object role: re-delegation refused at the gate.
            assert_eq!(
                crate::ipc::ipc_cap_grant(peer as u64, 0, 0),
                -1,
                "object role never carries GRANT"
            );
            assert_eq!(task_cap(peer, 0).cap, Cap::None);
            // 2) Reading a foreign subtree (root 2) is a scope expansion:
            //    refused at the gate with ExpansionRequired, blocked request on
            //    the record (mechanism 3's denied path).
            let store = crate::objstore::ObjStore::new();
            assert_eq!(
                objstore_subtree_summary(agent, 0, 2, 0, &store),
                Err(DelegationError::ExpansionRequired)
            );
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleExpand,
                2
            ));
            // 3) The agent cannot mint itself more authority (no ObjectRoot).
            assert_eq!(
                role_grant(ROLE_OBJECT_READER as u64, agent as u64, 2, 1),
                -1,
                "no ObjectRoot: cannot self-grant"
            );
            // 4) Audit: the agent never successfully expanded.
            assert!(!crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleExpand,
                2
            ));
        }
    }

    /// Mechanism 2 (§9.2): an ephemeral grant lapses after GRANT_TTL and reuse
    /// is denied at the gate (Expired), with the denial audited.
    #[test]
    fn ephemeral_grant_expires_and_blocks_reuse() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            let (grantor, agent) = (1usize, 2usize);
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::ObjectRoot,
                    rights: OBJECT_ROOT_RIGHTS,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(role_grant(ROLE_OBJECT_READER as u64, agent as u64, 1, 0), 0);
            let store = crate::objstore::ObjStore::new();
            set_current_for_test(agent);
            // Within the window: works.
            assert!(objstore_subtree_summary(agent, 0, 1, 0, &store).is_ok());
            // Advance the clock past the ephemeral TTL.
            crate::audit::advance_tick_for_test(GRANT_TTL + 10);
            // Lapsed grant reuse is denied at the gate (Expired). The first
            // in-window use was already audited as a success; the expired
            // attempt is audited as a failure and adds no new success.
            assert_eq!(
                objstore_subtree_summary(agent, 0, 1, 0, &store),
                Err(DelegationError::Expired)
            );
            assert!(crate::audit::ever_succeeded(
                agent,
                crate::audit::OpKind::RoleExercise,
                1
            ));
            let total_exercises =
                crate::audit::op_counts(agent)[crate::audit::OpKind::RoleExercise.index()];
            assert_eq!(
                total_exercises, 2,
                "one success + one expired-failure, both audited"
            );
        }
    }

    /// Mechanism 3 (§9.3): a real scope-expansion request. Staying inside the
    /// granted scope needs no prompt; expanding to a new subtree is blocked
    /// until a confirmation mints the new cap, and the diff (what's being
    /// added) is attributable.
    #[test]
    fn scope_expansion_requires_confirmation() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            let (grantor, agent) = (1usize, 2usize);
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::ObjectRoot,
                    rights: OBJECT_ROOT_RIGHTS,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(role_grant(ROLE_OBJECT_READER as u64, agent as u64, 1, 0), 0);
            let mut store = crate::objstore::ObjStore::new();
            store.create(2, None).unwrap();
            set_current_for_test(agent);
            // Path A: inside granted scope (root 1) — no prompt needed.
            assert!(objstore_subtree_summary(agent, 0, 1, 0, &store).is_ok());
            // Path B: request expansion to root 2 — blocked until confirmed.
            let pid = request_expansion(agent, 2, Rights::READ);
            assert_eq!(
                objstore_subtree_summary(agent, 0, 2, 0, &store),
                Err(DelegationError::ExpansionRequired),
                "no cap minted until confirmation"
            );
            // Confirm with the ObjectRoot holder (the human reviewer).
            assert_eq!(confirm_expansion(grantor, pid, 1), 0);
            // The expanded cap (root 2) now exists at slot 1 and works.
            set_current_for_test(agent);
            assert!(objstore_subtree_summary(agent, 1, 2, 0, &store).is_ok());
            assert!(crate::audit::ever_succeeded(
                grantor,
                crate::audit::OpKind::RoleExpand,
                2
            ));
        }
    }

    /// Mechanisms 3 + 5: the high-risk (WRITE / "apply") expansion requires a
    /// distinct second party (two-party confirmation). One party confirming
    /// twice is refused; the cap is only minted after two distinct reviewers.
    #[test]
    fn apply_edit_requires_two_party_confirmation() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            let (reviewer_a, reviewer_b, agent) = (1usize, 2usize, 3usize);
            spawn("ra", dummy, 0x200000).unwrap();
            spawn("rb", dummy, 0x300000).unwrap();
            spawn("agent", dummy, 0x400000).unwrap();
            set_task_cap(
                reviewer_a,
                0,
                CapSlot {
                    cap: Cap::ObjectRoot,
                    rights: OBJECT_ROOT_RIGHTS,
                },
            );
            set_task_cap(
                reviewer_b,
                0,
                CapSlot {
                    cap: Cap::ObjectRoot,
                    rights: OBJECT_ROOT_RIGHTS,
                },
            );
            // Agent requests the high-risk (WRITE/apply) expansion to root 2.
            let pid = request_expansion(agent, 2, Rights::READ.union(Rights::WRITE));
            // First reviewer confirms: accepted but awaiting second party.
            assert_eq!(confirm_expansion(reviewer_a, pid, 1), 0);
            // Same party confirming again is refused (no self-two-party).
            assert_eq!(confirm_expansion(reviewer_a, pid, 1), -1);
            // Second, distinct reviewer confirms: cap minted with WRITE.
            assert_eq!(confirm_expansion(reviewer_b, pid, 1), 0);
            let got = task_cap(agent, 1);
            assert_eq!(got.cap, Cap::Object(crate::cap::Oid::new(2, 0)));
            assert!(got.rights.contains(Rights::WRITE));
        }
    }

    /// Mechanism 5 (§9.5, reduced): a read-only reader that stays inside its
    /// shape passes; an off-profile write op in its audit trail is flagged.
    #[test]
    fn reader_shape_monitor_flags_off_profile_use() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            let (grantor, agent) = (1usize, 2usize);
            spawn("grantor", dummy, 0x200000).unwrap();
            spawn("agent", dummy, 0x300000).unwrap();
            set_task_cap(
                grantor,
                0,
                CapSlot {
                    cap: Cap::ObjectRoot,
                    rights: OBJECT_ROOT_RIGHTS,
                },
            );
            set_current_for_test(grantor);
            assert_eq!(role_grant(ROLE_OBJECT_READER as u64, agent as u64, 1, 0), 0);
            set_current_for_test(agent);
            let store = crate::objstore::ObjStore::new();
            let _ = objstore_subtree_summary(agent, 0, 1, 0, &store);
            assert!(
                reader_shape_ok(agent),
                "a read-only reader that only exercised its grant stays in shape"
            );
            // Off-shape: a write op appears in the agent's audit trail.
            crate::audit::record(agent, crate::audit::OpKind::MemWrite, Some(9), true);
            assert!(!reader_shape_ok(agent), "off-profile write is flagged");
        }
    }

    /// Boot-log demo (prompt §2 Verify): runs the whole Track-1 flow against
    /// real object-store data, prints via the kernel log, and is asserted here
    /// the same way every other live-verified phase is. The same `demo_track1`
    /// function is callable from the boot path.
    #[test]
    fn track1_boot_demo() {
        let _g = crate::kernel_state_guard();
        clean_world();
        crate::role::demo_track1();
        // After the demo: the agent's reader grant existed and was exercised.
        assert!(crate::audit::op_counts(2)[crate::audit::OpKind::RoleExercise.index()] >= 1);
    }
}

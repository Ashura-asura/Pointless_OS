//! The grant service (design doc §9): role-shaped, ephemeral-by-default grants minted
//! under a grant root so revoking one anchor removes the whole grant from every CSpace.
//! Every minted right is recorded; every use is in the kernel audit log.

use capability_core::{
    CapHandle, Kernel, KernelError, KernelResult, ObjectKind, Rights, TaskHandle,
};

/// Expiry policy (§9.2: grants default to ephemeral and task-scoped, not persistent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantPolicy {
    /// Dies when the kernel clock passes `now + ticks`, or when the bound task
    /// completes (the supervisor revokes it then) — whichever comes first.
    TaskScoped { ticks: u64 },
    /// Only allowed for roles with `allow_persistent`. Requires the distinct
    /// persistent-grant confirmation path; still revoked by `revoke()` at any time.
    Persistent,
}

/// A real object the grantor intends to grant, named by a cap in the *grantor's*
/// CSpace (so the grantor is the only one who can supply it — the agent cannot name
/// anything).
#[derive(Debug, Clone)]
pub struct GrantTarget {
    pub label: String,
    pub source: CapHandle,
}

/// One line of the confirmation diff. The human reviews *additions* per §9.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub note: &'static str,
    pub kind: ObjectKind,
    pub rights: Rights,
    pub target_label: String,
    pub policy: String,
}

/// A validated proposal awaiting (and only then capable of) confirmation.
#[derive(Debug)]
pub struct PendingGrant {
    pub role_id: &'static str,
    pub grantee_label: String,
    pub grantee: CapHandle, // cap to the grantee task, in the grantor's CSpace
    pub target: GrantTarget,
    pub policy: GrantPolicy,
    pub request: crate::role::CapRequest,
}

/// What the grantee ended up holding, as decided by the *kernel* (not by what anyone
/// asked for): the input to the reachable-authority-auditor check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedCap {
    pub slot: u32,
    pub kind: ObjectKind,
    pub rights: Rights,
    pub deadline: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ActiveGrant {
    pub role_id: &'static str,
    pub grantee_label: String,
    pub caps: Vec<GrantedCap>,
    pub issued_at: u64,
}

/// Runs under the grantor's identity. Owns exactly one grant root; revoke() removes
/// the whole grant — every cap minted under it, from every CSpace — whoever currently
/// holds them (I4, cross-grantee revocation). Retains a grant registry so the
/// "always-visible, easy-to-audit grant list" (§9.2) is a real, queryable thing
/// rather than a UI abstraction.
pub struct GrantService {
    grantor: TaskHandle,
    grant_root: CapHandle,
    registry: Vec<ActiveGrant>,
}

impl GrantService {
    pub fn new(
        kernel: &mut Kernel,
        grantor: TaskHandle,
        creator: CapHandle,
    ) -> KernelResult<GrantService> {
        let grant_root = kernel.create_grant_root(grantor, creator)?;
        Ok(GrantService {
            grantor,
            grant_root,
            registry: Vec::new(),
        })
    }

    /// The current grant list: every grant this service has confirmed and not yet
    /// revoked, with role, grantee, deadline (None = persistent) and issue time.
    pub fn list_active(&self) -> &[ActiveGrant] {
        &self.registry
    }

    /// Validate a role grant request and produce its diff for human review. Rejected
    /// up front if: the role is unknown, the grantor cannot supply the requested
    /// rights, or the policy is persistent on a role that forbids it.
    pub fn propose(
        &self,
        kernel: &Kernel,
        library: &crate::role::RoleLibrary,
        role_id: &str,
        grantee_label: &str,
        grantee: CapHandle,
        target: GrantTarget,
        policy: GrantPolicy,
    ) -> KernelResult<PendingGrant> {
        let role = library
            .get(role_id)
            .ok_or(KernelError::InvalidOperation)?;
        if role.requests.len() != 1 {
            return Err(KernelError::InvalidOperation); // v1: single-request roles
        }
        match policy {
            GrantPolicy::Persistent if !role.allow_persistent => {
                return Err(KernelError::InvalidOperation); // §9.2 gate
            }
            _ => {}
        }
        let request = &role.requests[0];
        let info = kernel
            .cap_info(self.grantor, target.source)
            .map_err(|_| KernelError::NoCap)?;
        if info.kind != request.kind {
            return Err(KernelError::WrongObjectType);
        }
        if !info.rights.superset_of(request.rights) {
            return Err(KernelError::InsufficientRights(request.rights));
        }
        Ok(PendingGrant {
            role_id: role.id,
            grantee_label: grantee_label.to_string(),
            grantee,
            target,
            policy,
            request: *request,
        })
    }

    /// The diff a human reviews before confirming (§9.3): additions only, expansion
    /// beyond the current role is impossible here by construction.
    pub fn diff(pending: &PendingGrant) -> Vec<DiffLine> {
        let policy = match pending.policy {
            GrantPolicy::TaskScoped { ticks } => {
                format!("expires in {ticks} ticks or on completion")
            }
            GrantPolicy::Persistent => "persistent (separate confirmation flow)".to_string(),
        };
        vec![DiffLine {
            note: pending.request.note,
            kind: pending.request.kind,
            rights: pending.request.rights,
            target_label: pending.target.label.clone(),
            policy,
        }]
    }

    /// Mint the grant after review. The kernel re-checks every authority assumption at
    /// mint time: if the grantor lost the source cap between review and confirm, this
    /// fails. Returns what the grantee actually holds.
    pub fn confirm(
        &mut self,
        kernel: &mut Kernel,
        pending: PendingGrant,
    ) -> KernelResult<ActiveGrant> {
        let expiry = match pending.policy {
            GrantPolicy::TaskScoped { ticks } => Some(kernel.now() + ticks),
            GrantPolicy::Persistent => None,
        };
        let slot = kernel.grant_mint(
            self.grantor,
            self.grant_root,
            pending.target.source,
            pending.grantee,
            pending.request.rights,
            expiry,
        )?;
        let cap = GrantedCap {
            slot: slot.0,
            kind: pending.request.kind, // validated == kernel-declared rights
            rights: pending.request.rights,
            deadline: expiry,
        };
        let active = ActiveGrant {
            role_id: pending.role_id,
            grantee_label: pending.grantee_label,
            caps: vec![cap],
            issued_at: kernel.now(),
        };
        self.registry.push(active.clone());
        Ok(active)
    }

    /// The task-scoped half of "expires on completion": the supervisor calls this when
    /// the bound task ends. Every cap of the grant vanishes — from the agent's CSpace
    /// and anywhere the agent managed to push them (it cannot, but the kernel's
    /// derivation graph would catch it if it had). A revoked grant leaves the list.
    pub fn revoke(&mut self, kernel: &mut Kernel) -> KernelResult<()> {
        kernel.revoke(self.grantor, self.grant_root)?;
        self.registry.clear();
        Ok(())
    }
}
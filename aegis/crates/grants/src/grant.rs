//! The grant service (design doc §9): role-shaped, ephemeral-by-default grants minted
//! under a grant root so revoking one anchor removes the whole grant from every CSpace.
//! Every minted right is recorded; every use is in the kernel audit log.

use capability_core::{
    CapHandle, Kernel, KernelError, KernelResult, ObjectId, ObjectKind, Rights, TaskHandle,
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
    /// Filled by `propose` from the role definition: high-risk roles can never
    /// be confirmed by a single party (§9: two-party confirmation for
    /// irreversible actions).
    pub high_risk: bool,
}

/// A high-risk grant mid-confirmation: one party has approved; the mint
/// happens only after a *different* party confirms (§9, two-party
/// confirmation — "the same control banks use for wire transfers over a
/// threshold").
#[derive(Debug)]
pub struct PendingTwoParty {
    pub role_id: &'static str,
    pub grantee_label: String,
    pub grantee: CapHandle,
    pub target: GrantTarget,
    pub policy: GrantPolicy,
    pub request: crate::role::CapRequest,
    pub first: ObjectId,
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
    /// Who confirmed this grant. One entry = single-party; two distinct
    /// entries = two-party confirmation (§9).
    pub approvals: Vec<ObjectId>,
}

/// One entry of the service's policy log: every suspension, resumption, and
/// refused confirmation — the "distinct, more visible confirmation flow"
/// (§9.2) made auditable, and the "suspension is reversible and logged,
/// silent permanent revocation is not" (§9) record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEvent {
    Suspended {
        at: u64,
        agent: ObjectId,
        reason: String,
    },
    Resumed {
        at: u64,
        agent: ObjectId,
    },
    ConfirmationRefused {
        at: u64,
        agent: ObjectId,
        role: &'static str,
        reason: &'static str,
    },
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
    /// Agents whose grants are suspended by the anomaly monitor, pending
    /// human review (§9). Suspension is ledger state: reversible, logged, and
    /// *not* revocation — already-minted caps stay live.
    suspended: Vec<ObjectId>,
    policy_log: Vec<PolicyEvent>,
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
            suspended: Vec::new(),
            policy_log: Vec::new(),
        })
    }

    /// The current grant list: every grant this service has confirmed and not yet
    /// revoked, with role, grantee, deadline (None = persistent) and issue time.
    pub fn list_active(&self) -> &[ActiveGrant] {
        &self.registry
    }

    /// The policy log: suspensions, resumptions, refused confirmations.
    pub fn policy_log(&self) -> &[PolicyEvent] {
        &self.policy_log
    }

    pub fn is_suspended(&self, agent: ObjectId) -> bool {
        self.suspended.contains(&agent)
    }

    /// Validate a role grant request and produce its diff for human review. Rejected
    /// up front if: the role is unknown, the grantor cannot supply the requested
    /// rights, or the policy is persistent on a role that forbids it.
    #[allow(clippy::too_many_arguments)]
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
        let role = library.get(role_id).ok_or(KernelError::InvalidOperation)?;
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
            high_risk: role.high_risk,
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
        if pending.high_risk {
            // §9: a role that touches irreversible actions cannot be confirmed
            // by a single click — two-party confirmation is the only path.
            let agent = kernel
                .cap_info(self.grantor, pending.grantee)
                .map_err(|_| KernelError::NoCap)?
                .obj;
            self.policy_log.push(PolicyEvent::ConfirmationRefused {
                at: kernel.now(),
                agent,
                role: pending.role_id,
                reason: "high-risk role requires two-party confirmation",
            });
            return Err(KernelError::InvalidOperation);
        }
        // The anomaly circuit breaker (§9): a suspended agent's *whole grant
        // flow* is frozen pending human review — suspension blocks new
        // confirmations, while the already-minted caps stay live.
        let agent = kernel
            .cap_info(self.grantor, pending.grantee)
            .map_err(|_| KernelError::NoCap)?
            .obj;
        if self.is_suspended(agent) {
            self.policy_log.push(PolicyEvent::ConfirmationRefused {
                at: kernel.now(),
                agent,
                role: pending.role_id,
                reason: "agent's grants are suspended pending human review",
            });
            return Err(KernelError::InvalidOperation);
        }
        let active = self.mint(kernel, pending, vec![])?;
        Ok(active)
    }

    /// Open a two-party confirmation for a high-risk grant (§9: "a two-party
    /// confirmation rather than a single click"). `first` is the first human
    /// reviewer; the grant still does not exist.
    pub fn open_two_party(
        &mut self,
        _kernel: &Kernel,
        pending: PendingGrant,
        first: TaskHandle,
    ) -> KernelResult<PendingTwoParty> {
        if !pending.high_risk {
            return Err(KernelError::InvalidOperation);
        }
        Ok(PendingTwoParty {
            role_id: pending.role_id,
            grantee_label: pending.grantee_label,
            grantee: pending.grantee,
            target: pending.target,
            policy: pending.policy,
            request: pending.request,
            first: first.id(),
        })
    }

    /// The second, *different* party confirms; only now does the mint happen.
    /// One person approving twice is refused — two-party means two.
    pub fn confirm_second(
        &mut self,
        kernel: &mut Kernel,
        pending: PendingTwoParty,
        second: TaskHandle,
    ) -> KernelResult<ActiveGrant> {
        let agent = kernel
            .cap_info(self.grantor, pending.grantee)
            .map_err(|_| KernelError::NoCap)?
            .obj;
        if second.id() == pending.first {
            self.policy_log.push(PolicyEvent::ConfirmationRefused {
                at: kernel.now(),
                agent,
                role: pending.role_id,
                reason: "second confirmer must be a different person",
            });
            return Err(KernelError::InvalidOperation);
        }
        if self.is_suspended(agent) {
            self.policy_log.push(PolicyEvent::ConfirmationRefused {
                at: kernel.now(),
                agent,
                role: pending.role_id,
                reason: "agent's grants are suspended pending human review",
            });
            return Err(KernelError::InvalidOperation);
        }
        let active = self.mint(
            kernel,
            PendingGrant {
                role_id: pending.role_id,
                grantee_label: pending.grantee_label,
                grantee: pending.grantee,
                target: pending.target,
                policy: pending.policy,
                request: pending.request,
                high_risk: true,
            },
            vec![pending.first, second.id()],
        )?;
        Ok(active)
    }

    fn mint(
        &mut self,
        kernel: &mut Kernel,
        pending: PendingGrant,
        approvals: Vec<ObjectId>,
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
            approvals,
        };
        self.registry.push(active.clone());
        Ok(active)
    }

    /// The anomaly monitor's circuit breaker (§9): auto-suspend, never
    /// auto-revoke. Suspension is ledger state — the already-minted caps stay
    /// live (revocation is permanent; suspension is neither), and every new
    /// confirmation for the agent is refused until a human resumes it.
    pub fn suspend(&mut self, kernel: &Kernel, agent: TaskHandle, reason: &str) {
        let id = agent.id();
        if !self.suspended.contains(&id) {
            self.suspended.push(id);
        }
        self.policy_log.push(PolicyEvent::Suspended {
            at: kernel.now(),
            agent: id,
            reason: reason.to_string(),
        });
    }

    /// Human review clears the suspension: reversible, logged, never silent.
    pub fn resume(&mut self, kernel: &Kernel, agent: TaskHandle) {
        let id = agent.id();
        self.suspended.retain(|a| *a != id);
        self.policy_log.push(PolicyEvent::Resumed {
            at: kernel.now(),
            agent: id,
        });
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

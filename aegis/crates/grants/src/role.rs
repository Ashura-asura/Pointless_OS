//! The role library (design doc §9.1): task-shaped roles defined by the *system*, not
//! by the agent requesting them. A role expands to a specific, narrow, auditable
//! capability set; the role is the reviewable unit.

use capability_core::{ObjectKind, Rights};

/// One capability a role requires. `rights` is the *exact* set the grantee will be
/// allowed — the system declares it, not the requesting agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapRequest {
    pub kind: ObjectKind,
    pub rights: Rights,
    pub note: &'static str,
}

const RESTART_SERVICE_REQS: [CapRequest; 1] = [CapRequest {
    kind: ObjectKind::Task,
    rights: Rights::READ.union(Rights::CONTROL),
    note: "read the named service's state and restart it",
}];

const TRIAGE_INBOX_REQS: [CapRequest; 1] = [CapRequest {
    kind: ObjectKind::Endpoint,
    rights: Rights::SEND,
    note: "submit already-classified triage results (no reads)",
}];

const MODIFY_POLICY_REQS: [CapRequest; 1] = [CapRequest {
    kind: ObjectKind::Task,
    rights: Rights::CONTROL,
    note: "modify the security-policy service's configuration (irreversible)",
}];

/// A task-shaped role.
#[derive(Debug, Clone, Copy)]
pub struct Role {
    pub id: &'static str,
    pub name: &'static str,
    /// Whether this role may ever be granted persistently. False by default
    /// (§9.2: grants default to ephemeral and task-scoped).
    pub allow_persistent: bool,
    /// Whether this role touches irreversible actions (§9: anything touching
    /// "deleting data, sending money, modifying security policy itself").
    /// High-risk roles require two-party confirmation, never a single click.
    pub high_risk: bool,
    pub requests: &'static [CapRequest],
}

/// The registry of roles the system knows. Reviewable once per role type, not per app.
pub struct RoleLibrary {
    roles: Vec<Role>,
}

impl RoleLibrary {
    pub fn default_roles() -> RoleLibrary {
        RoleLibrary {
            roles: vec![
                Role {
                    id: "restart-service",
                    name: "Restart a named service",
                    allow_persistent: false,
                    high_risk: false,
                    requests: &RESTART_SERVICE_REQS,
                },
                Role {
                    id: "triage-inbox",
                    name: "Triage my inbox",
                    allow_persistent: true,
                    high_risk: false,
                    requests: &TRIAGE_INBOX_REQS,
                },
                Role {
                    id: "modify-security-policy",
                    name: "Modify security policy",
                    allow_persistent: true,
                    high_risk: true,
                    requests: &MODIFY_POLICY_REQS,
                },
            ],
        }
    }

    pub fn get(&self, id: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_role_is_narrow_and_never_persistent() {
        let lib = RoleLibrary::default_roles();
        let role = lib.get("restart-service").unwrap();
        assert!(!role.allow_persistent);
        assert_eq!(role.requests.len(), 1);
        let req = &role.requests[0];
        assert_eq!(req.kind, ObjectKind::Task);
        // Control, not GRANT: the agent can restart, never re-delegate.
        assert!(!req.rights.contains(Rights::GRANT));
    }
}

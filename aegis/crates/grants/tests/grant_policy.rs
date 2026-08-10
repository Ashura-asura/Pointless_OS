//! Executable checks for the grant-policy claims of the design doc (§9.1-9.3):
//! roles are task-shaped and system-defined; grants default to ephemeral and
//! task-scoped; persistent grants are gated per role by a distinct confirmation
//! path; and confirm re-checks authority at mint time (a review is never a
//! TOCTOU hole). Enforcement here: the policy gates are kernel+service enforced,
//! not advisory; the kernel clock kills task-scoped grants; revocation on task
//! completion removes the grant from every CSpace (I4).

use capability_core::{AuditFilter, CapHandle, Kernel, OpKind, TaskHandle};
use grants::role::RoleLibrary;
use grants::{GrantPolicy, GrantService, GrantTarget};

fn boot() -> (Kernel, TaskHandle, CapHandle) {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    (k, root, creator)
}

fn task(
    k: &mut Kernel,
    root: TaskHandle,
    creator: CapHandle,
    label: &str,
) -> (TaskHandle, CapHandle) {
    k.create_task(root, creator, label).unwrap()
}

/// The restart-service role is ephemeral-only: the persistent policy is refused
/// at propose time (§9.2 gate), while a persistent-permissible role (triage-inbox)
/// is accepted. The gate is the *role's*, not the caller's, judgment.
#[test]
fn persistent_policy_is_gated_per_role() {
    let (mut k, root, creator) = boot();
    let (_smtp, smtp_cap) = task(&mut k, root, creator, "smtp");
    let agent_cap = task(&mut k, root, creator, "agent").1;
    let svc = GrantService::new(&mut k, root, creator).unwrap();
    let lib = RoleLibrary::default_roles();

    let ephemeral = GrantPolicy::TaskScoped { ticks: 5 };
    let persistent = GrantPolicy::Persistent;

    // Ephemeral: fine for both roles.
    assert!(svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "agent",
            agent_cap,
            GrantTarget {
                label: "smtp".into(),
                source: smtp_cap
            },
            ephemeral,
        )
        .is_ok());
    // Persistent on an ephemeral-only role: refused.
    assert!(svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "agent",
            agent_cap,
            GrantTarget {
                label: "smtp".into(),
                source: smtp_cap
            },
            persistent,
        )
        .is_err());
    // Persistent on a role that permits it: accepted. Triage-inbox's target is an
    // endpoint, and the grantor must be able to supply one.
    let inbox_ep = k.create_endpoint(root, creator).unwrap();
    assert!(svc
        .propose(
            &k,
            &lib,
            "triage-inbox",
            "agent",
            agent_cap,
            GrantTarget {
                label: "inbox".into(),
                source: inbox_ep
            },
            persistent,
        )
        .is_ok());
}

/// Task-scoped means real: the kernel clock kills the grant, and the ActiveGrant
/// records the exact deadline the grantee is held to.
#[test]
fn ephemeral_grants_die_on_the_kernel_clock() {
    let (mut k, root, creator) = boot();
    let (_smtp, smtp_cap) = task(&mut k, root, creator, "smtp");
    let (agent, agent_cap) = task(&mut k, root, creator, "agent");
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    let lib = RoleLibrary::default_roles();

    let pending = svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "agent",
            agent_cap,
            GrantTarget {
                label: "smtp".into(),
                source: smtp_cap,
            },
            GrantPolicy::TaskScoped { ticks: 5 },
        )
        .unwrap();
    let active = svc.confirm(&mut k, pending).unwrap();
    assert_eq!(
        active.caps[0].deadline,
        Some(k.now() + 5),
        "the grantee is held to the declared deadline"
    );
    assert!(k.task_spawn(agent, CapHandle(active.caps[0].slot)).is_ok());

    // Before the deadline: still live. After the clock passes it: dead — expiry is
    // enforced by lookup, not by policy.
    k.advance(4);
    assert!(k.task_spawn(agent, CapHandle(active.caps[0].slot)).is_ok());
    k.advance(2);
    assert!(k.task_spawn(agent, CapHandle(active.caps[0].slot)).is_err());
}

/// The "expires on completion" half: revoke removes the grant from the grantee's
/// CSpace but never touches the grantor's own cap (I4 subtree from the root).
#[test]
fn completion_revoke_removes_the_grant_and_only_the_grant() {
    let (mut k, root, creator) = boot();
    let (smtp, smtp_cap) = task(&mut k, root, creator, "smtp");
    let (agent, agent_cap) = task(&mut k, root, creator, "agent");
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    let lib = RoleLibrary::default_roles();

    let pending = svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "agent",
            agent_cap,
            GrantTarget {
                label: "smtp".into(),
                source: smtp_cap,
            },
            GrantPolicy::TaskScoped { ticks: 100 },
        )
        .unwrap();
    let active = svc.confirm(&mut k, pending).unwrap();
    svc.revoke(&mut k).unwrap();

    // The grantee lost the cap…
    assert!(k.task_spawn(agent, CapHandle(active.caps[0].slot)).is_err());
    // …the grantor kept its own.
    assert!(k.task_running(root, smtp_cap).is_ok());
    // The whole life of the grant is on record: mint and revoke, both audited.
    assert!(k
        .audit()
        .ever_succeeded(root.id(), OpKind::Grant, smtp.id()));
    assert_eq!(
        k.audit()
            .query(Some(root.id()), AuditFilter::Ops(&[OpKind::Revoke]))
            .count(),
        1
    );
}

/// The §9.2 visibility claim: the always-visible grant list is a queryable
/// registry, not a UI abstraction — it shows every confirmed grant with its role,
/// grantee and deadline (None = persistent), and a grant leaves the list when
/// revoked.
#[test]
fn the_active_grant_list_is_queryable_and_honest() {
    let (mut k, root, creator) = boot();
    let (_smtp, smtp_cap) = task(&mut k, root, creator, "smtp");
    let inbox_ep = k.create_endpoint(root, creator).unwrap();
    let (_agent, agent_cap) = task(&mut k, root, creator, "agent");
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    let lib = RoleLibrary::default_roles();

    let ephemeral = svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "agent",
            agent_cap,
            GrantTarget {
                label: "smtp".into(),
                source: smtp_cap,
            },
            GrantPolicy::TaskScoped { ticks: 100 },
        )
        .unwrap();
    svc.confirm(&mut k, ephemeral).unwrap();
    let persistent = svc
        .propose(
            &k,
            &lib,
            "triage-inbox",
            "agent",
            agent_cap,
            GrantTarget {
                label: "inbox".into(),
                source: inbox_ep,
            },
            GrantPolicy::Persistent,
        )
        .unwrap();
    svc.confirm(&mut k, persistent).unwrap();

    let list = svc.list_active();
    assert_eq!(
        list.len(),
        2,
        "both grants are visible, persistent one included"
    );
    let persistent_grant = list.iter().find(|g| g.role_id == "triage-inbox").unwrap();
    assert_eq!(
        persistent_grant.caps[0].deadline, None,
        "persistent is honestly marked"
    );
    let task_scoped = list
        .iter()
        .find(|g| g.role_id == "restart-service")
        .unwrap();
    assert!(
        task_scoped.caps[0].deadline.is_some(),
        "task-scoped grants carry their deadline"
    );

    svc.revoke(&mut k).unwrap();
    assert!(
        svc.list_active().is_empty(),
        "revoked grants leave the visible list"
    );
}
/// A review is never a TOCTOU hole: if the grantor's authority disappears between
/// propose and confirm, confirm fails — the mint re-checks every assumption.
#[test]
fn confirm_rechecks_authority_after_review() {
    let (mut k, root, creator) = boot();
    let (_smtp, smtp_cap) = task(&mut k, root, creator, "smtp");
    let agent_cap = task(&mut k, root, creator, "agent").1;
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    let lib = RoleLibrary::default_roles();

    let pending = svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "agent",
            agent_cap,
            GrantTarget {
                label: "smtp".into(),
                source: smtp_cap,
            },
            GrantPolicy::TaskScoped { ticks: 100 },
        )
        .unwrap();
    // Between review and confirm, the grantor's source cap is revoked.
    k.revoke(root, smtp_cap).unwrap();
    assert!(svc.confirm(&mut k, pending).is_err());
    // The refused mint is audited, like any other refusal.
    assert_eq!(
        k.audit()
            .query(Some(root.id()), AuditFilter::Ops(&[OpKind::Grant]))
            .filter(|r| !r.ok)
            .count(),
        1,
        "the refused mint is on record"
    );
}

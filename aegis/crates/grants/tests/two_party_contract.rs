//! Executable checks for the two-party confirmation claim of the design doc
//! (§9: the highest-risk persistent grants — "anything touching irreversible
//! actions: deleting data, sending money, modifying security policy itself" —
//! require a two-party confirmation rather than a single click).

use capability_core::{CapHandle, Kernel, Rights, TaskHandle};
use grants::role::RoleLibrary;
use grants::{GrantPolicy, GrantService, GrantTarget};

fn boot() -> (Kernel, TaskHandle, CapHandle) {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    (k, root, creator)
}

fn task(k: &mut Kernel, root: TaskHandle, creator: CapHandle, label: &str) -> (TaskHandle, CapHandle) {
    k.create_task(root, creator, label).unwrap()
}

/// The high-risk role grant proposal: modify-security-policy, a persistent
/// grant over the policy-service task, targeted at `agent`.
fn high_risk_proposal(
    k: &mut Kernel,
    _root: TaskHandle,
    svc: &GrantService,
    lib: &RoleLibrary,
    agent_cap: CapHandle,
    policy_task_cap: CapHandle,
) -> grants::PendingGrant {
    svc.propose(
        k,
        lib,
        "modify-security-policy",
        "admin-agent",
        agent_cap,
        GrantTarget {
            label: "security-policy-service".into(),
            source: policy_task_cap,
        },
        GrantPolicy::Persistent,
    )
    .unwrap()
}

#[test]
fn a_single_click_cannot_confirm_a_high_risk_grant() {
    let (mut k, root, creator) = boot();
    let (policy_svc, policy_cap) = task(&mut k, root, creator, "policy-svc");
    let (agent, agent_cap) = task(&mut k, root, creator, "admin-agent");
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    let lib = RoleLibrary::default_roles();

    // The proposal itself is fine (role is known, grantor can supply CONTROL
    // over the policy service).
    let pending = high_risk_proposal(&mut k, root, &svc, &lib, agent_cap, policy_cap);

    // One person confirming is flatly refused — and the refusal is on the
    // policy log as a distinct event, not a silent no.
    let err = svc.confirm(&mut k, pending).unwrap_err();
    assert_eq!(err, capability_core::KernelError::InvalidOperation);
    assert!(svc.policy_log().iter().any(|e| matches!(
        e,
        grants::PolicyEvent::ConfirmationRefused { role: "modify-security-policy", .. }
    )));
    // No mint happened: no grants active, and the agent holds nothing.
    assert!(svc.list_active().is_empty());
    assert!(k.caps_of(agent).len() == 1, "agent still holds only its self-cap");
    let _ = policy_svc;
}

#[test]
fn two_party_confirmation_mints_only_after_two_distinct_people() {
    let (mut k, root, creator) = boot();
    let (policy_svc, policy_cap) = task(&mut k, root, creator, "policy-svc");
    let (agent, agent_cap) = task(&mut k, root, creator, "admin-agent");
    let (alice, _) = task(&mut k, root, creator, "reviewer-alice");
    let (bob, _) = task(&mut k, root, creator, "reviewer-bob");
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    let lib = RoleLibrary::default_roles();

    let pending = high_risk_proposal(&mut k, root, &svc, &lib, agent_cap, policy_cap);
    let two_party = svc.open_two_party(&k, pending, alice).unwrap();

    // Alice approving twice is refused: two-party means two different people.
    // (The grant does not exist yet either way.)
    assert!(svc.confirm_second(&mut k, two_party, alice).is_err());
    assert!(svc.list_active().is_empty());
    assert!(svc
        .policy_log()
        .iter()
        .any(|e| matches!(e, grants::PolicyEvent::ConfirmationRefused {
            reason: "second confirmer must be a different person",
            ..
        })));

    // Bob (a different person) confirms: the mint happens, and the grant
    // records both approvals — the "distinct, more visible confirmation flow".
    let two_party = high_risk_proposal(&mut k, root, &svc, &lib, agent_cap, policy_cap);
    let two_party = svc.open_two_party(&k, two_party, alice).unwrap();
    let active = svc.confirm_second(&mut k, two_party, bob).unwrap();
    assert_eq!(active.approvals, vec![alice.id(), bob.id()]);
    assert_eq!(svc.list_active().len(), 1);
    // The grantee actually holds CONTROL over the policy service.
    let agent_caps = k.caps_of(agent);
    let hold = agent_caps
        .iter()
        .find(|c| c.obj == policy_svc.id())
        .expect("the agent holds the policy-service capability");
    assert!(hold.rights.contains(Rights::CONTROL));
}

#[test]
fn non_high_risk_role_cannot_abuse_the_two_party_path() {
    let (mut k, root, creator) = boot();
    let (_smtp, smtp_cap) = task(&mut k, root, creator, "smtp");
    let (_agent, agent_cap) = task(&mut k, root, creator, "agent");
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    let lib = RoleLibrary::default_roles();

    // A normal role uses the normal single-confirmation path…
    let pending = svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "agent",
            agent_cap,
            GrantTarget { label: "smtp".into(), source: smtp_cap },
            GrantPolicy::TaskScoped { ticks: 5 },
        )
        .unwrap();
    assert!(!pending.high_risk);
    let (alice, _) = task(&mut k, root, creator, "reviewer");
    // …and cannot be routed through the two-party door: that door exists for
    // irreversible actions only.
    assert!(svc.open_two_party(&k, pending, alice).is_err());
}
//! Executable checks for the invariants stated in `aegis/spec/capability-model.md`:
//! I2 (delegation monotonicity), I4 (cross-grantee, transitive revocation), I5
//! (kernel-enforced ephemerality, inheritance, no extension), and the failure-audit
//! guarantee.

use capability_core::{
    AuditFilter, CapHandle, Kernel, KernelError, ObjectKind, OpKind, Rights, TaskHandle,
};

fn boot() -> (Kernel, TaskHandle, CapHandle) {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    (k, root, creator)
}

fn smtp_server(k: &mut Kernel, root: TaskHandle, creator: CapHandle) -> (TaskHandle, CapHandle) {
    k.create_task(root, creator, "smtp").unwrap()
}

fn caps_of(k: &Kernel, t: TaskHandle) -> Vec<(ObjectKind, Rights)> {
    k.authorized(t)
        .iter()
        .map(|c| (c.kind, c.rights))
        .collect()
}

/// Every task's self cap lives in slot 0, and within a test the grant order is fixed
/// (slots are allocated first-free), so capability slots are deterministic: grant N
/// into a task's fresh CSpace lands in slot N. Tests therefore address caps by slot
/// rather than by matching rights — matching on compound right sets is brittle, and
/// slot addressing is exactly how a task would address its own CSpace.

/// I2 — delegation monotonicity: a grant can never carry more rights than the source
/// cap the grantor holds, however much is requested.
#[test]
fn delegation_can_never_expand_rights() {
    let (mut k, root, creator) = boot();
    let (_smtp, smtp_cap) = smtp_server(&mut k, root, creator);

    let (bob, bob_cap) = k.create_task(root, creator, "bob").unwrap();
    let (zed, zed_cap) = k.create_task(root, creator, "zed").unwrap();
    let (wally, wally_cap) = k.create_task(root, creator, "wally").unwrap();

    // root -> bob: CONTROL|GRANT on smtp (slot 1) + naming cap to zed (slot 2).
    k.grant(root, smtp_cap, bob_cap, Rights::GRANT.union(Rights::CONTROL), None)
        .unwrap();
    k.grant(root, zed_cap, bob_cap, Rights::CONTROL, None).unwrap();

    // bob -> zed: bob asks for EVERYTHING. The kernel clamps to bob's CONTROL|GRANT.
    // Zed now holds: self (0), smtp C|G (1).
    k.grant(bob, CapHandle(1), CapHandle(2), Rights::ALL, None).unwrap();
    assert_eq!(
        caps_of(&k, zed),
        vec![
            (ObjectKind::Task, Rights::ALL),
            (ObjectKind::Task, Rights::GRANT.union(Rights::CONTROL)),
        ]
    );
    // Zed may kill smtp (CONTROL)…
    assert!(k.task_kill(zed, CapHandle(1)).is_ok());
    k.task_spawn(zed, CapHandle(1)).unwrap();

    // zed -> wally: zed narrows to CONTROL (subset of its own C|G — the kernel mints
    // rights ∩ source, so a grantor can only pass rights it holds).
    // root also gave zed a naming cap to wally (slot 2). Wally: self (0), smtp C (1).
    k.grant(root, wally_cap, zed_cap, Rights::CONTROL, None).unwrap();
    k.grant(zed, CapHandle(1), CapHandle(2), Rights::CONTROL, None).unwrap();
    assert!(k.task_spawn(wally, CapHandle(1)).is_ok());

    // wally cannot delegate: no GRANT on its source (wally's cap is exactly C). The
    // kernel refuses, loudly — nobody can mint rights they don't hold (I2).
    assert_eq!(
        k.grant(wally, CapHandle(1), CapHandle(0), Rights::READ, None).unwrap_err(),
        KernelError::InsufficientRights(Rights::GRANT)
    );
    // Wally's smtp cap is precisely CONTROL — narrowly scoped, no more.
    assert_eq!(
        caps_of(&k, wally),
        vec![
            (ObjectKind::Task, Rights::ALL),
            (ObjectKind::Task, Rights::CONTROL),
        ]
    );
}

/// I4 — revocation is transitive and cross-grantee, even through chains: the grantor
/// never needs to know where its grants went.
#[test]
fn revocation_removes_derived_caps_from_all_cspaces() {
    let (mut k, root, creator) = boot();
    let (_smtp, smtp_cap) = smtp_server(&mut k, root, creator);

    // root -> bob: GRANT+CONTROL on smtp (so bob may narrow and re-delegate), plus a
    // task cap to carol so bob can name carol.
    let (bob, bob_cap) = k.create_task(root, creator, "bob").unwrap();
    let (carol, carol_cap) = k.create_task(root, creator, "carol").unwrap();
    k.grant(root, smtp_cap, bob_cap, Rights::GRANT.union(Rights::CONTROL), None)
        .unwrap();
    k.grant(root, carol_cap, bob_cap, Rights::CONTROL, None).unwrap();

    // bob -> carol: bob hands carol CONTROL (subset of bob's own C|G — the kernel
    // mints rights ∩ source, so carol can never exceed bob). Carol: self (0), smtp C (1).
    k.grant(bob, CapHandle(1), CapHandle(2), Rights::CONTROL, None).unwrap();
    assert_eq!(
        caps_of(&k, carol),
        vec![(ObjectKind::Task, Rights::ALL), (ObjectKind::Task, Rights::CONTROL)]
    );

    // Root revokes its smtp cap. The whole subtree dies: bob's C|G and carol's READ.
    k.revoke(root, smtp_cap).unwrap();
    // bob keeps: the self cap + the carol task cap (chain rooted in root's *carol*
    // cap, which was not revoked).
    assert_eq!(
        caps_of(&k, bob),
        vec![
            (ObjectKind::Task, Rights::ALL),
            (ObjectKind::Task, Rights::CONTROL),
        ]
    );
    // carol keeps only its self cap.
    assert_eq!(caps_of(&k, carol), vec![(ObjectKind::Task, Rights::ALL)]);
}

/// I4' — grant-mint under a grant root: revoking the anchor removes the grant caps
/// from *every* grantee's CSpace at once, and the grantor's own caps survive.
#[test]
fn grant_root_revocation_cleans_every_grantee() {
    let (mut k, root, creator) = boot();
    let (smtp, smtp_cap) = smtp_server(&mut k, root, creator);
    let (bob, bob_cap) = k.create_task(root, creator, "bob").unwrap();
    let (carol, carol_cap) = k.create_task(root, creator, "carol").unwrap();

    let grant_root = k.create_grant_root(root, creator).unwrap();
    k.grant_mint(root, grant_root, smtp_cap, bob_cap, Rights::CONTROL, None)
        .unwrap();
    k.grant_mint(root, grant_root, smtp_cap, carol_cap, Rights::CONTROL, None)
        .unwrap();
    assert!(caps_of(&k, bob).contains(&(ObjectKind::Task, Rights::CONTROL)));
    assert!(caps_of(&k, carol).contains(&(ObjectKind::Task, Rights::CONTROL)));

    // Revoke the anchor: both grantees lose the cap; root keeps its own.
    k.revoke(root, grant_root).unwrap();
    assert_eq!(caps_of(&k, bob), vec![(ObjectKind::Task, Rights::ALL)]);
    assert_eq!(caps_of(&k, carol), vec![(ObjectKind::Task, Rights::ALL)]);
    assert!(k.task_spawn(root, smtp_cap).is_ok());
}

/// I5 — ephemerality is kernel-enforced: copies inherit the parent's remaining life,
/// a requested extension is clamped, and every use fails after the deadline.
#[test]
fn expiry_kills_caps_and_cannot_be_extended() {
    let (mut k, root, creator) = boot();
    let (_smtp, smtp_cap) = smtp_server(&mut k, root, creator);

    // bob gets ALL on smtp, but only until t=100 (a grant, not an ownership).
    let (bob, bob_cap) = k.create_task(root, creator, "bob").unwrap();
    let (carol, carol_cap) = k.create_task(root, creator, "carol").unwrap();
    k.grant(root, smtp_cap, bob_cap, Rights::ALL, Some(100)).unwrap();
    // bob also gets a task cap to carol so it can name carol when re-granting.
    k.grant(root, carol_cap, bob_cap, Rights::CONTROL, None).unwrap();

    // Bob: self (0), smtp ALL exp100 (1), carol cap (2). Bob copies — the copy is an
    // exact derivation of the parent grant (slot 3), so it inherits the deadline.
    let copy = k.copy(bob, CapHandle(1), Rights::READ).unwrap();
    assert!(k.task_running(bob, copy).is_ok(), "copy should work pre-deadline");

    // bob tries to extend: grant carol the cap with expiry 5000. The kernel clamps
    // to the source's remaining life (I5) — no op may push a deadline forward.
    k.grant(bob, CapHandle(1), CapHandle(2), Rights::CONTROL, Some(5000))
        .unwrap();
    let carol_smtp = CapHandle(1); // carol: self (0), smtp CONTROL exp100 (1).
    assert!(k.task_kill(carol, carol_smtp).is_ok(), "carol usable before deadline");

    // At t=101 everything derived from that grant is dead: bob's original, bob's
    // copy, and carol's would-be-extended cap.
    k.advance(101);
    assert_eq!(k.task_running(bob, CapHandle(1)).unwrap_err(), KernelError::CapExpired);
    assert_eq!(k.task_running(bob, copy).unwrap_err(), KernelError::CapExpired);
    assert_eq!(k.task_kill(carol, carol_smtp).unwrap_err(), KernelError::CapExpired);
}

/// Every failed operation lands in the audit log (spec §2), even failures that carry
/// no capability at all (forged handles).
#[test]
fn failed_operations_are_audited() {
    let (mut k, root, creator) = boot();
    let (smtp, smtp_cap) = smtp_server(&mut k, root, creator);
    let (bob, _bob_cap) = k.create_task(root, creator, "bob").unwrap();

    assert_eq!(
        k.task_kill(bob, CapHandle(u32::MAX)).unwrap_err(),
        KernelError::NoCap
    );
    // Root acting legitimately just so both success and failure paths are exercised.
    k.task_kill(root, smtp_cap).unwrap();

    let failures: Vec<_> = k
        .audit()
        .query(Some(bob.id()), AuditFilter::Failed)
        .collect();
    assert!(
        failures.iter().any(|r| r.op == OpKind::TaskKill),
        "bob's rejected TaskKill was not audited"
    );
}
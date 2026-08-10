//! The auditor's own tests: the property that makes the design-doc promise real is
//! that a violation *fails* — these fixtures prove the failure paths are detected,
//! and that honest systems audit clean.

use capability_audit::audit::audit;
use capability_audit::manifest::{Manifest, Repo};
use capability_audit::{AuditWarning, Violation};
use capability_core::{CapHandle, Kernel, ObjectKind, Rights, TaskHandle};
use grants::{GrantPolicy, GrantService, GrantTarget, RoleLibrary};

struct World {
    kernel: Kernel,
    root: TaskHandle,
    creator: CapHandle,
    smtp_cap: CapHandle,
    agent: TaskHandle,
    agent_cap: CapHandle,
}

fn world() -> World {
    let mut kernel = Kernel::new();
    let (root, _selfcap, creator) = kernel.boot("session").unwrap();
    let (smtp, smtp_cap) = kernel.create_task(root, creator, "smtp").unwrap();
    let (agent, agent_cap) = kernel.create_task(root, creator, "assistant").unwrap();
    let _ = smtp;
    World {
        kernel,
        root,
        creator,
        smtp_cap,
        agent,
        agent_cap,
    }
}

/// The role flow used by the demo: assistant gets "restart-service" over smtp.
fn grant_restart(w: &mut World) {
    let lib = RoleLibrary::default_roles();
    let mut svc = GrantService::new(&mut w.kernel, w.root, w.creator).unwrap();
    let pending = svc
        .propose(
            &w.kernel,
            &lib,
            "restart-service",
            "assistant",
            w.agent_cap,
            GrantTarget {
                label: "smtp".to_string(),
                source: w.smtp_cap,
            },
            GrantPolicy::TaskScoped { ticks: 1000 },
        )
        .unwrap();
    svc.confirm(&mut w.kernel, pending).unwrap();
}

fn session_manifest() -> Manifest {
    Manifest::new("session", Repo::Kernel)
        .allow(ObjectKind::Creator, Rights::ALL)
        .allow(ObjectKind::Task, Rights::ALL)
        .allow(ObjectKind::GrantRoot, Rights::GRANT)
}

fn assistant_manifest() -> Manifest {
    Manifest::new("assistant", Repo::Service)
        .allow(ObjectKind::Task, Rights::READ.union(Rights::CONTROL))
}

#[test]
fn honest_system_audits_clean() {
    let mut w = world();
    grant_restart(&mut w);
    let report = audit(
        &w.kernel,
        &[
            (w.root, &session_manifest()),
            (w.agent, &assistant_manifest()),
        ],
    );
    assert!(report.is_clean(), "honest system flagged: {report:?}");
    // The session holds GRANT-carrying naming caps into the assistant, so the
    // overhang of what it *could* push beyond the assistant's manifest is surfaced.
    assert!(
        report.warnings.contains_key("assistant"),
        "expected the session->assistant delivery overhang to be surfaced: {report:?}"
    );
}

/// The promise under test: reach grew beyond the manifest -> violation -> build break.
#[test]
fn reach_beyond_manifest_is_a_violation() {
    let mut w = world();
    grant_restart(&mut w);
    let mem = w
        .kernel
        .create_mem(w.root, w.creator, vec![0u8; 8])
        .unwrap();
    w.kernel
        .grant(w.root, mem, w.agent_cap, Rights::WRITE, None)
        .unwrap();
    let report = audit(&w.kernel, &[(w.agent, &assistant_manifest())]);
    assert!(!report.is_clean(), "build did not break: {report:?}");
    let vs = report.violations.get("assistant").unwrap();
    assert!(
        vs.iter().any(|v| matches!(
            v,
            Violation::Undeclared { pair }
                if pair.kind == ObjectKind::MemRegion && pair.rights == Rights::WRITE
        )),
        "undeclared mem-region WRITE not flagged: {vs:?}"
    );
}

/// A userspace repo may not request kernel-equivalent capabilities; the kernel repo may.
#[test]
fn kernel_equivalent_request_gated_by_repo_class() {
    let w = world();
    let service_wants_creator =
        Manifest::new("service", Repo::Service).allow(ObjectKind::Creator, Rights::ALL);
    let report = audit(&w.kernel, &[(w.root, &service_wants_creator)]);
    assert!(
        !report.is_clean(),
        "service repo with Creator audited clean"
    );
    assert!(
        report
            .violations
            .get("service")
            .unwrap()
            .iter()
            .any(|v| matches!(v, Violation::KernelEquivalent { .. })),
        "repo gate not enforced"
    );

    let report2 = audit(&w.kernel, &[(w.root, &session_manifest())]);
    assert!(report2.is_clean(), "kernel repo flagged: {report2:?}");
}

/// The structural self cap never needs declaring.
#[test]
fn structural_self_cap_is_exempt() {
    let w = world();
    let bare = Manifest::new("bare", Repo::Service);
    let report = audit(&w.kernel, &[(w.agent, &bare)]);
    assert!(report.is_clean(), "self-cap-only task flagged: {report:?}");
}

/// The delivery-overhang warning fires only when the target itself is narrower
/// than what a GRANT-holding grantor could push into it.
#[test]
fn delivery_overhang_tracks_the_declared_ceiling() {
    let mut w = world();
    grant_restart(&mut w);

    let report = audit(
        &w.kernel,
        &[
            (w.root, &session_manifest()),
            (w.agent, &assistant_manifest()),
        ],
    );
    let has_overhang = report.warnings.get("assistant").is_some_and(|ws| {
        ws.iter()
            .any(|x| matches!(x, AuditWarning::DeliveryOverhang { .. }))
    });
    assert!(has_overhang, "narrow target not warned: {report:?}");

    let wide_pet = assistant_manifest()
        .allow(ObjectKind::Creator, Rights::ALL)
        .allow(ObjectKind::GrantRoot, Rights::GRANT)
        .allow(ObjectKind::Task, Rights::ALL);
    let report2 = audit(
        &w.kernel,
        &[(w.root, &session_manifest()), (w.agent, &wide_pet)],
    );
    assert!(
        !report2.warnings.contains_key("assistant"),
        "wide target still warned: {report2:?}"
    );
}

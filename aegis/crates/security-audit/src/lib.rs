//! Aggregate security audit (Phase 12).
//!
//! Design doc §7 Phase 12: "Production hardening, security audits, real
//! hardware certification." This crate turns the reachable-authority audit
//! into an *aggregate* gate that runs as part of every `cargo test`: it builds
//! the reference system, audits every bound service against its compiled
//! manifest, and the contract tests below assert both the happy path (a
//! well-formed system is clean) and the negative paths (kernel-equivalent
//! demands, undeclared holdings, and delivery overhang all surface exactly as
//! the design doc says they must).
//!
//! Honest limits: this is a model-level security audit over the finite
//! reference scenario. It is NOT a certification of the implementation on real
//! hardware — see `../../../../Docs/SECURITY_AUDIT.md` for the certification status matrix
//! (every hardware-touching operation remains UNTESTED). It also cannot find
//! bugs the manifests/kernel model do not express.
//!
//! The crate is test-only: it exists to gate the build, not to ship a binary.

#![cfg(test)]

use capability_audit::audit::{audit, is_kernel_equivalent, Violation};
use capability_audit::manifest::{Declared, Manifest, Repo};
use capability_audit::manifests::{assistant, session};
use capability_audit::{reach, AuditReport};
use capability_core::{CapHandle, Kernel, ObjectKind, Rights, TaskHandle};
use grants::{GrantPolicy, GrantService, GrantTarget, RoleLibrary};

/// Build the reference world: boot session, supervised services, one
/// role-granted assistant (same scenario as `capability-audit`'s CI entry).
fn build_reference_world() -> (
    Kernel,
    TaskHandle,
    TaskHandle,
    CapHandle,
    CapHandle,
    CapHandle,
) {
    let mut k = Kernel::new();
    let (root, _root_self, root_creator) = k.boot("session").unwrap();
    let (_smtp, smtp_cap) = k.create_task(root, root_creator, "smtp").unwrap();
    let (_ntp, _ntp_cap) = k.create_task(root, root_creator, "ntp").unwrap();
    k.task_spawn(root, smtp_cap).unwrap();
    let (agent, agent_cap) = k.create_task(root, root_creator, "assistant").unwrap();

    let lib = RoleLibrary::default_roles();
    let mut svc = GrantService::new(&mut k, root, root_creator).unwrap();
    let pending = svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "assistant",
            agent_cap,
            GrantTarget {
                label: "smtp".to_string(),
                source: smtp_cap,
            },
            GrantPolicy::TaskScoped { ticks: 1000 },
        )
        .unwrap();
    svc.confirm(&mut k, pending).unwrap();
    (k, root, agent, agent_cap, smtp_cap, root_creator)
}

/// Audit the two bound services (session, assistant) of the reference world.
fn reference_report(k: &Kernel, root: TaskHandle, agent: TaskHandle) -> AuditReport {
    let session_m = session();
    let assistant_m = assistant();
    let bindings: Vec<(TaskHandle, &Manifest)> = vec![(root, &session_m), (agent, &assistant_m)];
    audit(k, &bindings)
}

#[test]
fn reference_world_is_clean() {
    let (k, root, agent, _, _, _) = build_reference_world();
    let report = reference_report(&k, root, agent);
    assert!(report.is_clean(), "reference world must have no violations");
    assert_eq!(report.violation_count(), 0);
    assert_eq!(report.entries.len(), 2);
}

#[test]
fn kernel_repo_may_declare_kernel_authority() {
    // The session lives in the kernel repo: Creator + Rights::ALL is legal.
    let s = session();
    assert!(s.repo.is_kernel());
    assert!(s
        .declares
        .iter()
        .any(|p| is_kernel_equivalent(p) && p.kind == ObjectKind::Creator));
}

#[test]
fn userspace_kernel_equivalent_demand_is_a_violation() {
    let (k, root, agent, _, _, _) = build_reference_world();
    let session_m = session();
    let bad = Manifest::new("assistant", Repo::Service).allow(ObjectKind::Creator, Rights::ALL);
    let report = audit(&k, &[(root, &session_m), (agent, &bad)]);
    assert!(!report.is_clean());
    let vs = &report.violations["assistant"];
    assert!(vs
        .iter()
        .any(|v| matches!(v, Violation::KernelEquivalent { .. })));
}

#[test]
fn undeclared_holdings_fail() {
    // Give the assistant an endpoint it never declared: audit must flag it.
    let (mut k, root, agent, agent_cap, _, root_creator) = build_reference_world();
    let ep = k.create_endpoint(root, root_creator).unwrap();
    k.grant(root, ep, agent_cap, Rights::SEND, None).unwrap();

    let report = reference_report(&k, root, agent);
    assert!(!report.is_clean());
    let vs = &report.violations["assistant"];
    assert!(vs.iter().any(|v| matches!(v, Violation::Undeclared { .. })));
}

#[test]
fn delivery_overhang_warns_but_stays_clean() {
    // A *userspace* grantor holding a GRANT-carrying naming cap into the assistant
    // and holding strictly more than the assistant declares: overhang is a *warning*,
    // never a build-breaking violation (design decision in ../../../../Docs/spec/capability-model.md).
    // The kernel/boot session's own bootstrap edge is exempt (trusted bootstrap).
    let (mut k, root, agent, agent_cap, _, root_creator) = build_reference_world();
    let (ops, ops_cap) = k.create_task(root, root_creator, "ops").unwrap();
    k.grant(
        root,
        agent_cap,
        ops_cap,
        Rights::GRANT.union(Rights::RECEIVE),
        None,
    )
    .unwrap();

    let session_m = session();
    let assistant_m = assistant();
    let ops_m = Manifest::new("ops", Repo::Service)
        .allow(ObjectKind::Task, Rights::GRANT.union(Rights::RECEIVE));
    let report = audit(
        &k,
        &[(root, &session_m), (agent, &assistant_m), (ops, &ops_m)],
    );
    assert!(report.is_clean(), "overhang must not break the build");
    assert!(
        report.warning_count() > 0,
        "userspace grantor's authority overhang onto the assistant must be surfaced"
    );
    assert!(report.warnings.contains_key("assistant"));
}

#[test]
fn empty_audit_is_clean() {
    let k = Kernel::new();
    let report = audit(&k, &[]);
    assert!(report.is_clean());
    assert_eq!(report.violation_count(), 0);
    assert_eq!(report.entries.len(), 0);
}

#[test]
fn unbound_tasks_are_not_audited() {
    // Only bound services ship a manifest; unbound tasks are skipped.
    let (k, root, agent, _, _, _) = build_reference_world();
    let session_m = session();
    let report = audit(&k, &[(root, &session_m)]);
    assert!(report.is_clean());
    assert_eq!(report.entries.len(), 1);
    let _ = agent;
}

#[test]
fn classifier_identifies_kernel_equivalent_pairs() {
    assert!(is_kernel_equivalent(&Declared {
        kind: ObjectKind::Creator,
        rights: Rights::ALL,
    }));
    assert!(is_kernel_equivalent(&Declared {
        kind: ObjectKind::GrantRoot,
        rights: Rights::GRANT,
    }));
    assert!(!is_kernel_equivalent(&Declared {
        kind: ObjectKind::Endpoint,
        rights: Rights::SEND.union(Rights::RECV),
    }));
    assert!(!is_kernel_equivalent(&Declared {
        kind: ObjectKind::Task,
        rights: Rights::READ.union(Rights::CONTROL),
    }));
}

#[test]
fn holdings_exclude_structural_self_cap() {
    // A task's own self cap is mandatory infrastructure, never declared
    // authority. A task that was granted nothing must have EMPTY holdings:
    // its only cap is the self cap, which reachability must exclude.
    let mut k = Kernel::new();
    let (root, _self_cap, root_creator) = k.boot("session").unwrap();
    let (clean, _clean_cap) = k.create_task(root, root_creator, "clean").unwrap();

    let tasks = [clean];
    let snap = reach::snapshot(&k, &tasks);
    let holding = reach::holdings(&snap);
    assert!(
        holding[&clean].is_empty(),
        "self cap leaked into authority: {:?}",
        holding[&clean]
    );
    let _ = root;
}

#[test]
fn reference_report_renders_without_panic() {
    let (k, root, agent, _, _, _) = build_reference_world();
    let report = reference_report(&k, root, agent);
    let mut out = String::new();
    for e in &report.entries {
        out.push_str(&format!(
            "{} reachable={} declared={}\n",
            e.service, e.reachable, e.declared
        ));
    }
    for (service, vs) in &report.violations {
        for v in vs {
            out.push_str(&format!("VIOLATION {service}: {v}\n"));
        }
    }
    assert!(out.contains("session"));
    assert!(out.contains("assistant"));
}

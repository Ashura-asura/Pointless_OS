//! The CI entry point: `cargo run -p capability-audit`.
//!
//! Builds the reference scenario (boot → supervised services → one role-granted
//! assistant), audits the reachable authority of every bound service against its
//! manifest, prints the report, and exits non-zero if any violation exists. The
//! design doc's promise (§10 [CLOSED] "TCB creep"): a manifest violation *breaks the
//! build* — this binary is that break, wired into CI on every commit.

use capability_audit::audit::audit;
use capability_audit::manifests::{assistant, session};
use capability_audit::{AuditReport, Manifest};
use capability_core::{CapHandle, Kernel, TaskHandle};
use grants::{GrantPolicy, GrantService, GrantTarget, RoleLibrary};
use std::process::ExitCode;

fn build_reference_world() -> (Kernel, TaskHandle, TaskHandle, CapHandle, CapHandle) {
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
    (k, root, agent, agent_cap, smtp_cap)
}

fn render(report: &AuditReport) -> String {
    let mut out = String::new();
    out.push_str("reachable-authority audit\n");
    out.push_str("-------------------------\n");
    for e in &report.entries {
        let repo = if e.repo.is_kernel() { "kernel" } else { "service" };
        out.push_str(&format!(
            "  {:<10} ({:>7} repo)  reachable={:<2} declared={}\n",
            e.service, repo, e.reachable, e.declared
        ));
    }
    for (service, vs) in &report.violations {
        for v in vs {
            out.push_str(&format!("  VIOLATION  {service}: {v}\n"));
        }
    }
    for (service, ws) in &report.warnings {
        for w in ws {
            out.push_str(&format!("  warning    {service}: {w}\n"));
        }
    }
    out.push_str(&format!(
        "result: {} violations, {} warnings\n",
        report.violation_count(),
        report.warning_count()
    ));
    out
}

fn main() -> ExitCode {
    let (k, root, agent, _agent_cap, _smtp_cap) = build_reference_world();
    let session = session();
    let assistant = assistant();
    let bindings: Vec<(TaskHandle, &Manifest)> =
        vec![(root, &session), (agent, &assistant)];
    let report = audit(&k, &bindings);
    print!("{}", render(&report));
    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
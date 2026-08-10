//! The CI entry point: `cargo run -p capability-audit`.
//!
//! Builds the reference scenario (boot → supervised services → one role-granted
//! assistant), audits the reachable authority of every bound service against its
//! manifest, prints the report, and exits non-zero if any violation exists. The
//! design doc's promise (§10 [CLOSED] "TCB creep"): a manifest violation *breaks the
//! build* — this binary is that break, wired into CI on every commit.

use capability_audit::audit::audit;
use capability_audit::manifests::{assistant, session};
use capability_audit::{reach, AuditReport, Manifest};
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
        let repo = if e.repo.is_kernel() {
            "kernel"
        } else {
            "service"
        };
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

fn format_rights(rights: capability_core::Rights) -> String {
    if rights == capability_core::Rights::ALL {
        "ALL".to_string()
    } else {
        format!("{rights}")
    }
}

fn render_graph(k: &Kernel, bindings: &[(TaskHandle, &Manifest)]) -> String {
    let mut out = String::new();
    out.push_str("capability graph\n");
    out.push_str("----------------\n");
    let tasks: Vec<TaskHandle> = bindings.iter().map(|(t, _)| *t).collect();
    let snap = reach::snapshot(k, &tasks);
    let edges = reach::delivery_edges(&snap);

    for (task, manifest) in bindings {
        let label = manifest.service;
        let repo = if manifest.repo.is_kernel() {
            "kernel"
        } else {
            "service"
        };
        out.push_str(&format!("  {} ({} repo):\n", label, repo));
        if let Some(caps) = snap.get(task) {
            for cap in caps {
                let kind_name = format!("{:?}", cap.kind);
                let rights_str = format_rights(cap.rights);
                out.push_str(&format!("    [{}] {}\n", kind_name, rights_str));
            }
        }
        let delegation_targets: Vec<&str> = edges
            .iter()
            .filter(|(from, _)| *from == *task)
            .filter_map(|(_, to)| {
                bindings
                    .iter()
                    .find(|(t, _)| *t == *to)
                    .map(|(_, m)| m.service)
            })
            .collect();
        if delegation_targets.is_empty() {
            out.push_str("    (no delegation edges)\n");
        } else {
            out.push_str(&format!(
                "    → could delegate to: {}\n",
                delegation_targets.join(", ")
            ));
        }
    }
    out
}

fn print_help() {
    eprintln!("Usage: capability-audit [OPTIONS]");
    eprintln!();
    eprintln!("Audits reachable authority of every bound service against its manifest.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --graph   Print a human-readable capability graph after the audit report");
    eprintln!("  --help    Show this help message");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut graph_mode = false;

    for arg in &args[1..] {
        match arg.as_str() {
            "--graph" => graph_mode = true,
            "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown option: {other}");
                print_help();
                return ExitCode::FAILURE;
            }
        }
    }

    let (k, root, agent, _agent_cap, _smtp_cap) = build_reference_world();
    let session = session();
    let assistant = assistant();
    let bindings: Vec<(TaskHandle, &Manifest)> = vec![(root, &session), (agent, &assistant)];
    let report = audit(&k, &bindings);
    print!("{}", render(&report));

    if graph_mode {
        print!("{}", render_graph(&k, &bindings));
    }

    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

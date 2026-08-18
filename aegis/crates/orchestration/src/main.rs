//! Runnable entry point for the orchestration session: prints each step and
//! its verdict, then exits non-zero if any invariant failed.

use orchestration::{session, Decision};

fn main() {
    let report = session();
    for s in &report.steps {
        println!("[{}] {}", if s.ok { "ok" } else { "FAIL" }, s.label);
        println!("      {}", s.detail);
    }
    println!(
        "\n{} kernel audit records, {} refusals; {} orchestrator verdicts",
        report.audit_len,
        report.audit_failed,
        report.decisions.len()
    );
    for d in &report.decisions {
        match d {
            Decision::Approved { action, detail } => println!("  approved: {action} — {detail}"),
            Decision::CeilingDenied { action, detail } => {
                println!("  ceiling-denied: {action} — {detail}")
            }
            Decision::SuspendedGate { action, detail } => {
                println!("  held-while-suspended: {action} — {detail}")
            }
        }
    }
    if report.all_ok() {
        println!("\nsession held end to end");
    } else {
        println!("\nsession FAILED an invariant");
        std::process::exit(1);
    }
}

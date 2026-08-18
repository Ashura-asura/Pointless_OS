//! Runnable entry point for the Aegis SDK tour. The logic lives in the
//! library (`sdk_example::tour`) so the same steps are contract-tested; this
//! binary only prints the report.

use sdk_example::tour;

fn main() {
    let report = tour();
    println!("Aegis SDK tour — role-grant lifecycle end to end");
    println!("{}", "-".repeat(64));
    for step in &report.steps {
        let mark = if step.ok { "ok " } else { "FAIL" };
        println!("[{mark}] {} — {}", step.label, step.detail);
    }
    println!("{}", "-".repeat(64));
    println!(
        "done: {} steps, {} all-ok; audit log {} records ({} refusals)",
        report.steps.len(),
        report.steps.iter().filter(|s| s.ok).count(),
        report.audit_len,
        report.audit_failed
    );
    if !report.all_ok() {
        std::process::exit(1);
    }
}

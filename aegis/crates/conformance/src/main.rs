//! CLI for the Phase 4 conformance harness.
//!
//! Usage: `cargo run -p conformance -- <trace-file>`
//!
//! Reads a `C:` capability trace (extract from a traced kernel's serial log
//! with `^C:`), replays it against the capability-core model, prints the
//! verdict-agreement summary, and exits 0 if every traced verdict matched the
//! model, 1 if any diverged.

use conformance::{parse_trace, Replayer};
use std::process::exit;

fn main() {
    let mut args = std::env::args();
    let path = args.nth(1).unwrap_or_else(|| {
        eprintln!("usage: conformance <trace-file>");
        exit(2);
    });
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        exit(2);
    });
    let evs = match parse_trace(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse error: {e}");
            exit(2);
        }
    };
    let mut r = Replayer::new();
    let rep = r.replay(&evs).clone();
    println!("trace: {path}");
    println!(
        "spawns={} grants={} revokes={} ops-checked={}",
        rep.spawned, rep.grants, rep.revokes, rep.ops
    );
    println!(
        "verdicts: kernel ok={} denied={} | model ok={} denied={}",
        rep.kernel_ok, rep.kernel_denied, rep.model_ok, rep.model_denied
    );
    if rep.agreed() {
        println!("CONFORMANCE: OK — the model's authorization verdicts agree with the kernel at every step");
        exit(0);
    }
    println!("CONFORMANCE: DIVERGENCE(S)");
    for d in &rep.divergences {
        println!("  {d}");
    }
    exit(1);
}

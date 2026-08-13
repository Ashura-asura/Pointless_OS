//! Integration test: the checked-in ring-3 denial-demo trace must replay
//! against the model with zero divergences.

use conformance::{parse_trace, Replayer, RING3_DEMO_TRACE};

#[test]
fn ring3_denial_demo_trace_conforms_to_the_model() {
    let evs = parse_trace(RING3_DEMO_TRACE).expect("fixture parses");
    let mut r = Replayer::new();
    let rep = r.replay(&evs).clone();
    assert!(
        rep.agreed(),
        "model disagreed with the kernel:\n{}",
        rep.divergences.join("\n")
    );
    // The specific Phase 3 claims, restated as model facts:
    // 1. the denied task's three gated ops are denied (not panics, not
    //    successes) — the model independently denies all of them;
    // 2. the client's echo call is authorized once the server's grant lands;
    // 3. the server's create / grant / serve / reply are all authorized.
    let denied_calls = rep.kernel_denied;
    assert_eq!(denied_calls, 5, "five denied verdicts recorded");
    assert_eq!(rep.model_denied, 5, "model denies exactly the same five");
    assert_eq!(rep.kernel_ok, 5, "five authorized verdicts recorded");
    assert_eq!(rep.model_ok, 5, "model authorizes exactly the same five");
}

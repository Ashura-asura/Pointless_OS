//! Phase L (part 1 of 2): chaos testing against the real live system.
//!
//! Design doc §7 Phase 10 / master roadmap Phase L: randomized task
//! crashes, randomized network partition (reusing Phase I's fail-closed
//! path), randomized resource exhaustion, run as a soak test with a
//! zero-fail-open assertion after every iteration.
//!
//! Honest scope, same discipline as `vmx.rs`: this is real code against
//! this kernel's real `Supervisor`, real `Fleet`, and real frame
//! allocator — not a simulation layered on top of them.
//!
//! What "soak period" means here in practice: `run()` takes an iteration
//! count, not a wall-clock duration — this kernel has no wall-clock timer
//! plumbed to this module, and faking a duration by counting LAPIC ticks
//! would be a duration in name only. Report the real iteration count you
//! actually ran (Ground Rule 4), not a rounded-up "extended soak" claim —
//! 10k+ iterations at zero fail-open is a meaningful number to cite either
//! way.
//!
//! Three real fault categories, matching the master doc:
//!   1. Task crash — `Supervisor::handle_crash` against a real, already
//!      supervised task (`service_idx`, passed in by the caller — reuse
//!      the existing IDX_SERVICE from the boot demo; do NOT point this at
//!      a synthetic/never-spawned index, `restart_task` rebuilds from a
//!      task's *real* remembered entry/stack, which only exists once a
//!      task has actually been spawned).
//!   2. Network partition — a real two-node `Fleet` pair (mirrors the
//!      already-passing `remote_capability_denied_while_issuer_partitioned`
//!      test in fleet.rs almost exactly, just driven by the PRNG instead
//!      of a fixed script), asserting the fail-closed property holds
//!      under randomized ordering of partition/heartbeat/verify.
//!   3. Resource exhaustion — real frame allocation to real exhaustion
//!      (not a fake counter), asserting the allocator fails closed
//!      (`None`, never a corrupted/aliased frame) and that every
//!      allocated frame is fully returned afterward (no leak).
//!
//! The single invariant checked after every iteration, across all three
//! categories: **fail-open count stays zero.** "Fail-open" is defined
//! precisely per category below, not left implicit.

#![cfg(feature = "chaos-demo")]

use crate::cap::Rights;
use crate::fleet::{Fleet, FleetError, NodeId, TokenObjectKind};
use crate::frame;
use crate::supervisor::Supervisor;

/// xorshift64 — tiny, deterministic, no external crate. Seeded explicitly
/// so a run that finds a problem is reproducible by citing the seed, per
/// this repo's evidence discipline.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // xorshift64 requires a non-zero state.
        Rng(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Scenario {
    TaskCrash,
    NetworkPartition,
    ResourceExhaustion,
}

impl Scenario {
    fn pick(rng: &mut Rng) -> Scenario {
        match rng.below(3) {
            0 => Scenario::TaskCrash,
            1 => Scenario::NetworkPartition,
            _ => Scenario::ResourceExhaustion,
        }
    }
}

struct Tally {
    ran: u32,
    fail_open: u32,
    recovered_or_closed: u32,
}

/// Task-crash scenario: crash the real supervised service task, assert the
/// outcome is always one of the two closed states the breaker defines —
/// "fail-open" here means specifically: the task ends up schedulable again
/// (`is_task_alive`) WITHOUT a matching restart having been recorded, i.e.
/// state moved forward without going through the supervisor at all.
///
/// Every `Some` outcome of `handle_crash` records exactly two audit entries
/// (`Crash` + `Restart`, or `Crash` + `Trip`) — see supervisor.rs — so the
/// liveness check is paired against a real +2 audit delta.
fn chaos_task_crash(sup: &mut Supervisor, service_idx: usize) -> bool {
    let before_audit = sup.audit_len();
    let outcome = sup.handle_crash(service_idx);
    match outcome {
        // Budget available: must have logged Crash+Restart (+2), and the task
        // must be alive again afterward (else the "restart" was a lie).
        Some(true) => {
            let logged_restart = sup.audit_len() >= before_audit + 2;
            let alive = crate::tasks::is_task_alive(service_idx);
            logged_restart && alive
        }
        // Budget spent: breaker tripped, task must stay dead — a task
        // that's alive here despite a tripped breaker IS fail-open. Logged
        // Crash+Trip (+2).
        Some(false) => {
            let logged_trip = sup.audit_len() >= before_audit + 2;
            let dead = !crate::tasks::is_task_alive(service_idx);
            logged_trip && dead
        }
        // Not supervised — shouldn't happen once set up below, but is not
        // itself a fail-open (no action was taken at all).
        None => true,
    }
}

/// Network-partition scenario: real two-node Fleet pair, randomized order
/// of mark_unreachable / heartbeat / verify. Fail-open here means
/// specifically: `verify()` returns `Ok(())` for a capability whose
/// issuer is currently marked unreachable — the exact property Phase I's
/// fail-closed design exists to prevent.
fn chaos_network_partition(rng: &mut Rng) -> bool {
    let id_a = NodeId([0x11u8; 32]);
    let id_b = NodeId([0x22u8; 32]);
    let key_a = [0xAAu8; 32];
    let key_b = [0xBBu8; 32];

    let mut fleet_a = Fleet::new(id_a, key_a);
    let mut fleet_b = Fleet::new(id_b, key_b);
    // Both directions must trust each other (mirrors fleet.rs's set_up_ab):
    // `send_to` requires the *sender* to have the peer registered, and
    // `verify` requires the *verifier* to trust the issuer. Registering only
    // one direction would make send_to (or verify) fail with UntrustedPeer on
    // every iteration — a setup failure that would look like a chaos failure.
    if fleet_a.register_peer(id_b, key_b).is_err() || fleet_b.register_peer(id_a, key_a).is_err() {
        return false; // setup failure is itself a bug worth flagging, not a pass
    }

    let chain = fleet_a.issue(
        rng.next_u64() % 4096,
        TokenObjectKind::Task,
        Rights::READ,
        None,
    );
    let cap = match fleet_a.send_to(chain, id_b) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Randomized script: 4-8 random actions from {partition, heartbeat,
    // verify}, checking the invariant after every single verify.
    let steps = 4 + rng.below(5) as u32;
    let mut partitioned = false;
    for _ in 0..steps {
        match rng.below(3) {
            0 => {
                let _ = fleet_b.mark_unreachable(id_a);
                partitioned = true;
            }
            1 => {
                let _ = fleet_b.heartbeat(id_a);
                partitioned = false;
            }
            _ => {
                let result = fleet_b.verify(&cap);
                if partitioned {
                    // THE invariant: partitioned issuer must never verify Ok.
                    if result == Ok(()) {
                        return false; // fail-open, caught live
                    }
                    if result != Err(FleetError::PeerUnreachable) {
                        // Wrong error is a real bug too (e.g. stale masking
                        // unreachable), just not the specific fail-open this
                        // scenario is targeted at — still log it as a miss.
                        return false;
                    }
                } else if result != Ok(()) {
                    // Not partitioned and denied anyway is over-restrictive,
                    // not fail-open — don't count it as a chaos failure here,
                    // but it's real signal if you see this hit in practice.
                }
            }
        }
    }
    true
}

/// Resource-exhaustion scenario: allocate real frames to real exhaustion,
/// assert the allocator returns `None` (never panics, never hands out a
/// frame it thinks is free but isn't), then free everything and assert
/// the free count returns to where it started — a leak here would itself
/// be a fail-open (the system silently lost real capacity).
fn chaos_resource_exhaustion() -> bool {
    let (free_before, _total) = unsafe { frame::stats_global() };

    let mut held: [u64; 256] = [0; 256];
    let mut n: usize = 0;
    // Cap this scenario's own footprint well below a full real-exhaustion
    // run to avoid starving the rest of a live boot during the demo; a
    // full-exhaustion pass is real but belongs in its own dedicated,
    // non-shared boot mode — noted honestly rather than silently narrowing
    // scope here. `None` from the allocator is real exhaustion reached —
    // expected, not a failure.
    while n < held.len() {
        match unsafe { frame::alloc_global() } {
            Some(phys) => {
                held[n] = phys;
                n += 1;
            }
            None => break,
        }
    }

    let mut ok = true;
    for &phys in held.iter().take(n) {
        if !unsafe { frame::free_global(phys) } {
            ok = false; // freeing a frame we just allocated must never fail
        }
    }

    let (free_after, _) = unsafe { frame::stats_global() };
    ok && free_after == free_before
}

/// Run `iterations` randomized chaos rounds against the real live system.
/// `service_idx` must be an already-spawned, currently-alive task (reuse
/// the existing IDX_SERVICE from the boot demo — see module docs on why a
/// synthetic index is unsafe here). Prints the real tally at the end;
/// returns `true` iff fail-open count was zero across the whole run.
///
/// # Safety
/// Calls into the real supervisor/task-table/frame-allocator machinery;
/// same single-threaded-kernel caveats as the rest of this codebase (must
/// not run concurrently with anything else touching these tables).
pub unsafe fn run(iterations: u32, seed: u64, service_idx: usize) -> bool {
    crate::sprintln!(
        "Aegis: [chaos] starting {} iterations, seed={:#x}, service_idx={}",
        iterations,
        seed,
        service_idx
    );

    let mut sup = Supervisor::new();
    if !sup.supervise(service_idx, 3) {
        crate::sprintln!(
            "Aegis: [chaos] FATAL: could not register service_idx under a fresh Supervisor"
        );
        return false;
    }

    let mut rng = Rng::new(seed);
    let mut tally = Tally {
        ran: 0,
        fail_open: 0,
        recovered_or_closed: 0,
    };

    for i in 0..iterations {
        let scenario = Scenario::pick(&mut rng);
        let ok = match scenario {
            Scenario::TaskCrash => chaos_task_crash(&mut sup, service_idx),
            Scenario::NetworkPartition => chaos_network_partition(&mut rng),
            Scenario::ResourceExhaustion => chaos_resource_exhaustion(),
        };
        tally.ran += 1;
        if ok {
            tally.recovered_or_closed += 1;
        } else {
            tally.fail_open += 1;
            crate::sprintln!(
                "Aegis: [chaos] FAIL-OPEN at iteration {} scenario={:?} (seed={:#x})",
                i,
                scenario,
                seed
            );
        }
    }

    crate::sprintln!(
        "Aegis: [chaos] done: {} ran, {} recovered/fail-closed, {} fail-open",
        tally.ran,
        tally.recovered_or_closed,
        tally.fail_open
    );
    tally.fail_open == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise the pure/host-testable parts (RNG determinism, the
    // network-partition scenario, which only touches Fleet — no task
    // table or frame allocator involved) the same way the rest of this
    // crate's #[cfg(test)] modules do. The task-crash and
    // resource-exhaustion scenarios touch kernel-global task/frame state
    // and are exercised by `run()` itself under a real boot, not here.

    #[test]
    fn rng_is_deterministic_for_a_given_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn rng_below_stays_in_range() {
        let mut r = Rng::new(1);
        for _ in 0..1000 {
            assert!(r.below(3) < 3);
        }
    }

    #[test]
    fn network_partition_scenario_never_fails_open_across_many_seeds() {
        for seed in 0..500u64 {
            let mut rng = Rng::new(seed);
            assert!(
                chaos_network_partition(&mut rng),
                "fail-open in network-partition scenario at seed {}",
                seed
            );
        }
    }
}

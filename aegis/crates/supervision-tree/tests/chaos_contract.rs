//! Chaos tests for the supervision-tree runtime (design doc Phase 10):
//! inject ordered and random-looking fault sequences and verify that the
//! supervision invariants hold under every permutation tested.

use capability_core::{CapHandle, Kernel, OpKind, Rights, TaskHandle};
use supervision_tree::{RestartPolicy, RuntimeEvent, Supervisor};

struct World {
    k: Kernel,
    root: TaskHandle,
    creator: CapHandle,
}

fn world() -> World {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    World { k, root, creator }
}

fn spawn(w: &mut World, label: &str) -> (TaskHandle, CapHandle) {
    w.k.create_task(w.root, w.creator, label).unwrap()
}

fn census(k: &Kernel, task: TaskHandle) -> Vec<(capability_core::ObjectId, String, Rights)> {
    let mut out: Vec<_> = k
        .caps_of(task)
        .into_iter()
        .filter(|c| c.obj != task.id())
        .map(|c| (c.obj, format!("{:?}", c.kind), c.rights))
        .collect();
    out.sort();
    out
}

/// Budget of zero: first crash should trip immediately, no restarts.
#[test]
fn budget_zero_trips_on_first_crash() {
    let mut w = world();
    let mut sup = Supervisor::new(w.root);
    let (a, a_cap) = spawn(&mut w, "svc-a");
    let idx = sup
        .add(
            &mut w.k,
            "svc-a",
            a,
            a_cap,
            RestartPolicy { max_restarts: 0 },
        )
        .unwrap();

    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);

    assert!(!sup.is_running(&mut w.k, idx));
    assert_eq!(sup.restarts_of(idx), 0);
    assert!(sup
        .log()
        .iter()
        .any(|e| matches!(e, RuntimeEvent::Trip { .. })));
}

/// Interleaved crashes: A crashes, B crashes, A crashes again, B crashes
/// again — each within its own budget, siblings unaffected.
#[test]
fn interleaved_crashes_track_independently() {
    let mut w = world();
    let mut sup = Supervisor::new(w.root);

    let (a, a_cap) = spawn(&mut w, "svc-a");
    let (b, b_cap) = spawn(&mut w, "svc-b");
    let (c, c_cap) = spawn(&mut w, "svc-c");

    let idx_a = sup
        .add(
            &mut w.k,
            "svc-a",
            a,
            a_cap,
            RestartPolicy { max_restarts: 2 },
        )
        .unwrap();
    let idx_b = sup
        .add(
            &mut w.k,
            "svc-b",
            b,
            b_cap,
            RestartPolicy { max_restarts: 1 },
        )
        .unwrap();
    let idx_c = sup
        .add(
            &mut w.k,
            "svc-c",
            c,
            c_cap,
            RestartPolicy { max_restarts: 3 },
        )
        .unwrap();

    let c_before = census(&w.k, c);

    // Interleave: A1, B1, A2, B2(trip), A3(trip)
    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);
    assert!(sup.is_running(&mut w.k, idx_a));
    assert_eq!(sup.restarts_of(idx_a), 1);

    w.k.task_kill(w.root, b_cap).unwrap();
    sup.pump(&mut w.k);
    assert!(sup.is_running(&mut w.k, idx_b));
    assert_eq!(sup.restarts_of(idx_b), 1);

    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);
    assert!(sup.is_running(&mut w.k, idx_a));
    assert_eq!(sup.restarts_of(idx_a), 2);

    // B's second crash exhausts budget 1.
    w.k.task_kill(w.root, b_cap).unwrap();
    sup.pump(&mut w.k);
    assert!(!sup.is_running(&mut w.k, idx_b));
    assert_eq!(sup.restarts_of(idx_b), 1);
    assert!(sup
        .log()
        .iter()
        .any(|e| matches!(e, RuntimeEvent::Trip { node, .. } if node == "svc-b")));

    // A's third crash exhausts budget 2.
    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);
    assert!(!sup.is_running(&mut w.k, idx_a));
    assert_eq!(sup.restarts_of(idx_a), 2);
    assert!(sup
        .log()
        .iter()
        .any(|e| matches!(e, RuntimeEvent::Trip { node, .. } if node == "svc-a")));

    // C never crashed: untouched.
    assert!(sup.is_running(&mut w.k, idx_c));
    assert_eq!(census(&w.k, c), c_before);
}

/// Rapid crash-restart cycle: kill and pump in tight loop, verify state
/// machine stays consistent — no panic, no double-restart, budget exact.
#[test]
fn rapid_crash_restart_cycle_stays_consistent() {
    let mut w = world();
    let mut sup = Supervisor::new(w.root);

    let (a, a_cap) = spawn(&mut w, "svc-a");
    let idx = sup
        .add(
            &mut w.k,
            "svc-a",
            a,
            a_cap,
            RestartPolicy { max_restarts: 3 },
        )
        .unwrap();

    // 7 rapid cycles: 3 restarts within budget, then trip. After the trip,
    // pump() skips faulted subsystems — further crashes are not logged.
    for _ in 0..7 {
        w.k.task_kill(w.root, a_cap).unwrap();
        sup.pump(&mut w.k);
    }

    assert!(!sup.is_running(&mut w.k, idx));
    assert_eq!(sup.restarts_of(idx), 3);

    // pump() skips faulted subsystems, so only crashes before the trip are
    // recorded: 4 (3 within budget + 1 that triggers the trip).
    let crashes = sup
        .log()
        .iter()
        .filter(|e| matches!(e, RuntimeEvent::Crash { .. }))
        .count();
    let trips = sup
        .log()
        .iter()
        .filter(|e| matches!(e, RuntimeEvent::Trip { .. }))
        .count();
    assert_eq!(
        crashes, 4,
        "crashes before trip: 3 within budget + 1 that trips"
    );
    assert_eq!(trips, 1, "exactly one trip event");
}

/// Escalation clears the budget: child trips, parent adopts with fresh
/// budget, parent can restart the subsystem.
#[test]
fn escalation_clears_budget_for_parent() {
    let mut w = world();
    let mut child = Supervisor::new(w.root);
    let mut parent = Supervisor::new(w.root);

    let (a, a_cap) = spawn(&mut w, "svc-a");
    child
        .add(
            &mut w.k,
            "svc-a",
            a,
            a_cap,
            RestartPolicy { max_restarts: 1 },
        )
        .unwrap();

    // Trip the child.
    w.k.task_kill(w.root, a_cap).unwrap();
    child.pump(&mut w.k);
    w.k.task_kill(w.root, a_cap).unwrap();
    child.pump(&mut w.k);
    assert!(!child.is_running(&mut w.k, 0));

    // Escalate to parent.
    child.escalate(&mut w.k, 0, &mut parent);
    assert_eq!(child.subsystem_count(), 0);

    // Parent has fresh budget: crash and restart succeeds.
    assert!(parent.is_running(&mut w.k, 0));
    w.k.task_kill(w.root, a_cap).unwrap();
    parent.pump(&mut w.k);
    assert!(parent.is_running(&mut w.k, 0));
    assert_eq!(parent.restarts_of(0), 1);
}

/// Crash one service while another is already faulted: the faulted one
/// stays faulted, the new crash is handled independently.
#[test]
fn new_crash_during_existing_fault() {
    let mut w = world();
    let mut sup = Supervisor::new(w.root);

    let (a, a_cap) = spawn(&mut w, "svc-a");
    let (b, b_cap) = spawn(&mut w, "svc-b");
    let idx_a = sup
        .add(
            &mut w.k,
            "svc-a",
            a,
            a_cap,
            RestartPolicy { max_restarts: 0 },
        )
        .unwrap();
    let idx_b = sup
        .add(
            &mut w.k,
            "svc-b",
            b,
            b_cap,
            RestartPolicy { max_restarts: 2 },
        )
        .unwrap();

    // Trip A immediately.
    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);
    assert!(!sup.is_running(&mut w.k, idx_a));

    // Now crash B while A is faulted.
    w.k.task_kill(w.root, b_cap).unwrap();
    sup.pump(&mut w.k);
    assert!(sup.is_running(&mut w.k, idx_b));
    assert_eq!(sup.restarts_of(idx_b), 1);

    // A is still faulted, unaffected.
    assert!(!sup.is_running(&mut w.k, idx_a));
    assert_eq!(sup.restarts_of(idx_a), 0);
}

/// Budget accounting is exact: budget N means exactly N restarts, not N-1
/// and not N+1, across interleaved services.
#[test]
fn budget_accounting_is_exact_under_interleave() {
    let mut w = world();
    let mut sup = Supervisor::new(w.root);

    let (a, a_cap) = spawn(&mut w, "svc-a");
    let (b, b_cap) = spawn(&mut w, "svc-b");
    let idx_a = sup
        .add(
            &mut w.k,
            "svc-a",
            a,
            a_cap,
            RestartPolicy { max_restarts: 3 },
        )
        .unwrap();
    let idx_b = sup
        .add(
            &mut w.k,
            "svc-b",
            b,
            b_cap,
            RestartPolicy { max_restarts: 3 },
        )
        .unwrap();

    // 4 crashes each, alternating. After 3 restarts each, both breakers
    // trip on the 4th crash. Further crashes are skipped by pump().
    for i in 0..8 {
        if i % 2 == 0 {
            w.k.task_kill(w.root, a_cap).unwrap();
            sup.pump(&mut w.k);
        } else {
            w.k.task_kill(w.root, b_cap).unwrap();
            sup.pump(&mut w.k);
        }
    }

    // Both should have exhausted budget exactly.
    assert!(!sup.is_running(&mut w.k, idx_a));
    assert!(!sup.is_running(&mut w.k, idx_b));
    assert_eq!(sup.restarts_of(idx_a), 3);
    assert_eq!(sup.restarts_of(idx_b), 3);

    // Total spawns: 2 initial + 3 A restarts + 3 B restarts = 8.
    let spawns =
        w.k.audit()
            .query(
                None,
                capability_core::AuditFilter::Ops(&[OpKind::TaskSpawn]),
            )
            .filter(|r| r.caller == w.root.id())
            .count();
    assert_eq!(spawns, 8);
}

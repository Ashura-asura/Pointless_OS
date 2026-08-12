//! Supervision-runtime contract (design doc §5): supervision is circuit
//! breaker + supervision tree — restarts within budget, a real breaker that
//! trips instead of retrying forever, escalation to a parent supervisor that
//! renews the whole subsystem, and a decision log that cross-checks the
//! kernel audit (neither side can rewrite the other).

use capability_core::{AuditFilter, CapHandle, Kernel, ObjectId, OpKind, Rights, TaskHandle};
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

fn ops(k: &Kernel, caller: ObjectId, op: OpKind) -> usize {
    let filter = match op {
        OpKind::TaskSpawn => AuditFilter::Ops(&[OpKind::TaskSpawn]),
        OpKind::TaskKill => AuditFilter::Ops(&[OpKind::TaskKill]),
        _ => return 0,
    };
    k.audit()
        .query(None, filter)
        .filter(|r| r.caller == caller)
        .count()
}

/// The census of one task (non-self caps), for "untouched" assertions.
fn census(k: &Kernel, task: TaskHandle) -> Vec<(ObjectId, String, Rights)> {
    let mut out: Vec<_> = k
        .caps_of(task)
        .into_iter()
        .filter(|c| c.obj != task.id())
        .map(|c| (c.obj, format!("{:?}", c.kind), c.rights))
        .collect();
    out.sort();
    out
}

#[test]
fn crashes_are_restarted_within_budget_and_siblings_are_untouched() {
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
    let b_before = census(&w.k, b);

    // A crash before the first pump (or one detected on the next pulse):
    // the pump restores A within budget, from the supervisor's own CONTROL.
    w.k.task_kill(w.root, a_cap).unwrap();
    let restarted = sup.pump(&mut w.k);
    assert_eq!(restarted, vec!["svc-a".to_string()]);
    assert!(sup.is_running(&mut w.k, idx_a));
    assert_eq!(sup.restarts_of(idx_a), 1);

    // The decision log reconstructs the cycle with the kernel's own facts.
    assert_eq!(
        sup.log(),
        &[
            RuntimeEvent::Crash {
                at: w.k.now(),
                node: "svc-a".to_string(),
                task: a.id(),
            },
            RuntimeEvent::Restart {
                at: w.k.now(),
                node: "svc-a".to_string(),
                attempt: 1,
            },
        ]
    );

    // Containment: the fault did not cascade — the sibling is untouched in
    // census and in operation, and the runtime logged nothing about it.
    assert!(sup.is_running(&mut w.k, idx_b));
    assert_eq!(census(&w.k, b), b_before);

    // A second crash is restarted again; the state machine stays consistent
    // with the kernel audit (1 initial spawn + 2 restarts).
    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);
    assert!(sup.is_running(&mut w.k, idx_a));
    assert_eq!(sup.restarts_of(idx_a), 2);
    assert_eq!(ops(&w.k, w.root.id(), OpKind::TaskSpawn), 4);
}

#[test]
fn the_circuit_breaker_trips_instead_of_retrying_forever() {
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
    let b_before = census(&w.k, b);

    // Four crashes against a budget of three restarts.
    for _ in 0..4 {
        w.k.task_kill(w.root, a_cap).unwrap();
        sup.pump(&mut w.k);
    }

    // The fourth crash exhausted the budget: the breaker is open.
    assert!(!sup.is_running(&mut w.k, idx_a));
    assert_eq!(sup.restarts_of(idx_a), 3);
    let spawns_without_init = ops(&w.k, w.root.id(), OpKind::TaskSpawn) - 2;
    assert_eq!(spawns_without_init, 3, "exactly the budget was burned");
    assert_eq!(
        sup.log()
            .iter()
            .filter(|e| matches!(e, RuntimeEvent::Crash { .. }))
            .count(),
        4
    );
    assert!(sup
        .log()
        .iter()
        .any(|e| matches!(e, RuntimeEvent::Trip { node, .. } if node == "svc-a")));

    // "Never silently retry": further crashes are refused, and the refusal
    // is recorded — the log grows by a crash notice, the spawn count does
    // not move, and the breaker state does not flap.
    let log_before = sup.log().len();
    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);
    assert_eq!(sup.log().len(), log_before, "trip is already on record");
    assert_eq!(sup.restarts_of(idx_a), 3);
    assert!(!sup.is_running(&mut w.k, idx_a));
    assert_eq!(
        sup.log()
            .iter()
            .filter(|e| matches!(e, RuntimeEvent::Restart { .. }))
            .count(),
        3
    );

    // Containment holds even through the trip: the sibling never crashed,
    // never restarted, and is untouched.
    assert!(sup.is_running(&mut w.k, idx_b));
    assert_eq!(census(&w.k, b), b_before);
    assert_eq!(
        sup.log()
            .iter()
            .filter(|e| matches!(e, RuntimeEvent::Crash { .. }))
            .count(),
        sup.log()
            .iter()
            .filter(|e| matches!(e, RuntimeEvent::Crash { node, .. } if node == "svc-a"))
            .count(),
        "the only crash on record is A's"
    );
}

#[test]
fn escalation_to_a_parent_renews_the_budget_for_the_whole_subsystem() {
    let mut w = world();
    let mut child = Supervisor::new(w.root);
    let mut parent = Supervisor::new(w.root);

    // A subsystem under a tight child budget.
    let (a, a_cap) = spawn(&mut w, "svc-a");
    let idx_a = child
        .add(
            &mut w.k,
            "svc-a",
            a,
            a_cap,
            RestartPolicy { max_restarts: 1 },
        )
        .unwrap();

    // Crash; restart; crash again: the child's breaker trips after one.
    w.k.task_kill(w.root, a_cap).unwrap();
    child.pump(&mut w.k);
    assert_eq!(child.restarts_of(idx_a), 1);
    w.k.task_kill(w.root, a_cap).unwrap();
    child.pump(&mut w.k);
    assert!(!child.is_running(&mut w.k, idx_a));

    // Escalation: the child surrenders the subsystem to its parent, and the
    // surrender is an audited step in both logs.
    child.escalate(&mut w.k, idx_a, &mut parent);
    assert_eq!(child.subsystem_count(), 0);
    assert!(matches!(
        child.log().last(),
        Some(RuntimeEvent::Escalate { node, .. }) if node == "svc-a"
    ));
    assert!(matches!(
        parent.log().last(),
        Some(RuntimeEvent::Adopt { node, .. }) if node == "svc-a"
    ));

    // The parent restarts the whole subsystem under its own authority with a
    // fresh budget: the subsystem is live again, and the new budget counts
    // from zero.
    let idx_a2 = 0;
    assert!(parent.is_running(&mut w.k, idx_a2));
    assert_eq!(parent.restarts_of(idx_a2), 0);

    w.k.task_kill(w.root, a_cap).unwrap();
    parent.pump(&mut w.k);
    assert!(parent.is_running(&mut w.k, idx_a2));
    assert_eq!(parent.restarts_of(idx_a2), 1);
}

#[test]
fn the_policy_decision_log_crosschecks_the_kernel_audit() {
    let mut w = world();
    let mut sup = Supervisor::new(w.root);

    let (a, a_cap) = spawn(&mut w, "svc-a");
    let (b, b_cap) = spawn(&mut w, "svc-b");
    let _ia = sup
        .add(
            &mut w.k,
            "svc-a",
            a,
            a_cap,
            RestartPolicy { max_restarts: 2 },
        )
        .unwrap();
    let _ib = sup
        .add(
            &mut w.k,
            "svc-b",
            b,
            b_cap,
            RestartPolicy { max_restarts: 1 },
        )
        .unwrap();

    let log = |s: &Supervisor| {
        s.log()
            .iter()
            .filter_map(|e| match e {
                RuntimeEvent::Crash { task, .. } => Some(("crash", *task)),
                RuntimeEvent::Restart { .. } => Some(("restart", ObjectId::from_raw(0))),
                RuntimeEvent::Trip { .. } => Some(("trip", ObjectId::from_raw(0))),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    // A scripted failure history: A crashes three times (budget 2 -> trip),
    // B crashes once (budget 1 -> one restart).
    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);
    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);
    w.k.task_kill(w.root, a_cap).unwrap();
    sup.pump(&mut w.k);
    w.k.task_kill(w.root, b_cap).unwrap();
    sup.pump(&mut w.k);

    // The runtime's account: exactly the scripted sequence, with A's crashes
    // carrying A's kernel task id and no ghost events.
    let seq = log(&sup);
    assert_eq!(
        seq,
        vec![
            ("crash", a.id()),
            ("restart", ObjectId::from_raw(0)),
            ("crash", a.id()),
            ("restart", ObjectId::from_raw(0)),
            ("crash", a.id()),
            ("trip", ObjectId::from_raw(0)),
            ("crash", b.id()),
            ("restart", ObjectId::from_raw(0)),
        ]
    );

    // The kernel's account: initial spawns (2) + A's two restarts + B's one
    // restart = five TaskSpawns; every kernel op is attributed to the
    // supervisor role, and the kill side (the crasher) is equally on record.
    assert_eq!(ops(&w.k, w.root.id(), OpKind::TaskSpawn), 5);
    assert_eq!(ops(&w.k, w.root.id(), OpKind::TaskKill), 4);

    // Cross-check: neither side can be selectively rewritten. The runtime
    // cannot retroactively alter its decisions (append-only), and the kernel
    // does not know about policy at all — its spawn count IS the restart
    // count the runtime claims, no more, no less.
    let runtime_restarts = seq.iter().filter(|(k, _)| *k == "restart").count();
    assert_eq!(
        runtime_restarts,
        ops(&w.k, w.root.id(), OpKind::TaskSpawn) - 2
    );
}

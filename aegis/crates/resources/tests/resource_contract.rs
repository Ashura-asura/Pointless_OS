//! Resource-model contract (design doc §8): budgets are hierarchical and
//! cannot be overcommitted, metering is kernel truth (audit log for CPU, cap
//! tables for memory), and the governor recycles an over-budget service with
//! ordinary revocation — siblings provably unaffected.

use capability_audit::{Manifest, Repo};
use capability_core::{CapHandle, Kernel, ObjectKind, Rights, TaskHandle};
use object_store::Store;
use packages::{Package, PackageManager};
use resources::{recycle, Alloc, Budget, Meter};

struct World {
    k: Kernel,
    root: TaskHandle,
    creator: CapHandle,
    store: Store,
    manager: PackageManager,
}

fn world() -> World {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    let store = Store::new(root, creator);
    let manager = PackageManager::new(root, creator);
    World {
        k,
        root,
        creator,
        store,
        manager,
    }
}

fn spawn(w: &mut World, label: &str) -> TaskHandle {
    w.k.create_task(w.root, w.creator, label).unwrap().0
}

fn editor_package(w: &mut World, writable: bool) -> Package {
    let config = w.store.commit(&mut w.k, b"max_cols=80").unwrap();
    let rights = if writable {
        Rights::READ.union(Rights::WRITE)
    } else {
        Rights::READ
    };
    let manifest = Manifest::new("text-editor", Repo::Service)
        .allow(ObjectKind::Task, Rights::CONTROL)
        .allow(ObjectKind::MemRegion, rights)
        // Payload delivery is READ-only by derivation: the envelope covers it
        // explicitly, as the audit compares exact (kind, rights) pairs.
        .allow(ObjectKind::MemRegion, Rights::READ);
    Package {
        name: "text-editor",
        manifest,
        payload: vec![("config.toml".to_string(), config)],
    }
}

fn worker_package(w: &mut World) -> Package {
    let config = w.store.commit(&mut w.k, b"queue=8").unwrap();
    let manifest = Manifest::new("worker", Repo::Service)
        .allow(ObjectKind::Task, Rights::CONTROL)
        .allow(ObjectKind::Endpoint, Rights::SEND.union(Rights::RECV))
        .allow(ObjectKind::MemRegion, Rights::READ);
    Package {
        name: "worker",
        manifest,
        payload: vec![("worker.toml".to_string(), config)],
    }
}

fn endpoint_slot(k: &Kernel, task: TaskHandle) -> u32 {
    (1..256u32)
        .find(
            |s| matches!(k.cap_info(task, CapHandle(*s)), Ok(i) if i.kind == ObjectKind::Endpoint),
        )
        .unwrap()
}

fn live_minus_self(k: &Kernel, task: TaskHandle) -> usize {
    (1..256u32)
        .filter(|s| k.cap_info(task, CapHandle(*s)).is_ok())
        .count()
}

/// §8: a hierarchy cannot overcommit a fixed total — a parent cannot hand out
/// more than it holds, every service has exactly one parent, and what the root
/// handed out plus what it kept is precisely its budget.
#[test]
fn hierarchical_allocation_cannot_overcommit() {
    let mut w = world();
    let a = spawn(&mut w, "svc-a");
    let b = spawn(&mut w, "svc-b");
    let a1 = spawn(&mut w, "svc-a1");
    let a2 = spawn(&mut w, "svc-a2");
    let loner = spawn(&mut w, "svc-loner");

    let mut alloc = Alloc::root(
        w.root,
        Budget {
            cpu: 1000,
            mem: 1_048_576,
        },
    );
    alloc
        .give(
            w.root,
            a,
            Budget {
                cpu: 400,
                mem: 200_000,
            },
        )
        .unwrap();
    alloc
        .give(
            w.root,
            b,
            Budget {
                cpu: 300,
                mem: 150_000,
            },
        )
        .unwrap();
    alloc
        .give(
            a,
            a1,
            Budget {
                cpu: 200,
                mem: 100_000,
            },
        )
        .unwrap();
    alloc
        .give(
            a,
            a2,
            Budget {
                cpu: 100,
                mem: 50_000,
            },
        )
        .unwrap();

    assert_eq!(
        alloc.remaining(a),
        Some(Budget {
            cpu: 100,
            mem: 50_000
        }),
        "a parent keeps exactly what it did not hand down"
    );
    assert_eq!(
        alloc.remaining(w.root),
        Some(Budget {
            cpu: 300,
            mem: 698_576
        }),
        "root committed 700 cpu to its two children and keeps the difference"
    );
    assert!(
        alloc
            .give(
                a,
                spawn(&mut w, "svc-a3"),
                Budget {
                    cpu: 200,
                    mem: 100_000
                }
            )
            .is_err(),
        "A has only 100 cpu left; a 200 cpu child would exceed the envelope"
    );
    assert!(
        alloc.give(b, a1, Budget { cpu: 10, mem: 1 }).is_err(),
        "A1 already has one parent; the tree stays a tree"
    );
    assert_eq!(
        alloc.remaining(w.root).unwrap().cpu
            + alloc.entry(a).unwrap().budget.cpu
            + alloc.entry(b).unwrap().budget.cpu,
        1000,
        "allocation conserves the total: root kept + subtree tops = the root's budget"
    );
    assert!(
        alloc.remaining(loner).is_none(),
        "never-budgeted services have no envelope"
    );
}

/// §8: metering is kernel truth — every successful record is attributed by the
/// kernel to exactly one caller, so a partition of the log by task is exact,
/// and a freshly installed READ-only service holds zero writable bytes.
#[test]
fn metering_is_kernel_truth_partitioning_the_log_by_task() {
    let mut w = world();
    let app = {
        let pkg = editor_package(&mut w, false);
        w.manager
            .install(&mut w.k, &mut w.store, "editor", &pkg)
            .unwrap()
    };

    let total: usize =
        w.k.audit()
            .query(None, capability_core::AuditFilter::All)
            .count();
    let root_ops: usize =
        w.k.audit()
            .query(Some(w.root.id()), capability_core::AuditFilter::Success)
            .count();
    let app_ops = Meter::cpu_spent(&w.k, app.task) as usize;

    assert_eq!(
        app_ops + root_ops,
        total,
        "every log record belongs to exactly one task: the partition is exact"
    );
    assert_eq!(
        Meter::resident(&mut w.k, app.task),
        0,
        "a READ-only service holds zero writable bytes — its memory envelope is empty"
    );
}

/// §8: the governor recycles an over-budget service with ordinary revocation;
/// its siblings keep every cap, and the recycled service can be reinstalled
/// into a clean envelope.
#[test]
fn the_governor_recycles_an_over_budget_service_and_siblings_survive() {
    let mut w = world();
    let pkg = worker_package(&mut w);
    let _ep = w.k.create_endpoint(w.root, w.creator).unwrap();

    let a = w
        .manager
        .install(&mut w.k, &mut w.store, "worker-a", &pkg)
        .unwrap();
    let b = w
        .manager
        .install(&mut w.k, &mut w.store, "worker-b", &pkg)
        .unwrap();
    let a_ep = endpoint_slot(&w.k, a.task);

    let mut alloc = Alloc::root(w.root, Budget { cpu: 100, mem: 0 });
    alloc
        .give(w.root, a.task, Budget { cpu: 2, mem: 0 })
        .unwrap();
    alloc
        .give(w.root, b.task, Budget { cpu: 98, mem: 0 })
        .unwrap();

    for i in 0..3u8 {
        w.k.ep_send(a.task, CapHandle(a_ep), vec![i]).unwrap();
    }
    let spent = Meter::cpu_spent(&w.k, a.task);
    assert!(spent > 2, "the worker spent beyond its envelope of 2");

    let b_spent_before = Meter::cpu_spent(&w.k, b.task);
    recycle(&mut w.k, w.root, a.anchor).unwrap();

    assert_eq!(
        live_minus_self(&w.k, a.task),
        0,
        "the recycled service holds no cap at all — its anchor was revoked"
    );
    assert!(
        live_minus_self(&w.k, b.task) >= 1,
        "the sibling kept its envelope untouched"
    );
    assert_eq!(
        Meter::cpu_spent(&w.k, b.task),
        b_spent_before,
        "recycling A cost B nothing"
    );

    // A clean reinstall = a clean envelope: fresh task, zero spent.
    let a2 = w
        .manager
        .install(&mut w.k, &mut w.store, "worker-a2", &pkg)
        .unwrap();
    assert_ne!(a2.task, a.task);
    assert_eq!(
        Meter::cpu_spent(&w.k, a2.task),
        0,
        "the fresh envelope starts clean"
    );
}

/// §8: memory metering is the cap-table truth — a WRITE region sized N meters
/// N resident bytes, and a recycle empties the envelope exactly.
#[test]
fn resident_memory_is_the_writable_regions_a_task_can_reach() {
    let mut w = world();
    let app = {
        let pkg = editor_package(&mut w, true);
        w.manager
            .install(&mut w.k, &mut w.store, "editor", &pkg)
            .unwrap()
    };

    let mut total = 0u64;
    let mut writable = 0u64;
    let mut count = 0u64;
    for slot in 1..256u32 {
        if let Ok(info) = w.k.cap_info(app.task, CapHandle(slot)) {
            if info.kind == ObjectKind::MemRegion {
                let len = w.k.mem_len(app.task, CapHandle(slot)).unwrap() as u64;
                total += len;
                count += 1;
                if info.rights.contains(Rights::WRITE) {
                    writable += len;
                }
            }
        }
    }
    assert_eq!(
        count, 3,
        "the declared R|W region, the declared READ pair, and the payload READ \
         delivery — every declared pair is granted, and the payload is READ-only"
    );
    assert!(
        writable < total,
        "only the declared R|W region is writable; payload and the READ pair are not"
    );
    assert_eq!(
        Meter::resident(&mut w.k, app.task),
        writable,
        "the meter reads exactly the WRITE-bearing bytes the cap table grants"
    );

    recycle(&mut w.k, w.root, app.anchor).unwrap();
    assert_eq!(
        Meter::resident(&mut w.k, app.task),
        0,
        "after recycle the service can reach nothing, so it holds nothing"
    );
}

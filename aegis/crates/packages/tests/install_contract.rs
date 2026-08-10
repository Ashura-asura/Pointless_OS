//! Package-model contract (design doc §8): installs grant exactly the declared
//! manifest, nothing ambient; installs run no code; failed installs roll back
//! completely; content-addressed payloads deduplicate across installs; the
//! per-install anchor revocation removes every minted cap from every CSpace.

use capability_audit::{audit::audit as run_audit, Manifest, Repo};
use capability_core::{AuditFilter, CapHandle, Kernel, ObjectKind, OpKind, Rights, TaskHandle};
use object_store::Store;
use packages::{Package, PackageManager};

struct World {
    k: Kernel,
    root: TaskHandle,
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
        store,
        manager,
    }
}

const CONFIG: &[u8] = b"max_cols=80";
const DICT_STR: &str = "a; an; the; capability";

fn editor_manifest() -> Manifest {
    Manifest::new("text-editor", Repo::Service)
        .allow(ObjectKind::Task, Rights::CONTROL)
        .allow(ObjectKind::MemRegion, Rights::READ)
}

fn editor_package(w: &mut World, with_dict: bool) -> Package {
    let config = w.store.commit(&mut w.k, CONFIG).unwrap();
    if with_dict {
        let dict = w.store.commit(&mut w.k, DICT_STR.as_bytes()).unwrap();
        Package {
            name: "text-editor",
            manifest: editor_manifest(),
            payload: vec![("config.toml".to_string(), config)],
        }
        .with_file("dict.txt".to_string(), dict)
    } else {
        Package {
            name: "text-editor",
            manifest: editor_manifest(),
            payload: vec![("config.toml".to_string(), config)],
        }
    }
}

/// The app's live cap table as decided by the kernel, excluding its self-cap.
fn app_slots(w: &Kernel, app: TaskHandle) -> Vec<(u32, ObjectKind, Rights)> {
    let mut out = Vec::new();
    for slot in 1..256u32 {
        if let Ok(info) = w.cap_info(app, CapHandle(slot)) {
            out.push((slot, info.kind, info.rights));
        }
    }
    out
}

fn live_cap_count(w: &Kernel, task: TaskHandle) -> usize {
    (0..256u32)
        .filter(|s| w.cap_info(task, CapHandle(*s)).is_ok())
        .count()
}

fn create_task_count(w: &Kernel) -> usize {
    w.audit()
        .query(None, AuditFilter::Ops(&[OpKind::CreateTask]))
        .count()
}

/// Every READ-only MemRegion slot, plus the highest kind seen: the minted task
/// cap must be CONTROL and exactly one of the two regions must hold CONFIG.
fn read_regions(w: &mut Kernel, app: TaskHandle) -> Vec<(u32, Vec<u8>)> {
    let mut out = Vec::new();
    for (slot, kind, rights) in app_slots(w, app) {
        if kind == ObjectKind::MemRegion && rights == Rights::READ {
            let len = w.mem_len(app, CapHandle(slot)).unwrap_or(0);
            if let Ok(bytes) = w.mem_read(app, CapHandle(slot), 0, len) {
                out.push((slot, bytes));
            }
        }
    }
    out
}

/// §8: install grants exactly the manifest, nothing ambient. The app ends up
/// with its self-cap, one CONTROL task cap, two READ regions (one declared,
/// one payload) and no way to widen any of them — the auditor has already
/// certified the install inside `PackageManager::install`.
#[test]
fn install_grants_exactly_the_manifest_and_nothing_ambient() {
    let mut w = world();
    let pkg = editor_package(&mut w, false);
    let before = live_cap_count(&w.k, w.root);
    let app = w
        .manager
        .install(&mut w.k, &mut w.store, "editor", &pkg)
        .unwrap();

    let slots = app_slots(&w.k, app.task);
    assert_eq!(
        slots.len(),
        3,
        "exactly: declared Task CONTROL + declared MemRegion READ + payload READ"
    );
    let (_, kinds, rights): (Vec<_>, Vec<_>, Vec<_>) =
        slots.iter().map(|(s, k, r)| (*s, *k, *r)).fold(
            (Vec::new(), Vec::new(), Vec::new()),
            |(mut a, mut b, mut c), (s, k, r)| {
                a.push(s);
                b.push(k);
                c.push(r);
                (a, b, c)
            },
        );
    assert_eq!(kinds.iter().filter(|k| **k == ObjectKind::Task).count(), 1);
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == ObjectKind::MemRegion)
            .count(),
        2
    );
    assert!(rights.iter().all(|r| !r.contains(Rights::WRITE)));

    let regions = read_regions(&mut w.k, app.task);
    assert_eq!(regions.len(), 2, "both regions readable, neither writable");
    assert!(
        regions.iter().any(|(_, b)| b == CONFIG),
        "the payload content arrived with the install"
    );
    for (slot, _) in &regions {
        assert!(
            w.k.mem_write(app.task, CapHandle(*slot), 0, b"x".to_vec())
                .is_err(),
            "READ-only by derivation"
        );
    }

    let report = run_audit(&w.k, &[(app.task, &pkg.manifest)]);
    assert!(report.is_clean());
    assert_eq!(
        live_cap_count(&w.k, w.root),
        before + 2,
        "the manager's table grows by exactly its two install artifacts: the app's \
         naming cap and the grant anchor — nothing else"
    );
}

/// §8: installs run no code and spawn nothing but the app itself. The only new
/// CreateTask record in the window is the app's own creation; the app performs
/// no operation at all during install.
#[test]
fn install_runs_no_code_and_spawns_nothing_but_the_app() {
    let mut w = world();
    let before = create_task_count(&w.k);
    let pkg = editor_package(&mut w, false);
    let app = w
        .manager
        .install(&mut w.k, &mut w.store, "editor", &pkg)
        .unwrap();

    let spawned: Vec<_> =
        w.k.audit()
            .query(None, AuditFilter::Ops(&[OpKind::CreateTask]))
            .skip(before)
            .collect();
    assert_eq!(spawned.len(), 1, "exactly one task was created: the app");
    assert_eq!(
        spawned[0].caller,
        w.root.id(),
        "the single spawn is attributable to the manager, not to anything the install ran"
    );
    assert_eq!(
        w.k.audit()
            .query(Some(app.task.id()), AuditFilter::All)
            .count(),
        0,
        "the app never performed any operation during install"
    );
}

/// §10-style repository discipline: a package that declares kernel-equivalent
/// authority (the Creator kind) is refused by the manifest audit and rolled
/// back — the manager's table is exactly as it was and no task is left behind.
#[test]
fn kernel_equivalent_install_is_refused_and_rolls_back() {
    let mut w = world();
    let config = w.store.commit(&mut w.k, CONFIG).unwrap();
    let pkg = Package {
        name: "root-wanter",
        manifest: Manifest::new("root-wanter", Repo::Service)
            .allow(ObjectKind::Task, Rights::CONTROL)
            .allow(ObjectKind::Creator, Rights::CONTROL),
        payload: vec![("config.toml".to_string(), config)],
    };
    let root_before = live_cap_count(&w.k, w.root);

    let err = w
        .manager
        .install(&mut w.k, &mut w.store, "root-wanter", &pkg)
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid operation",
        "refused by the manifest audit"
    );

    assert_eq!(
        live_cap_count(&w.k, w.root),
        root_before,
        "the rollback removed every artifact the failed install added — the app naming \
         cap, the grant anchor and the task itself"
    );
}

/// §8: a manifest asking for authority the manager does not hold (MEMORY
/// CONTROL) is refused up front — nothing to derive from, so nothing is minted.
#[test]
fn an_unholdable_request_is_refused_up_front_and_rolled_back() {
    let mut w = world();
    let config = w.store.commit(&mut w.k, CONFIG).unwrap();
    let pkg = Package {
        name: "mem-tyrant",
        manifest: Manifest::new("mem-tyrant", Repo::Service)
            .allow(ObjectKind::MemRegion, Rights::CONTROL),
        payload: vec![("config.toml".to_string(), config)],
    };
    let root_before = live_cap_count(&w.k, w.root);

    let err = w
        .manager
        .install(&mut w.k, &mut w.store, "mem-tyrant", &pkg)
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "no capability in slot",
        "no source cap exists"
    );

    assert_eq!(
        live_cap_count(&w.k, w.root),
        root_before,
        "refused before anything was minted, so nothing had to be taken back"
    );
}

/// §8: payloads are content-addressed — a second install of an identical
/// package adds no new block, and both apps read the same bytes.
#[test]
fn identical_payloads_share_blocks_across_installs() {
    let mut w = world();
    let blocks_after_first = {
        let pkg = editor_package(&mut w, true);
        w.manager
            .install(&mut w.k, &mut w.store, "editor-a", &pkg)
            .unwrap();
        w.store.block_count()
    };
    let pkg_b = editor_package(&mut w, true);
    let app_b = w
        .manager
        .install(&mut w.k, &mut w.store, "editor-b", &pkg_b)
        .unwrap();

    assert_eq!(
        w.store.block_count(),
        blocks_after_first,
        "identical bytes = identical content hashes = zero new blocks"
    );
    let regions = read_regions(&mut w.k, app_b.task);
    assert!(regions.iter().any(|(_, b)| b == CONFIG));
    assert!(regions.iter().any(|(_, b)| b == DICT_STR.as_bytes()));
}

/// §8 + I4: revoking one install's grant root strips its delivered caps from
/// that install's task while the sibling install keeps all of its authority.
#[test]
fn revoking_the_anchor_removes_every_minted_cap_of_that_install_only() {
    let mut w = world();
    let pkg_a = editor_package(&mut w, false);
    let pkg_b = editor_package(&mut w, true);
    let app_a = w
        .manager
        .install(&mut w.k, &mut w.store, "editor-a", &pkg_a)
        .unwrap();
    let app_b = w
        .manager
        .install(&mut w.k, &mut w.store, "editor-b", &pkg_b)
        .unwrap();
    assert_eq!(app_slots(&w.k, app_a.task).len(), 3);

    w.k.revoke(w.root, app_a.anchor).unwrap();

    assert_eq!(
        app_slots(&w.k, app_a.task).len(),
        0,
        "every minted cap of install A died with its anchor"
    );
    assert!(
        app_slots(&w.k, app_b.task).len() >= 3,
        "install B is unrelated and unaffected"
    );
    assert!(
        w.k.cap_info(app_a.task, CapHandle(0)).is_ok(),
        "the app task still exists — it now holds only its own self-cap and no \
         authority it did not bootstrap with"
    );
    assert!(
        w.k.cap_info(app_a.task, CapHandle(1)).is_err(),
        "the revoked install left no cap behind it could reach"
    );
}

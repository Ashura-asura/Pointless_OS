//! Update-architecture contract (design doc §8): generations are staged
//! without disturbing the boot target, activation is health-gated and is a
//! store content flip that uses no capability authority, and rollback returns
//! to the last-known-good generation while touching no installed caps —
//! provable from the kernel audit log, record by record.

use capability_audit::{audit::audit, Manifest, Repo};
use capability_core::{AuditFilter, CapHandle, Kernel, ObjectKind, OpKind, Rights, TaskHandle};
use object_store::{FlatView, Store};
use packages::{InstalledApp, Package, PackageManager};
use system_update::{GenerationDescriptor, UpdateManager};

struct World {
    k: Kernel,
    root: TaskHandle,
    store: Store,
    updates: UpdateManager,
}

fn world() -> World {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    let mut store = Store::new(root, creator);
    let mut view = FlatView::new(&mut k, &mut store).unwrap();
    // Bootstrap: the bootloader lays down the boot-config view with an empty
    // `current` pointer once, before any generation exists.
    assert!(view.create_file(&mut k, &mut store, "current"));
    let manager = PackageManager::new(root, creator);
    World {
        k,
        root,
        store,
        updates: UpdateManager::new(manager, view),
    }
}

fn editor_package(w: &mut World) -> Package {
    let config = w.store.commit(&mut w.k, b"max_cols=80").unwrap();
    Package {
        name: "text-editor",
        manifest: Manifest::new("text-editor", Repo::Service)
            .allow(ObjectKind::Task, Rights::CONTROL)
            .allow(ObjectKind::MemRegion, Rights::READ),
        payload: vec![("config.toml".to_string(), config)],
    }
}

fn health_ok(_: &Kernel, _: &InstalledApp) -> bool {
    true
}

fn health_bad(_: &Kernel, _: &InstalledApp) -> bool {
    false
}

/// The authority ops whose records must not appear during a pointer flip.
const AUTHORITY_OPS: &'static [OpKind] = &[
    OpKind::Grant,
    OpKind::Copy,
    OpKind::Revoke,
    OpKind::CreateTask,
    OpKind::CreateGrantRoot,
    OpKind::Destroy,
    OpKind::TaskKill,
];

fn authority_record_count(k: &Kernel) -> usize {
    k.audit()
        .query(None, AuditFilter::Ops(AUTHORITY_OPS))
        .count()
}

fn boot_target(w: &mut World) -> GenerationDescriptor {
    w.updates.boot_target(&mut w.k, &mut w.store).unwrap()
}

fn live_slot_count(w: &Kernel, task: TaskHandle) -> usize {
    (1..256u32)
        .filter(|s| w.cap_info(task, CapHandle(*s)).is_ok())
        .count()
}

/// §8: staging a candidate generation installs it fully without disturbing the
/// boot target; the staged app is inert until activated.
#[test]
fn staging_a_candidate_does_not_disturb_the_current_generation() {
    let mut w = world();
    let pkg = editor_package(&mut w);
    let staged = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    let app1 = w.updates.activate(&mut w.k, &mut w.store, staged, health_ok).unwrap();
    assert!(boot_target(&mut w).n == 1);

    let staged2 = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    assert_eq!(staged2.descriptor.n, 2);

    assert_eq!(boot_target(&mut w).n, 1, "the boot target is untouched by staging");
    assert_eq!(
        w.k.audit().query(Some(staged2.app.task.id()), AuditFilter::All).count(),
        0,
        "the staged app has not run and drove no operations"
    );
    assert!(live_slot_count(&w.k, app1.task) >= 2, "the current generation keeps its caps");
    let report = audit(&w.k, &[(app1.task, &pkg.manifest)]);
    assert!(report.is_clean(), "the current generation still passes its ceiling");
}

/// §8: activation is gated on health; a failing candidate leaves the current
/// generation booting exactly as before.
#[test]
fn a_failed_health_check_blocks_activation_and_preserves_the_current_generation() {
    let mut w = world();
    let pkg = editor_package(&mut w);
    let staged = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    assert!(w.updates.activate(&mut w.k, &mut w.store, staged, health_ok).is_some());

    let staged2 = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    assert!(
        w.updates.activate(&mut w.k, &mut w.store, staged2, health_bad).is_none(),
        "activation refused: health check failed"
    );
    assert_eq!(boot_target(&mut w).n, 1, "the refused generation never became default");
}

/// §8: an activation flip is store content, not capability authority — the
/// kernel audit for the flip window contains zero authority operations.
#[test]
fn activation_is_a_content_pointer_flip_with_no_capability_authority() {
    let mut w = world();
    let pkg = editor_package(&mut w);
    let staged = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    assert!(w.updates.activate(&mut w.k, &mut w.store, staged, health_ok).is_some());

    let staged2 = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    let authority_before = authority_record_count(&w.k);
    assert!(w.updates.activate(&mut w.k, &mut w.store, staged2, health_ok).is_some());

    assert_eq!(boot_target(&mut w).n, 2);
    assert_eq!(
        authority_record_count(&w.k),
        authority_before,
        "activating performed no grant, copy, revoke, spawn or root-creating op: \
         the flip is a single content write in the boot view"
    );
}

/// §8: rollback returns to the last known good generation; the survivor's caps
/// were never touched, and the dead generation keeps nothing bootable.
#[test]
fn rollback_restores_the_last_known_good_generation_without_touching_installed_caps() {
    let mut w = world();
    let pkg = editor_package(&mut w);
    let staged = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    let app1 = w.updates.activate(&mut w.k, &mut w.store, staged, health_ok).unwrap();

    let staged2 = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    let app2 = w.updates.activate(&mut w.k, &mut w.store, staged2, health_ok).unwrap();
    assert_eq!(boot_target(&mut w).n, 2);

    // Gen-2 dies after activation (its install anchor is revoked — an external
    // event the operator observes as "the new version crashes").
    w.k.revoke(w.root, app2.anchor).unwrap();

    let authority_before = authority_record_count(&w.k);
    let rolled = w.updates.rollback(&mut w.k, &mut w.store).unwrap();
    assert_eq!(rolled, 1, "restored the last generation healthy at activation");
    assert_eq!(boot_target(&mut w).n, 1);
    assert_eq!(
        authority_record_count(&w.k),
        authority_before,
        "rollback performed zero authority operations: it is a content pointer flip"
    );

    assert!(live_slot_count(&w.k, app1.task) >= 2, "the survivor still holds its caps");
    let report = audit(&w.k, &[(app1.task, &pkg.manifest)]);
    assert!(report.is_clean(), "the survivor still passes its manifest ceiling");

    assert!(
        w.updates.rollback(&mut w.k, &mut w.store).is_err(),
        "rollback is anchored to last-known-good: after returning to gen-1 there \
         is nothing earlier to roll back to"
    );
}

/// The updater is not a second root: after a whole update cycle the only grant
/// roots anywhere in the boot task's CSpace are the two install anchors, the
/// only creator is the boot role's own, and the only task caps are the boot
/// task and the two installed apps — nothing the update machinery itself could
/// have minted for itself.
#[test]
fn the_updater_holds_no_special_authority() {
    let mut w = world();
    let pkg = editor_package(&mut w);
    let staged = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    assert!(w.updates.activate(&mut w.k, &mut w.store, staged, health_ok).is_some());
    let staged2 = w.updates.stage(&mut w.k, &mut w.store, &pkg).unwrap();
    assert!(w.updates.activate(&mut w.k, &mut w.store, staged2, health_ok).is_some());
    w.updates.rollback(&mut w.k, &mut w.store).unwrap();

    let (mut grant_roots, mut creators, mut tasks) = (0, 0, 0);
    for slot in 0..256u32 {
        if let Ok(info) = w.k.cap_info(w.root, CapHandle(slot)) {
            match info.kind {
                ObjectKind::GrantRoot => grant_roots += 1,
                ObjectKind::Creator => creators += 1,
                ObjectKind::Task => tasks += 1,
                _ => {}
            }
        }
    }
    assert_eq!(grant_roots, 2, "exactly the two install anchors exist");
    assert_eq!(creators, 1, "the boot role's own creator — nothing new");
    assert_eq!(tasks, 3, "boot task + the two installed apps, all from the installs");
}
//! Executable check for the package-driven execution pipeline (design doc §8):
//! a package is installed, the app is started, it reads its granted payload,
//! and it is refused when it tries to go beyond its manifest.

use capability_core::{CapHandle, Kernel, TaskHandle};
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
    World { k, root, store, manager }
}

#[test]
fn install_then_execute_then_verify_caps() {
    let mut w = world();

    // 1. Build a package: a "monitor" that gets CONTROL over a task and READ
    //    over a config file.
    let config = w.store.commit(&mut w.k, b"interval=5\n").unwrap();
    let manifest = capability_audit::Manifest::new("monitor", capability_audit::Repo::Service)
        .allow(capability_core::ObjectKind::Task, capability_core::Rights::CONTROL)
        .allow(capability_core::ObjectKind::MemRegion, capability_core::Rights::READ);
    let pkg = Package {
        name: "monitor",
        manifest,
        payload: vec![("config.toml".to_string(), config)],
    };

    // 2. Install the package.
    let app = w.manager.install(&mut w.k, &mut w.store, "monitor-app", &pkg).unwrap();

    // 3. Start the installed app.
    w.k.task_spawn(w.root, app.task_cap).unwrap();
    assert!(w.k.task_running(w.root, app.task_cap).unwrap(), "app is running");

    // 4. The app reads its config file (uses its READ MemRegion cap).
    let mut found_config = false;
    for slot in 0..256u32 {
        if let Ok(info) = w.k.cap_info(app.task, CapHandle(slot)) {
            if info.kind == capability_core::ObjectKind::MemRegion
                && info.rights == capability_core::Rights::READ
            {
                let len = w.k.mem_len(app.task, CapHandle(slot)).unwrap_or(0);
                if len > 0 {
                    let bytes = w.k.mem_read(app.task, CapHandle(slot), 0, len).unwrap();
                    assert_eq!(bytes, b"interval=5\n", "app reads its config payload");
                    found_config = true;
                    break;
                }
            }
        }
    }
    assert!(found_config, "app holds a readable MemRegion with config data");

    // 5. The app tries to write to a READ-only region — refused.
    for slot in 0..256u32 {
        if let Ok(info) = w.k.cap_info(app.task, CapHandle(slot)) {
            if info.kind == capability_core::ObjectKind::MemRegion
                && info.rights == capability_core::Rights::READ
            {
                let result = w.k.mem_write(app.task, CapHandle(slot), 0, b"hacked".to_vec());
                assert!(result.is_err(), "READ-only region refuses write");
                break;
            }
        }
    }

    // 6. The app tries to create a new task (not in its manifest) — refused.
    let has_creator = (0..256u32).any(|s| {
        w.k.cap_info(app.task, CapHandle(s))
            .map(|i| i.kind == capability_core::ObjectKind::Creator)
            .unwrap_or(false)
    });
    assert!(!has_creator, "app holds no Creator cap");

    // 7. The app's authority is exactly what the manifest declared.
    let mut cap_count = 0u32;
    for slot in 0..256u32 {
        if w.k.cap_info(app.task, CapHandle(slot)).is_ok() {
            cap_count += 1;
        }
    }
    // self-cap + Task CONTROL + MemRegion READ (config) + MemRegion READ (declared) = 4
    assert_eq!(cap_count, 4, "app holds exactly 4 caps: self + declared + payload");
}
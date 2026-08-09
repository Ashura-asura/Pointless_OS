//! Device-model and graphics contract (design doc §8): devices are
//! capability-scoped objects with typed interfaces owned by userspace drivers
//! (no kernel-resident devices, no ambient access); a driver crash is
//! contained to its own execution context and recovered by the supervision
//! tree without touching the rest of the system; GPU memory and command-queue
//! capabilities are isolated per context by the kernel; and the compositor is
//! an ordinary, replaceable userspace service.

use capability_core::{
    AuditFilter, CapHandle, Kernel, KernelError, ObjectId, OpKind, Rights, TaskHandle,
};
use devices::graphics::GraphicsService;
use devices::{cap_for, slots_of, DeviceError, DeviceKind, Devices};

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

/// A fresh execution context named by `root` (the supervisor's handle).
fn spawn(w: &mut World, label: &str) -> (TaskHandle, CapHandle) {
    w.k.create_task(w.root, w.creator, label).unwrap()
}

/// The (kind, rights) caps a task holds, minus its self-cap, as decided by the
/// kernel — the object-identity projection for census comparisons.
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

fn send_count(k: &Kernel, caller: ObjectId) -> usize {
    k.audit()
        .query(None, AuditFilter::Ops(&[OpKind::Send]))
        .filter(|r| r.caller == caller)
        .count()
}

const SECTORS: &[u8] = b"0123456789abcdef";

#[test]
fn devices_are_capability_scoped_objects_with_typed_interfaces_owned_by_a_driver() {
    let mut w = world();
    let mut devs = Devices::new(w.root, w.creator);
    let disk0 = devs
        .register_block(&mut w.k, "disk0", SECTORS.to_vec())
        .unwrap();
    let eth0 = devs.register_net(&mut w.k, "eth0").unwrap();
    let gpu0 = devs.register_gpu(&mut w.k, "gpu0", vec![0u8; 16]).unwrap();

    // The device directory is a userspace registry: three typed devices,
    // none of them kernel-resident by construction (the kernel has no device
    // namespace at all — only objects).
    let listed = devs.list();
    assert_eq!(listed.len(), 3);
    assert_eq!(listed[0].0, disk0);
    assert_eq!(listed[2].2, DeviceKind::Gpu);

    // Ownership: a userspace driver claims the block device and holds the
    // operative device caps in *its own* CSpace.
    let (driver, driver_name) = spawn(&mut w, "block-driver");
    devs.claim(&mut w.k, disk0, driver, driver_name).unwrap();
    // Execution contexts start stopped; the supervision tree starts drivers.
    w.k.task_spawn(w.root, driver_name).unwrap();
    let disk_obj = devs.command_obj(disk0).unwrap();
    let driver_caps = w.k.caps_of(driver);
    let driver_holds = driver_caps
        .iter()
        .find(|c| c.obj == disk_obj)
        .expect("driver holds the block device");
    assert!(driver_holds.rights.contains(Rights::WRITE));
    assert!(driver_holds.rights.contains(Rights::READ));

    // A client is licenced: a narrowed READ cap, minted into the client's own
    // CSpace. The op resolves through the *caller's* cap.
    let (client, client_name) = spawn(&mut w, "disk-client");
    devs.grant_surface(&mut w.k, disk0, client_name, Rights::READ)
        .unwrap();
    assert_eq!(
        devs.read_sector(&mut w.k, client, disk0, 0, SECTORS.len()).unwrap(),
        SECTORS
    );

    // Typed interface: every kind speaks only its own record formats, and the
    // gate trips before any kernel op — a block device has no queue, no wire.
    assert_eq!(
        devs.read_sector(&mut w.k, client, eth0, 0, 4),
        Err(DeviceError::WrongInterface(
            "read_sector is a block-device interface"
        ))
    );
    let err = devs.submit_commands(&mut w.k, client, disk0, vec![0xAA]).unwrap_err();
    assert_eq!(
        err,
        DeviceError::WrongInterface("submit_commands is a GPU-command-queue interface")
    );
    assert_eq!(
        devs.send_frame(&mut w.k, client, disk0, b"x".to_vec()),
        Err(DeviceError::WrongInterface(
            "send_frame is a network-device interface"
        ))
    );

    // Capability scoping within the interface: the client's READ-only licence
    // cannot write, and the kernel says so (not the registry).
    assert_eq!(
        devs.write_sector(&mut w.k, client, disk0, 0, b"pwn".to_vec()),
        Err(DeviceError::Kernel(KernelError::InsufficientRights(Rights::WRITE)))
    );

    // No ambient access: a task that knows the device id but holds no cap
    // cannot touch it — device memory is reachable only through a granted
    // device capability (the model's IOMMU analogue).
    let (outsider, _) = spawn(&mut w, "outsider");
    assert_eq!(
        devs.read_sector(&mut w.k, outsider, disk0, 0, 4),
        Err(DeviceError::NotHeld)
    );
    assert_eq!(
        devs.submit_commands(&mut w.k, outsider, gpu0, vec![0xBB]),
        Err(DeviceError::NotHeld)
    );
}

#[test]
fn a_driver_crash_is_contained_to_its_context_and_recovered_by_supervision() {
    let mut w = world();
    let mut devs = Devices::new(w.root, w.creator);
    let disk0 = devs
        .register_block(&mut w.k, "disk0", SECTORS.to_vec())
        .unwrap();

    let (driver, driver_name) = spawn(&mut w, "block-driver");
    devs.claim(&mut w.k, disk0, driver, driver_name).unwrap();
    w.k.task_spawn(w.root, driver_name).unwrap();
    let (client, client_name) = spawn(&mut w, "disk-client");
    devs.grant_surface(&mut w.k, disk0, client_name, Rights::READ)
        .unwrap();
    let (other, other_name) = spawn(&mut w, "unrelated");
    let scratch = w.k.create_mem(w.root, w.creator, b"scratch".to_vec()).unwrap();
    w.k
        .grant(w.root, scratch, other_name, Rights::READ, None)
        .unwrap();
    let scratch_obj = w.k.cap_info(w.root, scratch).unwrap().obj;
    let other_before = census(&w.k, other);

    // Crash: the driver's execution context dies. No caps are stolen, no
    // objects are broken — the kernel only records that the driver is not
    // running (supervision is explicit, like everything else).
    w.k.task_kill(w.root, driver_name).unwrap();
    assert!(!devs.is_up(&mut w.k, disk0));

    // New licences are refused while the device is down: the supervision hook
    // — a dead driver cannot license new clients.
    let (_late, late_name) = spawn(&mut w, "late-client");
    assert_eq!(
        devs.grant_surface(&mut w.k, disk0, late_name, Rights::READ),
        Err(DeviceError::DeviceDown)
    );

    // The blast radius stops at the driver: the alive client's granted caps
    // ride through (revocation is explicit), and the unrelated app is
    // untouched in census and in operation.
    assert_eq!(
        devs.read_sector(&mut w.k, client, disk0, 0, SECTORS.len()).unwrap(),
        SECTORS
    );
    assert_eq!(census(&w.k, other), other_before);
    let other_cap = cap_for(&w.k, other, scratch_obj).unwrap();
    assert_eq!(
        w.k.mem_read(other, other_cap, 0, 7).unwrap(),
        b"scratch"
    );

    // Recovery: the supervision tree restarts the driver...
    w.k.task_spawn(w.root, driver_name).unwrap();
    assert!(devs.is_up(&mut w.k, disk0));
    // ...and licensing flows again.
    let (fresh, fresh_name) = spawn(&mut w, "fresh-client");
    devs.grant_surface(&mut w.k, disk0, fresh_name, Rights::READ)
        .unwrap();
    assert_eq!(
        devs.read_sector(&mut w.k, fresh, disk0, 0, SECTORS.len()).unwrap(),
        SECTORS
    );
}

#[test]
fn gpu_memory_and_command_queues_are_isolated_between_contexts() {
    let mut w = world();
    let gfx = GraphicsService::new(w.root, w.creator);

    let clear_a: Vec<u8> = b"AAAABBBB".to_vec();
    let clear_b: Vec<u8> = b"CCCCDDDD".to_vec();
    let (ctx_a, name_a) = spawn(&mut w, "ctx-a");
    let (ctx_b, name_b) = spawn(&mut w, "ctx-b");
    let mut gfx = gfx;
    let a = gfx.attach(&mut w.k, ctx_a, name_a, clear_a).unwrap();
    let b = gfx.attach(&mut w.k, ctx_b, name_b, clear_b).unwrap();

    // Each context holds exactly its own queue (SEND) and its own framebuffer
    // (READ|WRITE): the kernel isolated GPU memory and queues between
    // contexts by giving them distinct objects and per-context caps.
    let a_caps = census(&w.k, ctx_a);
    assert_eq!(a_caps.len(), 2);
    for (obj, _, rights) in &a_caps {
        assert!(*obj == a.queue_obj || *obj == a.fb_obj);
        if *obj == a.queue_obj {
            assert_eq!(*rights, Rights::SEND);
        } else {
            assert!(rights.contains(Rights::WRITE) && rights.contains(Rights::READ));
        }
    }

    // User-mode submission is an ordinary endpoint send, attributed to the
    // submitting context in the audit log.
    let a_queue_slot = slots_of(&w.k, ctx_a, a.queue_obj)[0];
    gfx.submit(&mut w.k, ctx_a, CapHandle(a_queue_slot), b"draw x3".to_vec())
        .unwrap();
    assert_eq!(send_count(&w.k, ctx_a.id()), 1);

    // Isolation both ways: a context cannot reach its neighbour's queue or
    // framebuffer. Capability handles resolve against the *caller's* table, so
    // B's objects simply have no slots in A's table — the kernel never gave
    // A a path onto them, whatever slot number B reports.
    assert!(slots_of(&w.k, ctx_a, b.fb_obj).is_empty());
    assert!(slots_of(&w.k, ctx_a, b.queue_obj).is_empty());
    assert!(slots_of(&w.k, ctx_b, a.fb_obj).is_empty());
    assert!(slots_of(&w.k, ctx_b, a.queue_obj).is_empty());
    // Behaviourally: reading a slot number B reported either fails (A has no
    // such slot) or lands on one of A's *own* objects — never B's bytes.
    let b_fb_slot = slots_of(&w.k, ctx_b, b.fb_obj)[0];
    let cross = w.k.mem_read(ctx_a, CapHandle(b_fb_slot), 0, 4);
    match cross {
        Err(KernelError::NoCap) => {}
        Ok(bytes) => assert_ne!(bytes, b"CCCC".to_vec(), "A read B's framebuffer"),
        other => panic!("unexpected cross-read result: {other:?}"),
    }
    let b_queue_slot = slots_of(&w.k, ctx_b, b.queue_obj)[0];
    match w.k.cap_info(ctx_a, CapHandle(b_queue_slot)) {
        Err(_) => {}
        Ok(info) => assert_eq!(info.obj, a.queue_obj, "A resolved B's reported queue slot to a foreign object"),
    }
    // The framework's resolution path is equally deaf to foreign objects.
    assert_eq!(
        gfx.write_fb(&mut w.k, ctx_a, b, 0, b"pwned".to_vec()),
        Err(KernelError::NoCap)
    );

    // A context renders only into its own window...
    gfx.write_fb(&mut w.k, ctx_a, a, 0, b"AROW".to_vec())
        .unwrap();
    let a_slot = slots_of(&w.k, ctx_a, a.fb_obj)[0];
    assert_eq!(
        w.k.mem_read(ctx_a, CapHandle(a_slot), 0, 4).unwrap(),
        b"AROW"
    );
    // ...and B's window never saw it.
    let b_fb_slot = slots_of(&w.k, ctx_b, b.fb_obj)[0];
    assert_eq!(
        w.k.mem_read(ctx_b, CapHandle(b_fb_slot), 0, 4).unwrap(),
        b"CCCC"
    );
}

#[test]
fn a_compositor_is_a_replaceable_userspace_service() {
    let mut w = world();
    let mut gfx = GraphicsService::new(w.root, w.creator);

    let (ctx_a, name_a) = spawn(&mut w, "ctx-a");
    let (ctx_b, name_b) = spawn(&mut w, "ctx-b");
    let a = gfx.attach(&mut w.k, ctx_a, name_a, b"AAAA".to_vec()).unwrap();
    let b = gfx.attach(&mut w.k, ctx_b, name_b, b"BBBB".to_vec()).unwrap();
    gfx.write_fb(&mut w.k, ctx_a, a, 0, b"xxxx".to_vec())
        .unwrap();
    gfx.write_fb(&mut w.k, ctx_b, b, 0, b"yyyy".to_vec())
        .unwrap();

    // The display server is a userspace service with READ grants onto every
    // framebuffer; the screen comes out of *its* caps.
    let (compositor1, name1) = spawn(&mut w, "compositor-v1");
    gfx.attach_compositor(&mut w.k, compositor1, name1)
        .unwrap();
    w.k.task_spawn(w.root, name1).unwrap();
    let screen = gfx.compose(&mut w.k).unwrap();
    assert_eq!(screen, vec![b"xxxx".to_vec(), b"yyyy".to_vec()]);

    let ctx_a_before = census(&w.k, ctx_a);
    let ctx_b_before = census(&w.k, ctx_b);

    // The compositor dies; compositing stops for a dead display server, and
    // the contexts' capsules are untouched.
    w.k.task_kill(w.root, name1).unwrap();
    assert_eq!(gfx.compose(&mut w.k), Err(DeviceError::DeviceDown));
    assert_eq!(census(&w.k, ctx_a), ctx_a_before);
    assert_eq!(census(&w.k, ctx_b), ctx_b_before);

    // Replacement: a fresh display server, re-licenced, composites the same
    // screen. The kernel state never moved.
    let (compositor2, name2) = spawn(&mut w, "compositor-v2");
    gfx.attach_compositor(&mut w.k, compositor2, name2)
        .unwrap();
    w.k.task_spawn(w.root, name2).unwrap();
    assert_eq!(gfx.compose(&mut w.k).unwrap(), screen);
    assert_eq!(census(&w.k, ctx_a), ctx_a_before);
    assert_eq!(census(&w.k, ctx_b), ctx_b_before);
}
//! Loopback-stack contract (design doc §8): a userspace network stack whose
//! sockets are capability-scoped kernel endpoint objects. Holding the network
//! capability means holding a specific, revocable right to talk to a specific
//! endpoint — there is no ambient "open any socket" authority, and every hop
//! of every packet is visible in the kernel audit log with a real attributed
//! caller.

use capability_core::{CapHandle, Kernel, ObjectKind, TaskHandle};
use net::LoopbackStack;

struct World {
    k: Kernel,
    root: TaskHandle,
    creator: CapHandle,
    stack: LoopbackStack,
}

fn world() -> World {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    let stack = LoopbackStack::new(root, creator);
    World {
        k,
        root,
        creator,
        stack,
    }
}

fn spawn(w: &mut World, label: &str) -> TaskHandle {
    w.k.create_task(w.root, w.creator, label).unwrap().0
}

/// The stack's name for a task: a cap in the stack's CSpace naming it. v1: the
/// stack and the boot task are one identity, so the task cap from create_task
/// (in the boot task's CSpace, RECEIVE-bearing) is that name.
fn cap_of(k: &Kernel, root: TaskHandle, t: TaskHandle) -> CapHandle {
    let root_slot = (0..256u32)
        .find(|s| matches!(k.cap_info(root, CapHandle(*s)), Ok(i) if i.obj == t.id()))
        .unwrap();
    CapHandle(root_slot)
}

/// §8: sockets are capability-scoped objects — a task holding no channel cap
/// cannot inject into a socket, even knowing the port number, and the kernel
/// agrees at the SEND capability check.
#[test]
fn sockets_are_capability_scoped_and_ports_are_not_ambient_authority() {
    let mut w = world();
    let app_a = spawn(&mut w, "app-a");
    let app_b = spawn(&mut w, "app-b");
    let outsider = spawn(&mut w, "outsider");

    let (port_a, slot_a) = {
        let name = cap_of(&w.k, w.root, app_a);
        w.stack.register(&mut w.k, app_a, name).unwrap()
    };
    let (port_b, slot_b) = {
        let name = cap_of(&w.k, w.root, app_b);
        w.stack.register(&mut w.k, app_b, name).unwrap()
    };
    assert_ne!(port_a, port_b, "ports are unique per socket");

    // The outsider knows the port numbers but holds no channel cap.
    assert!(
        w.stack
            .send(&mut w.k, outsider, CapHandle(0), port_a, b"x".to_vec())
            .is_err(),
        "a task without a channel cap cannot speak, even knowing the port"
    );
    assert!(
        w.k.ep_send(outsider, CapHandle(0), b"raw".to_vec())
            .is_err(),
        "and the kernel agrees: no SEND cap, no injection at any layer"
    );

    w.stack
        .send(&mut w.k, app_a, CapHandle(slot_a), port_b, b"ping".to_vec())
        .unwrap();
    let b_to_a = w
        .stack
        .recv(&mut w.k, app_b, CapHandle(slot_b))
        .unwrap()
        .unwrap();
    assert_eq!(b_to_a, b"ping");
}

/// §8: the stack is a router over real kernel endpoints — every hop is a
/// logged, attributed endpoint op, so a packet's path is fully reconstructible
/// from the audit log alone.
#[test]
fn every_hop_is_an_attributed_endpoint_op_in_the_audit_log() {
    let mut w = world();
    let app_a = spawn(&mut w, "app-a");
    let app_b = spawn(&mut w, "app-b");
    let (port_b, slot_b) = {
        let name = cap_of(&w.k, w.root, app_b);
        w.stack.register(&mut w.k, app_b, name).unwrap()
    };
    let (port_a, slot_a) = {
        let name = cap_of(&w.k, w.root, app_a);
        w.stack.register(&mut w.k, app_a, name).unwrap()
    };
    let _ = (port_a, slot_a);

    for i in 0..3u8 {
        w.stack
            .send(&mut w.k, app_a, CapHandle(slot_a), port_b, vec![i])
            .unwrap();
    }

    // FIFO over the loopback: the endpoint queue preserves order exactly.
    for i in 0..3u8 {
        let got = w
            .stack
            .recv(&mut w.k, app_b, CapHandle(slot_b))
            .unwrap()
            .unwrap();
        assert_eq!(got, vec![i], "packets arrive in the order they were sent");
    }
    assert_eq!(
        w.stack.recv(&mut w.k, app_b, CapHandle(slot_b)).unwrap(),
        None,
        "and the queue is drained exactly"
    );

    // Every hop is attributed: the three injection sends are A's, the three
    // forward hops are the stack's — the log tells the whole path.
    let a_sends =
        w.k.audit()
            .query(
                Some(app_a.id()),
                capability_core::AuditFilter::Ops(&[capability_core::OpKind::Send]),
            )
            .count();
    let stack_sends =
        w.k.audit()
            .query(
                Some(w.root.id()),
                capability_core::AuditFilter::Ops(&[capability_core::OpKind::Send]),
            )
            .count();
    assert_eq!(
        a_sends, 3,
        "injection sends are attributed to the sender task"
    );
    assert!(
        stack_sends >= 3,
        "forward hops are attributed to the router"
    );
}

/// §8: network capabilities are revocable rights. Once the stack drops its
/// router cap, that socket is gone from the interface while every other
/// socket keeps working.
#[test]
fn a_socket_can_be_torn_down_without_touching_its_peers() {
    let mut w = world();
    let app_a = spawn(&mut w, "app-a");
    let (port_a, _) = {
        let name = cap_of(&w.k, w.root, app_a);
        w.stack.register(&mut w.k, app_a, name).unwrap()
    };
    let app_b = spawn(&mut w, "app-b");
    let (port_b, _) = {
        let name = cap_of(&w.k, w.root, app_b);
        w.stack.register(&mut w.k, app_b, name).unwrap()
    };

    let channel_a = (0..256u32)
        .find(|s| matches!(w.k.cap_info(w.root, CapHandle(*s)), Ok(i) if i.kind == ObjectKind::Endpoint))
        .unwrap();
    w.stack.unsubscribe(&mut w.k, CapHandle(channel_a)).unwrap();

    assert!(
        !w.stack.is_listening(port_a),
        "A's socket is gone from the interface"
    );
    assert!(w.stack.is_listening(port_b), "B's socket is untouched");
}

/// The stack is a router, not a root: after a conversation its CSpace holds
/// exactly its own artifacts plus the boot role's — no grant roots, no extra
/// creators, no new task authority.
#[test]
fn the_stack_holds_no_authority_beyond_its_sockets() {
    let mut w = world();
    let app_a = spawn(&mut w, "app-a");
    let app_b = spawn(&mut w, "app-b");
    let (port_a, _) = {
        let name = cap_of(&w.k, w.root, app_a);
        w.stack.register(&mut w.k, app_a, name).unwrap()
    };
    let (port_b, _) = {
        let name = cap_of(&w.k, w.root, app_b);
        w.stack.register(&mut w.k, app_b, name).unwrap()
    };

    let (mut grant_roots, mut creators, mut endpoints) = (0, 0, 0);
    for slot in 0..256u32 {
        if let Ok(info) = w.k.cap_info(w.root, CapHandle(slot)) {
            match info.kind {
                ObjectKind::GrantRoot => grant_roots += 1,
                ObjectKind::Creator => creators += 1,
                ObjectKind::Endpoint => endpoints += 1,
                _ => {}
            }
        }
    }
    assert_eq!(grant_roots, 0, "the stack created no grant roots");
    assert_eq!(creators, 1, "only the boot role's own creator");
    assert_eq!(endpoints, 2, "exactly the two channel endpoints it routes");
    assert!(w.stack.is_listening(port_a) && w.stack.is_listening(port_b));
}

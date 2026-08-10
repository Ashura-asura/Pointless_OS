//! Executable checks for the endpoint/IPC claims of the design doc (§8 IPC: two
//! primitives, rendezvous endpoints, capability-scoped socket objects). Enforcement
//! here: SEND/RECV are rights on the endpoint *capability*, not ambient access; a
//! task with no endpoint cap cannot name an endpoint (handles resolve against its
//! own CSpace only); delivery is FIFO; every send, recv and refusal is in the audit
//! log keyed by endpoint identity.

use capability_core::{
    AuditFilter, CapHandle, Kernel, KernelError, ObjectKind, OpKind, Rights, TaskHandle,
};

fn boot() -> (Kernel, TaskHandle, CapHandle) {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    (k, root, creator)
}

fn task(
    k: &mut Kernel,
    root: TaskHandle,
    creator: CapHandle,
    label: &str,
) -> (TaskHandle, CapHandle) {
    k.create_task(root, creator, label).unwrap()
}

/// The endpoint's identity as introspected through the caller's own cap
/// (`CapInfo.obj` — the stable, queryable audit key, design doc §9.4).
fn endpoint_id(k: &Kernel, root: TaskHandle, ep: CapHandle) -> capability_core::ObjectId {
    k.cap_info(root, ep).unwrap().obj
}

/// The slot of the first endpoint cap in `t`'s CSpace (slot addressing is how a
/// task names its own table).
fn endpoint_slot(k: &Kernel, t: TaskHandle) -> u32 {
    k.authorized(t)
        .iter()
        .find(|c| c.kind == ObjectKind::Endpoint)
        .unwrap()
        .slot
}

/// SEND and RECV are independent rights on the endpoint capability: a task granted
/// only SEND cannot receive, and vice versa. FIFO delivery between the two peers.
#[test]
fn send_and_recv_are_independent_rights() {
    let (mut k, root, creator) = boot();
    let (smtp, smtp_cap) = task(&mut k, root, creator, "smtp");
    let (ntp, ntp_cap) = task(&mut k, root, creator, "ntp");
    let ep = k.create_endpoint(root, creator).unwrap();

    // smtp may only send; ntp may only receive.
    k.grant(root, ep, smtp_cap, Rights::SEND, None).unwrap();
    k.grant(root, ep, ntp_cap, Rights::RECV, None).unwrap();
    let smtp_ep = endpoint_slot(&k, smtp);
    let ntp_ep = endpoint_slot(&k, ntp);

    k.ep_send(smtp, CapHandle(smtp_ep), b"hello".to_vec())
        .unwrap();
    assert_eq!(
        k.ep_recv(ntp, CapHandle(ntp_ep)).unwrap(),
        Some(b"hello".to_vec()),
        "FIFO delivery broke"
    );

    // The gaps: smtp cannot receive, ntp cannot send.
    assert_eq!(
        k.ep_recv(smtp, CapHandle(smtp_ep)).unwrap_err(),
        KernelError::InsufficientRights(Rights::RECV)
    );
    assert_eq!(
        k.ep_send(ntp, CapHandle(ntp_ep), b"reply".to_vec())
            .unwrap_err(),
        KernelError::InsufficientRights(Rights::SEND)
    );
}

/// A narrowed copy keeps the narrowing: a RECV-only copy of a full endpoint cap
/// cannot send on the *copy*.
#[test]
fn narrowed_copies_preserve_the_narrowing() {
    let (mut k, root, creator) = boot();
    let ep = k.create_endpoint(root, creator).unwrap();
    let recv_copy = k.copy(root, ep, Rights::RECV).unwrap();
    // The copy: receive works (empty queue -> None, not an error)…
    assert_eq!(k.ep_recv(root, recv_copy).unwrap(), None);
    // …but sending on it is refused, even though the original cap in root's table
    // still carries SEND.
    assert_eq!(
        k.ep_send(root, recv_copy, b"x".to_vec()).unwrap_err(),
        KernelError::InsufficientRights(Rights::SEND)
    );
}

/// No endpoint cap, no endpoint: forged or leaked slot numbers resolve against the
/// caller's own table and fail cleanly.
#[test]
fn fabricated_handles_cannot_name_an_endpoint() {
    let (mut k, root, creator) = boot();
    let (smtp, _smtp_cap) = task(&mut k, root, creator, "smtp");
    let (ntp, ntp_cap) = task(&mut k, root, creator, "ntp");
    let (agent, _agent_cap) = task(&mut k, root, creator, "agent");
    let ep = k.create_endpoint(root, creator).unwrap();
    k.grant(root, ep, ntp_cap, Rights::SEND, None).unwrap();

    // The agent "learned" ntp's endpoint slot number. It is meaningless outside
    // ntp's table: the agent's own slot carries nothing.
    let leaked = endpoint_slot(&k, ntp);
    assert_eq!(
        k.ep_send(agent, CapHandle(leaked), b"x".to_vec())
            .unwrap_err(),
        KernelError::NoCap
    );
    // Its own slot 0 holds the self cap, a Task cap: not an endpoint.
    assert_eq!(
        k.ep_send(agent, CapHandle(0), b"x".to_vec()).unwrap_err(),
        KernelError::WrongObjectType
    );
    // smtp never received a cap: same story.
    assert_eq!(
        k.ep_recv(smtp, CapHandle(0)).unwrap_err(),
        KernelError::WrongObjectType
    );
}

/// Every send, recv and refusal is in the audit log, keyed by endpoint identity —
/// "what did this agent actually do with what it was given" stays answerable.
#[test]
fn ipc_is_fully_audited() {
    let (mut k, root, creator) = boot();
    let (smtp, smtp_cap) = task(&mut k, root, creator, "smtp");
    let (ntp, ntp_cap) = task(&mut k, root, creator, "ntp");
    let (agent, _agent_cap) = task(&mut k, root, creator, "agent");
    let ep = k.create_endpoint(root, creator).unwrap();
    let ep_obj = endpoint_id(&k, root, ep);

    k.grant(root, ep, smtp_cap, Rights::SEND, None).unwrap();
    k.grant(root, ep, ntp_cap, Rights::RECV, None).unwrap();
    let smtp_ep = endpoint_slot(&k, smtp);
    let ntp_ep = endpoint_slot(&k, ntp);

    k.ep_send(smtp, CapHandle(smtp_ep), b"ping".to_vec())
        .unwrap();
    k.ep_recv(ntp, CapHandle(ntp_ep)).unwrap();
    assert_eq!(
        k.ep_send(agent, CapHandle(0), b"x".to_vec()).unwrap_err(),
        KernelError::WrongObjectType
    );

    assert!(k.audit().ever_succeeded(smtp.id(), OpKind::Send, ep_obj));
    assert!(k.audit().ever_succeeded(ntp.id(), OpKind::Recv, ep_obj));
    let refused = k
        .audit()
        .query(Some(agent.id()), AuditFilter::Ops(&[OpKind::Send]))
        .filter(|r| !r.ok)
        .count();
    assert_eq!(refused, 1, "the refusal is on record");
}

/// The asynchronous notification path (design doc §8, second primitive): a sender
/// with nobody listening never blocks — the kernel buffers the message and the
/// receiver drains the queue later, one message at a time, in FIFO order.
#[test]
fn async_senders_never_block_and_fifo_survives_the_buffer() {
    let (mut k, root, creator) = boot();
    let (sensor, sensor_cap) = task(&mut k, root, creator, "sensor");
    let (daemon, daemon_cap) = task(&mut k, root, creator, "daemon");
    let ep = k.create_endpoint(root, creator).unwrap();
    k.grant(root, ep, sensor_cap, Rights::SEND, None).unwrap();
    k.grant(root, ep, daemon_cap, Rights::RECV, None).unwrap();
    let sensor_ep = endpoint_slot(&k, sensor);
    let daemon_ep = endpoint_slot(&k, daemon);

    // Burst of three events while the daemon is busy elsewhere. Non-blocking by
    // construction; the queue absorbs the burst.
    for i in 0..3u8 {
        k.ep_send(sensor, CapHandle(sensor_ep), vec![i]).unwrap();
    }
    // Nothing lost or reordered, drained one at a time.
    assert_eq!(
        k.ep_recv(daemon, CapHandle(daemon_ep)).unwrap(),
        Some(vec![0])
    );
    assert_eq!(
        k.ep_recv(daemon, CapHandle(daemon_ep)).unwrap(),
        Some(vec![1])
    );
    assert_eq!(
        k.ep_recv(daemon, CapHandle(daemon_ep)).unwrap(),
        Some(vec![2])
    );
    assert_eq!(
        k.ep_recv(daemon, CapHandle(daemon_ep)).unwrap(),
        None,
        "queue must be drained, not duplicated"
    );
    // The burst is on record even though no one was listening at the time.
    let ep_obj = endpoint_id(&k, root, ep);
    assert!(k.audit().ever_succeeded(sensor.id(), OpKind::Send, ep_obj));
}

/// Endpoints are anonymous queue identities, never ambient channels: two endpoints
/// keep separate queues even between the same tasks.
#[test]
fn two_endpoints_keep_separate_queues() {
    let (mut k, root, creator) = boot();
    let (peer, peer_cap) = task(&mut k, root, creator, "peer");
    let ep_a = k.create_endpoint(root, creator).unwrap();
    let ep_b = k.create_endpoint(root, creator).unwrap();
    k.grant(root, ep_a, peer_cap, Rights::SEND, None).unwrap();
    k.grant(root, ep_b, peer_cap, Rights::SEND, None).unwrap();
    let ep_a_slot = endpoint_slot(&k, peer);
    // Two endpoints in peer's table; find the slot that is NOT ep_a.
    let ep_b_slot = k
        .authorized(peer)
        .iter()
        .filter(|c| c.kind == ObjectKind::Endpoint)
        .map(|c| c.slot)
        .find(|s| *s != ep_a_slot)
        .unwrap();

    k.ep_send(peer, CapHandle(ep_a_slot), b"a".to_vec())
        .unwrap();
    k.ep_send(peer, CapHandle(ep_b_slot), b"b".to_vec())
        .unwrap();
    assert_eq!(
        k.ep_recv(root, ep_a).unwrap(),
        Some(b"a".to_vec()),
        "ep_a must yield only its own message"
    );
    assert_eq!(k.ep_recv(root, ep_a).unwrap(), None);
    assert_eq!(k.ep_recv(root, ep_b).unwrap(), Some(b"b".to_vec()));
}

/// Bulk data moves by capability grant, not byte-copy through the kernel (design
/// doc §8): the producer creates a region, grants READ of it to the consumer, and
/// only the *notification* travels over the endpoint. The payload never enters the
/// kernel's queue — it is addressed by the region cap the consumer already holds.
#[test]
fn bulk_data_moves_by_capability_grant_not_byte_copy() {
    let (mut k, root, creator) = boot();
    let (producer, producer_cap) = task(&mut k, root, creator, "producer");
    let (consumer, consumer_cap) = task(&mut k, root, creator, "consumer");
    let region = k.create_mem(root, creator, vec![7u8; 64 * 1024]).unwrap();
    let ep = k.create_endpoint(root, creator).unwrap();

    k.grant(root, region, producer_cap, Rights::WRITE, None)
        .unwrap();
    k.grant(root, region, consumer_cap, Rights::READ, None)
        .unwrap();
    k.grant(root, ep, producer_cap, Rights::SEND, None).unwrap();
    k.grant(root, ep, consumer_cap, Rights::RECV, None).unwrap();
    let producer_slot = |k: &Kernel| endpoint_slot(k, producer);
    let producer_region = {
        let caps = k.authorized(producer);
        caps.iter()
            .find(|c| c.kind == ObjectKind::MemRegion)
            .unwrap()
            .slot
    };
    let consumer_region = {
        let caps = k.authorized(consumer);
        caps.iter()
            .find(|c| c.kind == ObjectKind::MemRegion)
            .unwrap()
            .slot
    };

    // Producer writes the payload into the shared region, then notifies.
    k.mem_write(
        producer,
        CapHandle(producer_region),
        0,
        b"log line #1".to_vec(),
    )
    .unwrap();
    k.ep_send(producer, CapHandle(producer_slot(&k)), b"ready".to_vec())
        .unwrap();

    // Consumer is woken by the notification — a 5-byte message — and reads the
    // 64 KiB payload straight out of the region through its own cap.
    assert_eq!(
        k.ep_recv(consumer, CapHandle(endpoint_slot(&k, consumer)))
            .unwrap(),
        Some(b"ready".to_vec())
    );
    assert_eq!(
        k.mem_read(consumer, CapHandle(consumer_region), 0, 11)
            .unwrap(),
        b"log line #1".to_vec()
    );
    // The rest of the region is intact behind the read window.
    assert_eq!(
        k.mem_read(consumer, CapHandle(consumer_region), 11, 3)
            .unwrap(),
        vec![7, 7, 7]
    );
    // READ-only cannot be turned into WRITE: the grant narrowed the cap (I2).
    assert_eq!(
        k.mem_write(consumer, CapHandle(consumer_region), 0, b"x".to_vec())
            .unwrap_err(),
        KernelError::InsufficientRights(Rights::WRITE)
    );
    // The payload never entered the endpoint queue: only the notification did.
    let ep_obj = endpoint_id(&k, root, ep);
    let sent = k
        .audit()
        .query(Some(producer.id()), AuditFilter::Ops(&[OpKind::Send]))
        .filter(|r| r.ok && r.target == Some(ep_obj))
        .count();
    assert_eq!(
        sent, 1,
        "exactly one byte-copy class of traffic: the notification"
    );
}

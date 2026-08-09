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

fn task(k: &mut Kernel, root: TaskHandle, creator: CapHandle, label: &str) -> (TaskHandle, CapHandle) {
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

    k.ep_send(smtp, CapHandle(smtp_ep), b"hello".to_vec()).unwrap();
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
        k.ep_send(ntp, CapHandle(ntp_ep), b"reply".to_vec()).unwrap_err(),
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
        k.ep_send(agent, CapHandle(leaked), b"x".to_vec()).unwrap_err(),
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

    k.ep_send(smtp, CapHandle(smtp_ep), b"ping".to_vec()).unwrap();
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
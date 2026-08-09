//! Executable checks for the behavioral anomaly circuit breaker (§9): a
//! lightweight, capability-less monitor reads the kernel's own audit log,
//! compares the agent's op-shape against the role's trained baseline, and on
//! significant deviation *suspends* — never revokes — the agent's grants,
//! pending human review. Suspension is reversible and logged; revocation is
//! permanent and is never performed by the monitor.

use capability_core::{
    AuditFilter, CapHandle, Kernel, ObjectId, OpKind, TaskHandle,
};
use grants::monitor::{Monitor, MonitorEvent};
use grants::role::RoleLibrary;
use grants::{GrantPolicy, GrantService, GrantTarget};

fn boot() -> (Kernel, TaskHandle, CapHandle) {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    (k, root, creator)
}

fn spawn(k: &mut Kernel, root: TaskHandle, creator: CapHandle, label: &str) -> (TaskHandle, CapHandle) {
    k.create_task(root, creator, label).unwrap()
}

/// The agent's own slot naming `obj`, scanned from its CSpace.
fn agent_slot(k: &Kernel, agent: TaskHandle, obj: ObjectId) -> CapHandle {
    (0..256u32)
        .find(|s| k.cap_info(agent, CapHandle(*s)).is_ok_and(|i| i.obj == obj))
        .map(CapHandle)
        .expect("the agent holds a cap to this object")
}

/// Grant the agent the restart-service role (READ+CONTROL over `svc`),
/// task-scoped.
fn grant_restart_role(
    k: &mut Kernel,
    _root: TaskHandle,
    svc: &mut GrantService,
    agent_cap: CapHandle,
    svc_task_cap: CapHandle,
) {
    let lib = RoleLibrary::default_roles();
    let pending = svc
        .propose(
            k,
            &lib,
            "restart-service",
            "agent",
            agent_cap,
            GrantTarget {
                label: "svc".into(),
                source: svc_task_cap,
            },
            GrantPolicy::TaskScoped { ticks: 100 },
        )
        .unwrap();
    svc.confirm(k, pending).unwrap();
}

fn op_count(k: &Kernel, caller: ObjectId, op: OpKind) -> usize {
    k.audit()
        .query(Some(caller), AuditFilter::All)
        .filter(|r| r.op == op)
        .count()
}

#[test]
fn a_significant_deviation_auto_suspends_without_revoking() {
    let (mut k, root, creator) = boot();
    let (svc_task, svc_task_cap) = spawn(&mut k, root, creator, "smtp");
    let (agent, agent_cap) = spawn(&mut k, root, creator, "agent");
    k.task_spawn(root, agent_cap).unwrap();
    k.task_spawn(root, svc_task_cap).unwrap();
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    grant_restart_role(&mut k, root, &mut svc, agent_cap, svc_task_cap);

    // The role's normal shape: the agent occasionally checks the service
    // state (a task_running via its READ right) — that's what it *does*.
    let agent_svc = agent_slot(&k, agent, svc_task.id());
    for _ in 0..2 {
        assert!(k.task_running(agent, agent_svc).unwrap());
    }
    let mut monitor = Monitor::train(&k, agent);
    assert!(monitor.log().iter().any(|e| matches!(e, MonitorEvent::Trained { shapes: 1 })));

    // Still doing what its shape says: no deviation, no suspension.
    assert!(k.task_running(agent, agent_svc).unwrap());
    assert!(!monitor.observe(&k, &mut svc));
    assert!(!svc.is_suspended(agent.id()));

    // Significant deviation: the agent now does something its role never does
    // — endpoint sends. The refused ops still land in the kernel log with the
    // caller attributed, which is exactly the kernel truth the monitor reads.
    for _ in 0..4 {
        let _ = k.ep_send(agent, CapHandle(0), vec![1u8].into());
    }
    assert!(monitor.observe(&k, &mut svc));
    assert!(svc.is_suspended(agent.id()));
    assert!(svc.policy_log().iter().any(|e| matches!(
        e,
        grants::PolicyEvent::Suspended { agent: a, .. } if *a == agent.id()
    )));
    assert!(monitor
        .log()
        .iter()
        .any(|e| matches!(e, MonitorEvent::Deviation { seen: n, .. } if *n >= 4)));

    // Suspended is not revoked: the already-minted cap still works — the
    // agent's state checks pass — because the monitor took nothing away.
    assert!(k.task_running(agent, agent_svc).unwrap());
    assert_eq!(op_count(&k, agent.id(), OpKind::Revoke), 0, "the monitor never revokes");

    // But the grant flow is frozen: a new confirmation for the suspended
    // agent is refused, and the refusal is a visible policy event.
    let inbox = k.create_endpoint(root, creator).unwrap();
    let pending = svc
        .propose(
            &k,
            &RoleLibrary::default_roles(),
            "triage-inbox",
            "agent",
            agent_cap,
            GrantTarget {
                label: "inbox".into(),
                source: inbox,
            },
            GrantPolicy::TaskScoped { ticks: 50 },
        )
        .unwrap();
    assert!(svc.confirm(&mut k, pending).is_err());
    assert_eq!(svc.list_active().len(), 1, "the original grant is untouched");
}

#[test]
fn suspension_is_reversible_logged_and_never_silent() {
    let (mut k, root, creator) = boot();
    let (svc_task, svc_task_cap) = spawn(&mut k, root, creator, "smtp");
    let (agent, agent_cap) = spawn(&mut k, root, creator, "agent");
    k.task_spawn(root, agent_cap).unwrap();
    k.task_spawn(root, svc_task_cap).unwrap();
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    grant_restart_role(&mut k, root, &mut svc, agent_cap, svc_task_cap);

    let agent_svc = agent_slot(&k, agent, svc_task.id());
    assert!(k.task_running(agent, agent_svc).unwrap());
    let mut monitor = Monitor::train(&k, agent);

    // Deviation: an op kind the profile never saw.
    let _ = k.ep_send(agent, CapHandle(0), vec![1u8].into());
    assert!(monitor.observe(&k, &mut svc));
    assert!(svc.is_suspended(agent.id()));

    // Kernel state is untouched: no Revoke records exist anywhere.
    assert_eq!(op_count(&k, agent.id(), OpKind::Revoke), 0);

    // Human review resumes the agent: reversible, and the resume is a logged
    // policy event, never silent.
    svc.resume(&k, agent);
    assert!(!svc.is_suspended(agent.id()));
    assert!(svc.policy_log().iter().any(|e| matches!(
        e,
        grants::PolicyEvent::Resumed { agent: a, .. } if *a == agent.id()
    )));

    // With the suspension cleared, the grant flow works again.
    let inbox = k.create_endpoint(root, creator).unwrap();
    let pending = svc
        .propose(
            &k,
            &RoleLibrary::default_roles(),
            "triage-inbox",
            "agent",
            agent_cap,
            GrantTarget {
                label: "inbox".into(),
                source: inbox,
            },
            GrantPolicy::TaskScoped { ticks: 50 },
        )
        .unwrap();
    assert!(svc.confirm(&mut k, pending).is_ok());
}

#[test]
fn the_monitor_is_a_read_only_service_with_no_authority() {
    let (mut k, root, creator) = boot();
    let (monitor_task, monitor_cap) = spawn(&mut k, root, creator, "monitor");

    // The monitor's complete authority: a self-cap. Nothing else was granted.
    let caps = k.caps_of(monitor_task);
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].obj, monitor_task.id());

    // Training is passive reading of kernel truth — and it happens before any
    // refused activity, so the profile of a task that has done nothing is
    // empty. (Failed ops are still logged with attribution; training would
    // otherwise see them.)
    let watch = Monitor::train(&k, monitor_task);
    assert!(watch.log().iter().any(|e| matches!(e, MonitorEvent::Trained { shapes: 0 })));

    // Fabricated authority is refused at the kernel: it cannot kill, revoke,
    // or create — its only "power" is reading the audit log and asking a
    // grant service to flip ledger state.
    assert!(k.task_kill(monitor_task, monitor_cap).is_err());
    assert!(k.revoke(monitor_task, monitor_cap).is_err());
    assert!(k.create_task(monitor_task, CapHandle(0), "x").is_err());
}
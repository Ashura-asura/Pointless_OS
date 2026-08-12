//! Executable checks for the supervision claims of the design doc (§5: supervision
//! is circuit breaker + supervision tree, not silent retry). The kernel's side of
//! the contract is capability-shaped: a crash is a TaskKill event, a restart is a
//! TaskSpawn through a granted CONTROL cap, containment is the supervisor's
//! full-subtree revoke (I4), and every step — including the refused retry after
//! revocation — is an audited event. Enforcement here: the supervision cycle is
//! reconstructable from the audit log alone, the escalation stop is enforced and
//! logged, and the power to restart is exactly the granted role (READ+CONTROL over
//! one named service), never anything ambient.

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

/// The supervision scene: root supervises smtp; agent is granted the
/// "restart-service" role (READ+CONTROL over smtp's task cap, nothing else).
struct Scene {
    k: Kernel,
    root: TaskHandle,
    smtp: TaskHandle,
    smtp_cap: CapHandle,
    agent: TaskHandle,
    role_slot: u32,
}

fn scene() -> Scene {
    let (mut k, root, creator) = boot();
    let (smtp, smtp_cap) = task(&mut k, root, creator, "smtp");
    let (agent, agent_cap) = task(&mut k, root, creator, "agent");
    k.grant(
        root,
        smtp_cap,
        agent_cap,
        Rights::READ.union(Rights::CONTROL),
        None,
    )
    .unwrap();
    // The agent's copy of the role: find the slot in ITS table naming smtp's task
    // obj (slot addressing is how a task names its own table).
    let mut role_slot = None;
    for slot in 0..256 {
        if let Ok(info) = k.cap_info(agent, CapHandle(slot)) {
            if info.obj == smtp.id() && info.kind == ObjectKind::Task {
                role_slot = Some(slot);
                break;
            }
        }
    }
    let role_slot = role_slot.unwrap_or_else(|| panic!("role cap not found in agent's CSpace"));
    Scene {
        k,
        root,
        smtp,
        smtp_cap,
        agent,
        role_slot,
    }
}

/// Crash containment is a full-subtree revoke, not a flag flip: after the
/// supervisor revokes the authorizing cap, the agent's restart power is gone
/// from its own table — while the supervisor's world (and the dead task's
/// forensic state, `running == false`) survives for diagnosis.
#[test]
fn crash_containment_is_a_full_subtree_revoke() {
    let mut s = scene();
    // The crash. The supervisor keeps its own authorizing cap.
    s.k.task_kill(s.root, s.smtp_cap).unwrap();
    assert!(!s.k.task_running(s.root, s.smtp_cap).unwrap());

    // Containment: revoke the authorizing cap; the whole derivation subtree dies
    // everywhere (I4), including the agent's granted copy.
    s.k.revoke(s.root, s.smtp_cap).unwrap();
    let after = s.k.caps_of(s.agent);
    assert!(
        after
            .iter()
            .all(|c| c.kind != ObjectKind::Task || c.obj != s.smtp.id()),
        "the role's task cap must be gone from the agent: {after:?}"
    );
    let refused_restart = s.k.task_spawn(s.agent, CapHandle(s.role_slot)).unwrap_err();
    assert_eq!(refused_restart, KernelError::NoCap);
    // Forensics survive the containment: the death is on record as a kill (not a
    // destroy), so diagnosis did not lose the dead task.
    assert!(s
        .k
        .audit()
        .ever_succeeded(s.root.id(), OpKind::TaskKill, s.smtp.id()));
}

/// The restart window: while the role is live, a restart is a distinct, audited
/// event — the supervisor's kill and the agent's spawns are different records with
/// different callers, so the cycle is reconstructable; the role bought restart
/// only (no creation, no grants, no kills beyond the one service).
#[test]
fn the_supervision_cycle_is_reconstructable_from_the_audit() {
    let mut s = scene();
    s.k.task_kill(s.root, s.smtp_cap).unwrap();
    s.k.task_spawn(s.agent, CapHandle(s.role_slot)).unwrap();
    // Second restart attempt (crash-loop) while the role is live: the kernel
    // permits the retry; escalation is the supervisor's decision, and the retry
    // itself stays on record.
    s.k.task_spawn(s.agent, CapHandle(s.role_slot)).unwrap();

    assert!(s
        .k
        .audit()
        .ever_succeeded(s.root.id(), OpKind::TaskKill, s.smtp.id()));
    let spawns =
        s.k.audit()
            .query(Some(s.agent.id()), AuditFilter::Ops(&[OpKind::TaskSpawn]))
            .filter(|r| r.ok && r.target == Some(s.smtp.id()))
            .count();
    assert_eq!(spawns, 2, "both restart attempts are on record");
    let unrelated =
        s.k.audit()
            .query(
                Some(s.agent.id()),
                AuditFilter::Ops(&[
                    OpKind::CreateTask,
                    OpKind::CreateEndpoint,
                    OpKind::CreateMemRegion,
                    OpKind::CreateGrantRoot,
                    OpKind::Grant,
                    OpKind::Revoke,
                    OpKind::TaskKill,
                ]),
            )
            .filter(|r| r.ok)
            .count();
    assert_eq!(unrelated, 0, "the role bought restart only");
}

/// Escalation ends the retry loop: once containment has revoked the role, the
/// agent cannot keep restarting — and the refusal is a logged failed TaskSpawn,
/// never a silent swallow.
#[test]
fn escalation_stops_the_retry_loop_and_logs_it() {
    let mut s = scene();
    s.k.task_kill(s.root, s.smtp_cap).unwrap();
    s.k.revoke(s.root, s.smtp_cap).unwrap();

    assert!(s.k.task_spawn(s.agent, CapHandle(s.role_slot)).is_err());
    let refusals =
        s.k.audit()
            .query(Some(s.agent.id()), AuditFilter::Ops(&[OpKind::TaskSpawn]))
            .filter(|r| !r.ok)
            .count();
    assert_eq!(refusals, 1, "the refused retry is on record, not silent");
}

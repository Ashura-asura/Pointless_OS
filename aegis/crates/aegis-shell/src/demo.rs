//! The smallest prototype that proves the architecture (design doc §11.F, run on a
//! host model instead of seL4): boot → supervised service → agent granted exactly one
//! role → the agent restarts the crashed service and nothing else → adversarial suite.
//!
//! The adversarial suite runs under the agent's own identity: the point is that
//! identity granting and capability enforcement are different mechanisms, and only
//! the latter decides what may happen.

use capability_core::{
    AuditFilter, CapHandle, Kernel, KernelError, ObjectKind, OpKind, TaskHandle,
};
use grants::{GrantPolicy, GrantService, GrantTarget, RoleLibrary};

use crate::rogue::{escalation_suite, RogueContext};

pub struct Outcome {
    /// Escalation attempts that were required to fail, and did.
    pub failed_escalations: usize,
}

/// The agent's entire authorized job: bring the named service back up.
fn restart_service(kernel: &mut Kernel, me: TaskHandle, service: CapHandle) -> bool {
    let down = !kernel.task_running(me, service).unwrap_or(false);
    if down {
        kernel.task_spawn(me, service).is_ok()
    } else {
        true
    }
}

pub fn run() -> Outcome {
    let mut k = Kernel::new();
    let (root, _root_self, root_creator) = k.boot("session").unwrap();

    // Two services, one of which the agent is never authorized to touch.
    let (smtp, smtp_cap) = k.create_task(root, root_creator, "smtp").unwrap();
    let (ntp, ntp_cap) = k.create_task(root, root_creator, "ntp").unwrap();
    k.task_spawn(root, smtp_cap).unwrap();
    k.task_spawn(root, ntp_cap).unwrap();

    // The agent: an execution context like any other, currently holding *nothing*
    // but its self cap.
    let (agent, agent_cap) = k.create_task(root, root_creator, "assistant").unwrap();

    // ---- grant flow: role-shaped, ephemeral, diff-confirmed, audited
    let lib = RoleLibrary::default_roles();
    let mut svc = GrantService::new(&mut k, root, root_creator).unwrap();
    let pending = svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "assistant",
            agent_cap,
            GrantTarget {
                label: "smtp".to_string(),
                source: smtp_cap,
            },
            GrantPolicy::TaskScoped { ticks: 1000 },
        )
        .unwrap();

    println!("--- confirmation diff (human review, section 9.3) ---");
    for line in GrantService::diff(&pending) {
        println!("  + grant agent 'assistant': {:<56} kind={} rights={} policy={} -> target '{}'",
            line.note, line.kind, line.rights, line.policy, line.target_label);
    }

    let granted = svc.confirm(&mut k, pending).unwrap();
    let grant_slot = CapHandle(granted.caps[0].slot);

    // ---- reachable-authority auditor (design doc §10 [CLOSED]): the build breaks
    // if the agent's reachable authority ever grows beyond its manifest. Audited
    // *after* the adversarial suite, so the ceiling claim covers the attack run too.
    let session_manifest = capability_audit::manifests::session();
    let assistant_manifest = capability_audit::manifests::assistant();
    let report = capability_audit::audit::audit(
        &k,
        &[
            (root, &session_manifest),
            (agent, &assistant_manifest),
        ],
    );
    for (service, ws) in &report.warnings {
        for w in ws {
            println!("  audit warning  {service}: {w}");
        }
    }
    assert!(
        report.is_clean(),
        "reachable authority exceeds the manifest: {report:?}"
    );
    println!(
        "[PASS] reachable-authority audit: {} services within declared manifests ({} warnings)",
        report.entries.len(),
        report.warning_count()
    );

    // ---- the task itself: smtp crashes; the agent restarts it, nothing else
    k.task_kill(root, smtp_cap).unwrap(); // the crash (would be a supervisor detection)
    assert!(!k.task_running(root, smtp_cap).unwrap());

    assert!(
        restart_service(&mut k, agent, grant_slot),
        "agent failed its one authorized job"
    );
    assert!(
        k.task_running(root, smtp_cap).unwrap(),
        "service did not come back up"
    );

    // ---- adversarial suite: same identity, same kernel, escalation must fail
    let ctx = RogueContext {
        me: agent,
        my_slots: vec![CapHandle(0), grant_slot],
        // The agent "knows" the raw index of ntp's cap in the *owner's* CSpace.
        // Using it must fail: handles resolve against the caller's CSpace.
        leaked_owner_slot: ntp_cap,
    };
    let mut required = 0usize;
    for attempt in escalation_suite() {
        let result = (attempt.run)(&mut k, &ctx);
        let ok = if attempt.expected_failure {
            result.is_err()
        } else {
            result.is_ok()
        };
        if attempt.expected_failure {
            required += 1;
        }
        let marker = if ok { "PASS" } else { "FAIL" };
        let outcome = match &result {
            Ok(()) => "ok (confined)".to_string(),
            Err(e) => format!("rejected: {e}"),
        };
        println!("[{marker}] {:<42} {outcome:<24} ({})", attempt.name, attempt.explains);
        assert!(ok, "ceiling broken by '{}': {result:?}", attempt.name);
    }

    // ---- audit trail: "what did the agent actually do" is answerable
    assert!(
        k.audit().ever_succeeded(agent.id(), OpKind::TaskSpawn, smtp.id()),
        "audit lost the authorized restart"
    );
    assert!(
        !k.audit().ever_succeeded(agent.id(), OpKind::TaskKill, ntp.id()),
        "audit shows the agent touched ntp — the ceiling did not hold"
    );
    assert!(
        !k.audit().ever_succeeded(agent.id(), OpKind::CreateTask, ntp.id()),
        "audit shows the agent created objects"
    );
    let ok_ops = k
        .audit()
        .query(Some(agent.id()), AuditFilter::Success)
        .count();
    let failed_ops = k
        .audit()
        .query(Some(agent.id()), AuditFilter::Failed)
        .count();
    println!(
        "--- audit: agent performed {ok_ops} successful ops and {failed_ops} rejected ops, all logged ---"
    );

    // ---- completion: task-scoped grant dies with the task (supervisor revokes)
    svc.revoke(&mut k).unwrap();
    let after = k.authorized(agent);
    assert_eq!(after.len(), 1, "revoke left trace: {after:?}");
    assert_eq!(after[0].kind, ObjectKind::Task); // only the self cap

    // ---- second grant, short-lived: the kernel clock kills it, not the supervisor
    let mut svc2 = GrantService::new(&mut k, root, root_creator).unwrap();
    let pending2 = svc2
        .propose(
            &k,
            &lib,
            "restart-service",
            "assistant",
            agent_cap,
            GrantTarget {
                label: "smtp".to_string(),
                source: smtp_cap,
            },
            GrantPolicy::TaskScoped { ticks: 10 },
        )
        .unwrap();
    let g2 = svc2.confirm(&mut k, pending2).unwrap();
    let g2_slot = CapHandle(g2.caps[0].slot);
    assert!(k.task_running(agent, g2_slot).is_ok(), "fresh grant unusable");
    k.advance(11);
    assert_eq!(
        k.task_running(agent, g2_slot).unwrap_err(),
        KernelError::CapExpired,
        "expired grant still usable"
    );
    println!("[PASS] kernel-clock expiry kills a grant the supervisor forgot about");

    // persistent policy is refused for a role that forbids it (§9.2 gate)
    let persistent = svc2.propose(
        &k,
        &lib,
        "restart-service",
        "assistant",
        agent_cap,
        GrantTarget {
            label: "smtp".to_string(),
            source: smtp_cap,
        },
        GrantPolicy::Persistent,
    );
    assert!(persistent.is_err(), "persistent grant slipped through the §9.2 gate");
    println!("[PASS] persistent grant refused for an ephemeral-only role");
    svc2.revoke(&mut k).unwrap();
    assert_eq!(k.authorized(agent).len(), 1, "second revoke left trace");

    Outcome {
        failed_escalations: required,
    }
}
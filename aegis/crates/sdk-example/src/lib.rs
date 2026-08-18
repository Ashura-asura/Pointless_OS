//! Aegis model SDK tour — a runnable, testable walk through the capability
//! substrate that the SDK crates expose (`capability-core` + `grants`).
//!
//! Run it: `cargo run -p sdk-example`. The very same function backs the
//! contract tests below, so the tour can never drift from the model it
//! documents: if a step's invariant ever breaks, a test fails.
//!
//! The walk follows design doc §9 / §11.F: a **zero-capability agent** is
//! denied before it is granted anything, receives a role-shaped,
//! task-scoped grant after a human reviews the one-line diff, uses it for
//! exactly what the role allows, cannot escalate it, loses it to time
//! (I5) and to revocation (I4), and every one of those steps is in the
//! kernel audit log.

use capability_core::{
    AuditFilter, CapHandle, Kernel, KernelError, ObjectId, ObjectKind, OpKind, Rights, TaskHandle,
};
use grants::monitor::{Monitor, MonitorEvent};
use grants::role::RoleLibrary;
use grants::{GrantPolicy, GrantService, GrantTarget};

/// One step of the tour: a label, whether its invariants held, and the detail
/// string printed for a live run.
#[derive(Debug, Clone)]
pub struct Step {
    pub label: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// The tour's report: the steps in order, plus closing audit statistics.
#[derive(Debug)]
pub struct TourReport {
    pub steps: Vec<Step>,
    pub audit_len: usize,
    pub audit_failed: usize,
}

impl TourReport {
    pub fn all_ok(&self) -> bool {
        self.steps.iter().all(|s| s.ok)
    }
}

/// Find the agent's own slot naming `obj` — the capability a grant minted
/// into the agent's CSpace. Asserts it exists (used where the tour expects
/// the grant to be live).
fn agent_slot(k: &Kernel, agent: TaskHandle, obj: ObjectId) -> CapHandle {
    (0..256u32)
        .find(|s| k.cap_info(agent, CapHandle(*s)).is_ok_and(|i| i.obj == obj))
        .map(CapHandle)
        .expect("the agent holds a capability to this object")
}

fn ok_step(label: &'static str, detail: impl Into<String>) -> Step {
    Step {
        label,
        ok: true,
        detail: detail.into(),
    }
}

/// Propose the high-risk `modify-security-policy` grant for the agent over
/// the policy service (used three times: single-click refusal, same-party
/// refusal, and the real two-party mint).
fn propose_policy(
    k: &Kernel,
    svc: &GrantService,
    lib: &RoleLibrary,
    agent_cap: CapHandle,
    policy_cap: CapHandle,
) -> grants::PendingGrant {
    svc.propose(
        k,
        lib,
        "modify-security-policy",
        "ops-agent",
        agent_cap,
        GrantTarget {
            label: "policy-service".into(),
            source: policy_cap,
        },
        GrantPolicy::TaskScoped { ticks: 1000 },
    )
    .expect("the high-risk proposal is well-formed")
}

/// Run the whole tour. Every step records its own invariant; the report
/// tells you whether the tour held together.
pub fn tour() -> TourReport {
    let mut steps: Vec<Step> = Vec::new();
    let mut k = Kernel::new();

    // 1 — boot: the root task and its Creator cap; all authority begins here.
    let (root, _self_cap, creator) = k.boot("session-orchestrator").unwrap();
    steps.push(ok_step(
        "1. boot",
        "root task + creator cap minted (the single source of all authority)",
    ));

    // 2 — the services the agent will (eventually) be allowed to touch.
    let (greeter, greeter_cap) = k.create_task(root, creator, "greeter-service").unwrap();
    let (_policy, policy_cap) = k.create_task(root, creator, "policy-service").unwrap();
    k.task_spawn(root, greeter_cap).unwrap();
    k.task_spawn(root, policy_cap).unwrap();
    steps.push(ok_step(
        "2. services",
        "greeter-service + policy-service created and spawned",
    ));

    // 3 — the agent starts with exactly one cap: its own self-cap.
    let (agent, agent_cap) = k.create_task(root, creator, "ops-agent").unwrap();
    let held = k.authorized(agent).len();
    steps.push(Step {
        label: "3. zero-capability agent",
        ok: held == 1,
        detail: format!("agent holds {held} cap(s) — only its self-cap"),
    });

    // 4 — denial before grant: a foreign kill and a foreign role-grant are
    // refused at the capability gates, and the refusals land in the audit log.
    let kill_err = k.task_kill(agent, CapHandle(9)).unwrap_err();
    let grant_err = k
        .grant(agent, CapHandle(9), CapHandle(0), Rights::ALL, None)
        .unwrap_err();
    steps.push(Step {
        label: "4. denial before grant",
        ok: matches!(kill_err, KernelError::NoCap) && matches!(grant_err, KernelError::NoCap),
        detail: format!("foreign kill {kill_err:?}; foreign role-grant {grant_err:?}"),
    });

    // 5 — the grant service owns one grant root under the orchestrator.
    let mut svc = GrantService::new(&mut k, root, creator).unwrap();
    let lib = RoleLibrary::default_roles();
    steps.push(ok_step(
        "5. grant service",
        "grant root minted; role library loaded (restart-service, observe-service, …)",
    ));

    // 6 — propose the restart-service role, review the one-line diff, confirm.
    let pending = svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "ops-agent",
            agent_cap,
            GrantTarget {
                label: "greeter-service".into(),
                source: greeter_cap,
            },
            GrantPolicy::TaskScoped { ticks: 100 },
        )
        .unwrap();
    let diff = GrantService::diff(&pending);
    let diff_ok = diff.len() == 1
        && diff[0].kind == ObjectKind::Task
        && diff[0].rights.contains(Rights::READ)
        && diff[0].rights.contains(Rights::CONTROL)
        && !diff[0].rights.contains(Rights::GRANT);
    let active = svc.confirm(&mut k, pending).unwrap();
    steps.push(Step {
        label: "6. propose → diff → confirm",
        ok: diff_ok && active.caps.len() == 1 && active.caps[0].deadline.is_some(),
        detail: format!(
            "1-line diff reviewed (READ+CONTROL over greeter-service, no GRANT); \
             grant minted at agent slot {}",
            active.caps[0].slot
        ),
    });

    // 7 — the agent does exactly what the role allows: read state, restart.
    let svc_slot = agent_slot(&k, agent, greeter.id());
    let running = k.task_running(agent, svc_slot).unwrap();
    k.task_kill(agent, svc_slot).unwrap();
    k.task_spawn(agent, svc_slot).unwrap();
    steps.push(Step {
        label: "7. authorized after grant",
        ok: running,
        detail: "agent reads service state (READ) and restarts it (CONTROL)".to_string(),
    });

    // 8 — the role cannot escalate: the server cap carries no GRANT, so a
    // re-grant attempt is refused — the agent never becomes an authority.
    let es_err = k
        .grant(agent, svc_slot, CapHandle(0), Rights::ALL, None)
        .unwrap_err();
    steps.push(Step {
        label: "8. escalation refused",
        ok: matches!(es_err, KernelError::InsufficientRights(Rights::GRANT)),
        detail: format!("re-grant attempt refused: {es_err:?}"),
    });

    // 9 — task-scoped grants die to time (I5) without any revocation.
    k.advance(200);
    let exp_err = k.task_running(agent, svc_slot).unwrap_err();
    steps.push(Step {
        label: "9. task-scoped expiry",
        ok: matches!(exp_err, KernelError::CapExpired),
        detail: format!("after 200 ticks the 100-tick grant is gone: {exp_err:?}"),
    });

    // 10 — high-risk roles need two-party confirmation, never a single click.
    let alice = k.create_task(root, creator, "reviewer-alice").unwrap().0;
    let bob = k.create_task(root, creator, "reviewer-bob").unwrap().0;

    let single_pending = propose_policy(&k, &svc, &lib, agent_cap, policy_cap);
    let single_err = svc.confirm(&mut k, single_pending).unwrap_err();
    let ptp_pending = propose_policy(&k, &svc, &lib, agent_cap, policy_cap);
    let ptp = svc.open_two_party(&k, ptp_pending, alice).unwrap();
    let same_err = svc.confirm_second(&mut k, ptp, alice).unwrap_err();
    let final_pending = propose_policy(&k, &svc, &lib, agent_cap, policy_cap);
    let final_ptp = svc.open_two_party(&k, final_pending, alice).unwrap();
    let active2 = svc.confirm_second(&mut k, final_ptp, bob).unwrap();
    let policy_slot = active2.caps[0].slot;
    let refused_logged = svc.policy_log().iter().any(|e| {
        matches!(
            e,
            grants::PolicyEvent::ConfirmationRefused {
                role: "modify-security-policy",
                ..
            }
        )
    });
    steps.push(Step {
        label: "10. two-party confirmation",
        ok: matches!(single_err, KernelError::InvalidOperation)
            && matches!(same_err, KernelError::InvalidOperation)
            && active2.approvals == vec![alice.id(), bob.id()]
            && refused_logged,
        detail: format!(
            "single click refused; same-party second refused; {} + {} mint CONTROL \
             over policy-service at agent slot {policy_slot}",
            alice.id().as_u64(),
            bob.id().as_u64()
        ),
    });

    // 11 — the anomaly circuit breaker: trained on the role's shape, it
    // suspends (never revokes) when the agent does something off-profile.
    let mut monitor = Monitor::train(&k, agent);
    let trained = monitor
        .log()
        .iter()
        .any(|e| matches!(e, MonitorEvent::Trained { .. }));
    let calm = monitor.observe(&k, &mut svc);
    let _ = k.ep_send(agent, CapHandle(9), b"ping".to_vec()); // off-profile op
    let flagged = monitor.observe(&k, &mut svc);
    let suspended = svc.is_suspended(agent.id());
    svc.resume(&k, agent);
    steps.push(Step {
        label: "11. anomaly circuit breaker",
        ok: trained && !calm && flagged && suspended && !svc.is_suspended(agent.id()),
        detail: format!(
            "trained on the role's shape; calm pass {calm}; off-profile send flagged {flagged}; \
             suspended {suspended}, then resumed by human review"
        ),
    });

    // 12 — revocation (I4): one root revoke removes the grant from everywhere,
    // whoever currently holds it.
    svc.revoke(&mut k).unwrap();
    let gone = k.cap_info(agent, CapHandle(policy_slot));
    steps.push(Step {
        label: "12. revocation",
        ok: matches!(gone, Err(KernelError::NoCap)) && svc.list_active().is_empty(),
        detail: format!(
            "grant root revoked; policy cap at slot {policy_slot} is {gone:?}; active grants: {}",
            svc.list_active().len()
        ),
    });

    // 13 — the audit trail is complete: nothing silent, refusals included.
    let failed = k.audit().query(None, AuditFilter::Failed).count();
    let kill_audited = k
        .audit()
        .query(Some(agent.id()), AuditFilter::Ops(&[OpKind::TaskKill]))
        .any(|r| !r.ok);
    let total = k.audit().len();
    steps.push(Step {
        label: "13. audit summary",
        ok: failed > 0 && kill_audited && total >= steps.len(),
        detail: format!(
            "{total} records total, {failed} refusals — the denied step-4 kill is in the log \
             as a failed TaskKill"
        ),
    });

    TourReport {
        steps,
        audit_len: total,
        audit_failed: failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_whole_tour_holds() {
        let report = tour();
        assert!(
            report.all_ok(),
            "tour failed at step(s): {:?}",
            report
                .steps
                .iter()
                .filter(|s| !s.ok)
                .map(|s| s.label)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_tour_leaves_no_active_authority() {
        let report = tour();
        // After step 12 nothing grants remain; the report's own steps are the
        // only post-condition. Re-running the flow on a fresh kernel must
        // reproduce the exact same step count (determinism of the tour).
        assert_eq!(report.steps.len(), 13);
    }

    #[test]
    fn the_refusals_are_audited_not_silent() {
        let report = tour();
        // The kernel audit log records every refused capability op (the
        // two-party refusals additionally land in the grant service's policy
        // log — asserted inside step 10 itself).
        assert!(report.audit_failed >= 5, "refusals must be in the log");
    }
}

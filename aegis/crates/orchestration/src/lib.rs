//! The adaptive orchestration layer (design doc §5 "Adaptive / AI orchestration
//! architecture", Phase 6). Where `sdk-example` walks a single role-grant
//! lifecycle, this crate composes the three runtime mechanisms that *bound* an
//! agent in a live session and turns them into one runnable loop:
//!
//! 1. **The grant ceiling** — an agent may *propose* an action; the
//!    orchestrator checks the proposal against the role the agent was actually
//!    granted (kernel truth, not the agent's self-report) and refuses anything
//!    outside it *before* any kernel op executes. Refused proposals never reach
//!    the kernel: they are prevented, and the refusal itself is logged.
//! 2. **The anomaly monitor** — after training on the role's shape, every turn
//!    is observed; a deviation suspends the agent's grants (never revokes) and
//!    stays suspended until a human resumes it.
//! 3. **The supervision tree** — the agent itself is a supervised subsystem:
//!    a crash is restarted within budget from the supervisor's own CONTROL cap,
//!    and repeated crashes trip the circuit breaker instead of retrying
//!    silently.
//!
//! Run it: `cargo run -p orchestration`. The same function backs the contract
//! tests, so the session can never drift from the mechanisms it documents.
//!
//! Honest limits (the model is a single in-process kernel): there is no
//! capability-transfer IPC, so the orchestrator shares the boot context's
//! CSpace rather than being a genuinely separate task with a CONTROL-only cap;
//! the boundary the model *can* express is that the agent's authority is a
//! task-scoped, revocable role minted by the grant service — the agent never
//! holds the grant root, and the orchestrator never reaches through it to the
//! supervised service.

use capability_core::{
    AuditFilter, CapHandle, Kernel, KernelError, KernelResult, ObjectId, Rights, TaskHandle,
};
use grants::monitor::{Monitor, MonitorEvent};
use grants::role::RoleLibrary;
use grants::{GrantPolicy, GrantService, GrantTarget};
use supervision_tree::{RestartPolicy, RuntimeEvent, Supervisor};

/// An action the worker agent *proposes*. Nothing here executes until the
/// orchestrator has checked it against the granted ceiling.
#[derive(Debug, Clone)]
pub enum Action {
    /// Read the supervised service's state (needs READ).
    ReadServiceState,
    /// Kill and respawn the supervised service (needs CONTROL).
    RestartService,
    /// Kill an object the agent holds no capability to (always refused).
    KillForeign(ObjectId),
    /// Hammer the READ on the service faster than the trained baseline
    /// (in-cap, but rate-deviant — the monitor's job).
    ReadStateBurst(usize),
}

/// The orchestrator's verdict on a proposed action. Every verdict is logged:
/// the audit trail covers *requests*, not just executed ops.
#[derive(Debug, Clone)]
pub enum Decision {
    /// The proposal was within the granted ceiling and executed.
    Approved {
        action: &'static str,
        detail: String,
    },
    /// Refused before any kernel op: no capability, or the cap lacked the
    /// needed right. The kernel audit is untouched — prevention, not
    /// post-hoc refusal.
    CeilingDenied {
        action: &'static str,
        detail: String,
    },
    /// Refused because the monitor has the agent suspended.
    SuspendedGate {
        action: &'static str,
        detail: String,
    },
}

/// One session step: label, whether its invariant held, detail for a live run.
#[derive(Debug, Clone)]
pub struct Step {
    pub label: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// The session report: steps in order, every decision the orchestrator made,
/// and closing audit statistics.
#[derive(Debug)]
pub struct SessionReport {
    pub steps: Vec<Step>,
    pub decisions: Vec<Decision>,
    pub audit_len: usize,
    pub audit_failed: usize,
}

impl SessionReport {
    pub fn all_ok(&self) -> bool {
        self.steps.iter().all(|s| s.ok)
    }
}

fn ok_step(label: &'static str, detail: impl Into<String>) -> Step {
    Step {
        label,
        ok: true,
        detail: detail.into(),
    }
}

/// The runtime: the orchestrator's own context, the worker agent it
/// supervises, the service the role covers, the grant service + monitor, and
/// the supervision tree that owns the worker.
pub struct Orchestrator {
    pub root: TaskHandle,
    pub worker: TaskHandle,
    pub worker_cap: CapHandle,
    pub target: TaskHandle,
    pub target_cap: CapHandle,
    pub victim: TaskHandle,
    pub svc: GrantService,
    pub monitor: Option<Monitor>,
    pub supervisor: Supervisor,
    pub log: Vec<Decision>,
}

impl Orchestrator {
    /// Boot the session domain: root, the supervised service, the worker
    /// agent, an unrelated victim (used to probe the ceiling), the grant
    /// service, and the supervision tree that adopts the worker under a
    /// restart budget of two.
    pub fn start(k: &mut Kernel) -> KernelResult<Orchestrator> {
        let (root, _self_cap, creator) = k.boot("orchestration-domain")?;
        let (target, target_cap) = k.create_task(root, creator, "agent-service")?;
        k.task_spawn(root, target_cap)?;
        let (worker, worker_cap) = k.create_task(root, creator, "worker-agent")?;
        let (victim, _victim_cap) = k.create_task(root, creator, "unrelated-victim")?;
        let svc = GrantService::new(k, root, creator)?;
        let supervisor = Supervisor::new(root);
        let mut o = Orchestrator {
            root,
            worker,
            worker_cap,
            target,
            target_cap,
            victim,
            svc,
            monitor: None,
            supervisor,
            log: Vec::new(),
        };
        o.supervisor
            .add(
                k,
                "worker-agent",
                worker,
                worker_cap,
                RestartPolicy { max_restarts: 2 },
            )
            .expect("supervisor adopts the worker");
        Ok(o)
    }

    /// The worker's own slot naming `target` — the cap a grant minted into its
    /// CSpace, if any.
    fn slot_for(&self, k: &Kernel, target: ObjectId) -> Option<CapHandle> {
        (0..256u32)
            .find(|s| {
                k.cap_info(self.worker, CapHandle(*s))
                    .is_ok_and(|i| i.obj == target)
            })
            .map(CapHandle)
    }

    /// The policy engine: one proposed action, checked against the ceiling,
    /// then executed as the worker only if it is in-role. The refusal paths
    /// never call the kernel.
    pub fn act(&mut self, k: &mut Kernel, action: Action) -> Decision {
        let (label, target, need) = match &action {
            Action::ReadServiceState => ("read service state", self.target.id(), Rights::READ),
            Action::RestartService => ("restart service", self.target.id(), Rights::CONTROL),
            Action::KillForeign(o) => ("kill foreign task", *o, Rights::CONTROL),
            Action::ReadStateBurst(_) => {
                ("read service state (burst)", self.target.id(), Rights::READ)
            }
        };

        if self.svc.is_suspended(self.worker.id()) {
            let d = Decision::SuspendedGate {
                action: label,
                detail: "agent is suspended; proposal held until human resume".into(),
            };
            self.log.push(d.clone());
            return d;
        }

        let Some(slot) = self.slot_for(k, target) else {
            let d = Decision::CeilingDenied {
                action: label,
                detail: format!(
                    "no capability names {:?} — refused before any kernel op",
                    target
                ),
            };
            self.log.push(d.clone());
            return d;
        };

        let held = k
            .cap_info(self.worker, slot)
            .map(|i| i.rights)
            .unwrap_or(Rights::NONE);
        if !held.contains(need) {
            let d = Decision::CeilingDenied {
                action: label,
                detail: format!(
                    "capability to {:?} lacks {need:?} — refused before any kernel op",
                    target
                ),
            };
            self.log.push(d.clone());
            return d;
        }

        let detail = match action {
            Action::ReadServiceState => {
                let running = k.task_running(self.worker, slot).unwrap_or(false);
                format!("READ ok — service state running={running}")
            }
            Action::RestartService => {
                k.task_kill(self.worker, slot).expect("CONTROL over target");
                k.task_spawn(self.worker, slot)
                    .expect("CONTROL over target");
                "CONTROL ok — killed and respawned".to_string()
            }
            Action::KillForeign(_) => unreachable!("foreign kills never clear the ceiling"),
            Action::ReadStateBurst(n) => {
                let mut running = true;
                for _ in 0..n {
                    running &= k.task_running(self.worker, slot).unwrap_or(false);
                }
                format!("{n} in-cap reads — all running={running}")
            }
        };
        let d = Decision::Approved {
            action: label,
            detail,
        };
        self.log.push(d.clone());
        d
    }

    /// One observation pass of the per-turn adaptive loop: the monitor reads
    /// the kernel's attribution of the worker and suspends it if the shape has
    /// deviated. Returns whether it flagged.
    pub fn monitor_pass(&mut self, k: &mut Kernel) -> bool {
        match &mut self.monitor {
            Some(m) => m.observe(k, &mut self.svc),
            None => false,
        }
    }

    /// One supervision pass over the worker. Returns the subsystems restarted
    /// this pass; a worker past budget trips the breaker instead.
    pub fn supervise(&mut self, k: &mut Kernel) -> Vec<String> {
        self.supervisor.pump(k)
    }
}

/// Run the whole session. Every step records its own invariant; the report
/// tells you whether the mechanisms held together.
pub fn session() -> SessionReport {
    let mut steps: Vec<Step> = Vec::new();
    let mut k = Kernel::new();
    let lib = RoleLibrary::default_roles();
    let mut o = Orchestrator::start(&mut k).expect("domain boots");

    // 1 — boot: root + creator; every object in this domain derives from here.
    steps.push(ok_step(
        "1. boot",
        "root + creator minted; agent-service, worker-agent, victim created",
    ));

    // 2 — propose the restart-service role, review the one-line diff, confirm.
    let pending = o
        .svc
        .propose(
            &k,
            &lib,
            "restart-service",
            "worker-agent",
            o.worker_cap,
            GrantTarget {
                label: "agent-service".into(),
                source: o.target_cap,
            },
            GrantPolicy::TaskScoped { ticks: 10_000 },
        )
        .expect("the restart-service proposal is well-formed");
    let diff = GrantService::diff(&pending);
    let diff_ok = diff.len() == 1
        && diff[0].kind == capability_core::ObjectKind::Task
        && diff[0].rights.contains(Rights::READ)
        && diff[0].rights.contains(Rights::CONTROL)
        && !diff[0].rights.contains(Rights::GRANT);
    let active = o.svc.confirm(&mut k, pending).expect("confirm");
    steps.push(Step {
        label: "2. propose → diff → confirm",
        ok: diff_ok && active.caps.len() == 1 && active.caps[0].deadline.is_some(),
        detail: format!(
            "1-line diff reviewed (READ+CONTROL over agent-service, no GRANT); minted at slot {}",
            active.caps[0].slot
        ),
    });

    // 3 — in-role work through the policy engine: every action is approved and
    // the kernel confirms the agent really holds the granted authority.
    let d1 = o.act(&mut k, Action::ReadServiceState);
    let d2 = o.act(&mut k, Action::RestartService);
    let granted_ok = matches!(d1, Decision::Approved { .. })
        && matches!(d2, Decision::Approved { .. })
        && k.task_running(o.worker, CapHandle(active.caps[0].slot))
            .unwrap_or(false);
    steps.push(Step {
        label: "3. in-role work within the ceiling",
        ok: granted_ok,
        detail: format!(
            "{} — {}",
            match d1 {
                Decision::Approved { detail, .. } => detail,
                _ => "refused".into(),
            },
            match d2 {
                Decision::Approved { detail, .. } => detail,
                _ => "refused".into(),
            }
        ),
    });

    // 4 — the ceiling holds in both directions: the role cannot escalate (the
    // service cap carries no GRANT), and a foreign kill is refused before any
    // kernel op — the audit log is untouched by the refusal.
    let es_err = k
        .grant(
            o.worker,
            CapHandle(active.caps[0].slot),
            CapHandle(0),
            Rights::ALL,
            None,
        )
        .unwrap_err();
    let audit_before = k.audit().len();
    let d3 = o.act(&mut k, Action::KillForeign(o.victim.id()));
    let audit_after = k.audit().len();
    let ceiling_ok = matches!(es_err, KernelError::InsufficientRights(Rights::GRANT))
        && matches!(d3, Decision::CeilingDenied { .. })
        && audit_before == audit_after;
    steps.push(Step {
        label: "4. ceiling holds: no escalation, foreign kill prevented",
        ok: ceiling_ok,
        detail: format!(
            "re-grant refused {es_err:?}; foreign kill refused as {:?}; \
             kernel audit untouched ({audit_before} → {audit_after} records)",
            d3
        ),
    });

    // 5 — train the monitor on the role's shape; a calm turn stays calm.
    o.monitor = Some(Monitor::train(&k, o.worker));
    let trained = o
        .monitor
        .as_ref()
        .expect("just trained")
        .log()
        .iter()
        .any(|e| matches!(e, MonitorEvent::Trained { .. }));
    let _ = o.act(&mut k, Action::ReadServiceState);
    let calm = o.monitor_pass(&mut k);
    steps.push(Step {
        label: "5. monitor trained, calm turn calm",
        ok: trained && !calm,
        detail: format!(
            "trained on the role's op-shape; a within-baseline read stayed calm (flagged={calm})"
        ),
    });

    // 6 — the same in-cap capability used at an anomalous rate: the ceiling
    // approves each read, the monitor suspends the agent (never revokes), and
    // the policy engine refuses further work until a human resumes it.
    let d4 = o.act(&mut k, Action::ReadStateBurst(4));
    let flagged = o.monitor_pass(&mut k);
    let suspended = o.svc.is_suspended(o.worker.id());
    let d5 = o.act(&mut k, Action::ReadServiceState);
    let held_while_suspended = matches!(d5, Decision::SuspendedGate { .. });
    o.svc.resume(&k, o.worker);
    let d6 = o.act(&mut k, Action::ReadServiceState);
    let resumed_ok = matches!(d4, Decision::Approved { .. })
        && flagged
        && suspended
        && held_while_suspended
        && !o.svc.is_suspended(o.worker.id())
        && matches!(d6, Decision::Approved { .. });
    steps.push(Step {
        label: "6. anomaly suspends, human resumes",
        ok: resumed_ok,
        detail: format!(
            "burst approved by ceiling {flagged}; monitor flagged + suspended {suspended}; \
             in-role work held while suspended {held_while_suspended}; human resume ok"
        ),
    });

    // 7 — the agent is supervised: a crash is restarted within budget from the
    // supervisor's own CONTROL cap, and the restart is on both logs.
    k.task_kill(o.root, o.worker_cap)
        .expect("root controls worker");
    let restarted = o.supervise(&mut k);
    let restart_logged = o.supervisor.log().iter().any(|e| {
        matches!(
            e,
            RuntimeEvent::Restart {
                node,
                ..
            } if node == "worker-agent"
        )
    });
    let running_again = o.supervisor.is_running(&mut k, 0);
    steps.push(Step {
        label: "7. supervision restarts within budget",
        ok: restarted.iter().any(|n| n == "worker-agent") && restart_logged && running_again,
        detail: format!(
            "crash → restart pass restarted {:?}; event logged; running again: {running_again}",
            restarted
        ),
    });

    // 8 — close: one root revoke removes the role everywhere, and the engine
    // now refuses even the in-role action the agent used to perform.
    o.svc.revoke(&mut k).expect("root revokes");
    let gone = o.slot_for(&k, o.target.id()).is_none();
    let d7 = o.act(&mut k, Action::ReadServiceState);
    let refused_after = matches!(d7, Decision::CeilingDenied { .. });
    let no_active = o.svc.list_active().is_empty();
    steps.push(Step {
        label: "8. revocation: no lingering authority",
        ok: gone && refused_after && no_active,
        detail: format!(
            "role revoked; cap gone {gone}; in-role action now refused {refused_after}; \
             active grants: {}",
            o.svc.list_active().len()
        ),
    });

    // 9 — the audit trail is complete: refusals are logged, the orchestrator's
    // decision log records every verdict, requests included.
    let failed = k.audit().query(None, AuditFilter::Failed).count();
    let total = k.audit().len();
    let decisions = o.log.len();
    steps.push(Step {
        label: "9. audit summary",
        ok: failed > 0 && total >= steps.len() && decisions >= 6,
        detail: format!(
            "{total} kernel records, {failed} refusals; orchestrator logged {decisions} verdicts"
        ),
    });

    SessionReport {
        steps,
        decisions: o.log,
        audit_len: total,
        audit_failed: failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_holds_end_to_end() {
        let report = session();
        assert!(
            report.all_ok(),
            "session failed at step(s): {:?}",
            report
                .steps
                .iter()
                .filter(|s| !s.ok)
                .map(|s| s.label)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_session_is_deterministic() {
        let a = session();
        let b = session();
        assert_eq!(a.steps.len(), b.steps.len());
        assert_eq!(a.decisions.len(), b.decisions.len());
        assert_eq!(a.audit_len, b.audit_len);
    }

    #[test]
    fn the_breaker_trips_instead_of_silent_retry() {
        let mut k = Kernel::new();
        let mut o = Orchestrator::start(&mut k).unwrap();
        // Budget is two restarts. Kill three times: two restarts, then trip.
        for _ in 0..2 {
            k.task_kill(o.root, o.worker_cap).unwrap();
            assert!(
                o.supervise(&mut k).iter().any(|n| n == "worker-agent"),
                "restarts stay within budget"
            );
        }
        k.task_kill(o.root, o.worker_cap).unwrap();
        let pass = o.supervise(&mut k);
        assert!(pass.is_empty(), "no silent retry past the budget");
        assert!(
            o.supervisor
                .log()
                .iter()
                .any(|e| matches!(e, RuntimeEvent::Trip { node, .. } if node == "worker-agent")),
            "the breaker trips and is audited"
        );
        assert!(
            !o.supervisor.is_running(&mut k, 0),
            "the subsystem stays faulted after the trip"
        );
    }

    #[test]
    fn a_never_granted_agent_is_denied_before_execution() {
        let mut k = Kernel::new();
        let mut o = Orchestrator::start(&mut k).unwrap();
        // No role was ever proposed for the worker: the engine must refuse
        // both the service action and the foreign kill, without touching the
        // kernel audit log.
        let before = k.audit().len();
        let d1 = o.act(&mut k, Action::ReadServiceState);
        let d2 = o.act(&mut k, Action::KillForeign(o.target.id()));
        let after = k.audit().len();
        assert!(matches!(d1, Decision::CeilingDenied { .. }));
        assert!(matches!(d2, Decision::CeilingDenied { .. }));
        assert_eq!(
            before, after,
            "prevention means the kernel never saw the ops"
        );
    }
}

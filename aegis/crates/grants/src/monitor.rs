//! The behavioral anomaly monitor (design doc §9: "behavioral anomaly
//! detection as a runtime circuit breaker — a lightweight monitor (not the AI
//! itself, not in the TCB, just another capability-scoped service) watches
//! whether an agent's actual capability usage matches the statistical shape
//! of what that role normally does, and auto-suspends (not auto-revokes —
//! suspension is reversible and logged, silent permanent revocation is not)
//! the agent's remaining grants on significant deviation, pending human
//! review").
//!
//! The monitor is a read-only observer of kernel truth: its sole input is the
//! audit log (every op the agent performed, attributed by the kernel), and
//! its sole output is a call into the grant service's suspension ledger — it
//! holds no capability of its own and cannot revoke, kill, or mint anything.
//! Its profile is the op-shape ("what that role normally does") trained from
//! an observed baseline; a significant deviation is any op kind whose rate
//! more than doubled, or an op kind the profile never saw. Every trained
//! baseline, every deviation, and every suspension decision is itself logged —
//! the monitor's decisions are as auditable as the facts it reads.
//!
//! Honest limits: the "statistical shape" is a per-op-kind count over the
//! whole log (no sliding window, no rate smoothing) and the deviation rule is
//! a fixed threshold rather than a learned model — the mechanism (observe,
//! suspend-not-revoke, log, await human review) is what this models, not the
//! statistics.

use capability_core::{AuditFilter, Kernel, OpKind, TaskHandle};

/// The trained shape of a role: how often the agent performs each op kind,
/// from an observed baseline of kernel truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpShape {
    pub op: OpKind,
    pub expected: usize,
}

/// The monitor's own decision log: facts (what deviated) and decisions (what
/// it did about it) together, so the monitor's behavior is as auditable as
/// the audit log it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorEvent {
    Trained {
        shapes: usize,
    },
    Deviation {
        op: OpKind,
        seen: usize,
        expected: usize,
        at: u64,
    },
    Suspended {
        at: u64,
        reason: String,
    },
}

/// One lightweight, capability-less observer of one agent. Construction is
/// the only kernel-adjacent step (it reads the audit log); after that it only
/// needs the grant service to act.
pub struct Monitor {
    agent: TaskHandle,
    profile: Vec<OpShape>,
    log: Vec<MonitorEvent>,
}

impl Monitor {
    /// Train the role's shape from the agent's actual usage so far. The
    /// baseline is whatever the kernel says the agent has done — the monitor
    /// has no opinion about what it *should* do, only about deviating from
    /// what it *does*.
    pub fn train(kernel: &Kernel, agent: TaskHandle) -> Monitor {
        let counts = op_counts(kernel, agent);
        let profile: Vec<OpShape> = counts
            .into_iter()
            .map(|(op, expected)| OpShape { op, expected })
            .collect();
        Monitor {
            agent,
            profile: profile.clone(),
            log: vec![MonitorEvent::Trained {
                shapes: profile.len(),
            }],
        }
    }

    pub fn log(&self) -> &[MonitorEvent] {
        &self.log
    }

    /// The deviation rule: an op kind more than doubled its baseline rate, or
    /// appeared when the profile never saw it. Returns the most deviant op.
    fn deviation(&self, kernel: &Kernel) -> Option<(OpKind, usize, usize)> {
        let counts = op_counts(kernel, self.agent);
        for shape in &self.profile {
            let seen = count_of(&counts, shape.op);
            // A 2x baseline rate is the model's "significant deviation".
            if shape.expected > 0 && seen > shape.expected.saturating_mul(2) {
                return Some((shape.op, seen, shape.expected));
            }
        }
        // Off-profile ops: kinds the role has never done before, now live.
        for (op, seen) in counts {
            if seen > 0 && !self.profile.iter().any(|s| s.op == op) {
                return Some((op, seen, 0));
            }
        }
        None
    }

    /// One observation pass: read the kernel's attribution of the agent's
    /// activity, and if it deviates from the trained shape, suspend the
    /// agent's grants with the grant service (never revoke them). Suspension
    /// stays until a human resumes the agent — the monitor does not
    /// auto-restart; it contains and surfaces.
    pub fn observe(&mut self, kernel: &Kernel, service: &mut crate::GrantService) -> bool {
        match self.deviation(kernel) {
            None => false,
            Some((op, seen, expected)) => {
                let at = kernel.now();
                self.log.push(MonitorEvent::Deviation {
                    op,
                    seen,
                    expected,
                    at,
                });
                service.suspend(kernel, self.agent, &format!("op-shape deviation on {op:?}"));
                self.log.push(MonitorEvent::Suspended {
                    at,
                    reason: "significant deviation from the role's trained op-shape".to_string(),
                });
                true
            }
        }
    }
}

fn op_counts(kernel: &Kernel, agent: TaskHandle) -> Vec<(OpKind, usize)> {
    let mut counts: Vec<(OpKind, usize)> = Vec::new();
    for r in kernel.audit().query(Some(agent.id()), AuditFilter::All) {
        match counts.iter_mut().find(|(op, _)| *op == r.op) {
            Some((_, n)) => *n += 1,
            None => counts.push((r.op, 1)),
        }
    }
    counts
}

fn count_of(counts: &[(OpKind, usize)], op: OpKind) -> usize {
    counts
        .iter()
        .find(|(o, _)| *o == op)
        .map(|(_, n)| *n)
        .unwrap_or(0)
}

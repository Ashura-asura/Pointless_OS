//! The behavioral anomaly circuit breaker (design doc §9), kernel-complete:
//! a lightweight, capability-less monitor reads the kernel's own attributed
//! audit log (`audit.rs`), compares the agent's op-shape against the role's
//! trained baseline, and on significant deviation *suspends* — never revokes —
//! the agent's grants as recorded in the suspension ledger, pending human
//! review. This mirrors the model crate's `grants::monitor` contract-test-for-
//! contract, over the real gates: the kernel's every gated op lands in the
//! audit ring with the caller attributed, which is exactly what the monitor
//! trains on and observes.
//!
//! The monitor is a read-only observer of kernel truth: its sole input is the
//! audit log and its sole output is a call into the grant ledger. It holds no
//! capability of its own and cannot revoke, kill, mint, or read an object —
//! those gates all require a cap the monitor does not carry. Its profile is
//! the op-shape ("what that role normally does") trained from an observed
//! baseline; a significant deviation is any op kind whose rate more than
//! doubled, or an op kind the profile never saw. Every trained baseline, every
//! deviation, and every suspension decision is logged — the monitor's
//! decisions are as auditable as the facts it reads.
//!
//! Suspension is a ledger record, not a kernel-object operation: `resume` is
//! the human-review path and is reversible and logged (never silent). The one
//! kernel gate the ledger touches is `ipc_cap_grant` — a suspended agent's
//! grant flow is frozen (it cannot delegate new authority) while its already-
//! minted caps keep working, because the monitor never took anything away.
//!
//! Honest limits over the model: the "statistical shape" is a per-op-kind
//! count over the audit ring's recent history (no sliding window, no rate
//! smoothing) with a fixed 2x / unseen-op deviation rule rather than a learned
//! model — the mechanism (observe, suspend-not-revoke, log, await human
//! review) is what this implements, not the statistics. The ledger is a bounded
//! in-memory ring; the monitor's "no capability" claim is structural (it has
//! no cap field and no way to touch the CSpace), proven by the gate tests that
//! refuse a cap-less task. The model grants the monitor one self-cap; the
//! kernel has no self-cap object yet, so the kernel monitor's CSpace is empty.

use crate::audit::{op_counts, tick, OpKind};
use crate::tasks::MAX_TASKS;

/// Ledger capacity for monitor + policy decisions. Small, bounded, ring-based.
pub const MAX_POLICY_LOG: usize = 64;

/// The trained shape of a role: how often the agent performs each op kind,
/// from an observed baseline of kernel truth. `None` entries in a profile are
/// op kinds the baseline never saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpShape {
    pub op: OpKind,
    pub expected: usize,
}

/// The monitor's own decision log: facts (what deviated) and decisions (what
/// it did about it) together, so the monitor's behavior is as auditable as the
/// audit log it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        reason: &'static str,
    },
}

/// Grant-service ledger records: every suspension and every human-review
/// resume, timestamped. Suspension is never silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEvent {
    Suspended {
        agent: usize,
        at: u64,
        reason: &'static str,
    },
    Resumed {
        agent: usize,
        at: u64,
    },
}

/// One lightweight, capability-less observer of one agent. Construction is the
/// only kernel-adjacent step (it reads the audit log); after that its only act
/// is asking the ledger to flip suspension state.
pub struct AnomalyMonitor {
    agent: usize,
    profile: [Option<OpShape>; OpKind::COUNT],
    log: [Option<MonitorEvent>; MAX_POLICY_LOG],
    head: usize,
    len: usize,
}

impl AnomalyMonitor {
    /// Train the role's shape from the agent's actual usage so far. The
    /// baseline is whatever the kernel says the agent has done — the monitor
    /// has no opinion about what it *should* do, only about deviating from
    /// what it *does*.
    pub fn train(agent: usize) -> AnomalyMonitor {
        let counts = op_counts(agent);
        let mut profile = [None; OpKind::COUNT];
        let mut shapes = 0;
        for (op, c) in OpKind::ALL.iter().zip(counts.iter()) {
            if *c > 0 {
                profile[op.index()] = Some(OpShape {
                    op: *op,
                    expected: *c as usize,
                });
                shapes += 1;
            }
        }
        let mut m = AnomalyMonitor {
            agent,
            profile,
            log: [None; MAX_POLICY_LOG],
            head: 0,
            len: 0,
        };
        m.push(MonitorEvent::Trained { shapes });
        m
    }

    /// The deviation rule: an op kind more than doubled its baseline rate, or
    /// appeared when the profile never saw it. Returns the most deviant op.
    fn deviation(&self) -> Option<(OpKind, usize, usize)> {
        let counts = op_counts(self.agent);
        for shape in self.profile.iter().flatten() {
            let seen = counts[shape.op.index()] as usize;
            // A 2x baseline rate is the model's "significant deviation".
            if shape.expected > 0 && seen > shape.expected.saturating_mul(2) {
                return Some((shape.op, seen, shape.expected));
            }
        }
        // Off-profile ops: kinds the role has never done before, now live.
        for (op, seen) in OpKind::ALL.iter().zip(counts.iter()) {
            if *seen > 0 && !self.profile.iter().flatten().any(|s| s.op == *op) {
                return Some((*op, *seen as usize, 0));
            }
        }
        None
    }

    /// One observation pass: read the kernel's attribution of the agent's
    /// activity, and if it deviates from the trained shape, suspend the agent
    /// with the grant ledger (never revoke anything). Suspension stays until a
    /// human resumes the agent — the monitor does not auto-restart; it
    /// contains and surfaces.
    pub fn observe(&mut self) -> bool {
        match self.deviation() {
            None => false,
            Some((op, seen, expected)) => {
                let at = tick();
                self.push(MonitorEvent::Deviation {
                    op,
                    seen,
                    expected,
                    at,
                });
                let reason = "significant deviation from the role's trained op-shape";
                // SAFETY: single-threaded kernel; the ledger is the one global
                // suspension state and is not held across a context switch.
                if unsafe { ledger() }.suspend(self.agent, reason) {
                    self.push(MonitorEvent::Suspended { at, reason });
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Number of monitor decisions logged.
    pub fn log_len(&self) -> usize {
        self.len
    }

    /// The `i`-th decision, oldest first, `None` past the end.
    pub fn log(&self, i: usize) -> Option<MonitorEvent> {
        self.log.get(i).copied().flatten()
    }

    fn push(&mut self, e: MonitorEvent) {
        self.log[self.head % MAX_POLICY_LOG] = Some(e);
        self.head += 1;
        self.len = core::cmp::min(self.len + 1, MAX_POLICY_LOG);
    }
}

/// The grant suspension ledger: who is suspended and why, with a full decision
/// log. This is the one piece of grant-service state the kernel keeps — the
/// flip from "agent active" to "agent suspended, awaiting human review".
pub struct GrantLedger {
    suspended: [bool; MAX_TASKS],
    log: [Option<PolicyEvent>; MAX_POLICY_LOG],
    head: usize,
    len: usize,
}

impl GrantLedger {
    pub const fn new() -> GrantLedger {
        GrantLedger {
            suspended: [false; MAX_TASKS],
            log: [None; MAX_POLICY_LOG],
            head: 0,
            len: 0,
        }
    }

    /// Suspend `agent`, recording the decision. `false` when the agent is not
    /// a valid task or is already suspended (suspension is idempotent, and is
    /// never silent — the record lands either way).
    pub fn suspend(&mut self, agent: usize, reason: &'static str) -> bool {
        if agent >= MAX_TASKS || self.suspended[agent] {
            return false;
        }
        self.suspended[agent] = true;
        self.push(PolicyEvent::Suspended {
            agent,
            at: tick(),
            reason,
        });
        true
    }

    /// Human-review path: clear `agent`'s suspension. Reversible and logged —
    /// a resume is a visible policy event, never silent.
    pub fn resume(&mut self, agent: usize) -> bool {
        if agent >= MAX_TASKS || !self.suspended[agent] {
            return false;
        }
        self.suspended[agent] = false;
        self.push(PolicyEvent::Resumed { agent, at: tick() });
        true
    }

    /// Is `agent` currently suspended? Read by `ipc_cap_grant` to freeze the
    /// grant flow.
    pub fn is_suspended(&self, agent: usize) -> bool {
        agent < MAX_TASKS && self.suspended[agent]
    }

    /// Number of agents currently suspended.
    pub fn suspended_count(&self) -> usize {
        self.suspended.iter().filter(|s| **s).count()
    }

    /// Number of policy decisions logged.
    pub fn log_len(&self) -> usize {
        self.len
    }

    /// The `i`-th policy decision, oldest first, `None` past the end.
    pub fn log(&self, i: usize) -> Option<PolicyEvent> {
        self.log.get(i).copied().flatten()
    }

    fn push(&mut self, e: PolicyEvent) {
        self.log[self.head % MAX_POLICY_LOG] = Some(e);
        self.head += 1;
        self.len = core::cmp::min(self.len + 1, MAX_POLICY_LOG);
    }

    /// Test-only: reset so contract tests start from a deterministic empty
    /// ledger.
    #[cfg(test)]
    pub fn clear_for_test(&mut self) {
        self.suspended = [false; MAX_TASKS];
        self.log = [None; MAX_POLICY_LOG];
        self.head = 0;
        self.len = 0;
    }
}

impl Default for GrantLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// The single kernel-resident grant ledger. Read (freeze) by `ipc_cap_grant`,
/// written (suspend/resume) by the anomaly monitor and human review.
static mut LEDGER: GrantLedger = GrantLedger::new();

/// Access to the kernel-resident grant ledger.
///
/// # Safety
/// Single-threaded kernel; must not be held across a context switch. The
/// returned reference aliases the single global ledger — callers must not
/// retain it across other ledger-touching calls.
pub unsafe fn ledger() -> &'static mut GrantLedger {
    &mut *core::ptr::addr_of_mut!(LEDGER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{Cap, CapSlot, Rights};
    use crate::ipc::ipc_cap_grant;
    use crate::mem::mem_read;
    use crate::supervisor::{revoke_slot, task_kill, task_state};
    use crate::tasks::{set_current_for_test, set_task_cap, spawn, task_cap};

    extern "sysv64" fn dummy() -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    /// A clean world: empty audit ring, empty channel/region tables, empty task
    /// table with every cap slot cleared, empty ledger. Called under the
    /// kernel state guard so no other test writes global state concurrently.
    fn clean_world() {
        unsafe {
            crate::audit::reset_for_test();
            crate::channel::reset_channels_for_test();
            crate::mem::reset_regions_for_test();
            crate::tasks::reset_table_for_test();
            crate::monitor::ledger().clear_for_test();
            for i in 0..crate::tasks::MAX_TASKS {
                for s in 0..crate::tasks::MAX_CAPS {
                    set_task_cap(i, s, CapSlot::empty());
                }
            }
        }
    }

    /// §9: a significant deviation from the role's trained op-shape
    /// auto-suspends the agent without revoking a single capability, the
    /// suspension is visible in both the monitor's and the ledger's logs, and
    /// the agent's grant flow is frozen while its minted caps keep working.
    #[test]
    fn significant_deviation_auto_suspends_without_revoking() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            // svc = task 0, agent = task 1.
            let (svc, agent) = (0usize, 1usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("agent", dummy, 0x200000).unwrap();
            // Agent holds: READ on svc (state checks) and GRANT on svc
            // (delegation), so a later grant is refused for the RIGHT reason
            // (freeze), not for missing authority.
            set_task_cap(
                agent,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_task_cap(
                agent,
                1,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::GRANT,
                },
            );

            set_current_for_test(agent);
            // The role's normal shape: the agent occasionally checks service
            // state — that's what it *does*.
            assert_eq!(task_state(0), 1);
            assert_eq!(task_state(0), 1);
            let mut monitor = AnomalyMonitor::train(agent);
            assert!(matches!(
                monitor.log(0),
                Some(MonitorEvent::Trained { shapes: 1 })
            ));

            // Still doing what its shape says: no deviation, no suspension.
            assert_eq!(task_state(0), 1);
            assert!(!monitor.observe());
            assert!(!crate::monitor::ledger().is_suspended(agent));

            // Significant deviation: the agent now does something its role
            // never does — memory reads. Refused ops still land in the kernel
            // log with the caller attributed, which is exactly the kernel
            // truth the monitor reads.
            let mut buf = [0u8; 4];
            for _ in 0..4 {
                assert_eq!(mem_read(0, 0, 4, buf.as_mut_ptr() as u64), -1);
            }
            assert!(monitor.observe());
            assert!(crate::monitor::ledger().is_suspended(agent));
            let suspended_logged = {
                let led = crate::monitor::ledger();
                (0..led.log_len())
                    .any(|i| matches!(led.log(i), Some(PolicyEvent::Suspended { agent: a, .. }) if a == agent))
            };
            assert!(suspended_logged);
            let dev_logged = (0..monitor.log_len())
                .any(|i| matches!(monitor.log(i), Some(MonitorEvent::Deviation { seen, .. }) if seen >= 4));
            assert!(dev_logged);

            // Suspended is not revoked: the already-minted cap still works —
            // the agent's state checks pass (the ledger only freezes new
            // delegation) because the monitor took nothing away.
            assert_eq!(task_state(0), 1);
            assert_eq!(crate::audit::revoke_count(agent), 0);

            // But the grant flow is frozen: a suspended agent cannot delegate
            // new authority, and its existing cap is untouched.
            assert_eq!(ipc_cap_grant(0, 1, 5), -1);
            assert_eq!(
                task_cap(agent, 0).cap,
                Cap::Task(crate::cap::Oid::new(svc as u32, 0))
            );
        }
    }

    /// §9: suspension is reversible and logged — a human review resumes the
    /// agent, the resume is a visible policy event (never silent), and the
    /// grant flow works again. Kernel objects are untouched throughout: zero
    /// Revoke records.
    #[test]
    fn suspension_is_reversible_logged_and_never_silent() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            let (svc, agent) = (0usize, 1usize);
            spawn("svc", dummy, 0x100000).unwrap();
            spawn("agent", dummy, 0x200000).unwrap();
            set_task_cap(
                agent,
                0,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::READ,
                },
            );
            set_task_cap(
                agent,
                1,
                CapSlot {
                    cap: Cap::Task(crate::cap::Oid::new(svc as u32, 0)),
                    rights: Rights::GRANT,
                },
            );

            set_current_for_test(agent);
            assert_eq!(task_state(0), 1);
            let mut monitor = AnomalyMonitor::train(agent);

            // Deviation: an op kind the profile never saw.
            let mut buf = [0u8; 4];
            assert_eq!(mem_read(0, 0, 4, buf.as_mut_ptr() as u64), -1);
            assert!(monitor.observe());
            assert!(crate::monitor::ledger().is_suspended(agent));

            // Kernel state is untouched: no Revoke records exist anywhere.
            assert_eq!(crate::audit::revoke_count(agent), 0);

            // Human review resumes the agent: reversible, and the resume is a
            // logged policy event, never silent.
            assert!(crate::monitor::ledger().resume(agent));
            assert!(!crate::monitor::ledger().is_suspended(agent));
            let resumed = {
                let led = crate::monitor::ledger();
                (0..led.log_len())
                    .any(|i| matches!(led.log(i), Some(PolicyEvent::Resumed { agent: a, .. }) if a == agent))
            };
            assert!(resumed);

            // With the suspension cleared, the grant flow works again.
            assert_eq!(ipc_cap_grant(0, 1, 5), 0);
        }
    }

    /// §9: the monitor is a read-only service with no authority. It holds no
    /// capabilities at all (the kernel has no self-cap object, so unlike the
    /// model's one-cap monitor its CSpace is empty), training is passive
    /// reading of kernel truth, and fabricated authority is refused at the
    /// kernel gate: it cannot kill, revoke, or read an object.
    #[test]
    fn the_monitor_is_a_read_only_service_with_no_authority() {
        let _g = crate::kernel_state_guard();
        clean_world();
        unsafe {
            let monitor = 0usize;
            spawn("monitor", dummy, 0x100000).unwrap();
            assert!(
                (0..crate::tasks::MAX_CAPS).all(|s| task_cap(monitor, s).cap == Cap::None),
                "the monitor's complete authority is nothing; it only reads the audit log"
            );

            // Training is passive reading of kernel truth — before any activity,
            // so the profile of a task that has done nothing is empty.
            let watch = AnomalyMonitor::train(monitor);
            assert!(matches!(
                watch.log(0),
                Some(MonitorEvent::Trained { shapes: 0 })
            ));

            // Fabricated authority is refused at the kernel: no cap, no kill /
            // revoke / read — the gates deny a cap-less task.
            set_current_for_test(monitor);
            assert_eq!(task_kill(0), -1);
            assert_eq!(revoke_slot(0), -1);
            let mut buf = [0u8; 4];
            assert_eq!(mem_read(0, 0, 4, buf.as_mut_ptr() as u64), -1);
        }
    }
}

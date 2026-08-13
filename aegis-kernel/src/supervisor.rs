//! Minimal supervision-tree runtime (Phase 2): the kernel-side close contract
//! of Erlang-style supervision. A supervisor is created with a capability
//! right to CONTROL its children; a child crash is a `TaskKill` event, the
//! supervisor may restart it (respawn against its remembered entry point) up
//! to a fixed budget, and when the budget is spent the breaker *trips*: the
//! child is left dead and the failure is recorded — never silently retried
//! forever (the anti-"auto-recovery hides bugs" property of the design doc).
//!
//! This is the *runtime*, not the policy: retry cadence and escalation to a
//! parent supervisor are the supervision-tree crate's job in the `aegis`
//! model; this kernel module provides the primitives (budgeted restart,
//! trip, audit records) that policy sits on.
//!
//! Honest limits: single supervisor, no hierarchy yet (escalation to a parent
//! is a model-level concept this module does not implement); the audit trail
//! is an in-memory ring, not a durable log; restart re-enters the same entry
//! point rather than re-spawning fresh user state.

use crate::cap::{Cap, CapSlot, Rights};
use crate::tasks::MAX_TASKS as MAX_TASKS_TABLE;
use crate::tasks::{current_idx, is_task_alive, kill_task, restart_task, task_cap, MAX_CAPS};

pub const MAX_CHILDREN: usize = 8;
pub const MAX_AUDIT: usize = 16;

/// Resolve a capability slot to a task index, requiring the caller to hold the
/// given rights on it (READ for `task_state`, CONTROL for `task_kill`/
/// `task_restart`). `None` when the slot is empty, names a non-task object, or
/// the held rights are insufficient. Mirrors `ipc::caps_endpoint`.
fn caps_task(cur: usize, slot: u64, need: Rights) -> Option<usize> {
    if slot as usize >= MAX_CAPS {
        return None;
    }
    match task_cap(cur, slot as usize) {
        CapSlot {
            cap: Cap::Task(idx),
            rights,
        } if rights.contains(need) => Some(idx as usize),
        _ => None,
    }
}

/// Syscall: 1 if the task named by `slot` is alive, 0 if it is dead. Requires
/// READ on the task capability (the model's `task_running`).
pub fn task_state(slot: u64) -> i64 {
    let cur = current_idx();
    let idx = match caps_task(cur, slot, Rights::READ) {
        Some(i) => i,
        None => return -1,
    };
    if is_task_alive(idx) {
        1
    } else {
        0
    }
}

/// Syscall: kill the task named by `slot`. Requires CONTROL on the task
/// capability (the model's `task_kill`). Returns 0 or -1.
pub fn task_kill(slot: u64) -> i64 {
    let cur = current_idx();
    let idx = match caps_task(cur, slot, Rights::CONTROL) {
        Some(i) => i,
        None => return -1,
    };
    kill_task(idx);
    0
}

/// Syscall: restart a killed task named by `slot` against its remembered entry
/// point. Requires CONTROL on the task capability (the model's `task_spawn`).
/// Returns 0 on a successful respawn, -1 otherwise.
pub fn task_restart(slot: u64) -> i64 {
    let cur = current_idx();
    let idx = match caps_task(cur, slot, Rights::CONTROL) {
        Some(i) => i,
        None => return -1,
    };
    if restart_task(idx) {
        0
    } else {
        -1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    Crash,
    Restart,
    Trip,
}

#[derive(Clone, Copy, Debug)]
pub struct AuditRecord {
    pub kind: AuditKind,
    pub child: usize,
}

#[derive(Clone, Copy)]
struct Child {
    active: bool,
    /// Task index this child supervises.
    task_idx: usize,
    /// Remaining restarts before the breaker trips.
    budget_left: usize,
}

pub struct Supervisor {
    children: [Child; MAX_CHILDREN],
    audit_head: usize,
    audit: [AuditRecord; MAX_AUDIT],
}

impl Supervisor {
    pub const fn new() -> Self {
        Supervisor {
            children: [Child {
                active: false,
                task_idx: usize::MAX,
                budget_left: 0,
            }; MAX_CHILDREN],
            audit_head: 0,
            audit: [AuditRecord {
                kind: AuditKind::Crash,
                child: usize::MAX,
            }; MAX_AUDIT],
        }
    }

    /// Adopt `task_idx` under this supervisor with `budget` restarts allowed
    /// before the breaker trips. Returns false when there is no room or the
    /// task index is invalid.
    pub fn supervise(&mut self, task_idx: usize, budget: usize) -> bool {
        if task_idx >= MAX_TASKS_TABLE {
            return false;
        }
        let slot = self.children.iter_mut().find(|c| !c.active);
        match slot {
            Some(c) => {
                *c = Child {
                    active: true,
                    task_idx,
                    budget_left: budget,
                };
                true
            }
            None => false,
        }
    }

    /// Number of children under supervision.
    pub fn child_count(&self) -> usize {
        self.children.iter().filter(|c| c.active).count()
    }

    /// Remaining restart budget for supervised child `child` (index in the
    /// supervisor's table). `None` if not supervised.
    pub fn budget_of(&self, child: usize) -> Option<usize> {
        self.children
            .get(child)
            .filter(|c| c.active)
            .map(|c| c.budget_left)
    }

    /// Total audit records logged so far (ring-count).
    pub fn audit_len(&self) -> usize {
        self.audit_head
    }

    pub fn audit(&self, i: usize) -> Option<AuditRecord> {
        self.audit.get(i).copied()
    }

    fn record(&mut self, kind: AuditKind, child: usize) {
        self.audit[self.audit_head % MAX_AUDIT] = AuditRecord { kind, child };
        self.audit_head += 1;
    }

    /// Handle a crash of task `idx`. If `idx` is supervised and has budget
    /// left, restart it (returns `true`). If the budget is spent the breaker
    /// trips: the child is killed and the trip is recorded (returns `false`).
    /// Returns `None` for a task this supervisor does not control.
    pub fn handle_crash(&mut self, idx: usize) -> Option<bool> {
        let child = self
            .children
            .iter_mut()
            .find(|c| c.active && c.task_idx == idx)?;
        if child.budget_left > 0 {
            child.budget_left -= 1;
            self.record(AuditKind::Crash, idx);
            // A restart re-enters a reaped task: mark it Zombie first so the
            // respawn path rebuilds a fresh frame against the remembered entry.
            if is_task_alive(idx) {
                kill_task(idx);
            }
            if restart_task(idx) {
                self.record(AuditKind::Restart, idx);
                return Some(true);
            }
            // Respawn failed (e.g. the slot is invalid): treat as tripped.
            self.record(AuditKind::Trip, idx);
            return Some(false);
        }
        // Budget spent: trip the breaker. Leave the task dead, record it.
        self.record(AuditKind::Crash, idx);
        self.record(AuditKind::Trip, idx);
        if is_task_alive(idx) {
            kill_task(idx);
        }
        Some(false)
    }

    /// Drop supervision of task `idx` (used when reaping a child). Returns
    /// true if it was supervised.
    pub fn release(&mut self, idx: usize) -> bool {
        let slot = self
            .children
            .iter_mut()
            .find(|c| c.active && c.task_idx == idx);
        match slot {
            Some(c) => {
                *c = Child {
                    active: false,
                    task_idx: usize::MAX,
                    budget_left: 0,
                };
                true
            }
            None => false,
        }
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

/// A single kernel-resident supervisor for the live fault path. Populated by
/// boot code via `supervise`; the default instance supervises nothing, so the
/// existing ring-3 fault-kill behavior is unchanged until a task is adopted.
static mut GLOBAL: Supervisor = Supervisor::new();

/// Access to the kernel-resident supervision instance.
///
/// # Safety
/// Single-threaded kernel; must not be held across a context switch.
pub unsafe fn global_supervisor() -> &'static mut Supervisor {
    &mut *core::ptr::addr_of_mut!(GLOBAL)
}

/// Live ring-3 fault hook: `true` when a supervised child was restarted (the
/// kernel fault path should NOT also kill it), `false` otherwise.
pub fn handle_fault(idx: usize) -> bool {
    if idx == usize::MAX {
        return false;
    }
    unsafe { global_supervisor() }.handle_crash(idx) == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{
        reset_table_for_test, set_current_for_test, spawn, spawned_count, task_cap,
    };

    extern "sysv64" fn dummy() -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    /// Fresh supervisor, no global side effects.
    fn fresh() -> Supervisor {
        Supervisor::new()
    }

    #[test]
    fn supervise_rejects_invalid_and_fills_up() {
        let _g = crate::kernel_state_guard();
        let mut s = fresh();
        assert!(!s.supervise(usize::MAX, 3));
        assert!(!s.supervise(MAX_TASKS_TABLE, 3));
        for _ in 0..MAX_CHILDREN {
            assert!(s.supervise(0, 1));
        }
        assert!(!s.supervise(1, 1), "child table is full");
        assert_eq!(s.child_count(), MAX_CHILDREN);
    }

    #[test]
    fn crash_with_budget_restarts_and_keeps_task_alive() {
        let _g = crate::kernel_state_guard();
        unsafe {
            reset_table_for_test();
            spawn("c", dummy, 0x100000).unwrap();
            set_current_for_test(0);
        }
        let mut s = fresh();
        assert!(s.supervise(0, 2));
        // Simulate a crash.
        assert_eq!(s.handle_crash(0), Some(true));
        assert_eq!(s.budget_of(0), Some(1));
        assert!(
            is_task_alive(0),
            "restart must make the task runnable again"
        );
        // Again: budget drops to 0, still restarted.
        assert_eq!(s.handle_crash(0), Some(true));
        assert_eq!(s.budget_of(0), Some(0));
        // Third crash: no budget left -> trip, task killed.
        assert_eq!(s.handle_crash(0), Some(false));
        assert!(!is_task_alive(0), "tripped child must stay dead");
        // The refusal is recorded, not swallowed: 2x(Crash,Restart) + Crash+Trip.
        assert_eq!(s.audit_len(), 6);
    }

    #[test]
    fn unsupervised_task_is_not_handled() {
        let _g = crate::kernel_state_guard();
        let mut s = fresh();
        assert_eq!(s.handle_crash(3), None, "no child -> not ours to handle");
        assert_eq!(s.audit_len(), 0);
    }

    #[test]
    fn release_drops_supervision() {
        let _g = crate::kernel_state_guard();
        let mut s = fresh();
        s.supervise(0, 1);
        assert!(s.release(0));
        assert!(!s.release(0));
        assert_eq!(s.child_count(), 0);
        assert_eq!(s.handle_crash(0), None);
    }

    #[test]
    fn restart_is_per_task_budget_not_global() {
        let _g = crate::kernel_state_guard();
        unsafe {
            reset_table_for_test();
            spawn("a", dummy, 0x200000).unwrap();
            spawn("b", dummy, 0x300000).unwrap();
        }
        let mut s = fresh();
        s.supervise(0, 0);
        s.supervise(1, 3);
        // Task 0 has zero budget: crash -> trip immediately.
        assert_eq!(s.handle_crash(0), Some(false));
        // Task 1 still has full budget.
        assert_eq!(s.budget_of(1), Some(3));
        assert_eq!(s.handle_crash(1), Some(true));
        let _ = spawned_count();
        let _ = task_cap(0, 0);
    }
}

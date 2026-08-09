//! The supervision-tree runtime (design doc §5: self-healing is *circuit
//! breaker + supervision tree*, not silent retry — "contain the fault so it
//! doesn't cascade, preserve full forensic state, escalate with an auditable
//! trail, never silently retry the same failure indefinitely").
//!
//! The kernel already provides the supervision *primitives* (controlled in
//! `capability-core/tests/supervision.rs`): a crash is a TaskKill event, a
//! restart is a TaskSpawn through a granted CONTROL cap, and both are audited.
//! This crate is the *runtime* on top of them — the policy layer that decides
//! what to do next. It is ordinary userspace: it holds only the naming caps
//! (CONTROL) it was given, it reads liveness from kernel truth
//! (`task_running`), and every decision it makes is written to its own
//! append-only decision log. The two logs cross-check: the kernel audit side
//! records *that* a spawn happened; the runtime side records *why* — neither
//! can be rewritten by the other.
//!
//! The circuit breaker is real: a subsystem that crashes more than its policy
//! allows is *tripped open* — the runtime refuses further restarts, records
//! the trip, and stays open until a supervisor (a parent, or the operator)
//! adopts the subsystem with a fresh budget. Nothing retries silently.
//!
//! Honest limits: liveness is `task_running` only (no heartbeat, no health
//! checks); the tree's policy tables run in one execution context in the
//! model (real OTP gives every supervisor its own process and the parent
//! creates a fresh child supervisor on restart); and the restart budget is
//! per-subsystem-lifetime, not a sliding window.

use capability_core::{CapHandle, Kernel, ObjectId, TaskHandle};

/// The restart budget one subsystem may burn before its breaker opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    pub max_restarts: u32,
}

/// The runtime's view of one supervised subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Running, as far as the kernel is concerned.
    Running,
    /// The kernel says it is not running; restarts remain within budget.
    Crashed,
    /// The breaker tripped: no further automatic restarts.
    Faulted,
}

/// One entry of the runtime's decision log. The kernel audit records the ops
/// (kill, spawn); this log records the *policy*: why a crash happened, why a
/// restart was granted, why the breaker opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEvent {
    Crash {
        at: u64,
        node: String,
        task: ObjectId,
    },
    Restart {
        at: u64,
        node: String,
        attempt: u32,
    },
    /// The breaker opened: no further automatic restarts, never silent.
    Trip {
        at: u64,
        node: String,
        restarts_burned: u32,
    },
    /// The subsystem was surrendered to a parent supervisor.
    Escalate {
        at: u64,
        node: String,
    },
    /// A parent adopted the subsystem with a fresh budget (whole-subsystem
    /// restart under the parent's authority).
    Adopt {
        at: u64,
        node: String,
    },
}

#[derive(Debug, Clone)]
pub struct Subsystem {
    name: String,
    task: TaskHandle,
    /// Naming cap in *this supervisor's* CSpace: the runtime's only authority
    /// over the subsystem is exactly what it was granted (CONTROL).
    task_cap: CapHandle,
    policy: RestartPolicy,
    restarts: u32,
    state: NodeState,
}

/// The userspace supervision runtime: a pump-driven loop over a flat table of
/// subsystems. Vertical escalation happens by surrendering a subsystem to a
/// parent `Supervisor` instance.
pub struct Supervisor {
    service: TaskHandle,
    subsystems: Vec<Subsystem>,
    log: Vec<RuntimeEvent>,
}

impl Supervisor {
    pub fn new(service: TaskHandle) -> Supervisor {
        Supervisor {
            service,
            subsystems: Vec::new(),
            log: Vec::new(),
        }
    }

    /// Supervise a subsystem. `task_cap` must be a naming cap in the
    /// supervisor's own CSpace carrying CONTROL (the "restart-service" role
    /// from §9, mechanically enforced by the kernel). The subsystem is
    /// spawned immediately — every supervised context is started by its
    /// supervisor, born under a policy.
    pub fn add(
        &mut self,
        k: &mut Kernel,
        name: &str,
        task: TaskHandle,
        task_cap: CapHandle,
        policy: RestartPolicy,
    ) -> usize {
        let _ = k.task_spawn(self.service, task_cap).unwrap();
        let idx = self.subsystems.len();
        self.subsystems.push(Subsystem {
            name: name.to_string(),
            task,
            task_cap,
            policy,
            restarts: 0,
            state: NodeState::Running,
        });
        idx
    }

    pub fn log(&self) -> &[RuntimeEvent] {
        &self.log
    }

    /// How many subsystems this supervisor currently owns.
    pub fn subsystem_count(&self) -> usize {
        self.subsystems.len()
    }

    /// The runtime's record of how many restarts a subsystem burned.
    pub fn restarts_of(&self, idx: usize) -> u32 {
        self.subsystems[idx].restarts
    }

    /// The kernel's live answer for one subsystem.
    pub fn is_running(&self, k: &mut Kernel, idx: usize) -> bool {
        self.subsystems[idx].state == NodeState::Running
            && k
                .task_running(self.service, self.subsystems[idx].task_cap)
                .unwrap_or(false)
    }

    /// The pump: check every subsystem against kernel truth; restart within
    /// budget; trip the breaker when the budget is spent. Returns the names
    /// of the subsystems restarted this pass.
    pub fn pump(&mut self, k: &mut Kernel) -> Vec<String> {
        let mut restarted = Vec::new();
        let mut events = Vec::new();
        for s in self.subsystems.iter_mut() {
            if s.state == NodeState::Faulted {
                continue;
            }
            let running = k.task_running(self.service, s.task_cap).unwrap_or(false);
            if running {
                s.state = NodeState::Running;
                continue;
            }
            events.push(RuntimeEvent::Crash {
                at: k.now(),
                node: s.name.clone(),
                task: s.task.id(),
            });
            s.state = NodeState::Crashed;
            if s.restarts < s.policy.max_restarts {
                // Restart within budget, from *this* supervisor's own role.
                if k.task_spawn(self.service, s.task_cap).is_ok() {
                    s.restarts += 1;
                    s.state = NodeState::Running;
                    restarted.push(s.name.clone());
                    events.push(RuntimeEvent::Restart {
                        at: k.now(),
                        node: s.name.clone(),
                        attempt: s.restarts,
                    });
                }
            } else {
                // Budget spent: the breaker opens. Recorded, never silent.
                s.state = NodeState::Faulted;
                events.push(RuntimeEvent::Trip {
                    at: k.now(),
                    node: s.name.clone(),
                    restarts_burned: s.restarts,
                });
            }
        }
        self.log.extend(events);
        restarted
    }

    /// Escalate a subsystem to a parent supervisor. The parent's business is
    /// what to do with it; this runtime's business is to refuse silent
    /// indefinite retry and make the surrender an audited step. The parent
    /// restarts the whole subsystem under its own authority — a fresh spawn
    /// from the parent's own role, and a fresh budget.
    pub fn escalate(&mut self, k: &mut Kernel, idx: usize, to: &mut Supervisor) {
        let node = self.subsystems[idx].name.clone();
        self.subsystems[idx].state = NodeState::Faulted;
        self.log
            .push(RuntimeEvent::Escalate { at: k.now(), node: node.clone() });
        let mut s = self.subsystems.swap_remove(idx);
        if k.task_spawn(to.service, s.task_cap).is_ok() {
            s.restarts = 0;
            s.state = NodeState::Running;
        } else {
            s.state = NodeState::Crashed;
        }
        to.subsystems.push(s);
        to.log.push(RuntimeEvent::Adopt { at: k.now(), node });
    }
}
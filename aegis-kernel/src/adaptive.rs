use crate::agent::{Agent, AgentId, CapabilityScope};
use crate::profiler::Profiler;

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Tighten(CapabilityScope),
    Suspend(&'static str),
    Terminate(&'static str),
}

pub struct AdaptivePolicy {
    pub base_scope: CapabilityScope,
    pub tighten_threshold: f32,
    pub suspend_threshold: f32,
    pub terminate_threshold: f32,
    escalation_count: [u8; 32],
}

impl AdaptivePolicy {
    pub fn new(base_scope: CapabilityScope) -> Self {
        Self {
            base_scope,
            tighten_threshold: 0.3,
            suspend_threshold: 0.7,
            terminate_threshold: 0.95,
            escalation_count: [0; 32],
        }
    }

    pub fn evaluate(&mut self, agent: &Agent, profiler: &Profiler) -> PolicyDecision {
        let deviation = profiler.compute_deviation(agent.id);
        if deviation < self.tighten_threshold {
            return PolicyDecision::Allow;
        }
        if deviation < self.suspend_threshold {
            return PolicyDecision::Tighten(Self::tighten_scope(&agent.scope));
        }
        let idx = (agent.id as usize) % 32;
        self.escalation_count[idx] += 1;
        if self.escalation_count[idx] >= 3 {
            return PolicyDecision::Terminate("repeated high deviation");
        }
        PolicyDecision::Suspend("high deviation")
    }

    pub fn tighten_scope(scope: &CapabilityScope) -> CapabilityScope {
        let mut new_scope = scope.clone();
        new_scope.network_allowed = false;
        new_scope.max_memory_pages = (new_scope.max_memory_pages / 2).max(1);
        new_scope.max_file_handles = (new_scope.max_file_handles / 2).max(1);
        for i in 0..32 {
            new_scope.allowed_syscalls[i] = scope.allowed_syscalls[i] && (i % 2 == 0);
        }
        new_scope
    }

    pub fn record_suspension(&mut self, agent_id: AgentId) {
        let idx = (agent_id as usize) % 32;
        self.escalation_count[idx] += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentState;

    fn make_agent(id: AgentId) -> Agent {
        Agent {
            id,
            state: AgentState::Running,
            scope: CapabilityScope::permissive(),
            created_at: 0,
            last_active_at: 0,
            syscall_count: 0,
            deviation_score: 0.0,
        }
    }

    #[test]
    fn allow_when_deviation_low() {
        let mut prof = Profiler::new(1000);
        for i in 0..32 {
            for _ in 0..10 {
                prof.record(crate::profiler::SyscallRecord {
                    agent_id: 1,
                    syscall_num: i,
                    timestamp: 100,
                    arg1: 0,
                    arg2: 0,
                    success: true,
                });
            }
        }
        let agent = make_agent(1);
        let mut policy = AdaptivePolicy::new(CapabilityScope::permissive());
        assert_eq!(policy.evaluate(&agent, &prof), PolicyDecision::Allow);
    }

    #[test]
    fn tighten_when_deviation_medium() {
        let mut prof = Profiler::new(1000);
        for i in 0..320 {
            let syscall = if i < 64 {
                0u32
            } else {
                ((i - 64) % 31 + 1) as u32
            };
            prof.record(crate::profiler::SyscallRecord {
                agent_id: 1,
                syscall_num: syscall,
                timestamp: 100,
                arg1: 0,
                arg2: 0,
                success: true,
            });
        }
        let agent = make_agent(1);
        let mut policy = AdaptivePolicy::new(CapabilityScope::permissive());
        let dev = prof.compute_deviation(1);
        assert!(dev >= 0.3 && dev < 0.7, "deviation {} not in medium range", dev);
        match policy.evaluate(&agent, &prof) {
            PolicyDecision::Tighten(_) => {}
            other => panic!("expected Tighten, got {:?}", other),
        }
    }

    #[test]
    fn suspend_when_deviation_high() {
        let mut prof = Profiler::new(1000);
        for _ in 0..3200 {
            prof.record(crate::profiler::SyscallRecord {
                agent_id: 1,
                syscall_num: 0,
                timestamp: 100,
                arg1: 0,
                arg2: 0,
                success: true,
            });
        }
        let agent = make_agent(1);
        let mut policy = AdaptivePolicy::new(CapabilityScope::permissive());
        assert_eq!(policy.evaluate(&agent, &prof), PolicyDecision::Suspend("high deviation"));
    }

    #[test]
    fn terminate_after_repeated_suspensions() {
        let mut prof = Profiler::new(1000);
        for _ in 0..3200 {
            prof.record(crate::profiler::SyscallRecord {
                agent_id: 1,
                syscall_num: 0,
                timestamp: 100,
                arg1: 0,
                arg2: 0,
                success: true,
            });
        }
        let agent = make_agent(1);
        let mut policy = AdaptivePolicy::new(CapabilityScope::permissive());
        for _ in 0..2 {
            policy.evaluate(&agent, &prof);
        }
        assert_eq!(
            policy.evaluate(&agent, &prof),
            PolicyDecision::Terminate("repeated high deviation")
        );
    }

    #[test]
    fn tighten_scope_removes_network() {
        let scope = CapabilityScope::permissive();
        let tightened = AdaptivePolicy::tighten_scope(&scope);
        assert!(!tightened.network_allowed);
    }
}

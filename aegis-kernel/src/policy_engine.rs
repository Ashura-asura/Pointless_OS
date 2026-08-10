use crate::agent::{Agent, AgentId, CapabilityScope};
use crate::profiler::Profiler;
use crate::adaptive::PolicyDecision;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PolicyRule {
    MaxSyscalls(u32),
    MaxMemory(u32),
    NoNetwork,
    TimeLimit(u32),
    RequireApproval(&'static str),
}

impl PolicyRule {
    pub fn check(&self, agent: &Agent, profile: &crate::profiler::UsageProfile) -> bool {
        match self {
            PolicyRule::MaxSyscalls(max) => profile.total_syscalls <= *max,
            PolicyRule::MaxMemory(max) => profile.peak_memory_pages <= *max,
            PolicyRule::NoNetwork => !agent.scope.network_allowed,
            PolicyRule::TimeLimit(_max_ticks) => true,
            PolicyRule::RequireApproval(_name) => false,
        }
    }

    fn description(&self) -> &'static str {
        match self {
            PolicyRule::MaxSyscalls(_) => "MaxSyscalls",
            PolicyRule::MaxMemory(_) => "MaxMemory",
            PolicyRule::NoNetwork => "NoNetwork",
            PolicyRule::TimeLimit(_) => "TimeLimit",
            PolicyRule::RequireApproval(_) => "RequireApproval",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub agent_id: AgentId,
    pub rule_description: &'static str,
    pub passed: bool,
    pub action_taken: &'static str,
    pub timestamp: u64,
}

struct AuditSlot {
    entry: AuditEntry,
    used: bool,
}

struct RuleSlot {
    rule: PolicyRule,
    used: bool,
}

pub struct PolicyEngine {
    rules: [RuleSlot; 16],
    rule_count: usize,
    audit_log: [AuditSlot; 128],
    log_count: usize,
}

impl PolicyEngine {
    pub fn new() -> Self {
        const DEFAULT_RULE: RuleSlot = RuleSlot {
            rule: PolicyRule::MaxSyscalls(0),
            used: false,
        };
        const DEFAULT_AUDIT: AuditSlot = AuditSlot {
            entry: AuditEntry {
                agent_id: 0,
                rule_description: "",
                passed: false,
                action_taken: "",
                timestamp: 0,
            },
            used: false,
        };
        Self {
            rules: [DEFAULT_RULE; 16],
            rule_count: 0,
            audit_log: [DEFAULT_AUDIT; 128],
            log_count: 0,
        }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        if self.rule_count < self.rules.len() {
            self.rules[self.rule_count] = RuleSlot { rule, used: true };
            self.rule_count += 1;
        }
    }

    pub fn evaluate(&mut self, agent: &Agent, profiler: &Profiler) -> PolicyDecision {
        let empty_profile = crate::profiler::UsageProfile::new(agent.id);
        let profile_ref = profiler.get_profile(agent.id).unwrap_or(&empty_profile);

        let mut worst = PolicyDecision::Allow;
        for i in 0..self.rule_count {
            if self.rules[i].used {
                let rule = self.rules[i].rule;
                let passed = rule.check(agent, profile_ref);
                let description = rule.description();

                let action: &'static str = if passed {
                    "Allow"
                } else {
                    match rule {
                        PolicyRule::RequireApproval(_) => "Terminate",
                        PolicyRule::MaxSyscalls(_) | PolicyRule::MaxMemory(_) => "Suspend",
                        _ => "Tighten",
                    }
                };

                self.log_entry(AuditEntry {
                    agent_id: agent.id,
                    rule_description: description,
                    passed,
                    action_taken: action,
                    timestamp: 0,
                });

                if !passed {
                    let new_worst = match rule {
                        PolicyRule::RequireApproval(_) => {
                            PolicyDecision::Terminate("approval required")
                        }
                        PolicyRule::MaxSyscalls(_) | PolicyRule::MaxMemory(_) => {
                            PolicyDecision::Suspend("resource limit exceeded")
                        }
                        PolicyRule::NoNetwork | PolicyRule::TimeLimit(_) => {
                            PolicyDecision::Tighten(CapabilityScope::restrictive())
                        }
                    };
                    worst = Self::worst_decision(worst, new_worst);
                }
            }
        }
        worst
    }

    fn worst_decision(a: PolicyDecision, b: PolicyDecision) -> PolicyDecision {
        fn severity(d: &PolicyDecision) -> u8 {
            match d {
                PolicyDecision::Allow => 0,
                PolicyDecision::Tighten(_) => 1,
                PolicyDecision::Suspend(_) => 2,
                PolicyDecision::Terminate(_) => 3,
            }
        }
        if severity(&b) > severity(&a) { b } else { a }
    }

    fn log_entry(&mut self, entry: AuditEntry) {
        if self.log_count < self.audit_log.len() {
            self.audit_log[self.log_count] = AuditSlot { entry, used: true };
            self.log_count += 1;
        }
    }

    pub fn audit_log(&self) -> &[AuditEntry] {
        static EMPTY: [AuditEntry; 0] = [];
        if self.log_count == 0 {
            return &EMPTY;
        }
        unsafe {
            core::slice::from_raw_parts(
                &self.audit_log[0].entry as *const AuditEntry,
                self.log_count,
            )
        }
    }

    pub fn clear_audit_log(&mut self) {
        for slot in self.audit_log.iter_mut() {
            slot.used = false;
        }
        self.log_count = 0;
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
    fn evaluate_passes_all_rules() {
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
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule::MaxSyscalls(320));
        assert_eq!(engine.evaluate(&agent, &prof), PolicyDecision::Allow);
    }

    #[test]
    fn evaluate_fails_on_max_syscalls() {
        let mut prof = Profiler::new(1000);
        for _ in 0..100 {
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
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule::MaxSyscalls(50));
        assert_eq!(
            engine.evaluate(&agent, &prof),
            PolicyDecision::Suspend("resource limit exceeded")
        );
    }

    #[test]
    fn evaluate_fails_on_no_network() {
        let prof = Profiler::new(1000);
        let mut agent = make_agent(1);
        agent.scope.network_allowed = true;
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule::NoNetwork);
        assert_eq!(engine.evaluate(&agent, &prof), PolicyDecision::Tighten(CapabilityScope::restrictive()));
    }

    #[test]
    fn audit_log_records_every_evaluation() {
        let mut prof = Profiler::new(1000);
        let agent = make_agent(1);
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule::MaxSyscalls(320));
        engine.add_rule(PolicyRule::NoNetwork);
        engine.evaluate(&agent, &prof);
        let log = engine.audit_log();
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn clear_audit_log_empties_log() {
        let mut prof = Profiler::new(1000);
        let agent = make_agent(1);
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule::MaxSyscalls(320));
        engine.evaluate(&agent, &prof);
        engine.clear_audit_log();
        let log = engine.audit_log();
        assert_eq!(log.len(), 0);
    }
}

// Adaptive-layer ceiling verification (Phase 10).
//
// Design doc §3/§5/§7 Phase 10: "formal verification of the adaptive layer's
// ceiling (not its policy)". The claim verified here is not *what the adaptive
// layer decides* (policy is validated by testing and auditing, never by proof)
// but that the adaptive layer can NEVER exceed the capability ceiling: no
// decision — from AdaptivePolicy, PolicyEngine, or any compatible personality —
// may widen a scope, raise a budget, or add an allowed syscall. Every outcome
// is monotonically non-expanding, and under adversarial inputs the worst case
// is still within the granted scope. Honest limits: these are property-style
// contract tests over the model's decision logic (finite, deterministic);
// they are not an inductive formal proof and do not cover real hardware.
//
// This module is test-only (`#![cfg(test)]`): it exists to verify the ceiling,
// not to be part of the kernel image.

#![cfg(test)]

use crate::adaptive::{AdaptivePolicy, PolicyDecision};
use crate::agent::{Agent, AgentId, CapabilityScope};
use crate::policy_engine::{PolicyEngine, PolicyRule};
use crate::profiler::Profiler;

fn make_agent(id: AgentId, scope: CapabilityScope) -> Agent {
    Agent {
        id,
        state: crate::agent::AgentState::Running,
        scope,
        created_at: 0,
        last_active_at: 0,
        syscall_count: 0,
        deviation_score: 0.0,
    }
}

/// A scope S2 is within the ceiling of S1 iff S2 is no more permissive than
/// S1 on every dimension: no allowed syscall removed-from-outside, budgets
/// never raised, and network never added.
fn scope_within_ceiling(ceiling: &CapabilityScope, candidate: &CapabilityScope) -> bool {
    candidate.network_allowed <= ceiling.network_allowed
        && candidate.max_memory_pages <= ceiling.max_memory_pages
        && candidate.max_file_handles <= ceiling.max_file_handles
        && candidate.time_slice_ms <= ceiling.time_slice_ms
        && (0..32).all(|i| !candidate.allowed_syscalls[i] || ceiling.allowed_syscalls[i])
}

/// A decision is within the ceiling if it is Allow, or its attached scope is
/// within the ceiling (Suspend/Terminate carry no scope).
fn decision_within_ceiling(ceiling: &CapabilityScope, d: &PolicyDecision) -> bool {
    match d {
        PolicyDecision::Allow => true,
        PolicyDecision::Tighten(s) => scope_within_ceiling(ceiling, s),
        PolicyDecision::Suspend(_) | PolicyDecision::Terminate(_) => true,
    }
}

fn high_deviation_profiler(agent_id: AgentId) -> Profiler {
    let mut prof = Profiler::new(1000);
    for _ in 0..3200 {
        prof.record(crate::profiler::SyscallRecord {
            agent_id,
            syscall_num: 0,
            timestamp: 100,
            arg1: 0,
            arg2: 0,
            success: true,
        });
    }
    prof
}

fn medium_deviation_profiler(agent_id: AgentId) -> Profiler {
    let mut prof = Profiler::new(1000);
    // Half in syscall 0, half spread across others => deviation ~0.5
    for i in 0..1600 {
        prof.record(crate::profiler::SyscallRecord {
            agent_id,
            syscall_num: if i % 2 == 0 { 0 } else { (i % 7) as u32 },
            timestamp: 100,
            arg1: 0,
            arg2: 0,
            success: true,
        });
    }
    prof
}

#[test]
fn tighten_never_expands_any_dimension() {
    for scope in [
        CapabilityScope::permissive(),
        CapabilityScope::restrictive(),
    ] {
        let tightened = AdaptivePolicy::tighten_scope(&scope);
        assert!(
            scope_within_ceiling(&scope, &tightened),
            "tighten expanded the scope"
        );
    }
}

#[test]
fn tighten_reduces_network_when_present() {
    let scope = CapabilityScope::permissive();
    let tightened = AdaptivePolicy::tighten_scope(&scope);
    assert!(!tightened.network_allowed);
}

#[test]
fn tighten_never_raises_memory_budget() {
    let scope = CapabilityScope::permissive();
    let tightened = AdaptivePolicy::tighten_scope(&scope);
    assert!(tightened.max_memory_pages <= scope.max_memory_pages);
    assert!(tightened.max_memory_pages >= 1);
}

#[test]
fn tighten_never_raises_zero_budget_to_nonzero() {
    let scope = CapabilityScope::restrictive();
    let tightened = AdaptivePolicy::tighten_scope(&scope);
    assert_eq!(tightened.max_file_handles, 0);
    assert_eq!(tightened.max_memory_pages, 1);
}

#[test]
fn tighten_never_adds_an_allowed_syscall() {
    let scope = CapabilityScope::permissive();
    let tightened = AdaptivePolicy::tighten_scope(&scope);
    for i in 0..32 {
        assert!(
            !tightened.allowed_syscalls[i] || scope.allowed_syscalls[i],
            "syscall {} added by tighten",
            i
        );
    }
}

#[test]
fn tighten_restrictive_stays_restrictive() {
    let scope = CapabilityScope::restrictive();
    let tightened = AdaptivePolicy::tighten_scope(&scope);
    assert!(scope_within_ceiling(&scope, &tightened));
    assert!(tightened.max_memory_pages >= 1);
}

#[test]
fn adaptive_medium_deviation_decision_stays_in_ceiling() {
    let prof = medium_deviation_profiler(1);
    let agent = make_agent(1, CapabilityScope::permissive());
    let mut policy = AdaptivePolicy::new(agent.scope.clone());
    let decision = policy.evaluate(&agent, &prof);
    assert!(decision_within_ceiling(&agent.scope, &decision));
}

#[test]
fn adaptive_high_deviation_decision_stays_in_ceiling() {
    let prof = high_deviation_profiler(1);
    let agent = make_agent(1, CapabilityScope::permissive());
    let mut policy = AdaptivePolicy::new(agent.scope.clone());
    let decision = policy.evaluate(&agent, &prof);
    assert!(decision_within_ceiling(&agent.scope, &decision));
}

#[test]
fn repeated_suspensions_escalate_but_never_widen() {
    let prof = high_deviation_profiler(1);
    let agent = make_agent(1, CapabilityScope::permissive());
    let mut policy = AdaptivePolicy::new(agent.scope.clone());
    for _ in 0..4 {
        let decision = policy.evaluate(&agent, &prof);
        assert!(decision_within_ceiling(&agent.scope, &decision));
    }
}

#[test]
fn policy_engine_allow_is_in_ceiling() {
    let prof = Profiler::new(1000);
    let agent = make_agent(1, CapabilityScope::permissive());
    let mut engine = PolicyEngine::new();
    engine.add_rule(PolicyRule::MaxSyscalls(10_000));
    let decision = engine.evaluate(&agent, &prof);
    assert_eq!(decision, PolicyDecision::Allow);
    assert!(decision_within_ceiling(&agent.scope, &decision));
}

#[test]
fn policy_engine_tighten_is_in_ceiling() {
    let prof = Profiler::new(1000);
    let mut agent = make_agent(1, CapabilityScope::permissive());
    agent.scope.network_allowed = true;
    let mut engine = PolicyEngine::new();
    engine.add_rule(PolicyRule::NoNetwork);
    let decision = engine.evaluate(&agent, &prof);
    assert!(decision_within_ceiling(&agent.scope, &decision));
}

#[test]
fn policy_engine_suspend_is_in_ceiling() {
    let prof = Profiler::new(1000);
    let agent = make_agent(1, CapabilityScope::permissive());
    let mut engine = PolicyEngine::new();
    engine.add_rule(PolicyRule::MaxMemory(0));
    let decision = engine.evaluate(&agent, &prof);
    assert!(decision_within_ceiling(&agent.scope, &decision));
}

#[test]
fn worst_case_decision_never_exceeds_restrictive_ceiling() {
    let prof = high_deviation_profiler(1);
    let agent = make_agent(1, CapabilityScope::restrictive());
    let mut policy = AdaptivePolicy::new(agent.scope.clone());
    for _ in 0..5 {
        let decision = policy.evaluate(&agent, &prof);
        assert!(
            decision_within_ceiling(&agent.scope, &decision),
            "decision escaped restrictive ceiling: {:?}",
            decision
        );
    }
}

#[test]
fn tighten_from_restrictive_keeps_at_least_one_syscall() {
    let scope = CapabilityScope::restrictive();
    let tightened = AdaptivePolicy::tighten_scope(&scope);
    assert!((0..32).any(|i| tightened.allowed_syscalls[i]));
}

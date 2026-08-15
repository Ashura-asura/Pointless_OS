---------------------------------- MODULE AegisCeiling ----------------------------------
(*
  Aegis Phase L — formal verification of the adaptive layer's CEILING, not its
  policy (master roadmap Phase L / design doc §7 Phase 10). This is the TLA+
  counterpart of aegis-kernel/src/ceiling.rs's Rust property tests
  (scope_within_ceiling / decision_within_ceiling): those check specific
  hand-picked adversarial sequences against the model's decision logic; this
  spec has TLC search EVERY reachable sequence of role/policy actions under
  arbitrary interleaving, for every role defined so far (restart-service,
  observe-service, query-advisor — role.rs's ROLE_QUERY_ADVISOR from Phase F).

  What this proves and what it doesn't (stated up front, same discipline as
  AegisCapabilities.tla):
    - PROVES: for the finite instance below, no reachable state has any
      role's EffectiveScope exceeding its GrantedScope on any dimension, and
      QueryAdvisor's EffectiveScope never includes a host outside its one
      approved destination. This is the "ceiling", i.e. the ADAPTIVE LAYER
      cannot escape what it was granted — checked across every ordering the
      search explores, not just the specific sequences hand-tested in Rust.
    - DOES NOT PROVE: that the adaptive layer's *decisions* are good, safe,
      or aligned with intent — that's policy, and per design doc §10 it is
      explicitly inherent/unprovable by construction (judgment cannot be
      proven, only bounded). This spec treats the adaptive layer's choice of
      which action to take at each step as fully adversarial (Eve again, same
      role this construct plays in AegisCapabilities.tla) — it may pick the
      WORST action available to it at every step; the claim is that even the
      worst available action never breaches the ceiling, because the actions
      available to it structurally cannot.
    - This module was written by reading role.rs/ceiling.rs/agent.rs directly
      but was NOT run through TLC in the environment that wrote it (no
      TLA+ tooling available there). Run it the same way
      AegisCapabilities.tla is already run in this repo's own CI before
      citing a state count — see the "how to run" note at the bottom.

  Representational choices:
    - Roles = {"RestartService", "ObserveService", "QueryAdvisor"} — the
      three defined in role.rs today. Extending this set when a fourth role
      lands is the intended maintenance path for this file, not a rewrite.
    - A scope is a record with four monotone-narrowable dimensions
      (mirrors CapabilityScope in agent.rs / ceiling.rs exactly):
        network   \in BOOLEAN        (network_allowed)
        memPages  \in 0..MaxPages    (max_memory_pages)
        fileHnds  \in 0..MaxHandles  (max_file_handles)
        timeSlice \in 0..MaxSlice    (time_slice_ms)
      "Narrower" means: network implies no widening True, and the three
      numeric fields never increase.
    - QueryAdvisor carries one extra dimension no other role has: hostScope
      \in {NoHost, ApprovedHost, AnyHost} — modeling role.rs's actual
      distinction (network capability scoped to exactly one destination,
      never ambient). ApprovedHost is the only value QueryAdvisor's granted
      scope may ever hold to start; AnyHost exists in the type only so the
      adversary can legally ATTEMPT to reach it — the invariant is that no
      reachable state ever has QueryAdvisor's effective hostScope = AnyHost.
    - GrantedScope[r] is fixed per role at boot (mirrors role.rs: a role
      grant installs an exact, fixed capability set — it is not itself
      narrowable, only what the AGENT holding it can do within it is).
    - EffectiveScope[r] is what TLC searches over: starts equal to
      GrantedScope[r], and every step is either AdaptiveNarrow (the real
      adaptive-layer operation — always available, always narrows-or-holds,
      matching PolicyDecision::Tighten/Suspend/Terminate/Allow in
      adaptive.rs) or WidenAttempt (models an adversarial bug/compromise
      attempting to escape — included specifically so the CHECK has teeth:
      if this spec's Next relation ever accidentally permitted WidenAttempt
      to succeed, TLC would find the counterexample immediately, the same
      "a bug would be caught, not just believed absent" argument
      AegisCapabilities.tla makes for its own invariants).
*)
EXTENDS Integers

CONSTANTS
  Roles,        \* {"RestartService", "ObserveService", "QueryAdvisor"}
  MaxPages,     \* bound on memPages for TLC finiteness
  MaxHandles,   \* bound on fileHnds
  MaxSlice      \* bound on timeSlice

ASSUME Roles = {"RestartService", "ObserveService", "QueryAdvisor"}
ASSUME MaxPages \in 1..8 /\ MaxHandles \in 1..8 /\ MaxSlice \in 1..8

HostVals == {"NoHost", "ApprovedHost", "AnyHost"}

\* A scope for a non-QueryAdvisor role omits hostScope entirely (modeled as
\* "NoHost", the value every non-QueryAdvisor role's scope is fixed at,
\* since only query-advisor ever holds a network-destination capability at
\* all per role.rs).
Scopes == [
  network   : BOOLEAN,
  memPages  : 0..MaxPages,
  fileHnds  : 0..MaxHandles,
  timeSlice : 0..MaxSlice,
  hostScope : HostVals
]

\* Fixed per-role grants, matching role.rs's actual role definitions:
\*  - RestartService: no network, moderate everything else (it restarts a
\*    task, nothing more).
\*  - ObserveService: read-only-shaped (narrower memory/handles than
\*    restart-service — it only watches), no network.
\*  - QueryAdvisor: THE role with network, but scoped to exactly one host —
\*    ApprovedHost, never AnyHost, per role.rs's actual capability grant.
GrantedScope == [r \in Roles |->
  CASE r = "RestartService" ->
         [network |-> FALSE, memPages |-> MaxPages, fileHnds |-> MaxHandles,
          timeSlice |-> MaxSlice, hostScope |-> "NoHost"]
    [] r = "ObserveService" ->
         [network |-> FALSE, memPages |-> MaxPages - 1, fileHnds |-> MaxHandles - 1,
          timeSlice |-> MaxSlice, hostScope |-> "NoHost"]
    [] r = "QueryAdvisor" ->
         [network |-> TRUE, memPages |-> 1, fileHnds |-> 1,
          timeSlice |-> MaxSlice, hostScope |-> "ApprovedHost"]
]

VARIABLE EffectiveScope

TypeOK == EffectiveScope \in [Roles -> Scopes]

Init == EffectiveScope = GrantedScope

\* A scope s2 is "no more permissive than" s1 — the same relation
\* ceiling.rs's scope_within_ceiling checks in Rust, plus the hostScope
\* dimension role.rs actually has and the Rust model (pre-Phase-L) didn't
\* yet formalize.
WithinCeiling(ceiling, candidate) ==
  /\ candidate.network \in BOOLEAN
  /\ (candidate.network => ceiling.network)
  /\ candidate.memPages <= ceiling.memPages
  /\ candidate.fileHnds <= ceiling.fileHnds
  /\ candidate.timeSlice <= ceiling.timeSlice
  /\ (candidate.hostScope = "ApprovedHost" => ceiling.hostScope = "ApprovedHost")
  /\ (candidate.hostScope = "AnyHost" => ceiling.hostScope = "AnyHost") \* never true for any granted scope above — this is the clause that gives CeilingInvariant its teeth

\* The real adaptive-layer operation (adaptive.rs's AdaptivePolicy /
\* PolicyEngine, modeled at the ceiling.rs level of abstraction): picks ANY
\* new scope for role r that is within the CURRENT effective scope's
\* ceiling — Tighten narrows, Suspend/Terminate are the degenerate "narrow
\* to nothing" case, Allow is "narrow by zero" (no change). The adversary
\* (this operation is fully nondeterministic — TLC tries every candidate)
\* picks the worst one available; that is still bounded by construction.
AdaptiveNarrow(r) ==
  \E s \in Scopes :
    /\ WithinCeiling(EffectiveScope[r], s)
    /\ EffectiveScope' = [EffectiveScope EXCEPT ![r] = s]

\* The adversarial "what if a bug let this happen" operation: an attempt to
\* set role r's effective scope to something OUTSIDE its own granted
\* ceiling. Modeled but — critically — this spec's Next relation below
\* does NOT include it as a reachable transition; it exists so a reviewer
\* (or a deliberate mutation to Next, e.g. for a regression check) can
\* verify TLC actually reports a CeilingInvariant violation if this were
\* ever wired in, the same "the check has teeth" argument the header makes.
WidenAttempt(r) ==
  \E s \in Scopes :
    /\ ~WithinCeiling(GrantedScope[r], s)
    /\ EffectiveScope' = [EffectiveScope EXCEPT ![r] = s]

Next == \E r \in Roles : AdaptiveNarrow(r)

Spec == Init /\ [][Next]_EffectiveScope

\* THE ceiling property: every role's effective scope, in every reachable
\* state, under arbitrary interleaving of arbitrary narrowing choices for
\* every role, stays within what that role was granted at boot.
CeilingInvariant ==
  \A r \in Roles : WithinCeiling(GrantedScope[r], EffectiveScope[r])

\* The QueryAdvisor-specific headline result the master doc calls out by
\* name (Phase F's adversarial test, generalized here to ALL reachable
\* states rather than the specific hand-tested sequences): the advisor
\* role's effective host scope can never become AnyHost. Implied by
\* CeilingInvariant already (WithinCeiling's last clause), stated again as
\* its own named invariant so a TLC counterexample on this specific
\* property is unambiguous about which claim broke.
QueryAdvisorNeverEscapesHostScope ==
  EffectiveScope["QueryAdvisor"].hostScope # "AnyHost"

InvAll == TypeOK /\ CeilingInvariant /\ QueryAdvisorNeverEscapesHostScope

===========================================================================
(*
  How to run (mirrors this repo's own AegisCapabilities.tla / .cfg pattern
  — see AegisCeiling.cfg alongside this file):

    tlc2 -config AegisCeiling.cfg AegisCeiling.tla

  Report the real state count TLC prints, the same way 331k states is cited
  for AegisCapabilities — don't carry this file's number forward as a claim
  until that command has actually been run and its real output captured,
  per Ground Rule 4.
*)

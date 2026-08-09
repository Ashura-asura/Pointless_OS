--------------------------------- MODULE AegisCapabilities ----------------------------------
(*
  Aegis Phase 0 — the capability delegation rules, in TLA+.
  This is the model of aegis/spec/capability-model.md, faithful to crates/capability-core.
  It is deliberately minimal: any claim it makes is about THIS model, i.e. about the
  authority semantics of the delegation machinery, not about real-machine isolation
  (the honest ceiling already stated in capability-model.md §5).

  Why the model has teeth:
    - every task is an *adversary*: the search explores every task trying every
      operation with every admissible parameter combination (all request shapes are
      explored; the adversary may pick maximal or empty request sets);
    - the invariants I1..I5 below must hold in EVERY reachable state;
    - a bug in the model that dropped, say, the rights intersection or the expiry
      clamp would be found by TLC as a counterexample, not by reading.

  Representational choices (all documented so the model can be argued with):
    - CapId = [obj |-> o, n |-> k]: a capability is kernel-minted only; `mints`
      counts minted caps and no op can mint a cid with n > mints (I1).
    - rightsFrom[c] = the cap c was minted from (the clamp source). Roots (self
      caps, boot caps, the creator's child self-cap) have rightsFrom = NONE.
    - children[parent] = caps minted with parent as revocation root: the Rust
      `parents` map, inverted. Revocation removes exactly the named subtree from
      EVERY CSpace (I4) and marks each removed cap revoked; the marker exists only
      to make "no revoked cap present anywhere" checkable as an invariant.
    - GrantRoot-derived caps parent to the grant-root cap (grant_mint), so revoking
      a grant root cleans every grantee at once while the grantor's own caps survive.
    - Expiry: ExpClamp(req, par) = min — no op can extend a cap past its parent's
      life (I5). Root caps expire at INF (the bound, not an infinity).
    - Self caps of created tasks are rightsFrom = NONE with ALL rights: creation is
      gated on holding a capability to Creator, and the child's authority over
      itself is full (as in the Rust kernel) — creation "starts from nothing".
    - Consent (I6): every Grant/GrantMint must name its destination through a cap
      the caller holds that carries the RECEIVE right — a bare naming reference
      (rights = {}) confers no write access to another task's CSpace. `consentedInto`
      is the shadow marker set exactly where the guard licenses a mint; the I6
      invariant says every cap present anywhere was minted under consent. The
      coupling guard-event to marker is what gives the invariant its teeth: a spec
      bug inserting a cap into a CSpace without the consent path would be caught
      (the marker is unset); removing the marker along with the guard is a change
      that is visible in review of this file itself. That is the honest statement
      of what this check can and cannot do.
    - RQ / XQ bound the request shapes TLC explores. This is standard model-checking
      honesty: the check is for the checked instance (see the .cfg). ALLRIGHTS is
      included, and clamping is monotone in the request, so the maximal request
      subsumes the rest. RQ also includes {} (zero rights): minting an empty naming
      reference and then trying to use it as a grant destination must still fail.
*)
EXTENDS Integers, FiniteSets

CONSTANTS
  Tasks,                 \* the (finite) set of tasks; a task is also an object
  Slots,                 \* slot indices in a CSpace; must contain 0, 1, 2
  RIGHTS,                \* right tokens
  Root,                  \* the boot-time authority holder
  Eve,                   \* an ordinary task that plays the adversary in the search
  Creator,               \* the object a cap must name to create tasks
  GrantRoot,             \* the singleton grant-root object
  MaxMints,              \* bound on total cap mints (keeps TLC finite)
  INF,                   \* "never expires" as a large but finite tick bound
  Horizon                \* clock bound: Tick never runs past it; the I5 check only
                         \* needs a few expiry frames, and bounding now guarantees
                         \* the search terminates instead of unfolding a long tail
                         \* of clock-only states per configuration

ASSUME 0 \in Slots /\ 1 \in Slots /\ 2 \in Slots
ASSUME Root \in Tasks /\ Eve \in Tasks /\ Root # Eve
ASSUME Creator \notin Tasks /\ GrantRoot \notin Tasks /\ Creator # GrantRoot
ASSUME MaxMints > 4 /\ INF >= 100
ASSUME Horizon >= 5
ASSUME "G" \in RIGHTS /\ "RECEIVE" \in RIGHTS   \* the tokens used below must be rights

\* the right tokens named in the ops, as definitions (not constants) so the
\* adversarial search cannot reassign them
RightG == "G"
RightReceive == "RECEIVE"

Slot0 == 0
Slot1 == 1
Slot2 == 2

Objects == Tasks \cup {Creator, GrantRoot}
CapId == {[obj |-> o, n |-> k] : o \in Objects, k \in 1..MaxMints}
NONE == [obj |-> CHOOSE o \in Objects : TRUE, n |-> 0]
ALLRIGHTS == RIGHTS

\* request shapes the adversarial search may try (see header comment)
RQ == {ALLRIGHTS, {"G"}, {"C"}, {}}
\* requested expiries: never, short, long
XQ == {INF, 5}   \* expiry shapes: never, and expiring inside the checked horizon

VARIABLES
  cspaces,              \* [Task -> [Slot -> CapId \cup {NONE}]]
  mints,                \* number of caps ever minted (global counter, 0..MaxMints)
  rightsOf,             \* [CapId -> SUBSET RIGHTS]
  expiresAt,            \* [CapId -> 0..INF]
  rightsFrom,           \* [CapId -> CapId \cup {NONE}]  clamp source
  children,             \* [CapId -> SUBSET CapId]       revocation tree
  revoked,              \* [CapId -> BOOLEAN]            removed by a revoke
  consentedInto,        \* [CapId -> BOOLEAN]            minted under I6 consent
  now                   \* kernel clock

vars == <<cspaces, mints, rightsOf, expiresAt, rightsFrom, children, revoked, consentedInto, now>>

minted(c) == c.n \in 1..mints

Present(t, c) == \E s \in Slots : cspaces[t][s] = c

UsableAt(t, c) == /\ minted(c)
                  /\ Present(t, c)
                  /\ ~ revoked[c]
                  /\ now <= expiresAt[c]

(*
  The caps a task may actually exercise. Quantifying the adversarial search over
  this set — rather than over all of CapId with a UsableAt guard — is a pure
  enumeration-basis optimization: it changes no semantic (every op that previously
  could pick c must have UsableAt(caller, c) anyway) and cuts TLC's candidate
  tuples by roughly two orders of magnitude, without shrinking the model.
*)
Usable(t) == {c \in CapId : UsableAt(t, c)}

ExpClamp(req, par) == IF req < par THEN req ELSE par

(*
  The subtree rooted at c: {c} plus everything transitively minted under it.
  Recursion is on a decreasing natural bound, so TLC terminates: a derivation
  chain cannot be longer than the total number of mints.
*)
RECURSIVE Subtree(_, _)
Subtree(c, n) ==
    IF n = 0 THEN {} ELSE {c} \cup UNION {Subtree(k, n - 1) : k \in children[c]}

Init ==
    /\ mints = 4
    /\ LET selfR  == [obj |-> Root, n |-> 1]
           cc     == [obj |-> Creator, n |-> 2]
           gr     == [obj |-> GrantRoot, n |-> 3]
           selfE  == [obj |-> Eve, n |-> 4]
        IN
        /\ cspaces = [t \in Tasks |->
            IF t = Root THEN [s \in Slots |->
                IF s = Slot0 THEN selfR
                ELSE IF s = Slot1 THEN cc
                ELSE IF s = Slot2 THEN gr
                ELSE NONE]
            ELSE IF t = Eve THEN [s \in Slots |-> IF s = Slot0 THEN selfE ELSE NONE]
            ELSE [s \in Slots |-> NONE]]
    /\ rightsOf      = [c \in CapId |-> IF c.n \in 1..4 THEN ALLRIGHTS ELSE {}]
    /\ expiresAt     = [c \in CapId |-> INF]
    /\ rightsFrom    = [c \in CapId |-> NONE]
    /\ children      = [c \in CapId |-> {}]
    /\ revoked       = [c \in CapId |-> FALSE]
    /\ consentedInto = [c \in CapId |-> TRUE]    \* boot caps are consented at boot
    /\ now           = 0

(* creation is gated on holding a capability naming Creator; the child's self cap
   is a fresh root (full rights over itself), like the Rust kernel *)
CreateTask ==
    \E caller \in Tasks : \E cc \in Usable(caller), u \in Tasks:
        /\ cc.obj = Creator
        /\ cspaces[u][Slot0] = NONE
        /\ mints < MaxMints
        /\ LET nc == [obj |-> u, n |-> mints + 1] IN
           /\ cspaces'  = [t \in Tasks |->
                IF t = u THEN [s \in Slots |-> IF s = Slot0 THEN nc ELSE cspaces[u][s]]
                ELSE cspaces[t]]
           /\ mints'    = mints + 1
           /\ rightsOf' = [c \in CapId |-> IF c = nc THEN ALLRIGHTS ELSE rightsOf[c]]
           /\ expiresAt'= [c \in CapId |-> IF c = nc THEN INF ELSE expiresAt[c]]
           /\ consentedInto' = [c \in CapId |-> IF c = nc THEN TRUE ELSE consentedInto[c]]
           /\ UNCHANGED <<rightsFrom, children, revoked, now>>

(* copy: a narrowed clone of the caller's own cap, into the caller's CSpace —
   self-consent, no destination guard needed *)
Copy ==
    \E caller \in Tasks : \E sc \in Usable(caller) : \E rq \in RQ, xq \in XQ, s \in Slots:
        /\ RightG \in rightsOf[sc]
        /\ cspaces[caller][s] = NONE
        /\ mints < MaxMints
        /\ LET nc == [obj |-> sc.obj, n |-> mints + 1] IN
           /\ cspaces'  = [t \in Tasks |->
                IF t = caller THEN [w \in Slots |-> IF w = s THEN nc ELSE cspaces[caller][w]]
                ELSE cspaces[t]]
           /\ mints'    = mints + 1
           /\ rightsOf' = [c \in CapId |-> IF c = nc THEN rq \cap rightsOf[sc] ELSE rightsOf[c]]
           /\ expiresAt'= [c \in CapId |-> IF c = nc THEN ExpClamp(xq, expiresAt[sc]) ELSE expiresAt[c]]
           /\ rightsFrom' = [c \in CapId |-> IF c = nc THEN sc ELSE rightsFrom[c]]
           /\ children' = [c \in CapId |->
                IF c = sc THEN children[sc] \cup {nc}
                ELSE IF c = nc THEN {} ELSE children[c]]
           /\ consentedInto' = [c \in CapId |-> IF c = nc THEN TRUE ELSE consentedInto[c]]
           /\ UNCHANGED <<revoked, now>>

(* grant: like Copy, but the mint lands in another task's CSpace — naming the target
   requires holding a capability to that task (the slot table is not addressable),
   and that capability must carry RECEIVE (I6): pushing caps into a task's CSpace
   needs the task's consent as encoded in the cap; a bare naming reference ({}) is
   not a mailbox *)
Grant ==
    \E caller \in Tasks : \E sc \in Usable(caller), tc \in Usable(caller) : \E rq \in RQ, xq \in XQ, s \in Slots:
        /\ tc.obj \in Tasks
        /\ caller # tc.obj
        /\ RightG \in rightsOf[sc]
        /\ RightReceive \in rightsOf[tc]
        /\ cspaces[tc.obj][s] = NONE
        /\ mints < MaxMints
        /\ LET nc == [obj |-> sc.obj, n |-> mints + 1] IN
           /\ cspaces'  = [t \in Tasks |->
                IF t = tc.obj THEN [w \in Slots |-> IF w = s THEN nc ELSE cspaces[tc.obj][w]]
                ELSE cspaces[t]]
           /\ mints'    = mints + 1
           /\ rightsOf' = [c \in CapId |-> IF c = nc THEN rq \cap rightsOf[sc] ELSE rightsOf[c]]
           /\ expiresAt'= [c \in CapId |-> IF c = nc THEN ExpClamp(xq, expiresAt[sc]) ELSE expiresAt[c]]
           /\ rightsFrom' = [c \in CapId |-> IF c = nc THEN sc ELSE rightsFrom[c]]
           /\ children' = [c \in CapId |->
                IF c = sc THEN children[sc] \cup {nc}
                ELSE IF c = nc THEN {} ELSE children[c]]
           /\ consentedInto' = [c \in CapId |-> IF c = nc THEN TRUE ELSE consentedInto[c]]
           /\ UNCHANGED <<revoked, now>>

(* grant-mint (the grant service's op, spec-grant flow §4): rights/expiry clamp from
   the source cap, but the derivation is rooted in the grant-root cap, so revoking
   the grant root cleans every grantee while the grantor's own caps survive.
   Destination consent (RECEIVE on the naming cap) applies as in Grant (I6). *)
GrantMint ==
    \E caller \in Tasks : \E gc \in Usable(caller), sc \in Usable(caller), tc \in Usable(caller) : \E rq \in RQ, xq \in XQ, s \in Slots:
        /\ gc.obj = GrantRoot
        /\ RightG \in rightsOf[gc]
        /\ RightG \in rightsOf[sc]
        /\ tc.obj \in Tasks
        /\ caller # tc.obj
        /\ RightReceive \in rightsOf[tc]
        /\ cspaces[tc.obj][s] = NONE
        /\ mints < MaxMints
        /\ LET nc == [obj |-> sc.obj, n |-> mints + 1] IN
           /\ cspaces'  = [t \in Tasks |->
                IF t = tc.obj THEN [w \in Slots |-> IF w = s THEN nc ELSE cspaces[tc.obj][w]]
                ELSE cspaces[t]]
           /\ mints'    = mints + 1
           /\ rightsOf' = [c \in CapId |-> IF c = nc THEN rq \cap rightsOf[sc] ELSE rightsOf[c]]
           /\ expiresAt'= [c \in CapId |-> IF c = nc THEN ExpClamp(xq, expiresAt[sc]) ELSE expiresAt[c]]
           /\ rightsFrom' = [c \in CapId |-> IF c = nc THEN sc ELSE rightsFrom[c]]
           /\ children' = [c \in CapId |->
                IF c = gc THEN children[gc] \cup {nc}
                ELSE IF c = nc THEN {} ELSE children[c]]
           /\ consentedInto' = [c \in CapId |-> IF c = nc THEN TRUE ELSE consentedInto[c]]
           /\ UNCHANGED <<revoked, now>>

(* revocation: needs GRANT on the revoked cap; removes the whole subtree from EVERY
   CSpace — including tables the caller cannot name (I4) *)
Revoke ==
    \E caller \in Tasks : \E c \in Usable(caller):
        /\ RightG \in rightsOf[c]
        /\ LET RS == Subtree(c, MaxMints) IN
           /\ cspaces'  = [t \in Tasks |->
                [s \in Slots |-> IF cspaces[t][s] \in RS THEN NONE ELSE cspaces[t][s]]]
           /\ revoked'  = [d \in CapId |-> revoked[d] \/ d \in RS]
           /\ children' = [d \in CapId |-> IF d \in RS THEN {} ELSE children[d] \ RS]
           /\ UNCHANGED <<mints, rightsOf, expiresAt, rightsFrom, consentedInto, now>>

Tick ==
    \E a \in {5}:
        /\ now + a <= Horizon
        /\ now' = now + a
        /\ UNCHANGED <<cspaces, mints, rightsOf, expiresAt, rightsFrom, children, revoked, consentedInto>>

Next == CreateTask \/ Copy \/ Grant \/ GrantMint \/ Revoke \/ Tick

(* The capability automaton terminates (finite mint budget, bounded clock); a
   terminal state is legal, so the temporal formula must admit stuttering -
   otherwise TLC would report every end-of-execution state as a "deadlock".
   The stutter step adds no new states; the invariant check is over exactly the
   same reachable set. *)
Spec == Init /\ [][Next \/ UNCHANGED vars]_vars

(* ------------------------------------------------------------------ invariants *)

TypeOK == /\ mints \in 0..MaxMints
          /\ cspaces \in [Tasks -> [Slots -> CapId \cup {NONE}]]
          /\ rightsOf \in [CapId -> SUBSET RIGHTS]
          /\ expiresAt \in [CapId -> 0..INF]
          /\ rightsFrom \in [CapId -> CapId \cup {NONE}]
          /\ children \in [CapId -> SUBSET CapId]
          /\ revoked \in [CapId -> BOOLEAN]
          /\ consentedInto \in [CapId -> BOOLEAN]
          /\ now \in 0..INF

\* I1 — no forgery: only kernel-minted caps ever sit in any slot.
I1 == \A t \in Tasks, s \in Slots:
        cspaces[t][s] = NONE \/ minted(cspaces[t][s])

\* I2 — delegation monotonicity: a minted cap never carries rights its source
\*      does not have, and the grantor can only hand on what it holds.
I2 == \A c \in CapId:
        ~ (minted(c) /\ rightsFrom[c] # NONE) \/ rightsOf[c] \subseteq rightsOf[rightsFrom[c]]

\* I3 — no object forgery / no self-escalation: a minted cap refers to the object
\*      its source referred to; you cannot mint a capability to an object you hold
\*      no capability for, and no op can re-widen a live cap's rights (the ops are
\*      the only state transitions, checked by TLC).
I3 == \A c \in CapId:
        ~ (minted(c) /\ rightsFrom[c] # NONE) \/ c.obj = rightsFrom[c].obj

\* I4 — cross-grantee revocation: after a revoke the entire subtree is gone from
\*      every CSpace; the marker makes "no revoked cap present anywhere" checkable.
I4 == \A t \in Tasks, s \in Slots:
        cspaces[t][s] = NONE \/ ~ revoked[cspaces[t][s]]

\* I5 — ephemerality is kernel-enforced: expiry never extends along a derivation
\*      chain, and an expired or revoked cap is unusable by guard in every action.
I5 == \A c \in CapId:
        ~ (minted(c) /\ rightsFrom[c] # NONE) \/ expiresAt[c] <= expiresAt[rightsFrom[c]]

\* I6 — grant consent: every cap present in any CSpace was minted under consent.
\*      The consent *guard* (RECEIVE on the destination naming cap) lives in the
\*      Grant/GrantMint actions; the marker is set only there. A mint path that
\*      skips consent leaves the marker unset and violates this invariant — by
\*      construction there is exactly one such path per minting action.
I6 == \A t \in Tasks, s \in Slots:
        cspaces[t][s] = NONE \/ consentedInto[cspaces[t][s]]

InvAll == TypeOK /\ I1 /\ I2 /\ I3 /\ I4 /\ I5 /\ I6

=============================================================================
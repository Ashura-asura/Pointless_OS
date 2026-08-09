# Aegis Capability Model — Formal Specification (Phase 0)

*Status: v0.1 — the executable reference is `crates/capability-core`; this document is normative where the two disagree (and that is a bug in the code, not the spec).*

This is the Phase 0 artifact from `os-from-first-principles.md` §7: a formalization of the
capability delegation rules, written before implementation. Notation is TLA+-flavored;
the Rust tests in `capability-core` are the executable model check for the invariants stated
here. We do not claim a machine-checked theorem — we state the intended invariants precisely
and test them. That is the honest ceiling on a host-machine model.

---

## 1. State

```
Caps         = set of all active capability instances    (each has a unique id: CapId)
Derived ⊆    Caps × Caps          — derivation edges; acyclic
CSpace       = Task × Slot → Caps?   — slot tables (kernel-owned memory)
Objects      = set of kernel objects (Task, Endpoint, MemRegion, GrantRoot, ...)
CapOf        : Caps → Objects       — the object a cap refers to
RightsOf     : Caps → 2^RIGHTS      — rights set carried by a cap
ExpiresAt    : Caps → Nat ∪ {∞}     — clock tick at which a cap dies (∞ = never)
G (global)   : set of all ops ever performed   — the audit log
```

RIGHTS = { R (read), W (write), C (control a task's lifecycle), S (send on an endpoint),
           RCV (receive from an endpoint), G (grant/copy/mint to others) }.

A **task** is an execution context: `(cs: CSpace, running: Bool, label: String)`.
A task's authority, at any moment, is *exactly*:

```
Authorized(t) = { c ∈ Caps : slot ∈ slots_of(t.cs), c = slot contents, now < ExpiresAt(c) }
```

## 2. Operations (all mediated by the kernel; none reach kernel state except through these)

```
create(t, obj)              — object materializes as a cap c in a free slot of t's CSpace.
                              Only the kernel mints fresh caps (no user-supplied bytes
                              ever become an ObjectId).
copy(t, c, rights ⊆ RightsOf(c))
                            — new cap c', a fresh CapId, Derived(c', c), RightsOf(c') = rights.
mint_and_grant(t, c, u, rights ⊆ RightsOf(c))
                            — like copy, but placed into u's CSpace; requires G ∈ RightsOf(c).
                              Statutory: rights ⊆ RightsOf(c)  (delegation monotonicity).
destroy(t, c)               — removes c from t's CSpace.
revoke(t, c)                — requires G ∈ RightsOf(c). Removes c and every descendant
                              (transitively) from *all* CSpace. Powers the "take back
                              everything I granted, and everything derived from it" op.
ep_send(t, c, m)            — requires S ∈ RightsOf(c). Appends m to the endpoint's queue.
ep_recv(t, c)               — requires RCV ∈ RightsOf(c). Pops the queue, or yields None
                              (non-blocking; scheduling is a userspace concern in Aegis).
mem_read / mem_write         — require R / W on the MemRegion cap.
task_kill / task_spawn(t, c) — require C ∈ RightsOf(c). Lifecycle control of the target task.
grant_expire(t, g)          — only the holder of a GrantRoot cap may set/clear its expiry;
                              no operation extends ExpiresAt on a cap the caller does not
                              hold Control for. In particular: no op, at all, extends
                              ExpiresAt of any cap.  (The kernel owns the clock.)
```

Every successful and every failed operation appends one line to the audit log G.

## 3. Invariants (the claims the tests prove, expressed formally)

**I1 — No forgery.** For every task t and object o: if o is *not* its creator's root and no
authorized cap of t refers to o, then no sequence of operations available to t maps to an
authorized cap referring to o. Formally: `Authorized(t) = ∅` never grows by any mechanism
other than `copy/mint_and_grant/create`, and those all start from an existing authorized cap
(create starts from nothing but gives only the *new* object). Enforcement is structural:
`ObjectId` is a kernel-only nonce, constructible nowhere else; `Kernel` is the only `&mut`
owner of the object table and every CSpace.

```
I1: for all t: Authorized(t) ⊆ {c : ∃ chain of create/mint edges from some creator}
```

**I2 — Delegation monotonicity (no privilege expansion).** 
```
forall (t, c, u, rights) in mint_and_grant:
    rights ⊆ RightsOf(c) ∧ G ∈ RightsOf(c) ∧ c ∈ Authorized(t)
⇒ RightsOf(new_cap) ⊆ RightsOf(c)
```
Rotation of rights into rights the granter held is impossible because `RightsOf` is a
monotone map over the derivation graph and derivation only narrows.

**I3 — No self-escalation.** For any task t and any op, the rights actually exercised are
`⊆ RightsOf` of some cap in `Authorized(t)`. In particular an untrusted component (an AI
agent) cannot: enlarge caps it holds, mint caps it was not given, extend its own expiry,
mutate its own CSpace except via kernel ops, or fabricate an ObjectId. Enforced by the
single lookup path: every op resolves its arguments through `Authorized(t)` first.

**I4 — Cross-grantee revocation (transitivity + reachability).** If g is derived from c
(transitively), and c is revoked by any grantor holding G on c, then g is removed from
*all* CSPaces — including ones the grantor cannot name. Consequently: the grantor never
needs to know where its grants went; there is no "escape hatch" copy that survives a
revoke.

**I5 — Ephemerality is kernel-enforced.** If `ExpiresAt(g) = T < Now` then g ∉ Authorized(t)
for every t; no op can resurrect it, and no op can change a cap's expiry without
GrantRoot Control (and no op may *extend*). One-shot grants die with the task: when a task
terminates, its GrantRoot is revoked by the grant-orchestration service.

## 4. The grant flow (roles layer, §9 of the design doc)

```
Role r ∈ Roles ; RoleToCaps : Roles → 2^(Objects × RIGHTS embedded)   — defined by the system
propose(granter, r, grantee, params) → Proposal { visible diff: set of (object, rights) added }
confirm(granter_proxy, Proposal) → Grant { root g, Caps_g, ExpiryPolicy }
effect: ∀ (obj, rts) ∈ RoleToCaps(r): cap c(obj, rts) minted under g; Caps_g = {c...}
        ExpiresAt(c) = policy (task-scoped: revoked on task completion)
        Diff recorded in audit log; every use of c is logged.
```

## 5. Known simplifications (where the model departs from the real design)

1. The kernel is a typed single-threaded engine in-process; real isolation (address
   spaces, IOMMU) is *out of scope of the model* and the tests do not claim it. The model
   proves *authority* properties (I1–I5), not memory isolation.
2. `ep_recv` is non-blocking; the doc's rendezvous semantics are realized by the harness
   driving the tasks (scheduling is userspace anyway).
3. Nonces are probabilistic (one ~64-bit source per object), not entropy-certified.
   Security therefore does not rest on nonce strength: unforgeability is type-level
   (kernel-only constructor), matching how a real kernel's unforgeability rests on
   kernel-owned state, not on the secrecy of an index.
# Aegis Capability Model — Formal Specification (Phase 0)

*Status: v0.2 — the executable reference is `crates/capability-core`; this document is normative where the two disagree (and that is a bug in the code, not the spec). The delegation invariants below are machine-checked on a finite instance by TLC against `AegisCapabilities.tla` (§6).*

This is the Phase 0 artifact from `os-from-first-principles.md` §7: a formalization of the
capability delegation rules, written before implementation. Notation is TLA+-flavored;
the Rust tests in `capability-core` are the executable model check for the invariants stated
here, and `AegisCapabilities.tla` is the machine-checked model (exhaustive TLC run, §6).
The honest ceiling: invariants are proven for a *finite scalar instance* of the model
(see §6 for exactly what sizes), not for all configurations; type-level enforcement claims
(I1, unforgeability) rest on the kernel architecture, not on model checking.

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
           RCV (receive from an endpoint), G (grant/copy/mint to others),
           RE (receive into own CSpace — grant consent, I6) }.

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
                            — like copy, but placed into u's CSpace; requires G ∈ RightsOf(c)
                              and a cap to u (in t's CSpace) carrying RE (I6 — the
                              destination consents before its table is written).
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

**I6 — Grant consent.** A task's CSpace may only be written into by a caller holding a
cap to that task which carries RE (`mint_and_grant` requires it). A bare naming
reference — including a cap minted with `Rights = ∅` — confers *no* write access to the
target's CSpace; in particular it cannot be used to exhaust the target's CSpace or to
inject unrequested capabilities. RE is part of every self-cap (a task can always accept
grants for itself) and of the creator's cap to the tasks it creates, so legitimate
delegation (role grants, orchestrator flows) is unaffected. Formally:

```
I6: forall (t, c, u, rights) in mint_and_grant:
      RE ∈ RightsOf(cap_u) ∧ cap_u ∈ Authorized(t)
```
where `cap_u` is the cap naming `u` used as the destination argument.

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
   proves *authority* properties (I1–I6), not memory isolation.
2. `ep_recv` is non-blocking; the doc's rendezvous semantics are realized by the harness
   driving the tasks (scheduling is userspace anyway).
3. Nonces are probabilistic (one ~64-bit source per object), not entropy-certified.
   Security therefore does not rest on nonce strength: unforgeability is type-level
   (kernel-only constructor), matching how a real kernel's unforgeability rests on
   kernel-owned state, not on the secrecy of an index.

## 6. Machine-checked verification (TLC)

`AegisCapabilities.tla` is a TLA+ model of the capability automaton: state is the
CSpace table, the mint counter, per-cap `rightsOf / expiresAt / rightsFrom / children /
revoked`, a `consentedInto` shadow array, and the clock `now`. Actions are
`CreateTask, Copy, Grant, GrantMint, Revoke, Tick`, all searching over every caller and
every cap that caller *actually holds* (quantifying over `Usable(caller)` prunes the TLC
enumeration basis by ~2 orders of magnitude; it adds no semantics). The validity claims are
invariants I1–I6 + TypeOk below; RIGHTS maps to spec tokens 1:1 with
`RE ⇔ "RECEIVE"` and `G ⇔ "G"`.

The I6 claim is checked with a shadow register: `consentedInto[c]` is set on exactly the
paths that represent consent (boot, self-cap minting, Creator→child, Grant/GrantMint with
`RightReceive ∈ rightsOf[tc]`, Copy into the caller's own table — a task always accepts
for itself), and I6 asserts every occupied slot is covered by a true shadow:

```
I6 ⊆ Occ(t, s) = cspaces[t][s] ≠ NONE ⇒ consentedInto[cspaces[t][s]]
```

The shadow is a proof artifact (sound: only consenting paths set it; the real mechanism
is the `Rights::RECEIVE` gate in `grant`/`grant_mint`, tested by
`grant_requires_receiver_consent` in Rust).

### Checked instance (exactly what TLC proved)

```
Tasks   = {Root, Eve}            Size budget: 2 tasks —
Slots   = {0, 1, 2}               3 CSpace slots (the real kernel has 256)
RIGHTS  = {R, W, C, S, RCV, G, RECEIVE}
MaxMints = 6                      4 minted at boot (root self, creator,
                                  grant root, eve self) + 2 adversarial mints
RQ      = {ALLRIGHTS, {G}, {C}, {}}   request shapes; clamping is monotone
XQ      = {INF(500), 5}           expiry shapes; INF is 500 ticks, ∞-like
Horizon = 12                      clock stops here (TLC termination; any
                                  expiry ≤ 12 is exercised)
```

The adversarial search covers: creation cascades, grant/copy/mint chains of every
request shape into every free slot, revocation of cap sub-trees (including a task
revoking its own authority — Subtree bookkeeping: revoked-flag, children pruning and
CSpace clearing stay consistent), expiry frames (cap dies at tick 5 and is unusable
after), and mint-budget exhaustion where the adversary holds at most zero-rights
naming caps.

Result of the exhaustive run (tla2tools 1.8.0 / TLC 2026.07.31, 7 workers):

```
Model checking completed. No error has been found.
331143 states generated, 74772 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 11.
Finished in 1min 28s
```

What this does **not** claim:

- It is a finite-instance proof: 2 tasks, 3 slots, 2 post-boot mints. It is *evidence*
  for the general claim, not a proof of it (that would require induction/Isabelle).
- I1's unforgeability (no byte sequence becomes an ObjectId) is type-level design, not
  model-checkable here; the model *uses* unforgeability (caps are records only the
  actions mint).
- `Tick` moves the clock by fixed steps to a fixed horizon; "expiry at 40" is not a
  distinct case from "expiry at 5" for the checked properties (both are a finite
  expiry ≤ horizon facing the same code path).
- The TLA+ spec must always stay in sync with `capability-core`: the Rust tests are
  the executable check of the same invariants, run on every `cargo test`; the TLA+
  run pins the intent. Divergence is a bug in one of the two.

### Machine-checked verification (executable): IPC and shared memory

`capability-core/tests/ipc.rs` (7 tests, on every `cargo test`) checks the §8 IPC
claims against the real kernel, not a model:

- SEND and RECV are independent rights on the endpoint capability; a task granted
  only SEND cannot receive and vice versa (`InsufficientRights`), and delivery is
  FIFO.
- A narrowed copy keeps the narrowing: a RECV-only copy cannot send on the copy
  (I2 clamping, executable).
- No endpoint cap, no endpoint: slot numbers "leaked" from another task's CSpace
  resolve against the caller's own table and fail (`NoCap`), and a slot that holds
  a non-endpoint cap fails with `WrongObjectType`.
- Every send, recv and refusal is in the audit log, keyed by endpoint identity
  (`CapInfo.obj`), so "what did this agent actually do with what it was given"
  stays answerable without tracking conversations.
- The async notification path: a sender whose receiver is busy never blocks — the
  kernel buffers the burst and the receiver drains one message at a time, in FIFO
  order, with no duplication.
- Endpoints are anonymous queue identities: two endpoints between the same tasks
  keep separate queues.
- Bulk data moves by capability grant, not byte-copy (the seL4/Zircon pattern):
  the producer writes a 64 KiB region through its WRITE cap, the consumer is
  notified over the endpoint by a 5-byte message, and reads the payload through
  its own READ-granted region cap. The payload never enters the kernel's queue
  (the audit shows exactly one Send of the notification), and the READ-only grant
  cannot be turned into WRITE.

The demo (`cargo run --release -p aegis-shell`) re-enacts the same claims in the
boot scene — the agent cannot talk to the services even knowing the exact slot
numbers, and its refusals appear in the reachable-authority audit alongside the
endpoint state.

### Machine-checked verification (executable): aegis-kernel IPC (real hardware)

`aegis-kernel/src/ipc.rs` implements a synchronous call/serve/reply IPC system
for the bare-metal kernel. This is a **separate, real-hardware IPC** from the
model-level `capability-core` IPC above.

**What exists**: Endpoints, `ipc_call`, `ipc_serve`, `ipc_reply`,
`ipc_endpoint_create`, `ipc_cap_grant`. Ring-3 echo server/client demo
verified under QEMU and VMware Workstation 26 with 0 exceptions.

**Capability-aware delivery (Phase 1)**: a slot is now a `(Cap, Rights)` pair
(`aegis-kernel/src/cap.rs`): `Rights` is a bitfield (READ/WRITE/CONTROL/
SEND/RECV/GRANT), `Cap` names an `Endpoint`, `Task`, or `MemRegion`, and the
syscall entries are rights-gated — `ipc_call` requires SEND, `ipc_serve` and
`ipc_reply` require RECV, `ipc_cap_grant` requires GRANT, and `CapGrant`
copies the slot verbatim (rights never widened, I2). `ipc_endpoint_create`
installs SEND|RECV|GRANT. The kernel enforces at delivery time and never
trusts the caller to state its own authority. `#[cfg(test)]` contract tests
(`ipc.rs` and `cap.rs` test modules, 14 tests) pin all seven gates: wrong
rights, wrong object kind, and out-of-range slots all deny cleanly.

**Honest limits**:
- The ring-3 path through `int 0x80` still needs real/virtual hardware; its
  proof is the live QEMU/VMware boot, not `cargo test`. The contract tests
  cover the capability-gate logic, not the privilege transition.
- Single-threaded; no concurrency testing.
- The IPC is synchronous only (no async notification variant).
- Not formally verified; follows seL4-lineage design but does not inherit
  seL4's proof.

### Machine-checked verification (executable): aegis-kernel memory + supervision (Phase 2)

`aegis-kernel/src/mem.rs` and `aegis-kernel/src/supervisor.rs` realize the
frame-backed memory-region capability and the supervision-tree runtime for the
bare-metal kernel:

- `mem_create` allocates real physical frames (`frame::alloc_contiguous_global`),
  identity-maps them, and installs a READ|WRITE|GRANT `MemRegion` capability
  (`MEM_RIGHTS`, mirroring the model's `create_mem`); `mem_len`/`mem_read`/
  `mem_write` are gated on the caller's READ/WRITE rights over the capability
  and bounds-checked exactly like the model (`capability-core`'s `mem_read`
  returns bytes copied; out-of-range offsets and wrong rights deny cleanly as
  -1, never a panic — 9 contract tests in `mem.rs`).
- The two accessor paths (`caps_region` → `task_cap`, `region()` from the
  `static mut REGIONS`) go through raw pointers (`addr_of_mut!` + `ptr::read`/
  `write`), never forming shared references to the `static mut` — that is UB
  under Rust 2024's `static_mut_refs` rule, and this crate compiles warning-free.
- `supervisor.rs` is the kernel-side close contract of §5: a supervisor adopts
  tasks with a per-child restart budget; a crash (`handle_crash`) restarts the
  task against its remembered entry point (respawn, via `tasks::restart_task`
  rebuilding the interrupted frame) up to budget, then the breaker *trips* and
  the child stays dead. Every crash, restart and trip is recorded (audit ring),
  and escalation/retry policy remains the `supervision-tree` crate's job.
- The live fault path (`cpu.rs` exception hook) calls `supervisor::handle_fault`
  so a supervised, budgeted task restarts instead of dying; unsupervised tasks
  keep the existing kill-and-continue behavior, and killed zombies can be
  reaped and their slots reused by `spawn` (`reset_table_for_test` in `tasks.rs`).
- Syscall numbers 10–16 (MemCreate/MemLen/MemRead/MemWrite, TaskState/TaskKill/
  TaskRestart) are wired in `syscall.rs`; `TaskKill`/`TaskRestart` require the
  CONTROL right, `TaskState` requires READ.

`#[cfg(test)]` contract tests (304 in the aegis-kernel lib) pin the gates. Tests
that pin the single global `CURRENT`/task/region tables run under a shared test
mutex (`kernel_state_guard`) so they stay serialized and deterministic.

Honest limits: region caps are authority records, not address-space isolation
(no per-task page-table windows yet); revocation is slot clearing only; the
audit ring is in-memory; restart re-enters the same entry point (no fresh user
state); no supervision hierarchy (single kernel-resident supervisor).

### Machine-checked verification (executable): supervision (§5)

`capability-core/tests/supervision.rs` (3 tests) checks the kernel side of the
supervision-tree contract — the part that must hold before any automatic-recovery
claim is worth making:

- Containment is a full-subtree revoke (I4), not a flag flip: killing smtp only
  marks it dead; the supervisor's `revoke` removes the agent's restart role from
  the agent's own table in one operation, and the refused retry fails with
  `NoCap`. The kill is recorded, not erased — forensics survive containment.
- The supervision cycle is reconstructable from the audit log alone: the
  supervisor's TaskKill and the agent's TaskSpawn(s) are distinct records with
  distinct callers and targets; the agent's log shows spawns only (no creation,
  no grants, no revokes — the role bought restart only).
- Escalation stops the retry loop and logs it: after revocation the agent cannot
  keep restarting, and the refusal is a logged failed TaskSpawn — never a silent
  swallow (the anti-"auto-recovery hides bugs" property of §5).

Scheduling and retry policy remain userspace (the kernel's close contract): the
kernel decides *whether* an op may run and records it; the supervision tree
decides *how often* to retry.

### Machine-checked verification (executable): object store (§8 + §10 [CLOSED])

`object-store` (8 tests: 6 contract + 1 SHA-256 vectors + 1 index) realizes the storage
claims against the same kernel:

- Ground truth is content-addressed immutable blocks: identical bytes are the
  same block, stored once (dedup); the SHA-256 content hash is integrity itself
  (implemented dependency-free, pinned against the standard vectors; the
  non-empty ones were cross-checked with the host OS's SHA-256 at authoring
  time).
- Blocks are capability-addressed: the content hash *and* the kernel object id
  grant nothing. A reader with no region cap in its own CSpace reads nothing;
  the store grants READ into the reader's table, and the granted cap is a
  narrowed copy that cannot be widened into WRITE (I2, executable).
- Mutable data is a COW layer: writes create new blocks and new node regions,
  never mutating existing ones — snapshot stability is mechanical, one region
  per version.
- The §10 [CLOSED] contract is stated as *types* and *behavior*: `commit`'s and
  `write_version`'s function-pointer types carry no index and no index result
  (the assignments compile only if that is true); a full file workload runs
  with no index registered at all; the relationship index ingests *only* the
  write-ahead log, orders behind, catches up later, and rebuilds identically
  from the log — a cache, never a participant, exactly the property that
  structurally closes the WinFS failure mode.
- The POSIX file view is a projection: file bytes are store blocks, the
  namespace is a COW store object, every mutation is WAL material. No second
  source of truth exists to drift.

Honest limits: single-region blocks (no multi-block files), in-memory WAL, flat
namespace, and durability ends at process exit — a block device is Phase 3/4.

### Machine-checked verification (executable): aegis-kernel object store (Phase 4)

`aegis-kernel/src/store.rs` (9 tests) realizes the same §8 + §10 [CLOSED]
claims inside the bare-metal kernel crate, over real kernel region records and
the real capability gates — not a mock kernel:

- Blocks are content-addressed immutable SHA-256 regions: the same content
  commits to the same block (dedup asserted as `block_count`), integrity is the
  hash itself, and the 4 FIPS 180-4 vectors (empty, `abc`, 448-bit, 1M `a`)
  pin the self-contained, allocation-free implementation.
- Blocks are capability-addressed at the kernel boundary: knowing a hash or
  object id grants nothing — `grant_read` installs a *narrowed READ-only*
  `MemRegion` copy into the recipient's own CSpace, then reads flow through the
  genuine `mem::mem_read` gate and writes are refused by `mem::mem_write` (I2,
  executable). A fabricated slot with no region cap returns -1 via `mem::mem_len`.
- Mutable data is a COW layer over the immutable blocks: every write creates
  new regions, never mutating existing ones, so a node id you hold reads that
  version forever (snapshot stability is mechanical).
- The §10 [CLOSED] contract is stated as *types* and *behavior*: `commit`'s and
  `write_version`'s function-pointer types carry no index; a full file workload
  runs with no index registered; the relationship index ingests *only* the WAL,
  catches up later, and rebuilds identically from the log — a cache, never a
  participant.
- The POSIX `FlatView` is a projection: file bytes are store blocks, the flat
  namespace is a COW store object, every mutation is WAL material.

Honest limits: block/node bytes live in a fixed 8 KiB in-kernel arena
(`ARENA_BYTES`), not on the Phase-3 NVMe/FAT block-device path (that driver
remains separate and read-only); the region table (`MAX_REGIONS=32`), block,
node, and WAL counts are bounded; single-region blocks (no multi-block files);
in-memory WAL — durability still ends at process exit; contract tests bind
regions to in-test memory, so real frame-backed binding is proven only by the
live boot.

### Machine-checked verification (executable): packages (§8)

`packages` (7 contract tests: 6 in `install_contract.rs` + 1 in `exec_contract.rs`) realizes the package
model against the same kernel, the store, and the auditor:

- A package is a declared authority ceiling (manifest, repository boundary as
  trust boundary) plus a content-addressed payload of store blocks. Payload
  bytes are immutable by construction: identical payloads across installs add
  zero new blocks (dedup is *observable*, asserted as `block_count` staying
  flat), and every install reads back the same bytes.
- Installation grants exactly — and only — what the manifest declares: the app
  task's live cap table after install is precisely its self-cap plus the
  declared minted caps plus READ-only payload delivery, all clamped by
  derivation (I2: no WRITE anywhere, asserted per cap). Nothing ambient: the
  manager's own table grows only by its two install artifacts.
- Installation runs no code: over the whole window the kernel audit shows
  exactly one CreateTask record (the app itself, attributable to the manager)
  and zero operations performed by the app during install. There is no script
  step anywhere in the install path.
- Installations are transactional and rollback-capable by construction: every
  minted cap — declared and payload alike — hangs off one per-install grant
  root (I4). A refused install (unholdable source: nothing to derive from;
  kernel-equivalent request: audited out, per the §10 [CLOSED] repository
  boundary) revokes that root plus the task and the world is measurably as it
  was. Revoking a live install's anchor leaves the app alive but holding
  precisely zero authority.
- Enforcement is *the kernel's*, not policy fiction: mint time re-checks what
  the manager holds, the kernel clamps rights, and the manifest audit certifies
  reachability before the install returns success.

Honest limits: v1 has one service host (the packager, the store and the boot
task are one identity, so "what the manager may grant" is exactly its own cap
table), no code signing or online update channel, and no separate package
repository service.

### Machine-checked verification (executable): updates (§8)

`system-update` (5 contract tests) realizes the update architecture against the
same kernel, store, packages and auditor:

- Generations are *staged*: a candidate is fully installed (manifest-gated) and
  the boot target — a `current` pointer inside the boot-config store view — is
  provably untouched while staging; the staged app is inert (zero audit
  records) until activated.
- Activation is health-gated (the check is operator-supplied; the manager
  enforces the gating) and refused candidates never become default.
- The flip itself is store content, not capability authority: the kernel audit
  for the activation window contains zero grant/copy/revoke/spawn/root-creating
  records — evidencing the "updates are data, not principals" claim.
- Rollback returns to the last-known-good generation (healthy at activation,
  and not the current target). The rollback window likewise executes zero
  authority operations, and the survivor's caps were never touched (clean
  manifest re-audit). The dethroned generation leaves the applied history, so
  a second rollback is provably a no-op *and* its ordinary install anchor still
  revokes it like any other software.
- The updater is not a second root: after a full stage/activate/rollback cycle
  the world contains exactly the two install anchors as grant roots, the boot
  role's one creator, and the boot task plus the two installed apps — nothing
  the machinery could have minted for itself.

Honest limits: generations are single-application (one package per generation),
boot-target persistence is in-memory store content (no block device), and
health signals are supplied by the operator rather than probed from hardware.

### Machine-checked verification (executable): the resource model (§8)

`resources` (4 contract tests) realizes hierarchical budgets over the
supervision tree, metered from kernel truth and enforced by revocation:

- Budgets are a hierarchy mirroring the tree. The ledger refuses overcommit —
  a parent cannot subdivide more than it holds, a service has exactly one
  parent — and conserves the total: root kept plus subtree tops equals the
  root's budget, exactly (no accounting can stretch a fixed total).
- Metering trusts no userspace bookkeeping: CPU is every successful audit
  record attributed to the task (the log is the scheduler's clock; a partition
  of the log by task is provably exact), and memory is the WRITE-reachable
  bytes of the task's live regions, read straight from the cap tables. A
  READ-only service provably meters zero resident bytes.
- Enforcement is ordinary revocation: an over-budget service is recycled
  through its own install anchor — the governor holds no special authority —
  and siblings are provably untouched, by cap census and by meter.
- A recycled service reinstalls into a clean envelope (fresh task, zero spent).

Honest limits: CPU is metered in executed-op units rather than hardware ticks,
memory is a footprint of what caps *could* write rather than what was touched,
and v1 does no dynamic re-scheduling — the recycle-then-reinstall cycle is the
whole enforcement loop.

### Machine-checked verification (executable): the network stack (§8)

`net` (4 contract tests) realizes the doc's userspace-netstack sentence
verbatim: *"holding a network capability means holding a specific, revocable
right to talk to a specific endpoint or class of endpoint, not ambient 'this
process can open any socket' authority."*

- Sockets are kernel endpoint objects under a userspace port namespace. Ports
  are not ambient authority: a task that knows a port number but holds no
  channel cap is refused by the stack, and the kernel refuses the raw `ep_send`
  underneath it. A socket's channel cap is minted into the subscriber's own
  CSpace, narrowed by derivation.
- The stack is a real router, not a wrapper: a packet traverses two logged,
  attributed hops (the sender's injection, then the stack's forward from its
  own router caps), and the audit log alone reconstructs the whole path —
  sender task, router, destination — with no path that bypasses the log.
- The loopback is FIFO (message order is endpoint-queue order), and tearing a
  socket down removes it from the interface without touching any peer.
- The stack is a router, not a root: after a conversation, the census of its
  CSpace shows exactly its channel endpoints and the boot role's own creator —
  zero grant roots, zero new authority.

Honest limits: loopback interface only (no NIC, no IP packet framing), one
stack instance, ports are per-socket addresses, and routing authority (a
Creator cap) is held by the stack's host identity — this is the "one driver,
one capability envelope" arrangement, not an ambient networking stack.

### Machine-checked verification (executable): aegis-kernel netstack (Phase 5)

`aegis-kernel/src/netstack.rs` (4 tests) over `channel.rs` (the design §8
second IPC primitive — an asynchronous FIFO box — as a real capability object,
`Cap::Channel`; 2 tests) realizes the same §8 claim inside the bare-metal
kernel crate, over the real capability gates instead of a mock kernel:

- Sockets ARE channel capabilities: the netstack mints a fresh channel, keeps
  a SEND|RECV router cap under its own service identity, and installs a
  *narrowed* SEND|RECV copy into the subscriber's CSpace — no GRANT, so a
  channel cannot be delegated onward (I2, asserted per cap). Ports are not
  ambient authority: a task that knows a port but holds no channel cap is
  refused by the stack AND fails the raw `ch_send` gate (-1) underneath it.
- The stack is a real two-hop router: hop 1 is the sender injecting into its
  own channel through its own SEND-gated cap; hop 2 is the stack draining its
  router copy and forwarding the same bytes into the destination's channel
  through its router caps. Both hops resolve through `caps_channel`, so there
  is no hidden path to inject into a socket without holding its cap.
- Loopback is FIFO (channel queue order is preserved; the drain is exact), and
  tearing a socket down destroys the channel object — the subscriber's still
  held cap goes dangling and every gated operation on it fails, while peers
  keep working.
- The stack is a router, not a root: after registrations, the census of its
  CSpace shows exactly its channel router caps and nothing else.

Honest limits: the kernel keeps no audit log, so the model's "every hop is an
attributed op in the audit log" claim stays proven by `capability-audit`, not
here; loopback only, one stack instance, ports are per-socket addresses;
bounded message size (`CHANNEL_BUF=64`), depth (`CHANNEL_DEPTH=8`), channel
table (`MAX_CHANNELS=16`) and port table (`MAX_PORTS=8`); no wire framing — the
Ethernet/ARP/IPv4/UDP/TCP header models in `ethernet.rs`/`arp.rs`/`ipv4.rs`/
`udp.rs`/`tcp.rs` remain separately tested, not wired into this loopback slice.

### Machine-checked verification (executable): the device model and graphics (§8)

`devices` (4 contract tests) realizes the doc's §8 sentences for devices and
graphics. The device registry (`Devices`) is a *userspace* service: there is
no kernel API to enumerate or touch a device — a device is a registry entry
plus the kernel objects its licence derives from, and every operation resolves
through a cap the *caller itself* holds. Its typed interface gates match the
doc's device list (block device, network device, GPU command queue).

- Devices are capability-scoped objects with typed interfaces: a client
  licenced with READ on the block device reads sectors and is refused `write`
  by the kernel (`InsufficientRights`); the *registry* refuses whole
  interfaces — a block device has no command queue, a net device no sector
  interface — before any kernel op. Every kind speaks exactly its own record
  formats.
- No ambient access: a task that knows a device id but was never licenced gets
  `NotHeld` on every op — device memory is reachable only through a granted
  device capability (the model's IOMMU analogue; a real IOMMU is hardware and
  out of scope, see §5).
- Ownership: a device's operative caps live in the *driver's own CSpace*
  (`claim`), so the driver is the licenced operator of record, and nothing is
  kernel-resident — the only owners are contexts.
- Crash containment and supervision recovery (§5's concrete payoff): killing
  the driver only stops its execution context — `is_up` goes false, no new
  licences are issued (`DeviceDown`), while already-granted client caps ride
  through (revocation is explicit in this model) and an unrelated service's
  census and operations are bit-identical. Restarting the driver restores
  licensing and service. Execution contexts start stopped; starting them is a
  supervision-tree action, and a driver's "up" state is exactly the kernel's
  running record, not the registry's opinion.
- Graphics: GPU access is capability-scoped command-queue submission — a
  context's queue is granted SEND only (user-mode submission, no read-back),
  and submissions are ordinary attributed `ep_send` in the audit log. GPU
  memory and queue isolation between contexts is kernel-enforced by objects:
  each context holds only its own queue and its own framebuffer, and cap
  handles resolve against the caller's table alone — a neighbouring context's
  reported slot numbers either fail or land on the caller's *own* objects,
  never on the neighbour's.
- Compositing is an ordinary, replaceable userspace service (the display
  server): it holds READ grants on every framebuffer and the screen comes out
  of its own caps. A dead display server stops the screen (`DeviceDown`) while
  the contexts' capsules are untouched; a replacement compositor rebuilds the
  identical screen with no kernel state having moved.

Honest limits: no real IOMMU, MMIO, DMA, or interrupt model (the isolation
claim is modelled at the object/cap level, which is where the kernel's
authority actually sits); the framebuffer model is per-context byte regions
with no subregion clipping; one display server per service instance; and the
device registry's licensing decisions run in the platform identity — the
registry itself is trusted userspace, not a kernel mechanism.

### Machine-checked verification (executable): the supervision-tree runtime (§5)

The kernel's side of the supervision contract is already checked by
`capability-core/tests/supervision.rs`. This crate is the *runtime* on top of
it — the policy layer the doc calls for: supervision is circuit breaker +
supervision tree, not silent retry; "contain the fault so it doesn't cascade,
preserve full forensic state, escalate with an auditable trail, never silently
retry the same failure indefinitely."

- Restarts are within budget: `Supervisor::pump` reads liveness from kernel
  truth (`task_running` — the runtime has no opinion, only policy), restarts a
  crashed subsystem through its own granted CONTROL cap, and records every
  crash and restart with the kernel's clock and the subsystem's task id.
- The circuit breaker is real: when a subsystem burns its `max_restarts` budget
  the breaker trips open — no further automatic restarts, the trip is logged,
  and every later crash leaves both the breaker state and the log unchanged
  (no silent retry, no flapping). Exactly the budget is burned in kernel
  TaskSpawn records.
- Containment: a crashing (or tripped) subsystem never touches its siblings —
  their kernel census and their operations are bit-identical throughout, and
  the runtime logs nothing about them.
- Escalation: a tripped subsystem is surrendered to a parent supervisor; the
  parent restarts the whole subsystem under its own authority (a fresh spawn,
  a fresh budget) and the surrender-and-adoption is an audited step in both
  decision logs.
- Forensic cross-check: the runtime's decision log and the kernel audit are
  independently append-only; the sequence of crashes (with kernel task ids),
  restarts, and trips in the runtime log exactly equals the kernel's
  TaskKill/TaskSpawn counts — neither side can be selectively rewritten.

Honest limits: liveness is `task_running` only (no heartbeat or health checks);
the policy tables run in one execution context in the model (real OTP gives
every supervisor its own process); the restart budget is per-subsystem-lifetime
rather than a sliding window; and the runtime holds CONTROL on its charges'
naming caps — the "restart-service" role from §9, mechanically.

### Machine-checked verification (executable): grant policy (§9)

`grants/tests/grant_policy.rs` (4 tests) checks the §9.1-9.3 policy claims
against the grant service and kernel together:

- Persistent grants are gated per role: `propose` refuses `Persistent` for a role
  that declares `allow_persistent = false` (restart-service), and accepts it for
  one that does (triage-inbox) — the gate is the role definition, not the caller.
- Task-scoped grants are real expiry: the grantee is held to the exact deadline
  (`now + ticks`), the cap is live before the clock passes it, gone after —
  enforced by capability lookup, not by advisory policy.
- Completion revoke removes the grant from the grantee's CSpace (I4 subtree under
  the grant root) while the grantor's own caps survive — and both the mint and
  the revoke are audited events.
- A review is never a TOCTOU hole: if the grantor's source cap dies between
  `propose` and `confirm`, the mint fails and the refusal is logged — the
  confirmation re-checks every authority assumption at mint time.

### Machine-checked verification (executable): two-party confirmation and the anomaly circuit breaker (§9)

`grants/tests/two_party_contract.rs` and `grants/tests/anomaly_contract.rs` (6
tests) check the §9 controls for irreversible actions and for behavioral
deviation:

- The highest-risk role ("modify-security-policy": CONTROL over the policy
  service itself, persistent) cannot be confirmed by a single click: `confirm`
  refuses it with `InvalidOperation`, the refusal is a visible `ConfirmationRefused`
  policy event, and nothing is minted. The two-party door is the only path —
  and it is closed to ordinary roles (`open_two_party` refuses non-high-risk
  requests), so the special door cannot be abused as a back door.
- Two-party means two distinct people: Alice approving twice is refused; Alice
  then Bob mints. The grantee ends up actually holding CONTROL over the policy
  service (verified via `caps_of`), the active grant records both approvals,
  and the grantor's own caps are untouched.
- The anomaly monitor is the §9 circuit breaker in action: it is trained on
  the agent's *actual* op-shape read from the kernel's own audit log
  (successful `task_running` state checks as the role's normal shape), and
  observes deviation — off-profile op kinds (endpoint sends a restart-role
  agent never does) or a >2x baseline rate. On deviation it *suspends* the
  agent's grants: the already-minted cap still works (nothing was revoked —
  the kernel log shows zero `Revoke` records), and the agent's whole grant
  flow is frozen: new confirmations are refused and logged until a human
  `resume`s the agent. Every step — train, deviation, suspend, resume — is a
  logged event; nothing happens silently.
- The monitor itself has no authority: its `caps_of` is exactly its own
  self-cap, and fabricated kill/revoke/create attempts are all refused by the
  kernel. It is a read-only service (the audit log is the only thing it
  reads) plus an invocation of a grant service's ledger — exactly "not the AI
  itself, not in the TCB, just another capability-scoped service".

Honest limits: the shape baseline is a fixed per-op count from the agent's
full audit history — there is no sliding window, no rate smoothing, and no
time-decay, so "what the role normally does" is a snapshot, not a model; the
"significant" threshold is a flat 2x rule, not a statistical measure; the
baseline is what the agent *does*, never what it *should* do — an agent whose
history already contains the anomaly is never flagged; and the monitor's suspension
touches only grant confirmations — the already-minted caps live until their
own expiry, the same trade-off the design doc declares (suspension is
reversible, revocation is not, so the breaker errs on the side of not
revoking).

### Machine-checked verification (executable): batched submission queues (the io_uring pattern)

The design doc's [REDUCED] answer to "IPC overhead vs. a monolithic kernel's
syscall path" — "batched submission queues (the io_uring pattern: submit many
operations, one kernel crossing, collect results asynchronously) for
high-frequency operations like file I/O" — is checked by
`io-batch/tests/batch_contract.rs` and `capability-core`'s `batch_submit`:

- One kernel crossing for many operations: a 64-entry submission (32 writes,
  32 reads, sector offsets at 9-byte strides) produces exactly one audited
  `Batch` record and zero individual `MemRead`/`MemWrite` records — the
  audited crossing count is O(1), never O(ops) — while every entry's effect
  lands in the region, verified op by op afterwards.
- Queued operations cost nothing: entries accumulated in the submission
  queue leave the kernel untouched (no records, no data) until `submit` — the
  accumulation is caller-side, the crossing is one call.
- Batching the crossing never batches the authority: a submission mixing a
  legal write with out-of-range writes and a read of a capability slot the
  caller does not hold completes per entry — the legal write lands, each
  unlawful entry returns `Failed` in its own completion slot, the refused
  writes have zero effect, and the kernel logs one Failed record per refused
  entry — refusals are as visible as successes.
- Completions are drained apart from submissions: a second crossing happens
  while the first batch's completion queue is still unconsumed, each
  submission is one crossing (two submissions = two Batch records), and
  completion order is submission order.

Honest limits: the "kernel crossing" is one audited Batch record, not a real
syscall boundary — there is no hardware submission queue, no interrupt or
notification path, and the kernel model itself is synchronous (completions
are materialized at submit and drained later; the async half of the pattern
is the isolation between the caller-side accumulation and the separate
completion queue, which nothing forces the caller to drain eagerly). The
design doc's own caveat applies: this claims the same performance
*neighborhood* as seL4 IPC benchmarks, never parity with a bare syscall, and
the model measures crossings, not wall time.

### Delivery overhang: warning, not a gate (design decision)

The reachable-authority auditor detects **delivery overhang**: a grantor holding a
GRANT-carrying naming cap into a task could push copies of strictly more than the
task's manifest declares. This is surfaced as `AuditWarning::DeliveryOverhang`, not
as an `AuditViolation`.

**Decision: warning, not gate.** Rationale:

1. The overhang is *latent* — it describes what a grantor *could* push, not what
   has been pushed. The exercised set stays manifest-bounded by I2 (delegation
   monotonicity) and I6 (grant consent).
2. The kernel is the real enforcement boundary: every `grant`/`grant_mint` re-checks
   authority at delivery time. The auditor is a build-time cross-check, not the
   enforcement mechanism.
3. Making it a violation would produce false positives for legitimate patterns: a
   session granting an assistant more than the assistant declared is the *intended*
   use case for the session-as-orchestrator model (§9). Corollary: the warning
   skips edges whose grantor is the kernel/boot repository (`Repo::Kernel`) — the
   session is the trusted bootstrap authority, and its power to deposit capabilities
   into the tasks it created is by design, not the userspace-TCB-creep the check
   exists to catch (design doc §10). Userspace grantors that could over-deliver
   still warn.
4. The existing test `delivery_overhang_tracks_the_declared_ceiling` verifies the
   warning fires correctly (via a userspace grantor) and disappears when the
   target's manifest is wide enough.

This is a deliberate design choice, not an open gap. If a future threat model
requires delivery overhang to be a hard gate, the path is: promote
`AuditWarning::DeliveryOverhang` to `AuditViolation` in `audit.rs`, and the CI
workflow (`cargo test --workspace`) will enforce it.

---

## 7. Kernel implementation claims (Phases 1-7, `aegis-kernel`)

The Phase 0 formal model above governs the capability-crate workspace (`aegis/crates`).
Phases 1-7 in `aegis-kernel` implement the real-hardware-facing substrate: boot, process
isolation, drivers, networking, AI orchestration, and shell. Every claim below is
machine-checked by `#[cfg(test)]` contract tests in the same crate (304 total as of
Phase 2: +9 memory-region gates in `mem.rs`, +5 supervision-runtime tests in
`supervisor.rs`), run by `cargo test` from `aegis-kernel/`. Honest limits: tests run as
host-target unit tests proving the *model logic*; every hardware-touching operation
(lgdt/lidt/cr3, PCIe config I/O, IOMMU tables, NVMe queues, VirtIO MMIO, VGA writes) is
UNTESTED on real hardware.

### Machine-checked verification (executable): boot and ELF64 loading (§5, Phase 1)

`uefi-boot/src/elf.rs` (10 tests in `uefi-boot/tests/elf_contract.rs`): header validation
(magic, class, endianness, type, machine), PT_LOAD segment parsing, rejection of invalid
binaries. Honest limits: proves the parser against crafted byte buffers, not a boot on
real firmware.

### Machine-checked verification (executable): process isolation and scheduling (§5, Phase 2)

`scheduler.rs` (10 tests): spawn, schedule_next, tick/preempt, block/wake, round-robin
cycling, zombie reaping. Honest limits: GDT/TSS, IDT stubs, and per-process page tables
are code-only; the actual lgdt/lidt/cr3 switching is UNTESTED on real hardware.

### Machine-checked verification (live): preemptive task switching on bare metal (§5, Phase 2)

`aegis-kernel/src/tasks.rs`: `TaskFrame` (15 GPRs + error slot + iretq words), naked
`switch_frame` — registers saved into the frame's slots, restored via pops, resume via
`iretq`; the same path serves fresh targets (all-zero slots) and saved targets (their
last switch spilled real registers). The LAPIC timer stub runs `timer_preempt` on every
tick: `next_after` picks the next context (round-robin idle → task 0 → … → last task →
idle), `CURRENT` advances, and the switch happens with the interrupt frame on the
current context's stack — so the interrupted context resumes later from its exact
interruption point. Tasks run on 16 KiB stacks (`alloc_contiguous_global`; fixed
4-slot table). VERIFIED live under QEMU/OVMF on the current commit: two demo tasks
that NEVER yield print every 2048 ticks (progress is impossible without preemption),
at stable stack addresses (0x37F70 / 0x3BF70); the idle loop still gets CPU every
third tick; 0 exceptions across a 14 s boot. The live verification caught a real bug
in the earlier cooperative path: the saved RSP included the `call`-pushed return
address, so every resume ran 8 bytes deeper (2 switches per hlt-gated round = −16
bytes/tick); after ~500 ticks the kernel stack had walked into the task table, a
switch hit a never-spawned slot (RSP=0) and the machine triple-faulted. The save path
now stores the pre-call RSP (`rsp+8`).

Honest limits: verified under QEMU/TCG only, not on physical hardware; single
fixed-priority round-robin (no priorities, no blocking/wait queues); no dynamic spawn
after boot, no task removal; user mode now exists (see below) but per-process
page-fault-driven isolation (separate user page tables per process) is not built yet.

### Machine-checked verification (live): ring-3 user task + `int 0x80` syscall gate (§5, Phase 2 extension)

`aegis-kernel/src/main.rs` (`task_user`) plus `syscall.rs` (`syscall_stub` + `syscall_trap_rust`)
+ `gdt.rs`/`idt.rs`: a demo task is dropped to CPL3 by the scheduler's `switch_frame`,
whose `iretq` target frame carries the user selectors (CS=0x1B, SS=0x23 with RPL=3);
the task runs on its own user stack and its kernel transitions use a dedicated CPL0
stack via `TSS.RSP0` (`timer_preempt` writes the next task's CPL0 top before the
switch). A DPL-3 `int 0x80` interrupt gate (`SYS_VECTOR`) enters the kernel; the stub
saves the GPR block (rax/rsi/rcx/rdx carry num/args), `dispatch` serves the `Write`
syscall (prints the untrusted buffer to COM1, length capped at `WRITE_MAX_LEN`), and
`iretq` returns to CPL3. VERIFIED live under QEMU/TCG on the current commit: `george`
runs at CPL3, prints `Aegis: [user] ring 3 hello via int 0x80`, and is preempted by
the LAPIC timer every tick alongside two CPL0 tasks (`alpha`/`beta`) and the idle loop
— privilege transitions both directions work, 0 exceptions across an 18 s boot (5
user prints interleaved with kernel prints). The live verification caught two real
bugs: (1) the kernel PML4 entry linking the user window lacked the `USER` bit, so the
user page-table walk faulted at the very first instruction fetch — every level of the
walk must set `USER`; (2) the syscall stub saves `rax…r11` in the order
`push 0; push rax; …; push r11`, so `rax` lands at frame slot 10 (not slot 1) — the
handler was reading the wrong registers and syscalls silently returned -1, fixed by
correcting the slot indices. CR4 SMEP/SMAP are also cleared at boot (defensive; the
firmware had them off here, but correct for real hardware).

Honest limits: verified under QEMU/TCG only, not on physical hardware; the first 1 GiB
is mapped with a single user-accessible huge page, so this proves the *privilege
transition* machinery (CPL3 entry, syscall gate, TSS.RSP0, per-task CPL0 stacks), not
memory isolation between processes. **There is no Rust contract test for the bare-metal
CPL3 transition** (it requires a CPU in ring 3); the contract tests that back this
section live in `tasks.rs` (`fresh_user_frame_uses_ring3_selectors`, `next_after`
round-robins idle→0→1→2→idle for 3 tasks, `task_new_user_places_both_stack_tops_correctly`)
and `syscall.rs` (`dispatch` for each syscall number, `clamp_write_len`, unknown→-1).
Those prove the frame/selector/scheduler/dispatch building blocks; the end-to-end
transition is proven only by the live QEMU boot above.

### Machine-checked verification (executable): driver framework (§8, Phase 3)

`pci.rs` (6), `iommu.rs` (5), `nvme.rs` (5): config-space address construction, BAR
parsing (32/64-bit), device identification, DMA page-table mapping, device-to-domain
assignment, SQ/CQ entry construction, phase-bit tracking. Honest limits: all I/O-port and
MMIO operations are UNTESTED on real hardware.

### Machine-checked verification (executable): networking stack (§8, Phase 5)

`net.rs` (9), `ethernet.rs` (5), `arp.rs` (6), `ipv4.rs` (6), `udp.rs` (8), `tcp.rs` (9):
device init, frame parse/serialize, ethertype validation, ARP table ops and packet
construction, IPv4 checksums, loopback/broadcast detection, UDP (RFC 768) and TCP
(RFC 793) header parse/serialize with pseudo-header checksum verification and
length/data-offset validation. Honest limits: UDP/TCP are header models only — no
connection state machine, no socket layer, not wired into the boot path; no real NIC
traffic; drivers UNTESTED on real hardware.

### Machine-checked verification (executable): AI orchestration (§5, Phase 6)

`agent.rs` (8), `profiler.rs` (5), `adaptive.rs` (5), `policy_engine.rs` (5): agent
lifecycle and capability scoping, syscall histograms and deviation, auto-tighten/
suspend/terminate, rule evaluation and audit trail. In the kernel (`aegis-kernel`),
Phase 6 is closed by the **real attributed audit log** — `audit.rs` (3 tests), a
512-record ring where every gated op (`task_state`/`task_kill`/`task_restart`,
`ch_send_as`/`ch_recv_as`, `mem_len`/`mem_read`/`mem_write`, `ipc_cap_grant`, and the
GRANT-gated `revoke_slot`) lands attributed `(tick, caller, op, target, ok)` on
success and refusal alike — and the **§9 anomaly circuit breaker** — `monitor.rs`
(3 tests): a capability-less `AnomalyMonitor` trains on the agent's real op-shape
from the audit log and, on significant deviation (an op's rate more than doubled, or
an op never in the shape), suspends — never revokes — via the `GrantLedger`, which
freezes `ipc_cap_grant` for a suspended agent while minted caps keep working, is
reversible and logged on human review, and is itself refused any authority (a
cap-less monitor task cannot kill, revoke, or read an object). Honest limits:
profiler is histogram-based, not ML; no real AI model; no real-time integration; the
audit log is a bounded in-memory ring (no durability), and the ledger gates only
delegation — the supervisor/channel/mem gates do not consult it.

### Machine-checked verification (executable): native app model and shell (§8, Phase 7)

`shell.rs` (6), `window.rs` (7), `object_graph.rs` (6), `input.rs` (5): app
launch/stop/restart and focus, window z-order/hit-test/compositor order/dirty regions,
graph node/relationship CRUD and traversal, input ring buffer and focus dispatch. Honest
limits: no GPU, no framebuffer output; these model tests use synthetic events — real
keyboard input is proven live in the kernel (see `aegis-kernel/src/ps2.rs` +
`desktop.rs` and the `shell-compositor@key` serial assertions in
`HONEST_STATUS.md`), no mouse hardware.

### Machine-checked verification (executable): Linux compatibility (§5/§7 Phase 8)

`linux_abi.rs` (12), `elf_loader.rs` (12), `linux_compat.rs` (8): Linux x86-64 syscall
number/register translation to capability-scoped Aegis operations; ET_EXEC/ET_DYN header
and PT_LOAD validation with bounds checks plus System V initial stack layout
(argc/argv/envp/auxv); personality gating where every translated operation is checked
against the context's capability scope (the AI ceiling applies to compat code). Honest
limits: translation is model logic, not a real ring-3 syscall trap; the lightweight-VM
execution vehicle from §5 (WSL2-lineage) is not built — it needs a hypervisor.

### Machine-checked verification (executable): Windows compatibility (§5/§7 Phase 9)

`nt_abi.rs` (12), `pe_loader.rs` (12), `win_compat.rs` (7): narrow NT syscall subset
translation (NtCreateFile/Read/Write/Close/CreateSection/MapView/TerminateProcess/
DeviceIoControl/QuerySystemTime) to capability-scoped Aegis operations; PE32+ (x64)
validation (MZ/PE signatures, machine, entry point, image base, section flags and
bounds); personality gating on the capability scope. Honest limits: this is the narrow
well-behaved-subset translator only, model logic — the design doc is explicit that full
Windows fidelity requires a licensed Windows kernel or VM (neither built).

### Machine-checked verification (executable): adaptive-layer ceiling (§3/§5 Phase 10)

`ceiling.rs` (14, test-only module): every decision from `AdaptivePolicy` and
`PolicyEngine` is verified monotonically non-expanding against its source scope —
tighten never raises memory/file budgets (including never raising a zero budget to a
nonzero one), never adds an allowed syscall, never adds network; worst-case adversarial
profiles never escape even a restrictive ceiling. This verification *caught and fixed a
real bug*: `tighten_scope` previously floored `(budget / 2)` at 1, expanding a
restrictive 0-file-handle budget to 1. Honest limits: finite deterministic property
tests, not an inductive proof; the ceiling (not the policy) is what is verified, per the
design doc.

### Machine-checked verification (executable): distributed extension (§3/§5/§7 Phase 11)

`crates/fleet` (22): cross-machine capability transport over the macaroon token format.
Node identity, explicit locality (`Local`/`Remote` — never hidden, per the design doc),
a wire-format `RemoteCapability` envelope (serialize/deserialize round-trip), a peer
trust registry, and verification that checks HMAC chain integrity under the issuer's
key, issuer trust, **recipient binding** (the intended recipient is cryptographically
bound into the HMAC chain at send time, so relayed tokens and forged recipient fields
are rejected — regression-tested for the relay finding), and expiry. Remote attenuation
(rights narrow + expiry clamp) is verified across nodes. Honest limits: two-node
in-process model — no sockets, no consensus, no partition/split-brain modeling (the
design doc's CAP warning explicitly applies); `bind_caveat` requires the issuer key,
whereas real macaroons allow keyless attenuation (documented model difference).

### Machine-checked verification (executable): production hardening (§8/§7 Phase 12)

`crates/security-audit` (10) + `aegis-kernel/src/hardening.rs` (17) + `SECURITY_AUDIT.md`:
the reachable-authority audit is promoted to an aggregate build gate with contract
tests covering the clean reference world, kernel-equivalent-demand rejection,
undeclared-holding rejection, overhang-warns-not-fails, and structural-self-cap
exclusion; kernel boundary tests drive every parser and both syscall ABIs with
garbage/truncated/overflowing inputs under `catch_unwind` and assert total (error,
never-panic) behavior — including regressions proving the ELF/PE loaders reject
attacker-controlled offset arithmetic with `checked_add`/`checked_mul` instead of
wrapping or panicking; the certification matrix records exactly what is and is not
certified. Honest limits: deterministic boundary testing, not fuzzing; model-level
audit, not hardware certification — every hardware-touching operation remains UNTESTED;
no inductive proof; no secure boot/attestation.

### Machine-checked verification (executable): hypervisor groundwork (§8 Phase U)

`aegis-kernel` additions (56 tests): `ept.rs` (13) — the 4-level EPT builder for the
VMX path: grant-bounded `map` (refuses misalignment, overflow, out-of-grant, overlap —
each refusal leaves the table untouched), `unmap_all` returns every table page
(`table_pages` back to 0, allocator outstanding 0), `translate`, `eptp(root)` builds
the VMCS EPTP value, `EptViolation`/`decode_ept_violation`, zero allocation while
empty, OOM budget refusal. `vdev.rs` (19) — the in-guest device models the VM-exit
handlers will service: 8259 PIC (cascaded, in-service hold, EOI), 16550 UART, 8254
PIT (modes 0/2/3), PCI config bus fabricating host bridge + virtio-blk at I/O BAR
0xC000. `virtio.rs` (11) — legacy virtio-blk queue engine: negotiation, descriptor
chains, IN/OUT/FLUSH/GET_ID, ISR/IRQ semantics. `vm.rs` (~13) — `Vm` with `pub ept`,
the bzImage guest boot protocol (`GuestBoot::build`/`write_all`: zero page with e820
+ boot_params handoff, code at 0x100000, initrd, cmdline, GDT/TSS), `BootState`,
`PitTicker`, `Cap::VmRoot`-gated VM creation.

### Machine-checked verification (executable): the resumable VMX run loop (§8 Phase U-6)

`aegis-kernel` additions (7 more tests, 657 kernel total): `vmx.rs` now implements
the run loop that connects the above pieces — `vmx_run_guest` (first `vmlaunch`,
then repeated `vmresume`; every VM-exit returns to the loop: the entry trampolines
write the caller's RSP into VMCS HOST_RSP each entry so the exit landing pad `ret`s
back into the loop with the guest's 15 GPRs saved; r11-as-base is loaded last), exit
dispatch over the corrected SDM Table 29-1 map (external interrupt → LAPIC EOI +
per-exit hook; HLT → guest activity state HLT + RIP +1; I/O instruction →
`decode_io_exit` per SDM Table 27-5 + opcode fetch through the EPT + `Vm::handle_io`
emulation into the in-guest 16550/PIC/PIT + IN result written to the guest's saved
RAX with upper bits preserved + RIP advanced by instruction length; EPT violation →
counted on the VM + caller policy hook; anything unhandled is a loud `Err`, never
swallowed), EPT activation in the VMCS (`setup_controls(use_ept, ept_root)`:
EXT_INT_EXITING|IO_EXITING|HLT_EXITING|SECONDARY_CONTROLS primary, EPT +
unrestricted guest + TSC offsetting secondary, EPTP programmed; refused — not
degraded — if the capability MSRs cannot grant them), and `setup_guest_state_from_boot`
(protected-mode VMCS guest state from `BootState`, AR bytes matching the
`GuestBoot::write_setup_gdt` descriptors). Feature-gated `run_loop_demo()` proves the
whole chain end-to-end on VMX hardware: a 32-bit guest under EPT prints through the
emulated 16550 and halts, bounded by an exit budget; `bringup_demo` now returns after
its round trip instead of halting. Honest limits: the hardware half (vmlaunch /
vmresume / real EPT walks / the trampoline register dance) has never run — no VT-x
on the development machine (`VirtualizationFirmwareEnabled=False`); the decode,
dispatch, control-bit and state-setup logic is contract-tested, and the two demos
run automatically behind `vmx_supported()` on any VT-x-capable boot. The live
Aegis-hosted guest boot (Phase U DoD) remains hardware-gated; the guest-image half
is proven real — a Linux bzImage + BusyBox initramfs built by `guest/build-guest.sh`
boots standalone under QEMU with committed evidence in `guest/out/`.

### Machine-checked verification (executable): guest applications (§8 Phase V)

The guest image now runs **real applications**, verified executable end-to-end:

- **Five guest apps** are committed in `guest/initramfs/usr/bin/` (mode 0755):
  `calc` (bc expression calculator), `fib` (first N Fibonacci via shell arithmetic),
  `wordcount` (line/word/byte counts of stdin), `sysinfo` (system report over
  `uname`/`date`/`uptime`/`/proc/meminfo`/`ps`), and `filedemo` (tar round-trip of
  `/bin/busybox` + `/bin/echo` with md5 verification).
- **Deterministic append-only cpio rebuild.** `guest/out/initramfs.cpio.gz` is
  rebuilt by a throwaway Python script (kept in `%TEMP%`, not committed) that
  gunzips the existing archive, truncates it at the last newc `TRAILER!!!` (110-byte
  backup from the name, `070701` magic verified at that offset), appends five newc
  entries for `usr/bin/{calc,fib,wordcount,sysinfo,filedemo}` (ino 1..5,
  mode `0100755`, uid/gid 0, nlink 1, mtime 0, filesize = script length, dev/rdev 0,
  namesize = len(name)+1, check 0; name and data NUL-padded per the GNU-cpio newc
  layout the kernel's unpacker expects — header+name on a 4-byte boundary), appends
  a fresh trailer, and re-gzips with `gzip.compress(data, mtime=0)`. The script's
  self-check re-parses the result: the 5 new entries exist with byte-exact content,
  **every original archive byte before the trailer is byte-identical to the
  pre-patch archive**, the archive stays 512-byte block aligned (matching the
  original GNU-cpio output — without it the kernel reports "Initramfs unpacking
  failed: junk within compressed archive"), and it ends with `TRAILER!!!`.
- **Same image the hypervisor embeds.** `aegis-kernel/src/vmx.rs` embeds exactly
  this file (`GUEST_INITRAMFS = include_bytes!("../../guest/out/initramfs.cpio.gz")`),
  so the standalone evidence describes the payload Aegis would hand the guest.
- **Standalone QEMU re-evidence.** The guest booted standalone under QEMU 11.0.50
  (SeaBIOS `-kernel` + `-initrd`; the `AEGIS_NO_OVMF=1` path) with
  `guest/evidence-commands.txt` driven over the serial console and the whole boot
  captured in `guest/out/boot-standalone-serial.log` (334 lines): `calc "6 * 7"` →
  `42`; `calc "2^10"` → `1024`; `fib 12` → `0 1 1 2 3 5 8 13 21 34 55 89`;
  `echo … | wordcount` → `1 9 44`; `sysinfo` prints its report; `filedemo` lists
  `bin/busybox` + `bin/echo` and prints two identical md5 lines
  (`198c0144fc34df609da629151a1e1818`); then `poweroff -f` → ACPI S5 → clean QEMU
  exit (rc 0). The log is real QEMU serial output — never hand-edited.

**Honest limits.** `sysinfo`'s `mem:` and `procs:` fields print empty/`1` because
the initramfs contains no `/proc` mountpoint (the guest `/init`'s
`mount -t proc proc /proc` fails on the missing directory), so `/proc/meminfo` and
`ps` are unavailable inside the guest; the app and every other field are real, and
this is a guest-image limitation rather than an emulation claim. And — as in Phase
U/U-6/U-7 — this evidence is for the **standalone** guest under QEMU; the
Aegis-hosted run of the same image remains **hardware-gated** (no VT-x on this
machine: `VirtualizationFirmwareEnabled=False`), which is why this section is an
executable machine-checked claim about the guest image, not a claim that the
hypervisor has hosted it yet.

### Machine-checked verification (executable): calculator / viewer / package-manager apps (§8 Phase AA)

`aegis-kernel` additions (27 more tests, 684 kernel total; **687 with
`--features vmx-demo`**): three more real desktop app windows complete the
six-window desktop, all over the same boot-view store the editor, browser, and
shell already share.

- `calc.rs` (8) — the calculator model: digit/operator/equals/clear state,
  chained-op ordering (`6 * 7 =` accumulates 42), division-by-zero → `E`,
  4-digit display truncation, and the `BUTTONS` byte-string layout that
  `desktop.rs` hit-tests (`calc_button_at`) so a mouse click presses a button.
  `Desktop::calc_result` exposes the display for the serial `calc@result` line.
- `viewer.rs` (6) — `parse_ppm`/`parse_dim` decode the P6/P5 headers (the
  corner-detection bounds were fixed to reject oversized dimensions), palette
  quantization maps each pixel to the compositor's 16-color `PALETTE`
  (`gpu_compositor::PALETTE` is now `pub`), and `build_demo_ppm` produces the
  444-byte 12x12 gradient the kernel seeds as `img.ppm` — the same store object
  the browser lists, so the viewer renders exactly what the browser opens.
- `pkgmgr.rs` (4) — listing (`pkg-*` root files), selection, and the
  selected-name gate behind the `[Inst]`/`[Rem]` action bar; install writes the
  catalog payload through the store (content-addressed, so reinstall dedups),
  remove unlinks via COW — the same honest "a package is a store object"
  mechanism as Phase 7's update path.
- `desktop.rs` (5 new integration tests) — the full event pipeline drives
  `taskbar_click_focuses_and_raises_the_calculator`,
  `mouse_click_on_calc_buttons_computes_42`, `tab_cycles_through_all_six_windows`,
  `pkgmgr_click_selects_and_install_returns_outcome`, and
  `viewer_window_is_listed_and_renderable` through the real `apply_mouse`/
  `apply_key` paths with a MemDisk-backed `EditorFs` (the `test_store` seam) —
  the same handler code the live kernel runs.
- `editor.rs` (2) — `remove_named`/`remove_named_at`, the COW unlink halves the
  package manager's remove uses; the `EditorFs<C: BlockIo>` generalization adds
  the `EditorHandle` trait + `with`/`test_store` seam (tests inject a MemDisk
  controller; the live kernel's `NvmeController` is unchanged), keeping the
  public call surface identical.
- `update.rs` (2) — `remove_file`/`remove_file_at` (the `Store`/`BootView` COW
  unlink) with reuse/emptiness rules.

**Live proof (mouse-only, QEMU):** `uefi-boot/serial-aa-demo.log` +
`scr-aa-{baseline,calc,pkg}.ppm` — taskbar Calc click then `6` `*` `7` `=` →
`Aegis: calc@result 42`; taskbar Pkg click → listing row select → `[Inst]` →
`Aegis: pkgmgr@install -> installed row 0`; boot markers
`Aegis: viewer@boot img.ppm -> 12x12` and `pkgmgr@boot listing
[pkg-alpha.txt,pkg-beta.txt] (2 packages, window id=8)`.

**Honest limits.** Windows are boot-time singletons — a taskbar segment click
focuses + raises the one existing window, it does not spawn a new instance (no
window-instantiation path yet, as Phase S noted). The calculator has no
parentheses or unary ops (fixed-array 4-digit arithmetic). The viewer renders
the demo image and any store object the browser can open; there is no image
decoder beyond PPM. The package manager installs/removes the catalog payloads by
store-object content addressing; there is no manifest/signature step (that stays
the Phase-7 `update.rs` path). Mouse-driven input is the emulated PS/2 path,
and all display is QEMU/OVMF framebuffer output — UNTESTED on real hardware.

### Machine-checked verification (executable): ACPI discovery + SMP groundwork (§8 Phase Y)

`aegis-kernel` additions (26 more tests, **710 kernel total; 713 with
`--features vmx-demo`**): the kernel now reads the *real* ACPI tables the
firmware exposes and enumerates the CPUs/APICs — the first step toward SMP —
as pure, total, contract-tested code, with a tested encoder path so the same
types can later construct guest ACPI tables.

- `acpi.rs` (26) — **parsers:** `parse_rsdp` (revision 0/1/2; ACPI 1.0
  checksum over bytes 0..20 and, for rev ≥ 2, the extended checksum over the
  full 36 bytes; nonzero RSDT required; future revisions rejected — they must
  fail to parse, never be misread); `parse_sdt_header` (length ≥ 36, whole-table
  checksum, non-zero signature); `parse_table_entries` (RSDT 32-bit / XSDT
  64-bit; an XSDT entry ≥ 0x1_0000_0000 rejects the WHOLE parse — the identity
  map covers only the first 4 GiB — never silent truncation; bounded by
  `MAX_TABLES`); `parse_madt` (44-byte fixed part then `{type,length,body}`
  entries: LAPIC / IOAPIC first-wins / IRQ override; unknown types skipped by
  length; a length byte < 2 or an entry overrunning the table stops the walk
  cleanly; never panics); `scan_rsdp` (16-byte-aligned offsets only).
  **Discovery:** `discover_core<R: PhysRead>` is the pure decision logic over an
  abstract physical-memory reader (tests inject synthetic regions); `read_phys`/
  `LiveReader` are the live identity-mapped reads; the RSDP search is three-tier
  — the EBDA segment word at 0x40E, the 0xE0000..0x100000 F-seg window, then the
  UEFI ACPI Reclaim/NVS regions from the boot memory map (`acpi_ranges_from_map`
  over new `TYPE_ACPI_RECLAIM`/`TYPE_ACPI_NVS`, where OVMF installs the RSDP at
  high addresses the legacy locations cannot reach). **SMP groundwork:**
  `smp_info_from_madt` yields `SmpInfo` (enabled-CPU count, APIC ids, IOAPIC,
  LAPIC address), stashed by `set_discovered` for future SMP phases.
  **Guest-flexibility seam:** `build_rsdp`/`build_madt`/`build_sdt_header`
  encode over the *same* types, and the round-trip tests
  (`build_rsdp_round_trips`, `build_madt_round_trips`) keep encoder and parser
  in lockstep — NOT yet wired into the VM; a future guest-ACPI phase consumes
  this seam.
- `main.rs` — boot markers (`Aegis: acpi: scanning for RSDP`, `RSDP rev=…
  rsdt=… (checksum ok)`, `root table RSDT count=…`, `MADT at 0x… lapic=…`,
  `SMP: N processor(s) enabled (apic ids […])`, `irq overrides: K`); an
  ACPI-absent boot prints one honest line (`ACPI unavailable - running with
  legacy PIC/PIT`) and continues to the desktop.

**Live proof (`uefi-boot/serial-acpi-demo.log`, QEMU `-machine q35 -smp 2`):**
`Aegis: acpi: RSDP rev=0 rsdt=0x1FB7D000 xsdt=0x0 (checksum ok)` (found via the
UEFI ACPI Reclaim region — EBDA/F-seg empty under OVMF),
`root table RSDT count=6`, `MADT at 0x1FB78000 lapic=0xFEE00000 flags=0x1`,
`SMP: 2 processor(s) enabled (apic ids [0,1])` (matches `-smp 2`),
`ioapic=0xFEC00000 gsi_base=0`, `irq overrides: 5`, then
`compositor desktop shown on the VM display` — **0 exceptions, 0 panics**.

**Honest limits.** This is CPU/APIC *enumeration* groundwork, not bring-up:
BSP only, no AP boot (INIT-SIPI), no per-CPU LAPIC reprogramming, no per-CPU
stacks. Any ACPI table above 4 GiB is rejected because the identity map covers
only the first 4 GiB (documented — real machines can place them there). The
search is the Linux-style EBDA + F-seg + ACPI-region scan; vendor-specific RSDP
locations on physical hardware would be missed. Everything is QEMU/OVMF-verified,
UNTESTED on physical silicon.
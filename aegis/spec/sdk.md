# Aegis model SDK

This is the *executable model SDK*: the crates in the `aegis` workspace that
implement, as pure, contract-tested Rust, the capability substrate described
in `spec/capability-model.md` and the design monograph
(`os-from-first-principles.md`). Everything here is model code — it runs on a
host OS, not on bare metal. The real kernel is `aegis-kernel/`; the bridge
that proves the model and the kernel agree is `conformance`.

## The two-tier story (read this first)

- **`aegis-kernel`** — the actual bare-metal kernel (paging, drivers, IPC,
  the capability gates that decide every syscall).
- **`aegis` workspace** — the *model* of the same authority rules: a
  `Kernel` in `capability-core` whose authorization verdicts are derived
  independently from the kernel's, plus services built on that model.
- **`conformance`** — replays the *kernel's* live capability trace
  (`C:` lines, emitted by the `trace` feature) against the model and asserts
  the two agree at every step. Agreement is the conformance claim; a
  divergence is a bug.

So the SDK crates are not toys next to the kernel — they are the
independently-derived oracle the kernel is measured against.

## Crate map

The crates are grouped by the layer of the design they model. Every crate is
`publish = false` by default; depend on them with `path` dependencies inside
this workspace.

### Authority core

- **`capability-core`** — the kernel *model*: `Kernel`, tasks, endpoints,
  memory regions, grant roots, the CSpace authority rules (I1–I6 in the
  spec), `copy`/`grant`/`grant_mint`/`revoke`/`destroy`, IPC, batched
  submission, and the audit log every op — success or refusal — appends to.
  This is the crate a conformance check replays against.
- **`grants`** — the role library and grant flow (design doc §9):
  role-shaped, ephemeral-by-default grants (`RoleLibrary`,
  `GrantService::propose` → `diff` → `confirm`), high-risk two-party
  confirmation, the anomaly circuit breaker (`Monitor`), and the policy log
  of suspensions/resumptions/refusals.
- **`macaroon`** — capability *tokens*: a macaroon-style chain
  (`TokenChain`, caveats, `bind_caveat`, `verify`) that turns a capability
  into a bearer token bounded by exactly the caveats the issuer set.

### Application models

- **`object-store`** — capability-addressed content-addressed immutable
  blocks, a COW layer, a POSIX file-view projection, and a rebuildable
  relationship index that consumes only the write-ahead log.
- **`packages`** — installation grants exactly the capabilities a package
  manifest declares, nothing ambient; transactional, no code at install.
- **`system-update`** — staged, health-gated, transactional update
  generations; rollback needs no capability authority at all.
- **`resources`** — hierarchical budgets over the supervision tree, metered
  from kernel truth, enforced by the governor's recycle.
- **`supervision-tree`** — the supervision runtime: circuit breaker +
  supervision tree (contain, preserve forensic state, escalate with an
  auditable trail).
- **`devices`** — every device discovered, IOMMU-fenced, exposed as a
  capability-scoped object with a typed interface.
- **`net`** — a loopback network stack: a network capability is a specific,
  revocable right to talk to a specific peer.
- **`io-batch`** — batched submission (the io_uring pattern): one kernel
  crossing for many operations, per-entry authorization.

### Orchestration and agents

- **`aegis-shell`** — the smallest end-to-end prototype (design doc §11.F):
  a supervised service, a capability-scoped agent granted one role, and the
  adversarial suite proving the agent cannot exceed its ceiling.
- **`fleet`** — cross-machine capability transport: capability envelopes,
  consensus re-election, split-brain resolution, remote invocation of a
  transferred capability.

### Audit and verification

- **`capability-audit`** — the reachable-authority auditor (design doc §10
  [CLOSED] "TCB creep"): every service's capability manifest vs. the
  authority the model says it can actually reach. **This is the
  build-breaking gate in CI** (`cargo run -p capability-audit`).
- **`security-audit`** — the aggregate security-audit certification matrix
  (Phase 12).
- **`conformance`** — the model-vs-kernel replay harness (see above).

### The tour

- **`sdk-example`** — a runnable, contract-tested walk through the whole
  lifecycle (below).

## The canonical example: `cargo run -p sdk-example`

The best way to see the SDK is to run it:

```sh
cd aegis
cargo run -p sdk-example
```

It prints the role-grant lifecycle end to end, 13 steps:

1. **boot** — root task + Creator cap; all authority begins here.
2. **services** — the tasks the agent will (eventually) be allowed to touch.
3. **zero-capability agent** — the agent holds exactly one cap: its self-cap.
4. **denial before grant** — a foreign kill and a foreign role-grant are
   refused at the capability gates, and the refusals are in the audit log.
5. **grant service** — one grant root under the orchestrator; role library
   loaded.
6. **propose → diff → confirm** — `restart-service` proposed, the one-line
   diff reviewed (READ+CONTROL, no GRANT), the grant minted task-scoped.
7. **authorized after grant** — the agent reads state (READ) and restarts
   the service (CONTROL).
8. **escalation refused** — the server cap has no GRANT, so re-granting it
   is refused: the agent never becomes an authority.
9. **task-scoped expiry** — time kills the grant (I5) without a revocation.
10. **two-party confirmation** — the high-risk `modify-security-policy` role
    cannot be confirmed by a single click; the same-party second is refused;
    two distinct reviewers mint it.
11. **anomaly circuit breaker** — trained on the role's shape, it suspends
    (never revokes) the agent on an off-profile op, then resumes on human
    review.
12. **revocation** — one root revoke removes the grant from everywhere,
    whoever holds it (I4).
13. **audit summary** — every step, including every refusal, is in the
    kernel audit log.

The exact same function backs the crate's contract tests, so the tour cannot
drift from the model it documents: if a step's invariant ever breaks, a test
fails. To build a variant for your own flow, read `sdk-example/src/lib.rs` —
each step is a short, commented slice of the `capability-core` + `grants`
API.

## Dependencies

A minimal consumer needs only `capability-core`:

```toml
[dependencies]
capability-core = { path = "../capability-core" }
```

Add `grants` for the role library and grant service, `macaroon` for bearer
tokens, and the application-model crates as the design calls for them. All
crates depend only on `capability-core` (or on each other), never on the
kernel, and never on each other's private state — the model's isolation
boundary is Rust module privacy, exactly as in `capability-core/src/kernel.rs`.

## Future flexibility

- **New crates and steps** are first-class workspace members: `cargo test
  --workspace` and CI (`cargo test`, `cargo clippy --workspace --all-targets`,
  `cargo fmt --check`, `cargo run -p capability-audit`) cover them
  automatically. To add a step to the tour, extend `sdk-example::tour` and
  add a test — the tour stays honest by construction.
- **The model is the conformance oracle.** When `aegis-kernel` changes a
  gate, `conformance` must still replay the kernel's trace without
  divergence; a new kernel gate is expected to arrive with its trace fixture.
- **Publishing** is deliberately off (`publish = false`): the crates are
  versioned together with the design docs they implement, not as an
  independent ecosystem. Releasing them as a standalone SDK is a decision
  for later — the seam (stable public surfaces, workspace-versioned) is
  already there.

## Contract-test counts

- `aegis` workspace: **131 contract tests** across 17 crates (including 3 in
  `sdk-example`), `cargo fmt`/`clippy -D warnings` clean.
- The kernel (`aegis-kernel`) and bootloader (`uefi-boot`) are counted
  separately; see `HONEST_STATUS.md` for the combined totals.
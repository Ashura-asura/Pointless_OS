# Honest Status — Pointless OS / Aegis

*Generated: 2026-08-10. Every claim below is verified by `cargo test` on the current commit.*

## What exists (77 tests, 0 failures)

### Kernel model (`capability-core`)
A single-threaded, in-process capability kernel with:
- CSpace (capability space) per task, 256-slot table
- 5 object types: Task, Endpoint, MemRegion, GrantRoot, Creator
- 7 rights: READ, WRITE, CONTROL, SEND, RECV, GRANT, RECEIVE
- Authority invariants I1-I6: least authority (I1), monotonic rights (I2), expiry inheritance (I3), grant-root derivation (I4), expiry never extendible (I5), I6 (grant consent)
- TLA+ model-checked: 331k states, 0 invariant violations (2 tasks, 3 slots)
- Batched submission: one kernel crossing for N ops (io_uring pattern)

### Services built on the kernel
| Service | Tests | What it proves |
|---------|-------|----------------|
| IPC (endpoints) | 7 | Capability-scoped SEND/RECV, narrowed copies, FIFO delivery |
| Object store | 8 | Content-addressed immutable blocks, COW layers, WAL index |
| Packages | 7 | Content-addressed install, manifest-gated caps, exec demo |
| System update | 5 | Staged generations, health-gated activation, auto-rollback |
| Resources | 4 | Hierarchical budgets, kernel-truth metering, revocation |
| Network (loopback) | 4 | Capability-scoped sockets, audit-trail path reconstruction |
| Devices | 4 | Typed interfaces (Block/Net/Gpu), crash containment |
| Supervision tree | 4 | Circuit breaker, bounded restart, escalation, forensic audit |
| Grant policy | 5 | Role-shaped grants, ephemeral/persistent, two-party confirm |
| Anomaly monitor | 3 | Op-shape profiling, deviation suspension, zero authority |
| Batched I/O | 3 | Per-entry capability checks, completions drained apart |
| Macaroon tokens | 4 | HMAC-SHA256 chain, caveat narrowing, tamper detection |

### Tooling
- `capability-audit`: reachable-authority CLI, `--graph` flag for capability visualization
- `aegis-shell`: interactive demo exercising IPC, grants, anomaly monitoring
- Model-doc sections in `spec/capability-model.md` for every implemented claim

## What doesn't exist (honest list)

| Claim | Status | Why it's missing |
|-------|--------|-----------------|
| Real hardware isolation | Not built | In-process model only; no address spaces, IOMMU, or page tables |
| seL4-class formal proof | Not built | TLA+ model-checking (finite instance), not inductive proof |
| POSIX filesystem projection | Not started | Would project object store into file semantics |
| Real network driver | Not started | Loopback only; no NIC, no real packets |
| Linux/Windows compat layers | Not started | Deliberately deferred (Phase 8-9 in design doc) |
| AI orchestration layer | Not started | Phase 6 in design doc; anomaly monitor is the first step |
| Graphical shell | Not started | Phase 7 in design doc |
| Constant-time HMAC | Not built | `!=` comparison in macaroon verify; production needs `subtle` crate |
| Distributed consensus | Not started | Macaroon tokens exist; real cross-machine orchestration is Phase 11 |
| Chaos testing | Not started | Phase 10 in design doc |

## What the tests actually prove

Each test is a **contract test**: it constructs a kernel, exercises a specific operation sequence, and asserts the expected outcome (success or error). This proves the *model* implements the spec. It does not prove:

- Performance characteristics
- Behavior under concurrency (the kernel is single-threaded)
- Correctness under adversarial input beyond what the test covers
- Real-world deployment viability

The TLA+ model-check covers 331k states with 2 tasks and 3 capability slots. This is evidence, not proof. Scaling to real workloads would require either a larger model-check or an inductive proof.

## Phase status (from design doc)

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Architecture research + capability model | ✅ Done |
| 1 | Boot + minimal kernel | ✅ Done (model) |
| 2 | Userspace resource managers + supervision tree | ✅ Done (model) |
| 3 | Driver framework (IOMMU) | ⬜ Not started |
| 4 | Storage service + POSIX view | ⬜ Partial (storage yes, POSIX no) |
| 5 | Networking stack | ⬜ Partial (loopback only) |
| 6 | AI orchestration layer | ⬜ Partial (anomaly monitor only) |
| 7 | Native app model + shell | ⬜ Partial (aegis-shell demo only) |
| 8 | Linux compat | ⬜ Not started |
| 9 | Windows compat | ⬜ Not started |
| 10 | Self-healing hardening + chaos testing | ⬜ Not started |
| 11 | Distributed extension (macaroons) | 🟡 Scaffold (token crate exists, no transport) |
| 12 | Production hardening | ⬜ Not started |

## Commits (this session)

| Hash | Description |
|------|-------------|
| `2388c74` | Network crate (loopback stack, 4 contract tests) |
| `e4bda96` | Device interfaces + graphics compositor (4 tests) |
| `4e2fdbb` | Supervision-tree crate (circuit breaker, 4 tests) |
| `45d1d47` | Two-party confirmation + anomaly monitor (6 tests) |
| `777b037` | Batched I/O submission (io_uring pattern, 3 tests) |
| `2f2eeea` | Capability-graph debug tool + README |
| `fccfac4` | Package-driven exec demo (1 test) |
| `ee3865b` | Macaroon capability tokens (4 tests) |

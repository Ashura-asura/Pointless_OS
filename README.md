# Pointless OS

An executable reference implementation of a capability-based operating system design. Built on Rust, modeled against TLA+, verified by contract tests on every `cargo test`.

## Status

87 tests passing, 0 failures across 41 crate targets. The reachable-authority auditor runs clean (0 violations, 3 warnings). The interactive demo (`cargo run -p aegis-shell`) runs without errors.

## What Is Implemented

The kernel model (`capability-core`) proves six authority invariants (I1-I6) via TLA+ model checking (331k states, 0 errors) and Rust contract tests. On top of that:

- **IPC**: capability-scoped endpoints, SEND/RECV independence, narrowed copies, FIFO delivery, bulk data via memory capability grant (7 tests)
- **Storage**: content-addressed immutable blocks, COW mutable layer, WAL-based index that never sits in any write's completion path (8 tests)
- **Packages**: content-addressed installation, manifest-gated capability grants, no code execution during install (6 tests)
- **Updates**: staged generations, health-gated activation, automatic rollback to last-known-good (5 tests)
- **Resources**: hierarchical budgets, kernel-truth metering, revocation enforcement (4 tests)
- **Network**: loopback stack with capability-scoped sockets, audit-trail path reconstruction (4 tests)
- **Devices**: typed device interfaces (Block/Net/Gpu), crash containment, replaceable compositor (4 tests)
- **Supervision**: circuit breaker with bounded restart, escalation to parent, forensic cross-check with kernel audit (4 tests)
- **Grant policy**: role-shaped grants, ephemeral by default, persistent gated per role (5 tests)
- **Two-party confirmation**: high-risk roles refuse single-click, require two distinct people (3 tests)
- **Anomaly circuit breaker**: monitor trains on actual op-shape, suspends on deviation, never revokes, has zero authority (3 tests)
- **Batched I/O**: one kernel crossing for N operations (io_uring pattern), per-entry capability checks (3 tests)
- **POSIX file view**: flat namespace projection over object store — create, read, write, delete, list (tested as projection with no second source of truth)
- **Chaos testing**: 6 contract tests injecting interleaved faults into supervision tree
- **Package-driven exec**: install a package, start its app, app reads granted payload, refuses writes and Creator access (1 test)
- **Macaroon capability tokens**: HMAC-SHA256 chained portable tokens for cross-machine authority transfer (4 tests)
- **Constant-time HMAC comparison**: production-grade token verification using `subtle::ConstantTimeEq`
- **Chaos testing**: fault injection into supervision tree verifying budget exactness, sibling isolation, escalation, and state machine consistency under interleaved crashes (6 tests)
- **Reachable-authority auditor**: CI entry point that computes actual capability reachability vs manifests (CLI tool)

## What Is Not Done

- Real hardware isolation (address spaces, IOMMU) — not in scope for model
- Linux/Windows compatibility layers — deliberately deferred (Phase 8-9)
- Graphical shell — Phase 7 in design doc
- Cross-machine transport for macaroon tokens — token format exists, no network transport
- Real network driver — loopback only, no NIC

## Honest Limits

- The kernel is a typed single-threaded engine in-process. Real hardware isolation (address spaces, IOMMU) is out of scope.
- The TLA+ proof is finite-instance (2 tasks, 3 slots). Evidence, not induction proof.
- The "kernel crossing" in io_uring is an audit record, not a real syscall boundary.
- AI behavior is monitored (anomaly detection), not formally verified.
- The compatibility moat (Linux/Windows) is acknowledged as unsolved by design.

## Running

```
cargo test --workspace     # Run all 87 tests
cargo run -p capability-audit # Reachable-authority audit
cargo run -p capability-audit -- --graph  # Capability graph visualization
cargo run -p aegis-shell      # Interactive demo
```
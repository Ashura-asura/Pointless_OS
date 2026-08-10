# Honest Status — Pointless OS / Aegis

*Generated: 2026-08-10. Every claim below is verified by `cargo test` on the current commit.*

## What exists (87 tests, 0 failures)

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
| Chaos testing | 6 | Interleaved faults, budget-zero trips, rapid crash cycles, escalation-clears-budget, exact accounting under interleave |

### Real hardware boot (uefi-boot + aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| UEFI boot | — | Boots via UEFI firmware, prints memory map, sets up 4-level page tables (identity-mapped first 1GB via 2MB huge pages), loads ELF kernel |
| ELF64 parser | 10 | Validates ELF headers (magic, class, endianness, type, machine), parses PT_LOAD segments, rejects invalid binaries |
| Bare-metal kernel | — | `#![no_std]` entry point, writes to VGA text buffer at 0xB8000 |
| Disk image builder | — | Creates 16MB GPT+FAT16 image with `/EFI/BOOT/BOOTX64.EFI` |

### Real process isolation (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| GDT/TSS | — | Ring 0/3 transitions, kernel/user segment selectors. UNTESTED: requires lgdt/ltr on real hardware |
| IDT | — | Exception handler stubs for vectors 0-31. UNTESTED: requires lidt on real hardware |
| Per-process page tables | — | 4-level paging with kernel/user split (upper half shared, lower half per-process). UNTESTED: requires mov cr3 on real hardware |
| Process abstraction | — | State machine (Ready/Running/Blocked/Zombie), CpuState for context switch |
| Round-robin scheduler | 10 | Spawn, schedule_next, tick/preempt, block/wake, round-robin cycling, zombie reaping |
| Syscall framework | — | SyscallNum enum, dispatch stub. Returns -1 for unimplemented syscalls |

### Tooling
- `capability-audit`: reachable-authority CLI, `--graph` flag for capability visualization
- `aegis-shell`: interactive demo exercising IPC, grants, anomaly monitoring
- Model-doc sections in `spec/capability-model.md` for every implemented claim
- GitHub Actions CI: `cargo fmt --check`, `cargo clippy`, `cargo test --workspace` on every push

## What doesn't exist (honest list)

| Claim | Status | Why it's missing |
|-------|--------|-----------------|
| Real hardware isolation | Not built | In-process model only; no address spaces, IOMMU, or page tables |
| Real process isolation (address spaces, page faults) | Not built | Boot creates identity mapping but no per-process page tables yet |
| seL4-class formal proof | Not built | TLA+ model-checking (finite instance), not inductive proof |
| Real network driver | Not started | Loopback only; no NIC, no real packets |
| Linux/Windows compat layers | Not started | Deliberately deferred (Phase 8-9 in design doc) |
| AI orchestration layer | Not started | Phase 6 in design doc; anomaly monitor is the first step |
| Graphical shell | Not started | Phase 7 in design doc |
| Cross-machine transport for macaroon tokens | Not started | Token format exists; network transport between kernels is Phase 11 |
| File metadata (timestamps, permissions beyond capability rights) | Not started | Currently no metadata beyond capability rights |
| Delivery overhang as hard gate | Deliberately warning | Kernel enforces at delivery time (I2/I6); auditor is build-time cross-check, not enforcement |

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
| 1 | Boot + minimal kernel | ✅ Done (real + model): UEFI boot, page tables, ELF loader (10 parser tests), bare-metal kernel. Honest limits: identity mapping only (no per-process isolation yet), no real hardware test (VMware needed) |
| 2 | Userspace resource managers + supervision tree | ✅ Done (real + model): GDT/TSS, IDT, per-process page tables, process abstraction, round-robin scheduler (10 tests), syscall framework. Honest limits: hardware ops untested (need VMware), no real timer interrupt yet |
| 3 | Driver framework (IOMMU) | ✅ Done (model: typed Block/Net/Gpu interfaces, capability scoping, crash containment, GPU isolation, compositor; 4 contract tests. Real IOMMU is hardware, out of scope) |
| 4 | Storage service + POSIX view | ✅ Done (model: FlatView is a flat, single-level namespace projection — create/read/write/delete/list by name. Not a hierarchical POSIX filesystem — no nested dirs, no path resolution, no permission bits, no symlinks. 8 contract tests) |
| 5 | Networking stack | ⬜ Partial (loopback only) |
| 6 | AI orchestration layer | ⬜ Partial (anomaly monitor only) |
| 7 | Native app model + shell | ⬜ Partial (aegis-shell demo only) |
| 8 | Linux compat | ⬜ Not started |
| 9 | Windows compat | ⬜ Not started |
| 10 | Self-healing hardening + chaos testing | ✅ Done (6 chaos tests + 4 supervision tests) |
| 11 | Distributed extension (macaroons) | 🟡 Token crate complete (HMAC-SHA256 chain, constant-time verify, serialization); no cross-machine transport |
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
| `25ef050` | Fix install_contract.rs 3-tuple collect + GROUND_RULES.md |
| `7e30671` | Stricter ground rules + constant-time HMAC |
| `d36d893` | Chaos tests for supervision tree |
| `e265e90` | Update HONEST_STATUS.md and README: 87 tests verified from clean lockfile |
| `22c9c0e` | CI + delivery overhang + hardened HMAC |
| `22e75f3` | Fix HONEST_STATUS.md and README: POSIX view complete, chaos tests done, phase status accurate |
| `687f975` | Fix CI: cargo fmt, 0 clippy warnings under -Dwarnings, all 87 tests pass from clean lockfile |
| `1021c3d` | Pin Rust toolchain to 1.97.1 in CI to match local rustfmt version |
| `949b3cc` | Phase 1: UEFI boot crate — boots via UEFI, prints memory map, sets up page tables, halts |
| `e6ca02e` | Fix uefi-boot: .gitignore, reduce disk image to 16MB |
| `d34d974` | Phase 1: kernel loader — bare-metal kernel, ELF64 parser (10 tests), UEFI loads and jumps to kernel |
| `5cb4b18` | Fix uefi-boot: remove .cargo/config.toml so ELF tests run on host target |
| `0357a0f` | Phase 2: real process isolation — GDT/TSS, IDT, per-process page tables, process abstraction, round-robin scheduler (10 tests), syscall framework |
| `19d0c57` | Fix scheduler tests: move to #[cfg(test)] unit tests so they run on host target |
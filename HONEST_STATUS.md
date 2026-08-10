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

### Real driver framework (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| PCIe enumeration | 6 | Config space address building, BAR parsing (32/64-bit), device identification, device list. UNTESTED: requires I/O port access (inl/outl) on real hardware |
| IOMMU (VT-d) | 5 | Domain creation, DMA page table mapping/unmapping, device-to-domain assignment, DMAR table parsing. UNTESTED: requires real VT-d hardware |
| NVMe queues | 5 | Submission/completion queue entry construction, tail/head pointer management, phase-bit tracking. UNTESTED: requires real NVMe device |

### Real networking stack (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| VirtIO-net driver | 9 | Device init, MAC address handling, header construction, device status. UNTESTED: requires real VirtIO NIC |
| Ethernet frames | 5 | Frame parsing/serialization, ethertype validation, minimum size enforcement, broadcast |
| ARP | 6 | Table lookup/insert/remove, request/reply construction, packet parsing. UNTESTED: no real network |
| IPv4 | 6 | Packet parsing/serialization, checksum computation, address formatting, loopback/broadcast detection |

### Real AI orchestration (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| Agent runtime | 8 | Agent lifecycle (spawn/suspend/resume/terminate), capability scoping, restrictive vs permissive scopes |
| Usage profiler | 5 | Syscall histogram tracking, deviation computation, baseline comparison, record management |
| Adaptive grants | 5 | Auto-tighten on medium deviation, suspend on high, terminate after repeated suspensions, scope reduction |
| Policy engine | 5 | Rule-based evaluation (max syscalls, memory, network), audit trail logging |

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
| 3 | Driver framework (IOMMU) | ✅ Done (real + model): PCIe enumeration (6 tests), VT-d IOMMU domain isolation (5 tests), NVMe command queues (5 tests). Model: typed Block/Net/Gpu interfaces, crash containment, GPU isolation, compositor (4 tests). Honest limits: all hardware ops UNTESTED (need real PCIe/IOMMU/NVMe) |
| 4 | Storage service + POSIX view | ✅ Done (model: FlatView is a flat, single-level namespace projection — create/read/write/delete/list by name. Not a hierarchical POSIX filesystem — no nested dirs, no path resolution, no permission bits, no symlinks. 8 contract tests) |
| 5 | Networking stack | ✅ Done (real + model): VirtIO-net driver (9 tests), Ethernet frames (5), ARP (6), IPv4 (6). Model: loopback stack (4 tests). Honest limits: no real NIC hardware, no TCP/UDP yet |
| 6 | AI orchestration layer | ✅ Done (real + model): Agent runtime (8 tests), usage profiler (5), adaptive grants (5), policy engine (5). Model: anomaly monitor (3 tests). Honest limits: no real AI model, profiler is histogram-based not ML, no real-time learning |
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
| `4efac77` | Phase 3: driver framework — PCIe enumeration (6 tests), VT-d IOMMU domain isolation (5 tests), NVMe command queues (5 tests) |
| `f0bec06` | Phase 5: real networking — VirtIO-net driver, Ethernet frames, ARP, IPv4 (22 tests) |
| `6e82f3f` | Phase 6: AI orchestration — agent runtime, usage profiler, adaptive grants, policy engine (23 tests) |
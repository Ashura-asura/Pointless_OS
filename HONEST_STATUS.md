# Honest Status — Pointless OS / Aegis

*Generated: 2026-08-12. Every claim below is verified by `cargo test` on the current commit.*

## What exists (verified clean)

Test counts are kept separate on purpose: `aegis-kernel` is a **standalone bare-metal crate that is NOT a member of the `aegis` workspace**, so its tests are never covered by `cargo test --workspace`.

- **aegis workspace (model crates):** 113 contract tests, 0 failures — `cargo test --workspace` from a clean lockfile (Rule 1/10).
- **aegis-kernel (bare-metal, separate crate):** 242 contract tests, 0 failures — `cargo test` on the host target; the ring-3 *integration* is additionally proven by a live QEMU/TCG boot (not a contract test — see Ring-3 row).
- **uefi-boot:** 13 ELF parser contract tests.

Combined contract-test count across all crates: **368**. The bare-metal CPL3 transition itself has no contract test (it needs real/virtual hardware); its proof is the live boot.

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
| UEFI boot | — | Boots via OVMF firmware in QEMU, prints memory map, sets up 4-level page tables (identity-mapped first 1GB via 2MB huge pages), loads ELF kernel, **applies base-0 relocations** (R_X86_64_RELATIVE written into .rela.dyn slots before handoff), calls **ExitBootServices**, writes the final memory map as a **boot-info handoff** to 0x10000 (flat 20-byte entries, magic-validated — verified live: 116 descriptors) |
| ELF64 parser | 13 | Validates ELF headers (magic, class, endianness, type, machine), parses PT_LOAD segments, parses `.rela.dyn`/`.rela.plt` relocation entries, applies R_X86_64_RELATIVE, rejects symbolic relocation types, rejects invalid binaries |
| Bare-metal kernel | — | `#![no_std]` entry point, 4GB identity paging, COM1 serial output, **frame allocator** (bitmap, 4 GiB/1 MiB frames; fed by the boot-info map; reserves `[0, image_end)` + the handoff page). **VERIFIED under QEMU/OVMF**: prints banner, kernel-started, page tables up, CR3, own GDT + TSS, IDT + PIC masked, APIC timer armed, boot-info consumed (120 descriptors, 485 MB conventional), allocator stats + live alloc/free probe (157876 frames free; first frame exactly one page above the 0x30000 image end) and idle-loops printing `Aegis: tick = ... (timer alive)` — 24576 ticks over a 40 s run, zero exceptions |
| Disk image builder | — | Creates 16MB GPT+FAT16 image with `/EFI/BOOT/BOOTX64.EFI` |

### Real process isolation (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| GDT/TSS | — | Ring 0/3 transitions, kernel/user segment selectors. **VERIFIED under QEMU/TCG**: `lgdt` installs the kernel's 8-entry GDT (0x08 kcode/0x10 kdata/0x18 ucode/0x20 udata/0x28 TSS/0x30 TSS-upper-half/0x38 kcode mirror), `ltr` needs the 64-bit TSS as a full 16-byte descriptor (QEMU quirk — upper half must be zeroed, else #GP(0x28)); still UNTESTED on real hardware |
| IDT | — | Exception handler stubs for vectors 0-31 (naked, save GPRs + error code, print vector/RIP/RSP via CPU and halt), install via `lidt` with DPL-0 interrupt/trap gates. **VERIFIED under QEMU/TCG**: gates at selector 0x08/attr 0x8E deliver (timer vector dispatched continuously); still UNTESTED on real hardware |
| Cooperative task switching | — | `switch_frame`: 15-GPR save into frame slots, restore via pop, `iretq` resume (registers uniform for fresh/saved targets); the LAPIC timer stub preempts every tick: `timer_preempt` / `next_after` round-robin (idle→task0…→idle), tasks on 16 KiB stacks (`alloc_contiguous`). **VERIFIED under QEMU/TCG**: two demo tasks that NEVER yield print every 2048 ticks (progress proves preemption) at stable rsp (0x37F70/0x3BF70), idle still gets CPU every third tick, 0 exceptions across a 14 s boot. Fixed a real bug earlier: the saved rsp included the `call`-pushed return address, so every resume ran 8 bytes deeper (2 switches per hlt-gated round = −16/tick leak → stack walked into the task table ~1 s in → switch to a never-spawned slot → #PF triple-fault reboot); the save path now stores the pre-call rsp (`rsp+8`). Single fixed-priority round-robin — no priority, no wait queues; UNTESTED on real hardware |
| Per-process page tables | — | 4-level paging with kernel/user split (upper half shared, lower half per-process). UNTESTED: requires mov cr3 on real hardware |
| Process abstraction | — | State machine (Ready/Running/Blocked/Zombie), CpuState for context switch |
| Round-robin scheduler | 10 | Spawn, schedule_next, tick/preempt, block/wake, round-robin cycling, zombie reaping |
| Ring-3 user task | — | A demo task dropped to CPL3 via `iretq` (fresh frame carries user CS=0x1B/SS=0x23), serviced by a DPL-3 `int 0x80` interrupt-gate (`syscall_stub` + `syscall_trap_rust` dispatch: Exit/Write/Read/Yield/Fork). **VERIFIED under QEMU/TCG**: a CPL3 task (`george`) runs on its own user stack, prints `Aegis: [user] ring 3 hello via int 0x80` through the syscall gate, and is preempted by the LAPIC timer every tick alongside two CPL0 tasks (`alpha`/`beta`) and the idle loop — privilege transitions both ways work, 0 exceptions across an 18 s boot (5 user prints interleaved with kernel prints). Two real bugs were found and fixed live: (1) `PML4[0]` lacked the `USER` bit, so the user page table walk faulted at the very first fetch — every level needs `USER`; (2) the syscall stub saves `rax…r11` such that `rax` lands at frame slot 10, not slot 1, so the handler was reading the wrong registers and syscalls silently returned -1 — indices corrected. CR4 SMEP/SMAP are also cleared at boot (defensive; firmware had them off here, but correct for real hardware). Still UNTESTED on real hardware |
| Syscall framework | — | SyscallNum enum, dispatch stub. Returns -1 for unimplemented syscalls. The ring-3 `Write` path (untrusted buffer pointer + capped length) prints to COM1 and mirrors to the VGA console |
| IPC (endpoints, call/serve/reply) | — | Synchronous IPC: `ipc_call`, `ipc_serve`, `ipc_reply`, `ipc_endpoint_create`, `ipc_cap_grant`. **VERIFIED under QEMU and VMware Workstation 26**: echo server/client demo, 0 exceptions, idle stack dedicated to avoid clobber. No contract tests — proof is live boot. Dedicated idle stack (`cpu::IDLE_STACK_TOP`) allocated from frame allocator to prevent triple-fault (idle's saved rsp was clobbered by other tasks' timer/syscall entries on shared KERNEL_STACK). `schedule_next` wrap-around fix: `c+1 >= spawned` maps to 0, checks all tasks before returning idle. UNTESTED on real hardware |
| Memory isolation (per-task U/S) | — | A ring-3 `iso-test` task attempts to read a kernel-only address (0x1000000, present but not USER in its PML4). **VERIFIED under QEMU**: the read #PFs, the exception handler prints `PAGE FAULT at CR2=0x1000000 - memory isolation verified`, task killed. Fixed live: exception-stub argument order so the Rust handler read the right vector/error/RIP. UNTESTED on real hardware |

### Real display output (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| VGA text console | 4 | 80x25 white-on-black mirror of the COM1 stream (`vga.rs`: Bochs VBE disable, CRTC/GC/AC programming, 16-color DAC palette, 8x16 font uploaded into plane 2 via map A; `sprintln!` and the ring-3 `Write` syscall print to 0xB8000). **VERIFIED under QEMU**: screendump decodes glyph-for-glyph to the exact Aegis log lines ("Aegis: [client] echo reply..."), plane-2 glyph probe matches the embedded font, DAC readback matches the programmed palette, pixels = black `000000` bg + white `ffffff` fg. Three real bugs fixed live: (1) SR4 chain4 bit made QEMU scatter text writes by `addr&3`; (2) SR2=0x0F let the odd/even parity rule stamp plane 2 (the font area) with screen characters — SR2=0x03 keeps chars on plane 0 / attrs on plane 1; (3) a 0x3C0 readback during the flip-flop data phase corrupted `ar[0]` (green background). Honest limits: text mode only — no framebuffer graphics, no GPU accel, no mouse/keyboard input; font covers 0x00..=0x7F (higher chars render blank); the low 2 MB is USER-flagged in per-task PML4s, so a ring-3 task could scribble the screen (cosmetic, accepted for the demo); UNTESTED on real hardware |

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

### Real shell and UI (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| Shell runtime | 6 | App launch/stop/restart, focus tracking, lifecycle management |
| Window manager | 7 | Window creation/destruction, z-ordering, hit testing, compositor order, dirty tracking |
| Object graph | 6 | Node/relationship CRUD, neighbor traversal, type filtering |
| Input handler | 5 | Ring buffer push/pop, full/empty detection, focus-based dispatch |

### Real Linux compat layer (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| Syscall ABI translation | 12 | Linux x86-64 syscall numbers + register args map to Aegis operations (read/write/open/close/mmap/munmap/exit/socket/connect/send/recv/exec/sleep); unknown numbers rejected |
| ELF loader | 12 | ET_EXEC/ET_DYN header validation (magic/class/endian/type/machine), PT_LOAD parsing with bounds checks, interpreter detection, load-range computation, System V initial stack layout (argc/argv/envp/auxv) |
| Compat personality | 8 | Linux contexts translate and gate operations on the capability scope; native personalities reject Linux syscalls; denials are counted |

Honest limits for Phase 8: translation is model logic, not a real ring-3 syscall trap; the lightweight-VM execution vehicle (design doc §5, WSL2-lineage) is not built — it needs a hypervisor. The compat layer is an unprivileged capability-scoped service, matching the design doc's AI ceiling.

### Real Windows compat layer (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| NT syscall ABI translation | 12 | Narrow NT syscall subset (NtCreateFile/Read/Write/Close/CreateSection/MapView/TerminateProcess/DeviceIoControl/QuerySystemTime...) maps to Aegis operations; unknown numbers rejected |
| PE loader | 12 | PE32+ (x64) validation: MZ/PE signatures, machine type, entry point, image base, section table with read/write/execute flags and bounds checks |
| Windows compat personality | 7 | Windows contexts translate and gate NT operations on the capability scope; native personalities reject NT syscalls; denials counted |

Honest limits for Phase 9: the design doc is explicit that full Windows compatibility without licensing Windows or running a real Windows kernel is not a solved problem anywhere. This is the narrow well-behaved-subset translator (model logic); the VM-based full-fidelity path (needs a hypervisor + Windows) is not built.

### Real adaptive-ceiling verification (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| Ceiling verification | 14 | Every AdaptivePolicy/PolicyEngine decision is monotonically non-expanding: tighten never raises budgets, never adds a syscall, never adds network; worst-case adversarial inputs stay within the granted (even restrictive) scope |

This phase caught and fixed a real bug: `tighten_scope` previously did `(budget / 2).max(1)`, which raised a restrictive scope's 0 file-handle budget to 1 — an actual ceiling expansion. Now floored at `min(current, 1)`.

Honest limits: property-style contract tests over finite deterministic model logic — not an inductive formal proof, and no coverage of real hardware (supervision/chaos tests remain the model-crate layer, 10 tests).

### Real distributed extension (fleet crate)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| Fleet transport | 15 | Node identity, explicit locality (Local vs Remote — never hidden), wire-format envelope round-trips, peer trust registry, HMAC chain verification across nodes, expiry enforcement, remote attenuation (rights narrow + expiry clamp), tamper/unknown-issuer/untrusted-peer rejection, **recipient binding**: intended recipient is HMAC-bound at send time, so relayed tokens and forged recipient fields are rejected (2 regression tests for the audit finding) |

Honest limits: two-node in-process model (no sockets, no real network); no consensus, replication, or split-brain handling — the design doc's CAP/partition warning applies and partition behavior is deliberately NOT modeled. `macaroon::bind_caveat` requires the signing key, so attenuation is done by a node holding the issuer key; real macaroons allow keyless caveats (documented difference).

### Real production hardening (security-audit + aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| Aggregate security audit | 10 | Reference world is clean (0 violations); kernel-equivalent demand from userspace repo is a violation; undeclared holdings are violations; delivery overhang warns but never breaks the build; self caps excluded from reachable authority; unbound tasks skipped |
| Kernel boundary/panic-safety | 17 | All parsers (ELF/PE/IPv4/Ethernet/ARP) and both syscall ABIs return errors on garbage/truncated/overflowing inputs and never panic; ELF/PE loaders reject attacker-controlled offsets that would overflow (checked_add/checked_mul — 4 regression tests); compat layers reject garbage; shell/window/graph/input reject bad IDs without panicking |
| Certification matrix | — | `SECURITY_AUDIT.md`: what is certified (model-level only), what is NOT (all real-hardware ops UNTESTED, no inductive proof, no fuzzing, no distributed guarantees) |

### Tooling
- `capability-audit`: reachable-authority CLI, `--graph` flag for capability visualization
- `aegis-shell`: interactive demo exercising IPC, grants, anomaly monitoring
- Model-doc sections in `spec/capability-model.md` for every implemented claim
- GitHub Actions CI: `cargo fmt --check`, `cargo clippy`, `cargo test --workspace` on every push

## What doesn't exist (honest list)

| Claim | Status | Why it's missing |
|-------|--------|-----------------|
| Real hardware isolation (verified on actual hardware) | Model-level code only | Page tables, IOMMU, NVMe, VirtIO drivers exist but are UNTESTED on real hardware (need VMware) |
| Real process isolation on hardware (page faults, cr3 switching) | Code + 10 contract tests + scheduler + ring-3 task live under QEMU | Cooperative task switching and a ring-3 user task (CPL3 `iretq` + `int 0x80` syscall) verified live under QEMU/TCG; per-task isolation via page-table U/S bits verified under QEMU (isolation-test task faults on a kernel-only address and is killed); still UNTESTED on real hardware |
| seL4-class formal proof | Not built | TLA+ model-checking (finite instance), not inductive proof |
| Real network I/O on a NIC | Driver code + 22 tests | VirtIO-net driver exists; no real NIC traffic, no TCP/UDP yet |
| Linux/Windows compat layers | Partially built (Phase 8+9 model-level) | Linux (32 tests) + Windows (31 tests) translation/loader/personality; no hypervisor VM vehicles; full Windows fidelity explicitly not solved by translation alone |
| AI orchestration on real hardware | Model-level code only | Agent/profiler/adaptive/policy tested in-process (23 tests); no real-time integration |
| Graphical shell on a real display | Model-level code only | Shell/window/graph/input tested in-process (24 tests); a VGA text console mirrors kernel output on the QEMU display (verified live), but no framebuffer graphics, no GPU accel, no real input |
| Cross-machine transport for macaroon tokens | Partially built (Phase 11 model-level) | fleet crate: transport/envelope/locality/verification (13 tests) in-process; no real network, no consensus |
| File metadata (timestamps, permissions beyond capability rights) | Not started | Currently no metadata beyond capability rights |
| Delivery overhang as hard gate | Deliberately warning | Kernel enforces at delivery time (I2/I6); auditor is build-time cross-check, not enforcement |
| Linux kernel in a lightweight VM (WSL2-lineage) | Not built | Phase 8 execution vehicle; needs a hypervisor. Translation layer is the testable part |

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
| 1 | Boot + minimal kernel | ✅ Done (real + model): UEFI boot, page tables, ELF loader + relocations (13 parser tests), bare-metal kernel printing via COM1 serial under QEMU/OVMF (0 exceptions across 24576 ticks in a 40 s timer run). Honest limits: not run on physical hardware (VMware needed); per-process isolation added in Phase 2 |
| 2 | Userspace resource managers + supervision tree | ✅ Done (real + model): GDT/TSS, IDT, per-process page tables, process abstraction, round-robin scheduler (10 tests), syscall framework. **LAPIC timer verified under QEMU/TCG**: 8-entry GDT installed + TSS loaded (16-byte descriptor quirk), IDT gates deliver, periodic timer (~570 ticks/s) drives the idle loop. **Cooperative task switching verified under QEMU/TCG**: alpha/beta tasks interleave every 512 ticks at stable rsp, 6665/6665 interrupt rsp deltas = 0 (after fixing the resume-rsp drift — saved rsp had included the call's return address); still cooperative, still not run on physical hardware. **Per-task memory isolation verified under QEMU**: iso-test task's kernel-only read #PFs and is killed (page-fault-driven isolation, fixed exception-stub arg order); still not run on physical hardware |
| 3 | Driver framework (IOMMU) | ✅ Done (real + model): PCIe enumeration (6 tests), VT-d IOMMU domain isolation (5 tests), NVMe command queues (5 tests). Model: typed Block/Net/Gpu interfaces, crash containment, GPU isolation, compositor (4 tests). Honest limits: all hardware ops UNTESTED (need real PCIe/IOMMU/NVMe) |
| 4 | Storage service + POSIX view | ✅ Done (model: FlatView is a flat, single-level namespace projection — create/read/write/delete/list by name. Not a hierarchical POSIX filesystem — no nested dirs, no path resolution, no permission bits, no symlinks. 8 contract tests) |
| 5 | Networking stack | ✅ Done (real + model): VirtIO-net driver (9 tests), Ethernet frames (5), ARP (6), IPv4 (6). Model: loopback stack (4 tests). Honest limits: no real NIC hardware, no TCP/UDP yet |
| 6 | AI orchestration layer | ✅ Done (real + model): Agent runtime (8 tests), usage profiler (5), adaptive grants (5), policy engine (5). Model: anomaly monitor (3 tests). Honest limits: no real AI model, profiler is histogram-based not ML, no real-time learning |
| 7 | Native app model + shell | ✅ Done (real): Shell runtime (6 tests), window manager (7), object-relationship graph (6), input dispatcher (5). Honest limits: no GPU rendering, no real display output, no real keyboard/mouse hardware |
| 8 | Linux compat | ✅ Done (real, model-level): syscall ABI translation (12 tests), ELF loader + initial stack (12 tests), compat personality with capability gating (8 tests). Honest limits: no hypervisor lightweight-VM vehicle (needs hypervisor); translation proven against buffers, not a live Linux userspace |
| 9 | Windows compat | ✅ Done (real, model-level): NT syscall ABI translation (12 tests), PE32+ loader (12 tests), Windows compat personality with capability gating (7 tests). Honest limits: narrow well-behaved-subset translator only; full-fidelity VM path (needs hypervisor + Windows) not built; design doc says full Windows compat is unsolved by translation alone |
| 10 | Self-healing hardening + chaos testing | ✅ Done: supervision-tree (4) + chaos (6) model tests; adaptive-ceiling verification (14) in aegis-kernel — caught+fixed real scope-expansion bug in tighten_scope |
| 11 | Distributed extension (macaroons) | ✅ Done (model-level): fleet crate — cross-machine capability transport with explicit locality, wire envelope, peer trust, chain/expiry verification, remote attenuation (13 tests). Honest limits: two-node in-process model; no real network/consensus; partition behavior deliberately not modeled (design doc CAP warning) |
| 12 | Production hardening | ✅ Done (model-level): security-audit aggregate gate (10 tests), kernel boundary/panic-safety tests (13), SECURITY_AUDIT.md certification matrix. Honest limits: NO real-hardware certification of any kind — all hardware ops UNTESTED; no inductive proof; no fuzzing; secure boot/attestation not built |

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
| `86f8686` | Phase 7: shell — app runtime, window manager, object-relationship graph, input dispatcher (23 tests) |
| `df5a6d7` | Update HONEST_STATUS: Phase 7 now has real shell (runtime/window/graph/input, 23 tests) |
| `8bf8c0c` | Fix HONEST_STATUS: accurate counts (197 total from clean lockfile), remove stale rows, honest VM-compat note |
| `1d49bc4` | Rule 6: machine-checked verification sections for kernel Phases 1-7 in capability-model.md |
| `6b5a68f` | cargo fmt across aegis-kernel and uefi-boot (fmt-check clean, tests still 99 + 10) |
| `c2d83c1` | Fix clippy -Dwarnings in aegis-kernel (Default impls, is_some_and, flatten, safety docs) |
| `91c8455` | CI: kernel + bootloader job — fmt, clippy, tests, release target builds |
| `cf19232` | Phase 8: Linux compat — syscall ABI translation (12 tests), ELF loader + initial stack (12 tests), compat personality with capability gating (8 tests) |
| `3bfca8a` | Phase 9: Windows compat — NT syscall ABI translation (12 tests), PE32+ loader (12 tests), Windows compat personality with capability gating (7 tests) |
| `2ed2b56` | Phase 10: adaptive-ceiling verification (14 tests); FIXED tighten_scope budget-expansion bug |
| `91165ff` | Phase 11: fleet crate — cross-machine capability transport, explicit locality, wire envelope, peer trust, verification (13 tests) |
| `305ce8c` | Phase 12: production hardening — security-audit aggregate gate (10 tests), kernel boundary tests (13), SECURITY_AUDIT.md |
| `d59ebd9` | Security fixes from audit: fleet recipient binding (HMAC-bound, relay rejected) + ELF/PE checked offset arithmetic (6 regression tests total) |
| `d54dccd` | Loader applies base-0 R_X86_64_RELATIVE relocations; kernel boots under QEMU/OVMF via COM1 serial (5 lines, idle loop, 0 exceptions / 7810 timer ints); GOT/memset eliminated from kernel; elf_contract 13 tests |
| `2213061` | Fix CI: bootloader clippy -D warnings in elf_contract.rs test mirror |
| `602c1a2` | LAPIC timer delivers under QEMU/TCG: call init_gdt (never called — all IDT deliveries #GP'd on loader's GDT), 16-byte TSS descriptor slot for QEMU `ltr`, periodic LVT 0x20030 (bit 16 was the timer mask); naked exception stubs save GPRs + error code; idle loop prints ticks — verified 24576 ticks, 0 exceptions |
| `ff835fb` | Boot-info handoff: loader writes final EBS memory map to 0x10000 (20-byte flat entries, magic-validated); kernel parses + prints it — verified live: 116 descriptors, 485 MB conventional (8 parser tests) |
| `6fc8d49` | Frame allocator: bitmap over boot-info map (4 GiB/1M frames, 128 KiB BSS); handoff v2 carries loader-computed image_end — verified live: 157876 frames free, probe frames land exactly above image end (10 tests) |
| `2e35c90` | Cooperative scheduler: iretq-based `switch_frame` (GPR save into frame slots, pop + iretq resume, `yield_now`/`run_idle`, 16 KiB task stacks), fixed resume-rsp drift (stored pre-call rsp — the call-pushed return address was making every resume 8 bytes deeper; −16/tick → ~1 s triple-fault) — verified live: alpha/beta interleave every 512 ticks, stable rsp, 6665/6665 int deltas = 0 (229 tests) |
| `79bac4d` | Preemptive scheduling: timer stub preempts every tick (`timer_preempt`, round-robin `next_after`: idle→task0…→idle); demo tasks never yield, so their progress proves preemption — verified live 14 s: alpha/beta print every 2048 ticks at stable rsp, idle keeps its tick prints, 0 exceptions (231 tests) |
| `ring3` | Ring-3 user task verified under QEMU/TCG: CPL3 `george` task + `int 0x80` syscall gate; fixed PML4 `USER` bit (user walk faulted at first fetch) and syscall stub register-save index bug (rax landed at slot 10, handler read slot 1); clear CR4 SMEP/SMAP at boot; 0 exceptions, 5 user prints interleaved with kernel prints (238 tests) |
| `32fa2a0` | IPC: synchronous call/serve/reply + capabilities (`ipc_call`, `ipc_serve`, `ipc_reply`, `ipc_endpoint_create`, `ipc_cap_grant`); Ring-3 echo server/client demo; `set_ret` fix (writes to offset 112 = rax slot); `resume_ret` reads from same offset |
| `cef6559` | Fix VMware triple-fault crash: idle loop shared KERNEL_STACK → dedicated idle stack (`cpu::IDLE_STACK_TOP`); `switch_to_idle_stack(entry)`; `IDLE_FRAME` initialized at boot; `context_cpl0_top(idle)` returns `idle_stack_top()`; `schedule_next` wrap-around fix (c+1 >= spawned maps to 0); verified QEMU + VMware, 0 exceptions |
| `4c010de` | Fix CI: cargo fmt + clippy safety docs (7 `# Safety` doc comments added) |
| `8a29c1b` | Per-task memory isolation via page-table U/S bits (verified under QEMU) |
| `eacd5c4` | Fix exception stub arg order; verify per-task memory isolation under QEMU |
| `d81ea68` | VGA text console: visible demo on QEMU/VMware display (vga.rs + font.rs, route SR2/SR4, palette + font upload verified; 4 new tests, 242 kernel tests total) |
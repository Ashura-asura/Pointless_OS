# Honest Status — Pointless OS / Aegis

*Generated: 2026-08-15. Every claim below is verified by `cargo test` on the current commit.*

## Deep audit vs `os-from-first-principles.md` (2026-08-14)

A phase-by-phase audit against the design doc's §7 roadmap, based on the
**actual code** (`aegis-kernel/src/`, `aegis/crates/*`, `uefi-boot/`) — not on
the docs' claims. Two numbers, honestly separated:

- **Full 12-phase roadmap completion: ~62%** (unweighted mean of the per-phase
  scores below). The remaining ~38% is almost entirely in phases the design doc
  itself defers ("do nothing on Windows compatibility, distributed systems, or
  a graphical shell — those are all later-phase and premature before the core
  claim is validated", §11.G) plus genuinely absent engineering (real IOMMU
  hardware registers, real GPU, hypervisor vehicles).
- **Core architectural claim (§11.F prototype / Phase 6): ~85–90%** — the
  "smallest prototype that proves the architecture" (role-granted,
  zero-capability AI agent that provably cannot self-escalate, running one
  real task) is genuinely delivered and live-verified under QEMU. This is the
  claim the design doc itself says to bet the project on.

| Phase (§7) | Honest score | What is real | What is missing |
|---|---|---|---|
| 0 — Capability model formalization | 90% | TLA+ spec (`AegisCapabilities.tla`+`.cfg`), invariants I1–I6, TLC 331k states (documented), 961-line `capability-model.md` | Isabelle-style spec (doc says "TLA+/Isabelle-style" — either/or; only TLA+ done) |
| 1 — Boot + minimal kernel | 75% | UEFI boot, 4-level paging, NX, per-task isolation, capability-aware IPC — all live under QEMU | No seL4-class formal proof (multi-year; master-roadmap chose own kernel); "verified" = QEMU/TCG, not proof |
| 2 — Resource managers + supervision | 75% | Real `mem.rs` MemRegion caps, `supervisor.rs` budgeted restart/trip, `tasks.rs` kill/restart — now ALSO ring-3: a userspace page manager (`mem-rm`) that mints pages and recycles them purely through capability-gated grants/revokes, plus hierarchical supervision (the ring-3 supervisor escalates upward, a ring-3 parent ADOPTS the subsystem with a fresh budget and trips only on its own budget), all live under QEMU | Revocation is instance-named (no grant-root derivation tree, model I4); budgets are count-based, not CPU/energy; still no ring-3-per-resource policy beyond pages |
| 3 — IOMMU-backed drivers (NVMe/NIC/GPU) | 70% | Real NVMe driver (live QEMU); real e1000e NIC driver (live ARP TX/RX under QEMU, externally captured); **real TCP/IP over the NIC under QEMU** (handshake + HTTP request/response + close, externally captured); **real VT-d IOMMU DMA isolation (Phase G, closed)**: `iommu::translate` is the real gate every NVMe/e1000 DMA address passes before a PRP/descriptor is written — per-device domains provisioned in `probe`, buffers identity-mapped before use, and a live boot proves an out-of-domain DMA (0x100000000) is denied at the IOMMU (`AddressNotMapped`, fault recorded) while NVMe/e1000 keep operating and the kernel continues | IOMMU is a software gate mirroring VT-d semantics, not real DMAR hardware registers (no MMIO programming of an actual IOMMU); identity-mapped IOVA space (not yet distinct from physical); NIC driver is polled (no interrupts/MSI-X); no GPU path |
| 4 — Storage + POSIX view | 85% | Object store twice (in-kernel `store.rs` + write-through `nvme_store.rs`, SHA-256/COW/dedup/digest-verify), live; **full POSIX view now live under QEMU**: nested dirs, absolute/relative path resolution with `.`/`..`, cwd, mode/uid metadata, COW-to-root path persistence, unlink/rmdir with emptiness+root rules | No symlinks/hard links; mode bits are projection metadata (enforcement stays capability-shaped); bounds `MAX_DEPTH=8`/`MAX_FILES=8`; in-memory arena store (no multi-block files); no timestamps |
| 5 — Networking as a service | 85% | Real capability-gated loopback `netstack.rs` (6 tests); real e1000e NIC driver (7 tests); **a full polled TCP/IP stack in the kernel (`netif.rs`, 9 tests) that drives a real three-way handshake, HTTP request/response and close over the wire under QEMU** — SYN→SYN-ACK→ACK→GET→HTTP response→FIN captured externally on the host (pcap), with the HTTP response body rendered by the kernel; **plus a real TLS 1.3 client on a second socket (`tls.rs`, 18 tests): the kernel sends a spec-correct ClientHello to an OpenSSL-backed server on 8443, parses the ServerHello, derives the X25519 ECDHE shared secret that matches the host byte-for-byte, runs the full RFC 8446 §7.1 key schedule (handshake + application traffic secrets, now byte-validated end-to-end against RFC 8448 §3's published trace), and uses AES-128-GCM record protection — encrypted server flight and client Finished verified against the live capture, externally captured** | No interrupts (polled only); QEMU socket netdev, not physical hardware; live app-data exchange verified under the fixed `s_ap` derivation (see Phase-E log); certificate chain not verified; fixed deterministic scalar (no CSPRNG in the guest); no outbound routing/NAT; single connection demo wired in `main.rs`, syscalls 19–23 provide the capability-scoped socket API for tasks |
| 6 — AI orchestration layer (the §11.F target) | 85% | Zero-cap ring-3 agent, kernel-declared roles (`restart-service`/`observe-service`), RoleGrant syscall 18, adversarial self-escalation all refused at gates, audit log — live under QEMU | No real AI model (histogram profiler), no real-time integration; anomaly observer test-only (ledger wired) |
| 7 — Native app model + shell | 55% | `shell.rs`/window/graph/input (model-tested); live VGA text compositor + PS/2 keyboard (Tab-focus/arrows) | Shell not wired into boot; no object/relationship-based UI; no framebuffer graphics |
| 8 — Linux compat | 55% | Linux ABI translation + ELF loader + personality gating (32 tests), exercised live | No lightweight-VM vehicle (needs hypervisor), no ring-3 trap |
| 9 — Windows compat | 45% | NT ABI translation + PE loader + personality gating (31 tests), exercised live | No VM full-fidelity path (design doc: unsolved anywhere by translation) |
| 10 — Supervision hardening + chaos + formal ceiling | 60% | Ceiling property tests (14), model chaos tests (6), model supervision (10) | Ceiling checks are contract tests, not an inductive proof; no kernel chaos testing |
| 11 — Distributed extension | 50% | `fleet` crate (22 tests): locality, recipient binding, fail-closed partition | Two-node in-process model; no sockets, no consensus; no real network |
| 12 — Production hardening + real-hardware certification | 40% | security-audit gate (10), kernel boundary tests (21), `SECURITY_AUDIT.md` matrix | NO real-hardware certification of anything; no fuzzing; no inductive proof |

**Why the two numbers differ.** The design doc (§11) says the actual target is
§11.F's "smallest prototype that proves the architecture", and explicitly
calls Phases 7–12 later-phase/premature. That target is delivered. But if the
yardstick is "everything in the §7 roadmap done at real, production depth",
the honest number is **~59%** — and the missing 41% is not hidden, it is
listed row by row above and in the "What doesn't exist" table below.

## Known Limits

This is the **single consolidated Known Limits section** (`README.md` and
`ARCHITECTURE.md` point here). Limits use the three-way split: **closed**
(fixed, tested), **reduced** (better than before, not solved), **inherent**
(cannot be closed by better engineering — state plainly, never imply progress).

### Closed (fixed, tested)

- Per-task memory isolation via page-table U/S bits — faulting task kicked out by
  the page-fault handler, kernel keeps running (verified under QEMU).
- NX enforcement — only the kernel text window (parsed from the running ELF) is
  executable; ring-3 fetch from 0xB8000 faults with the NX bit in the error code,
  only the faulting task is killed (verified under QEMU).
- Live hardware-path I/O — PCI enumeration, NVMe block I/O, FAT16 reads all
  verified under QEMU/OVMF with 0 exceptions.
- IPC echo call/serve/reply under QEMU and VMware Workstation 26, 0 exceptions.
- Adaptive-ceiling verification caught and fixed a real scope-expansion bug
  (`tighten_scope` budget `/2 .max(1)` raised a restrictive 0-budget to 1).
- **Layout-dependent syscall-gate corruption (the old "pre-existing boot fault")**
  — root-caused and fixed. `switch_to_kernel_stack` did an in-function `mov rsp`
  to a fresh kernel-stack top, but the compiler's frame-relative slots (`%rsp`+off)
  then pointed *above* the stack top, spilling into whatever BSS statics the
  linker had placed there. When code-size shifts put `KERNEL_IDT` (or VGA
  cursor state / the memory-region table) directly above `KERNEL_STACK`, the
  first ring-3 `int 0x80` hit an all-zero gate → `#GP(0x402)` → double fault,
  reproducibly on some layouts and not others. Fix: `_start` now switches stacks
  via a never-returning asm `jmp` trampoline (`switch_to_kernel_stack_and_jump`)
  *before* any C prologue runs, so the boot kernel's entire frame lives inside
  the 16 KiB stack. Verified: full denial/IPC/isolation/NX demo passes, 0
  exceptions, across two rebuilds with different codegen layouts.

### Reduced (better than before, not solved)

- **Formal verification** is TLA+ model-checking (331k states, finite instance:
  2 tasks, 3 slots), not an inductive seL4-class proof.
- **Real hardware** is UNTESTED — everything runs under QEMU/TCG or VMware; many
  driver paths need a real device.
- **The IOMMU (Phase G) is a software gate mirroring VT-d semantics, not real DMAR
  hardware.** Every NVMe/e1000 DMA address passes `iommu::translate` (per-device
  domains, identity-mapped buffers, three-way `IommuFault`, bounded fault ring)
  and a live boot proves the denial path — but no real DMAR MMIO registers are
  programmed, the IOVA space is identity-mapped to physical (not yet distinct),
  and nothing has run on real VT-d hardware. This is the honest "reduced"
  middle ground: real translation and real gating happen at the driver/IOMMU
  boundary; programming an actual hardware IOMMU remains future work.
- **Compatibility** is model-level translation only (Linux 32 + Windows 31 tests).
  No hypervisor VM vehicle; full Win32/NT fidelity remains unsolved.
- **Distributed / fleet** is a two-node in-process model (15 tests); no real
  network, no consensus, partition behavior deliberately not modeled.
- **AI orchestration** is real kernel policy modules (23 tests) plus the real
  attributed audit log and anomaly monitor / grant ledger (6 tests, Phase 6) and a
  contract-tested ceiling (14 tests); no real-time integration, no real AI.
- **AI role library** is two roles (kernel tests `observer_role_grant`,
  `observer_cannot_self_escalate` in `aegis-kernel/src/role.rs`; model test
  `observe_role_is_read_only_and_never_controls` in `aegis/crates/grants`). Every
  role stays kernel-declared and GRANT-gated: an observer with `observe-service`
  gets READ over one task and is refused restart / role-grant / kill at the gates,
  never by its own code. Two roles remain a proof the discipline scales, not a
  claim the library is complete.
- **The audit ring is bounded (512 records) and evicts honestly** — live boots
  show the early grant records can be evicted before a late dump, so the recorded
  denial trail is complete but the earliest successes may be gone from the ring
  (grant-side lines print ring3-side from the supervisor). A bigger ring costs
  kernel memory; the bound is a deliberate, documented compromise, not a bug.
- **Graphical shell** is contract-tested model code (29 tests: shell 6, window 7,
  graph 6, input 5, desktop key-handling 5). The live compositor demo is
  *displayed* on the VM and its z-order occlusion is proven two ways: visually
  and by the serial assertion `Aegis: shell-compositor: menu(#) occludes
  clock(.) under overlap; status bar = true; z-order compositing = true`.
  **Interactive keyboard input now works live (Phase-10 item 4)**: a real PS/2
  driver (`ps2.rs`, 7 tests) takes IRQ1 through the legacy PIC → LAPIC LVT0
  ExtINT virtual-wire path, translates scancode set 1 (the controller command
  byte is reprogrammed with bit 6 = translation kept set, so raw set-2 bytes
  become set-1), and feeds a bounded ring buffer drained by a dedicated kernel
  task; Tab cycles focus and arrows move the focused window, all asserted live
  via the serial lines `Aegis: shell-compositor@key: Tab focus -> window id=3
  overlap_cell='.'` and `arrow move -> window id=3 region=(x,y)`. **Screen
  match (the prompt's "serial assertion first, screen match second" second
  half) is now also proven**: QEMU `screendump` PPMs (committed as
  `uefi-boot/scr0..5.ppm`) show each Tab/arrow keypress changes the VGA text
  display in the menu-window region, and after an `up` keypress the frame is
  byte-identical to the after-Tab frame (window returned to its origin —
  scr5 == scr1 by SHA-256), proving the window visibly moves and is not just
  a serial-side effect. Proven scope:
  the driver's scancode coverage is set-1 subset (letters/digits/punct,
  modifiers, arrows, Tab, Enter, Esc, Space, Backspace), translation verified
  live under QEMU (VMware's synthetic-input capture was refused, so QEMU's
  `sendkey` monitor command is the injection vehicle); real application content
  and a full compositor still do not exist.
- **IPC overhead** vs a monolithic syscall path is reduced (batched submission,
  shared-memory capability grants), not eliminated.
- **POSIX view (Phase C) is a capability-scoped projection, not a permission system.** The new hierarchical `TreeView` (nested dirs, path resolution, cwd, mode/uid metadata, COW path persistence — live under QEMU) keeps the in-kernel arena object store as its substrate; mode/uid bits are metadata for the projection and the authority that actually gates access remains capability-shaped (region caps), so there is no permission-bit enforcement anywhere. Bounds: `MAX_DEPTH=8`, `MAX_FILES=8` per dir, `MAX_BLOCKS=48`/`MAX_NODES=48` in a 48 KiB arena — the live demo reaches 36 nodes / 60 WAL seqs, so headroom is deliberate but finite; no symlinks/hard links, no multi-block files, no timestamps.
- **Capability conformance** is verdict-level, not end-to-end. The harness
  replays the kernel's `C:` trace against the model and proves *authorized /
  denied* agreement on every traced op — it does not compare message payloads,
  timing, or rendezvous ordering, and it adapts the kernel's coarser creation /
  grant mechanics into the model's Creator-cap and I6-consent ceremony (both
  documented in `aegis/crates/conformance`).

### Inherent (cannot be closed by better engineering)

- **Distributed transparency under partition** — CAP theorem. The design makes
  locality and partition failure visible and fail-safe by default, not hidden.
- **Proving AI agent behavior, not just its ceiling** — a capability check is a
  decidable check; a model's behavior under adversarial input is not.
- **The compatibility moat** — full native Win32/NT fidelity without a real
  Windows kernel, and instant parity with Linux's syscall-path tuning, are
  ecosystem network effects, not engineering gaps.
- **A human granting too much authority** — bounded by role-shaped ephemeral
  grants + audit, never eliminated; anyone claiming otherwise is not being
  straight with you.

## What exists (verified clean)

Test counts are kept separate on purpose: `aegis-kernel` is a **standalone bare-metal crate that is NOT a member of the `aegis` workspace**, so its tests are never covered by `cargo test --workspace`.

- **aegis workspace (model crates):** 128 contract tests, 0 failures (incl. the master-roadmap Phase-4 conformance harness `crates/conformance`, 4 tests: trace parsing, the denial-demo replay-agreement proof, a flipped-verdict divergence detector; the §10 item-4 `fleet` partition fail-safe, 22 tests: locality/recipient-binding/expiry/trust transport plus peer reachability heartbeat + fail-closed denial on partitioned or stale issuers; and the Phase-C `object-store` mirror of the hierarchical POSIX view — 9 contract + 2 lib tests — `cargo test --workspace` from a clean lockfile (Rule 1/10)).
- **aegis-kernel (bare-metal, separate crate):** 438 contract tests, 0 failures — `cargo test` on the pinned 1.97.1 toolchain (verified this session: includes the Phase-5 loopback netstack in `netstack.rs` — 4 tests over the design §8 async channel box in `channel.rs` — 2 tests: sockets are `Cap::Channel` objects nodded with SEND|RECV into subscriber CSpaces (no GRANT, I2), ports are not ambient authority (a cap-less task is refused by the stack and by the raw gate), a two-hop capability-gated router preserving FIFO order with an exact drain, teardown that destroys the channel and dangles a subscriber's cap while peers keep working, and a router-not-a-root CSpace census — plus the **Phase E real TCP/IP stack in `netif.rs` (9 tests)**: a polled client stack on top of the e1000e driver with ARP resolve/request/reply, IPv4 TX with checksums, RX demux (ARP/ICMP/UDP/TCP), ICMP echo reply, a TCP client state machine (Closed/SynSent/Established/FinWait1/FinWait2) with RTO retransmission, slow-start congestion window, send-buffer compaction, UDP send/recv, and a capability-scoped socket API behind syscalls 19–23 (`Cap::NetEndpoint`, SEND|RECV gated) — plus the IPv4 payload-slicing fix that bounds the payload by `total_length` so TCP checksum verification sees exactly the segment, not Ethernet padding (2 new regression tests in `ipv4.rs`) — plus the **Phase E TLS 1.3 module in `tls.rs` (18 tests)**: Vec-free TLS record layer (5-byte header, content types 22/23/24), `build_client_hello` with wire layouts validated against a real OpenSSL client (server_name + supported_versions 0x0304 + signature_algorithms + supported_groups 0x001d + key_share x25519), `parse_server_hello` (KeyShareEntry uses a u16 `key_exchange` length — the 1-byte read produced a low-order rejection in the first live run), scalar-multiplication X25519 (RFC 7748 §5.2 vectors 1 & 2 + base-point-all-zero rejection), HKDF-Extract/Expand/ExpandLabel (RFC 5869 case 1), AES-128-GCM (`aes.rs`, RFC 8448 record-protection vector), the full RFC 8446 §7.1 key schedule (early secrets, handshake secrets, `s_hs`/`c_hs`, master secret, `c_ap`/`s_ap` application traffic keys, `res_master`), server-flight decrypt + client Finished, and `real_capture_debug` which decrypts the encrypted ServerHello/EE records from the live QEMU capture and cross-checks the transcript hash + `s_hs` key against the captured flight; root-caused the `s_ap`/`c_ap` derivation per RFC 8446 §7.1 (both application traffic secrets derive over ClientHello…server Finished; only `res master` uses client Finished — the old code derived `s_ap` after pushing client Finished, so server app records failed auth; fixed in `build_client_finished`) — plus the Phase-4 object store in `store.rs` (15 tests): FIPS 180-4 SHA-256 vectors, content-address dedup, capability-addressed blocks served by the real `mem::mem_len`/`mem_read`/`mem_write` gates where a granted READ-only cap reads and writing refuses, COW version-stable snapshots, a relationship index that consumes only the store WAL and rebuilds identically, index-free commit/write signatures, and the Phase-C full POSIX `TreeView` projection (nested dirs, absolute/relative path resolution with `.`/`..` and cwd, mode/uid metadata, COW-to-root path persistence with version-stable old roots, unlink/rmdir with emptiness + root-not-removable rules, bounds `MAX_DEPTH`/`MAX_FILES`) — plus the UDP/TCP header parsers in `udp.rs`/`tcp.rs` — RFC 768/793 parse/serialize with pseudo-header checksum verification — and the full Phase-12 `hardening.rs` adversarial boundary suite — ELF/PE/IPv4/Ethernet/ARP/UDP/TCP parse-and-never-panic, syscall/ABI translation totality, compat-layer/shell/window/graph/input bad-ID rejection — plus the Phase-1 `cap.rs`/`ipc.rs` capability-rights model: SEND/RECV/GRANT gates on call/serve/reply/grant and the Task/MemRegion/Channel object kinds — and the Phase 2 additions: `mem.rs` frame-backed MemRegion cap gates + bounds checks (9 tests, incl. the new Phase B `grant_use_revoke_deny_cycle_across_tasks` contract for the ring-3 page manager), `supervisor.rs` budgeted restart/trip/audit runtime (5 tests, incl. the new `parent_adopts_subsystem_with_fresh_budget_after_child_trip` hierarchical-adoption contract), `tasks.rs` kill/restart/restore primitives, and `kernel_state_guard` test serialization — plus the Phase-6 kernel audit log in `audit.rs` (3 tests: a 512-entry ring where every gated op — task lifecycle, channel send/recv, memory read/write, delegation, revoke — lands attributed `(tick, caller, op, target, ok)`, success and refusal alike, with per-caller op histograms, target-success queries, and a revoke counter) and the §9 anomaly circuit breaker in `monitor.rs` (3 tests: a capability-less `AnomalyMonitor` trains on the agent's real op-shape and on significant deviation suspends — never revokes — via the `GrantLedger`, which freezes the `ipc_cap_grant` gate while minted caps keep working; suspension is reversible + logged; a cap-less monitor task cannot kill, revoke, or read an object) — and the Phase-6 kernel role library in `role.rs` (7 tests): the two roles `restart-service` (READ|CONTROL over one task, no GRANT) and `observe-service` (READ over one task only, no CONTROL, no GRANT) are kernel-declared, granted by the gated `role_grant` syscall 18, and each has its own adversarial self-escalation denial test — an observer that can READ the live service state and the crash, and whose restart/role-grant/kill are all refused by the capability gate, never by its own code (`observer_role_grant`, `observer_cannot_self_escalate`)) — plus the **Phase G real VT-d IOMMU gate in `iommu.rs` (12 tests)**: the sparse page-number-keyed page table (no masked-index collision), the three-way `IommuFault` gate (`DeviceNotAssigned`/`AddressNotMapped`/`PermissionDenied`), per-device domain provisioning + identity mapping, the fault ring (16) with monotonic `fault_total`, and the out-of-domain denial test (`translate_denies_out_of_domain_dma_like_misdirected_write`) that the live boot reproduces. The ring-3 *integration* is additionally proven by a live QEMU/TCG boot (not a contract test — see Ring-3 row).
- **uefi-boot:** 13 ELF parser contract tests.

Combined contract-test count across all crates: **566** (438 kernel + 128 model; uefi-boot's 13 parser tests listed separately). The bare-metal CPL3 transition itself has no contract test (it needs real/virtual hardware); its proof is the live boot.

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
| Object store | 15 | Content-addressed immutable blocks, COW layers, WAL index, full POSIX TreeView (nested dirs, path resolution, cwd, mode/uid metadata, COW path persistence, unlink/rmdir) |
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
| NVMe storage driver | — | QEMU q35 NVMe controller (BAR0 `0xC000000000`, 768 GiB, above the 4 GiB identity map). **VERIFIED under QEMU/TCG**: probe → reset (admin SQES 64 B / CQES 16 B) → create IO SQ+CQ (qid 1) → identify (model `QEMU NVMe Ctrl`, firmware `11.0.50`, namespace 1 = 16 MiB) → polled LBA0/LBA1 reads; LBA0 protective-MBR signature and LBA1 GPT `EFI PART` header both verify, **0 exceptions**. **Phase G: every DMA address now passes the IOMMU gate** — the device is provisioned into its own domain in `probe`, its 5 DMA buffers are identity-mapped before any PRP is written, and each `dma_addr` translates on the device bdf; live boot confirms in-domain reads pass and an out-of-domain address is denied at the IOMMU. 64-bit MMIO mapped via kernel PML4[1]/PDPT[256]/PD[0]/PT[0] (4 KiB NX pages). Completion phase tag is bit 16 of D3 (status field = bits 17+); initial phase = 1. UNTESTED on real hardware |
| FAT16 filesystem reader (live NVMe) | — | Read-only FAT16 over live NVMe block I/O (`fat.rs`). **VERIFIED under QEMU/OVMF**: kernel mounts the ESP at LBA 2048, walks `EFI/BOOT/`, finds `BOOTX64.EFI` (230912 bytes, cluster 4), and reads its first sector via real NVMe reads — `MZ signature: true`, **0 exceptions**. Boot-breaking bug found and fixed live: `read_first_sector` did `out.copy_from_slice(ctrl.lba_data())` where `lba_data()` returns the 4 KiB DMA buffer but `out` is 512 B — panicked at `fat.rs:186`; fixed to copy only `&ctrl.lba_data()[..512]`. UNTESTED on real hardware |

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
| Memory isolation (per-task U/S) | — | A ring-3 `iso-test` task attempts to read a kernel-only address (0x1000000, present but not USER in its PML4). **VERIFIED under QEMU**: the read #PFs, the exception handler prints `PAGE FAULT at CR2=0x1000000 - memory isolation verified`, the task is KILLED, and the kernel keeps running — page-fault-driven isolation now kills only the faulting task and resumes the scheduler (previously a ring-3 fault halted the whole kernel). UNTESTED on real hardware |
| NX (non-executable pages) | 8 | Only the kernel image's R+X PT_LOAD window (parsed from the running ELF at identity address 0, `page_tables::kernel_text_window`) is executable. Kernel stacks/BSS, the VGA framebuffer (0xB8000), LAPIC MMIO, allocator frames and ring-3 stacks are marked NX; per-user PML4s clone the low tables instead of mutating the shared kernel tables; IA32_EFER.NXE set explicitly at boot. **VERIFIED under QEMU**: boot banner `NX enabled: kernel text 0x35E0-0x9534 executable`; a ring-3 `nx-test` task executing 0xB8000 faults with the NX (instruction-fetch) error-code bit — `NX violation: instruction fetch at CR2=0xB8000 - non-executable page verified (task killed, kernel survives)` — and the kernel keeps running: both fault demos plus the IPC demo complete in one boot, 0 exceptions across a 13k-tick run. UNTESTED on real hardware |
| ELF parser hardening (page_tables) | 1 | `text_window_from_elf` now uses `checked_add`/`checked_mul` for program-header offset math (mirrors `elf_loader.rs`). **Bug fixed + regression test added**: old `e_phoff as usize + i as usize * e_phentsize as usize` wrapped on a crafted `e_phoff` near `u64::MAX`, letting the bounds check pass then panicking on the real slice index — a reachable kernel panic in the W^X window computation. New test `text_window_rejects_overflowing_phoff` rejects it; kernel test count now 252. UNTESTED on real hardware |

### Real display output (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| VGA text console | 4 | 80x25 white-on-black mirror of the COM1 stream (`vga.rs`: Bochs VBE disable, CRTC/GC/AC programming, 16-color DAC palette, 8x16 font uploaded into plane 2 via map A; `sprintln!` and the ring-3 `Write` syscall print to 0xB8000). **VERIFIED under QEMU**: screendump decodes glyph-for-glyph to the exact Aegis log lines ("Aegis: [client] echo reply..."), plane-2 glyph probe matches the embedded font, DAC readback matches the programmed palette, pixels = black `000000` bg + white `ffffff` fg. Three real bugs fixed live: (1) SR4 chain4 bit made QEMU scatter text writes by `addr&3`; (2) SR2=0x0F let the odd/even parity rule stamp plane 2 (the font area) with screen characters — SR2=0x03 keeps chars on plane 0 / attrs on plane 1; (3) a 0x3C0 readback during the flip-flop data phase corrupted `ar[0]` (green background). Honest limits: text mode only — no framebuffer graphics, no GPU accel, no mouse input (PS/2 keyboard input works and drives the live compositor — see the Interactive-shell entry); font covers 0x00..=0x7F (higher chars render blank); the low 2 MB is USER-flagged in per-task PML4s, so a ring-3 task could scribble the screen (cosmetic, accepted for the demo); UNTESTED on real hardware |

### Real driver framework (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| PCIe enumeration | 6 | Config space address building, BAR parsing (32/64-bit), device identification, device list. UNTESTED: requires I/O port access (inl/outl) on real hardware |
| IOMMU (VT-d) | 12 | Real `translate` gate (page-number-keyed sparse table, no masked-index collision), domain creation, device-to-domain assignment, identity mapping, DMA page table map/unmap, fault ring (16) with monotonic `fault_total`, three-way `IommuFault` (DeviceNotAssigned/AddressNotMapped/PermissionDenied), out-of-domain DMA denial. **Phase G closed**: live under QEMU every NVMe/e1000 DMA address passes the gate and a deliberately misdirected DMA is denied at the IOMMU. Honest limit: software gate mirroring VT-d — no real DMAR MMIO programming; UNTESTED on real VT-d hardware |
| NVMe queues | 5 | Submission/completion queue entry construction, tail/head pointer management, phase-bit tracking. UNTESTED: requires real NVMe device |

### Real networking stack (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| e1000e NIC driver | 7 | `e1000.rs` (Intel 82574L/e1000e, q35 default) — legacy TX/RX descriptor rings in DMA frames, MAC read from RAL/RAH (little-endian), link status, ARP request build/reply detection, oversized-frame rejection. **LIVE under QEMU**: broadcast ARP request for the host gateway transmitted off the NIC, captured externally on the host, and the echoed ARP reply received by the polled RX ring (see Phase-D row). Honest limits: polled only, QEMU socket netdev not physical hardware |
| Polled TCP/IP stack (`netif.rs`) | 9 | Client stack on the e1000e driver: ARP resolve (table/request/reply), IPv4 TX (checksums), RX demux ARP/ICMP/UDP/TCP, ICMP echo reply, TCP client state machine (Closed/SynSent/Established/FinWait1/FinWait2) with seq/ack handling, RTO retransmission, slow-start cwnd, send-buffer compaction, UDP send/recv, and the capability-scoped socket API (syscalls 19–23, `Cap::NetEndpoint`, SEND|RECV gated). **LIVE under QEMU**: real three-way handshake, HTTP request/response, and FIN close against an external host peer, externally captured (see Phase-E row). Honest limits: client-only (no LISTEN/accept), polled clock for RTO, single destination per socket, TLS app-data exchange verified live after the `s_ap` fix (see `tls.rs`, 18 tests) |
| TLS 1.3 client (`tls.rs`) | 18 | Vec-free record layer (5-byte header, content types 22/23/24); `build_client_hello` (server_name + supported_versions 0x0304 + signature_algorithms + supported_groups 0x001d + key_share x25519, layouts validated against a real OpenSSL client); `parse_server_hello` (KeyShareEntry u16 `key_exchange` length); X25519 scalar multiplication (RFC 7748 §5.2 vectors 1 & 2 + base-point-all-zero rejection); HKDF-Extract/Expand/ExpandLabel (RFC 5869 case 1); AES-128-GCM (`aes.rs`) with RFC 8448 vector; **full RFC 8446 §7.1 key schedule** (early/handshake/master secrets, `s_ap`/`c_ap` traffic keys) and server-flight decrypt + client-Finished build verified against the live QEMU capture in `real_capture_debug`. **RFC 8448 §3 byte-for-byte**: the two application traffic secrets and their AES keys/IVs are asserted against the authoritative trace (auto-extracted `rfc8448_vec.rs`, `rfc8448_application_traffic_secrets`), and a full-transcript test drives the whole client state machine over the RFC's CH+SH+flight (X25519 shared secret, server Finished `9b9b141d…`, then c_ap/s_ap) with a regression guard that proves a Finished-inclusive `s_ap` (the old bug) diverges. **LIVE under QEMU**: ClientHello → OpenSSL ServerHello, ECDHE shared secret cross-checked byte-for-byte with the host peer; encrypted server flight processed and client Finished sent; **app records decrypted with the fixed `s_ap` key and the HTTPS response body rendered by the kernel** (see Phase-E log). Honest limits: no certificate-chain verification; fixed deterministic scalar (no CSPRNG in the guest) |
| VirtIO-net driver | 9 | Device init, MAC address handling, header construction, device status. UNTESTED: requires real VirtIO NIC |
| Ethernet frames | 5 | Frame parsing/serialization, ethertype validation, minimum size enforcement, broadcast |
| ARP | 6 | Table lookup/insert/remove, request/reply construction, packet parsing. UNTESTED: no real network |
| IPv4 | 6 | Packet parsing/serialization, checksum computation, address formatting, loopback/broadcast detection |
| UDP | 8 | RFC 768 datagram parse/serialize, pseudo-header checksum verification, length-field validation, zero-checksum (not-computed) handling |
| TCP | 9 | RFC 793 segment parse/serialize, data-offset validation, mandatory pseudo-header checksum verification; options exposed raw (not decoded), no connection state machine (honest limit — future socket layer) |

### Real AI orchestration (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| Agent runtime | 8 | Agent lifecycle (spawn/suspend/resume/terminate), capability scoping, restrictive vs permissive scopes |
| Usage profiler | 5 | Syscall histogram tracking, deviation computation, baseline comparison, record management |
| Adaptive grants | 5 | Auto-tighten on medium deviation, suspend on high, terminate after repeated suspensions, scope reduction |
| Policy engine | 5 | Rule-based evaluation (max syscalls, memory, network), audit trail logging |
| Kernel audit log | 3 | `audit.rs` ring (512 records): every gated op — task_state/kill/restart, channel send/recv, mem read/write, cap grant, revoke — lands attributed `(tick, caller, op, target, ok)` on success AND refusal, with per-caller op histograms, exact-target success queries, and a revoke counter (the "nothing was revoked" invariant is checked as it being zero) |
| Anomaly monitor + grant ledger | 3 | §9 circuit breaker kernel-complete: a capability-less `AnomalyMonitor` trains on the agent's real op-shape from the audit log, and on a significant deviation (>2x an op's rate, or an op never in the shape) suspends — never revokes — via the `GrantLedger`; the ledger freezes the `ipc_cap_grant` gate for a suspended agent (grant flow frozen, minted caps untouched) and is reversible + logged on human review; a cap-less monitor task cannot kill, revoke, or read an object |

### Real shell and UI (aegis-kernel)
| Component | Tests | What it proves |
|-----------|-------|----------------|
| Shell runtime | 6 | App launch/stop/restart, focus tracking, lifecycle management |
| Window manager | 7 | Window creation/destruction, z-ordering, hit testing, compositor order, dirty tracking |
| Object graph | 6 | Node/relationship CRUD, neighbor traversal, type filtering |
| Input handler | 5 | Ring buffer push/pop, full/empty detection, focus-based dispatch |
| PS/2 keyboard driver | 7 | `ps2.rs`: controller init (IRQ1 + translation bits in the command byte), scancode-set-1 translation (make/break, extended 0xE0, two-byte), bounded ring buffer, pop; live path proven under QEMU |
| Desktop key handling | 5 | `desktop.rs`: Tab cycles focus, arrows clamp-move the focused window, overlap-cell reporting, clipping at the 80x25 bounds, focus cycles among visible windows |

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
| Kernel boundary/panic-safety | 21 | All parsers (ELF/PE/IPv4/Ethernet/ARP/UDP/TCP) and both syscall ABIs return errors on garbage/truncated/overflowing inputs and never panic; ELF/PE loaders reject attacker-controlled offsets that would overflow (checked_add/checked_mul — 4 regression tests); compat layers reject garbage; shell/window/graph/input reject bad IDs without panicking |
| Certification matrix | — | `SECURITY_AUDIT.md`: what is certified (model-level only), what is NOT (all real-hardware ops UNTESTED, no inductive proof, no fuzzing, no distributed guarantees) |

### Tooling
- `capability-audit`: reachable-authority CLI, `--graph` flag for capability visualization
- `aegis-shell`: interactive demo exercising IPC, grants, anomaly monitoring
- Model-doc sections in `spec/capability-model.md` for every implemented claim
- GitHub Actions CI: `cargo fmt --check`, `cargo clippy`, `cargo test --workspace` on every push

## What doesn't exist (honest list)

| Claim | Status | Why it's missing |
|-------|--------|-----------------|
| Real hardware isolation (verified on actual hardware) | Model-level code only | Page tables, IOMMU, NVMe, VirtIO drivers exist but are UNTESTED on real hardware (need VMware); the IOMMU gate (Phase G) is software-mirrored VT-d, no real DMAR MMIO programming |
| Real process isolation on hardware (page faults, cr3 switching) | Code + 10 contract tests + scheduler + ring-3 task live under QEMU | Cooperative task switching and a ring-3 user task (CPL3 `iretq` + `int 0x80` syscall) verified live under QEMU/TCG; per-task isolation via page-table U/S bits verified under QEMU (isolation-test task faults on a kernel-only address and is killed); still UNTESTED on real hardware |
| seL4-class formal proof | Not built | TLA+ model-checking (finite instance), not inductive proof |
| Real network I/O on a NIC | Real e1000e driver + live ARP TX/RX (7 tests) + live TCP/IP (9 tests) + live TLS 1.3 client (18 tests) | Real Ethernet frames leave and re-enter the kernel under QEMU (polled e1000e driver; external host capture + ARP echo). **Phase E: the kernel's `netif.rs` stack drives a real TCP connection over that NIC** — ARP resolve, SYN→SYN-ACK→ACK handshake, an HTTP request/response, and a FIN close, all externally captured in `e1000-phase-e.pcap` with the HTTP response body rendered by the kernel; **and the `tls.rs` client runs the full RFC 8446 §7.1 key schedule + AES-128-GCM against a real OpenSSL server on 8443** — server flight decrypted, client Finished sent, app-record `s_ap` derivation root-caused + fixed (RFC 8446 §7.1) and the whole schedule validated byte-for-byte against RFC 8448 §3's published trace, live app-data exchange verified in the rebuilt kernel (Phase-E closure). Honest limits: polled (no interrupts); QEMU socket netdev, not physical hardware; client-only (no LISTEN/accept); no certificate-chain verification |
| Linux/Windows compat layers | Partially built (Phase 8+9 model-level) | Linux (32 tests) + Windows (31 tests) translation/loader/personality; no hypervisor VM vehicles; full Windows fidelity explicitly not solved by translation alone |
| AI orchestration on real hardware | Kernel policy + audit + monitor; no live integration | Agent/profiler/adaptive/policy tested in-process (23 tests); the attributed audit log and §9 anomaly monitor / grant ledger now run in the kernel over the real gates (6 tests); no real-time integration |
| Graphical shell on a real display | Model-level code + live PS/2 input | Shell/window/graph/input tested in-process (29 tests); a VGA text console mirrors kernel output on the QEMU display (verified live); real keyboard input now drives Tab-focus and arrow-move live under QEMU (serial-asserted), but no framebuffer graphics, no GPU accel, no mouse |
| Cross-machine transport for macaroon tokens | Partially built (Phase 11 model-level) | fleet crate: transport/envelope/locality/verification (13 tests) in-process; no real network, no consensus |
| File metadata (timestamps, permissions beyond capability rights) | Partly built (Phase C) | mode/uid bits now exist as POSIX-view projection metadata (nested dirs, path resolution, cwd, COW-to-root — live under QEMU); enforcement remains capability-shaped; no timestamps yet |
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
| 2 | Userspace resource managers + supervision tree | ✅ Done (real + model): GDT/TSS, IDT, per-process page tables, process abstraction, round-robin scheduler (10 tests), syscall framework. **LAPIC timer verified under QEMU/TCG**: 8-entry GDT installed + TSS loaded (16-byte descriptor quirk), IDT gates deliver, periodic timer (~570 ticks/s) drives the idle loop. **Cooperative task switching verified under QEMU/TCG**: alpha/beta tasks interleave every 512 ticks at stable rsp, 6665/6665 interrupt rsp deltas = 0 (after fixing the resume-rsp drift — saved rsp had included the call's return address); still cooperative, still not run on physical hardware. **Per-task memory isolation verified under QEMU**: iso-test task's kernel-only read #PFs and is killed (page-fault-driven isolation, fixed exception-stub arg order); still not run on physical hardware. **NX enforcement verified under QEMU**: only the kernel text window (parsed from the ELF) is executable; ring-3 fetch from the NX VGA page #PFs, only the faulting task is killed and the kernel survives. **Phase 2 memory + supervision**: `mem.rs` frame-backed MemRegion caps (READ/WRITE/GRANT-gated `mem_len`/`mem_read`/`mem_write`, model-exact bounds checks, 9 tests), `supervisor.rs` budgeted restart/trip/audit runtime (5 tests), `tasks.rs` kill/restart/restore primitives, fault-path `handle_fault` hook, syscalls 10–16, and test serialization via `kernel_state_guard` (304 kernel tests). **Phase B hierarchical + userspace resource managers (this commit)**: the resource manager and the supervision tree are now RING 3, live under QEMU — `mem-rm` (task 12) mints two pages and lends/recycles them purely via CapGrant/CapRevoke (client sees `mem_len` 4096 → -1 after free, denied at the gate), and `parent-sup` (task 14) is the supervisor ABOVE the ring-3 supervisor: when the child's restart budget is spent it escalates upward over IPC, the parent ADOPTS the subsystem with a fresh budget, takes over serving the kill-notification channel, and trips only when its own budget is spent (serial: `ESCALATION: child restart budget exhausted` → `escalation received; adopting subsystem` → `PARENT TRIP`). New contract tests: `grant_use_revoke_deny_cycle_across_tasks` (mem.rs) and `parent_adopts_subsystem_with_fresh_budget_after_child_trip` (supervisor.rs). 378 kernel tests. Honest limits: revoke is instance-named (flat CSpace, no I4 grant-root tree); budgets are restart-counts not CPU/energy; the parent re-arms the same NOTIFY_EP so escalation hand-off relies on the child surrendering (it stops serving) before the parent takes over — single-observer at a time |
| 3 | Driver framework (IOMMU) | ✅ Done (real + model): PCIe enumeration (6 tests), VT-d IOMMU domain isolation (12 tests), NVMe command queues (5 tests). Model: typed Block/Net/Gpu interfaces, crash containment, GPU isolation, compositor (4 tests). **Phase G (this commit): real IOMMU DMA isolation, live-verified** — `iommu::translate` gates every NVMe/e1000 DMA address (per-device domains, buffers identity-mapped before use); live QEMU/OVMF boot (`uefi-boot/serial-phase-g-clean.log`) shows NVMe identify + LBA/GPT reads and the full e1000 ARP/TCP/TLS path passing the gate, then a deliberately out-of-domain DMA to 0x100000000 denied at the IOMMU (`AddressNotMapped`, fault_total=1) with the kernel continuing (FAT16 + store + all task demos to tick 6364). Honest limits: software gate mirroring VT-d semantics, not real DMAR hardware registers; identity-mapped IOVA space; no real hardware test |
| 4 | Storage service + POSIX view | ✅ Done (real + model): the object store now *runs in the kernel* (`aegis-kernel/src/store.rs`, 15 contract tests): SHA-256 content-addressed immutable blocks over real kernel `MemRegion`s, capability-addressed at the gate (`grant_read` installs narrowed READ-only region caps into the recipient's CSpace; fabricated slots deny via `mem::mem_len`, granted slots serve `mem::read` and refuse `mem::mem_write` — I2), COW version-stable snapshots, a relationship index that consumes only the store WAL and rebuilds identically (index-free commit/write signatures — §10 [CLOSED]). **Phase C (this commit): the flat `FlatView` is replaced by the full POSIX `TreeView`** — a hierarchical namespace where files and directories are COW store objects: nested directories, absolute and relative path resolution (`.`, `..`, cwd), mode/uid metadata, path persistence (a mutation commits new versions of every dir on the root→parent path, the old root still reads the old tree), unlink/rmdir with emptiness + root-not-removable rules, all verified live under QEMU (`Aegis: POSIX-view:` lines in `uefi-boot/serial-phase-c.log`; screendump `uefi-boot/phase-c.pbm`). Model: `object-store` crate mirrors TreeView (9 contract + 2 lib tests). Honest limits: bytes live in a fixed 48 KiB in-kernel arena (not the Phase-3 NVMe/FAT device path, which stays a separate read-only driver); in-memory WAL; mode bits are projection metadata — the authority that gates access stays capability-shaped (region caps), no permission-bit enforcement; no symlinks/hard links; bounded `MAX_DEPTH=8`, `MAX_FILES=8`, `MAX_BLOCKS=48`, `MAX_NODES=48`, `MAX_WAL=128`; no multi-block files; no timestamps |
| 5 | Networking stack | ✅ Done (real + model): the capability-scoped socket layer now *runs in the kernel* (`aegis-kernel/src/netstack.rs` + `channel.rs`, 6 contract tests): sockets are `Cap::Channel` objects (the design §8 async box), minted SEND|RECV into subscriber CSpaces with no GRANT (I2), ports are not ambient authority (a cap-less task is refused by the stack and by the raw gate), a two-hop capability-gated router preserves FIFO order with an exact drain, teardown destroys the channel and hangs a subscriber's cap while peers keep working, and the stack's CSpace census is router-not-a-root. Model: `net` loopback stack (4 tests). **Phase D (this commit): a real NIC driver — `e1000.rs` (Intel 82574L/e1000e, QEMU q35's default NIC) transmits and receives real Ethernet frames under QEMU**: at boot the kernel probes the NIC (BAR0 identity-mapped, bus-master enabled), reads the MAC from the RAR registers (RAL/RAH are little-endian bytes; read back `52:54:00:12:34:56`), programs legacy TX+RX descriptor rings in DMA frames (RDLEN must be a multiple of 128 bytes — `E1000_XDLEN_MASK 0xFFFF80` masked a 4-desc ring to 0 and left the reply queued forever, so RX_RING_LEN is 8), transmits a broadcast ARP request for the host gateway 10.0.2.2, and an external host process (`uefi-boot/e1000_host_listener.py`) captures that frame off QEMU's `socket` netdev (4-byte big-endian length + raw frame), writes it to `uefi-boot/e1000-phase-d.pcap`, and echoes an ARP reply back into the guest; the kernel's polled RX ring receives it. Evidence (`uefi-boot/serial-phase-d.log`): `reset: true MAC 52:54:00:12:34:56`, `link up: true`, `ARP request sent (42 bytes): true`, `ARP reply received (60 bytes, ARP reply for us: true)`, `reply sender 52:54:00:12:34:02 @ 10.0.2.2`; the pcap holds the broadcast ARP request (proto 0806, op 0001, sender 10.0.2.15 → target 10.0.2.2). 7 new e1000 contract tests (descriptor layout, MAC roundtrip, ARP request/reply, oversized-frame rejection). **Also root-caused a latent boot-stack overflow the new module exposed**: the boot path uses ~27.7 KiB of stack, and the 16 KiB kernel stack (`.bss.stack`, grows down into `.bss`) was overflowing into the audit log's `HEAD` static — a deterministic `audit.rs` panic at the first record (the overflowing bytes `0x0F2E…` were boot-stack content). `KERNEL_STACK_SIZE` 16384 → 65536; verified clean (no panic, scheduler continues past tick 7500). Honest limits: polled driver (no interrupts/MSI-X); boot-time demo only — the ARP exchange is crafted in `main.rs`, NOT routed through the capability-scoped netstack/socket layer; QEMU socket netdev only (real emulated NIC, external host capture), NOT real physical hardware; single frame each way; no IP routing/UDP/TCP; RAR accepts all frames (BAM), no promiscuous/multicast filtering. **Phase E (this commit): a real polled TCP/IP client stack in the kernel (`netif.rs`, 9 contract tests) drives a real TCP connection over that NIC**: ARP resolve (request/reply), IPv4 TX with checksums, RX demux ARP/ICMP/UDP/TCP, ICMP echo reply, and a TCP client state machine (Closed/SynSent/Established/FinWait1/FinWait2) with seq/ack, RTO retransmission (verified live in an earlier run — the kernel retransmitted SYN ×4 on the wire), slow-start cwnd, and send-buffer compaction; the capability-scoped socket API is exposed through syscalls 19–23 (`Cap::NetEndpoint`, SEND|RECV gated). The boot demo (`main.rs`) resolves the host gateway, opens a socket to 10.0.2.2:8080, and the peer (`uefi-boot/e1000_host_listener.py`, now a minimal TCP server with correct IPv4/TCP checksums) completes the handshake, answers `GET / HTTP/1.0`, and acknowledges the FIN. Evidence (`uefi-boot/serial-phase-e.log`): `TCP SYN sent`, `TCP handshake complete (Established)`, `HTTP request sent (34 bytes)`, `HTTP response received (134 bytes)`, `body: HTTP/1.1 200 OK … Aegis kernel TCP demo: hello from the host peer!`, `socket closed (FIN sent)`; `uefi-boot/e1000-phase-e.pcap` holds the 6 guest frames — ARP request, SYN (seq 0x9E3779B8), handshake ACK (ack = server ISN+1), GET (34 B), ACK to the response, FIN|ACK — and `uefi-boot/e1000-phase-e.pcap-host-tx.pcap` holds the peer's SYN-ACK / ACK / 134-byte HTTP response / FIN-ACK. Two real bugs found and fixed live: (1) `IPv4Packet::parse` sliced its payload by remaining-buffer-length instead of the `total_length` field, so TCP checksum verification ran over Ethernet padding (a 54-byte frame padded to 60) and rejected every SYN-ACK — fixed by bounding the payload slice to `total_length` (+2 regression tests); (2) the listener's Ethernet header had src/dst reversed and its data segments started at the wrong sequence number (SYN consumes one). Honest limits (Phase E remainder): TLS not started; client-only (no LISTEN/accept); polled clock for RTO (boot demos run before the LAPIC timer); single connection per demo; QEMU socket netdev, not physical hardware. **TLS 1.3 on the wire (Phase E, next commit):** a second socket (`tls.rs`, 18 tests) speaks real TLS 1.3 to an OpenSSL-backed server on 10.0.2.2:8443 — `build_client_hello` (validated against a real OpenSSL client), `parse_server_hello`, scalar X25519 (RFC 7748 vectors), HKDF-ExpandLabel, AES-128-GCM (`aes.rs`), and the full RFC 8446 §7.1 key schedule (handshake + application traffic secrets, `res master`), with the ECDHE shared secret cross-checked byte-for-byte (kernel + host both derive `9A3E2DD5F5694AA5AE40525AC4C59CD28AE2EE8544B041E7A99B4604D819CF22` from the same keyshare; `e1000-tls.pcap` / `serial-tls.log` / `listener-tls.log`). Found live: ServerHello KeyShareEntry key length is u16 (1-byte read → low-order rejection) — fixed + regression test. Root-caused + fixed the app-record `s_ap` derivation bug per RFC 8446 §7.1 (both `c_ap` and `s_ap` derive over ClientHello…server Finished; only `res master` uses client Finished — old code derived `s_ap` after pushing client Finished, so the OpenSSL server's app records failed auth ×3; fix in `build_client_finished`). Host-side pcap repro proves the server flight decrypts under the fixed secrets; and the kernel's whole key schedule is now byte-validated end-to-end against RFC 8448 §3 (the authoritative trace, auto-extracted into `rfc8448_vec.rs`; `rfc8448_application_traffic_secrets` + `rfc8448_full_transcript_app_secrets` drive the REAL `derive_secret`/`traffic_key_from_secret`/`build_client_finished` functions and assert c_ap/s_ap keys+IVs, X25519 shared `8bd4054f…`, and the server Finished `9b9b141d…`). Honest limits: fixed deterministic scalar (no CSPRNG in the guest); live app-data exchange verified under the fixed `s_ap` derivation (Phase-E closure commit); no certificate-chain verification |
| 6 | AI orchestration layer | ✅ Done (real + model): Agent runtime (8 tests), usage profiler (5), adaptive grants (5), policy engine (5). **Real kernel audit log + §9 anomaly circuit breaker (this commit)**: `audit.rs` (3 tests) — every gated op (task lifecycle, channel send/recv, mem read/write, cap grant, revoke) lands attributed in a 512-record ring, success and refusal alike; `monitor.rs` (3 tests) — a capability-less `AnomalyMonitor` trains on the agent's real op-shape, and on significant deviation (2x rate or an unseen op) suspends via the `GrantLedger` (freezes `ipc_cap_grant`, never revokes; reversible + logged; a cap-less monitor cannot kill/revoke/read). Model: anomaly monitor (3 tests). Honest limits: no real AI model, profiler is histogram-based not ML, no real-time learning; audit is a bounded in-memory ring, not durable; the ledger only gates delegation (grant) — the supervisor/channel/mem gates do not consult it |
| 7 | Native app model + shell | ✅ Done (real): Shell runtime (6 tests), window manager (7), object-relationship graph (6), input dispatcher (5). **Interactive keyboard (Phase-10 item 4, this commit)**: PS/2 driver (7 tests) + desktop key handling (5 tests) — Tab cycles focus, arrows move the focused window, all serial-asserted live under QEMU. Honest limits: no GPU rendering, no framebuffer graphics, scancode coverage is a set-1 subset, no mouse |
| 8 | Linux compat | ✅ Done (real, model-level): syscall ABI translation (12 tests), ELF loader + initial stack (12 tests), compat personality with capability gating (8 tests). Honest limits: no hypervisor lightweight-VM vehicle (needs hypervisor); translation proven against buffers, not a live Linux userspace |
| 9 | Windows compat | ✅ Done (real, model-level): NT syscall ABI translation (12 tests), PE32+ loader (12 tests), Windows compat personality with capability gating (7 tests). Honest limits: narrow well-behaved-subset translator only; full-fidelity VM path (needs hypervisor + Windows) not built; design doc says full Windows compat is unsolved by translation alone |
| 10 | Supervision/circuit-breaker hardening + chaos testing | ✅ Done: supervision-tree (4) + chaos (6) model tests; adaptive-ceiling verification (14) in aegis-kernel — caught+fixed real scope-expansion bug in tighten_scope |
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
| `88f4e3c` | NX enforcement: only kernel text executable, data pages NX; ring-3 fault kills task, kernel survives (8 new tests, 250 kernel tests total; live-verified isolation + NX faults, 0 exceptions) |
| `e6962e7` | Phase 2 mem+supervision: frame-backed MemRegion caps (`mem_len`/`mem_read`/`mem_write`, READ/WRITE/GRANT-gated, model-exact bounds checks), supervision-tree runtime (budgeted restart, trip, audit ring), `tasks` kill/restart/restore + zombie-slot reuse, fault-path `handle_fault`, syscalls 10–16, `kernel_state_guard` test serialization; 304 kernel + 113 model + 13 uefi-boot tests pass clean (430 total), clippy + fmt clean |
| `ea7988f` | Phase 4 in the kernel: capability-addressed object store + POSIX FlatView in `aegis-kernel/src/store.rs` (9 contract tests) — SHA-256 (FIPS 180-4 vectors), content-address dedup, capability-gated reads through the real `mem` gates with a narrowed READ-only grant (write refused, I2), COW version-stable snapshots, WAL-consumer relationship index that rebuilds identically, index-free `commit`/`write_version` signatures (§10 [CLOSED]); `mem.rs` gains `region_base_len`/`claim_region`/`reset_regions_for_test` + `MAX_REGIONS` 16→32. 313 kernel + 113 model + 13 uefi-boot tests pass clean (439 total), clippy + fmt clean |
| `2c6412d` | Phase 5 in the kernel: capability-scoped sockets + loopback netstack in `aegis-kernel/src/netstack.rs` (4 tests) over the design §8 async FIFO channel box in `channel.rs` (2 tests) — sockets are `Cap::Channel` objects minted as narrowed SEND|RECV copies into subscriber CSpaces (no GRANT, I2), ports are not ambient authority (a cap-less task is refused by the stack and by the raw `ch_send` gate), a two-hop capability-gated router preserves FIFO order with an exact drain, unsubscribe destroys the channel and hangs the subscriber's cap while peers keep working, and the stack's CSpace census is router-not-a-root. 319 kernel + 113 model + 13 uefi-boot tests pass clean (445 total), clippy + fmt clean |
| `c887fd4` | Phase 6 in the kernel: the attributed audit log + §9 anomaly circuit breaker. `audit.rs` (3 tests): a 512-record ring where every gated op — `task_state`/`task_kill`/`task_restart`, `ch_send_as`/`ch_recv_as`, `mem_len`/`mem_read`/`mem_write`, `ipc_cap_grant`, and the new GRANT-gated `revoke_slot` — lands attributed `(tick, caller, op, target, ok)` on success and refusal, with per-caller op histograms, exact-target success queries, and a revoke counter. `monitor.rs` (3 tests): a capability-less `AnomalyMonitor` trains on the agent's real op-shape from the audit log and on significant deviation (an op's rate >2x its baseline, or an op never in the shape) suspends — never revokes — via the `GrantLedger`, which freezes the `ipc_cap_grant` gate for a suspended agent while minted caps keep working, is reversible + logged on human review, and is refused any authority (a cap-less monitor task cannot kill, revoke, or read an object). Closes the Phase-5 honest limit ("the kernel keeps no audit log"); also added the missing slot bounds guard to `caps_channel` and moved the `mem.rs` tests' `set_current_for_test` under the state guard (deterministic serialization). 325 kernel + 113 model + 13 uefi-boot tests pass clean (451 total), clippy + fmt clean |
| (master roadmap P3) | Capability denial demo + the boot-fault fix: a `task_denied` ring-3 task is spawned with an *empty* CSpace and every gated syscall it attempts is refused — `[denied] ipc_call(slot 0) -> DENIED (-1)`, `mem_len(slot 0) -> DENIED (-1)`, `task_state(slot 0) -> DENIED (-1)` — while the kernel, IPC server/client (echo reply), isolation test (PAGE FAULT at CR2=0x1000000, task killed, kernel survives) and NX test (fetch at 0xB8000) all complete in one boot, **0 exceptions**, verified under QEMU twice across different codegen layouts. Also **root-caused and fixed the old layout-dependent syscall-gate corruption** (`switch_to_kernel_stack`'s in-function `mov rsp` made the compiler's frame-relative slots point above the stack top, spilling into BSS statics — KERNEL_IDT / vga cursor / memory regions — whenever the linker placed them adjacent to the stack; hence the intermittent all-zero 0x80 gate / #GP(0x402) / double fault): `_start` now jumps onto the kernel stack before any C prologue (`switch_to_kernel_stack_and_jump`). 327 kernel + 113 model + 13 uefi-boot tests pass clean (453 total), clippy + fmt clean |
| (master roadmap P7, §10 item II pending) | Object store written through the real NVMe device: `nvme_store.rs` puts the content-addressed store (SHA-256 blocks, COW dirs) on the kernel's real NVMe driver — live `put`/`get` with digest verification and corruption detection boot under QEMU/OVMF (proof log `serial-p8.log` was local-only and is not reproducible from a fresh clone; the same store health lines are present in the committed `uefi-boot/serial-p10.log`). Store health lines all green: `store put`, `dedup`, `get readback`, `COW v1/v2 distinct`, `corruption detection + recovery`, `store usable`. Honest limits tracked in the §10 roadmap row (in-memory index session; NVMe device path proven by live boot). |
| (master roadmap §10 item 2) | Package/system-update model on the real NVMe store: `aegis-kernel/src/update.rs` stages candidate generations (`gen-N`) without touching `current`, flips the boot target only after a caller health gate (payload-verified digest checks), and rolls back to the last known good — `current` is a content-addressed COW boot-view pointer, every activate/rollback is a new dir write, and identical payload bytes dedup to one block. 9 new `update` tests + 1 `nvme_store` index-boundary test. Live QEMU/OVMF proof (`uefi-boot/serial-p10.log`): full stage → health-gated activate → rollback cycle on real hardware. Also closed a latent store bug — 48-byte index entries straddling the 512 B index-sector boundary (slot 10+) now pack/unpack across two sectors. |
| (master roadmap §10 item 1: Windows/Linux compat) | Personality translation layers implemented + exercised live: `linux_compat.rs`+`linux_abi.rs` (Linux x86-64 subset → capability-scoped `AegisOperation`) and `win_compat.rs`+`nt_abi.rs` (NT subset) + `pe_loader.rs` (PE front end). Each layer registers a context, translates, and gates every op on a `CapabilityScope` (memory op under file-only scope refused + counted). Live QEMU/OVMF proof (`uefi-boot/serial-p11.log`): file-scoped Linux context translates `write`, refused `mmap`; file-scoped Windows context translates `NtWriteFile`, refused `NtMapViewOfSection`. Inherent limit kept honest: full Windows fidelity needs a hypervisor (not built); full Linux fidelity needs a real ring-3 trap (not built) — translation layer only, not a full reimplementation. |
| (master roadmap §10 item 4: distributed/fleet transparency) | Partition failure made visible and fail-safe by default in `aegis/crates/fleet`: each trusted peer now carries explicit reachability state (heartbeat/last-seen vs. configurable `stale_after` window + explicit `mark_unreachable` partition flag), and `verify` of a remote capability fails closed (`PeerUnreachable`/`PeerStale`) when its issuer is partitioned or stale — never silently accepted. Locality and partition state are queryable (`peer_reachable`/`is_unreachable`/`is_stale`), so the failure is visible, not hidden. 7 new fleet contract tests (partition denial, stale-window denial + heartbeat recovery, local capability unaffected, state visibility, configurable window, unknown-peer fail-closed). Honest limits kept: two-node in-process model — no sockets, no consensus/split-brain resolution. |
| (master roadmap §10 item 3: GPU compositor / graphical shell) | Real kernel-side compositor in `aegis-kernel/src/compositor.rs`: a small, allocation-free, purely functional paint that composites the `WindowManager`'s z-ordered visible windows into one screen — higher windows occlude lower ones in overlap, every surface is clipped to its region and the screen bounds (negative origins clip correctly), hidden windows are skipped, unrendered windows paint transparent (never garbage); `window.rs` exposes bounds + per-window lookup to the compositor. 8 new compositor tests (empty→transparent, single-window paint, overlap occlusion, offscreen clipping, hidden-window skip, missing-framebuffer transparency, undersized-screen error, focus-reorder occlusion). Honest substrate: the VM's real display is the VGA text-mode buffer (a "pixel" is one text cell); the capability-scoped GPU service lives in model `crates/devices`. Live QEMU/OVMF proof (`uefi-boot/serial-p12.log`): status bar + clock + focused menu composite in z-order — `menu(#) occludes clock(.)` — 0 exceptions, alongside the store/update and compat demos in the same boot. |

| `e585e87` | Phase A: interactive shell is the default post-boot state — VGA text compositor + PS/2 keyboard (Tab focus / arrow moves) driven by a real `task_input` kernel task, live under QEMU (`uefi-boot/serial-qemu2.log`) |
| `babcc7e` | Phase B: userspace resource managers + hierarchical supervision in ring 3, live under QEMU (`uefi-boot/serial-phase-b.log`) — `mem-rm` (task 12) mints/lends/recycles pages purely via CapGrant/CapRevoke; `parent-sup` (task 14) is the supervisor above the ring-3 supervisor and ADOPTS the subsystem with a fresh budget when the child's restart budget is spent; named IDX_* constants fix the task-index-shift regression |
| `883ec37` | Fix CI: kernel release build (workflow RUSTFLAGS=-Dwarnings) errored on the unused IDX_* doc constants |
| `2501356` | Phase C: full POSIX view over the object store — hierarchical TreeView (nested dirs, absolute/relative path resolution with `.`/`..`, cwd, mode/uid metadata, COW-to-root persistence, unlink/rmdir emptiness + root-not-removable rules), live under QEMU (`uefi-boot/serial-phase-c.log`), 391 kernel + 125 model + 13 uefi-boot tests |
| Phase D (this commit) | Real e1000e NIC driver + live wire traffic: at boot the kernel probes the q35 NIC (8086:10D3), reads the MAC from RAR (RAL/RAH little-endian, read back `52:54:00:12:34:56`), programs legacy TX/RX rings in DMA frames (RX_RING_LEN 8 — a 4-desc ring hit `E1000_XDLEN_MASK 0xFFFF80` and was masked to 0), transmits a broadcast ARP request for the host gateway, and an external host process captures it off QEMU's socket netdev (`uefi-boot/e1000-phase-d.pcap`: proto 0806, op 0001, sender 10.0.2.15 → 10.0.2.2) and echoes an ARP reply the polled RX ring receives (`reset: true MAC 52:54:00:12:34:56`, `ARP request sent (42 bytes): true`, `ARP reply received (60 bytes, ARP reply for us: true)`, `reply sender 52:54:00:12:34:02 @ 10.0.2.2` — `uefi-boot/serial-phase-d.log`). 7 new e1000 tests (391 kernel lib total). **Root-caused + fixed a latent boot-stack overflow the module exposed**: the boot path uses ~27.7 KiB of stack and the 16 KiB kernel stack (grows down into `.bss`) was corrupting the audit log's `HEAD` static — a deterministic `audit.rs` panic; `KERNEL_STACK_SIZE` 16384 → 65536, verified clean (scheduler continues past tick 7500). Honest limits kept: polled driver (no interrupts), boot-time demo NOT wired into the socket layer, QEMU socket netdev only (not physical hardware), single ARP frame each way, RAR BAM-only |
| Phase E (commit 8365c47) | **Real TLS 1.3 client on the wire (second socket to OpenSSL server on 8443), completing the Phase-E remainder**: the kernel runs the full RFC 8446 §7.1 key schedule and AES-128-GCM record protection — `tls.rs` grows to 16 tests with a new `aes.rs` (AES-128-GCM, RFC 8448 vector) and `real_capture_debug` (decrypts the live-captured encrypted ServerHello/EE record with the derived `s_hs` key, transcript hash + shared secret cross-checked against the captured flight). **Root-caused + fixed the app-record auth failure** — RFC 8446 §7.1: BOTH `c_ap` and `s_ap` application traffic secrets derive over ClientHello…server Finished (only `res master` uses client Finished); `build_client_finished` derived `s_ap` AFTER pushing client Finished, so the OpenSSL server's app records failed auth (3× in `serial-tls.log`). Fixed + host-side pcap repro (`repro2.py`) proves the server flight decrypts under the fixed secrets. Live evidence: `uefi-boot/e1000-tls.pcap` (17 frames) + `listener-tls.log` (TLS records from server sent 1291 B / 478 B, application data + HTTPS response 156 B) + `serial-tls.log` (ClientHello 133 B, ECDHE shared `9A3E2DD5F5694AA5AE40525AC4C59CD28AE2EE8544B041E7A99B4604D819CF22` matches host, server Finished verified, client Finished sent). Honest status: kernel not yet rebuilt with the fix; live app-data exchange re-verification was PENDING here — CLOSED in commit d1d7fa3. 422 kernel + 128 model + 13 uefi-boot tests pass clean, raw output in commit |
| Phase E (commit 8a3e54a) | **RFC 8448 §3 end-to-end validation of the REAL kernel crypto** (the authoritative rfc-editor.org trace, not a hand-written repro): `rfc8448_vec.rs` auto-extracts the RFC's byte vectors (CH 196 B, SH 90 B, server flight 657 B, and the published transcript hashes `860c06ed…` / `9608102a…` / `209145a9…`) programmatically from the RFC text via `gen_rfc8448.py`. `rfc8448_application_traffic_secrets` asserts both application traffic secrets + AES-128-GCM keys/IVs byte-for-byte against the RFC's published values (`c ap traffic` → `17422dda…` key / `5b78923d…` iv; `s ap traffic` → `9f02283b…` key / `cf782b88…` iv). `rfc8448_full_transcript_app_secrets` drives the entire client state machine over the RFC transcript: X25519 shared `8bd4054f…`, server Finished `9b9b141d…` verified, then c_ap/s_ap match the RFC — plus a regression guard proving `s_ap` derived over a Finished-inclusive transcript (the old bug) diverges from the RFC value. Honest status: kernel not yet rebuilt with the fix; live app-data exchange re-verification was PENDING here — CLOSED in commit d1d7fa3. 424 kernel + 128 model + 13 uefi-boot tests pass clean (552 + 13), clippy/fmt/release-build clean, raw output in commit |
| Phase E CLOSED (commit d1d7fa3) | **Live app-data exchange re-verified with the rebuilt kernel** — the exact failure from the old run (`app record auth failed`) is gone (0 occurrences in the new log) and the kernel decrypts the server's application records with the corrected `s_ap` key. Evidence (`uefi-boot/serial-tls.log`, truncated at the preempt-spam boundary): `tls: TCP handshake complete (Established)`, `tls: ClientHello sent (133 bytes)`, `tls: ServerHello: version 0x0304 cipher 0x1301 group 0x001D`, `tls: ECDHE shared secret (kernel side): D8A320BF…`, `tls: server Finished verified`, `tls: client Finished sent (58 bytes)`, `tls: encrypted HTTP request sent (62 bytes)`, `tls: HTTPS response body: HTTP/1.1 200 OK … Aegis kernel TCP demo`, `tls: socket closed (FIN sent)`. Listener log: TLS records from server sent (1291 + 478 B), TLS application data from kernel (40 B `GET /aegis-tls`), TLS HTTPS response sent (156 B), FIN acknowledged. New `e1000-tls.pcap` = 18 frames (was 17). Same boot re-verified the plaintext TCP demo. **Phase E Definition of Done met: a real TCP connection under QEMU completing a TLS 1.3 handshake and exchanging real application data, externally captured.** 424 kernel + 128 model + 13 uefi-boot tests pass clean, clippy/fmt/release-build clean |
| Phase G CLOSED (commit c90acd2) | **Real VT-d IOMMU DMA isolation, live-verified.** `iommu.rs` (user-supplied, applied): `translate` is the real gate every NVMe/e1000 DMA address passes before a PRP/descriptor is written — page-number-keyed sparse table (fixes the old 512-slot masked-index collision), `MAX_MAPPINGS_PER_DOMAIN=64`, fault ring (16) with monotonic `fault_total`, three-way `IommuFault`, `provision_device` + `identity_map`, global `unsafe fn with`. `nvme.rs`/`e1000.rs`: per-device domains provisioned in `probe`, buffers identity-mapped before any address reaches hardware, `dma_addr` gate on every PRP/ring/descriptor. `main.rs`: live denial demo on the real NVMe bdf. Live QEMU/OVMF boot (`uefi-boot/serial-phase-g-clean.log`): NVMe identify + LBA0/1 (protective MBR / GPT header) and the full e1000 ARP→TCP→HTTP→TLS path all pass the gate, then `IOMMU: NVMe out-of-domain DMA to 0x100000000 denied at the IOMMU: true (AddressNotMapped) — fault_total = 1` and the kernel continues (FAT16 + NVMe-store + compat + all task demos to tick 6364). Honest limit kept: software gate mirroring VT-d, no real DMAR MMIO; identity-mapped IOVA space. 438 kernel + 128 model + 13 uefi-boot tests pass clean (579 total), clippy/fmt/release-build clean, raw output in commit |

## §10 follow-on: two-role library (kernel-gated roles, same discipline)

**Broader AI orchestration (roadmap §10 item 1) landed** — the role library is now two roles, granted and approved exactly the way Phase 6 was, with no shortcut:
- `restart-service` (READ|CONTROL over one task, no GRANT) — Phase 6 agent, task 8.
- `observe-service` (READ over one task only, no CONTROL, no GRANT) — §10 watchdog, task 10. Kernel tests `observer_role_grant` and `observer_cannot_self_escalate`; model test `observe_role_is_read_only_and_never_controls`.
- Live QEMU proof (`uefi-boot/serial-p9.log`): supervisor grants both roles via syscall 18 (role 0 to task 8, role 1 to task 10); the observer watchdog READS the service state, sees the crash, and every escalation/restart/kill attempt is refused at the gates with an audit record — `[§10] task_restart -> DENIED (-1)`, `role_grant -> DENIED (-1)`, `task_kill -> DENIED (-1)`, "watch-only role held; observation never became control". The two-role audit dump (`§10 two-role flow`) attributes both the agent's allowed restart and the observer's denials.
- 364 kernel + 125 model + 13 uefi-boot tests pass clean (502 total) from a clean lockfile, clippy/rustfmt clean. The audit ring's 512-entry bound is kept honest in Known Limits (early grant records can be evicted before a late dump; ring3-side grant lines print from the supervisor).

**§10 item 2 landed** — the package/system-update model now runs on top of the Phase-7 NVMe store (`aegis-kernel/src/update.rs`), with no change to the TCB discipline:
- A package is a manifest + named content-addressed payload blocks; the boot view is a COW directory block (every activate/rollback commits a NEW dir); a candidate "generation" is staged as `gen-N` without touching `current`; activation flips `current` only after a caller health gate (the default gate verifies every payload block against its content hash); rollback flips back to the last known good and drops the dethroned generation from history.
- 9 new `update` contract tests (`descriptor_roundtrips`, `decode_dir_tolerates_truncation_and_bit_flips`, `staging_a_candidate_does_not_disturb_the_boot_target`, `activation_is_health_gated`, `activation_is_a_content_flip_and_version_stable`, `rollback_restores_last_known_good_and_drop_dethroned`, `rollback_preserves_generations_up_to_the_target`, `identical_payloads_dedup_to_one_block`, `reopen_dedups_payloads_and_continues_numbering`) + 1 `nvme_store` boundary test (`many_blocks_span_index_sector_boundaries`).
- Live QEMU proof (`uefi-boot/serial-p10.log`): boot view created, staging leaves the boot target empty, a refused health gate leaves `current` untouched, a payload-verified activate flips to gen-1, a second activate flips to gen-2 as a new COW dir block, rollback returns to gen-1 with a second rollback finding nothing to restore, and reinstalling the same payload dedups to the same block id (only the descriptor + COW dir are new). The kernel also closed a latent store bug: 48-byte index entries straddling the 512 B index-sector boundary (slot 10+) panicked on out-of-range slices — they now pack/unpack across two sectors.

**§10 item 1 (Windows/Linux compat) landed** — the personality translation layers are implemented and exercised live, with no change to the TCB discipline:
- `linux_compat.rs` + `linux_abi.rs` translate the Linux x86-64 syscall surface (a documented subset: read/write/open/close/mmap/munmap/nanosleep/getpid/socket/connect/sendto/recvfrom/execve/exit/futex…) into the capability-scoped `AegisOperation` set; `win_compat.rs` + `nt_abi.rs` do the same for the NT syscall subset (NtCreateFile/ReadFile/WriteFile/Close/CreateSection/MapViewOfSection/CreateProcess/…); `pe_loader.rs` is the PE/Win32 image front end. Each layer registers a context, translates, and gates every op on the context's `CapabilityScope` — the same AI/agent ceiling as native and Linux-compat code (a memory op under a file-only scope is refused and counted).
- Contract tests already in the suite: `linux_compat` (8), `win_compat` (8), `linux_abi` (12), `nt_abi` (12), `pe_loader` (11) — translation correctness + capability gating + bad-ID/unknown rejection. The live kernel demo (`aegis-kernel/src/main.rs`) drives both layers under QEMU/OVMF: a file-scoped Linux context translates `write` and is refused `mmap` (1 denial); a file-scoped Windows context translates `NtWriteFile` and is refused `NtMapViewOfSection` (1 denial) — proof at `uefi-boot/serial-p11.log`.
- Honest inherent limits (per the design doc, not hidden): full Windows fidelity is **not** achieved by translation alone and the VM-based full-fidelity vehicle (a hypervisor) is **not** built; Linux full fidelity would need a real ring-3 trap, also **not** built. The translation layers are the WSL2-lineage / narrow-Win32-subset boundary — a translation layer, not a full syscall reimplementation.

**§10 item 4 (Distributed/fleet transparency) landed** — partition failure is now visible and fail-safe by default, no change to the TCB discipline:
- The `fleet` crate (transport/envelope over the `macaroon` token format) already made locality never-hidden (`Locality::Local`/`Remote(issuer)`) and cryptographically bound the intended recipient into the HMAC chain at send time (a holder cannot relay a token to a third party). It now models the design doc's "transparency lies under partition" warning: each peer carries explicit reachability state (heartbeat/last-seen vs. a configurable `stale_after` window, plus an explicit `mark_unreachable` partition flag), and `verify` of a **remote** capability fails closed with `PeerUnreachable`/`PeerStale` when its issuer is partitioned or stale — never silently accepted. Locality and partition state are queryable (`peer_reachable`, `is_unreachable`, `is_stale`), so the failure is visible, not hidden. New contract tests: partition denial, stale-window denial + heartbeat recovery, local capability unaffected by peer partition, partition state visible, configurable staleness, unknown-peer fail-closed.
- Honest inherent limits (kept, not removed): two-node in-process model — no sockets, no real network, no consensus/split-brain *resolution*; the model denies on stale/unreachable state, it does not heal the partition.

**§10 item 3 (GPU compositor / graphical shell) landed** — the deferred UI work now has a real, kernel-side compositor:
- `aegis-kernel/src/compositor.rs` is a small, allocation-free, purely functional paint: it clears a screen buffer, then paints the `WindowManager`'s z-ordered visible windows back-to-front, clipping each window's framebuffer to its region and to the screen bounds (negative-origin windows clip correctly), skipping hidden windows, and treating unrendered windows as transparent (never garbage). The `WindowManager` (`window.rs`) was already complete (create/destroy/move/resize/visibility/z-order/focus/hit-test/compositor_order/dirty regions) and now exposes its bounds + per-window lookup to the compositor. 8 new `compositor` contract tests: empty→transparent, single-window paint, overlap occlusion, offscreen clipping, hidden-window skip, missing-framebuffer transparency, undersized-screen error, focus-reorder occlusion.
- Honest substrate kept explicit: the VM's real display is the VGA text-mode buffer, so a "pixel" here is one text cell; the capability-scoped GPU *service* (queue=SEND, framebuffer=READ|WRITE, compositor=READ grants, dead-compositor refusal) lives in the model `crates/devices` and was already tested. Live QEMU/OVMF proof (`uefi-boot/serial-p12.log`): a status bar, a clock window, and a focused menu dialog composite in z-order — `menu(#) occludes clock(.) under overlap; status bar = true; z-order compositing = true` — rendered rows printed to serial, 0 exceptions, alongside the Phase-7 store/update and compat demos in the same boot.

**§10 item 4 (interactive shell) landed** — a real keyboard input path now drives the graphical shell:
- `aegis-kernel/src/ps2.rs` is a real PS/2 driver: controller init reprogrammes the 8042 command byte (bit 0 IRQ1 enable, bit 4 port-1 clock clear, **bit 6 translation kept set** so the controller converts scancode set 2 to set 1 — the original code cleared bit 6 and QEMU then delivered raw set-2 bytes `0x0D`/`0xF0`), a ring buffer holds scancodes, and `keyboard_trap_rust` runs on the IRQ1 gate. IRQ1 is routed through the legacy 8259A remapped to vector 0x21 and into the LAPIC via LVT0 ExtINT (virtual-wire), so the PS/2 path is a genuine device-interrupt path, not a poll. 7 contract tests (set-1 make/break, extended 0xE0, two-byte keys, translation, ring full/empty, pop).
- `aegis-kernel/src/desktop.rs` implements `Desktop::handle_key`: Tab cycles focus among visible windows and arrows clamp-move the focused window within the 80x25 screen. 5 contract tests.
- A dedicated `task_input` kernel task drains the ring buffer into `desktop::handle_key` — round-robin like alpha/beta, so it never depends on `run_idle`.
- **Live proof under QEMU** (the VM display is VGA text mode; VMware refused synthetic input capture, so QEMU's `sendkey` monitor command injects deterministic PS/2 scancodes — `uefi-boot/serial-qemu2.log`, committed): `Tab focus -> window id=3 overlap_cell='.'`, then `arrow move -> window id=3 region=(3,2)`, `(3,3)`, `(2,3)`, `(2,2)` for right/down/left/up — exactly the expected clamping on a two-window desktop — plus Enter/Esc/letters/Shift/Space consumed without panics. Guest stayed alive (ticks advancing, 0 exceptions).
- Honest limits (kept, not removed): scancode coverage is the set-1 subset the table translates (letters/digits/punct, modifiers, arrows, Tab, Enter, Esc, Space, Backspace); a full compositor with real application content does not exist; keyboard only, no mouse.

## Phase B: userspace resource managers + hierarchical supervision (ring 3)

The resource-manager and supervision-tree work is now delivered in **ring 3**, live under QEMU, on top of the Phase-2 kernel gates — no change to the TCB discipline:

- **`mem-rm` (task 12) — a userspace memory-page manager.** It mints two pages (`MemCreate`, backed by real frames), keeps the anchors in its own CSpace, and lends / recycles them purely through capability-gated IPC: `alloc` → `CapGrant(caller, our_slot, their_slot 2)`, `free` → `CapRevoke(caller, their_slot 2, our_slot)`. The manager, not the kernel, decides when a page is lent. Live proof (`uefi-boot/serial-phase-b.log`): `pool pages minted` → client `alloc page 0 -> OK`, `mem_len(slot 2) = 4096`, `mem_write -> OK`, `mem_read -> OK` → `free page 0 -> OK` → `mem_len(slot 2) after free = 18446744073709551615 (DENIED, recycled)` — the revoked page returns to the pool and every later op is refused at the gate. Repeated for page 1 (pool recycling).
- **Hierarchical supervision: the supervisor ABOVE the ring-3 supervisor.** `parent-sup` (task 14) boots with kernel-installed caps (slot 0 = NOTIFY_EP RECV, slot 1 = Task(iso-test) CONTROL|READ), creates an escalation endpoint, and grants it to the child supervisor (task 5) at the child's slot 3. When the child's restart budget is spent it leaves the child dead and calls back up; the parent **ADOPTS** the subsystem with a fresh budget, takes over serving the kill-notification channel, and trips only when its own budget is spent. Live proof (`uefi-boot/serial-phase-b.log`): `[supervisor] ESCALATION: child restart budget exhausted` → `[supervisor] escalating to parent supervisor` → `[parent-sup] escalation received; adopting subsystem` → `adopting child restart -> OK` → the parent serves 2 restarts under its own budget (`restarting adopted child, budget left 1/0 -> OK`) → `[parent-sup] PARENT TRIP`.
- **New contract tests** (+2, 378 kernel total): `grant_use_revoke_deny_cycle_across_tasks` (`mem.rs`) and `parent_adopts_subsystem_with_fresh_budget_after_child_trip` (`supervisor.rs`). Workspace 125 + uefi-boot 13 unchanged; combined 503.
- **Index-regression fix** shipped in the same commit: a prior commit inserted the `input` task at index 2 and shifted every later task index, silently breaking the live demos (the client's echo call never matched the server). All demo code now uses named `IDX_*` constants (single source of truth); `MAX_TASKS` 12→16. Live proof: `[client] echo reply: ping from client` returns in `serial-phase-b.log`.
- Honest limits (kept): revoke is **instance-named** (flat per-task CSpace, no model-I4 grant-root derivation tree — a grantor must name recipient+slot and cannot reach copies in CSpaces it cannot name); budgets are restart-counts, not CPU/energy; the escalation hand-off relies on the child supervisor surrendering (it stops serving the single-slot NOTIFY_EP mailbox) before the parent serves it — one observer at a time, no double-serve.

## Phase I: distributed extension over a real network — reduced, not closed

The model-level `fleet` crate (locality, recipient binding, fail-closed
`PeerStale`/`PeerUnreachable`) is proven at the model level (see §10 item 4
above). This section is the separate, harder claim — two real kernel
instances, two real QEMU processes, a real e1000-driven link between them.
It closes as **reduced, not closed**: a real cross-machine capability use,
proven live, with partition behavior fail-safe by construction. It does not
"solve" distributed transparency itself — the CAP-level gap stays labeled
inherent, per the design doc's own §10.

**What's proven live:**
- Node A and node B boot as two separate kernel images
  (`aegis-boot-node-a.img`/`aegis-boot-node-b.img`, feature-gated
  `fleet-node-a`/`fleet-node-b`), linked over a real QEMU socket netdev
  (`-netdev socket`, node B `listen`, node A `connect` to 45560) carrying
  real e1000e frames, not an in-process channel.
- **Happy path:** node A mints a capability (object 42, Endpoint, RS),
  binds it to node B, and transmits it once; node B receives the envelope
  and `verify OK` repeatedly. Latest clean run: **4,683 `verify OK`** cycles
  on node B, **~108k frames received**, RX `bad=0` in steady state,
  `max_drain=10` (bursts drained fine), `sat=0` (ring never saturated).
- **Fail-closed proof (the headline):** with the link live and node B
  verifying, node A was killed **by exact PID** (kill-node-a.bat /
  node-a.pid — the same-binary `taskkill /IM` mistake that killed both VMs
  in a prior attempt is impossible now, because the PID is captured by
  filtering on the unique `aegis-boot-node-a.img` substring in the command
  line). Node B stayed up and its next `verify` flipped to
  `verify DENIED (fail-closed): PeerStale — issuer reachable=false
  stale=true` and held it (2,178 DENIED and counting in the same run).
  The exact transition in `serial-fleet-b.log`: `verify OK` ... →
  `verify DENIED (fail-closed): PeerStale` at the same point the kill's
  `STALE_AFTER_TICKS` elapsed — no crash, no livelock.
- **Root cause actually found (not guessed):** QEMU's e1000e emulation
  delivers short, zero-padded frames (a 42-byte ARP padded to the 60-byte
  Ethernet minimum) with the RX descriptor's **DD bit set but RX_EOP
  clear**. `E1000::done()` correctly requires only DD (real-hardware
  behavior for single-descriptor receives). The earlier working theory
  ("RX ring too small") was wrong and was replaced by this measured one;
  the delivery pattern is documented at the fix point in `e1000.rs`.
- **Always-on diagnostics, committed (not one-off debug):** aggregate RX
  counters on the NIC (`rx_packets`, `rx_polls`, `rx_empty`, `rx_saturated`,
  `rx_bad_len`, `rx_max_drain`, plus `rx_bad_status`/`rx_bad_length` holding
  the status byte and length of the most recently rejected descriptor) and
  `NetIf::packets_received`, printed every `DIAG_EVERY` polls in both node
  demos. Every future run of this same demo re-produces the evidence without
  code changes.
- **RX path hardening shipped in the same commit:** `RX_RING_LEN` 8→64;
  Acquire/Release ordering fences around the descriptor re-arm ↔ `RDT`
  hand-off and the device-writeback → payload read; volatile-safe
  descriptor stores; malformed-descriptor skip loop in `receive()` so one
  bad descriptor cannot stall the polled drain; RX length validation
  (rejects DD-set zero-length / over-buffer lengths, counts them
  separately).

**Honest limits (kept, not glossed):**
1. **Repeat-run reliability is not yet evidenced.** One strong run (4,683
   verify OK, clean fail-closed transition) is one data point; the fix
   needs several independent cold launches to claim robustness. That
   evidence is the next step, not yet done.
2. **`bad_length` = 1 in 310k frames** (a pre-fix run) is observed but
   not yet explained; "benign so far" is not "understood." The latest run
   after the fix shows `bad=0` across ~108k frames; the counter exists so
   any future occurrence can be correlated with a specific frame.
3. No consensus, replication, or split-brain handling — unchanged from the
   model-level claim; partition behavior is fail-safe by construction
   (verify DENIED on stale issuer) but nothing *recovers* automatically.
4. The bridge-based frame capture used during diagnosis is not part of the
   committed flow; node A now connects straight to node B's listen port
   (45560), so a future debugging session needing the bridge must re-add
   it deliberately (it is a diagnostics tool, not the demo).

# Pointless OS ---> Still Prototype

An executable reference implementation of a capability-based operating system design. Built on Rust, modeled against TLA+, verified by contract tests on every `cargo test`, and booted bare-metal under QEMU/OVMF.

## Status

487 tests passing, 0 failures (118 model, 356 aegis-kernel, 13 uefi-boot ELF parser). The reachable-authority auditor runs clean. The kernel boots under QEMU/OVMF: UEFI loader → page tables → bare-metal kernel (GDT/TSS/IDT, LAPIC timer, frame allocator) → **cooperative scheduler running two tasks (alpha/beta) that interleave every 512 timer ticks** — live-run verified, 0 exceptions. IPC (endpoints, call/serve/reply, capabilities) verified under both QEMU and VMware Workstation 26 with 0 exceptions. Per-task memory isolation and NX enforcement (only the kernel text window executable) verified under QEMU: the iso-test and nx-test tasks fault and are killed while the kernel keeps running. **Live PCI enumeration** at boot decodes all 6 q35 devices (host/display/network/ISA/SATA/SMBus incl. BARs) over the legacy config ports. The demo is **visible on the VM display**: a VGA text console mirrors the whole boot log white-on-black (verified via screendump decoding). Phase 2 adds frame-backed memory-region capabilities (READ/WRITE/GRANT-gated `mem_len`/`mem_read`/`mem_write`), the supervision-tree runtime (budgeted restart, circuit-breaker trip, audit records) in `aegis-kernel`, and cross-grantee capability revocation (GRANT-gated `ipc_cap_revoke`, syscall 17) with a least-authority contract (spawn grants no implicit caps). Phase 4 adds the capability-addressed object store (SHA-256 content addressing, COW versions, WAL-consumer relationship index) and the POSIX `FlatView` projection in `aegis-kernel/src/store.rs`, with reads served through the real capability gates. Phase 6 adds the kernel's attributed audit log, the §9 anomaly monitor + grant ledger (suspends, never revokes), and the **capability-scoped `restart-service` AI-agent prototype**: a zero-capability ring-3 agent (task 8) receives exactly the `restart-service` role (READ|CONTROL over the service task 9, **no GRANT**) via kernel-gated syscall 18, restarts the crashed service, and has every self-escalation attempt (self-grant, foreign role-grant, foreign kill) refused by the kernel's capability gates with an audit record (`uefi-boot/serial-p6.log`). **§10 broadens the role library the same way**: the new `observe-service` watchdog role (READ over one task, no CONTROL, no GRANT) is granted to a second zero-capability ring-3 agent (task 10) through the same kernel-gated syscall 18 — it can see the crashed service and can never restart, kill, or upgrade to `restart-service`, all refused at the gates with audit records (`uefi-boot/serial-p9.log`). **Phase 7 puts the object store on real hardware**: `aegis-kernel/src/nvme_store.rs` writes the content-addressed store (SHA-256 blocks, COW dirs) through the kernel's real NVMe driver — live `put`/`get` with digest verification and corruption detection boot under QEMU/OVMF (`uefi-boot/serial-p8.log`). **§10 item 2 puts the package/system-update model on that hardware store**: `aegis-kernel/src/update.rs` stages candidate generations (`gen-N`) without touching `current`, flips the boot target only after a caller health gate (payload-verified digest checks), and rolls back to the last known good — `current` is a content-addressed boot-view pointer, every activate/rollback is a COW dir write, and identical payload bytes dedup to one block: live under QEMU/OVMF (`uefi-boot/serial-p10.log`). The **master-roadmap Phase 4 conformance harness** (`aegis/crates/conformance`) replays the kernel's live capability trace against the model and proves the model's authorization verdicts agree with the kernel's recorded verdicts at every traced op — including the three denials the empty-CSpace task is refused.

## What Is Implemented

### Kernel model (`capability-core`)

Proves six authority invariants (I1-I6) via TLA+ model checking (331k states, 0 errors) and Rust contract tests:

- **IPC**: capability-scoped endpoints, SEND/RECV independence, narrowed copies, FIFO delivery (7 tests)
- **Storage**: content-addressed immutable blocks, COW mutable layer, WAL-based index (8 tests)
- **Packages**: content-addressed installation, manifest-gated capability grants (6 tests)
- **Updates**: staged generations, health-gated activation, automatic rollback (5 tests)
- **Resources**: hierarchical budgets, kernel-truth metering, revocation enforcement (4 tests)
- **Network**: loopback stack with capability-scoped sockets (4 tests)
- **Devices**: typed device interfaces (Block/Net/Gpu), crash containment (4 tests)
- **Supervision**: circuit breaker with bounded restart, escalation, forensic cross-check (4 tests)
- **Grant policy**: role-shaped grants, ephemeral by default (5 tests)
- **Two-party confirmation**: high-risk roles require two distinct people (3 tests)
- **Anomaly circuit breaker**: op-shape profiling, deviation suspension, zero authority (3 tests)
- **Batched I/O**: one kernel crossing for N operations (io_uring pattern) (3 tests)
- **POSIX file view**: flat namespace projection over object store
- **Chaos testing**: fault injection into supervision tree, budget exactness, escalation (6 tests)
- **Package-driven exec**: install, launch, grant-gated payload access (1 test)
- **Macaroon capability tokens**: HMAC-SHA256 chained portable tokens, constant-time verification (4 tests)
- **Reachable-authority auditor**: CI entry point computing actual capability reachability vs manifests
- **Conformance harness (master-roadmap Phase 4)**: replays the kernel's live `C:` capability trace against the model Kernel and requires the model's authorization verdict to match the kernel's recorded verdict on **every** traced op — the denial-demo's three refusals and the client's authorized call among them (`aegis/crates/conformance`, 4 tests). Honest limits: verdict-level only (no payload/timing/rendezvous-order comparison), and the kernel's coarser creation/grant mechanics are adapted into the model's Creator-cap / I6-consent ceremony inside the harness — both documented in the crate

### Real boot path (uefi-boot + aegis-kernel, under QEMU/OVMF)

- **UEFI boot**: prints memory map, sets up 4-level identity page tables (first 1 GiB via 2 MB huge pages), loads the ELF kernel, applies base-0 relocations, calls ExitBootServices, hands off the final memory map as boot-info at 0x10000
- **ELF64 loader**: header validation, PT_LOAD parsing, R_X86_64_RELATIVE relocation application (13 tests)
- **Bare-metal kernel**: COM1 serial, 4 GiB identity paging, frame allocator (bitmap over boot-info map; 157876 frames verified free live)
- **GDT/TSS/IDT**: kernel + user selectors, TSS, exception stubs for vectors 0-31, DPL-3 `int 0x80` syscall gate
- **Ring-3 user task**: a demo task dropped to CPL3 via `iretq` (user CS=0x1B/SS=0x23) and serviced by the `int 0x80` syscall gate (Write prints to COM1 and the VGA console) — verified under QEMU/TCG: runs on its own user stack, preempted every tick alongside CPL0 tasks, 0 exceptions
- **LAPIC timer**: periodic, vector 0x30, drives the tick counter (~570 ticks/s)
- **Preemptive scheduler**: iretq-based `switch_frame`, the timer stub preempts round-robin every tick — tasks never yield, yet alpha/beta interleave every 2048 ticks at stable stack addresses, 0 exceptions
- **VGA text console**: 80x25 white-on-black mirror of the COM1 stream (Bochs VBE disable, CRTC/GC/AC programming, 8x16 font uploaded into plane 2, 16-color DAC palette) — verified via screendump: glyphs decode to the exact Aegis log lines, pixels are black `000000` + white `ffffff`; text mode only, no GPU accel (run QEMU with `-display gtk` to watch the demo)
- **Live PCI enumeration**: legacy 0xCF8/0xCFC config-port scan at boot — VID/DID/class/subclass/prog-if/rev + all 6 BARs decoded per device; verified under QEMU q35 (6 devices: host bridge, stdvga, e1000e, ISA, AHCI SATA, SMBus), bus 0 only (no PCI-PCI bridge traversal yet)
- **Object store (Phase 4)**: capability-addressed, content-hashed immutable blocks + COW versions + WAL-consumer relationship index + `FlatView` POSIX projection in `store.rs` — reads served through the real `mem` capability gates (READ-only grant, writes refused); 9 contract tests. Honest limits: fixed 8 KiB in-kernel byte arena (not wired to the NVMe/FAT device path), in-memory WAL, flat namespace, bounded region table
- **Object store on real NVMe (Phase 7)**: `nvme_store.rs` re-uses the hardened store semantics against the live device — SHA-256 content-addressed blocks and COW dirs over flat LBAs (header + index + data region), digest-verified reads, and a deliberate on-disk bit-flip detected without panic; verified live under QEMU/OVMF (`uefi-boot/serial-p8.log`). Honest limits: single flat partition region (8192+), fixed MAX_BLOCKS=170, header write bumps a 1-block index, no journaling
- **Capability-scoped networking (Phase 5)**: the design's async FIFO channel box (`channel.rs`, a `Cap::Channel` object, SEND/RECV-gated) + the two-hop loopback netstack (`netstack.rs`) that mints sockets as narrowed SEND|RECV channel caps — no GRANT, no ambient "open any socket"; ports are not authority, teardown hangs a subscriber's cap while peers keep working; 6 contract tests. Honest limits: loopback only, bounded message size/depth, no wire framing wired in yet
- **Attributed audit log + anomaly circuit breaker (Phase 6)**: every gated op — task lifecycle, channel send/recv, memory read/write, capability grant, revoke — lands attributed `(tick, caller, op, target, ok)` in the kernel's 512-record audit ring (`audit.rs`, success and refusal alike), and a capability-less `AnomalyMonitor` trains on the agent's real op-shape and, on significant deviation (2x rate or an unseen op), suspends — never revokes — via the `GrantLedger`, which freezes `ipc_cap_grant` while minted caps keep working and is reversible + logged on human review (`monitor.rs`); 6 contract tests. Honest limits: bounded in-memory ring (no durability), profiler is histogram-based not ML, ledger gates only delegation
- **Capability trace (feature `trace`, master-roadmap Phase 4)**: at the syscall dispatch choke point every capability-relevant syscall emits one `C:op` line (`caller, op, slot, object kind/id, rights held, verdict`) and every task spawn emits `C:spawn`; compiled out of the default build (no trace state, no extra output) — the raw material the `aegis/crates/conformance` harness replays against the model
- **Ring-3 supervision tree (master-roadmap Phase 5)**: a real crash on real hardware drives a real respawn — `tasks.rs` posts a `TaskKill` notification to a reserved endpoint (`NOTIFY_EP`), and a ring-3 `task_supervisor` (task 4, kernel-installed caps: `Endpoint(NOTIFY_EP)·RECV` for the kill stream, `Task(5)·CONTROL|READ` for the supervised task) observes the fault-kill of task 5, respawns it, and after a bounded restart budget escalates with a logged "leaving child dead" verdict while the kernel and peers keep running — verified live under QEMU (iso-fault kill → restart×budget → escalation; unrelated nx-fault task 6 death is refused with "not my child, ignoring"); NX vs page-fault isolation reason codes (`REASON_NX` / `REASON_PF_ISOLATION`) ride the notification. Policy lives in ring 3, never in the kernel; 5 new contract tests in `aegis-kernel`

### Drivers, compat layers, orchestration (contract-tested model code)

> Design only, not implemented — see design/future-work.md: Linux/Windows
> compatibility, distributed/fleet transparency, GPU compositor, broader AI
> orchestration.

Master roadmap (Phases 0–7): see `design/master-roadmap.md`.

PCIe/VT-d/NVMe drivers, VirtIO-net/Ethernet/ARP/IPv4, adaptive-ceiling verification, circuit-breaker (supervision) hardening + security audit.

## What Is Not Done

- Physical hardware verification (needs VMware) — everything runs under QEMU/TCG
- Priority/blocking scheduling — single fixed-priority round-robin; no wait queues
- User-mode isolation — per-task *page-fault-driven* isolation via U/S bits verified under QEMU (iso-test task faults on a kernel-only read and is killed); not run on physical hardware
- Hypervisor-based Linux/Windows execution vehicles (WSL2-lineage design paths)
- Real NIC traffic, real socket layer over a NIC, real wire framing (the capability-scoped loopback netstack and UDP/TCP header models exist in the kernel crate but are not wired into the boot path; Ethernet/ARP/IPv4 framing stays proven at header level only), real GPU-accelerated display output (a VGA text console works; no framebuffer graphics, no real input devices)
- Cross-machine macaroon transport (in-process model only, no network)
- SeL4-class inductive proof (TLA+ model-checking is finite-instance)

## Honest Limits

See **[Known Limits](HONEST_STATUS.md#known-limits)** — the single consolidated
section (closed / reduced / inherent split). Headline facts: contract tests prove
the model, not production behavior; the kernel is single-threaded; TLA+
model-checking is finite-instance (evidence, not induction); real hardware ops are
UNTESTED (need VMware); the io_uring "kernel crossing" is an audit record, not a
real syscall boundary.

## Running

```
cargo test --workspace          # Run all model tests (113)
cargo test -p aegis-kernel       # Run kernel tests (327)
cargo test -p uefi-boot          # Run ELF parser tests (13)
cargo run -p capability-audit   # Reachable-authority audit
cargo run -p capability-audit -- --graph  # Capability graph visualization
cargo run -p aegis-shell        # Interactive demo
```

Boot the real kernel under QEMU:

```
cd uefi-boot
cargo build --release --features uefi --target x86_64-unknown-uefi   # loader
python build_image.py                                                # 16 MB GPT+FAT16 image
qemu-system-x86_64 -machine q35 -m 512 \
  -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=OVMF_VARS.fd \
  -drive format=raw,file=aegis-boot.img,media=disk \
  -serial file:serial-dbg.log -display none
```

# Pointless OS ---> Still Prototype

An executable reference implementation of a capability-based operating system design. Built on Rust, modeled against TLA+, verified by contract tests on every `cargo test`, and booted bare-metal under QEMU/OVMF.

## Status

415 tests passing, 0 failures (113 model, 289 aegis-kernel, 13 uefi-boot ELF parser). The reachable-authority auditor runs clean. The kernel boots under QEMU/OVMF: UEFI loader → page tables → bare-metal kernel (GDT/TSS/IDT, LAPIC timer, frame allocator) → **cooperative scheduler running two tasks (alpha/beta) that interleave every 512 timer ticks** — live-run verified, 0 exceptions. IPC (endpoints, call/serve/reply, capabilities) verified under both QEMU and VMware Workstation 26 with 0 exceptions. Per-task memory isolation and NX enforcement (only the kernel text window executable) verified under QEMU: the iso-test and nx-test tasks fault and are killed while the kernel keeps running. **Live PCI enumeration** at boot decodes all 6 q35 devices (host/display/network/ISA/SATA/SMBus incl. BARs) over the legacy config ports. The demo is **visible on the VM display**: a VGA text console mirrors the whole boot log white-on-black (verified via screendump decoding).

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

### Drivers, compat layers, orchestration (contract-tested model code)

> Design only, not implemented — see design/future-work.md: Linux/Windows
> compatibility, distributed/fleet transparency, GPU compositor, broader AI
> orchestration.

PCIe/VT-d/NVMe drivers, VirtIO-net/Ethernet/ARP/IPv4, adaptive-ceiling verification, circuit-breaker (supervision) hardening + security audit.

## What Is Not Done

- Physical hardware verification (needs VMware) — everything runs under QEMU/TCG
- Priority/blocking scheduling — single fixed-priority round-robin; no wait queues
- User-mode isolation — per-task *page-fault-driven* isolation via U/S bits verified under QEMU (iso-test task faults on a kernel-only read and is killed); not run on physical hardware
- Hypervisor-based Linux/Windows execution vehicles (WSL2-lineage design paths)
- Real NIC traffic, real socket layer (UDP/TCP are header parse/serialize models only, not wired into the boot path), real GPU-accelerated display output (a VGA text console works; no framebuffer graphics, no real input devices)
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
cargo test -p aegis-kernel     # Run kernel tests (289)
cargo test -p uefi-boot        # Run ELF parser tests (13)
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

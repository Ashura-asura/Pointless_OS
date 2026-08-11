# Pointless OS

An executable reference implementation of a capability-based operating system design. Built on Rust, modeled against TLA+, verified by contract tests on every `cargo test`, and booted bare-metal under QEMU/OVMF.

## Status

355 tests passing, 0 failures (113 model, 229 aegis-kernel, 13 uefi-boot ELF parser). The reachable-authority auditor runs clean. The kernel boots under QEMU/OVMF: UEFI loader → page tables → bare-metal kernel (GDT/TSS/IDT, LAPIC timer, frame allocator) → **cooperative scheduler running two tasks (alpha/beta) that interleave every 512 timer ticks** — live-run verified, 0 exceptions.

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
- **GDT/TSS/IDT**: kernel + user selectors, TSS, exception stubs for vectors 0-31
- **LAPIC timer**: periodic, vector 0x30, drives the tick counter (~570 ticks/s)
- **Cooperative scheduler**: iretq-based `switch_frame` (full GPR save/restore), `yield_now` / `run_idle`, tasks on 16 KiB stacks — verified live: alpha/beta interleave every 512 ticks at stable stack addresses, 6665/6665 consecutive interrupt RSP deltas = 0, 0 exceptions

### Drivers, compat layers, orchestration (contract-tested model code)

PCIe/VT-d/NVMe drivers, VirtIO-net/Ethernet/ARP/IPv4, Linux syscall ABI + ELF loader, Windows NT ABI + PE32+ loader, adaptive-ceiling verification, agent runtime + usage profiler + adaptive grants + policy engine, shell + window manager + object graph + input dispatcher, self-healing hardening + security audit.

## What Is Not Done

- Physical hardware verification (needs VMware) — everything runs under QEMU/TCG
- Preemptive scheduling — tasks are cooperative (`yield_now`); a task that never yields starves the rest
- User-mode isolation — no ring-3 processes, no page-fault-driven isolation yet
- Hypervisor-based Linux/Windows execution vehicles (WSL2-lineage design paths)
- Real NIC traffic (no TCP/UDP), real GPU/display output, real input devices
- Cross-machine macaroon transport (in-process model only, no network)
- SeL4-class inductive proof (TLA+ model-checking is finite-instance)

## Honest Limits

- Task switching is verified under QEMU/TCG only, not on physical hardware.
- The kernel is single-threaded; all contract tests are deterministic model logic.
- The TLA+ proof is finite-instance (2 tasks, 3 slots) — evidence, not induction.
- The "kernel crossing" in io_uring is an audit record, not a real syscall boundary.
- Full Windows compatibility is explicitly unsolved by translation alone (design doc).

## Running

```
cargo test --workspace          # Run all 355 tests
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
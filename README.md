# Pointless OS (Aegis-inspired research substrate)

Pointless OS is an experimental operating system research repository exploring
capability-based substrates and AI-native orchestration for adaptive, auditable,
and resilient system behavior. The project focuses on a small, verifiable kernel
boundary and a userspace stack that treats AI agents as ordinary,
capability-scoped principals rather than part of the trusted computing base.

This repository contains kernel and userspace prototypes, formal models, test
harnesses, and design artifacts intended for research, evaluation, and
engineering experimentation.

## Quick links
- Architecture notes: Docs/ARCHITECTURE.md
- Design monograph: Docs/os-from-first-principles.md
- Honest status and limits: Docs/HONEST_STATUS.md
- Capability model + machine-checked verification: Docs/spec/capability-model.md
- Model SDK guide + runnable example: Docs/spec/sdk.md (`cargo run -p sdk-example`)
- Security audit notes: Docs/SECURITY_AUDIT.md
- Security policy + vulnerability reporting: SECURITY.md
- Threat model (adversary classes, emulation vs real hardware): Docs/THREAT_MODEL.md
- Hardware-evidence track (real firmware results, USB-canary status): Docs/HARDWARE_EVIDENCE.md
- Bridge phase — resume guest-kernel compatibility growth: Docs/BRIDGE_PHASE.md
- Bridge phase — gap inventory (flexible next-target options): Docs/BRIDGE_GAPS.md
- Project report: Docs/PROJECT_REPORT.md
- Licensing + third-party notices: Docs/LICENSING.md

## Vision
- Minimal trusted computing base: enforce isolation and capability semantics in a small kernel.
- Capability-first model: capabilities are the only authority tokens; no ambient root.
- AI as a principal (not TCB): AI agents receive explicit, auditable, and revocable capabilities.
- Modularity and observability: services run in userspace with supervision, extensive telemetry, and a persistent audit trail to support diagnosis and controlled automation.

## Key design principles
- Safety: prioritize memory- and type-safety in system components (Rust is the primary implementation language).
- Verifiability: keep the kernel and core primitives auditable and small enough for formal reasoning and contract tests.
- Least privilege: issuance of capabilities is explicit, role-shaped, and ephemeral by default.
- Separation of concerns: adaptive/AI orchestration is implemented outside the kernel as a userspace service under the same capability constraints.
- Compatibility via projection: present POSIX/Windows compatibility as projection or translation layers that run unprivileged and do not expand the TCB.

## Status

An active research prototype. **The 12 phases of the design-doc roadmap are
implemented as research milestones** (design + a first real implementation per
phase — see the evidence taxonomy in `Docs/HONEST_STATUS.md` for what "done"
means for each feature), with the core architectural claim — a role-granted,
zero-capability AI agent that provably cannot self-escalate, running one real
task — verified live under QEMU. The **live test suite is 949 tests**:
**798 in `aegis-kernel`** (contract tests over the real kernel, **795 with
`--features vmx-demo`**), **137 in the `aegis` model crates**, and **9 in
`uefi-boot`** (loader + ELF parsing + fleet-CFG); fmt/clippy-clean. The authoritative
totals are emitted by CI to `test-summary.json`. An external audit of
the kernel (2026-08-19) found a critical `ipc_cap_grant` bounds bug and
several boundary holes; all are fixed with adversarial tests, and the honest
gap inventory (what is designed-but-not-refactored and what is hardware- or
proof-gated) lives in `Docs/uncovered-from-first-principles.md`.

What is real and live-verified (all under QEMU/OVMF, evidence committed as
serial logs + framebuffer captures):

- **UEFI boot → bare-metal kernel**: 4-level paging, NX enforcement, ELF loader
  with relocations, GDT/TSS/IDT, LAPIC timer, cooperative scheduler with
  per-task page-table isolation (faulting tasks are killed, the kernel survives).
- **Real hardware drivers**: PCI enumeration, an NVMe driver (identify + LBA
  reads, 16 MB namespace), a polled e1000e NIC driver, and a **software VT-d
  IOMMU gate** (`iommu::translate`) that denies a deliberately out-of-domain DMA
  on a live boot while NVMe/e1000 keep operating.
- **Real networking**: a full polled TCP/IP stack drives a real three-way
  handshake + HTTP request/response + close over the wire (externally captured
  in pcap), plus a **real TLS 1.3 client** (RFC 8446 key schedule, X25519 ECDHE
  shared secret byte-matched against the host, AES-128-GCM record protection).
- **Storage + POSIX view**: a SHA-256 content-addressed object store with COW
  snapshots and dedup, on both an in-kernel store and a **write-through NVMe
  store**, with a hierarchical POSIX view (nested dirs, path resolution, cwd,
  unlink/rmdir) verified live.
- **AI orchestration (§11.F target)**: a zero-capability ring-3 agent granted
  the `restart-service` role via kernel syscall 18 — every self-escalation
  attempt (self-grant, foreign role-grant, foreign kill) is refused at the
  capability gates with an audit record.
- **Interactive desktop**: a live compositor desktop rendered to real 800x600
  pixels through a Bochs VBE framebuffer backend, PS/2 keyboard (Tab focus,
  arrow-move), a **PS/2 mouse driver** with a trail-free cursor, window chrome
  (drag/resize/close), a **text editor over the NVMe-backed store**, a
  **hierarchical file browser** (nested dirs, `.`/`..`, mouse-click
  create-dir/file via its action bar), a **shell window** (`ls`/`open`/`cat`/
  `new`/`clear`/`help`), and a **taskbar** (one segment per app window, click
  to focus + raise, focused segment highlighted) — two-boot demos prove
  edited and created files and directories survive a power cycle, and the
  desktop roadmap (phases H…S) is fully landed.
- **GOP-first display backend (real-hardware portability milestone 2)**:
  the UEFI loader queries the **Graphics Output Protocol** before
  ExitBootServices and hands the framebuffer + mode to the kernel in a
  boot-info block; the kernel's `GpuDevice` seam drives the **GOP
  framebuffer** (any resolution, BGRX/RGBX byte order, stride-aware) with the
  Bochs-VBE probe as fallback — the only display path a physical machine
  offers. Live-verified under QEMU/OVMF: the loader sets 800x600 via real
  firmware mode-setting, the handoff round-trips, and the desktop renders
  through the GOP path (taskbar demo 4/4, screendump pixel-matched).
  Honest limit: the GOP framebuffer must sit below 4 GiB (the loader's
  identity map covers 0..4 GiB); framebuffers above that are rejected and
  the kernel falls back.
- **Fleet / distributed**: a two-node link over real e1000e/socket-netdev
  frames — capability envelopes, consensus re-election, split-brain resolution,
  and remote invocation of a transferred capability.
- **Hypervisor groundwork**: a resumable VMX run loop (vmlaunch/vmresume,
  corrected SDM exit-reason map, EPT wired into the VMCS, I/O emulation into
  in-guest device models), a real **Linux guest image** (bzImage + static
  BusyBox initramfs, three standalone boot paths verified), a 4-level EPT
  builder, and a growing guest device set — virtio-blk, 8259 PIC / 16550
  UART / 8254 PIT / PCI config, then **UHCI USB (low-speed HID keyboard, full
  7-TD enumeration live) and a Sound Blaster 16 DSP (reset handshake 0xAA,
  version 4.5, sample-rate playback live)**. **Execution evidence:** Aegis has
  demonstrated live nested VT-x activation and genuine EPT VM-exit handling
  (VMXON → VMCS → VMLAUNCH → guest → EPT violation → real VM exit, under
  QEMU/KVM nested virt). **Phase U-7 progress:** the VMCS field-encoding root
  cause was found (`VM_EXIT_INTERRUPTION_INFO` was `0x440E` not `0x4404`),
  the Linux guest CR0 CD/NW bits were fixed, exception injection back into the
  guest is now working (#PF/#GP injected with error code and CR2 write), and a
  minimal guest IDT with iret handlers was written into guest memory.
  **What is NOT yet proven:** the Linux bzImage takes #GP(0) on its very first
  instruction at RIP=0x100000 (error code 0) — the boot protocol or code
  image setup needs further investigation. So: *guest exception delivery is
  wired but the first instruction faults.*
- **Host-side ACPI + SMP groundwork**: the kernel reads the *real* RSDP/RSDT/
  MADT tables QEMU/OVMF expose (three-tier search; >4 GiB entries rejected by
  the identity map) and enumerates the CPUs/APICs (`SMP: 2 processor(s)
  enabled` on `-smp 2`), with a tested guest-ACPI encoder seam.
- **Model SDK**: the `aegis` model crates are documented as an SDK
  (`Docs/spec/sdk.md`) with a runnable, contract-tested example —
  `cargo run -p sdk-example` walks the role-grant lifecycle end to end
  (denial before grant, propose→diff→confirm, escalation refused, expiry,
  two-party confirmation, circuit breaker, revocation, audit).
- **Hardening**: a real-kernel chaos harness (2000 iterations, 0 fail-open),
  host-side fuzzing over the three kernel boundary parsers (180M inputs,
  0 panics), a TLA+ ceiling proof model-checked through TLC (5.64M states,
  0 errors), and a security-audit certification matrix.

**Honest limits** (details in Docs/HONEST_STATUS.md — the single consolidated Known
Limits section, split into *closed / reduced / inherent*):

- Everything runs under QEMU/TCG or VMware — **no physical-hardware
  certification** of any driver.
- Formal verification is TLA+ finite-instance model-checking, not an
  seL4-class inductive proof.
- The IOMMU is a software gate mirroring VT-d semantics — no real DMAR MMIO
  registers are programmed.
- Networking is polled (no interrupts/MSI-X); TLS uses a fixed deterministic
  scalar (no CSPRNG in the guest); no certificate-chain verification.
- Windows/Linux compat is translation-layer only; the hypervisor path (VMX
  run loop, EPT, guest device models, real Linux guest image) has demonstrated
  live nested VT-x activation and EPT VM-exit handling, with exception
  injection into the guest working, but the guest's first instruction
  faults (#GP at 0x100000) — guest execution is not yet sustained.
- The kernel is single-threaded; contract tests prove the model, not
  production behavior.

## Language composition
- Rust: ~95%
- Python: ~3%
- TLA+: ~1%
- Other: ~0.4%

## Repository layout
- `aegis-kernel/` — the real kernel: boot, drivers, netstack, TLS, store,
  scheduler, supervision, desktop/compositor/editor, compat layers, ACPI/SMP,
   and the hypervisor device models (`cargo test` = 856 tests; **859 with
   `--features vmx-demo`**)
- `aegis/` — model crates mirroring the kernel (capability-core, store,
   net, fleet, grants, conformance, orchestration, etc.; 137 tests) + the SDK
  guide and runnable example in `Docs/spec/sdk.md` and `aegis/crates/sdk-example/`
- `uefi-boot/` — UEFI loader + image build + QEMU demo scripts (22 tests)
- `guest/` — the real Linux guest image (bzImage + BusyBox initramfs,
  build scripts, committed evidence)
- `phase-m-fuzz/` — host-side boundary-parser fuzzing harness
- `aegis/spec/` — TLA+ specs (capabilities + ceiling)
- `Docs/` — design monograph (`Docs/os-from-first-principles.md`), roadmap
  (`Docs/design/`), capability model + SDK guide (`Docs/spec/`), audits,
  licensing, and status docs
- `LICENSE`, `Docs/LICENSING.md` — dual-license terms and third-party notices

## Build & run (high level)

Requires a stable Rust toolchain (see `rust-toolchain.toml`), plus the
`x86_64-unknown-none` and `x86_64-unknown-uefi` targets for the kernel and
loader respectively.

- Run the full kernel suite:
  ```
  cd aegis-kernel && cargo test --release            # 795 tests
  cd aegis-kernel && cargo test --features vmx-demo  # 798 tests
  ```
- Run the model crates:
  ```
  cd aegis && cargo test --release                   # 136 tests
  ```
- Run the SDK example tour:
  ```
  cd aegis && cargo run -p sdk-example
  ```
- Build the boot image and run the editor demo under QEMU (two boots, proves
  file persistence across a power cycle):
  ```
  cd uefi-boot
  powershell -NoProfile -ExecutionPolicy Bypass -File qemu-editor-demo.ps1
  # then check serial-editor-boot2.log for "editor@reopen ... still edited = true"
  ```
- Other live demos: `qemu-browser-demo.ps1` (hierarchical browser with
  mouse-click create, two-boot), `qemu-mouse-demo.ps1`, `qemu-chrome-demo.ps1`,
  `qemu-live-demo.ps1`, `qemu-nonic-test.ps1`.

Exact per-component build/run instructions live in the component READMEs and
the demo scripts' headers.

## Contribution guidelines
- Open issues to discuss proposals and non-trivial changes before implementation.
- Keep pull requests focused and include tests, documentation, or reproducible verification steps.
- Follow project formatting and lint rules (run `rustfmt` and Clippy where applicable) — CI enforces `-Dwarnings`.

## Roadmap (high level)
1. Real-hardware certification (the single largest remaining gap).
2. Real DMAR IOMMU programming and interrupt-driven (MSI-X) NIC paths.
3. Aegis-hosted VM path: the hypervisor groundwork (VMX run loop, EPT, guest
   device models incl. UHCI/SB16, real Linux guest image, guest-ACPI seam) has
   demonstrated live nested VT-x activation and EPT VM-exit handling, with
   exception injection working (Phase U-7), but the Linux guest takes #GP(0)
   on its first instruction — that is the next VMX milestone.
4. More desktop apps on the live desktop: multi-instance spawning (taskbar
   "launch" currently raises the one boot-time instance of each app) and a
   manifest-driven app model (the desktop roadmap itself is complete).

## License
Refer to the repository LICENSE file for licensing terms.

## Contact & attribution
Repository: https://github.com/Ashura-asura/Pointless_OS
Maintainer: @Ashura-asura
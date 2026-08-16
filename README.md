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
- Architecture notes: ARCHITECTURE.md
- Design monograph: os-from-first-principles.md
- Honest status and limits: HONEST_STATUS.md
- Security audit notes: SECURITY_AUDIT.md
- Project report: PROJECT_REPORT.md

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

An active research prototype. **All 12 phases of the design-doc roadmap are
implemented and closed**, with the core architectural claim — a role-granted,
zero-capability AI agent that provably cannot self-escalate, running one real
task — verified live under QEMU. The **full live test suite is 718 tests**:
**568 in `aegis-kernel`** (contract tests over the real kernel,
`cargo test --features chaos-demo`), **128 in the `aegis` model crates**, and
**22 in `uefi-boot`** (loader + ELF parsing), fmt/clippy-clean.

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
  (drag/resize/close), and a **text editor over the NVMe-backed store** — a
  two-boot demo proves the edited memo.txt survives a power cycle
  (`still edited = true` on reboot).
- **Fleet / distributed**: a two-node link over real e1000e/socket-netdev
  frames — capability envelopes, consensus re-election, split-brain resolution,
  and remote invocation of a transferred capability.
- **Hardening**: a real-kernel chaos harness (2000 iterations, 0 fail-open),
  host-side fuzzing over the three kernel boundary parsers (180M inputs,
  0 panics), a TLA+ ceiling proof model-checked through TLC (5.64M states,
  0 errors), and a security-audit certification matrix.

**Honest limits** (details in HONEST_STATUS.md — the single consolidated Known
Limits section, split into *closed / reduced / inherent*):

- Everything runs under QEMU/TCG or VMware — **no physical-hardware
  certification** of any driver.
- Formal verification is TLA+ finite-instance model-checking, not an
  seL4-class inductive proof.
- The IOMMU is a software gate mirroring VT-d semantics — no real DMAR MMIO
  registers are programmed.
- Networking is polled (no interrupts/MSI-X); TLS uses a fixed deterministic
  scalar (no CSPRNG in the guest); no certificate-chain verification.
- Windows/Linux compat is translation-layer only; the VT-x bring-up primitive
  compiles + contract-tests but has not run on a VMX-capable CPU.
- The kernel is single-threaded; contract tests prove the model, not
  production behavior.

## Language composition
- Rust: ~95%
- Python: ~3%
- TLA+: ~1%
- Other: ~0.4%

## Repository layout
- `aegis-kernel/` — the real kernel: boot, drivers, netstack, TLS, store,
  scheduler, supervision, desktop/compositor/editor, compat layers
  (`cargo test --features chaos-demo` = 568 tests)
- `aegis/` — model crates mirroring the kernel (capability-core, store,
  net, fleet, etc.; 128 tests)
- `uefi-boot/` — UEFI loader + image build + QEMU demo scripts (22 tests)
- `phase-m-fuzz/` — host-side boundary-parser fuzzing harness
- `aegis/spec/` — TLA+ specs (capabilities + ceiling) and TLC configs
- `os-from-first-principles.md`, `design/` — design monograph and roadmap
- `docs/` — supplemental documentation

## Build & run (high level)

Requires a stable Rust toolchain (see `rust-toolchain.toml`), plus the
`x86_64-unknown-none` and `x86_64-unknown-uefi` targets for the kernel and
loader respectively.

- Run the full kernel suite:
  ```
  cd aegis-kernel && cargo test --features chaos-demo --release
  ```
- Run the model crates:
  ```
  cd aegis && cargo test --release
  ```
- Build the boot image and run the editor demo under QEMU (two boots, proves
  file persistence across a power cycle):
  ```
  cd uefi-boot
  powershell -NoProfile -ExecutionPolicy Bypass -File qemu-editor-demo.ps1
  # then check serial-editor-boot2.log for "editor@reopen ... still edited = true"
  ```
- Other live demos: `qemu-mouse-demo.ps1`, `qemu-chrome-demo.ps1`,
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
3. Hypervisor-based compat vehicles (VMX bring-up primitive exists).
4. Phase Q onward: more desktop apps on the live desktop (file browser, etc.).

## License
Refer to the repository LICENSE file for licensing terms.

## Contact & attribution
Repository: https://github.com/Ashura-asura/Pointless_OS
Maintainer: @Ashura-asura
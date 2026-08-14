# Security Audit & Certification Status — Pointless OS / Aegis

*Status: 2026-08-10. This document is the honest certification matrix for Phase 12.
No claim below outruns its test evidence; nothing here certifies production behavior.*

## What the audits cover (machine-checked)

| Audit | Where | Evidence |
|-------|-------|----------|
| Capability model invariants (I1-I6) | `aegis/crates/capability-core` | 20+ contract tests; TLA+ model-check (331k states, 2 tasks, 3 slots) |
| Reachable-authority vs compiled manifests | `aegis/crates/capability-audit` + `security-audit` | `cargo run -p capability-audit` (CI); 10 aggregate contract tests (clean reference world, kernel-equivalent rejection, undeclared-holdings rejection, overhang-warns-not-fails, self-cap exclusion) |
| Adaptive/AI ceiling (monotonic non-expansion) | `aegis-kernel/src/ceiling.rs` | 14 property tests; caught+fixed a real scope-expansion bug |
| Parser/syscall total functions (no panic on garbage) | `aegis-kernel/src/hardening.rs` | 21 boundary tests over ELF/PE loaders, IPv4/Ethernet/ARP/UDP/TCP parsers, both syscall ABIs, compat layers, shell/window/graph/input |
| Per-phase contracts | all crates | 514 total tests, 0 failures (125 workspace + 376 kernel + 13 bootloader) |

## Certification status by claim

| Claim | Certified? | Evidence / reason |
|-------|------------|-------------------|
| Capability model implements the Phase 0 spec | Model-level yes | Contract tests + TLA+ (finite instance, not inductive proof) |
| Kernel prevents self-escalation (AI ceiling) | Model-level yes | ceiling.rs property tests over decision logic |
| Compat layers gate on capability scope | Model-level yes | linux_compat/win_compat tests (63 tests) |
| Boot on real UEFI hardware | **NOT certified** | UNTESTED: needs VMware/QEMU on real firmware |
| GDT/TSS, IDT, per-process page tables on real CPU | **NOT certified** | UNTESTED: lgdt/lidt/cr3 require real hardware |
| PCIe/IOMMU/NVMe/VirtIO on real hardware | **NOT certified** | UNTESTED: requires real devices |
| Real NIC traffic (TCP/UDP) | **NOT certified** | Loopback + frame/protocol logic only |
| Cross-machine capability transport | **NOT certified** | Two-node in-process model; no sockets/consensus |
| Full Linux/Windows application compatibility | **NOT certified** | Design doc: full Windows fidelity explicitly unsolved by translation alone; no hypervisor VM vehicles |

## Threat model coverage (design doc §8)

| Threat | Contained by | Status |
|--------|-------------|--------|
| Malicious/buggy app | Capability scoping (manifest-bounded) | Verified at model level |
| Compromised driver | IOMMU + userspace isolation | Code exists; **UNTESTED on hardware** |
| Manipulated AI agent | Hard capability ceiling | ceiling.rs verified; policy behavior monitored, not proven |
| Compromised update | Content-addressing + signing | Model-level (system-update crate) |
| Human granting too much | Ephemeral/role-shaped/diff-confirmed grants + audit trail | Model-level (grants/anomaly); human-factors not testable here |
| Fully compromised kernel image at boot | Secure boot + attestation | **Not built** — acknowledged limit |

## Explicit non-certifications

1. **No real-hardware certification of any kind.** Every hardware-touching operation
   (page tables, GDT/IDT load, PCIe config I/O, IOMMU tables, NVMe queues, VirtIO MMIO,
   VGA) is UNTESTED and marked as such in the code.
2. **No formal (inductive) proof.** The TLA+ run is finite-instance model-checking; the
   ceiling verification is deterministic property testing. Neither is seL4-class proof.
3. **No security audit of third-party toolchain output.** The Rust compiler, UEFI
   firmware, and hypervisors are trusted per the threat model.
4. **No fuzzing.** hardening.rs is deterministic boundary testing, not coverage-guided
   fuzzing.
5. **No distributed-systems guarantees.** Partition/split-brain behavior is deliberately
   not modeled (design doc CAP warning).

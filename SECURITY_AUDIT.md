# Security Audit & Certification Status — Pointless OS / Aegis

*Status: 2026-08-10, fuzzing/ceiling rows updated 2026-08-16 (Phase M). This document
is the honest certification matrix for Phase 12. No claim below outruns its test
evidence; nothing here certifies production behavior.*

*Partial-reconciliation note: only the fuzzing and ceiling-proof rows were updated in
this pass, with real re-run numbers. Everything else in this file predates Phases
J/K/L (real VMware boots, real fleet networking, the VMX primitive) and has NOT been
independently re-checked against those — several "NOT certified" rows below may be
stale now that some of that work has real live-boot evidence elsewhere in
`HONEST_STATUS.md`. A full pass reconciling every claim in this file against current
`HONEST_STATUS.md` is real remaining work, not done here — don't treat the untouched
rows below as re-verified just because this file was edited.*

## What the audits cover (machine-checked)

| Audit | Where | Evidence |
|-------|-------|----------|
| Capability model invariants (I1-I6) | `aegis/crates/capability-core` | 20+ contract tests; TLA+ model-check (331k states, 2 tasks, 3 slots) |
| Reachable-authority vs compiled manifests | `aegis/crates/capability-audit` + `security-audit` | `cargo run -p capability-audit` (CI); 10 aggregate contract tests (clean reference world, kernel-equivalent rejection, undeclared-holdings rejection, overhang-warns-not-fails, self-cap exclusion) |
| Adaptive/AI ceiling (monotonic non-expansion) | `aegis-kernel/src/ceiling.rs` | 14 property tests; caught+fixed a real scope-expansion bug |
| Parser/syscall total functions (no panic on garbage) | `aegis-kernel/src/hardening.rs` | 21 boundary tests over ELF/PE loaders, IPv4/Ethernet/ARP/UDP/TCP parsers, both syscall ABIs, compat layers, shell/window/graph/input |
| Adaptive/AI ceiling under arbitrary interleaving (all 3 roles) | `aegis/spec/AegisCeiling.tla` | TLC model-check: 5,644,801 states / 147,456 distinct / 0 errors; negative control confirms non-vacuous |
| Boundary-parser fuzzing (decode_entries, parse_elf, parse_pe) | `phase-m-fuzz/` links the real `aegis-kernel` crate | **180,000,000 inputs across 2 independent seeds (random + mutation-based from valid seeds), 0 panics, against the real in-crate functions**; the extracted-copy harness in `phase-m-fuzz/extracted/` reproduces the identical numbers, so there is no extraction drift; extraction validated by running all 23 of the parsers' own original unit tests unmodified |
| Per-phase contracts | all crates | 645 total tests, 0 failures (495 kernel + 128 workspace + 22 bootloader: 13 ELF-contract + 9 fleet-CFG-contract) |

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
4. **Fuzzing covers three boundary parsers, not the full attack surface.**
`decode_entries`, `parse_elf`, `parse_pe` have a real host-side fuzz campaign
    (180M inputs across 2 seeds, 0 crashes, against the real in-crate functions).
    The network parsers named in the master roadmap
   (ARP/Ethernet/IPv4/UDP/TCP/TLS) are NOT yet in this campaign — they depend on
   kernel-crate types that don't extract as cleanly as the three above;
   `hardening.rs`'s 21 deterministic boundary tests are the only coverage those
   currently have. Extending the fuzz harness to them is real remaining work,
   not done here. The campaign is random+mutation, not coverage-guided
   (`cargo-fuzz` needs nightly + the real toolchain).
5. **No distributed-systems guarantees.** Partition/split-brain behavior is deliberately
   not modeled (design doc CAP warning).

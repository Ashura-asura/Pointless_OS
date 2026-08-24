# Security Audit & Certification Status — Pointless OS / Aegis

*Status: 2026-08-10, fuzzing/ceiling rows updated 2026-08-16 (Phase M), totals and
kernel-hardening rows updated 2026-08-19 (audit follow-up: ObjectID + pointer gate).
This document is the honest certification matrix for Phase 12. No claim below outruns
its test evidence; nothing here certifies production behavior.*

*Partial-reconciliation note: the fuzzing, kernel-boundary-hardening, and totals rows were
updated in this pass with real re-run numbers (kernel 787/790, workspace 136, bootloader
22). Several "NOT certified" rows below reflect real live-boot evidence gained in Phases
J/K/L/G/T/P/Q/R/S/AA and re-checked in `HONEST_STATUS.md` (real VMware boots, real fleet
networking, VT-d-style DMA gate, GOP-first display, live apps); the untouched rows below
that lack such evidence remain genuinely not certified. Don't treat any row as re-verified
just because this file was edited — the authoritative live status is `HONEST_STATUS.md`.*

## What the audits cover (machine-checked)

| Audit | Where | Evidence |
|-------|-------|----------|
| Capability model invariants (I1-I6) | `aegis/crates/capability-core` | 20+ contract tests; TLA+ model-check (331k states, 2 tasks, 3 slots) |
| Reachable-authority vs compiled manifests | `aegis/crates/capability-audit` + `security-audit` | `cargo run -p capability-audit` (CI); 10 aggregate contract tests (clean reference world, kernel-equivalent rejection, undeclared-holdings rejection, overhang-warns-not-fails, self-cap exclusion) |
| Adaptive/AI ceiling (monotonic non-expansion) | `aegis-kernel/src/ceiling.rs` | 14 property tests; caught+fixed a real scope-expansion bug |
| Parser/syscall total functions (no panic on garbage) | `aegis-kernel/src/hardening.rs` + `aegis-kernel/src/hardening_fuzz.rs` | 21 boundary tests over ELF/PE loaders, IPv4/Ethernet/ARP/UDP/TCP parsers, both syscall ABIs, compat layers, shell/window/graph/input; plus **14 hardened fuzz tests (~1.2M seeded parse calls over ethernet/arp/ipv4/udp/tcp/tls record decryption + a syscall-boundary fuzz driving every syscall number with hostile task/slot/endpoint indices + a direct walk-fuzz of the user-pointer gate — 0 panics, 0 OOB, current task never moved)** |
| Adaptive/AI ceiling under arbitrary interleaving (all 3 roles) | `aegis/spec/AegisCeiling.tla` | TLC model-check: 5,644,801 states / 147,456 distinct / 0 errors; negative control confirms non-vacuous |
| Boundary-parser fuzzing (decode_entries, parse_elf, parse_pe) | `phase-m-fuzz/` links the real `aegis-kernel` crate | **180,000,000 inputs across 2 independent seeds (random + mutation-based from valid seeds), 0 panics, against the real in-crate functions**; the extracted-copy harness in `phase-m-fuzz/extracted/` reproduces the identical numbers, so there is no extraction drift; extraction validated by running all 23 of the parsers' own original unit tests unmodified |
| Per-phase contracts | all crates | 1015 total tests, 0 failures (856 kernel + 137 workspace + 22 bootloader: 13 ELF-contract + 9 fleet-CFG-contract); kernel also green at 859 with `--features vmx-demo` |
| Kernel-boundary hardening (external audit, 2026-08-19) | `aegis-kernel/src/{ipc,netif,tasks,supervisor,mem}.rs` | Bounds+identity checks added on `ipc_cap_grant`/`ipc_reply`/netif slot indices/raw task accessors/cap-resolved ids; 5 adversarial tests (`cap_grant_refuses_out_of_range_recipient`, `reply_refuses_forged_and_out_of_range_callers`, `net_syscalls_refuse_out_of_range_slots`, `raw_accessors_refuse_out_of_range_indices`, `syscall_boundary_rejects_hostile_indices`); fail-closed, never panic |
| Generation-safe object identity (audit-follow-up, 2026-08-19) | `aegis-kernel/src/{cap,tasks,ipc,channel,netif,netstack,store,role,main,fleet,trace}.rs` | Every payloaded Cap carries `Oid { index, generation }`; every resolve is a single bounds+generation gate; slot reuse on a full table bumps the generation so a stale handle fails closed; **3 dedicated stale-cap tests** (`stale_task_cap_denied_after_slot_reuse`, `stale_channel_cap_denied_after_destroy_and_recreate`, `stale_socket_cap_denied_after_close_and_reopen`) |
| Centralized user-pointer validation (audit-follow-up, 2026-08-19) | `aegis-kernel/src/user_ptr.rs` + write/ipc/mem/channel/netif copy paths | `validate_range`/`copy_from_user`/`copy_to_user` do a strict 4-level page walk (4 KiB/2 MiB/1 GiB) over the calling task's PML4; kernel context is a trusted bypass; deferred IPC copies validate against the owning task's PML4; **3 gate tests + a direct gate-walk fuzz**; pointer args now fuzzed with the gate (not a scratch buffer) as the defense |
| Systematic syscall-boundary audit (Phase AC) | `Docs/SYSCALL_BOUNDARY_AUDIT.md` + `aegis-kernel/src/hardening_syscalls.rs` | Committed syscall→argument→check-or-justification table for every syscall 0–23 + unknown; **26 adversarial tests, one per syscall**, following the `cap_grant_refuses_out_of_range_recipient` pattern (hostile/boundary values for every ring-3 arg; assert refusal; assert the refusal is audited); closed 4 audit gaps (Write gate + ipc_call/ipc_serve/ipc_reply caps_endpoint failures now attributed) |
| Miri UB detection (Phase AD) | `.github/workflows/test.yml` `miri` job | `cargo miri test` clean across the whole model workspace (**136/136**, zero UB) + kernel host-testable modules (boot_info, channel, e1000, ept, ipc, policy_engine, hardening_fuzz, hardening_syscalls — all green under Miri), wired into CI as a standing gate; **found + fixed a real latent bug the native suite missed**: `policy_engine::audit_log()` sliced `[AuditSlot; 128]` as contiguous `[AuditEntry; N]`, so entries after the first read interleaved `used`-flag + padding bytes (test only asserted `.len()`); storage is now a contiguous `[AuditEntry; 128]` with a content-checking regression test. Also fixed test-harness UB the sweep surfaced (element-derived pointer provenance in boot_info/channel/ipc, unaligned descriptor-ring buffers in e1000, ownership-tagged fake phys in ept). Fuzz sweeps are `#[cfg_attr(miri, ignore)]` (100k–200k interpreted iterations; they still run natively) |
| ASan coverage (Phase AD) | `.github/workflows/test.yml` `asan` job | `RUSTFLAGS=-Zsanitizer=address cargo test` clean on the whole model workspace (**136/136**, no AddressSanitizer reports) and the whole kernel suite (**787/787**, release profile, no reports), wired into CI as a standing gate. Host caveat: on the Windows MSVC dev host `undefined` (UBSan) is not a supported sanitizer target and ASan needs the VS `clang_rt.asan_dynamic-x86_64.dll` on PATH; CI (Linux) needs neither workaround |
| Continuous fuzzing (Phase AE) | `aegis-kernel/src/fuzz_corpus.rs`, `hardening_fuzz.rs`, `vmx.rs`, `vdev.rs`, `virtio.rs`; `.github/workflows/test.yml` `fuzz-push` + `fuzz-nightly` jobs | Every hypervisor device-emulation / guest-untrusted path now has fixed-seed total-no-panic fuzz coverage: VMX guest-control decode + EPT-violation qualification (`vmx.rs`), the whole guest port surface `DeviceSet` (PIC/UART/PIT/RTC/PCI/virtio/UHCI/SB16) on hostile port/value sequences (`vdev.rs`), virtio descriptor chains + `MemStore` sectors (`virtio.rs`), TLS record framing + ServerHello (`hardening_fuzz.rs`), plus the network parsers (ethernet/arp/ipv4/udp/tcp/tls) in a `corpus_driven_fuzz_is_total_and_grows` harness over a committed, FNV-1a content-hashed corpus in `aegis-kernel/fuzz-corpus/` (11 targets). Wired into CI: a bounded read-only pass on every push (`fuzz-push`, release budget) and a long corpus-growth pass nightly (`fuzz-nightly`, `AEGIS_FUZZ_GROW=1`, commits corpus growth). **0 panics** across the initial committed corpus and all sweeps. See honest limits in non-certifications §4–§6. |
| 10x chaos / soak (Phase AF) | `aegis/crates/soak` (`soak` binary + `soak_smoke_bounded` test); `.github/workflows/test.yml` `soak` job | A `soak` harness drives the combined model subsystems — capability-core (create/task/endpoint/mem/copy/grant/grant_mint/revoke/destroy/ep/mem/task-kill-spawn/clock), orchestration `act` (policy engine + grants + supervision over ReadServiceState/RestartService/KillForeign/ReadStateBurst), supervision-tree pump (restart-budget), fleet issue/hold_local/send_to/verify/narrow/serialize roundtrips, resources `give`/`recycle` ledger, capability-audit — under a randomized, seeded workload, asserting a 10x-density invariant battery **after every op** (audit-log monotonicity; cspace slot bounds; delegated/granted/minted rights never expand beyond the source; revoke removes the whole subtree and destroyed caps stay unresolvable; fleet verify is fail-closed under a partitioned/unreachable issuer; resource ledger stays consistent; supervisor never exceeds its restart budget). Bounded 10-minute release soak: **63,673,513 steps / 63,673,513 invariant checks, 0 violations**. A short `soak_smoke_bounded` (400 steps) gates every push via `cargo test --workspace`, and a nightly `soak` job runs a 10-minute pass. See honest limits in non-certifications §7. |

## Certification status by claim

| Claim | Certified? | Evidence / reason |
|-------|------------|-------------------|
| Capability model implements the Phase 0 spec | Model-level yes | Contract tests + TLA+ (finite instance, not inductive proof) |
| Kernel prevents self-escalation (AI ceiling) | Model-level yes | ceiling.rs property tests over decision logic |
| Compat layers gate on capability scope | Model-level yes | linux_compat/win_compat tests (63 tests) |
| Boot on real UEFI hardware | **NOT certified** | UNTESTED: needs VMware/QEMU on real firmware |
| GDT/TSS, IDT, per-process page tables on real CPU | **NOT certified** | UNTESTED: lgdt/lidt/cr3 require real hardware |
| PCIe/IOMMU/NVMe/VirtIO on real hardware | **NOT certified** | UNTESTED: requires real devices |
| Real NIC traffic (TCP/UDP) | QEMU-verified, not hardware-certified | Live e1000e handshake + HTTP + close captured on host (Phase 5); no physical NIC |
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
4. **Fuzzing now covers the network parsers and hypervisor device-emulation paths, but is deterministic corpus + fixed-seed, NOT coverage-guided.** The host-side `decode_entries`/`parse_elf`/`parse_pe` campaign (180M inputs, 2 seeds, 0 crashes) is unchanged. Phase AE added fixed-seed total-no-panic sweeps over ethernet/arp/ipv4/udp/tcp/tls framing, TLS record + ServerHello, the full guest `DeviceSet` port surface, VMX guest-control + EPT qualification, and virtio descriptor chains — plus a committed, mutation/truncation-based corpus in `aegis-kernel/fuzz-corpus/` (11 targets, FNV-1a content-hashed seeds). All results are **0 panics**, but this is random+mutation and structured adversarial input, **not** `cargo-fuzz`/libFuzzer coverage-guided fuzzing — it proves total-no-panic and crash-free on the sampled inputs, not exhaustion of the input space or branch coverage of every parser state.
 5. **No distributed-systems guarantees.** Partition/split-brain behavior is deliberately
    not modeled (design doc CAP warning).
 6. **Fuzz coverage is gated on the committed corpus being exercised; it does not replace the syscall-boundary audit or Miri/ASan.** The corpus harness replays every committed `.bin` seed through each parser and asserts total no-panic; it does not assert semantic correctness of parse output beyond "did not panic / reject hostile lengths". Semantic-acceptance checks live in the deterministic boundary tests and `hardening_syscalls.rs`, not in the fuzz sweep.
 7. **The Phase AF soak is a bounded-duration, randomized invariant walk, NOT a fleet soak or an inductive proof.** It drives the combined model subsystems under a seeded PRNG for a fixed wall-clock budget (10 min in CI; 10 min locally for evidence) and re-checks an invariant battery after every op. It exercises the *model* workspace and the orchestrator/supervision/grants/fleet/resources stacks on the host (not the bare-metal kernel), and the random op mix is broad-but-shallow — it does not enumerate every interleaving of every subsystem, nor does it model real-time deadlines, power loss, or physical device faults. It proves the invariants hold over the sampled chaotic workload, not exhaustion of the state space.

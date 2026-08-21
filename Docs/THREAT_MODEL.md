# Threat Model

This is the coherent security-posture document for Aegis / Pointless OS. It
names the adversary classes the test suite already covers, states honestly
what is proven under emulation/virtualization versus real hardware, and folds
in the allocator hardening (Phase AG) and the hardware-evidence results
(track §2). Companion docs: [`SECURITY.md`](../SECURITY.md) (reporting),
[`HARDWARE_EVIDENCE.md`](HARDWARE_EVIDENCE.md) (real-firmware results),
[`Docs/SECURITY_AUDIT.md`](SECURITY_AUDIT.md) (external audit + fixes).

## Adversary classes covered

The existing suite effectively models three malicious principals:

1. **Malicious ring-3 task.** A userspace task that calls syscalls with
   bogus pointers, out-of-range indices, capability handles it was not
   granted, or tries to escalate. Covered by: the syscall boundary audit
   (24/24 vectors checked), `user_ptr` bounds checks, capability revocation,
   and per-task page-table isolation (a faulting task is killed; the kernel
   survives). Verify: `cd aegis-kernel && cargo test --release user_ptr`
   plus the syscall contract tests; the audit matrix in `Docs/SECURITY_AUDIT.md`.

2. **Malicious network peer.** A remote endpoint that sends malformed
   Ethernet/IPv4/TCP/UDP/TLS frames. Covered by the host-testable protocol
   parsers and the continuous fuzzing corpus (Phase AE). Verify:
   `cargo test --release` in `aegis-kernel` (net stack) and the nightly
   fuzzing corpus growth visible in git history.

3. **Malicious hypervisor guest.** A guest OS that probes MMIO/PIO/DMA
   outside its domain. Covered by the software VT-d IOMMU gate
   (`iommu::translate`) which denies an out-of-domain DMA on a live boot
   while legit devices keep operating, and by the EPT/NPT boundary work.
   Verify: the `serial-deny.log` / `serial-isolation.log` boot captures
   under `uefi-boot/`.

## Allocator hardening (Phase AG) — what is guarded vs accepted

The frame allocator and the store arena were audited and hardened:

- **Double-free / ownership confusion — GUARDED.** A second `alloced`
  ownership bitmap means `free()` rejects any frame that is not both
  "unavailable" and "owned by the allocator" — a free of a reserved or
  kernelspace frame (which the old `free()` accepted because it only checked
  the availability bitmap) is now rejected. Verified by
  `frame::double_free_is_rejected_and_leaves_count_unchanged`.
- **Size-sanity — GUARDED.** `alloc_contiguous(n)` rejects `n == 0`,
  `n > total_frames()`, or `n > free_count()` before committing.
- **Allocator invariants under adversarial load — GUARDED.** A dedicated
  `fuzz_run` oracle exercises alloc/free/exhaustion/double-free sequences with
  per-step invariant asserts; it is wired as a corpus fuzz target
  (`allocator`) and run under Miri. Verified: `cargo +nightly miri test
  frame::` clean (17 tests) and corpus fuzz (2,000 iters) with zero panics.
- **Store arena (bump allocator) — accepted risk, decided.** `arena_alloc`
  has `len == 0 → None`, an overflow-checked `checked_add`, and a bounds
  check; there is **no free path** (no double-free possible) and UAF is
  bounded by the capability model (a task holds the arena capability or it
  does not). No separate hardening was needed; this is a recorded decision,
  not an oversight.

## What is proven under emulation vs real hardware

| Property | Under QEMU/OVMF (emulation) | On real hardware (this laptop) |
|---|---|---|
| UEFI → bare-metal boot, 4-level paging, NX | Proven (serial/framebuffer captures) | Canary image builds; **boot not yet run** (see `HARDWARE_EVIDENCE.md` §4) |
| ACPI MADT/RSDP parsing | Proven (synthetic fixtures) | **Proven**: real MADT → 8 LAPICs/4C-8T through `parse_madt` |
| ACPI table checksum/length validation | Proven (synthetic fixtures) | **Proven**: 19 real tables through `parse_sdt_header` |
| PCI/SMBIOS inventory | n/a (synthetic) | **Proven**: 44 real PCI devices + real SMBIOS parsed |
| VT-x / nested VMX | TCG emulation only | **Firmware supports; Windows VBS/HVCI blocks** — reversible fix identified |
| Driver behavior (NVMe/e1000/IOMMU) | Proven live under QEMU | Not yet run on metal |

The honest line: **parser-correctness and the allocation/mmio/DMA boundaries
are now proven on this laptop's actual firmware**, not just adversarial
synthetic bytes. **Full bare-metal boot timing and driver liveness on metal
remain emulator-verified only** until the USB canary boot is executed.

## Closed / reduced / inherent (honest inventory)

- **Closed:** syscall boundary audit, double-free in the allocator, size
  over-allocation, Miri + ASan in CI, nightly fuzzing with real corpus
  growth, 63.6M-step soak with 0 violations.
- **Reduced:** store-arena risk reduced to a capability-bounded UAF with no
  free path (decided, not eliminated).
- **Inherent:** `no_std` cannot provide a general heap UAF detector; the
  project relies on capability scoping + bounds checks + the soak/fuzz
  discipline rather than a GC/spatial-safety runtime. Real-hardware boot
  evidence is inherently gated on a manual, host-state-changing step that CI
  cannot perform.

Every gap above is a decision recorded here, not an oversight.

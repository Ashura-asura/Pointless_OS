# Bridge phase — gap inventory (flexible starting point)

Companion to [`BRIDGE_PHASE.md`](BRIDGE_PHASE.md). The bridge phase's first
concrete step is to **enumerate gaps before coding a target**, so the next
direction stays open. This document records the current guest substrate and
the candidate next targets with their trade-offs. It intentionally does NOT
pick one — that choice is deferred to a follow-up once a target workload is
named.

## Current guest substrate (proven)
- **Guest = real Linux `bzImage`** booted under Aegis's VMX (`vm.rs`),
  unmodified (no Aegis-specific guest patches required).
- **Userspace = BusyBox initramfs** (`guest/initramfs`, `guest/build-guest.sh`)
  — the Phase V proof of concept: a guest userspace runs and is driven by the
  capability-scoped agent.
- **Hypervisor emulation surface that already works** (per `vm.rs`,
  `e1000.rs`, `nvme.rs`, `gpu.rs`, `pci.rs`, `iommu.rs`): PCI enumeration,
  NVMe block (identify + LBA reads), polled e1000e NIC, VGA/GPU framebuffer,
  software VT-d IOMMU gate, LAPIC timer, 4-level EPT.

## Candidate next targets (flexibility preserved)
Ordered by risk/leverage; **any one can be chosen without foreclosing the
others.**

1. **Deepen the Linux guest (more BusyBox apps / a fuller userspace).**
   - *Leverage:* the substrate already boots Linux + BusyBox; lowest risk.
   - *Gap to close:* which real apps/workloads fail today, and the missing
     device emulation / MSR / syscall paths they need (e.g., additional
     PCI devices, power management, more timer modes, RTC, virtio). Each gap
     closed behind a contract test — the project's standard.
   - *Flexibility:* leaves the Windows-guest option fully open.

2. **Boot a fuller Linux distribution image (not just BusyBox).**
   - *Leverage:* same kernel/emulation path; exercises more of a real distro's
     userspace (init, shells, package managers).
   - *Gap to close:* whatever the larger userspace touches that BusyBox didn't
     (more filesystems, more devices, more syscalls).
   - *Flexibility:* still Linux; no new architectural commitment.

3. **Attempt a Windows guest (stretch milestone).**
   - *Leverage:* highest-value compatibility proof; benefits most from the
     allocator/SMP/ACPI groundwork now in place.
   - *Gap to close:* substantially more — ACPI/APIC completeness (now validated
     on real firmware), more instruction/device emulation, possibly nested
     VMX (currently blocked on this laptop by Windows VBS/HVCI — see
     `HARDWARE_EVIDENCE.md`).
   - *Flexibility:* the hardest; doing 1–2 first de-risks it.

## Recommended immediate action (reversible, non-committal)
Pick a target (above). For target 1, the first reversible step is to **boot
the current Linux/BusyBox guest, run a battery of real apps, and log which
fail** — producing a concrete missing-emulation list. That list, not a
guess, drives the first contract-test-backed fix. No code is written until a
specific failing workload is named.

## Honest status
This is a planning artifact, not a code change. Nothing here was implemented
in this session; it exists so the next session can start from a named target
rather than re-deriving the landscape.

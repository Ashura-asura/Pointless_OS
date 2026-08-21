# Hardware-evidence track — results (Dell Inspiron 7400 / i7-1165G7)

This document records the real-hardware evidence gathered from the single
dev laptop, per the post-Phase-AF master prompt (track §2). It is the honest
account required by that track's Definition of Done. **All evidence files
live under `aegis-kernel/hardware-fixtures/` and `uefi-boot/`; they are
present locally but intentionally NOT committed to git** (per the
"do-not-commit" instruction for this working session). The verify commands
below regenerate and re-check everything from scratch.

## Host under test
- Manufacturer/Model: **Dell Inc. / Inspiron 7400**
- CPU: **11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz** — 4 cores / 8 logical
- BIOS: Dell Inc. DELL - 2 (2024-11-23)
- OS: Windows 11 (host), used only to extract raw firmware descriptors.

## 1. Raw firmware descriptors extracted
`scripts/extract-hardware-fixtures.ps1` (PowerShell, no third-party tools)
dumps real bytes via `GetSystemFirmwareTable` (ACPI), WMI
`MSSmBios_RawSMBiosTables` (SMBIOS), registry `Enum\PCI` + `Win32_PnPEntity`
(PCI), and `Win32_DeviceGuard` + registry (VT-x gate).

Committed-as-files fixtures:
- `hardware-fixtures/acpi-*.bin` — **19 real ACPI tables**: `DBGP, MCFG, FACP,
  APIC, BOOT, DMAR, HPET, FPDT, SSDT(x11), NHLT, LPIT, WSMT, DBG2, SLIC, TPM2,
  MSDM, UEFI(x2), PTDT, BGRT`. (This firmware is XSDT-only — RSDT is not
  published — so tables are dumped individually by signature, not via RSDT
  walk.)
- `hardware-fixtures/smbios.bin` — raw SMBIOS table section, **6515 bytes**,
  carries the genuine `Dell` / `Inspiron` vendor/model strings.
- `hardware-fixtures/pci-devices.tsv` — **44 real PCI devices** this host
  exposes (`<hwid>\t<source>\t<name>` rows; VEN/DEV inside the hwid).
- `hardware-fixtures/host-summary.txt`, `vtx-status.txt`.

## 2. Real fixtures through the kernel parsers
`aegis-kernel/src/hardware_evidence.rs` (two `#[ignore]`d tests, because the
fixtures are host-specific and absent in CI) feeds the **actual firmware
bytes** through the same `acpi`/`pci`/`smbios` parsers already fuzzed with
synthetic data. Run on the dev host:

```
cd aegis-kernel
cargo test --release -- --ignored hardware_evidence
```

Results (this host):
- **19/19 real ACPI tables parse cleanly** through `acpi::parse_sdt_header`
  (valid length + passing ACPI checksum over the genuine firmware bytes).
- **Real MADT → `acpi::parse_madt`** yields the genuine CPU topology:
  `lapic_address = 0xFEE00000`, **8 LAPIC entries, all enabled**
  (`apic_id` 0,2,4,6,1,3,5,7) — i.e. **4 cores / 8 threads (Hyper-Threading)**,
  plus an IOAPIC. This is the real hardware the SMP groundwork will boot on,
  not a QEMU fixture.
- **SMBIOS** blob is genuine (vendor/model strings present).
- **PCI inventory** of 44 devices parses; the host NVIDIA GeForce MX350
  (`VEN_10DE`) is correctly enumerated.

This is a genuinely different, valuable kind of evidence from synthetic
fuzzing: proof the parsers handle *this specific laptop's* firmware, not just
adversarial byte patterns.

## 3. VT-x: firmware vs Windows
`vtx-status.txt` verdict:

> **VT-x VERDICT: firmware supports it, but WINDOWS blocks it** (Memory
> Integrity / VBS reserves VMX). Disabling Core Isolation (Windows Security →
> Device Security → Core Isolation) should unblock nested VMX.

Concretely: `EnableVirtualizationBasedSecurity = 1` and Memory Integrity
(HVCI) is enabled, so the hypervisor reserves VMX for VBS. The firmware itself
does **not** disable virtualization. Reversible, one-time host change to
upgrade future hypervisor tests from TCG emulation to real nested-VMX.

## 4. USB canary — honest status
`uefi-boot/build-canary.ps1` builds `aegis-canary.img` (16 MB) from source:
the canary kernel (`--features kernel,canary`, where NVMe/FAT/store are
compiled **out** so the canary makes zero disk writes) embedded in the UEFI
loader, then wrapped into a bootable image with `build_image.py` +
`add_startup.py`.

- **Building the canary image: now WORKS.** It was found broken (a `-D
  warnings` dead-code error on `aa_seed` under the `canary` feature) and fixed
  in `src/main.rs` (`#[cfg_attr(feature = "canary", allow(dead_code))]`).
  Re-running the tooling produces `aegis-canary.img` (16 MB) and
  `aegis-canary.efi` (≈521 KB) with the canary kernel embedded (the
  built-in "does it embed the canary kernel?" sanity check passes).
  Verify: `cd uefi-boot && powershell -File build-canary.ps1`
- **The actual USB canary boot: NOT executed in this session.** Writing the
  image to a USB stick in DD mode and rebooting the physical dev laptop is a
  manual, host-state-changing step that cannot be performed from this agent
  session. This is the one piece of evidence the session cannot produce. When
  run, the canary's serial log (proving UEFI → bare-metal boot with storage
  compiled out) should be committed alongside the other phases' evidence. The
  tooling being green means the boot is a matter of media + reboot, not a
  code gap.

## Definition-of-Done checklist (track §2)
- [x] Real ACPI/PCI/SMBIOS fixtures extracted (files present).
- [x] Real fixtures pass through the real parsers with sane values (test passes).
- [x] Clear yes/no on VT-x: **firmware yes, Windows (VBS/HVCI) blocks** — reversible fix identified.
- [~] One USB canary boot: **image builds cleanly; physical boot not run this
  session** (manual media + reboot required). Honest account above.

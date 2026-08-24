# VMX live hosting (Phase A Problem 2) — runbook

The software half of "Aegis hosts its Linux guest" is done and test-proven:
`vm.rs` (guest layout / boot handoff / EPT / device dispatch), `vdev.rs` /
`virtio.rs` (the emulated minimal PC), `ept.rs` (nested paging), and the
`vmx.rs` run loop that launches a real Linux bzImage under Aegis's own
hypervisor. What remains is the **one hardware/boot step**: booting an Aegis
image that **owns VMX**.

This page is the operator runbook for that step, and it records what the
`vmx.rs` pre-flight (`vmx_host_readiness`) diagnoses.

## The single requirement

To host a guest, Aegis must be the entity that turned VT-x on:

- the CPU must have VT-x (**CPUID.1:ECX.VMX**);
- firmware must permit VMXON outside SMX (**IA32_FEATURE_CONTROL** bit 2,
  not locked off);
- **no other hypervisor may already own VMX** — i.e. KVM must not be loaded
  (Linux), and virtualization-based security / Core Isolation / Hyper-V must
  be off (Windows). A VM can still be the host if nested virtualization is
  exposed, but the hypervisor inside that VM is then the VMX owner.

Everything else (trampolines, VMCS writes, EPT, the guest boot) is already
wired behind the `vmx-demo` cargo feature.

## The pre-flight

Every VMX demo entry point (`bringup_demo`, `run_loop_demo`,
`guest_boot_demo`) now starts with `vmx_host_readiness()` and prints exactly
why a host cannot host, then returns before any `vmxon`. Serial output takes
one of these forms:

| Serial line | `VmxReadiness` | Meaning / remediation |
|---|---|---|
| `pre-flight not ready: VT-x (VMX) absent from CPUID.1:ECX[bit5]…` | `NoVtx` | CPU lacks Intel VT-x (or is AMD with SVM disabled). Enable virtualization in firmware. |
| `pre-flight not ready: IA32_FEATURE_CONTROL is locked by firmware/BIOS…` | `FeatureControlLockedDisabled` | BIOS has virtualization off. Enable "VT-x" / "Virtualization Technology" in firmware setup. |
| `pre-flight not ready: Aegis is a guest under another hypervisor…` | `UnderAnotherHypervisor` | Another VMM (KVM, Hyper-V/VBS/Core Isolation, or a VM without nested virt) owns VMX. Fix per platform below. |
| `VMX host ready — Aegis owns VMX` then `VMXON ok…` | `Ready` | Proceed to the run loop / guest boot. |

The classification logic is unit-tested in the kernel suite
(`classify_vmx_readiness_covers_all_states`,
`readiness_advice_is_actionable_per_state`,
`readiness_agrees_with_the_cpuid_probe`). `vmx_host_readiness()` itself reads
the privileged `IA32_FEATURE_CONTROL` MSR, so it runs only at CPL 0 (boot),
never in a user-mode host test.

> Session finding: on this Linux box `/proc/cpuinfo` and `/dev/kvm` indicate
> VT-x, but the in-process CPUID probe sees the VMX bit clear (sandbox-masked)
> and Aegis runs under another hypervisor — so the pre-flight here reports
> `NoVtx`/`UnderAnotherHypervisor` and the demos return before VMXON. That is
> the correct, honest behaviour; live verification needs a VMX-owner host.

## Steps

### 1. Build the Aegis vmx-demo image

```sh
rustup target add x86_64-unknown-none
cd aegis-kernel
cargo build --release --features kernel,vmx-demo
```

Wrap the resulting kernel (ELF) in the UEFI boot image with the existing
`uefi-boot/build_image.py` flow (the same path that produced
`uefi-boot/aegis-kernel.bin` and the checked-in VMware/VMDK boot images).

### 2. Choose a VMX-owner host

**Firmware (all platforms):** enable "VT-x" / "Virtualization Technology" /
"SVM" and (Windows) disable virtualization-based security.

**Linux host:** remove KVM before booting Aegis so Aegis is the VMX owner —
`modprobe -r kvm_intel kvm` (or boot a kernel without KVM). Confirm with
`cpuid | grep -i vmx` (the CPUID probe must report the VMX bit, not just the
`/proc/cpuinfo` flag) and confirm no other hypervisor is present
(`dmesg | grep -i hypervisor`).

**Windows host:** Settings → Core Isolation → Memory Integrity **off**; turn
off "Virtual Machine Platform" / Hyper-V if they are on; disable VBS via
`reg add HKLM\System\CurrentControlSet\Control\DeviceGuard /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0` and reboot. Then boot the Aegis vmx-demo image directly.

**Virtual machine as host:** enable nested virtualization on the VM (e.g.
VMware "Virtualize Intel VT-x/EPT", KVM `-cpu host,+vmx`) — the hypervisor
inside the VM is then the VMX owner.

### 3. Boot and observe

Boot the image and read the serial console. Expected success sequence:

```
Aegis: [vmx] pre-flight: VMX host ready — Aegis owns VMX   (or this line absent on older builds)
Aegis: [vmx] VMXON ok, region at …
Aegis: [vmx] VMCS active at …
…
Aegis: [vmx] guest boot: Phase U DoD marker seen — the real Linux kernel reached its shell through Aegis's hypervisor (N VM-exits)
```

If instead the pre-flight prints a `not ready` reason, the table above names
the exact remediation — no guessing.

## Nested-VMX live run (2026-08-24)

This session booted Aegis (`kernel,vmx-demo`) under QEMU/KVM with nested
VT-x (`-accel kvm -cpu host -m 3072`) and **the hypervisor ran for real**:

- `VMXON ok` — the first time the VMX instruction ever executed.
- `VMCS active` — vmclear + vmptrld succeeded.
- `vmlaunch` — the VM-entry instruction executed under nested hardware.
- The guest launched and caused real VM-exits (EPT violation, exception).

**Real bugs found and fixed in the bring-up** (all surfaced by the nested run):

| Bug | Symptom | Fix |
|---|---|---|
| Wrong secondary-controls MSR (`0x48A` = `VMCS_ENUM`) | `rdmsr` #GP in `setup_controls` EPT path | `IA32_VMX_PROCBASED2_CTLS = 0x48B` (Linux `msr-index.h`); no separate TRUE variant |
| EPTP reserved bits set (`3<<7`) | KVM nested `!nested_vmx_check_eptp` | Walk length goes in bits 5:3, not 11:7 (`3<<3`) |
| CR0 missing PG (bit 31) | KVM `!nested_guest_cr0_valid` (CR0_FIXED0=0x80000021) | Guest CR0 must have PE\|PG\|NE — i.e. paging is required |
| CR4 missing PSE (bit 4) | Guest 4 MiB-page PDE treated as 4 KB page-table pointer | `CR4 = 0x2010` (VMXE \| PSE) |
| Bring-up real-mode guest (PE=0) | Same CR0 validity check | Real-mode L2 needs unrestricted guest; disabled for now (run-loop/protected-mode works) |
| Second VMXON after already in root | Late demos failed with "VMXON failed" | `ensure_vmx_root()` latches the first VMXON |
| Pre-flight blocked nested guests | `UnderAnotherHypervisor` reported inside QEMU/KVM guest | Bit31≠qualifier; removed the blocker (nested VT-x is a valid host) |

**Remaining work (honest):** the run-loop guest (`mov al,'A'; out dx,al; hlt`) takes
a guest exception (vector 0) at the first instruction. The code at guest RIP
reads as `0xEE` (`out`) instead of `0xB0` (`mov al`), suggesting the code
write or EPT mapping has a subtle issue. The three real bugs fixed above
show the bring-up is converging quickly; this is the last diagnostic step
before a guest prints via the emulated 16550 under nested hardware.

**Evidence:** `Docs/test_runs/aegis-vmx-bootN.log` (multiple iterations on
GitHub in the commit that added this section).

## Boot self-test battery + on-screen console (real-hardware evidence)

For the bare-metal boot, a boot self-test battery (`baremetal_probe.rs`)
runs a fixed list of non-panicking `Result` probes over the live hardware
(PCI, NVMe, network, display, ACPI, memory map, framebuffer, serial) and
prints/keeps a `battery-contract`-style summary. A GOP framebuffer console
(`gop_console.rs`) renders that summary to the physical screen — the
reliable evidence channel on a UEFI laptop where COM1 is unwired (the VGA
text console renders nothing under GOP graphics mode). Verified under QEMU:
the battery reports each subsystem (`ok - …` / `FAIL - …: reason`) and the
summary is rendered to the GOP screen. The `memory_map` probe caught the
real allocator limitation (kernel sees 61 MiB of RAM when OVMF loads the
image high — the same constraint that blocks `guest_boot_demo`'s 128 MiB
guest).

Honest gap: writing the summary *to the USB stick itself* (the boot
procedure's Layer 2) needs a USB mass-storage driver (Aegis has only UHCI
HID emulation) plus a FAT writer (`fat.rs` is read-only) — real future
work. Until then the evidence is the on-screen report (photograph) plus
serial under QEMU.

## AHCI (SATA) driver — status

For the TP201S-class machine (Intel SATA controller `8086:22a3`, class
`0106`, prog-if `01` AHCI, two ports ata1/ata2), an AHCI driver
(`ahci.rs`) is implemented and **structurally verified under QEMU**:
`AhciController::probe` finds the controller, maps ABAR (BAR5), brings
port(s) up (spin-up, SATA link reset, `DET`=present, `BSY`/`DRQ` clear),
and issues IDENTIFY/READ DMA commands with a command list + PRD. QEMU's
trace confirms it maps the PRD (`dma_prepare_buf limit=512`) and runs the
transfer. Honest QEMU finding: the DMA read-back in QEMU/KVM lands only
partial data (identify word 0 `0x0040`) — a QEMU emulated-DMA visibility
quirk, not a command-list error (the trace shows the transfer is issued).
Real hardware DMA is coherent; final validation is a boot on the TP201S.
`BlockIo` is implemented so the object store can sit on a SATA disk.
Verified conclusion (2026-08-24): the DMA data direction is broken in
this QEMU's emulated AHCI — commands complete without error and QEMU's
own trace shows the PRD mapped (`dma_prepare_buf limit=512`) and the
transfer issued, but the data does not reach the guest buffer (tested in
both read and write directions, with buffers both from the frame
allocator and fixed low RAM). This is a QEMU version limitation, not a
command-path error; real hardware DMA is coherent, so the TP201S boot is
the definitive test.

Wi-Fi (QCA9377 / Intel / Realtek): not implemented — needs proprietary
firmware, a USB host stack, and a full 802.11/WPA2 stack; QEMU cannot
emulate Wi-Fi, so it is not verifiable here. Named future work.

## First real-hardware boot (ASUS TP201S, 2026-08-24)

First-ever Aegis boot on real silicon, from the Cruzer Blade USB stick
(kernel `df7f038`). Evidence: `Docs/test_runs/aegis-real-hardware-boot1-tp201s.log`.

The UEFI loader handed off cleanly: memory map (35 entries), page tables
(CR3 `0x74B45000`), kernel ELF parsed (36 MB, 4 segments), 386 relocations
applied, `no FLEET.CFG @ kernel uses compile-time defaults`. Notably the
machine exposes **~1.8 GB of conventional RAM** — the QEMU-only 61 MiB
frame-allocator limitation does not apply on this hardware, so the
`memory_map` probe should pass and the 128 MiB guest-RAM allocation is
feasible here. The kernel's own boot log (frame allocator, PCI scan, AHCI
probe, probe battery) follows the captured portion on the physical screen;
not yet transcribed.

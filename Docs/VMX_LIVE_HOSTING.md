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

## Honest boundary

This session could not perform step 3: it is not running on a VMX-owner host.
What is proven here:

- the pure guest-boot logic (bzImage parsing, e820, GDT/TSS, boot_params) —
  `vm.rs` tests;
- the EPT isolation and device emulation — `ept.rs` / `vdev.rs` / `virtio.rs`
  tests;
- the guest itself boots to an interactive shell under QEMU
  (`guest/out/boot-standalone-serial.log`, Track 2 battery 11/11);
- the VMX state machine, field encodings, and now the host-readiness
  pre-flight — `vmx.rs` tests under `--features vmx-demo` (825 passing).

Step 3 (a real CPU in VMX root operation, `vmlaunch`, real VM-exits) is the
sole remaining item and is a boot/hardware action, not a code change.

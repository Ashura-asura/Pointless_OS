# Separate user-level VMM component — design (Phase C, item 1)

Genode's strongest hypervisor property is that each VMM runs as an
**unprivileged component** with a tiny hypervisor TCB: the device models and
run loop live outside the kernel's protection domain, so a bug or compromise
in emulation cannot write kernel memory. This project's `vdev.rs` / `virtio.rs`
/ `vmx.rs` currently run *inside* the kernel with full authority — the single
biggest blast-radius reduction available, and (per `POST_TRACK2_ROADMAP.md`
Phase C) the natural next hypervisor hardening phase.

This document is that phase's design. It is **not** a claim that the split is
built; it is the precise, code-grounded plan — the honest completion of the
research item, with the one hard requirement identified up front.

## The hard requirement

The device models must be **pure**: no kernel globals, no privileged
instructions, no direct physical-memory access. They must reach the machine
only through an injected interface. **This is already true.** `vdev.rs` and
`virtio.rs` take a `GuestMem` (read/write guest-physical memory), a `BlockStore`
(sector I/O), and a `DevicePolicy`; they touch no kernel global (verified by
their contract tests running as ordinary host tests). `DeviceSet`, `VirtioBlk`,
`VirtioRng`, `Pic8259`, `Uart16550`, `Pit8254`, `CmosRtc`, `PciConfigBus`,
`UhciUsb`, `Sb16Dsp` are all relocation-ready today. That is what makes the
split a refactor of plumbing rather than a rewrite of semantics.

## What moves out (unprivileged component)

All of `vdev.rs` + `virtio.rs` — the device-set aggregation, every device
model, the virtio protocol. The component owns one `DeviceSet` instance (with
the VM's `MemStore`), services the guest's port-I/O and virtio requests, and
returns nothing but `IRQ` decisions. Its privilege is exactly the capabilities
it is handed.

## The interface surface (kernel -> component)

The component needs a small, explicit capability/IPC surface. Each item maps
to something the kernel already does; the messages are the minimal set:

| Need | Kernel service today | Proposed capability/IPC |
|---|---|---|
| Guest-physical memory access | `GuestMem` (`EptMem`, `vm.rs`) | `Mem` cap + `read`/`write` IPC (EPT-bounded; kernel checks the range lies in the VM grant) |
| Sector storage | `BlockStore` (`nvme.rs` object store) | `Io` cap + `read_sector`/`write_sector` IPC |
| Virtual clock | `Vm::advance_time` / `PitTicker` | `Clock` cap + `tick` IPC (host ticks in, PIT/CMOS state out) |
| IRQ delivery | `Pic8259::raise` (VMX run loop) | `Irq` cap + `raise(irq)` IPC (kernel keeps the VMCS injection) |
| Frame allocation for DMA | `frame` allocator | `DmaBuf` cap granted per-VM (confinement: the IOMMU domain per `iommu::confine_device_to_grant`) |
| Console TX | `uart.take_tx` (VMX run loop) | pass-through bytes on a channel |

Every message is checked by the kernel against the component's caps; a
compromised VMM can only do what the guest VM could do — read/write its own
grant, its own disk image, raise its own IRQs.

## What stays in the kernel (the tiny hypervisor TCB)

- VM-entry/exit and VMCS management (`vmx.rs` trampolines, `vmx_run_guest`).
- EPT page tables (`ept.rs`) — the grant is a kernel object; the kernel walks
  and bounds-checks every `Mem` IPC against it.
- PIC/APIC IRQ injection into the guest (the VMCS `VM_ENTRY_INTR_INFO` path).
- The IOMMU (`iommu.rs`) — the DMA-confinement gate stays in the TCB so a
  compromised VMM cannot widen its own DMA domain.
- The per-VM `DevicePolicy` allow-list (already the policy choke point).

## Staged plan

1. **Boundary extraction (no behavior change):** move `DeviceSet`+friends into
   a `vmm` crate (or `aegis/src/crates/vmm`) that implements a `GuestMem`/
   `BlockStore` trait pair — the existing contract tests relocate unchanged.
2. **IPC shims:** implement the six capabilities above as thin kernel
   dispatch that forwards to the component process; the kernel-side
   implementation of `GuestMem` becomes the EPT walk + grant check it already
   is today.
3. **Blast-radius proof:** run the whole guest device battery with the
   component in a separate address space; assert the component cannot touch
   a kernel page (MMU-fenced test), and that a fault in it (a deliberately
   panicking device model) does not take down the kernel.

## Known limits (from the existing code, not glossed over)

- `iommu.rs` uses a **flat page table capped at `MAX_MAPPINGS_PER_DOMAIN`
  (64 mappings)**. That is plenty for per-device DMA buffers (NVMe: 5, e1000:
  4) but cannot identity-map a whole guest grant (a 128 MiB grant is 32,768
  frames). Confining a *guest's entire RAM* therefore needs hierarchical
  IOMMU page tables — the honest future hardening item this design inherits.
- The component split depends on a user-space runtime (process + IPC) that
  does not exist yet; step 2 in the staged plan is a real kernel feature.

## Honest status

Not started in code — this is the design. The relocation of `vdev.rs`/
`virtio.rs` is genuinely low-risk (pure, host-testable today); the real work
is the IPC capability surface and a user-space runtime to host the component.
It stays the natural next hypervisor phase after Track 2 ships.

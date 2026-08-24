# Genode-informed Research Pass (Track 1.5 companion)

*Prompt §2: a cheap, parallel-safe research pass against the closest real prior
art to the guest-hosting compatibility strategy Track 2/3 are walking into.
Sources: Genode OS Framework Foundations 26.05 (genode.org/documentation/
genode-foundations), the Vancouver/Seoul/ARM VMM write-ups, and the release
notes for the NOVA/VirtualBox/Sculpt virtualization line. All claims below are
drawn from those documents, not from memory.*

## 1. How Genode scopes capability-gated I/O for guest/child components

- **Every resource is obtained via a parent-routed *session*, never ambient.**
  Core exposes raw resources (RAM, CPUs, IO_MEM, IO_PORT, IRQ) as services;
  a component gets a capability to one only by opening a *session* whose
  routing is decided by its parent. A component's only initial capability is
  its parent capability. There is no "open any device" authority — this is
  the principle of least authority, applied recursively (Foundations §3.1,
  §Core).
- **Device drivers are sandboxed per-device components.** A driver gets only
  the specific IO_MEM range, IO_PORT range, and IRQ numbers for *its* device
  (core's IO_MEM/IO_PORT/IRQ services deny any access outside the granted
  range, and refuse overlapping port ranges so two drivers can't share a
  port). The driver translates a device interface into a device-independent
  *session interface* (Nic/Block/Framebuffer/Terminal/...). (Foundations
  §Device drivers.)
- **Unmapped guest MMIO is default-deny.** In the ARM VMM, "All accesses to
  memory regions not assigned to any device model get ignored, or return
  zero." A guest cannot reach a device the VMM did not instantiate.
- **DMA is IOMMU-confined per device.** Genode subjects all DMA to the IOMMU
  when present, so a device (or a guest driving one) is confined to its own
  DMA buffers and cannot read/write arbitrary RAM. A guest OS is treated as
  *untrusted* even when a device is directly assigned to it. (Foundations
  §Device drivers, "DMA loophole".)

## 2. How Genode runs Linux as a component

- **The VMM is a separate, unprivileged user-level component per guest**
  (microhypervisor approach, Vancouver/Seoul/ARM VMM). The hypervisor (kernel)
  is tiny; the complex device-emulation code lives in a normal process. Bugs
  in one VMM/guest cannot affect another — the TCB of one VM is decoupled from
  every other and from the kernel. (Foundations §Architecture; release 15.02,
  19.05; genodians.org ARM VMM.)
- **The guest's virtual devices are backed by capability-routed Genode
  sessions.** L4Linux/Vancouver stub-drivers connect guest NIC/Block/
  Framebuffer/Terminal to host session services. I/O is mediated by a
  grantable, revocable capability at the component boundary — not by raw
  hardware the guest reaches directly. (Foundations §Architecture; release
  11.11 L4Linux.)
- **Guest physical memory is populated only from a dataspace the VMM proves
  it owns.** The kernel adds host-physical memory to the guest's second-stage
  page tables only from a dataspace capability the VMM holds — so the VMM
  cannot map arbitrary host memory (e.g. the hypervisor itself) into its
  guest. (genodians.org ARM virtualization.)

## 3. Comparison against this project's per-VM capability grant model

| Axis | Genode | This project (Aegis / `vm.rs`, `vdev.rs`) |
|---|---|---|
| VM creation | per-guest VMM component, unprivileged | `Cap::VmRoot:CONTROL` mints `Cap::Vm` (CONTROL) over one VM id (`cap.rs`, `vm.rs::can_create_vm`) |
| Guest device surface | each reachable device is a discrete, grantable, revocable *session*; default-deny for unmapped MMIO | fixed in-kernel `DeviceSet` (PIC/UART/PIT/RTC/PCI+virtio/UHCI/SB16); unknown ports return the floating-bus default (0xFF / ignored) — already a default-deny for *host* hardware |
| DMA to host | IOMMU-confined per device | not yet modeled (no IOMMU confinement in the EPT/grant path) |
| VMM trust boundary | VMM is a separate process; hypervisor TCB stays tiny | the VMM logic (`vdev.rs` device models, `vmx.rs` run loop) runs *inside the kernel* with full kernel authority |

**What this project already gets right (stated honestly):** the guest has no
path to host hardware. Guest port I/O is dispatched only to in-kernel device
models or to the floating-bus default; there is no `sys_out_port` that reaches
a real device. VM creation is capability-gated (`VmRoot`). This is the same
*containment* Genode achieves, even though the boundary is enforced by the
VM-exit handler + device models rather than by a per-device capability the
guest holds.

**Where Genode is ahead (candidates, not adopted here):**

1. **Per-guest device scoping is explicit and policy-driven in Genode; here it
   is implicitly fixed.** Every VM gets the same device set, and which classes
   a guest may reach is not a first-class, auditable policy. (Partially
   addressed — see §4.)
2. **Microhypervisor separation of the VMM.** In Genode the VMM is a
   *separate unprivileged component*; here the device models run in the kernel
   with full authority. Decoupling the VMM's TCB from the kernel is a real
   hardening but a large restructure — explicitly **out of scope** for this
   research pass ("not a mandate to restructure the hypervisor around Genode's
   design"). Flagged as a future, separately-scoped phase.
3. **IOMMU per-device DMA confinement.** Genode's strongest guest/host
   isolation guarantee. This project has no IOMMU layer yet. Larger lift and
   hardware-dependent; flagged as a future phase, not adopted now.

## 4. Adopted change (cheap, clearly valuable, per the prompt's cap of ≤2)

**A per-VM device allow-list (`DevicePolicy`) on `DeviceSet`** — see
`vdev.rs`. This makes the guest-capability boundary *explicit and policy-
scoped*, directly mirroring Genode's per-guest session routing: a VM may only
reach the device classes its policy declares. Essential bootstrap devices
(PIC/UART/PIT/RTC) are always present (a VM without them cannot boot); the
optional classes — `usb` (UHCI+HID), `audio` (SB16), `virtio` (virtio-blk) —
are gated by the policy. Disabling a class makes the guest's accesses to that
class's ports return the floating-bus default, exactly as if the device were
absent, so a policy can shrink a VM's attack surface without special VM-exit
handling and **without any behavior change by default** (`DevicePolicy::all()`
preserves historical behavior).

This is the one change the research surfaced as cheap-and-worthwhile: it turns
an implicit, fixed device surface into a deliberate, auditable grant — the
project's own §9 discipline ("a person can trust the result because the
boundary is explicit") applied to the hypervisor's guest edge.

Verification:
```
cargo test --lib vdev::tests::device_policy_gates_optional_classes
cargo test --lib vdev::      # 49 passed
cargo test --lib vm:: vmx::  # 15 + 14 passed
cargo clippy --lib --all-targets  # clean
cargo fmt --check            # clean
```

## 5. What is deliberately NOT done

- No restructure toward a separate-user-level VMM (item 2 above).
- No IOMMU DMA confinement (item 3 above).
- Two-party/high-risk gating (§9.5) remains `WRITE`-shaped; see
  `TRACK15_SUPERVISOR.md` for that separate, named limitation.

These are real, larger follow-ups and are recorded here as candidates for
future, separately-scoped phases rather than quietly folded into this pass.

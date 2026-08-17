# Real-Hardware Milestones (Phase 12 tail)

Status: **Milestone 1 prepared, not yet closed** — the canary image exists and is
QEMU-verified, but no physical machine has been provided to boot it on.

## Guardrails (non-negotiable, per user instruction: never damage the host OS)

1. **USB-boot only.** The canary boots from a USB stick; it never reads or
   writes the internal disk, never mounts any host partition, never touches
   EFI system variables after boot, and never flashes firmware/BIOS.
2. **The canary compiles the storage path OUT** (`feature = "canary"`): no
   NVMe probe, no FAT ESP mount, no object store, no editor/browser seeding,
   no system-update. A physical NVMe may be *present on the PCI bus* — the
   canary reports it in the scan and then never touches it. Verified: the
   canary binary contains none of the storage code (`NVMe: BAR`,
   `NVMe-store:`, `FAT16: ESP` strings absent; kernel 462208 -> 432328 bytes).
3. **The network demo is self-skipping** (no e1000e on most physical
   machines -> `e1000: no NIC found - driver skipped`); it is write-free even
   when present. The canary does not gate it.
4. **BitLocker check before any Secure Boot change.** If the host Windows
   volume is BitLocker-encrypted, disabling Secure Boot may trigger recovery.
   Run `manage-bde -status` on the host first; keep the recovery key handy,
   and re-enable Secure Boot after the boot test.
5. **Evidence is read-only**: phone photo of the display (serial capture only
   if the machine has a COM1 header — most laptops do not; the display is the
   primary evidence).

## Milestone 1 — serial/display canary boot on physical silicon (NOT CLOSED)

What it proves: the UEFI loader boots from USB on real firmware, queries the
real GOP, sets 800x600x32 (or uses the firmware mode), hands the framebuffer
to the kernel, and the kernel renders the desktop with 0 exceptions — with
zero disk writes.

Evidence to capture on the machine:
- Photo of the boot screen showing the Aegis desktop (shell window + status
  bar) — this is the display-side proof.
- If COM1 is available: serial log showing the `Aegis: CANARY: storage path
  compiled out` banner + `compositor desktop shown` + 0 `KERNEL EXCEPTION`.
- The machine must be **unplugged from the internal disk boot order** (boot
  menu F12/ESC/Del -> USB stick) so no host OS is involved.

Procedure:
1. On the host: `powershell -File build-canary.ps1` (or use the committed
   `aegis-canary.img`).
2. Write `aegis-canary.img` to a USB stick in **DD/raw mode** (Rufus: "Write
   in DD image mode"; balenaEtcher default).
3. On the target machine: check BitLocker (`manage-bde -status`), note the
   recovery key, enter the firmware boot menu, choose the USB stick. If it
   does not appear, disable Secure Boot (re-enable afterwards).
4. Capture the evidence above; then power off. Windows on the internal disk
   is unaffected — nothing wrote to it.

## Milestones 3 & 4 — input/storage/net drivers + VT-x on real silicon (BLOCKED)

- Milestone 3 requires a **dedicated spare NVMe** (the store write path will
  be pointed at a device the user designates; the boot NVMe is never touched).
  The full (non-canary) image is the driver test vehicle.
- Milestone 4 (VT-x bring-up on real silicon, `vmx-demo` feature) runs on any
  VMX-capable CPU but must NOT be the machine's primary OS boot — it takes
  over the machine after boot and halts; run it on the spare machine or in a
  nested-VM configuration.

## What is NOT yet done (honest)

- Nothing has booted on physical hardware. QEMU/OVMF (and VMware) remain the
  only execution environments.
- The canary itself is QEMU-verified only: `serial-canary-test.log` shows
  the canary banner, no NVMe/store/FAT lines with a real NVMe device present
  on the PCI bus, desktop blitted, 0 exceptions; `scr-canary-test.ppm`
  decodes to the 800x600 GOP desktop.
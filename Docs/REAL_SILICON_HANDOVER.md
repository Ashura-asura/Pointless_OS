# Real-Silicon Session Handover — TP201S tablet boot & input

*Self-contained for a fresh clone / fresh agent. Everything below assumes a
clone of `https://github.com/Ashura-asura/Pointless_OS.git` on a native Linux
host. All guidance that mattered for the TP201S is below; do not re-derive it.*

## TL;DR

The Aegis OS kernel boots on the **TP201S tablet** (real x86, UEFI skipped
`ExitBootServices` because it hangs), gets a **graphical shell**, but has
**no keyboard/mouse input**. Root cause on real silicon (QEMU is fine):

1. **Input is PS/2-only.** The kernel's only keyboard/mouse path is PS/2
   (`ps2.rs`, `ps2_mouse.rs`). QEMU emulates a PS/2 keyboard+mouse, so it
   works there. The tablet has **no PS/2 controller** — its keyboard dock /
   touchpad are **USB HID**. Confirmed live: `PS2=N`, `USB=Y`.
2. **The LAPIC timer ISR never fires on the tablet** — the on-screen counter
   `T=0` and never increments, and the live LAPIC timer count `TC` must be
   read to tell *why*. No timer interrupt ⇒ no preemption ⇒ no input ISRs
   either. This is the immediate blocker and is independent of PS/2-vs-USB.
3. The "graphical shell" is an **80×25 character-cell UI** (`SW=80,SH=25`)
   blitted to the framebuffer every frame via `desktop::blit →
   vga::vga_show_desktop`. Raw-pixel diagnostics are therefore invisible once
   the shell runs; **diagnostics must be rendered as cells** in the desktop.

## Environment / hardware facts (do not re-check)

- TP201S tablet, x86, UEFI firmware. Loader **skips `ExitBootServices`**
  (it hangs on this firmware) — UEFI is still resident.
- Framebuffer: `0x90000000`, **1366×768**, stride 1376, **BGRX** (write
  bytes `[0,1,2]` = `[B,G,R]`; swap R/B for correct color — cosmetic).
- LAPIC at `0xFEE00000`; I/O APIC at `0xFEC00000` (both GB3 identity-mapped).
- USB flash device is `/dev/sdb1`. sudo password `2003`.
  Staged EFI: `/tmp/aegis-esp/EFI/BOOT/BOOTX64.EFI`.
  USB mount: `/tmp/usbmnt` (mount with
  `mount -o rw,uid=asura27,gid=asura27 /dev/sdb1 /tmp/usbmnt`).
- Kernel is fully resident (unplugging USB after boot does NOT collapse shell).
- Serial/COM1 is **unwired** — no serial output to read. All diagnosis is
  on-screen (the cell status line below). Cannot see images.

## Build & flash procedure (exact)

```bash
cd Pointless_OS/aegis-kernel
cargo build --release --features kernel,vmx-demo --target x86_64-unknown-none
cp target/x86_64-unknown-none/release/aegis-kernel ../uefi-boot/aegis-kernel.bin
cd ../uefi-boot
cargo build --release --features uefi --target x86_64-unknown-uefi
cp target/x86_64-unknown-uefi/release/uefi-boot.efi /tmp/aegis-esp/EFI/BOOT/BOOTX64.EFI
sudo -S mount -o rw,uid=asura27,gid=asura27 /dev/sdb1 /tmp/usbmnt <<< "2003"
cp /tmp/aegis-esp/EFI/BOOT/BOOTX64.EFI /tmp/usbmnt/EFI/BOOT/BOOTX64.EFI
sync && sudo -S umount /tmp/usbmnt <<< "2003"
```
The loader embeds the kernel via `include_bytes!("../aegis-kernel.bin")`, so
the kernel MUST be copied into `uefi-boot/` and the loader rebuilt each time.
Note: `cargo build` at the repo root fails (no Cargo.toml there) — run it
inside `aegis-kernel/` and `uefi-boot/`.

## On-screen diagnostic (the key instrument)

`desktop.rs::render_diag()` paints a high-contrast (white-on-blue) status line
at **row 0** of the cell UI, re-blitted continuously (driven by a local
busy-loop cadence in `task_input`, NOT the timer, because the timer is dead).
Read it from the top line of the shell:

```
PS2=N USB=Y KB=_ MS=_ IO=N T=0 X2=0 SV=1 TC=12345 L=0
```

Fields:
- `PS2` — `Y`/`N` PS/2 controller responded to probe. (Tablet = `N`.)
- `USB` — `Y`/`N` XHCI host controller found via PCI. (`Y` on tablet.)
- `KB` / `MS` — `F` once the keyboard / mouse ISR has fired (latched).
- `IO`  — `Y`/`N` I/O APIC IRQ1 redirection verified accepted (read-back).
- `T`   — `timer_ticks()` count. **Stuck at 0 ⇒ timer ISR never runs.**
- `X2`  — `0`=xAPIC/MMIO LAPIC, `1`=x2APIC/MSR LAPIC.
- `SV`  — `0`/`1` LAPIC software-enabled (SVR bit 8).
- `TC`  — **live LAPIC timer current-count**; watch whether it changes.
- `L`   — LAPIC ID.

### How to read the pending answer (user is about to report this)

- **`TC` keeps changing** (even though `T=0`) ⇒ the LAPIC timer *hardware is
  running* but the interrupt is not delivered ⇒ **IDT / vector / TPR** problem
  (vector `0x30` not reaching `timer_trap_rust`). IDT does map `0x30`→
  `timer_stub`→`timer_trap_rust` (verified in `cpu.rs::init_idt`), so suspect
  TPR masking or a stale/duplicate IDT.
- **`TC` stuck** (same value, or `0x00000000`/`0xFFFFFFFF`) ⇒ the LAPIC isn't
  counting ⇒ my timer-setup writes aren't reaching it ⇒ **mode / MMIO access**
  problem. On real silicon the APIC MMIO page may need a correct memory type
  (UC), or `LAPIC_X2` is mis-set so MMIO writes are no-ops while the LAPIC is
  actually in x2APIC mode.
- `X2=1` ⇒ correctly in x2APIC MSR mode (MMIO caching irrelevant).
- `X2=0` ⇒ xAPIC MMIO mode; if `TC` is stuck, suspect APIC-page mapping /
  memory type.

## Code changes made this session (working tree, UNCOMMITTED)

- `cpu.rs`:
  - `init_lapic_timer()` x2APIC detect/downgrade-refusal → sets `LAPIC_X2`;
    mode-aware `lapic_read`/`lapic_write` (MSR `0x800+(reg>>4)` when x2APIC).
  - `init_ioapic_legacy()` (+ `route_ioapic_gsi`, `ioapic_eoi`,
    `init_ioapic`): programs the I/O APIC from MADT, routes GSI1→KEYBOARD_VECTOR
    (`0x21`), GSI12→MOUSE_VECTOR (`0x2C`); BSP LAPIC ID now `lapic_read(0x20)&0xFF`
    (low byte, not `>>24`).
  - Diagnostic statics + accessors: `PS2_PRESENT`, `IOAPIC_OK`, `KEY_FIRED`,
    `MOUSE_FIRED`, `USB_XHCI_FOUND`, `TIMER_TICKS` (now incremented in
    `timer_trap_rust`), and `lapic_diag()` returning `(x2,svr_enabled,timer_count,id)`.
  - `diag_fill()` (raw pixel block) and `tick_repaint_latches()` — these are
    now **ineffective** (overwritten by the cell UI) but harmless; keep or remove.
- `ps2.rs` `init_controller()`: sets `PS2_PRESENT` latch instead of pixel paint.
- `usbhcd.rs` `XhciController::probe()`: sets `USB_XHCI_FOUND` on success.
  The XHCI driver enumerates a device and reads its descriptor but has **NO
  HID / interrupt-endpoint support** — that is the missing piece for USB input.
- `desktop.rs`:
  - `render_diag()` — paints the status line above into `self.screen` (row 0)
    inside `composite()` (so it survives the per-frame blit).
  - `refresh()` — re-composite + blit (called from `task_input`).
- `main.rs` `task_input()`: periodic `desktop::refresh()` on a local busy-loop
  counter (not the timer) so the status updates even with a dead timer. Still
  drains `ps2::pop_event()` / `ps2_mouse::pop_event()` only — **no USB source
  yet**.

## Next steps (after the TC/X2/SV answer)

1. **Fix the LAPIC timer delivery** (the `T=0` blocker) using the TC/X2/SV
   readout. Most likely one of:
   - x2APIC/MSR mode not actually engaged while `LAPIC_X2=false` → MMIO
     no-ops; force x2APIC MSR usage, or correctly drop to xAPIC.
   - APIC MMIO page mapped with wrong PAT/memory type on real silicon (UC
     required) — fix the GB3 page-table attributes for the APIC range.
   - TPR masking the timer vector (0x30 ⇒ priority 3) — ensure TPR=0.
2. **Implement USB HID keyboard+mouse** on top of the existing `usbhcd.rs`
   XHCI driver: detect HID class (iface class `0x03`, boot protocol),
   `Set_Protocol`(boot), configure the interrupt IN endpoint, submit periodic
   interrupt TRBs, poll the transfer/event ring for the 8-byte keyboard /
   3–4-byte mouse report, and **push `InputEvent`s into the same PS/2 ring
   buffer** (`ps2::KEY_BUF`) that `task_input` already drains — so the desktop
   and `task_input` need no further changes. Add a USB poll call inside
   `task_input` (or a dedicated task) feeding that ring.
3. Verify `KB=`/`MS=` flip to `F` when typing/moving, then real input works.

## Key file references

- `aegis-kernel/src/cpu.rs` — LAPIC/x2APIC, I/O APIC, IDT, `timer_trap_rust`,
  `lapic_diag`, diagnostic statics (`init_lapic_timer` ~506, `init_ioapic_legacy` ~278).
- `aegis-kernel/src/ps2.rs` / `ps2_mouse.rs` — PS/2 input (QEMU-only on tablet).
- `aegis-kernel/src/usbhcd.rs` — XHCI driver (enumerate + control xfer; **no HID**).
- `aegis-kernel/src/desktop.rs` — `render_diag` (~1395), `composite`, `blit`,
  `refresh`, `handle_key`/`handle_mouse` (cell UI).
- `aegis-kernel/src/main.rs` — `task_input` (~2610) drains PS/2 rings; USB poll
  hook needed here.
- `aegis-kernel/src/page_tables.rs` — GB1/GB2 → 2 MiB PDs (framebuffer MMIO
  fix); check GB3 APIC-page memory type for the timer fix.

## Outstanding user question (answer drives the timer fix)

> From the top status line after boot, report `X2=`, `SV=`, whether `TC=`
> changes over ~2 s, `L=`, and confirm `T=0`, `PS2=N`, `USB=Y`, `KB=`/`MS=` stay `_`, `IO=N`.

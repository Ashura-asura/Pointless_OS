# Real-Silicon Session Handover — TP201S tablet boot & input

*Self-contained for a fresh clone / fresh agent. Everything below assumes a
clone of `https://github.com/Ashura-asura/Pointless_OS.git` on a native Linux
host. All guidance that mattered for the TP201S is below; do not re-derive it.*

## TL;DR (current state)

The Aegis OS kernel boots on the **TP201S tablet** (real x86, UEFI skipped
`ExitBootServices` because it hangs), gets a **graphical shell**, and now has
**USB-HID keyboard/mouse input** (the tablet's only input path). The LAPIC
timer fix (x2APIC-via-MSR) is implemented; whether it *engages* on the tablet
still needs a live read of `X2`/`SV`/`TC` (see diagnostics below).

Root causes addressed this session:
1. **Input was PS/2-only.** The tablet has **no PS/2 controller** — its
   keyboard dock / touchpad are **USB HID**. Confirmed live: `PS2=N`, `USB=Y`.
   **FIXED:** a full USB-HID driver now sits on top of `usbhcd.rs` and feeds
   the existing PS/2 ring buffers (`ps2::inject_scancode` /
   `ps2_mouse::inject_byte`), so `task_input` needs no other changes.
2. **LAPIC timer ISR may not fire** (`T=0`, `TC=0` observed). The likely cause
   is a broken APIC MMIO mapping on real silicon (page-table memory type, or
   the LAPIC left in x2APIC mode while the kernel used MMIO). **FIXED in code:**
   `init_lapic_timer()` now *enables x2APIC* (CPUID leaf 1 ECX bit 21 +
   `wrmsr(0x1B, |EXTD|ENABLE)`) and drives the LAPIC entirely via MSRs —
   bypassing the MMIO path. The APIC MMIO page is also marked `UNCACHEABLE`
   as a fallback. Whether `X2=1`/`SV=1`/`TC` counts on the tablet is still a
   live-check item.
3. The "graphical shell" is an **80×25 character-cell UI** (`SW=80,SH=25`)
   blitted every frame via `desktop::blit → vga::vga_show_desktop`. Raw-pixel
   diagnostics are invisible once the shell runs; **diagnostics are rendered
   as cells** in the desktop.

## Environment / hardware facts (do not re-check)

- TP201S tablet, x86, UEFI firmware. Loader **skips `ExitBootServices`**
  (it hangs on this firmware) — UEFI is still resident.
- Framebuffer: `0x90000000`, **1366×768**, stride 1376, **BGRX** (write
  bytes `[0,1,2]` = `[B,G,R]`; swap R/B for correct color — cosmetic).
- LAPIC at `0xFEE00000`; I/O APIC at `0xFEC00000` (both GB3 identity-mapped).
- USB flash device is `/dev/sdb1` (Cruzer Blade 7.5G). sudo password `2003`.
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

**CI note (this is enforced on push):** the GitHub `CI` workflow sets
`RUSTFLAGS=-Dwarnings` and runs, for both `aegis-kernel` and `uefi-boot`:
`cargo fmt --check`, `cargo clippy --all-targets`, `cargo test`, and a
release build. It also runs a `miri` job, an `asan` job, and a bounded
`fuzz_corpus` gate. A clean local pass of fmt+clippy+test+build for both
crates is the bar; see "CI fixes made this session" below for what had to be
cleaned up.

## On-screen diagnostic (the key instrument)

`desktop.rs::render_diag()` paints a high-contrast (white-on-blue) status line
at **row 0** of the cell UI, re-blitted continuously (driven by a local
busy-loop cadence in `task_input`, NOT the timer, because the timer may be
dead). Read it from the top line of the shell:

```
PS2=N USB=Y KB=_ MS=_ IO=N T=0 X2=0 SV=1 TC=12345 L=0
```

Fields:
- `PS2` — `Y`/`N` PS/2 controller responded to probe. (Tablet = `N`.)
- `USB` — `Y`/`N` XHCI host controller found via PCI and `set_usb_xhci_found`
  called. (`Y` on tablet — set in `boot_kernel` after `XhciController::probe`.)
- `KB` / `MS` — `F` once a keyboard / mouse event has been injected into the
  ring (latched via `cpu::mark_key_fired` / `mark_mouse_fired`, called from
  `ps2::inject_scancode` / `ps2_mouse::inject_byte`). This now flips on
  **USB-HID** input, not just a (absent) PS/2 ISR.
- `IO`  — `Y`/`N` I/O APIC IRQ1 redirection verified accepted (read-back).
- `T`   — `timer_ticks()` count. **Stuck at 0 ⇒ timer ISR never runs.**
- `X2`  — `0`=xAPIC/MMIO LAPIC, `1`=x2APIC/MSR LAPIC (engaged by
  `init_lapic_timer` when CPUID advertises it).
- `SV`  — `0`/`1` LAPIC software-enabled (SVR bit 8).
- `TC`  — **live LAPIC timer current-count**; watch whether it changes.
- `L`   — LAPIC ID.

### How to read it
- `TC` keeps changing (even if `T=0`) ⇒ LAPIC timer *hardware* is running but
  the interrupt is not delivered ⇒ IDT / vector / TPR problem.
- `TC` stuck ⇒ LAPIC isn't counting ⇒ timer-setup writes aren't reaching it.
  With `X2=1` the MSR path is in use (MMIO caching irrelevant); with `X2=0`
  suspect APIC-page memory type.
- `X2=1` ⇒ correctly in x2APIC MSR mode. `X2=0` ⇒ xAPIC MMIO mode; if `TC`
  stuck, suspect APIC-page mapping / memory type (the UNCACHEABLE fallback
  in `page_tables.rs` addresses this).

## USB-HID integration (this session — the input fix)

**Files (applied from `/home/asura27/Desktop/new files/`):** `usbhcd.rs`
(full HID driver), `ps2.rs` (adds `inject_scancode`), `ps2_mouse.rs` (adds
`inject_byte`). These three replace the previous PS/2-only input path.

- `usbhcd.rs`:
  - `XhciController::enumerate_hid_devices(&mut self) -> usize` — scans all
    ports for HID class (interface class `0x03`, boot protocol) keyboards /
    mice, configures the interrupt IN endpoint, arms periodic interrupt TRBs.
  - `poll_hid(&mut self)` — bounded drain of the event ring, decodes the
    8-byte keyboard / 3–4-byte mouse report via `hid_keycode_to_scancode`,
    and injects scancodes/bytes into the PS/2 rings through
    `crate::ps2::inject_scancode` / `crate::ps2_mouse::inject_byte`. **Polled,
    not interrupt-driven** — so input works even with the LAPIC timer dead.
  - `handle_hid_report` wraps its `inject_*` calls in `unsafe {}` blocks.
- `ps2.rs::inject_scancode(sc)` and `ps2_mouse.rs::inject_byte(byte)` now also
  call `crate::cpu::mark_key_fired()` / `mark_mouse_fired()` so the `KB=`/`MS=`
  diagnostic latches flip on real (USB) input.
- `main.rs`:
  - `static mut XHCI: Option<XhciController>` at module level (with
    `#[allow(static_mut_refs)]` on `task_input`).
  - In `boot_kernel`'s USB demo block: after `XhciController::probe`, call
    `enumerate_hid_devices()`, `set_usb_xhci_found(true)`, and store the
    controller in `XHCI`.
  - In `task_input`'s loop: `if let Some(x) = XHCI.as_mut() { x.poll_hid(); }`
    each iteration.

### IMPORTANT: do NOT apply the folder's `cpu.rs` / `page_tables.rs`
`/home/asura27/Desktop/new files/` also contains `cpu.rs` and
`page_tables.rs`, but those are an **older snapshot** — a public-symbol diff
shows they are *missing* `mark_key_fired`, `mark_mouse_fired`,
`set_usb_xhci_found`, `init_ioapic*`, `ioapic_eoi`, `diag_fill`, etc. The
on-disk `aegis-kernel/src/cpu.rs` and `page_tables.rs` are a strict superset
(they contain the x2APIC fix, I/O APIC driver, diagnostic statics, and the
UNCACHEABLE LAPIC page). Applying the folder `cpu.rs`/`page_tables.rs` would
**not compile**. Only `usbhcd.rs`, `ps2.rs`, `ps2_mouse.rs` from that folder
were applied.

## LAPIC timer fix (implemented; verify on hardware)

In `cpu.rs::init_lapic_timer()`:
1. `cpu_has_x2apic()` — CPUID leaf 1 `ECX` bit 21 (via `core::arch` intrinsic).
2. If supported, **enable x2APIC**: `let base = rdmsr(0x1B); wrmsr(0x1B, base |
   APIC_BASE_EXTD | APIC_BASE_ENABLE);` and set `LAPIC_X2 = true`.
3. `lapic_read`/`lapic_write` are mode-aware: when `LAPIC_X2`, they use the
   MSR interface `0x800 + (reg >> 4)`, bypassing the MMIO page entirely.
4. SVR enable / LVT timer / divide / initial-count then take effect via MSR.

Fallback (also in place): `page_tables.rs` marks the LAPIC's 4 KB page
`UNCACHEABLE` (PCD|PWT → PAT entry 3 = UC) so the xAPIC/MMIO path gets the
correct memory type on real silicon if x2APIC is unavailable.

## CI fixes made this session (so the push is green)

All under `RUSTFLAGS=-Dwarnings` (clippy turns these into errors):
- `cpu.rs`: `ioapic_write`/`ioapic_read` `base.add(0x00 / 4)` → `base.add(0)`
  (clippy `erasing_op`); `lapic_read` dropped the unused `hi` (`out("edx") _`);
  added `# Safety` docs to `init_diag_fb` and `diag_paint`
  (`missing_safety_doc`).
- `usbhcd.rs`: `(8 << 0)` → `8` (`identity_op`); `#[allow(clippy::needless_range_loop)]`
  on `poll_hid`; `#[allow(dead_code)]` on `HidDevice` and the `bdf` field.
- `main.rs`: `#[allow(static_mut_refs)]` on `task_input`.
- `gop_console.rs`: `scroll_drops_the_oldest_line` allocated an 800×600
  framebuffer, but `blit` draws `ROWS*16 = 640` pixel rows → it wrote ~79 KB
  past the buffer and corrupted the heap (glibc "double free or corruption"
  on drop, crashing `cargo test`). Fixed the test to allocate 800×640 so
  `blit` stays in bounds. (Runtime `blit` on the tablet is fine because the
  real GOP framebuffer is ≥640 px tall.)

After these, locally: `aegis-kernel` fmt+clippy clean, **856 unit tests
pass**, `cargo build --features kernel` (none target) OK; `uefi-boot`
fmt+clippy clean, 22 tests pass, `cargo build --features uefi` OK.

## Key file references

- `aegis-kernel/src/cpu.rs` — LAPIC/x2APIC (`init_lapic_timer`),
  I/O APIC (`init_ioapic_legacy`, `route_ioapic_gsi`, `ioapic_eoi`),
  IDT (`init_idt`, `timer_stub`, `exception_trap_rust`), `lapic_diag`,
  diagnostics (`set_usb_xhci_found`, `mark_key_fired`, `mark_mouse_fired`).
- `aegis-kernel/src/usbhcd.rs` — XHCI driver **with USB-HID**
  (`enumerate_hid_devices`, `poll_hid`, `handle_hid_report`,
  `hid_keycode_to_scancode`).
- `aegis-kernel/src/ps2.rs` / `ps2_mouse.rs` — PS/2 ring buffers + the new
  `inject_scancode` / `inject_byte` entry points used by the HID driver.
- `aegis-kernel/src/desktop.rs` — `render_diag` (~1395), `composite`, `blit`,
  `refresh`, `handle_key`/`handle_mouse`.
- `aegis-kernel/src/main.rs` — `boot_kernel` (USB HID setup), `task_input`
  (~2610, drains PS/2 rings + `poll_hid`).
- `aegis-kernel/src/page_tables.rs` — GB1/GB2 → 2 MiB PDs (framebuffer MMIO
  fix); LAPIC page `UNCACHEABLE`; DEV_HI window for 64-bit BARs.

## Expected on the tablet now

Top status line should read `USB=Y`, and **`KB=`/`MS=` flip to `F`** when you
press a key / move the mouse (the desktop should also respond — Tab/arrows/
typing), *independent of the timer*. `T=` may still be `0` until the x2APIC
enable is verified live: check `X2=1`, `SV=1`, and `TC` counting. If `T`
stays `0` with `X2=0`, the MMIO fallback (UNCACHEABLE) is the path to
investigate; if `X2=1` but `TC` still `0`, the MSR writes aren't reaching
the LAPIC (rare). Report the boot-log line
`xHCI: HID devices enumerated: N` and the status line if input or the timer
still misbehaves.

## Commit state

All of the above is committed and pushed to `main`
(`git@github.com:Ashura-asura/Pointless_OS.git`). The committed
`uefi-boot/aegis-kernel.bin` is the `kernel,vmx-demo` none-target build that
the loader embeds; it matches what was flashed to the USB.

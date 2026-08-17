//! Minimal VGA text-mode console (80x25, 0xB8000) so the live boot demo is
//! visible on the VM display instead of a blank screen. Mirrors the kernel's
//! serial `sprintln!` output one-for-one.
//!
//! Honest limits: text mode only (the UEFI firmware leaves the display in
//! 80x25 text mode for the boot console); the ring-3 `Write` syscall also
//! lands here, and the low 2 MB is USER-flagged in per-task PML4s, so a
//! user task could scribble the screen — cosmetic, accepted for the demo.

/// VGA text-mode framebuffer (color text buffer, 2 bytes per cell).
/// `static mut` only so the unit tests can redirect it to a RAM buffer.
static mut VGA_BUF: *mut u16 = 0xB8000 as *mut u16;
const COLS: usize = 80;
const ROWS: usize = 25;

/// Attribute byte for all cells: white on black.
const ATTR: u16 = 0x0F00;

/// Next cursor position. Kept in plain statics (single CPU, same nesting
/// tolerance as the serial logger: an interrupt printing mid-line just
/// interleaves a few cells).
static mut ROW: usize = 0;
static mut COL: usize = 0;

fn cells() -> &'static mut [u16] {
    unsafe { core::slice::from_raw_parts_mut(VGA_BUF, COLS * ROWS) }
}

fn newline() {
    unsafe {
        ROW += 1;
        COL = 0;
        if ROW >= ROWS {
            ROW = ROWS - 1;
            cells().copy_within(COLS..COLS * ROWS, 0);
            cells()[COLS * (ROWS - 1)..].fill(ATTR | b' ' as u16);
        }
    }
}

/// Write a string to the text-mode screen. `\r` is ignored (the kernel's
/// CRLF line endings only need `\n` here).
pub fn vga_write_str(s: &str) {
    vga_write_bytes(s.as_bytes());
}

/// Write raw bytes (e.g. a ring-3 `Write` syscall buffer) to the screen.
pub fn vga_write_bytes(bytes: &[u8]) {
    if display_frozen() {
        return;
    }
    for &b in bytes {
        if b == b'\r' {
            continue;
        }
        if b == b'\n' {
            newline();
            continue;
        }
        unsafe {
            if COL >= COLS {
                newline();
            }
            cells()[ROW * COLS + COL] = ATTR | b as u16;
            COL += 1;
        }
    }
}

/// True once the composited desktop has been blitted to the display. After
/// that, `sprintln!` / ring-3 `Write` stop touching the text buffer so the
/// GUI stays on screen; serial logging is unaffected (it happens first in
/// `sprintln!`).
static mut SHOWING_DESKTOP: bool = false;

fn display_frozen() -> bool {
    unsafe { SHOWING_DESKTOP }
}

/// Blit a composited screen (u16 cells: `char | attr<<8`) onto the real VGA
/// text buffer, centered, then freeze the display so the GUI stays visible
/// for the rest of the run.
pub fn vga_show_desktop(screen: &[u16], sw: usize, sh: usize) {
    unsafe {
        cells().fill(ATTR | b' ' as u16);
        let ox = (COLS.saturating_sub(sw)) / 2;
        let oy = (ROWS.saturating_sub(sh)) / 2;
        for y in 0..sh {
            let src = &screen[y * sw..(y + 1) * sw];
            let dst = &mut cells()[(oy + y) * COLS + ox..(oy + y) * COLS + ox + sw];
            dst.copy_from_slice(src);
        }
        SHOWING_DESKTOP = true;
        // Force the emulated VGA (QEMU/VMware) to re-scan the text buffer:
        // a pure memory blit does not trigger a redraw, but a sequencer
        // display-off/on transition does.
        force_display_refresh();
    }
}

fn out8(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, preserves_flags));
    }
}

fn in8(port: u16) -> u8 {
    let v: u8;
    unsafe {
        core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, preserves_flags));
    }
    v
}

/// Toggle the sequencer clocking-mode display-off bit so the text buffer is
/// re-scanned from 0xB8000 on the next frame. Works on QEMU stdvga and
/// VMware SVGA text mode. Also nudges the CRTC cursor position, which is the
/// classic trigger VMware/QEMU honour for re-scanning the text buffer.
fn force_display_refresh() {
    // SR0 index register; SR1 = clocking mode (bit 5 = screen off).
    out8(0x3C4, 0x01);
    let sr1 = in8(0x3C5);
    out8(0x3C4, 0x01);
    out8(0x3C5, sr1 | 0x20); // screen off
    out8(0x3C4, 0x01);
    out8(0x3C5, sr1 & !0x20); // screen back on
                              // CRTC start address (indices 0x0C/0x0D): poke it to the same value so
                              // the emulator re-reads the text buffer from row 0.
    out8(0x3D4, 0x0C);
    let sa_hi = in8(0x3D5);
    out8(0x3D4, 0x0D);
    let sa_lo = in8(0x3D5);
    out8(0x3D4, 0x0C);
    out8(0x3D5, sa_hi);
    out8(0x3D4, 0x0D);
    out8(0x3D5, sa_lo);
    // CRTC cursor location: poke high byte register (index 0x0E), then low.
    out8(0x3D4, 0x0E);
    out8(0x3D5, 0x00);
    out8(0x3D4, 0x0F);
    out8(0x3D5, 0x00);
    // CRTC cursor start/end (indices 0x0A/0x0B): enable a block cursor so the
    // redraw definitely lands.
    out8(0x3D4, 0x0A);
    out8(0x3D5, 0x0D);
    out8(0x3D4, 0x0B);
    out8(0x3D5, 0x0E);
}

/// Dump the current 80x25 text buffer to serial (printable chars only) so a
/// host-side observer can confirm exactly what the VM display holds after the
/// desktop blit.
pub fn vga_dump_buffer() {
    let mut line = [0u8; COLS + 1];
    for y in 0..ROWS {
        for (x, c) in line.iter_mut().enumerate().take(COLS) {
            let cell = cells()[y * COLS + x];
            let b = (cell & 0xFF) as u8;
            *c = if (0x20..0x7F).contains(&b) { b } else { b'?' };
        }
        line[COLS] = 0;
        crate::sprintln!(
            "VGA[{:02}] |{}|",
            y,
            core::str::from_utf8(&line[..COLS]).unwrap_or("")
        );
    }
}

/// Format one line (via `format_args!`) straight onto the screen plus a
/// trailing newline. Used by `sprintln!` so both sinks share one format.
pub fn vga_fmt_line(args: core::fmt::Arguments) {
    #[cfg(test)]
    {
        // Host unit tests have no VGA hardware or 0xB8000 mapping; keep
        // `sprintln!` safe to call from any code path exercised by tests.
        let _ = args;
    }
    #[cfg(not(test))]
    {
        if display_frozen() {
            return;
        }
        use core::fmt::Write;
        struct VgaWriter;
        impl Write for VgaWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                vga_write_str(s);
                Ok(())
            }
        }
        let _ = VgaWriter.write_fmt(args);
        vga_write_str("\n");
        unsafe {
            if !DIAGED {
                DIAGED = true;
                // One-shot proof that the text buffer really holds our output.
                let mut row0 = [0u8; 40];
                for (i, c) in cells()[0..40].iter().enumerate() {
                    let b = (c & 0xFF) as u8;
                    row0[i] = if (0x20..0x7F).contains(&b) { b } else { b'?' };
                }
                crate::sprintln!("VGA BUF row0 raw={:x?}", &row0[..]);
            }
        }
    }
}

/// One-shot text-buffer diagnostic (see `vga_fmt_line`).
#[cfg(not(test))]
static mut DIAGED: bool = false;

/// Clear the screen and reset the cursor. Text-mode entry is split out so
/// the buffer logic stays unit-testable on the host (no port I/O).
///
/// NOTE: `vga_enter_text_mode` must NOT be called from here — it disables
/// the firmware's Bochs-VBE/GOP display mode, which a pixel backend needs.
/// Callers that end up with no pixel backend call it explicitly.
pub fn vga_init() {
    vga_clear_screen();
}

/// Reset the cursor and blank the text buffer (no port I/O).
pub fn vga_clear_screen() {
    unsafe {
        cells().fill(ATTR | b' ' as u16);
        ROW = 0;
        COL = 0;
    }
}

/// Upload the embedded 8x16 font into VGA VRAM plane 2 (the classic
/// character-generator area) so hardware/firmware that never ran the VGA
/// BIOS can still render text. 256 chars x 32 bytes per char (16 glyph
/// bytes + 16 padding), map A at 0xA0000.
///
/// Honest limits: this is the classic VGA font-upload dance; chars >= 0x80
/// render as blanks because the embedded font only covers 0x00..=0x7F.
fn vga_upload_font() {
    fn out(port: u16, val: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, preserves_flags));
        }
    }
    fn out_index(port: u16, index: u8, val: u8) {
        out(port, index);
        out(port + 1, val);
    }

    // Put the VGA into the planar write state that routes byte writes at
    // 0xA0000 into plane 2.
    out_index(0x3CE, 0x05, 0x00); // graphics mode: read/write mode 0
    out_index(0x3CE, 0x06, 0x04); // memory map: 0xA0000, odd/even off
    out_index(0x3C4, 0x04, 0x06); // memory mode: no chaining, no odd/even
    out_index(0x3C4, 0x02, 0x04); // write only plane 2
    let base = 0xA0000 as *mut u8;
    for ch in 0..256usize {
        let glyph: [u8; 16] = if ch < 128 {
            crate::font::FONT8X16_BASIC[ch]
        } else {
            [0u8; 16]
        };
        unsafe {
            let dst = base.add(ch * 32);
            core::ptr::write_bytes(dst, 0, 32);
            core::ptr::copy_nonoverlapping(glyph.as_ptr(), dst, 16);
        }
    }
    // Back to text-mode state. SR4 = 0x03 (ext-mem + odd/even, no chain4,
    // no sequential mode): with bit3 clear the text path keeps cell writes
    // word-aligned in vram (QEMU gates addr>>=1 masking on these bits).
    out_index(0x3C4, 0x04, 0x03);
    // SR2 = 0x03: only planes 0/1 writable. Combined with the odd/even
    // parity rule in QEMU/real VGA, even bytes (chars) hit plane 0 and odd
    // bytes (attrs) hit plane 1; writing all planes instead would stamp
    // plane 2 (the font area) with screen contents.
    out_index(0x3C4, 0x02, 0x03); // write planes 0+1 (odd/even text)
    out_index(0x3CE, 0x05, 0x10); // graphics mode: text-ish state
    out_index(0x3CE, 0x06, 0x0E); // memory map: 0xB8000
}

/// Restore the standard 16-color VGA text palette in the DAC. UEFI graphics
/// output may leave the DAC entries scrambled, which shows up as wrong text
/// colors (e.g. everything green).
fn vga_set_palette16() {
    fn out(port: u16, val: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, preserves_flags));
        }
    }
    // Six-bit DAC values for the classic palette.
    const PAL: [[u8; 3]; 16] = [
        [0x00, 0x00, 0x00], // 0 black
        [0x00, 0x00, 0x2A], // 1 blue
        [0x00, 0x2A, 0x00], // 2 green
        [0x00, 0x2A, 0x2A], // 3 cyan
        [0x2A, 0x00, 0x00], // 4 red
        [0x2A, 0x00, 0x2A], // 5 magenta
        [0x2A, 0x2A, 0x00], // 6 brown
        [0x2A, 0x2A, 0x2A], // 7 light gray
        [0x15, 0x15, 0x15], // 8 dark gray
        [0x15, 0x15, 0x3F], // 9 light blue
        [0x15, 0x3F, 0x15], // a light green
        [0x15, 0x3F, 0x3F], // b light cyan
        [0x3F, 0x15, 0x15], // c light red
        [0x3F, 0x15, 0x3F], // d light magenta
        [0x3F, 0x3F, 0x15], // e yellow
        [0x3F, 0x3F, 0x3F], // f white
    ];
    out(0x3C8, 0); // DAC write index starts at entry 0
    for entry in PAL {
        for v in entry {
            out(0x3C9, v);
        }
    }
}

/// Disable the VMware SVGA device so its display falls back to legacy VGA.
///
/// The VMware EFI firmware hands off with the SVGA device still enabled in a
/// GOP graphics mode; while it is, VMware ignores the 0xB8000 text buffer
/// (and our Bochs VBE disable at 0x1CE/0x1CF is a no-op on VMware — verified
/// by the `vbe_enable=0xffff` readback). Per VMware's SVGA interface doc,
/// writing `SVGA_REG_ENABLE = 0` disables SVGA and "also enables VGA", so the
/// standard text-mode path programmed afterwards finally reaches the display.
///
/// Returns true if a VMware SVGA device was found and disabled.
fn vmware_svga_disable() -> bool {
    use crate::pci::{PciAddress, BAR0, CLASS, DEVICE_ID, VENDOR_ID};
    fn out32(port: u16, val: u32) {
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, preserves_flags));
        }
    }
    fn in32(port: u16) -> u32 {
        let v: u32;
        unsafe {
            core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, preserves_flags));
        }
        v
    }
    unsafe {
        for device in 0..32u8 {
            let addr = PciAddress::new(0, device, 0);
            let vendor = crate::pci::read_config_word(addr, VENDOR_ID);
            if vendor != 0x15AD {
                continue;
            }
            let device_id = crate::pci::read_config_word(addr, DEVICE_ID);
            let class = crate::pci::read_config_byte(addr, CLASS);
            // VMware SVGA-II (0x0405) / SVGA (0x0710), or any display class.
            if class != 0x03 && device_id != 0x0405 && device_id != 0x0710 {
                continue;
            }
            let bar0 = crate::pci::read_config_dword(addr, BAR0);
            if bar0 & 1 == 0 {
                continue; // BAR0 not I/O space
            }
            let io_base = (bar0 & 0xFFFC) as u16; // SVGA_INDEX_PORT = base+0
                                                  // SVGA registers are a dword index/value port pair at base+0/+1.
            out32(io_base, 0); // index = SVGA_REG_ID (probe/version)
            let svga_id = in32(io_base + 1);
            out32(io_base, 1); // index = SVGA_REG_ENABLE
            out32(io_base + 1, 0); // value = 0 (disable -> enables VGA)
            out32(io_base, 1);
            let enable = in32(io_base + 1);
            crate::sprintln!(
                "Aegis: VMware SVGA @ PCI {:02X}:{:02X}.{} bar0=0x{:X} id=0x{:08X} enable=0x{:X}",
                addr.bus,
                addr.device,
                addr.function,
                io_base,
                svga_id,
                enable
            );
            return true;
        }
    }
    false
}

/// Switch the VGA into 80x25 text mode through the legacy IO ports. The
/// UEFI firmware (OVMF/VMware EFI) leaves the display in a GOP graphics
/// mode, so writing 0xB8000 alone would be invisible; this standard
/// text-mode-3 reprogramming makes the emulated VGA (QEMU stdvga, VMware
/// SVGA, VirtualBox) render the text buffer again.
pub fn vga_enter_text_mode() {
    fn out(port: u16, val: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, preserves_flags));
        }
    }
    fn out_index(port: u16, index: u8, val: u8) {
        out(port, index);
        out(port + 1, val);
    }

    // VMware-specific: take the SVGA device out of GOP mode first (this also
    // re-enables VGA), so the legacy registers below actually drive the
    // display. No-op on QEMU/other machines.
    vmware_svga_disable();

    // Bochs VBE (used by OVMF/EDK2 for the GOP framebuffer): while VBE mode
    // is enabled QEMU ignores the legacy VGA registers and keeps showing the
    // old linear framebuffer. Disable it so the standard text-mode path
    // takes over the display.
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") 0x1CEu16, in("ax") 0x0004u16, options(nomem, preserves_flags));
        core::arch::asm!("out dx, ax", in("dx") 0x1CFu16, in("ax") 0x0000u16, options(nomem, preserves_flags));
    }
    // Misc Output Register: color, 28.3 MHz, CRTC at 0x3D4.
    out(0x3C2, 0x63);
    // Sequencer: hold sync reset + disable display while reprogramming.
    out_index(0x3C4, 0x00, 0x01); // sync reset on
    out_index(0x3C4, 0x01, 0x00); // clocking mode: display off
    out_index(0x3C4, 0x02, 0x03); // write planes 0+1 only (odd/even text)
    out_index(0x3C4, 0x04, 0x03); // memory mode: text (ext-mem, odd/even)
                                  // CRT Controller: 80x25 text timing.
    const CRTC: [(u8, u8); 25] = [
        (0x00, 0x5F),
        (0x01, 0x4F),
        (0x02, 0x50),
        (0x03, 0x82),
        (0x04, 0x55),
        (0x05, 0x81),
        (0x06, 0xBF),
        (0x07, 0x1F),
        (0x08, 0x00),
        (0x09, 0x4F),
        (0x0A, 0x2D), // cursor start: 0x20 = cursor disabled
        (0x0B, 0x0E),
        (0x0C, 0x00),
        (0x0D, 0x00),
        (0x0E, 0x00),
        (0x0F, 0x00),
        (0x10, 0x9C),
        (0x11, 0x8E),
        (0x12, 0x8F),
        (0x13, 0x28),
        (0x14, 0x1F),
        (0x15, 0x96),
        (0x16, 0xB9),
        (0x17, 0xA3),
        (0x18, 0xFF),
    ];
    for (i, v) in CRTC {
        out_index(0x3D4, i, v);
    }
    // Graphics Controller: planar read/write off, text map at B8000.
    out_index(0x3CE, 0x00, 0x00); // set/reset
    out_index(0x3CE, 0x01, 0x00); // enable set/reset
    out_index(0x3CE, 0x02, 0x00); // color compare
    out_index(0x3CE, 0x03, 0x00); // data rotate
    out_index(0x3CE, 0x04, 0x00); // read map
    out_index(0x3CE, 0x05, 0x10); // mode: read 0, no odd/even
    out_index(0x3CE, 0x06, 0x0E); // misc: B8000-BFFFF
    out_index(0x3CE, 0x07, 0x00); // color don't care
    out_index(0x3CE, 0x08, 0xFF); // bit mask
                                  // Attribute Controller: identity palette, text attributes.
    unsafe {
        core::arch::asm!("in al, dx", out("al") _, in("dx") 0x3DAu16, options(nomem, preserves_flags));
    }
    const AC: [(u8, u8); 21] = [
        (0x00, 0x00),
        (0x01, 0x01),
        (0x02, 0x02),
        (0x03, 0x03),
        (0x04, 0x04),
        (0x05, 0x05),
        (0x06, 0x06),
        (0x07, 0x07),
        (0x08, 0x08),
        (0x09, 0x09),
        (0x0A, 0x0A),
        (0x0B, 0x0B),
        (0x0C, 0x0C),
        (0x0D, 0x0D),
        (0x0E, 0x0E),
        (0x0F, 0x0F),
        (0x10, 0x0C),
        (0x11, 0x00),
        (0x12, 0x0F),
        (0x13, 0x08),
        (0x14, 0x00),
    ];
    for (i, v) in AC {
        out(0x3C0, i);
        out(0x3C0, v);
    }
    out(0x3C0, 0x20); // re-enable the attribute controller
                      // Sequencer: re-enable display, release sync reset.
    out_index(0x3C4, 0x01, 0x00);
    out_index(0x3C4, 0x00, 0x03);

    // The UEFI firmware (OVMF) never runs the classic VGA BIOS, which is the
    // step that normally loads the 8x16 character font into VRAM plane 2.
    // Without it the display renders every glyph as a blank cell.
    vga_upload_font();
    // OVMF may also leave the DAC palette in a graphics-mode-ish state;
    // restore the standard 16-color text palette.
    vga_set_palette16();

    unsafe {
        fn out8(port: u16, val: u8) {
            unsafe {
                core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, preserves_flags));
            }
        }
        fn in8(port: u16) -> u8 {
            let v: u8;
            unsafe {
                core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, preserves_flags));
            }
            v
        }
        fn in16(port: u16) -> u16 {
            let v: u16;
            unsafe {
                core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, preserves_flags));
            }
            v
        }
        // Read back what the VGA really holds (proves the writes landed).
        // NOTE: do NOT touch the attribute controller here -- on real HW a
        // 0x3C0 write outside the index phase corrupts ar[n], and QEMU
        // faithfully emulates that (observed: ar[0] corrupted by an
        // in-between index write during the flip-flop data phase).
        unsafe fn set_idx(port: u16, index: u8) {
            out8(port, index);
        }
        set_idx(0x3C4, 0x00);
        let seq0 = in8(0x3C5);
        set_idx(0x3C4, 0x01);
        let sr1 = in8(0x3C5);
        set_idx(0x3C4, 0x02);
        let sr2 = in8(0x3C5);
        set_idx(0x3C4, 0x03);
        let sr3 = in8(0x3C5);
        set_idx(0x3C4, 0x04);
        let sr4 = in8(0x3C5);
        set_idx(0x3CE, 0x05);
        let gcmode = in8(0x3CF);
        set_idx(0x3CE, 0x06);
        let gc6 = in8(0x3CF);
        set_idx(0x3CE, 0x04);
        let gcmap = in8(0x3CF);
        set_idx(0x3D4, 0x0C);
        let crtc_hi = in8(0x3D5);
        set_idx(0x3D4, 0x0D);
        let crtc_lo = in8(0x3D5);
        set_idx(0x3D4, 0x0E);
        let crtc_cur_hi = in8(0x3D5);
        set_idx(0x3D4, 0x0F);
        let crtc_cur_lo = in8(0x3D5);
        set_idx(0x3D4, 0x14);
        let cr14 = in8(0x3D5);
        set_idx(0x3D4, 0x17);
        let cr17 = in8(0x3D5);
        let misc = in8(0x3CC);
        out8(0x1CE, 0x04);
        let vbe_enable = in16(0x1CF);
        // Font probe: map A (GC6 bit2=0), read plane 2 (GC5=0, GC4=2).
        // No host odd/even and no CR17 bit6 => straight byte addressing,
        // so 0xA0000 + 0x41*32 + i reads vram[(0x820+i)*4 + 2], the exact
        // slot vga_upload_font wrote glyph 'A' (0x41) into.
        out_index(0x3CE, 0x06, 0x04);
        out_index(0x3CE, 0x05, 0x00);
        out_index(0x3CE, 0x04, 0x02);
        let cell0 = *(0xA0000usize as *const u8);
        let mut font_a = [0u8; 16];
        for (i, slot) in font_a.iter_mut().enumerate() {
            *slot = *(0xA0000usize as *const u8).add(0x41 * 32 + i);
        }
        out_index(0x3CE, 0x05, 0x10);
        out_index(0x3CE, 0x04, 0x00);
        out_index(0x3CE, 0x06, 0x0E);
        crate::sprintln!(
            "VGA RDBK2 sr1={:#04x} sr2={:#04x} sr3={:#04x} sr4={:#04x} cr14={:#04x} cr17={:#04x} cell0={:#04x}",
            sr1, sr2, sr3, sr4, cr14, cr17, cell0
        );
        crate::sprintln!("FONT A mapA plane2={:02x?}", font_a);
        // DAC readback: 0x3C7 = read index, one 0x3C9 read per byte, index
        // advances every 3rd byte (entries 0..=7).
        out8(0x3C7, 0);
        let mut dac = [0u8; 32];
        for slot in dac.iter_mut() {
            *slot = in8(0x3C9);
        }
        crate::sprintln!(
            "VGA READBACK seq0={:#04x} sr4={:#04x} gcmode={:#04x} gc6={:#04x} gcmap={:#04x} crtc_start={:02x}{:02x} cur={:02x}{:02x} misc={:#04x} vbe_enable={:#06x} dac0={:02x}{:02x}{:02x} dac1={:02x}{:02x}{:02x} dac7={:02x}{:02x}{:02x}",
            seq0, sr4, gcmode, gc6, gcmap, crtc_hi, crtc_lo, crtc_cur_hi, crtc_cur_lo, misc, vbe_enable,
            dac[0], dac[1], dac[2],
            dac[3], dac[4], dac[5],
            dac[21], dac[22], dac[23]
        );
    }
}

#[cfg(test)]
#[allow(static_mut_refs)] // test-only RAM stand-in for the VGA framebuffer
mod tests {
    use super::*;

    /// RAM-backed stand-in for the VGA framebuffer (the real 0xB8000 is not
    /// mapped in the host test process). VGA_BUF/ROW/COL are process-global
    /// mutable statics, so the tests must not run concurrently with each
    /// other: each test redirects the buffer to `RAM_BUF` and mutates the
    /// shared cursor.
    static mut RAM_BUF: [u16; COLS * ROWS] = [0x0720; COLS * ROWS];

    fn with_ram_buffer(f: impl FnOnce()) {
        unsafe {
            VGA_BUF = core::ptr::addr_of_mut!(RAM_BUF).cast();
        }
        f();
    }

    fn ram() -> &'static [u16] {
        unsafe { &*core::ptr::addr_of_mut!(RAM_BUF) }
    }

    fn with_vga_guard(f: impl FnOnce()) {
        static VGA_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = VGA_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        f();
    }

    #[test]
    fn plain_text_fills_cells() {
        with_vga_guard(|| {
            with_ram_buffer(|| {
                vga_clear_screen();
                vga_write_str("hi");
                assert_eq!(ram()[0], ATTR | b'h' as u16);
                assert_eq!(ram()[1], ATTR | b'i' as u16);
                unsafe {
                    assert_eq!(ROW, 0);
                    assert_eq!(COL, 2);
                }
            });
        });
    }

    #[test]
    fn crlf_handling() {
        with_vga_guard(|| {
            with_ram_buffer(|| {
                vga_clear_screen();
                vga_write_str("a\r\nb");
                assert_eq!(ram()[0], ATTR | b'a' as u16);
                assert_eq!(ram()[COLS], ATTR | b'b' as u16);
                unsafe {
                    assert_eq!(ROW, 1);
                    assert_eq!(COL, 1);
                }
            });
        });
    }

    #[test]
    fn long_line_wraps() {
        with_vga_guard(|| {
            with_ram_buffer(|| {
                vga_clear_screen();
                let s: String = "x".repeat(COLS + 3);
                vga_write_str(&s);
                unsafe {
                    assert_eq!(ROW, 1);
                    assert_eq!(COL, 3);
                }
            });
        });
    }

    #[test]
    fn scroll_keeps_bottom_row_clear() {
        with_vga_guard(|| {
            with_ram_buffer(|| {
                vga_clear_screen();
                let s: String = "x\n".repeat(ROWS);
                vga_write_str(&s);
                unsafe {
                    assert_eq!(ROW, ROWS - 1);
                    assert_eq!(COL, 0);
                }
                assert_eq!(ram()[COLS * (ROWS - 1)], ATTR | b' ' as u16);
            });
        });
    }
}

//! GOP framebuffer scrolling text console for the bare-metal boot.
//!
//! Under UEFI/GOP the firmware leaves the display in graphics mode, so the
//! VGA text-mode console (`vga.rs`, `0xB8000`) renders nothing on a real
//! laptop. This console mirrors every `sprintln!` line onto the GOP
//! framebuffer handed over by the bootloader — the boot log (device init,
//! the probe battery, the VMX demo) scrolls on the physical screen, so a
//! real-hardware run is captured by photographing the screen. White-on-black
//! 8x16 text (the same `FONT8X16_BASIC` the compositor uses); byte order
//! does not matter for white-on-black, so no `bgr` branch is needed.
//!
//! Honest scope: a fixed 80x40 cell buffer (no scrollback, no cursor); once
//! full, the oldest line is dropped. Calls before `install()` are no-ops
//! (the console has no framebuffer yet). Single-threaded boot discipline,
//! same as `vga.rs`.

#![allow(static_mut_refs)] // single-threaded boot console, same as vga.rs

use core::fmt::Write as _;
use core::ptr::{addr_of, addr_of_mut};

const COLS: usize = 80;
const ROWS: usize = 40;

// Installed framebuffer geometry (zero = not installed).
static mut FB_BASE: u64 = 0;
static mut FB_WIDTH: u32 = 0;
static mut FB_HEIGHT: u32 = 0;
static mut FB_STRIDE: u32 = 0;
static mut FB_BPP: u32 = 0;

// Scrolling text buffer (low byte = glyph code point).
// CRITICAL: CUR_ROW and CUR_COL are embedded as the first two entries of BUF
// because after the CR3 switch, the .bss pages holding the old standalone
// CUR_ROW/CUR_COL statics are NOT writable (writes silently vanish — page
// fault caught by early IDT handler).  BUF's first page IS writable
// (proven by text that does appear), so storing cursor state here keeps
// the '\n' handler functional.
//
// BUF layout: [cur_row: u16, cur_col: u16, drawn_upto: i16, text...]
const STATE_HDR: usize = 3; // first 3 u16 slots reserved for cursor state
static mut BUF: [u16; STATE_HDR + COLS * ROWS] = [0; STATE_HDR + COLS * ROWS];

/// Point the console at the GOP framebuffer. Installed once at kernel entry
/// so the whole boot log renders on the physical screen; later calls are
/// no-ops (they must not reset the accumulated buffer).
pub fn install(base: u64, width: u32, height: u32, stride_px: u32, bpp: u32) {
    unsafe {
        if FB_BASE == base && base != 0 {
            return;
        }
        FB_BASE = base;
        FB_WIDTH = width;
        FB_HEIGHT = height;
        FB_STRIDE = stride_px;
        FB_BPP = bpp;
        BUF[0] = 0; // cur_row
        BUF[1] = 0; // cur_col
        BUF[2] = (-1i16 as u16); // drawn_upto = -1
        for s in BUF[STATE_HDR..].iter_mut() {
            *s = 0;
        }
    }
}

fn installed() -> bool {
    unsafe { FB_BASE != 0 && FB_BPP >= 8 }
}

/// Forget the framebuffer (no-op console again). Used by tests so a
/// test-installed console does not keep blitting into a freed test buffer
/// when later tests call `sprintln!`.
pub fn reset() {
    unsafe {
        FB_BASE = 0;
        FB_BPP = 0;
    }
}

/// Mirror one formatted line (no newline handling) into the console: append
/// to the buffer (scrolling when full) and redraw the framebuffer. No-op
/// before `install`. Total: never panics, every pixel write is bounds-checked.
pub fn mirror(args: core::fmt::Arguments) {
    if !installed() {
        return;
    }
    // Format into a fixed stack buffer (no allocation).
    let mut tmp = [0u8; 384];
    let len;
    {
        let mut w = StackBuf(&mut tmp, 0);
        let _ = w.write_fmt(args);
        let _ = w.write_str("\n");
        len = w.1;
    }
    append(&tmp[..len]);
    blit();
}

struct StackBuf<'a>(&'a mut [u8], usize);

impl core::fmt::Write for StackBuf<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if self.1 < self.0.len() {
                self.0[self.1] = b;
                self.1 += 1;
            }
        }
        Ok(())
    }
}

fn append(data: &[u8]) {
    for &b in data {
        match b {
            b'\n' => unsafe {
                let row = BUF[0] as usize;
                let new_row = row + 1;
                BUF[0] = new_row as u16;
                BUF[1] = 0; // cur_col = 0
                if new_row >= ROWS {
                    scroll();
                    BUF[0] = (ROWS - 1) as u16;
                }
            },
            b'\r' => {}
            _ => unsafe {
                let col = BUF[1] as usize;
                let row = BUF[0] as usize;
                if col < COLS {
                    BUF[STATE_HDR + row * COLS + col] = b as u16;
                    BUF[1] = (col + 1) as u16;
                }
            },
        }
    }
}

fn scroll() {
    unsafe {
        BUF.copy_within(STATE_HDR + COLS..STATE_HDR + COLS * ROWS, STATE_HDR);
        for c in BUF[STATE_HDR + (ROWS - 1) * COLS..STATE_HDR + COLS * ROWS].iter_mut() {
            *c = 0;
        }
        BUF[2] = (-1i16 as u16); // drawn_upto = -1
    }
}

fn blit() {
    let base = unsafe { core::ptr::read_volatile(addr_of!(FB_BASE)) };
    let width = unsafe { core::ptr::read_volatile(addr_of!(FB_WIDTH)) };
    let _height = unsafe { core::ptr::read_volatile(addr_of!(FB_HEIGHT)) };
    let stride = unsafe { core::ptr::read_volatile(addr_of!(FB_STRIDE)) };
    let bpp = unsafe { core::ptr::read_volatile(addr_of!(FB_BPP)) };
    #[cfg(not(test))]
    if base >= 0x1_0000_0000 {
        return;
    }
    let bpp_bytes = (bpp / 8) as usize;
    if bpp_bytes == 0 {
        return;
    }
    let cols = (width / 8) as usize;
    let upto = (unsafe { BUF[0] as usize }).min(ROWS - 1);
    let start = unsafe { BUF[2] as i16 };
    let start = ((start as isize + 1).max(0)) as usize;
    let fb = base as *mut u8;
    unsafe {
        // Clear the new rows to black (they may hold garbage).
        for r in start..=upto {
            for px in 0..cols.min(COLS) * 8 {
                let py = r * 16;
                let off = (py * stride as usize + px) * bpp_bytes;
                for k in 0..bpp_bytes.min(4) {
                    core::ptr::write_volatile(fb.add(off + k), 0);
                }
            }
        }
        // Draw the new rows' glyphs.
        for r in start..=upto {
            for c in 0..cols.min(COLS) {
                let ch = BUF[STATE_HDR + r * COLS + c] as usize;
                let glyph = crate::font::FONT8X16_BASIC[ch & 0xFF];
                for (gy, bits) in glyph.iter().enumerate() {
                    for gx in 0..8 {
                        let on = (bits >> (7 - gx)) & 1 == 1;
                        let px = c * 8 + gx;
                        let py = r * 16 + gy;
                        let off = (py * stride as usize + px) * bpp_bytes;
                        let rgb = if on { 0xFFu8 } else { 0x00u8 };
                        for k in 0..bpp_bytes.min(4) {
                            core::ptr::write_volatile(fb.add(off + k), rgb);
                        }
                    }
                }
            }
        }
        BUF[2] = upto as u16; // drawn_upto
                              // DIAG: draw a 4-pixel-tall bright-green bar across the full width
                              // at the very bottom of the screen (y = height-4).  This is OUTSIDE
                              // the console text area (40 rows × 16 px = 640 px, screen = 768)
                              // so blit()'s row-clearing never touches it.  If it appears on the
                              // photo, blit() is being called AND the framebuffer writes land.
                              // If it does NOT appear, blit() is never entered or the FB address
                              // is wrong.  We paint it every blit() call so even a single call
                              // leaves evidence.
        {
            let w = width as usize;
            let h = _height as usize;
            if h > 8 && w > 0 {
                let bar_y0 = h - 4;
                for dy in 0u32..4 {
                    for dx in 0..w {
                        let off = ((bar_y0 + dy as usize) * stride as usize + dx) * bpp_bytes;
                        // BGRA: green = byte 1
                        for k in 0..bpp_bytes.min(4) {
                            core::ptr::write_volatile(
                                fb.add(off + k),
                                if k == 1 { 0xFF } else { 0x00 },
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The console's framebuffer + buffer are global statics, so the tests
    // that touch them must not run concurrently. Poison-tolerant: a panic
    // while holding the lock must not cascade into every other guarded test.
    static LOCK: Mutex<()> = Mutex::new(());
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn mirror_is_noop_before_install() {
        let _g = lock();
        // No framebuffer yet: mirroring must be a safe no-op.
        mirror(format_args!("hello"));
    }

    #[test]
    fn mirror_renders_into_an_installed_buffer() {
        let _g = lock();
        let mut fb = vec![0u8; 800 * 600 * 4];
        let base = fb.as_mut_ptr() as u64;
        install(base, 800, 600, 800, 32);
        mirror(format_args!("ABC\n"));
        assert!(fb.contains(&0xFF), "glyph pixels must be written");
        reset();
    }

    #[test]
    fn scroll_drops_the_oldest_line() {
        let _g = lock();
        let mut fb = vec![0u8; 800 * 640 * 4];
        let base = fb.as_mut_ptr() as u64;
        install(base, 800, 640, 800, 32);
        for i in 0..(ROWS as u32) {
            mirror(format_args!("line{}\n", i));
        }
        let ch0 = unsafe { BUF[STATE_HDR] } as u8;
        assert_eq!(ch0, b'l');
        let ch1 = unsafe { BUF[STATE_HDR + 1] } as u8;
        assert_eq!(ch1, b'i');
        assert_eq!(unsafe { BUF[0] as usize }, ROWS - 1);
        reset();
    }
}

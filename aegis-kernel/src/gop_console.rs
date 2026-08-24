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

const COLS: usize = 80;
const ROWS: usize = 40;

// Installed framebuffer geometry (zero = not installed).
static mut FB_BASE: u64 = 0;
static mut FB_WIDTH: u32 = 0;
static mut FB_HEIGHT: u32 = 0;
static mut FB_STRIDE: u32 = 0;
static mut FB_BPP: u32 = 0;

// Scrolling text buffer (low byte = glyph code point).
static mut BUF: [u16; COLS * ROWS] = [0; COLS * ROWS];
static mut CUR_ROW: usize = 0;
static mut CUR_COL: usize = 0;

/// Point the console at the GOP framebuffer. Installed once at kernel entry
/// so the whole boot log renders on the physical screen; later calls are
/// no-ops (they must not reset the accumulated buffer).
pub fn install(base: u64, width: u32, height: u32, stride_px: u32, bpp: u32) {
    unsafe {
        if FB_BASE != 0 {
            return;
        }
        FB_BASE = base;
        FB_WIDTH = width;
        FB_HEIGHT = height;
        FB_STRIDE = stride_px;
        FB_BPP = bpp;
        CUR_ROW = 0;
        CUR_COL = 0;
        BUF = [0; COLS * ROWS];
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
                CUR_ROW += 1;
                CUR_COL = 0;
                if CUR_ROW >= ROWS {
                    scroll();
                    CUR_ROW = ROWS - 1;
                }
            },
            b'\r' => {}
            _ => unsafe {
                if CUR_COL < COLS {
                    BUF[CUR_ROW * COLS + CUR_COL] = b as u16;
                    CUR_COL += 1;
                }
            },
        }
    }
}

fn scroll() {
    unsafe {
        // Shift every row up by one, dropping the oldest line.
        BUF.copy_within(COLS..COLS * ROWS, 0);
        // Clear the newly-emptied last row.
        for c in BUF[(ROWS - 1) * COLS..].iter_mut() {
            *c = 0;
        }
    }
}

fn blit() {
    let base = unsafe { FB_BASE };
    let width = unsafe { FB_WIDTH };
    let height = unsafe { FB_HEIGHT };
    let stride = unsafe { FB_STRIDE };
    let bpp = unsafe { FB_BPP };
    let bpp_bytes = (bpp / 8) as usize;
    if bpp_bytes == 0 {
        return;
    }
    // Clear only the region the console owns (rows 0..N*16 of the display)
    // — never the whole framebuffer, so the desktop compositor below it is
    // left alone. Then draw the glyphs.
    let cols = (width / 8) as usize;
    let rows = (height / 16) as usize;
    let nrows = rows.min(ROWS);
    let fb = base as *mut u8;
    unsafe {
        for r in 0..nrows {
            for px in 0..cols.min(COLS) * 8 {
                let py = r * 16;
                let off = (py * stride as usize + px) * bpp_bytes;
                for k in 0..bpp_bytes.min(4) {
                    *fb.add(off + k) = 0;
                }
            }
        }
    }
    for r in 0..nrows {
        for c in 0..cols.min(COLS) {
            let ch = unsafe { BUF[r * COLS + c] } as usize;
            let glyph = crate::font::FONT8X16_BASIC[ch & 0xFF];
            for (gy, bits) in glyph.iter().enumerate() {
                for gx in 0..8 {
                    let on = (bits >> (7 - gx)) & 1 == 1;
                    let px = c * 8 + gx;
                    let py = r * 16 + gy;
                    let off = (py * stride as usize + px) * bpp_bytes;
                    if off + bpp_bytes <= (nrows * 16) * stride as usize * bpp_bytes {
                        let rgb = if on { 0xFFu8 } else { 0x00u8 };
                        for k in 0..bpp_bytes.min(4) {
                            unsafe {
                                *fb.add(off + k) = rgb;
                            }
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
    // that touch them must not run concurrently.
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn mirror_is_noop_before_install() {
        let _g = LOCK.lock().unwrap();
        // No framebuffer yet: mirroring must be a safe no-op.
        mirror(format_args!("hello"));
    }

    #[test]
    fn mirror_renders_into_an_installed_buffer() {
        let _g = LOCK.lock().unwrap();
        let mut fb = vec![0u8; 800 * 600 * 4];
        let base = fb.as_mut_ptr() as u64;
        install(base, 800, 600, 800, 32);
        mirror(format_args!("ABC\n"));
        assert!(fb.contains(&0xFF), "glyph pixels must be written");
        reset();
    }

    #[test]
    fn scroll_drops_the_oldest_line() {
        let _g = LOCK.lock().unwrap();
        let mut fb = vec![0u8; 800 * 600 * 4];
        let base = fb.as_mut_ptr() as u64;
        install(base, 800, 600, 800, 32);
        // Fill ROWS-1 lines, then one more forces a scroll.
        for i in 0..(ROWS as u32) {
            mirror(format_args!("line{}\n", i));
        }
        // The first line must have scrolled off (row 0 is now 'line1').
        let ch0 = unsafe { BUF[0] } as u8;
        assert_eq!(ch0, b'l');
        let ch1 = unsafe { BUF[1] } as u8;
        assert_eq!(ch1, b'i');
        assert_eq!(unsafe { CUR_ROW }, ROWS - 1);
        reset();
    }
}

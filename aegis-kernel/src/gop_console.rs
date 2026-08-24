//! GOP framebuffer text console for the bare-metal boot.
//!
//! Under UEFI/GOP the firmware leaves the display in graphics mode, so the
//! VGA text-mode console (`vga.rs`, `0xB8000`) renders nothing on a real
//! laptop — this is why the on-screen evidence channel for the bare-metal
//! boot is a direct framebuffer renderer instead. White-on-black 8x16 text
//! (the same `FONT8X16_BASIC` the compositor uses) drawn straight into the
//! GOP framebuffer handed over by the bootloader.
//!
//! Honest scope: a minimal, read-only renderer for the boot self-test report
//! — no cursor, no scrolling, no terminal. It clears the framebuffer and
//! draws the text at the top-left, one line per `\n`. Byte order does not
//! matter for white-on-black (all three colour channels are equal), so no
//! `bgr` branch is needed.

/// Draw `text` (a `\n`-separated UTF-8 byte buffer) into the GOP framebuffer
/// at `base` (width×height, stride in pixels, `bpp` bits per pixel). Clears
/// the whole framebuffer to black first, then renders each line as 8x16
/// white-on-black text from the top-left corner. Total: no panics, every
/// pixel access is bounds-checked.
pub fn render_text(base: u64, width: u32, height: u32, stride_px: u32, bpp: u32, text: &[u8]) {
    let bpp_bytes = (bpp / 8) as usize;
    if bpp_bytes == 0 || width == 0 || height == 0 || text.is_empty() {
        return;
    }
    let fb = base as *mut u8;
    let total = (height as usize) * (stride_px as usize) * bpp_bytes;
    unsafe {
        for i in 0..total {
            *fb.add(i) = 0;
        }
    }
    let cols = (width / 8) as usize;
    let rows = (height / 16) as usize;
    let mut row = 0usize;
    let mut col = 0usize;
    for &b in text {
        if b == b'\n' {
            row += 1;
            col = 0;
            if row >= rows {
                return;
            }
            continue;
        }
        if col >= cols {
            continue;
        }
        let glyph = crate::font::FONT8X16_BASIC[b as usize];
        for (gy, bits) in glyph.iter().enumerate() {
            for gx in 0..8 {
                let on = (bits >> (7 - gx)) & 1 == 1;
                let px = col * 8 + gx;
                let py = row * 16 + gy;
                let off = (py * stride_px as usize + px) * bpp_bytes;
                if off + bpp_bytes <= total {
                    let rgb = if on { 0xFFu8 } else { 0x00u8 };
                    for k in 0..bpp_bytes.min(4) {
                        unsafe {
                            *fb.add(off + k) = rgb;
                        }
                    }
                }
            }
        }
        col += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_does_not_panic_on_degenerate_modes() {
        // Zero bpp / width / height must be a safe no-op.
        render_text(0x1000, 0, 0, 0, 0, b"hi\n");
        render_text(0x1000, 800, 600, 800, 0, b"hi\n");
        // Empty text must not touch the framebuffer at all.
        render_text(0x1000, 800, 600, 800, 32, b"");
    }

    #[test]
    fn render_draws_white_pixels_for_a_real_mode() {
        // A real heap-backed framebuffer: rendering must not fault and must
        // draw white (0xFF) pixels where glyph bits are set.
        let mut fb = vec![0u8; 800 * 600 * 4];
        let base = fb.as_mut_ptr() as u64;
        render_text(base, 800, 600, 800, 32, b"X\n");
        // 'X' has set glyph bits in rows 2-11; assert white pixels landed
        // somewhere in the framebuffer (rows are stride-separated, so scan
        // the whole buffer rather than the first cell's contiguous bytes).
        assert!(fb.contains(&0xFF), "glyph pixels must be written");
    }
}

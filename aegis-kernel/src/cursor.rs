//! Fixed arrow cursor sprite (Phase N) drawn into the GPU framebuffer on
//! top of the composited cell screen. The sprite is a 12x16 arrow pointing
//! up-left: rows 0..=11 fan out from the tip at (0,0) to full width, rows
//! 12..=15 form a short tail, all in white (0xFF,0xFF,0xFF,0xFF BGRX8888).
//!
//! `draw_cursor` is total: it clamps every pixel to the mode's bounds and
//! guards the byte offset against the framebuffer length, so it never
//! panics and never writes out of bounds — the same discipline as
//! `gpu_compositor::blit_cells`. `cursor_bounds` is the pure geometry
//! helper the tests use to reason about that clamping.

use crate::gpu::Mode;

/// Sprite width in pixels. Bits 11..0 of each `CURSOR_BITMAP` row are
/// used, MSB-first: bit 11 is the leftmost pixel of that scanline.
pub const CURSOR_W: usize = 12;
/// Sprite height in pixels (16 rows).
pub const CURSOR_H: usize = 16;

/// The 12-bit-wide arrow bitmap, one row per entry (bits 11..0 used, bit 11
/// = leftmost pixel). Twelve bits do not fit a `u8`, so each row is a `u16`
/// despite `CURSOR_H` entries. Rows 0..=11 are the up-left diagonal fanning
/// from a one-pixel tip to full width (`0b1000_0000_0000` with `r+1` set
/// bits); rows 12..=15 form the short down-right tail
/// (`0b1111_1100_0000`, `0b1110_1100_0000`, `0b1100_0110_0000`,
/// `0b1000_0110_0000`).
pub const CURSOR_BITMAP: [u16; CURSOR_H] = [
    0b1000_0000_0000, // row 0:  tip (1 bit)
    0b1100_0000_0000, // row 1
    0b1110_0000_0000, // row 2
    0b1111_0000_0000, // row 3
    0b1111_1000_0000, // row 4
    0b1111_1100_0000, // row 5
    0b1111_1110_0000, // row 6
    0b1111_1111_0000, // row 7
    0b1111_1111_1000, // row 8
    0b1111_1111_1100, // row 9
    0b1111_1111_1110, // row 10
    0b1111_1111_1111, // row 11: full width
    0b1111_1100_0000, // row 12: tail
    0b1110_1100_0000, // row 13
    0b1100_0110_0000, // row 14
    0b1000_0110_0000, // row 15
];

/// Draw the white arrow sprite with its top-left corner at pixel `(x, y)`
/// of `fb` (BGRX8888), clamping each pixel to the mode's bounds and
/// guarding every byte write against the framebuffer length. Total: never
/// panics, never writes out of bounds.
pub fn draw_cursor(fb: &mut [u8], mode: &Mode, x: i16, y: i16) {
    let bpp = (mode.bpp / 8) as usize;
    if bpp == 0 {
        return;
    }
    for (r, &row_bits) in CURSOR_BITMAP.iter().enumerate() {
        let py = y as i64 + r as i64;
        if py < 0 || py >= mode.height as i64 {
            continue;
        }
        let row_base = py as usize * mode.pitch;
        for c in 0..CURSOR_W {
            let px = x as i64 + c as i64;
            if px < 0 || px >= mode.width as i64 {
                continue;
            }
            // MSB-first: bit 11 of each row is the leftmost pixel.
            if (row_bits >> (CURSOR_W - 1 - c)) & 1 != 0 {
                let offset = row_base + px as usize * bpp;
                if offset + bpp > fb.len() {
                    continue;
                }
                // BGRX8888: the byte layout gpu_compositor also writes.
                fb[offset] = 0xFF; // B
                fb[offset + 1] = 0xFF; // G
                fb[offset + 2] = 0xFF; // R
                if bpp > 3 {
                    fb[offset + 3] = 0xFF; // X / alpha
                }
            }
        }
    }
}

/// The sprite's clamped in-bounds rectangle `(x0, y0, x1, y1)` within a
/// `w` x `h` framebuffer (x1/y1 exclusive). Pure geometry: `x0`/`y0` are
/// the first in-bounds row/column, `x1`/`y1` one past the last; when the
/// sprite is fully off-screen the rect is empty (`x1 <= x0` or `y1 <= y0`).
pub fn cursor_bounds(x: i16, y: i16, w: u32, h: u32) -> (i16, i16, i16, i16) {
    let (w, h) = (w as i32, h as i32);
    let x0 = (x as i32).clamp(0, w);
    let y0 = (y as i32).clamp(0, h);
    let x1 = (x as i32 + CURSOR_W as i32).clamp(x0, w);
    let y1 = (y as i32 + CURSOR_H as i32).clamp(y0, h);
    (x0 as i16, y0 as i16, x1 as i16, y1 as i16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn px(fb: &[u8], mode: &Mode, x: usize, y: usize) -> [u8; 4] {
        let bpp = (mode.bpp / 8) as usize;
        let o = y * mode.pitch + x * bpp;
        [fb[o], fb[o + 1], fb[o + 2], fb[o + 3]]
    }

    #[test]
    fn draw_at_origin_paints_tip() {
        let mode = Mode {
            width: 16,
            height: 16,
            bpp: 32,
            pitch: 16 * 4,
            bgr: true,
        };
        let mut buf = vec![0xABu8; 16 * 16 * 4];
        draw_cursor(&mut buf, &mode, 0, 0);
        // Tip (row 0, one bit) and row 1 (two bits) are white.
        assert_eq!(px(&buf, &mode, 0, 0), [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(px(&buf, &mode, 0, 1), [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(px(&buf, &mode, 1, 1), [0xFF, 0xFF, 0xFF, 0xFF]);
        // Row 15's tail (0b1000_0110_0000) has no column-11 bit: (11,15)
        // is outside the sprite and stays untouched.
        assert_eq!(px(&buf, &mode, 11, 15), [0xAB, 0xAB, 0xAB, 0xAB]);
    }

    #[test]
    fn draw_at_negative_position_is_safe() {
        let mode = Mode {
            width: 16,
            height: 16,
            bpp: 32,
            pitch: 16 * 4,
            bgr: true,
        };
        let mut buf = vec![0xABu8; 16 * 16 * 4];
        draw_cursor(&mut buf, &mode, -5, -5); // must not panic
                                              // The sprite at (-5,-5) partially overlaps the 16x16 mode (its
                                              // in-bounds rect is (0,0,7,11) — see cursor_bounds). Nothing
                                              // outside that rect may be touched: no out-of-bounds writes.
        for y in 11..16 {
            for x in 7..16 {
                assert_eq!(px(&buf, &mode, x, y), [0xAB, 0xAB, 0xAB, 0xAB]);
            }
        }
        // The overlapping part of the tip is painted (sprite col 5, row 5
        // -> fb pixel (0,0), a bitmap bit that is set) — the draw was not
        // skipped, just clamped.
        assert_eq!(px(&buf, &mode, 0, 0), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn draw_at_bottom_right_edge_is_safe() {
        let mode = Mode {
            width: 800,
            height: 600,
            bpp: 32,
            pitch: 800 * 4,
            bgr: true,
        };
        let mut buf = vec![0xABu8; 800 * 600 * 4];
        draw_cursor(&mut buf, &mode, 795, 595); // must not panic
        assert_eq!(buf.len(), 800 * 600 * 4); // length unchanged
                                              // In-bounds covered pixels are white where the bitmap has bits:
                                              // row 0 col 0 (795,595) and row 4 col 4 (799,599).
        assert_eq!(px(&buf, &mode, 795, 595), [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(px(&buf, &mode, 799, 599), [0xFF, 0xFF, 0xFF, 0xFF]);
        // A pixel the sprite cannot reach stays untouched.
        assert_eq!(px(&buf, &mode, 0, 599), [0xAB, 0xAB, 0xAB, 0xAB]);
    }

    #[test]
    fn draw_fully_offscreen_is_safe() {
        let mode = Mode {
            width: 16,
            height: 16,
            bpp: 32,
            pitch: 16 * 4,
            bgr: true,
        };
        let mut buf = vec![0xABu8; 16 * 16 * 4];
        draw_cursor(&mut buf, &mode, -100, -100); // must not panic
        draw_cursor(&mut buf, &mode, 200, 200); // must not panic
        assert!(buf.iter().all(|&b| b == 0xAB)); // untouched
    }

    #[test]
    fn cursor_bounds_clamps_correctly() {
        assert_eq!(cursor_bounds(0, 0, 800, 600), (0, 0, 12, 16));
        assert_eq!(cursor_bounds(-5, -5, 800, 600), (0, 0, 7, 11));
        assert_eq!(cursor_bounds(795, 595, 800, 600), (795, 595, 800, 600));
        assert_eq!(cursor_bounds(800, 600, 800, 600), (800, 600, 800, 600));
    }
}

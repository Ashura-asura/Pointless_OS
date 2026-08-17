//! Renders the compositor's `u16` text-cell screen onto a real pixel
//! framebuffer (Phase H) — a **second output backend** for the existing
//! desktop, not a rewrite of `compositor::composite` itself. The window
//! manager / compositor keep composing into `Cell`s exactly as before;
//! this module is the only thing that knows how to turn a `Cell` into
//! pixels, the same way `vga.rs::vga_show_desktop` is the only thing that
//! knows how to turn a `Cell` into a VGA text-mode write.
//!
//! It reuses the embedded 8x16 VGA font (`font::FONT8X16_BASIC`) and the
//! standard 16-color VGA/CGA palette, so the pixel output matches the
//! text-mode backend cell-for-cell (same glyphs, same colors) — just
//! rendered as real pixels instead of hardware text-mode cells.

use crate::compositor::Cell;
use crate::font::FONT8X16_BASIC;
use crate::gpu::GpuDevice;

const GLYPH_W: usize = 8;
const GLYPH_H: usize = 16;

/// Standard 16-color VGA/CGA palette as 8-bit RGB, `[R, G, B]` per entry —
/// matches `vga.rs`'s 6-bit DAC palette scaled up to 8 bits (`v * 4`, e.g.
/// `0x2A * 4 = 0xA8` ≈ `0xAA` below), so text rendered here has the same
/// colors as the VGA text-mode backend.
const PALETTE: [[u8; 3]; 16] = [
    [0x00, 0x00, 0x00], // 0 black
    [0x00, 0x00, 0xAA], // 1 blue
    [0x00, 0xAA, 0x00], // 2 green
    [0x00, 0xAA, 0xAA], // 3 cyan
    [0xAA, 0x00, 0x00], // 4 red
    [0xAA, 0x00, 0xAA], // 5 magenta
    [0xAA, 0x55, 0x00], // 6 brown
    [0xAA, 0xAA, 0xAA], // 7 light gray
    [0x55, 0x55, 0x55], // 8 dark gray
    [0x55, 0x55, 0xFF], // 9 light blue
    [0x55, 0xFF, 0x55], // a light green
    [0x55, 0xFF, 0xFF], // b light cyan
    [0xFF, 0x55, 0x55], // c light red
    [0xFF, 0x55, 0xFF], // d light magenta
    [0xFF, 0xFF, 0x55], // e yellow
    [0xFF, 0xFF, 0xFF], // f white
];

/// Blit a composited `Cell` (`char | attr<<8`) screen onto `gpu`'s pixel
/// framebuffer, glyph-rendered through the embedded 8x16 font.
///
/// No-op if `gpu` has no mode set (`set_mode` never called, or it failed)
/// or if `screen` is smaller than `sw * sh` — by design, per the module
/// doc: the VGA text backend never depends on this succeeding, so this
/// function fails silently rather than panicking the boot path.
///
/// `sw`/`sh` are the screen's dimensions **in text cells** (matches
/// `desktop::SW`/`SH`, 80x25); the rendered image is `sw*8` x `sh*16`
/// pixels, centered within the mode if the mode is larger, clipped if
/// smaller. Attribute byte layout matches `vga.rs`: low nibble =
/// foreground color index, high nibble = background color index.
///
/// Generic over `GpuDevice` so the same pixel path serves both the Bochs
/// VBE backend (QEMU) and the UEFI GOP backend (real hardware); the
/// mode's `bgr` flag selects the pixel byte order.
pub fn blit_cells<G: GpuDevice>(gpu: &mut G, screen: &[Cell], sw: usize, sh: usize) {
    let Some((fb, mode)) = gpu.framebuffer_mut() else {
        return; // no mode set: no-op, by design (see doc comment above)
    };
    if screen.len() < sw * sh {
        return; // undersized source: nothing sane to paint
    }
    let bpp_bytes = (mode.bpp / 8) as usize;
    if bpp_bytes == 0 {
        return;
    }

    // Clear the whole framebuffer first, same as `vga_show_desktop`
    // blanking the text buffer before centering the composited screen —
    // otherwise stale pixels from a previous, differently-sized frame
    // would show through around the edges.
    fb.fill(0);

    let image_w = sw * GLYPH_W;
    let image_h = sh * GLYPH_H;
    let ox = (mode.width as usize).saturating_sub(image_w) / 2;
    let oy = (mode.height as usize).saturating_sub(image_h) / 2;

    for cy in 0..sh {
        for cx in 0..sw {
            let cell = screen[cy * sw + cx];
            let ch = (cell & 0xFF) as usize;
            let attr = (cell >> 8) & 0xFF;
            let fg = PALETTE[(attr & 0x0F) as usize];
            let bg = PALETTE[((attr >> 4) & 0x0F) as usize];
            let glyph = &FONT8X16_BASIC[ch];

            for (row, &bits) in glyph.iter().enumerate() {
                let py = oy + cy * GLYPH_H + row;
                if py >= mode.height as usize {
                    break;
                }
                let row_base = py * mode.pitch;
                for col in 0..GLYPH_W {
                    let px = ox + cx * GLYPH_W + col;
                    if px >= mode.width as usize {
                        break;
                    }
                    // MSB first: bit 7 of each glyph byte is the leftmost
                    // pixel of that scanline.
                    let set = (bits >> (7 - col)) & 1 != 0;
                    let color = if set { fg } else { bg };
                    let offset = row_base + px * bpp_bytes;
                    if offset + bpp_bytes > fb.len() {
                        continue;
                    }
                    // Pixel byte order comes from the mode: BGRX8888 for
                    // Bochs/QEMU VBE and GOP `Bgr`, RGBX8888 for GOP
                    // `Rgb` (common on real hardware).
                    if mode.bgr {
                        fb[offset] = color[2]; // B
                        fb[offset + 1] = color[1]; // G
                        fb[offset + 2] = color[0]; // R
                    } else {
                        fb[offset] = color[0]; // R
                        fb[offset + 1] = color[1]; // G
                        fb[offset + 2] = color[2]; // B
                    }
                    if bpp_bytes > 3 {
                        fb[offset + 3] = 0xFF; // X / alpha
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::{BochsGpu, Mode};

    /// `FONT8X16_BASIC[0]` (char 0, NUL) is all-zero bytes: every pixel of
    /// that glyph is "unset", i.e. it paints as background everywhere.
    /// Verified directly against `font.rs`, not assumed.
    const CHAR_BLANK: u16 = 0x00;
    /// `FONT8X16_BASIC[0x41]` ('A'). Its bitmap's row 2 is `0b0001_0000`
    /// (verified against `font.rs`): bit 4 set, i.e. column 3 (MSB-first:
    /// `col = 7 - bit_index`) is foreground and every other column in that
    /// row — including column 0 — is background. Row 0 is `0x00`, so every
    /// column in row 0 is background too. Used below to check specific,
    /// pre-verified foreground/background pixels rather than assuming any
    /// glyph is uniformly solid (this font has no fully-solid glyph).
    const CHAR_A: u16 = 0x41;

    fn px(fb: &[u8], pitch: usize, x: usize, y: usize) -> [u8; 4] {
        let o = y * pitch + x * 4;
        [fb[o], fb[o + 1], fb[o + 2], fb[o + 3]]
    }

    fn bgrx(rgb: [u8; 3]) -> [u8; 4] {
        [rgb[2], rgb[1], rgb[0], 0xFF]
    }

    #[test]
    fn no_mode_set_is_a_no_op() {
        let mut buf = [0xABu8; 64];
        let mut gpu = BochsGpu::test_with_mode(&mut buf, None);
        let screen = [0u16; 1];
        blit_cells(&mut gpu, &screen, 1, 1);
        assert!(buf.iter().all(|&b| b == 0xAB)); // untouched
    }

    #[test]
    fn undersized_screen_is_a_no_op() {
        let mode = Mode {
            width: 8,
            height: 16,
            bpp: 32,
            pitch: 32,
            bgr: true,
        };
        let mut buf = [0xABu8; 32 * 16];
        let mut gpu = BochsGpu::test_with_mode(&mut buf, Some(mode));
        let screen: [u16; 1] = [0]; // needs 2*2 = 4 cells, only supplies 1
        blit_cells(&mut gpu, &screen, 2, 2);
        assert!(buf.iter().all(|&b| b == 0xAB)); // untouched
    }

    #[test]
    fn one_to_one_mode_paints_fg_and_bg_correctly() {
        // Mode exactly matches a single glyph cell: no centering offset.
        let mode = Mode {
            width: GLYPH_W as u32,
            height: GLYPH_H as u32,
            bpp: 32,
            pitch: GLYPH_W * 4,
            bgr: true,
        };
        let mut buf = vec![0u8; mode.pitch * GLYPH_H];
        let mut gpu = BochsGpu::test_with_mode(&mut buf, Some(mode));

        // attr: fg = 1 (blue), bg = 2 (green).
        let attr: u16 = (2 << 4) | 1;

        // A blank cell paints entirely background.
        let cell_blank = (attr << 8) | CHAR_BLANK;
        blit_cells(&mut gpu, &[cell_blank], 1, 1);
        assert_eq!(px(&buf, mode.pitch, 0, 0), bgrx(PALETTE[2]));
        assert_eq!(px(&buf, mode.pitch, 7, 15), bgrx(PALETTE[2]));

        // 'A': row 2 col 3 is foreground; row 2 col 0 and row 0 col 0 are
        // background (see CHAR_A doc comment above).
        let cell_a = (attr << 8) | CHAR_A;
        blit_cells(&mut gpu, &[cell_a], 1, 1);
        assert_eq!(px(&buf, mode.pitch, 3, 2), bgrx(PALETTE[1])); // fg (blue)
        assert_eq!(px(&buf, mode.pitch, 0, 2), bgrx(PALETTE[2])); // bg (green)
        assert_eq!(px(&buf, mode.pitch, 0, 0), bgrx(PALETTE[2])); // bg (green)
    }

    #[test]
    fn larger_mode_centers_the_image() {
        // Mode is 2x the size of a single glyph cell in each dimension:
        // the glyph should land centered, with the border left as the
        // full-buffer-clear black rather than whatever was there before.
        let mode = Mode {
            width: (GLYPH_W * 2) as u32,
            height: (GLYPH_H * 2) as u32,
            bpp: 32,
            pitch: GLYPH_W * 2 * 4,
            bgr: true,
        };
        let mut buf = vec![0xABu8; mode.pitch * (GLYPH_H * 2)];
        let mut gpu = BochsGpu::test_with_mode(&mut buf, Some(mode));

        // fg = white (15), bg = blue (1) — kept distinct from the clear
        // color (black) so "painted background" and "unpainted border"
        // are distinguishable in the assertions below.
        let attr: u16 = (1 << 4) | 15;
        let cell_a = (attr << 8) | CHAR_A;
        blit_cells(&mut gpu, &[cell_a], 1, 1);

        // Offset: (16-8)/2 = 4 in x, (32-16)/2 = 8 in y.
        let (ox, oy) = (GLYPH_W / 2, GLYPH_H / 2);
        assert_eq!(px(&buf, mode.pitch, ox + 3, oy + 2), bgrx(PALETTE[15])); // glyph fg
        assert_eq!(px(&buf, mode.pitch, ox, oy + 2), bgrx(PALETTE[1])); // glyph bg
        assert_eq!(px(&buf, mode.pitch, 0, 0), [0, 0, 0, 0]); // border: cleared
    }

    #[test]
    fn smaller_mode_clips_without_panicking() {
        // Mode is smaller than one glyph cell in both dimensions: every
        // in-bounds pixel must still land inside the buffer, and the
        // out-of-bounds part of the glyph is simply dropped.
        let mode = Mode {
            width: 4,
            height: 4,
            bpp: 32,
            pitch: 4 * 4,
            bgr: true,
        };
        let mut buf = vec![0u8; mode.pitch * 4];
        let mut gpu = BochsGpu::test_with_mode(&mut buf, Some(mode));

        let attr: u16 = (1 << 4) | 15; // fg = white, bg = blue
        let cell_a = (attr << 8) | CHAR_A;
        blit_cells(&mut gpu, &[cell_a], 1, 1); // must not panic
        assert_eq!(px(&buf, mode.pitch, 0, 0), bgrx(PALETTE[1])); // row0: all bg
        assert_eq!(px(&buf, mode.pitch, 3, 2), bgrx(PALETTE[15])); // row2 col3: fg
    }

    #[test]
    fn full_desktop_sized_screen_does_not_panic() {
        // Sanity check at the real desktop dimensions (80x25 cells) used
        // by `desktop::gpu_blit`, against a mode sized to exactly fit it.
        const SW: usize = 80;
        const SH: usize = 25;
        let mode = Mode {
            width: (SW * GLYPH_W) as u32,
            height: (SH * GLYPH_H) as u32,
            bpp: 32,
            pitch: SW * GLYPH_W * 4,
            bgr: true,
        };
        let mut buf = vec![0u8; mode.pitch * SH * GLYPH_H];
        let mut gpu = BochsGpu::test_with_mode(&mut buf, Some(mode));
        let screen = vec![0x0F41u16; SW * SH]; // white-on-black 'A' everywhere
        blit_cells(&mut gpu, &screen, SW, SH);
        assert_eq!(px(&buf, mode.pitch, 0, 0)[3], 0xFF);
    }

    #[test]
    fn rgb_mode_writes_rgbx_byte_order() {
        // GOP PixelFormat::Rgb framebuffers are RGBX8888: the red channel
        // byte comes first, unlike BGRX (Bochs). Same glyph, same palette
        // entry — only the byte order differs.
        fn rgbr(rgb: [u8; 3]) -> [u8; 4] {
            [rgb[0], rgb[1], rgb[2], 0xFF]
        }

        let mode = Mode {
            width: GLYPH_W as u32,
            height: GLYPH_H as u32,
            bpp: 32,
            pitch: GLYPH_W * 4,
            bgr: false, // GOP Rgb
        };
        let mut buf = vec![0u8; mode.pitch * GLYPH_H];
        let mut gop = crate::gpu::GopGpu::test_with_buffer(&mut buf, mode);

        let attr: u16 = (2 << 4) | 1; // fg = blue (1), bg = green (2)
        let cell_a = (attr << 8) | CHAR_A;
        blit_cells(&mut gop, &[cell_a], 1, 1);

        assert_eq!(px(&buf, mode.pitch, 3, 2), rgbr(PALETTE[1])); // fg: blue, R-first
        assert_eq!(px(&buf, mode.pitch, 0, 2), rgbr(PALETTE[2])); // bg: green
        assert_eq!(px(&buf, mode.pitch, 7, 15), rgbr(PALETTE[2])); // bg: green
    }
}

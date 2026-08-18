//! Phase AA: the kernel's fifth real application window — a PPM image viewer
//! model. The kernel can't hold a full bitmap in fixed memory (no allocator,
//! 12 KB stack), so this module reads a **P6 PPM at most 12x12** and reduces
//! every pixel to the standard 16-color VGA palette entry it is nearest to
//! (Euclidean distance in RGB space). The desktop's `render_viewer` then
//! paints each pixel as a 1x1 text cell whose fg/bg attribute is that palette
//! index, at the compositor's native cell resolution — a color image from a
//! raw binary file, with no pixel framebuffer, no allocator, and a fully
//! serial-evidence-able render loop.
//!
//! `build_demo_ppm()` synthesizes the demo image (blue background, white
//! diagonal cross, red corner blocks) that `main.rs` seeds into the NVMe
//! object store as `img.ppm` on first boot, and that the viewer window shows
//! after the seed.

use crate::gpu_compositor::PALETTE;

/// Maximum image width/height the model will accept. A 12x12 image is 432
/// bytes of raw P6 pixel data — well inside the 512-byte store payload and
/// small enough to paint as text cells.
pub const MAX_DIM: u32 = 12;

/// The reduced image: `dim` is the square edge length (1..=MAX_DIM) and
/// `cells` holds `dim*dim` compositor cells, one per pixel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewerImage {
    pub dim: u32,
    pub cells: [[u16; MAX_DIM as usize]; MAX_DIM as usize],
}

impl ViewerImage {
    /// A fresh, empty image (dim 0, all cells blank).
    pub fn new() -> ViewerImage {
        ViewerImage {
            dim: 0,
            cells: [[0u16; MAX_DIM as usize]; MAX_DIM as usize],
        }
    }

    /// The pixel cell at (x, y) — or the blank cell for an empty image.
    pub fn cell(&self, x: u32, y: u32) -> u16 {
        if self.dim == 0 {
            return 0;
        }
        self.cells[y as usize][x as usize]
    }
}

impl Default for ViewerImage {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a P6 PPM payload into a [`ViewerImage`]. The header is the magic
/// `P6`, ASCII width/height, and a maxval that must be `255`; after the
/// whitespace separating the maxval from the payload, the payload is exactly
/// `w*h*3` bytes of RGB triples. The demo payload (`build_demo_ppm`) packs the
/// 12-byte header `P6 12 12 255` directly against the pixel bytes (no
/// trailing separator), so the maxval is read as a bounded three-digit token.
/// Anything else — wrong magic, zero or oversized dimensions, a maxval other
/// than 255, or truncated/garbage pixel data — is rejected so the store's raw
/// bytes can never panic the viewer.
pub fn parse_ppm(data: &[u8]) -> Option<ViewerImage> {
    let mut pos = 0usize;
    let magic = next_token(data, &mut pos)?;
    if magic != b"P6" {
        return None;
    }
    let w = parse_dim(&mut next_token(data, &mut pos)?)?;
    let h = parse_dim(&mut next_token(data, &mut pos)?)?;
    if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM {
        return None;
    }
    skip_ws(data, &mut pos);
    // The maxval is the last header field and may abut the binary pixels
    // directly (the demo does), so read a bounded three-digit token instead of
    // whitespace-greedy scanning.
    let mut maxval = 0u32;
    let mut digits = 0usize;
    while digits < 3 && pos < data.len() && data[pos].is_ascii_digit() {
        maxval = maxval * 10 + (data[pos] - b'0') as u32;
        pos += 1;
        digits += 1;
    }
    if digits == 0 || maxval != 255 {
        return None;
    }
    // The whitespace after the maxval is consumed; the remaining bytes must be
    // exactly the pixel data (anything else — a short buffer, extra header
    // tokens, or trailing garbage — is rejected below).
    skip_ws(data, &mut pos);
    let need = (w * h * 3) as usize;
    if data.len() - pos != need {
        return None;
    }
    let px = &data[pos..];
    let mut img = ViewerImage::new();
    img.dim = w;
    for y in 0..h {
        for x in 0..w {
            let i = ((y * w + x) * 3) as usize;
            let idx = nearest_palette([px[i], px[i + 1], px[i + 2]]);
            // fg == bg == palette index: a solid 1x1 color cell. The empty
            // space glyph keeps the VGA text backend rendering the same way.
            img.cells[y as usize][x as usize] = (((idx << 4) | idx) as u16) << 8 | b' ' as u16;
        }
    }
    Some(img)
}

/// The next whitespace-delimited ASCII token.
fn next_token<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    skip_ws(data, pos);
    let start = *pos;
    while *pos < data.len() && !data[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
    if *pos == start {
        None
    } else {
        Some(&data[start..*pos])
    }
}

/// Skip ASCII whitespace.
fn skip_ws(data: &[u8], pos: &mut usize) {
    while *pos < data.len() && data[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

/// Parse a small unsigned ASCII integer token (max 3 digits).
fn parse_dim(t: &mut &[u8]) -> Option<u32> {
    if t.is_empty() || t.len() > 3 {
        return None;
    }
    let mut v = 0u32;
    for &b in t.iter() {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u32;
    }
    Some(v)
}

/// The palette index whose RGB is nearest to `rgb` (Euclidean distance).
fn nearest_palette(rgb: [u8; 3]) -> u8 {
    let mut best = 0u8;
    let mut best_d = u64::MAX;
    for (i, p) in PALETTE.iter().enumerate() {
        let dr = p[0] as i32 - rgb[0] as i32;
        let dg = p[1] as i32 - rgb[1] as i32;
        let db = p[2] as i32 - rgb[2] as i32;
        let d = (dr * dr + dg * dg + db * db) as u64;
        if d < best_d {
            best_d = d;
            best = i as u8;
        }
    }
    best
}

/// Synthesize the demo image: a 12x12 P6 PPM — blue background, a white
/// diagonal cross (`y == x || x + y == 11`), and red corner blocks. Returns
/// the header + pixel payload in the first 444 bytes of the 512-byte buffer
/// (12-byte header + 12*12*3 = 432 pixel bytes); the rest stays zero so the
/// store payload has no uninitialized tail.
pub fn build_demo_ppm() -> [u8; 512] {
    let mut out = [0u8; 512];
    let header = b"P6 12 12 255";
    out[..header.len()].copy_from_slice(header);
    let mut i = header.len();
    for y in 0..12u32 {
        for x in 0..12u32 {
            let corner = !(2..10).contains(&x) && !(2..10).contains(&y);
            let cross = x == y || x + y == 11;
            let rgb: [u8; 3] = if corner {
                [0xAA, 0x00, 0x00] // red corner blocks
            } else if cross {
                [0xFF, 0xFF, 0xFF] // white diagonal cross
            } else {
                [0x00, 0x00, 0xAA] // blue background
            };
            out[i] = rgb[0];
            out[i + 1] = rgb[1];
            out[i + 2] = rgb[2];
            i += 3;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(cell: u16) -> u8 {
        (cell >> 8) as u8
    }

    #[test]
    fn parse_valid_12x12_ppm() {
        let data = b"P6 3 3 255\n";
        let mut buf = [0u8; 512];
        buf[..data.len()].copy_from_slice(data);
        // red, white, blue in the first row
        buf[data.len()..data.len() + 9]
            .copy_from_slice(&[0xAA, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xAA]);
        buf[data.len() + 9..].fill(0x11); // the other rows: any color
        let img = parse_ppm(&buf[..data.len() + 9 + 18]).unwrap();
        assert_eq!(img.dim, 3);
        let c0 = attr(img.cell(0, 0));
        let c1 = attr(img.cell(1, 0));
        let c2 = attr(img.cell(2, 0));
        assert_eq!(c0 >> 4, 4); // red
        assert_eq!(c1 >> 4, 15); // white
        assert_eq!(c2 >> 4, 1); // blue
    }

    #[test]
    fn rejects_non_p6_magic() {
        let data = b"P5 3 3 255\n";
        assert!(parse_ppm(data).is_none());
    }

    #[test]
    fn rejects_oversized_dimensions() {
        let data = b"P6 13 12 255\n";
        assert!(parse_ppm(data).is_none());
        let data = b"P6 12 13 255\n";
        assert!(parse_ppm(data).is_none());
    }

    #[test]
    fn rejects_truncated_pixel_data() {
        let data = b"P6 12 12 255\n";
        let mut buf = [0u8; 512];
        buf[..data.len()].copy_from_slice(data);
        // Only 3 of the needed 432 pixel bytes present.
        buf[data.len()..data.len() + 3].copy_from_slice(&[0, 0, 0]);
        assert!(parse_ppm(&buf[..data.len() + 3]).is_none());
        // Trailing garbage is also rejected.
        let mut extra = [0u8; 512];
        extra[..data.len()].copy_from_slice(data);
        assert!(parse_ppm(&extra[..data.len() + 432 + 1]).is_none());
    }

    #[test]
    fn quantizes_to_palette_indices() {
        let data = b"P6 1 1 255\n";
        let mut buf = [0u8; 512];
        buf[..data.len()].copy_from_slice(data);
        buf[data.len()..data.len() + 3].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
        let img = parse_ppm(&buf[..data.len() + 3]).unwrap();
        assert_eq!(attr(img.cell(0, 0)) & 0x0F, 15); // exact white
        buf[data.len()..data.len() + 3].copy_from_slice(&[0x00, 0x00, 0xAA]);
        let img = parse_ppm(&buf[..data.len() + 3]).unwrap();
        assert_eq!(attr(img.cell(0, 0)) & 0x0F, 1); // exact blue
                                                    // A near-white off-palette value still lands on white.
        buf[data.len()..data.len() + 3].copy_from_slice(&[0xEE, 0xEE, 0xEE]);
        let img = parse_ppm(&buf[..data.len() + 3]).unwrap();
        assert_eq!(attr(img.cell(0, 0)) & 0x0F, 15);
    }

    #[test]
    fn build_demo_ppm_len_is_444() {
        let ppm = build_demo_ppm();
        // 12 header bytes + 12*12*3 = 444 total.
        assert_eq!(&ppm[..12], b"P6 12 12 255");
        assert_ne!(ppm[12], 0); // first pixel byte (red corner block)
        assert_eq!(ppm[444..], [0u8; 512 - 444]);
        // Round-trips through the parser.
        let img = parse_ppm(&ppm[..444]).unwrap();
        assert_eq!(img.dim, 12);
        // Red corner block, white cross, blue background — in that priority.
        assert_eq!(attr(img.cell(0, 0)) >> 4, 4); // top-left corner: red
        assert_eq!(attr(img.cell(11, 11)) >> 4, 4); // bottom-right corner: red
        assert_eq!(attr(img.cell(6, 6)) >> 4, 15); // cross center: white
        assert_eq!(attr(img.cell(2, 6)) >> 4, 1); // interior: blue
    }
}

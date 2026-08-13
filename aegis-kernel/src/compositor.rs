//! The graphical-shell compositor (roadmap §10 item 3: "GPU compositor /
//! graphical shell ... ordinary UI work, lowest risk"). This is the kernel
//! side of the display server: it turns the `WindowManager`'s z-ordered
//! window list plus per-window framebuffers into a single composited screen.
//!
//! Honest substrate: the VM's real display is the VGA text-mode buffer
//! (80x25, one `u16` cell per character position, char | attr<<8), so a
//! "pixel" here is one text cell. The compositor is deliberately a small,
//! allocation-free, purely functional paint: it clears the screen, then
//! paints visible windows back-to-front (ascending z-order), clipping each
//! window's framebuffer to its region and to the screen bounds, exactly as a
//! real compositor clips surfaces. Windows whose framebuffer is not yet
//! supplied render as transparent, so the display server never draws
//! garbage for an app that has not rendered its first frame.
//!
//! The graphics *service* in the model (`crates/devices`) already proves the
//! capability-scoped GPU story (queue = SEND, framebuffer = READ|WRITE,
//! compositor = READ grants, dead-compositor refusal); this module is the
//! userspace-style compositing step itself, exercised in the kernel and
//! driven live at boot.

use crate::window::WindowManager;

/// One composited cell. On the VGA text substrate this is a character cell
/// (`char | attr << 8`), but the compositor only ever copies cells around —
/// it never interprets their meaning, so it works for any cell format.
pub type Cell = u16;

/// A window whose framebuffer has not been supplied yet paints as this
/// value: nothing. The display server never shows garbage for an
/// unrendered app.
pub const TRANSPARENT: Cell = 0x0000;

/// Maximum number of compositable windows; mirrors the `WindowManager`.
pub const MAX_WINDOWS: usize = 32;

/// Composite the window manager's z-ordered, visible windows into `screen`.
///
/// `framebuffers` is indexed by window id - 1 (ids begin at 1): each entry is
/// that window's contents as `region.width * region.height` cells. Painting
/// order is `compositor_order()` — ascending z, i.e. back-to-front — so a
/// higher window occludes a lower one wherever they overlap. Each window is
/// clipped both to its own region and to the screen bounds; windows fully
/// off-screen contribute nothing; hidden windows are skipped.
///
/// Returns `Err` if `screen` is smaller than `screen_width * screen_height`.
pub fn composite(
    wm: &WindowManager,
    framebuffers: &[Option<&[Cell]>; MAX_WINDOWS],
    screen: &mut [Cell],
) -> Result<(), &'static str> {
    let (sw, sh) = wm.bounds();
    let needed = (sw as usize) * (sh as usize);
    if screen.len() < needed {
        return Err("screen buffer smaller than screen bounds");
    }
    screen[..needed].fill(TRANSPARENT);

    let order = wm.compositor_order();
    for id in order.iter().take_while(|&&id| id != 0) {
        let win = match wm.window(*id) {
            Some(w) => w,
            None => continue,
        };
        if !win.visible {
            continue;
        }
        let idx = (*id as usize) - 1;
        let fb = match framebuffers.get(idx).copied().flatten() {
            Some(fb) => fb,
            None => continue, // not yet rendered: transparent
        };
        let r = win.region;
        let rw = r.width as usize;
        if fb.len() < rw * (r.height as usize) {
            continue; // undersized framebuffer: treat as unrendered
        }

        // Intersection of the window region with the screen rectangle,
        // computed in i32 so a negative origin (window partially above or
        // left of the screen) clips correctly.
        let x0 = r.x.max(0) as usize;
        let y0 = r.y.max(0) as usize;
        let x1 = ((r.x as i32 + r.width as i32).min(sw as i32).max(0)) as usize;
        let y1 = ((r.y as i32 + r.height as i32).min(sh as i32).max(0)) as usize;

        for sy in y0..y1 {
            // Window-local row for this screen row. Clipping guarantees the
            // result is in [0, height).
            let src_row = ((sy as i32 - r.y as i32) as usize) * rw;
            let dst_row = sy * (sw as usize);
            for sx in x0..x1 {
                // Window-local column, likewise clipped into [0, width).
                let src_col = (sx as i32 - r.x as i32) as usize;
                screen[dst_row + sx] = fb[src_row + src_col];
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::Region;

    const SW: u16 = 8;
    const SH: u16 = 6;

    fn wm() -> WindowManager {
        WindowManager::new(SW, SH)
    }

    fn region(x: i16, y: i16, width: u16, height: u16) -> Region {
        Region {
            x,
            y,
            width,
            height,
        }
    }

    fn fb_fill(cell: Cell, w: u16, h: u16) -> &'static [Cell] {
        let v: &'static mut [Cell] =
            Box::leak(vec![cell; (w as usize) * (h as usize)].into_boxed_slice());
        v
    }

    #[test]
    fn empty_screen_is_all_transparent() {
        let m = wm();
        let mut screen = [0xABCD; (SW as usize) * (SH as usize)];
        composite(&m, &[None; MAX_WINDOWS], &mut screen).unwrap();
        assert!(screen.iter().all(|&c| c == TRANSPARENT));
    }

    #[test]
    fn single_window_paints_its_region() {
        let mut m = wm();
        let id = m.create_window(1, b"a", region(1, 1, 3, 2)).unwrap();
        let mut fbs = [None; MAX_WINDOWS];
        fbs[(id as usize) - 1] = Some(fb_fill(0x0F00 | b'A' as u16, 3, 2));
        let mut screen = [TRANSPARENT; (SW as usize) * (SH as usize)];
        composite(&m, &fbs, &mut screen).unwrap();
        // Cell (2,1) is inside the window; cell (0,0) and (5,3) are outside.
        assert_eq!(screen[(SW as usize) + 2], 0x0F00 | b'A' as u16);
        assert_eq!(screen[0], TRANSPARENT);
        assert_eq!(screen[3 * SW as usize + 5], TRANSPARENT);
    }

    #[test]
    fn higher_window_occludes_lower_in_overlap() {
        let mut m = wm();
        let lo = m.create_window(1, b"lo", region(0, 0, 5, 4)).unwrap();
        let hi = m.create_window(1, b"hi", region(2, 1, 4, 3)).unwrap();
        let mut fbs = [None; MAX_WINDOWS];
        fbs[(lo as usize) - 1] = Some(fb_fill(0x0F00 | b'L' as u16, 5, 4));
        fbs[(hi as usize) - 1] = Some(fb_fill(0x0F00 | b'H' as u16, 4, 3));
        let mut screen = [TRANSPARENT; (SW as usize) * (SH as usize)];
        composite(&m, &fbs, &mut screen).unwrap();
        // Overlap cell (3,2): hi is on top -> 'H'.
        assert_eq!(screen[2 * SW as usize + 3], 0x0F00 | b'H' as u16);
        // Below overlap, cell (1,3): only lo -> 'L'.
        assert_eq!(screen[3 * SW as usize + 1], 0x0F00 | b'L' as u16);
    }

    #[test]
    fn window_partially_offscreen_is_clipped() {
        let mut m = wm();
        let id = m.create_window(1, b"clip", region(-2, -1, 6, 4)).unwrap();
        let mut fbs = [None; MAX_WINDOWS];
        fbs[(id as usize) - 1] = Some(fb_fill(0x0F00 | b'C' as u16, 6, 4));
        let mut screen = [TRANSPARENT; (SW as usize) * (SH as usize)];
        composite(&m, &fbs, &mut screen).unwrap();
        // The window occupies x in [-2,4) and y in [-1,3); clipped to the
        // screen this is x in [0,4), y in [0,3). A cell inside paints...
        assert_eq!(screen[(SW as usize) + 1], 0x0F00 | b'C' as u16);
        // ...and cells beyond the clipped right edge (x=5) are untouched.
        assert_eq!(screen[5], TRANSPARENT);
        // Cells below the clipped bottom edge (y=4) are untouched too.
        assert_eq!(screen[4 * SW as usize], TRANSPARENT);
    }

    #[test]
    fn hidden_window_is_not_painted() {
        let mut m = wm();
        let id = m.create_window(1, b"h", region(0, 0, 4, 4)).unwrap();
        m.set_visible(id, false).unwrap();
        let mut fbs = [None; MAX_WINDOWS];
        fbs[(id as usize) - 1] = Some(fb_fill(0x0F00 | b'H' as u16, 4, 4));
        let mut screen = [0xABCD; (SW as usize) * (SH as usize)];
        composite(&m, &fbs, &mut screen).unwrap();
        assert!(screen.iter().all(|&c| c == TRANSPARENT));
    }

    #[test]
    fn missing_framebuffer_renders_transparent() {
        let mut m = wm();
        let _id = m.create_window(1, b"nr", region(0, 0, 4, 4)).unwrap();
        let fbs = [None; MAX_WINDOWS];
        // Do not supply a framebuffer for the visible window.
        let mut screen = [0xABCD; (SW as usize) * (SH as usize)];
        composite(&m, &fbs, &mut screen).unwrap();
        assert!(screen.iter().all(|&c| c == TRANSPARENT));
    }

    #[test]
    fn too_small_screen_buffer_fails() {
        let m = wm();
        let mut screen = [TRANSPARENT; 8];
        assert!(composite(&m, &[None; MAX_WINDOWS], &mut screen).is_err());
    }

    #[test]
    fn z_order_reorders_occlusion() {
        let mut m = wm();
        let a = m.create_window(1, b"a", region(0, 0, 4, 4)).unwrap();
        let b = m.create_window(1, b"b", region(1, 1, 4, 4)).unwrap();
        // Default z: b above a. Cell (2,2) shows b.
        let mut fbs = [None; MAX_WINDOWS];
        fbs[(a as usize) - 1] = Some(fb_fill(0x0F00 | b'A' as u16, 4, 4));
        fbs[(b as usize) - 1] = Some(fb_fill(0x0F00 | b'B' as u16, 4, 4));
        let mut screen = [TRANSPARENT; (SW as usize) * (SH as usize)];
        composite(&m, &fbs, &mut screen).unwrap();
        assert_eq!(screen[2 * SW as usize + 2], 0x0F00 | b'B' as u16);
        // Raise a above b: now a occludes.
        m.focus_window(a).unwrap();
        composite(&m, &fbs, &mut screen).unwrap();
        assert_eq!(screen[2 * SW as usize + 2], 0x0F00 | b'A' as u16);
    }
}

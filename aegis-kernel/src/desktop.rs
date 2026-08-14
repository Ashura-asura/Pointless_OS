//! The shell's live desktop (roadmap §10 item 4: interactive shell). Owns
//! the window manager, the per-window framebuffers, and the composited
//! screen for the whole run, so input-driven re-composition and re-blits can
//! mutate live state instead of a one-shot boot-time demo.
//!
//! Input contract, serial-first: the idle loop drains the PS/2 ring buffer
//! and calls `Desktop::apply_key`. Tab cycles focus between the clock and
//! menu windows (raising z-order and re-occluding them); the arrow keys move
//! the focused window one cell and clamp it to the screen bounds. Each
//! applied key re-composites and re-blits, and the caller prints the
//! resulting outcome over serial (a `KeyOutcome` mirror of the boot-time
//! `menu(#) occludes clock(.)` assertion, but driven by a real keypress).

use crate::compositor::{self, Cell, MAX_WINDOWS};
use crate::input::Key;
use crate::window::{Region, WindowManager};

/// Screen size in VGA text cells.
pub const SW: usize = 80;
pub const SH: usize = 25;

const CLOCK_W: u16 = 30;
const CLOCK_H: u16 = 8;
const MENU_W: u16 = 24;
const MENU_H: u16 = 5;

/// What a keypress did to the live desktop. The caller (idle loop) prints
/// it over serial as the keypress-driven analogue of the boot-time occlusion
/// assertion.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyOutcome {
    FocusChanged { window_id: u32, overlap_cell: u8 },
    Moved { window_id: u32, x: i16, y: i16, clipped: bool },
}

/// Live shell desktop: window manager + framebuffers + composited screen.
pub struct Desktop {
    wm: WindowManager,
    fb_title: [Cell; SW],
    fb_status: [Cell; SW],
    fb_clock: [Cell; (CLOCK_W as usize) * (CLOCK_H as usize)],
    fb_menu: [Cell; (MENU_W as usize) * (MENU_H as usize)],
    screen: [Cell; SW * SH],
    clock_id: u32,
    menu_id: u32,
    focus_cycle: [u32; 2],
    focus_pos: usize,
}

impl Desktop {
    /// Build the desktop exactly as the boot-time demo did: title and status
    /// bars plus a clock window and a focused menu window that occludes it.
    pub fn new() -> Desktop {
        let mut wm = WindowManager::new(SW as u16, SH as u16);
        let _title = wm
            .create_window(
                1,
                b"title",
                Region {
                    x: 0,
                    y: 0,
                    width: SW as u16,
                    height: 1,
                },
            )
            .unwrap();
        let _status = wm
            .create_window(
                2,
                b"status",
                Region {
                    x: 0,
                    y: SH as i16 - 1,
                    width: SW as u16,
                    height: 1,
                },
            )
            .unwrap();
        let clock = wm
            .create_window(
                3,
                b"clock",
                Region {
                    x: 2,
                    y: 2,
                    width: CLOCK_W,
                    height: CLOCK_H,
                },
            )
            .unwrap();
        let menu = wm
            .create_window(
                4,
                b"menu",
                Region {
                    x: 18,
                    y: 4,
                    width: MENU_W,
                    height: MENU_H,
                },
            )
            .unwrap();
        wm.focus_window(menu).unwrap();

        let mut fb_title = [0u16; SW];
        for c in fb_title.iter_mut() {
            *c = 0x1F00 | b' ' as u16;
        }
        for (i, t) in b" AEGIS GRAPHICAL SHELL -- live compositor desktop (80x25) -- transparent cells = blue desktop ".iter().enumerate()
        {
            if i < SW {
                fb_title[i] = 0x1F00 | *t as u16;
            }
        }
        let mut fb_status = [0u16; SW];
        for c in fb_status.iter_mut() {
            *c = 0x0F00 | b'-' as u16;
        }
        let mut fb_clock = [0u16; (CLOCK_W as usize) * (CLOCK_H as usize)];
        for (i, c) in fb_clock.iter_mut().enumerate() {
            *c = 0x0F00 | if i == 0 { b'C' } else { b'.' } as u16;
        }
        let mut fb_menu = [0u16; (MENU_W as usize) * (MENU_H as usize)];
        for (i, c) in fb_menu.iter_mut().enumerate() {
            *c = 0x0F00 | if i == 0 { b'M' } else { b'#' } as u16;
        }

        let mut d = Desktop {
            wm,
            fb_title,
            fb_status,
            fb_clock,
            fb_menu,
            screen: [compositor::TRANSPARENT; SW * SH],
            clock_id: clock,
            menu_id: menu,
            focus_cycle: [clock, menu],
            focus_pos: 1,
        };
        d.composite();
        d
    }

    /// Re-composite the window manager + framebuffers into `screen`, then
    /// paint the desktop background over any cell the compositor left
    /// transparent (so the whole screen is the blue desktop, not a void).
    fn composite(&mut self) {
        let mut fbs: [Option<&[Cell]>; MAX_WINDOWS] = [None; MAX_WINDOWS];
        fbs[0] = Some(&self.fb_title);
        fbs[1] = Some(&self.fb_status);
        fbs[2] = Some(&self.fb_clock);
        fbs[3] = Some(&self.fb_menu);
        compositor::composite(&self.wm, &fbs, &mut self.screen).unwrap();
        let desktop_bg: Cell = 0x1000 | b' ' as u16;
        for c in self.screen.iter_mut() {
            if *c == compositor::TRANSPARENT {
                *c = desktop_bg;
            }
        }
    }

    /// Blit the current composited screen onto the real VGA display.
    pub fn blit(&self) {
        crate::vga::vga_show_desktop(&self.screen, SW, SH);
    }

    /// The composited screen (for the boot-time assertion + tests).
    pub fn screen(&self) -> &[Cell] {
        &self.screen
    }

    /// Number of live windows.
    pub fn window_count(&self) -> usize {
        self.wm
            .compositor_order()
            .iter()
            .filter(|&&id| id != 0)
            .count()
    }

    /// Apply one keypress to the live desktop: Tab cycles focus between the
    /// clock and menu windows (re-occluding them); arrows move the focused
    /// window one cell, clamped to the screen bounds. Pure — re-composites
    /// in memory but does not blit, so tests can assert on `screen()`.
    pub fn apply_key(&mut self, key: Key) -> Option<KeyOutcome> {
        match key {
            Key::Tab => {
                self.focus_pos = (self.focus_pos + 1) % self.focus_cycle.len();
                let id = self.focus_cycle[self.focus_pos];
                self.wm.focus_window(id).ok()?;
                self.composite();
                let cell = (self.screen[5 * SW + 24] & 0xFF) as u8;
                Some(KeyOutcome::FocusChanged {
                    window_id: id,
                    overlap_cell: cell,
                })
            }
            Key::ArrowUp | Key::ArrowDown | Key::ArrowLeft | Key::ArrowRight => {
                let id = self.focus_cycle[self.focus_pos];
                let region = self.wm.window(id)?.region;
                let (nx, ny, clipped) = clamp_move(region, key);
                self.wm.move_window(id, nx, ny).ok()?;
                self.composite();
                Some(KeyOutcome::Moved {
                    window_id: id,
                    x: nx,
                    y: ny,
                    clipped,
                })
            }
            _ => None,
        }
    }

    /// Current region of the focused window.
    pub fn focused_region(&self) -> Region {
        self.wm
            .window(self.focus_cycle[self.focus_pos])
            .map(|w| w.region)
            .unwrap()
    }

    /// Window id of the clock app window.
    pub fn clock_id(&self) -> u32 {
        self.clock_id
    }

    /// Window id of the menu dialog window.
    pub fn menu_id(&self) -> u32 {
        self.menu_id
    }
}

/// Move `r` one cell in the arrow direction, clamped so the window never
/// leaves the screen. Returns the new origin and whether clamping fired.
fn clamp_move(r: Region, key: Key) -> (i16, i16, bool) {
    let (mut x, mut y) = (r.x, r.y);
    let mut clipped = false;
    match key {
        Key::ArrowUp => {
            y -= 1;
            if y < 0 {
                y = 0;
                clipped = true;
            }
        }
        Key::ArrowDown => {
            y += 1;
            if (y as i32 + r.height as i32) > SH as i32 {
                y = (SH as i32 - r.height as i32) as i16;
                clipped = true;
            }
        }
        Key::ArrowLeft => {
            x -= 1;
            if x < 0 {
                x = 0;
                clipped = true;
            }
        }
        Key::ArrowRight => {
            x += 1;
            if (x as i32 + r.width as i32) > SW as i32 {
                x = (SW as i32 - r.width as i32) as i16;
                clipped = true;
            }
        }
        _ => {}
    }
    (x, y, clipped)
}

/// The one live desktop, installed at boot after the demo assertions print.
static mut DESKTOP: Option<Desktop> = None;

/// Install the live desktop.
///
/// # Safety
///
/// Single-threaded boot-time call, once.
pub unsafe fn install(d: Desktop) {
    core::ptr::addr_of_mut!(DESKTOP).write(Some(d));
}

/// Blit the installed desktop onto the display (called once, after all boot
/// demo output has printed). Returns false if none was installed.
pub fn boot_blit() -> bool {
    if let Some(d) = unsafe { core::ptr::addr_of_mut!(DESKTOP).as_mut() }.and_then(|o| o.as_mut()) {
        d.blit();
        true
    } else {
        false
    }
}

/// Apply one keypress to the live desktop and re-blit. Returns the outcome
/// for the caller to print over serial.
pub fn handle_key(key: Key) -> Option<KeyOutcome> {
    let d = unsafe { core::ptr::addr_of_mut!(DESKTOP).as_mut() }.and_then(|o| o.as_mut())?;
    let out = d.apply_key(key)?;
    d.blit();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{InputBuffer, InputEvent};
    use crate::ps2::Ps2State;

    #[test]
    fn boot_layout_matches_original_assertion() {
        let d = Desktop::new();
        let in_menu = (d.screen()[5 * SW + 24] & 0xFF) as u8;
        let in_clock = (d.screen()[3 * SW + 5] & 0xFF) as u8;
        let status_ok = (d.screen()[(SH - 1) * SW] & 0xFF) as u8 == b'-';
        assert_eq!(in_menu, b'#');
        assert_eq!(in_clock, b'.');
        assert!(status_ok);
        assert_eq!(d.window_count(), 4);
    }

    #[test]
    fn tab_via_ring_buffer_changes_focus_and_composite() {
        // Phase-I ring buffer: translate a real Tab make scancode.
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        st.feed(&mut buf, 0x0F);
        let ev = buf.pop().unwrap();
        let InputEvent::Key(ke) = ev else {
            panic!("expected a Key event")
        };
        assert_eq!(ke.key, Key::Tab);
        assert!(ke.pressed);

        // Apply it to a fresh desktop: menu was occluding the clock at the
        // probe cell; the clock must now be topmost there.
        let mut d = Desktop::new();
        assert_eq!((d.screen()[5 * SW + 24] & 0xFF) as u8, b'#');
        let out = d.apply_key(ke.key).unwrap();
        match out {
            KeyOutcome::FocusChanged {
                window_id,
                overlap_cell,
            } => {
                assert_eq!(window_id, d.clock_id());
                assert_eq!(overlap_cell, b'.');
            }
            _ => panic!("expected a focus change"),
        }
        assert_eq!((d.screen()[5 * SW + 24] & 0xFF) as u8, b'.');
    }

    #[test]
    fn arrow_moves_focused_window_and_clamps() {
        let mut d = Desktop::new();
        // Focused window is the menu at (18,4): one ArrowLeft -> (17,4).
        let out = d.apply_key(Key::ArrowLeft).unwrap();
        match out {
            KeyOutcome::Moved {
                window_id,
                x,
                y,
                clipped,
            } => {
                assert_eq!(window_id, d.menu_id());
                assert_eq!((x, y), (17, 4));
                assert!(!clipped);
            }
            _ => panic!("expected a move"),
        }
        // Hammer left until the window hits the screen edge: clamped at x=0.
        for _ in 0..30 {
            let _ = d.apply_key(Key::ArrowLeft);
        }
        let out = d.apply_key(Key::ArrowLeft).unwrap();
        match out {
            KeyOutcome::Moved { x, clipped, .. } => {
                assert_eq!(x, 0);
                assert!(clipped);
            }
            _ => panic!("expected a move"),
        }
        let r = d.focused_region();
        assert!(r.x >= 0 && (r.x as i32 + r.width as i32) <= SW as i32);
        assert!(r.y >= 0 && (r.y as i32 + r.height as i32) <= SH as i32);
    }

    #[test]
    fn arrow_down_moves_into_clock_space() {
        let mut d = Desktop::new();
        let out = d.apply_key(Key::ArrowDown).unwrap();
        match out {
            KeyOutcome::Moved { x, y, .. } => assert_eq!((x, y), (18, 5)),
            _ => panic!("expected a move"),
        }
    }

    #[test]
    fn arrow_sequence_via_ring_buffer_reports_regions() {
        // Phase-I ring buffer feeding Phase-III movement: scancodes for
        // Left then Down, applied to the live desktop, must report the menu
        // at (17,4) then (17,5).
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        st.feed(&mut buf, 0xE0);
        st.feed(&mut buf, 0x4B);
        st.feed(&mut buf, 0xE0);
        st.feed(&mut buf, 0x50);
        let first = buf.pop().unwrap();
        let second = buf.pop().unwrap();
        let InputEvent::Key(ke1) = first else {
            panic!("expected a Key event")
        };
        let InputEvent::Key(ke2) = second else {
            panic!("expected a Key event")
        };
        let mut d = Desktop::new();
        match d.apply_key(ke1.key).unwrap() {
            KeyOutcome::Moved { x, y, .. } => assert_eq!((x, y), (17, 4)),
            _ => panic!("expected a move"),
        }
        match d.apply_key(ke2.key).unwrap() {
            KeyOutcome::Moved { x, y, .. } => assert_eq!((x, y), (17, 5)),
            _ => panic!("expected a move"),
        }
    }
}
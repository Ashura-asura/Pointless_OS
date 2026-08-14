//! The shell's live desktop (roadmap §10 item 4: interactive shell). Owns
//! the window manager, the per-window framebuffers, and the composited
//! screen for the whole run, so input-driven re-composition and re-blits can
//! mutate live state instead of a one-shot boot-time demo.
//!
//! Input contract, serial-first: the input task drains the PS/2 ring buffer
//! and calls `Desktop::apply_key`. Printable keys echo into the focused shell
//! window's line (the prompt `aegis:~$ ` is rendered first; typed characters
//! follow it, with a `_` cursor); Backspace removes the last character; Enter
//! submits (clears) the line. Each applied key re-composites and re-blits,
//! and the caller prints the resulting outcome over serial (a `KeyOutcome`
//! that mirrors the echoed character into the composited screen). The shell
//! window is the default post-boot surface — there are no demo windows.
//!
//! Honest limit: the shell echoes a single command line (no scrollback yet),
//! and only characters the PS/2 driver can translate (letters, digits,
//! Space) reach the line; punctuation has no `Key` variant in the input
//! model and is dropped upstream.

use crate::compositor::{self, Cell, MAX_WINDOWS};
use crate::input::{Key, KeyEvent};
use crate::window::{Region, WindowManager};

/// Screen size in VGA text cells.
pub const SW: usize = 80;
pub const SH: usize = 25;

/// Shell window geometry (the default post-boot surface).
pub const SHELL_X: i16 = 2;
pub const SHELL_Y: i16 = 2;
pub const SHELL_W: u16 = 60;
pub const SHELL_H: u16 = 12;

/// The shell prompt rendered at the start of the shell line.
const PROMPT: &[u8] = b"aegis:~$ ";

/// Maximum length of the echoed command line (prompt + chars must fit the
/// shell window width).
const LINE_MAX: usize = (SHELL_W as usize) - PROMPT.len();

/// What a keypress did to the live desktop. The caller (input task) prints
/// it over serial as the keypress-driven analogue of the boot-time shell
/// assertion: the echoed character is visible in the composited screen.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyOutcome {
    /// A printable key was appended to the shell line at `pos`.
    Echoed { window_id: u32, ch: u8, pos: usize },
    /// Backspace removed the last character; the line now has `pos` chars.
    Backspace { window_id: u32, pos: usize },
    /// Enter submitted (cleared) a `len`-character line.
    Enter { window_id: u32, len: usize },
    /// An arrow key moved the shell window; it is now at `(x, y)` (clamped
    /// to stay fully on screen and below the title / above the status bar
    /// — see `MOVE_MIN_X`..`MOVE_MAX_Y`).
    Moved { window_id: u32, x: i16, y: i16 },
}

/// Shell-window move bounds for arrow-key handling: horizontally clamped to
/// stay fully on screen (`0..=SW-SHELL_W`), vertically clamped to stay
/// fully below the title bar (row 0) and above the status bar (row
/// `SH-1`). One cell per keypress — the same granularity every other
/// dimension in this text-mode-native project already uses.
const MOVE_MIN_X: i16 = 0;
const MOVE_MAX_X: i16 = SW as i16 - SHELL_W as i16;
const MOVE_MIN_Y: i16 = 1;
const MOVE_MAX_Y: i16 = SH as i16 - 1 - SHELL_H as i16;

/// Live shell desktop: window manager + framebuffers + composited screen.
pub struct Desktop {
    wm: WindowManager,
    fb_title: [Cell; SW],
    fb_status: [Cell; SW],
    fb_shell: [Cell; (SHELL_W as usize) * (SHELL_H as usize)],
    screen: [Cell; SW * SH],
    shell_id: u32,
    line: [u8; LINE_MAX],
    line_len: usize,
}

impl Default for Desktop {
    fn default() -> Self {
        Self::new()
    }
}

impl Desktop {
    /// Build the default post-boot desktop: title and status bars plus the
    /// focused shell window that echoes typed characters.
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
        let shell = wm
            .create_window(
                3,
                b"shell",
                Region {
                    x: SHELL_X,
                    y: SHELL_Y,
                    width: SHELL_W,
                    height: SHELL_H,
                },
            )
            .unwrap();
        wm.focus_window(shell).unwrap();

        let mut fb_title = [0u16; SW];
        for c in fb_title.iter_mut() {
            *c = 0x1F00 | b' ' as u16;
        }
        for (i, t) in b" AEGIS GRAPHICAL SHELL -- interactive shell: type to echo (80x25) -- transparent cells = blue desktop ".iter().enumerate()
        {
            if i < SW {
                fb_title[i] = 0x1F00 | *t as u16;
            }
        }
        let mut fb_status = [0u16; SW];
        for c in fb_status.iter_mut() {
            *c = 0x0F00 | b'-' as u16;
        }

        let mut d = Desktop {
            wm,
            fb_title,
            fb_status,
            fb_shell: [0u16; (SHELL_W as usize) * (SHELL_H as usize)],
            screen: [compositor::TRANSPARENT; SW * SH],
            shell_id: shell,
            line: [0u8; LINE_MAX],
            line_len: 0,
        };
        d.render_shell();
        d.composite();
        d
    }

    /// Render the shell window's framebuffer from the prompt + echoed line.
    fn render_shell(&mut self) {
        let w = SHELL_W as usize;
        for (i, c) in self.fb_shell.iter_mut().enumerate() {
            *c = 0x0F00 | if i == 0 { b' ' } else { b'.' } as u16;
        }
        let mut col = 0usize;
        for &b in PROMPT.iter() {
            if col < w {
                self.fb_shell[col] = 0x0F00 | b as u16;
            }
            col += 1;
        }
        for (i, &b) in self.line[..self.line_len].iter().enumerate() {
            let idx = col + i;
            if idx < w {
                self.fb_shell[idx] = 0x0F00 | b as u16;
            }
        }
        let cur = col + self.line_len;
        if cur < w {
            self.fb_shell[cur] = 0x0F00 | b'_' as u16;
        }
    }

    /// Re-composite the window manager + framebuffers into `screen`, then
    /// paint the desktop background over any cell the compositor left
    /// transparent (so the whole screen is the blue desktop, not a void).
    fn composite(&mut self) {
        let mut fbs: [Option<&[Cell]>; MAX_WINDOWS] = [None; MAX_WINDOWS];
        fbs[0] = Some(&self.fb_title);
        fbs[1] = Some(&self.fb_status);
        fbs[2] = Some(&self.fb_shell);
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

    /// Apply one keypress to the live desktop: printable keys echo into the
    /// shell window's line, Backspace removes the last character, Enter
    /// submits (clears) the line. Pure — re-composites in memory but does
    /// not blit, so tests can assert on `screen()`.
    pub fn apply_key(&mut self, ke: KeyEvent) -> Option<KeyOutcome> {
        match ke.key {
            Key::Backspace => {
                if self.line_len > 0 {
                    self.line_len -= 1;
                    self.render_shell();
                    self.composite();
                    Some(KeyOutcome::Backspace {
                        window_id: self.shell_id,
                        pos: self.line_len,
                    })
                } else {
                    None
                }
            }
            Key::Enter => {
                let len = self.line_len;
                self.line_len = 0;
                self.render_shell();
                self.composite();
                Some(KeyOutcome::Enter {
                    window_id: self.shell_id,
                    len,
                })
            }
            Key::ArrowUp | Key::ArrowDown | Key::ArrowLeft | Key::ArrowRight => {
                let (cur_x, cur_y) = self.wm.window(self.shell_id).map(|w| (w.region.x, w.region.y))?;
                let (dx, dy): (i16, i16) = match ke.key {
                    Key::ArrowUp => (0, -1),
                    Key::ArrowDown => (0, 1),
                    Key::ArrowLeft => (-1, 0),
                    Key::ArrowRight => (1, 0),
                    _ => unreachable!(),
                };
                let nx = (cur_x + dx).clamp(MOVE_MIN_X, MOVE_MAX_X);
                let ny = (cur_y + dy).clamp(MOVE_MIN_Y, MOVE_MAX_Y);
                self.wm.move_window(self.shell_id, nx, ny).ok()?;
                self.composite();
                Some(KeyOutcome::Moved {
                    window_id: self.shell_id,
                    x: nx,
                    y: ny,
                })
            }
            _ => {
                let ch = key_to_char(ke.key, ke.modifiers.shift)?;
                if self.line_len >= LINE_MAX {
                    return None;
                }
                self.line[self.line_len] = ch;
                self.line_len += 1;
                let pos = self.line_len - 1;
                self.render_shell();
                self.composite();
                Some(KeyOutcome::Echoed {
                    window_id: self.shell_id,
                    ch,
                    pos,
                })
            }
        }
    }

    /// Window id of the shell window.
    pub fn shell_id(&self) -> u32 {
        self.shell_id
    }
}

/// Map a `Key` to its echoed byte, honoring the left-shift modifier for
/// uppercase letters. Returns `None` for keys the shell does not echo
/// (Tab, Escape, arrows, function keys).
fn key_to_char(key: Key, shift: bool) -> Option<u8> {
    Some(match key {
        Key::A => {
            if shift {
                b'A'
            } else {
                b'a'
            }
        }
        Key::B => {
            if shift {
                b'B'
            } else {
                b'b'
            }
        }
        Key::C => {
            if shift {
                b'C'
            } else {
                b'c'
            }
        }
        Key::D => {
            if shift {
                b'D'
            } else {
                b'd'
            }
        }
        Key::E => {
            if shift {
                b'E'
            } else {
                b'e'
            }
        }
        Key::F => {
            if shift {
                b'F'
            } else {
                b'f'
            }
        }
        Key::G => {
            if shift {
                b'G'
            } else {
                b'g'
            }
        }
        Key::H => {
            if shift {
                b'H'
            } else {
                b'h'
            }
        }
        Key::I => {
            if shift {
                b'I'
            } else {
                b'i'
            }
        }
        Key::J => {
            if shift {
                b'J'
            } else {
                b'j'
            }
        }
        Key::K => {
            if shift {
                b'K'
            } else {
                b'k'
            }
        }
        Key::L => {
            if shift {
                b'L'
            } else {
                b'l'
            }
        }
        Key::M => {
            if shift {
                b'M'
            } else {
                b'm'
            }
        }
        Key::N => {
            if shift {
                b'N'
            } else {
                b'n'
            }
        }
        Key::O => {
            if shift {
                b'O'
            } else {
                b'o'
            }
        }
        Key::P => {
            if shift {
                b'P'
            } else {
                b'p'
            }
        }
        Key::Q => {
            if shift {
                b'Q'
            } else {
                b'q'
            }
        }
        Key::R => {
            if shift {
                b'R'
            } else {
                b'r'
            }
        }
        Key::S => {
            if shift {
                b'S'
            } else {
                b's'
            }
        }
        Key::T => {
            if shift {
                b'T'
            } else {
                b't'
            }
        }
        Key::U => {
            if shift {
                b'U'
            } else {
                b'u'
            }
        }
        Key::V => {
            if shift {
                b'V'
            } else {
                b'v'
            }
        }
        Key::W => {
            if shift {
                b'W'
            } else {
                b'w'
            }
        }
        Key::X => {
            if shift {
                b'X'
            } else {
                b'x'
            }
        }
        Key::Y => {
            if shift {
                b'Y'
            } else {
                b'y'
            }
        }
        Key::Z => {
            if shift {
                b'Z'
            } else {
                b'z'
            }
        }
        Key::Zero => b'0',
        Key::One => b'1',
        Key::Two => b'2',
        Key::Three => b'3',
        Key::Four => b'4',
        Key::Five => b'5',
        Key::Six => b'6',
        Key::Seven => b'7',
        Key::Eight => b'8',
        Key::Nine => b'9',
        Key::Space => b' ',
        _ => return None,
    })
}

/// The one live desktop, installed at boot after the demo assertions print.
static mut DESKTOP: Option<Desktop> = None;

/// Optional GPU pixel backend for the live desktop (Phase H). Strictly
/// additive: the text-mode VGA backend above works unconditionally, with
/// or without this. When present, every `boot_blit`/`handle_key` re-blit
/// fans the same composited `Cell` screen out to real pixels too, via
/// `gpu_compositor::blit_cells` — see that module for why this is "a
/// second output backend", not a rewrite of the compositor itself.
static mut GPU: Option<crate::gpu::BochsGpu> = None;

/// Install the live desktop.
///
/// # Safety
///
/// Single-threaded boot-time call, once.
pub unsafe fn install(d: Desktop) {
    core::ptr::addr_of_mut!(DESKTOP).write(Some(d));
}

/// Install the GPU pixel output backend (Phase H). Optional: call this
/// before or after `install`, any time before the first `boot_blit`/
/// `handle_key`, only if `gpu::BochsGpu::probe` + `set_mode` succeeded.
///
/// # Safety
///
/// Single-threaded boot-time call, once.
pub unsafe fn install_gpu(g: crate::gpu::BochsGpu) {
    core::ptr::addr_of_mut!(GPU).write(Some(g));
}

/// True if a GPU pixel backend was installed (for boot-log clarity only).
pub fn gpu_installed() -> bool {
    unsafe { core::ptr::addr_of!(GPU).as_ref() }
        .map(|o| o.is_some())
        .unwrap_or(false)
}

/// Fan `screen` out to the GPU pixel backend, if one is installed. A no-op
/// (and `gpu_compositor::blit_cells` is itself a no-op on an unset mode)
/// when there is none — the VGA text backend never depends on this.
fn gpu_blit(screen: &[Cell]) {
    if let Some(g) = unsafe { core::ptr::addr_of_mut!(GPU).as_mut() }.and_then(|o| o.as_mut()) {
        crate::gpu_compositor::blit_cells(g, screen, SW, SH);
    }
}

/// Blit the installed desktop onto the display (called once, after all boot
/// demo output has printed) — both the VGA text backend and, if installed,
/// the GPU pixel backend. Returns false if no desktop was installed.
pub fn boot_blit() -> bool {
    if let Some(d) = unsafe { core::ptr::addr_of_mut!(DESKTOP).as_mut() }.and_then(|o| o.as_mut()) {
        d.blit();
        gpu_blit(d.screen());
        true
    } else {
        false
    }
}

/// Apply one keypress to the live desktop and re-blit both backends.
/// Returns the outcome for the caller to print over serial.
pub fn handle_key(ke: KeyEvent) -> Option<KeyOutcome> {
    let d = unsafe { core::ptr::addr_of_mut!(DESKTOP).as_mut() }.and_then(|o| o.as_mut())?;
    let out = d.apply_key(ke)?;
    d.blit();
    gpu_blit(d.screen());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{InputBuffer, InputEvent};
    use crate::ps2::Ps2State;

    /// Screen index of the first character cell after the shell prompt.
    fn echo_base() -> usize {
        SHELL_Y as usize * SW + SHELL_X as usize + PROMPT.len()
    }

    #[test]
    fn boot_shell_surface_is_default() {
        let d = Desktop::new();
        // The prompt is rendered in the focused shell window.
        let prompt_cell = (d.screen()[SHELL_Y as usize * SW + SHELL_X as usize] & 0xFF) as u8;
        assert_eq!(prompt_cell, b'a');
        let status_ok = (d.screen()[(SH - 1) * SW] & 0xFF) as u8 == b'-';
        assert!(status_ok);
        // Title + status + shell: no demo windows.
        assert_eq!(d.window_count(), 3);
    }

    #[test]
    fn keystroke_echoes_through_full_path() {
        // PS/2 ring buffer path: scancodes for 'h' (0x23) then 'i' (0x17).
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        st.feed(&mut buf, 0x23);
        st.feed(&mut buf, 0x17);
        let mut d = Desktop::new();
        let mut echoed: [u8; 2] = [0; 2];
        let mut n = 0;
        while let Some(ev) = buf.pop() {
            if let InputEvent::Key(ke) = ev {
                if ke.pressed {
                    if let Some(KeyOutcome::Echoed { ch, .. }) = d.apply_key(ke) {
                        echoed[n] = ch;
                        n += 1;
                    }
                }
            }
        }
        assert_eq!(n, 2);
        assert_eq!(echoed, [b'h', b'i']);
        // The composited screen shows prompt + echoed chars.
        let base = echo_base();
        assert_eq!((d.screen()[base] & 0xFF) as u8, b'h');
        assert_eq!((d.screen()[base + 1] & 0xFF) as u8, b'i');
    }

    #[test]
    fn shift_produces_uppercase_echo() {
        let mut d = Desktop::new();
        let out = d
            .apply_key(KeyEvent {
                key: Key::A,
                pressed: true,
                modifiers: crate::input::KeyModifiers {
                    shift: true,
                    ctrl: false,
                    alt: false,
                },
            })
            .unwrap();
        match out {
            KeyOutcome::Echoed { ch, .. } => assert_eq!(ch, b'A'),
            _ => panic!("expected an echo"),
        }
        assert_eq!((d.screen()[echo_base()] & 0xFF) as u8, b'A');
    }

    #[test]
    fn backspace_removes_last_char() {
        let mut d = Desktop::new();
        d.apply_key(KeyEvent {
            key: Key::H,
            pressed: true,
            modifiers: Default::default(),
        })
        .unwrap();
        d.apply_key(KeyEvent {
            key: Key::I,
            pressed: true,
            modifiers: Default::default(),
        })
        .unwrap();
        let base = echo_base();
        assert_eq!((d.screen()[base + 1] & 0xFF) as u8, b'i');
        let out = d
            .apply_key(KeyEvent {
                key: Key::Backspace,
                pressed: true,
                modifiers: Default::default(),
            })
            .unwrap();
        match out {
            KeyOutcome::Backspace { pos, .. } => assert_eq!(pos, 1),
            _ => panic!("expected a backspace"),
        }
        // The second char is gone; the cursor now sits after 'h'.
        let cur = d.screen()[echo_base() + 1] & 0xFF;
        assert_eq!(cur as u8, b'_');
    }

    #[test]
    fn enter_clears_the_line() {
        let mut d = Desktop::new();
        d.apply_key(KeyEvent {
            key: Key::H,
            pressed: true,
            modifiers: Default::default(),
        })
        .unwrap();
        let out = d
            .apply_key(KeyEvent {
                key: Key::Enter,
                pressed: true,
                modifiers: Default::default(),
            })
            .unwrap();
        match out {
            KeyOutcome::Enter { len, .. } => assert_eq!(len, 1),
            _ => panic!("expected an enter"),
        }
        // Line cleared: the cursor is back at the prompt end.
        let cur = d.screen()[echo_base()] & 0xFF;
        assert_eq!(cur as u8, b'_');
    }

    fn arrow(key: Key) -> KeyEvent {
        KeyEvent {
            key,
            pressed: true,
            modifiers: Default::default(),
        }
    }

    #[test]
    fn arrow_key_moves_shell_window() {
        let mut d = Desktop::new();
        let out = d.apply_key(arrow(Key::ArrowRight)).unwrap();
        match out {
            KeyOutcome::Moved { window_id, x, y } => {
                assert_eq!(window_id, d.shell_id());
                assert_eq!((x, y), (SHELL_X + 1, SHELL_Y));
            }
            _ => panic!("expected a move"),
        }
        // The prompt now renders one cell to the right of its original
        // origin; the old origin cell is back to desktop background.
        let moved_cell = (d.screen()[SHELL_Y as usize * SW + SHELL_X as usize + 1] & 0xFF) as u8;
        assert_eq!(moved_cell, b'a');
        let old_cell = d.screen()[SHELL_Y as usize * SW + SHELL_X as usize];
        assert_ne!((old_cell & 0xFF) as u8, b'a');
    }

    #[test]
    fn arrow_key_move_clamps_at_minimum() {
        let mut d = Desktop::new();
        // SHELL_Y is already 2; MOVE_MIN_Y is 1, so a single Up reaches the
        // clamp and a second Up must not go any further.
        d.apply_key(arrow(Key::ArrowUp)).unwrap();
        let out = d.apply_key(arrow(Key::ArrowUp)).unwrap();
        match out {
            KeyOutcome::Moved { y, .. } => assert_eq!(y, MOVE_MIN_Y),
            _ => panic!("expected a move"),
        }
    }

    #[test]
    fn arrow_key_move_clamps_at_maximum() {
        let mut d = Desktop::new();
        // Drive far past the right edge; must clamp at MOVE_MAX_X and stay
        // fully on screen (never past SW - SHELL_W).
        for _ in 0..(SW as i16) {
            d.apply_key(arrow(Key::ArrowRight)).unwrap();
        }
        let out = d.apply_key(arrow(Key::ArrowRight)).unwrap();
        match out {
            KeyOutcome::Moved { x, .. } => assert_eq!(x, MOVE_MAX_X),
            _ => panic!("expected a move"),
        }
    }
}

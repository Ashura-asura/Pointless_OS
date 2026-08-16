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
//!
//! Phase O adds window chrome: the shell window now has a title bar (drag
//! to move), a bottom-right resize handle, and a close button; `apply_mouse`
//! hit-tests the topmost app window's chrome and drives drag/resize/close
//! state.
//!
//! Phase P adds the kernel's first real application window — a text editor
//! over the NVMe-backed store (see `editor`). Two app windows now exist:
//! the shell (id 3) and the editor (id 4, [`EDITOR_X`]..). The desktop keeps
//! an explicit [`AppFocus`] model: Tab cycles focus between the shell and
//! the editor and raises the newly-focused window's z-order (so the focused
//! window occludes the other in overlap); a mouse press on an app window's
//! content focuses that window too. Keyboard routing is per-focus: in the
//! shell, printable keys echo / Backspace / Enter / arrows move the window;
//! in the editor, printable keys and Enter insert at the cursor, Backspace
//! deletes, arrows move the cursor, and F2 saves the buffer to `memo.txt`
//! through the boot-time `editor::EditorFs`. The editor starts from the
//! seeded file when durable storage is present, else from the seed bytes
//! in memory (UI only).

use crate::compositor::{self, Cell, MAX_WINDOWS};
use crate::editor::{self, Editor, EDITOR_BUF_MAX};
use crate::input::{Key, KeyEvent, MouseEvent};
use crate::window::{Region, WindowManager};

/// Screen size in VGA text cells.
pub const SW: usize = 80;
pub const SH: usize = 25;

/// Shell window geometry (the default post-boot surface).
pub const SHELL_X: i16 = 2;
pub const SHELL_Y: i16 = 2;
pub const SHELL_W: u16 = 60;
pub const SHELL_H: u16 = 12;

/// Editor window geometry (Phase P: the second app window). Chosen to
/// overlap the shell (x 10..61, y 6..13) so z-order does real occlusion
/// work: the focused window covers the other there, and the unfocused
/// editor's visible area is its non-overlapped band (columns 61..65 and
/// rows 14..19), which is what a click can reach when the shell is focused.
pub const EDITOR_X: i16 = 10;
pub const EDITOR_Y: i16 = 6;
pub const EDITOR_W: u16 = 56;
pub const EDITOR_H: u16 = 14;

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
    /// Tab cycled focus; `editor` is true when the editor window (id 4) is
    /// now focused and raised, false when focus returned to the shell.
    Focused { window_id: u32, editor: bool },
    /// A character was inserted into the focused editor at byte `pos`.
    Edited { window_id: u32, ch: u8, pos: usize },
    /// An arrow key moved the focused editor's cursor; it is now at `pos`.
    CursorMoved { window_id: u32, pos: usize },
    /// F2 saved the focused editor buffer (F2 is the save gesture): `len`
    /// bytes were written to `memo.txt` in the boot view; `block` is the
    /// first four bytes of the content block's digest (all-zero when no
    /// durable store is present — the in-memory fallback reports honestly).
    Saved {
        window_id: u32,
        len: usize,
        block: [u8; 4],
    },
}

/// Which app window owns keyboard input. Tab cycles this; a mouse press on
/// an app window's content sets it too. The default post-boot focus is the
/// shell (the editor is created below it in z-order and only raises when
/// focused).
#[derive(Debug, Clone, Copy, PartialEq)]
enum AppFocus {
    Shell,
    Editor,
}

/// What a mouse event did to the live desktop. The caller (input task)
/// prints it over serial.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MouseOutcome {
    /// The cursor is at `(x, y)` with the reported button latches (no
    /// window-chrome action).
    Moved {
        x: i16,
        y: i16,
        left: bool,
        right: bool,
    },
    /// A title-bar drag moved the window to `(x, y)`.
    DragMoved { window_id: u32, x: i16, y: i16 },
    /// A corner drag resized the window to `width` x `height`.
    Resized {
        window_id: u32,
        width: u16,
        height: u16,
    },
    /// The close button was released: the window is destroyed.
    Closed { window_id: u32 },
}

/// Minimum window size a corner drag can shrink an app window to.
const MIN_W: i16 = 20;
const MIN_H: i16 = 5;

/// An in-progress window-chrome drag (Phase O). Set on a left press over an
/// app window's chrome, cleared on release.
#[derive(Debug, Clone, Copy, PartialEq)]
enum DragState {
    /// Dragging the title bar: the window follows the cursor, keeping the
    /// grab offset (in cells) between the press point and the window origin.
    Move {
        window_id: u32,
        grab_dx: i16,
        grab_dy: i16,
    },
    /// Dragging the bottom-right corner: the window resizes to follow the
    /// cursor, clamped to the minimum and to the framebuffer/screen.
    Resize { window_id: u32 },
    /// Pressed the close button: the window is destroyed on release.
    Close { window_id: u32 },
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
    fb_editor: [Cell; (EDITOR_W as usize) * (EDITOR_H as usize)],
    screen: [Cell; SW * SH],
    shell_id: u32,
    editor_id: u32,
    editor: Editor,
    focus: AppFocus,
    line: [u8; LINE_MAX],
    line_len: usize,
    drag: Option<DragState>,
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
        let editor = wm
            .create_window(
                4,
                b"editor",
                Region {
                    x: EDITOR_X,
                    y: EDITOR_Y,
                    width: EDITOR_W,
                    height: EDITOR_H,
                },
            )
            .unwrap();
        // The shell is the default post-boot surface: focused AND raised, so
        // it occludes the editor across their overlap until the editor is
        // focused (Tab or a click on its content).
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
            fb_editor: [0u16; (EDITOR_W as usize) * (EDITOR_H as usize)],
            screen: [compositor::TRANSPARENT; SW * SH],
            shell_id: shell,
            editor_id: editor,
            editor: Desktop::editor_initial(),
            focus: AppFocus::Shell,
            line: [0u8; LINE_MAX],
            line_len: 0,
            drag: None,
        };
        d.render_shell();
        d.render_editor();
        d.composite();
        d
    }

    /// The editor's initial buffer: the saved `memo.txt` when a durable
    /// editor file handle was installed at boot (reopen-after-reboot), else
    /// the seed bytes so the in-memory fallback still shows content.
    fn editor_initial() -> Editor {
        if editor::durable() {
            let mut buf = [0u8; EDITOR_BUF_MAX];
            if let Some(n) = editor::with(|fs| fs.read_memo(&mut buf)).flatten() {
                return Editor::from_bytes(&buf[..n]);
            }
        }
        Editor::from_bytes(editor::SEED)
    }

    /// Render the shell window's framebuffer from its current size: row 0 is
    /// the title bar ("Shell" + a close button at the last cell), row 1 holds
    /// the prompt + echoed line + cursor. Re-rendered on every resize so the
    /// title bar and prompt stay aligned with the window's current width (the
    /// compositor indexes framebuffers by the window's current region width).
    fn render_shell(&mut self) {
        let (w, h) = self
            .wm
            .window(self.shell_id)
            .map(|w| (w.region.width as usize, w.region.height as usize))
            .unwrap_or((SHELL_W as usize, SHELL_H as usize));
        let total = w * h;
        for c in self.fb_shell[..total].iter_mut() {
            *c = 0x0F00 | b'.' as u16;
        }
        // Title bar (row 0): "Shell" + close button at the last cell.
        for i in 0..w {
            self.fb_shell[i] = 0x1F00 | b' ' as u16;
        }
        for (i, t) in b"Shell".iter().enumerate() {
            if i + 1 < w {
                self.fb_shell[i] = 0x1F00 | *t as u16;
            }
        }
        if w > 0 {
            self.fb_shell[w - 1] = 0x4F00 | b'X' as u16;
        }
        // Prompt + line + cursor on content row 1.
        let mut col = 0usize;
        for &b in PROMPT.iter() {
            if col < w {
                self.fb_shell[w + col] = 0x0F00 | b as u16;
            }
            col += 1;
        }
        for (i, &b) in self.line[..self.line_len].iter().enumerate() {
            let idx = w + col + i;
            if idx < total {
                self.fb_shell[idx] = 0x0F00 | b as u16;
            }
        }
        let cur = w + col + self.line_len;
        if cur < total {
            self.fb_shell[cur] = 0x0F00 | b'_' as u16;
        }
    }

    /// Render the editor window's framebuffer from its current size: row 0
    /// is the title bar ("Editor: memo.txt" + a close button at the last
    /// cell); the rows below paint the wrapped buffer via
    /// `Editor::visual_row` (the pure line-wrapping math), one visual row
    /// per window row, with the cursor drawn as `_` where it sits. Cells
    /// past the end of content keep the dotted fill.
    fn render_editor(&mut self) {
        let (w, h) = self
            .wm
            .window(self.editor_id)
            .map(|w| (w.region.width as usize, w.region.height as usize))
            .unwrap_or((EDITOR_W as usize, EDITOR_H as usize));
        let total = w * h;
        for c in self.fb_editor[..total].iter_mut() {
            *c = 0x0F00 | b'.' as u16;
        }
        // Title bar (row 0): "Editor: memo.txt" + close button at the last cell.
        for i in 0..w {
            self.fb_editor[i] = 0x1F00 | b' ' as u16;
        }
        for (i, t) in b"Editor: memo.txt".iter().enumerate() {
            if i + 1 < w {
                self.fb_editor[i] = 0x1F00 | *t as u16;
            }
        }
        if w > 0 {
            self.fb_editor[w - 1] = 0x4F00 | b'X' as u16;
        }
        // Content: one visual row per window row, wrapped by the width.
        let bytes = self.editor.as_bytes();
        for r in 0..h.saturating_sub(1) {
            if let Some((start, end, cursor_col)) = self.editor.visual_row(r, w) {
                let row_base = (r + 1) * w;
                for (i, &b) in bytes[start..end].iter().enumerate() {
                    if row_base + i < total {
                        self.fb_editor[row_base + i] = 0x0F00 | b as u16;
                    }
                }
                if let Some(col) = cursor_col {
                    let idx = row_base + col.min(w.saturating_sub(1));
                    if idx < total {
                        self.fb_editor[idx] = 0x0F00 | b'_' as u16;
                    }
                }
            }
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
        fbs[3] = Some(&self.fb_editor);
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

    /// Apply one keypress to the live desktop. Tab cycles focus (raising the
    /// newly-focused window); otherwise the key goes to whichever app window
    /// owns focus (see `apply_key_shell` / `apply_key_editor`). Pure —
    /// re-composites in memory but does not blit, so tests can assert on
    /// `screen()`.
    pub fn apply_key(&mut self, ke: KeyEvent) -> Option<KeyOutcome> {
        if ke.key == Key::Tab {
            return Some(self.cycle_focus());
        }
        match self.focus {
            AppFocus::Shell => self.apply_key_shell(ke),
            AppFocus::Editor => self.apply_key_editor(ke),
        }
    }

    /// Cycle keyboard focus between the shell and the editor, raising the
    /// newly-focused window's z-order so it occludes the other in overlap.
    fn cycle_focus(&mut self) -> KeyOutcome {
        match self.focus {
            AppFocus::Shell => {
                self.focus = AppFocus::Editor;
                let _ = self.wm.focus_window(self.editor_id);
                self.render_editor();
                self.composite();
                KeyOutcome::Focused {
                    window_id: self.editor_id,
                    editor: true,
                }
            }
            AppFocus::Editor => {
                self.focus = AppFocus::Shell;
                let _ = self.wm.focus_window(self.shell_id);
                self.render_shell();
                self.composite();
                KeyOutcome::Focused {
                    window_id: self.shell_id,
                    editor: false,
                }
            }
        }
    }

    /// Shell-focused keys: printable keys echo into the shell window's line,
    /// Backspace removes the last character, Enter submits (clears) the line,
    /// arrows move the shell window.
    fn apply_key_shell(&mut self, ke: KeyEvent) -> Option<KeyOutcome> {
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
                let (cur_x, cur_y) = self
                    .wm
                    .window(self.shell_id)
                    .map(|w| (w.region.x, w.region.y))?;
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

    /// Editor-focused keys: printable keys and Enter insert at the cursor,
    /// Backspace deletes the previous byte, arrows move the cursor, and F2
    /// saves the buffer to `memo.txt` through the boot-time editor file
    /// handle (the Phase P save gesture).
    fn apply_key_editor(&mut self, ke: KeyEvent) -> Option<KeyOutcome> {
        match ke.key {
            Key::Backspace => {
                if self.editor.backspace() {
                    self.render_editor();
                    self.composite();
                    Some(KeyOutcome::Backspace {
                        window_id: self.editor_id,
                        pos: self.editor.cursor(),
                    })
                } else {
                    None
                }
            }
            Key::Enter => {
                if self.editor.insert(b'\n') {
                    self.render_editor();
                    self.composite();
                    Some(KeyOutcome::Edited {
                        window_id: self.editor_id,
                        ch: b'\n',
                        pos: self.editor.cursor() - 1,
                    })
                } else {
                    None
                }
            }
            Key::F2 => Some(self.save_editor()),
            Key::ArrowUp | Key::ArrowDown | Key::ArrowLeft | Key::ArrowRight => {
                let moved = match ke.key {
                    Key::ArrowUp => self.editor.cursor_up(),
                    Key::ArrowDown => self.editor.cursor_down(),
                    Key::ArrowLeft => self.editor.cursor_left(),
                    Key::ArrowRight => self.editor.cursor_right(),
                    _ => false,
                };
                if moved {
                    self.render_editor();
                    self.composite();
                    Some(KeyOutcome::CursorMoved {
                        window_id: self.editor_id,
                        pos: self.editor.cursor(),
                    })
                } else {
                    None
                }
            }
            _ => {
                let ch = key_to_char(ke.key, ke.modifiers.shift)?;
                if self.editor.insert(ch) {
                    self.render_editor();
                    self.composite();
                    Some(KeyOutcome::Edited {
                        window_id: self.editor_id,
                        ch,
                        pos: self.editor.cursor() - 1,
                    })
                } else {
                    None
                }
            }
        }
    }

    /// F2: write the editor buffer to `memo.txt` in the boot view. With a
    /// durable handle this commits a new content block (+ COW dir block) to
    /// the NVMe store; without one (tests, no NVMe) the buffer is unchanged
    /// and the outcome reports the digest as all-zero — honest about the
    /// in-memory fallback.
    fn save_editor(&mut self) -> KeyOutcome {
        let len = self.editor.len();
        let mut bytes = [0u8; EDITOR_BUF_MAX];
        bytes[..len].copy_from_slice(self.editor.as_bytes());
        let block = editor::with(|fs| fs.write_memo(&bytes[..len]))
            .flatten()
            .unwrap_or([0u8; 32]);
        self.render_editor();
        self.composite();
        KeyOutcome::Saved {
            window_id: self.editor_id,
            len,
            block: [block[0], block[1], block[2], block[3]],
        }
    }

    /// Apply one mouse event to the live desktop. A left press on the
    /// topmost app window's chrome starts a drag (title bar = move, bottom-
    /// right corner = resize, close button = close on release); during a
    /// drag the window follows the cursor, clamped to the screen and, for a
    /// resize, to the minimum size and the window's framebuffer. A release
    /// ends the drag; presses anywhere else report the position instead.
    pub fn apply_mouse(&mut self, me: MouseEvent) -> Option<MouseOutcome> {
        let (cx, cy) = pixel_to_cell(me.x, me.y);
        if let Some(drag) = self.drag {
            if !me.left_button {
                // Release completes the drag.
                match drag {
                    DragState::Close { window_id } => {
                        self.drag = None;
                        let _ = self.wm.destroy_window(window_id);
                        self.composite();
                        return Some(MouseOutcome::Closed { window_id });
                    }
                    DragState::Move { .. } | DragState::Resize { .. } => {
                        self.drag = None;
                        return None;
                    }
                }
            }
            match drag {
                DragState::Move {
                    window_id,
                    grab_dx,
                    grab_dy,
                } => {
                    let (w, h) = self
                        .wm
                        .window(window_id)
                        .map(|w| (w.region.width as i16, w.region.height as i16))?;
                    let nx = (cx - grab_dx).clamp(0, SW as i16 - w);
                    let ny = (cy - grab_dy).clamp(1, SH as i16 - 1 - h);
                    self.wm.move_window(window_id, nx, ny).ok()?;
                    self.composite();
                    Some(MouseOutcome::DragMoved {
                        window_id,
                        x: nx,
                        y: ny,
                    })
                }
                DragState::Resize { window_id } => {
                    let (x, y) = self
                        .wm
                        .window(window_id)
                        .map(|w| (w.region.x, w.region.y))?;
                    let (fw, fh) = self.framebuffer_dims(window_id);
                    let nw = (cx - x + 1).clamp(MIN_W, (SW as i16 - x).min(fw));
                    let nh = (cy - y + 1).clamp(MIN_H, (SH as i16 - 1 - y).min(fh));
                    self.wm
                        .resize_window(window_id, nw as u16, nh as u16)
                        .ok()?;
                    // Re-render the resized window (title bar + content must
                    // follow the new width/height), not the shell blindly.
                    self.render_window(window_id);
                    self.composite();
                    Some(MouseOutcome::Resized {
                        window_id,
                        width: nw as u16,
                        height: nh as u16,
                    })
                }
                DragState::Close { .. } => None,
            }
        } else if me.left_button {
            if let Some(id) = self.wm.hit_test(cx, cy) {
                if self.is_app_window(id) {
                    if let Some(w) = self.wm.window(id) {
                        let (wx, wy, ww, wh) = (
                            w.region.x,
                            w.region.y,
                            w.region.width as i16,
                            w.region.height as i16,
                        );
                        if cx == wx + ww - 1 && cy == wy {
                            self.drag = Some(DragState::Close { window_id: id });
                            return None;
                        }
                        if cx == wx + ww - 1 && cy == wy + wh - 1 {
                            self.drag = Some(DragState::Resize { window_id: id });
                            return None;
                        }
                        if cy == wy {
                            self.drag = Some(DragState::Move {
                                window_id: id,
                                grab_dx: cx - wx,
                                grab_dy: cy - wy,
                            });
                            return None;
                        }
                    }
                    // A press on an app window's content (not its chrome)
                    // focuses that window: it takes keyboard input and is
                    // raised above the other app window.
                    self.focus_content_press(id);
                }
            }
            Some(MouseOutcome::Moved {
                x: me.x,
                y: me.y,
                left: true,
                right: me.right_button,
            })
        } else {
            Some(MouseOutcome::Moved {
                x: me.x,
                y: me.y,
                left: false,
                right: me.right_button,
            })
        }
    }

    /// Window id of the shell window.
    pub fn shell_id(&self) -> u32 {
        self.shell_id
    }

    /// Window id of the editor window.
    pub fn editor_id(&self) -> u32 {
        self.editor_id
    }

    /// Re-render the app window `id` from its current size.
    fn render_window(&mut self, id: u32) {
        if id == self.shell_id {
            self.render_shell();
        } else if id == self.editor_id {
            self.render_editor();
        }
    }

    /// Focus `id` on a mouse press over its content: keyboard input follows,
    /// and the window is raised above the other app window. A no-op when the
    /// window already owns focus.
    fn focus_content_press(&mut self, id: u32) {
        let next = if id == self.editor_id {
            AppFocus::Editor
        } else {
            AppFocus::Shell
        };
        if next != self.focus {
            self.focus = next;
            let _ = self.wm.focus_window(id);
            self.render_window(id);
            self.composite();
        }
    }

    /// True if `id` is a draggable app window (Phase O/P: the shell window
    /// and the editor window).
    fn is_app_window(&self, id: u32) -> bool {
        id == self.shell_id || id == self.editor_id
    }

    /// The framebuffer dimensions backing an app window (the ceiling a corner
    /// drag may resize it to). Each app window has its own fixed framebuffer.
    fn framebuffer_dims(&self, id: u32) -> (i16, i16) {
        if id == self.shell_id {
            (SHELL_W as i16, SHELL_H as i16)
        } else if id == self.editor_id {
            (EDITOR_W as i16, EDITOR_H as i16)
        } else {
            (0, 0)
        }
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

/// Pixel offset of the centered cell image within the GPU framebuffer
/// (Phase O): the mouse reports pixel coordinates, the window manager works
/// in cells. Set by `install_gpu` from the mode; (0,0) in tests.
static mut CELL_OFFSET: (i16, i16) = (0, 0);

/// Convert a GPU pixel coordinate to a screen cell coordinate, honoring the
/// centered-cell-image offset installed by `install_gpu`.
fn pixel_to_cell(px: i16, py: i16) -> (i16, i16) {
    let (ox, oy) = unsafe { core::ptr::addr_of!(CELL_OFFSET).read() };
    ((px - ox) / 8, (py - oy) / 16)
}

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
pub unsafe fn install_gpu(mut g: crate::gpu::BochsGpu) {
    if let Some((_, mode)) = g.framebuffer_mut() {
        let ox = ((mode.width as i16).saturating_sub(SW as i16 * 8)) / 2;
        let oy = ((mode.height as i16).saturating_sub(SH as i16 * 16)) / 2;
        core::ptr::addr_of_mut!(CELL_OFFSET).write((ox, oy));
    }
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
/// when there is none — the VGA text backend never depends on this. The
/// mouse cursor sprite is composited on top each frame: the full-screen
/// `blit_cells` redraw restores the pixels under the old cursor, so no
/// trails.
fn gpu_blit(screen: &[Cell]) {
    if let Some(g) = unsafe { core::ptr::addr_of_mut!(GPU).as_mut() }.and_then(|o| o.as_mut()) {
        crate::gpu_compositor::blit_cells(g, screen, SW, SH);
        let (cx, cy) = crate::ps2_mouse::cursor_pos();
        if let Some((fb, mode)) = g.framebuffer_mut() {
            crate::cursor::draw_cursor(fb, &mode, cx, cy);
        }
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

/// Apply one mouse event to the live desktop and re-blit both backends.
/// Returns the outcome for the caller to print over serial.
pub fn handle_mouse(me: MouseEvent) -> Option<MouseOutcome> {
    let d = unsafe { core::ptr::addr_of_mut!(DESKTOP).as_mut() }.and_then(|o| o.as_mut())?;
    let out = d.apply_mouse(me)?;
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
        (SHELL_Y + 1) as usize * SW + SHELL_X as usize + PROMPT.len()
    }

    #[test]
    fn boot_shell_surface_is_default() {
        let d = Desktop::new();
        // Title bar first cell is 'S' (of "Shell"); the prompt moved to row 1.
        let title_cell = (d.screen()[SHELL_Y as usize * SW + SHELL_X as usize] & 0xFF) as u8;
        assert_eq!(title_cell, b'S');
        let prompt_cell = (d.screen()[(SHELL_Y + 1) as usize * SW + SHELL_X as usize] & 0xFF) as u8;
        assert_eq!(prompt_cell, b'a');
        // Close button at the title bar's last cell.
        let close_cell = (d.screen()
            [SHELL_Y as usize * SW + SHELL_X as usize + SHELL_W as usize - 1]
            & 0xFF) as u8;
        assert_eq!(close_cell, b'X');
        let status_ok = (d.screen()[(SH - 1) * SW] & 0xFF) as u8 == b'-';
        assert!(status_ok);
        // Title + status + shell + editor: no demo windows.
        assert_eq!(d.window_count(), 4);
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
        let moved_cell =
            (d.screen()[(SHELL_Y + 1) as usize * SW + SHELL_X as usize + 1] & 0xFF) as u8;
        assert_eq!(moved_cell, b'a');
        let old_cell = d.screen()[(SHELL_Y + 1) as usize * SW + SHELL_X as usize];
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

    #[test]
    fn mouse_outcome_reports_event() {
        let mut d = Desktop::new();
        // Press on the global title bar (cell (0,0)): not an app window, so it
        // reports position rather than starting a drag.
        let out = d.apply_mouse(MouseEvent {
            x: 0,
            y: 0,
            left_button: true,
            right_button: false,
            scroll: 0,
        });
        assert_eq!(
            out,
            Some(MouseOutcome::Moved {
                x: 0,
                y: 0,
                left: true,
                right: false,
            })
        );
    }

    #[test]
    fn mouse_drag_moves_shell_window() {
        let mut d = Desktop::new();
        // Press on the title bar (cell (10,2) -> pixel (80,32)).
        let press = d.apply_mouse(MouseEvent {
            x: 80,
            y: 32,
            left_button: true,
            right_button: false,
            scroll: 0,
        });
        assert_eq!(press, None); // drag started, no visual change yet
                                 // Drag to cell (20,2) -> pixel (160,32): grab_dx = 10-2 = 8, new x = 20-8 = 12.
        let out = d
            .apply_mouse(MouseEvent {
                x: 160,
                y: 32,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::DragMoved { window_id, x, y } => {
                assert_eq!(window_id, d.shell_id());
                assert_eq!((x, y), (12, 2));
            }
            _ => panic!("expected a drag move"),
        }
        // Release ends the drag.
        let rel = d.apply_mouse(MouseEvent {
            x: 160,
            y: 32,
            left_button: false,
            right_button: false,
            scroll: 0,
        });
        assert_eq!(rel, None);
        let (wx, wy) =
            d.wm.window(d.shell_id())
                .map(|w| (w.region.x, w.region.y))
                .unwrap();
        assert_eq!((wx, wy), (12, 2));
    }

    #[test]
    fn mouse_drag_clamps_on_screen() {
        let mut d = Desktop::new();
        // Press on the title bar and drag far up-left: must clamp to (0,1).
        d.apply_mouse(MouseEvent {
            x: 80,
            y: 32,
            left_button: true,
            right_button: false,
            scroll: 0,
        });
        let out = d
            .apply_mouse(MouseEvent {
                x: 0,
                y: 0,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::DragMoved { x, y, .. } => assert_eq!((x, y), (0, 1)),
            _ => panic!("expected a drag move"),
        }
        d.apply_mouse(MouseEvent {
            x: 0,
            y: 0,
            left_button: false,
            right_button: false,
            scroll: 0,
        });
        let (wx, wy) =
            d.wm.window(d.shell_id())
                .map(|w| (w.region.x, w.region.y))
                .unwrap();
        assert_eq!((wx, wy), (0, 1));
    }

    #[test]
    fn mouse_resize_changes_size() {
        let mut d = Desktop::new();
        // Press on the resize handle (cell (61,13) -> pixel (488,208)).
        d.apply_mouse(MouseEvent {
            x: 488,
            y: 208,
            left_button: true,
            right_button: false,
            scroll: 0,
        });
        // Drag to cell (56,11) -> pixel (448,176): new size (56-2+1, 11-2+1) = (55,10).
        let out = d
            .apply_mouse(MouseEvent {
                x: 448,
                y: 176,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::Resized {
                window_id,
                width,
                height,
            } => {
                assert_eq!(window_id, d.shell_id());
                assert_eq!((width, height), (55, 10));
            }
            _ => panic!("expected a resize"),
        }
        d.apply_mouse(MouseEvent {
            x: 448,
            y: 176,
            left_button: false,
            right_button: false,
            scroll: 0,
        });
        let (w, h) =
            d.wm.window(d.shell_id())
                .map(|w| (w.region.width, w.region.height))
                .unwrap();
        assert_eq!((w, h), (55, 10));
    }

    #[test]
    fn mouse_resize_clamps_to_minimum() {
        let mut d = Desktop::new();
        d.apply_mouse(MouseEvent {
            x: 488,
            y: 208,
            left_button: true,
            right_button: false,
            scroll: 0,
        });
        // Drag to cell (2,2) -> pixel (16,32): raw size (1,1) clamps to MIN.
        let out = d
            .apply_mouse(MouseEvent {
                x: 16,
                y: 32,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::Resized { width, height, .. } => {
                assert_eq!((width, height), (MIN_W as u16, MIN_H as u16))
            }
            _ => panic!("expected a resize"),
        }
    }

    #[test]
    fn mouse_resize_cannot_exceed_framebuffer() {
        let mut d = Desktop::new();
        d.apply_mouse(MouseEvent {
            x: 488,
            y: 208,
            left_button: true,
            right_button: false,
            scroll: 0,
        });
        // Drag to cell (79,24) -> pixel (632,384): raw size (78,23) clamps to
        // min(SW-x, SHELL_W) x min(SH-1-y, SHELL_H) = (60,12).
        let out = d
            .apply_mouse(MouseEvent {
                x: 632,
                y: 384,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::Resized { width, height, .. } => {
                assert_eq!((width, height), (SHELL_W, SHELL_H))
            }
            _ => panic!("expected a resize"),
        }
    }

    #[test]
    fn mouse_close_destroys_window() {
        let mut d = Desktop::new();
        assert_eq!(d.window_count(), 4);
        // Press the close button (cell (61,2) -> pixel (488,32)).
        d.apply_mouse(MouseEvent {
            x: 488,
            y: 32,
            left_button: true,
            right_button: false,
            scroll: 0,
        });
        // Release: the window is destroyed.
        let out = d
            .apply_mouse(MouseEvent {
                x: 488,
                y: 32,
                left_button: false,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::Closed { window_id } => assert_eq!(window_id, d.shell_id()),
            _ => panic!("expected a close"),
        }
        assert_eq!(d.window_count(), 3);
        assert!(d.wm.window(d.shell_id()).is_none());
    }

    #[test]
    fn mouse_press_on_content_does_not_drag() {
        let mut d = Desktop::new();
        // Press on content (cell (10,5) -> pixel (80,80)): not chrome, no drag.
        let out = d
            .apply_mouse(MouseEvent {
                x: 80,
                y: 80,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::Moved { x, y, left, .. } => assert_eq!((x, y, left), (80, 80, true)),
            _ => panic!("expected a move report"),
        }
        let (wx, wy) =
            d.wm.window(d.shell_id())
                .map(|w| (w.region.x, w.region.y))
                .unwrap();
        assert_eq!((wx, wy), (SHELL_X, SHELL_Y));
    }

    #[test]
    fn mouse_release_without_drag_is_harmless() {
        let mut d = Desktop::new();
        let out = d
            .apply_mouse(MouseEvent {
                x: 80,
                y: 80,
                left_button: false,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::Moved { left, .. } => assert!(!left),
            _ => panic!("expected a move report"),
        }
    }

    fn key(key: Key) -> KeyEvent {
        KeyEvent {
            key,
            pressed: true,
            modifiers: Default::default(),
        }
    }

    #[test]
    fn editor_window_is_second_app_window() {
        let d = Desktop::new();
        assert_eq!(d.window_count(), 4);
        let w = d.wm.window(d.editor_id()).unwrap();
        assert_eq!(
            (w.region.x, w.region.y, w.region.width, w.region.height),
            (EDITOR_X, EDITOR_Y, EDITOR_W, EDITOR_H)
        );
    }

    #[test]
    fn tab_cycles_focus_and_raises_editor() {
        let mut d = Desktop::new();
        // Tab -> editor focused and raised: its title 'E' is now the topmost
        // cell at (10,6) (the shell previously occluded that cell).
        let out = d.apply_key(key(Key::Tab)).unwrap();
        match out {
            KeyOutcome::Focused {
                window_id,
                editor: true,
            } => assert_eq!(window_id, d.editor_id()),
            _ => panic!("expected focus on the editor"),
        }
        assert_eq!(
            (d.screen()[EDITOR_Y as usize * SW + EDITOR_X as usize] & 0xFF) as u8,
            b'E'
        );
        // Tab -> shell refocused and raised: the shell occludes (10,6) again.
        let out = d.apply_key(key(Key::Tab)).unwrap();
        match out {
            KeyOutcome::Focused {
                window_id,
                editor: false,
            } => assert_eq!(window_id, d.shell_id()),
            _ => panic!("expected focus back on the shell"),
        }
        assert_ne!(
            (d.screen()[EDITOR_Y as usize * SW + EDITOR_X as usize] & 0xFF) as u8,
            b'E'
        );
    }

    #[test]
    fn editor_typing_edits_buffer_and_screen() {
        let mut d = Desktop::new();
        d.apply_key(key(Key::Tab)).unwrap();
        // The editor starts from the seed; typing appends at cursor 24.
        let o1 = d.apply_key(key(Key::X)).unwrap();
        match o1 {
            KeyOutcome::Edited { window_id, ch, pos } => {
                assert_eq!(window_id, d.editor_id());
                assert_eq!((ch, pos), (b'x', 24));
            }
            _ => panic!("expected an edit"),
        }
        let o2 = d.apply_key(key(Key::Y)).unwrap();
        match o2 {
            KeyOutcome::Edited { ch, pos, .. } => assert_eq!((ch, pos), (b'y', 25)),
            _ => panic!("expected an edit"),
        }
        // Both chars are visible in the composited editor content row.
        let base = (EDITOR_Y as usize + 1) * SW + EDITOR_X as usize;
        assert_eq!((d.screen()[base + 24] & 0xFF) as u8, b'x');
        assert_eq!((d.screen()[base + 25] & 0xFF) as u8, b'y');
        // Backspace removes the last typed byte and moves the cursor back.
        let b = d.apply_key(key(Key::Backspace)).unwrap();
        match b {
            KeyOutcome::Backspace { window_id, pos } => {
                assert_eq!(window_id, d.editor_id());
                assert_eq!(pos, 25);
            }
            _ => panic!("expected a backspace"),
        }
    }

    #[test]
    fn editor_arrow_keys_move_cursor() {
        let mut d = Desktop::new();
        d.apply_key(key(Key::Tab)).unwrap();
        d.apply_key(key(Key::X)).unwrap();
        d.apply_key(key(Key::Y)).unwrap();
        let l = d.apply_key(key(Key::ArrowLeft)).unwrap();
        match l {
            KeyOutcome::CursorMoved { window_id, pos } => {
                assert_eq!(window_id, d.editor_id());
                assert_eq!(pos, 25);
            }
            _ => panic!("expected a cursor move"),
        }
        let r = d.apply_key(key(Key::ArrowRight)).unwrap();
        match r {
            KeyOutcome::CursorMoved { pos, .. } => assert_eq!(pos, 26),
            _ => panic!("expected a cursor move"),
        }
    }

    #[test]
    fn editor_enter_inserts_newline() {
        let mut d = Desktop::new();
        d.apply_key(key(Key::Tab)).unwrap();
        // Enter at the end of the seed (24 bytes) inserts '\n' at pos 24.
        let o = d.apply_key(key(Key::Enter)).unwrap();
        match o {
            KeyOutcome::Edited { ch, pos, .. } => assert_eq!((ch, pos), (b'\n', 24)),
            _ => panic!("expected an edit"),
        }
        // The cursor now sits on the empty second line; typing lands there.
        let h = d.apply_key(key(Key::H)).unwrap();
        match h {
            KeyOutcome::Edited { ch, pos, .. } => assert_eq!((ch, pos), (b'h', 25)),
            _ => panic!("expected an edit"),
        }
        // Up from line 2 col 1 returns to line 1, column clamped to the
        // line's length... here clamped to col 1 of the seed line.
        let up = d.apply_key(key(Key::ArrowUp)).unwrap();
        match up {
            KeyOutcome::CursorMoved { pos, .. } => assert_eq!(pos, 1),
            _ => panic!("expected a cursor move"),
        }
    }

    #[test]
    fn f2_save_reports_buffer_len_and_honest_block() {
        let mut d = Desktop::new();
        d.apply_key(key(Key::Tab)).unwrap();
        d.apply_key(key(Key::X)).unwrap();
        d.apply_key(key(Key::Y)).unwrap();
        let s = d.apply_key(key(Key::F2)).unwrap();
        match s {
            KeyOutcome::Saved {
                window_id,
                len,
                block,
            } => {
                assert_eq!(window_id, d.editor_id());
                // Seed (24) + 2 typed bytes. No durable handle is installed in
                // tests, so the block digest is honestly all-zero.
                assert_eq!(len, 26);
                assert_eq!(block, [0u8; 4]);
            }
            _ => panic!("expected a save"),
        }
    }
}

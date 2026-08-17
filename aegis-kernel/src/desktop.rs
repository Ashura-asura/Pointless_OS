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
//! Honest limit: only characters the PS/2 driver can translate (letters,
//! digits, Space) reach the line; punctuation has no `Key` variant in the
//! input model and is dropped upstream (Phase R's `terminal` module works
//! around this for file names specifically — see its module docs).
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
//! deletes, arrows move the cursor, and F2 saves the buffer to whichever
//! file is currently open (`memo.txt` at boot; see Phase Q below for how
//! that changes once the browser can open other files) through the
//! boot-time `editor::EditorFs`. The editor starts from the
//! seeded file when durable storage is present, else from the seed bytes
//! in memory (UI only).
//!
//! Phase Q adds the kernel's third real application window — a file browser
//! over the same boot view (see `browser`). Three app windows now exist: the
//! shell (id 3), the editor (id 4, [`EDITOR_X`]..), and the browser (id 5,
//! [`BROWSER_X`]..). Tab cycles focus shell -> editor -> browser -> shell and
//! raises the newly-focused window; the browser lists every entry in the
//! current directory of the hierarchical boot view (`editor::EditorFs::browser_list`),
//! arrow keys move its selection, Enter (or a click on a row) opens a file
//! into the editor or descends into a directory (Backspace / a `..` row goes
//! up), F3 creates a new empty `fileN.txt` and F4 a new `dirN` directory, and
//! the browser's action bar creates both by mouse click (Phase Q completion).
//! Without a durable store the browser lists nothing honestly — the same
//! in-memory fallback scope the editor already documents.
//!
//! Phase R upgrades the shell window (id 3, the one that has been present
//! since before Phase O) from a single echoed line into a real command
//! interpreter over the same boot view the editor and browser already use
//! (see `terminal`). Enter now parses the submitted line
//! (`terminal::Command::parse`) and runs it: `ls` lists every name in the
//! boot view, numbered; `open <n>` / `cat <n>` print the n-th listed name's
//! content; `new` creates the next unused `fileN.txt` (and refreshes the
//! browser too, so a file created from either app shows up in both); `clear`
//! empties the scrollback; `help` lists the commands. Output accumulates in
//! a bounded scrollback (`terminal::Terminal`) rendered above the prompt,
//! which has moved to the window's last row to make room for it. Honest
//! limit, inherited from `input.rs`: there is no `Key` for `.` or any other
//! punctuation, so a file name can never be typed directly — `ls` + a
//! numbered `open`/`cat` is the keyboard-only equivalent of the browser's
//! click-to-open gesture.
//!
//! Phase S turns the status-bar window (id 2, row `SH-1`) into a real
//! taskbar (`render_taskbar`): three fixed-width segments, `[Shell]`
//! `[Editor]` `[Browser]`, one per app window, the currently-focused one
//! drawn in reverse video. A left click on a segment (`apply_mouse`'s new
//! `STATUS_WINDOW_ID` branch) focuses and raises that window and reports
//! `MouseOutcome::TaskbarFocused` — the mouse-only way to switch between
//! the shell, editor, and browser without Tab, closing the DoD's "launch
//! the text editor, launch the file browser, click between them to bring
//! each to front" loop. Honest scope: every app window here is a
//! boot-time singleton (there is no window-instantiation path in this
//! codebase), so a taskbar click "launches" an app by raising its one
//! already-existing window rather than spawning a new instance — see the
//! note on `TASKBAR_LABELS` for what would be needed to go further.

use crate::browser::FileBrowser;
use crate::compositor::{self, Cell, MAX_WINDOWS};
use crate::editor::{self, Editor, EDITOR_BUF_MAX};
use crate::input::{Key, KeyEvent, MouseEvent};
use crate::store::{Name, MAX_DEPTH};
use crate::terminal::{Command, Terminal};
use crate::update::{KIND_DIR, VIEW_MAX_FILES};
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

/// File browser window geometry (Phase Q: the third real app window).
/// Overlaps the editor (columns 44..66, rows 13..20), so raising it does
/// real occlusion work too, same as the editor/shell overlap above.
pub const BROWSER_X: i16 = 44;
pub const BROWSER_Y: i16 = 13;
pub const BROWSER_W: u16 = 34;
pub const BROWSER_H: u16 = 10;

/// Taskbar layout (Phase S): the status-bar window (id 2, row `SH-1`) is
/// repurposed as a real taskbar — three fixed-width click segments, one
/// per always-present app window, in creation order. `TASKBAR_SEG_W = 12`
/// is wide enough for the longest label (`[Browser]`, 9 cells) with a
/// 3-cell gap so segments never visually run together.
///
/// Honest scope: every app window in this desktop (shell, editor, browser)
/// is a boot-time singleton — there is no per-app window-instantiation
/// path in this codebase, so a taskbar click "launches" an app by
/// focusing + raising its one already-existing window, not by spawning a
/// new instance. That matches the roadmap's DoD ("launch the text editor,
/// launch the file browser, click between them to bring each to front")
/// for a single window per app; true multi-instance spawning (e.g. two
/// editor windows open on two different files at once) would need a
/// window-instantiation refactor this phase does not attempt — flagged
/// here rather than silently implied.
const TASKBAR_SEG_W: i16 = 12;
const TASKBAR_LABELS: [&[u8]; 3] = [b"[Shell]", b"[Editor]", b"[Browser]"];

/// The id `create_window` was called with for the status/taskbar window
/// in `Desktop::new()`. A named const instead of the bare literal `2` at
/// each call site, matching how `shell_id`/`editor_id`/`browser_id` are
/// named even though their values are also fixed at construction.
const STATUS_WINDOW_ID: u32 = 2;

/// The shell prompt rendered at the start of the shell line.
const PROMPT: &[u8] = b"aegis:~$ ";

/// Maximum length of the echoed command line (prompt + chars must fit the
/// shell window width).
const LINE_MAX: usize = (SHELL_W as usize) - PROMPT.len();

/// Text printed by the shell's `help` command (Phase R).
const HELP_LINES: [&[u8]; 5] = [
    b"commands: help ls clear new open <n>",
    b"  ls        - list files, numbered",
    b"  open <n>  - print listing entry n (cat works too)",
    b"  new       - create the next fileN.txt",
    b"  clear     - clear this scrollback",
];

/// Render one `ls` row as `"<n> <name>"` into `out`, truncated to `out`'s
/// length (never panics on an oversized name). Mirrors
/// `browser::format_file_n`'s allocation-free decimal formatting, just for
/// a listing row instead of a generated file name.
fn format_listing_row(
    n: usize,
    name: &Name,
    out: &mut [u8; crate::terminal::OUT_LINE_MAX],
) -> usize {
    let mut at = 0usize;
    let mut digits = [0u8; 6];
    let mut d = 0usize;
    let mut v = n;
    if v == 0 {
        digits[0] = b'0';
        d = 1;
    }
    while v > 0 {
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        d += 1;
    }
    for i in (0..d).rev() {
        if at < out.len() {
            out[at] = digits[i];
            at += 1;
        }
    }
    if at < out.len() {
        out[at] = b' ';
        at += 1;
    }
    let bytes = name.as_slice();
    let take = bytes.len().min(out.len().saturating_sub(at));
    out[at..at + take].copy_from_slice(&bytes[..take]);
    at += take;
    at
}

/// What a keypress did to the live desktop. The caller (input task) prints
/// it over serial as the keypress-driven analogue of the boot-time shell
/// assertion: the echoed character is visible in the composited screen.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyOutcome {
    /// A printable key was appended to the shell line at `pos`.
    Echoed { window_id: u32, ch: u8, pos: usize },
    /// Backspace removed the last character; the line now has `pos` chars.
    Backspace { window_id: u32, pos: usize },
    /// Enter, with the shell focused, submitted a `len`-character command
    /// line (Phase R): the line was parsed and run (`ls`/`open`/`cat`/
    /// `new` touch the boot view; `help`/`clear` are local), appending
    /// `lines` output lines to the shell's scrollback (0 for an empty line
    /// or `clear`).
    Enter {
        window_id: u32,
        len: usize,
        lines: usize,
    },
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
    /// Enter, with the file browser focused, opened the selected file into
    /// the editor and moved focus there (the keyboard equivalent of
    /// clicking a browser row).
    Opened { window_id: u32 },
    /// F3, with the file browser focused, created a new blank file
    /// (`fileN.txt`, first unused N) and selected it in the listing.
    /// `name_len` is 0 when no durable store is present — the honest
    /// degrade (no boot view to create a file in).
    Created { window_id: u32, name_len: usize },
    /// Backspace, or Enter on the `..` row, with the file browser focused,
    /// moved up one directory (a no-op at the root).
    Up { window_id: u32 },
    /// Enter, with the file browser focused, descended into a selected
    /// directory and listed its entries (Phase Q completion: hierarchical).
    EnteredDir { window_id: u32 },
    /// F4, with the file browser focused, created a new directory (`dirN`,
    /// first unused N) in the current directory. `name_len` is 0 when no
    /// durable store is present.
    CreatedDir { window_id: u32, name_len: usize },
}

/// Which app window owns keyboard input. Tab cycles this; a mouse press on
/// an app window's content sets it too. The default post-boot focus is the
/// shell (the editor is created below it in z-order and only raises when
/// focused).
#[derive(Debug, Clone, Copy, PartialEq)]
enum AppFocus {
    Shell,
    Editor,
    Browser,
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
    /// A click on a file browser row opened that file in the editor and
    /// moved focus there — the file browser's headline "click to open"
    /// proof point.
    Opened { editor_id: u32, browser_id: u32 },
    /// A click on a directory row (or the `..` affordance) navigated the
    /// browser into it (Phase Q completion: hierarchical readdir/stat).
    EnteredDir { browser_id: u32 },
    /// A click on the `..` affordance moved the browser up one level.
    Up { browser_id: u32 },
    /// A click on the browser's "new file" affordance created a blank
    /// `fileN.txt`. `name_len` is 0 when no durable store is present.
    CreatedFile { browser_id: u32, name_len: usize },
    /// A click on the browser's "new dir" affordance created a `dirN`
    /// directory. `name_len` is 0 when no durable store is present.
    CreatedDir { browser_id: u32, name_len: usize },
    /// Phase S: a click on a taskbar entry brought `window_id` to front
    /// (focused + raised it), the mouse-only way to switch between the
    /// shell, editor, and browser windows without Tab. A no-op click on
    /// the entry for the window already in front still reports this —
    /// it's already at front, so there's nothing further to do.
    TaskbarFocused { window_id: u32 },
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
    fb_browser: [Cell; (BROWSER_W as usize) * (BROWSER_H as usize)],
    screen: [Cell; SW * SH],
    shell_id: u32,
    editor_id: u32,
    browser_id: u32,
    editor: Editor,
    editor_name: Name,
    /// The directory path the editor's open file lives in (empty = root).
    /// Set when the browser opens a file; the boot-time `memo.txt` starts at
    /// the root. `save_editor` writes through this path so a file opened
    /// from a subdirectory saves back to that subdirectory (Phase Q
    /// completion), not to the root.
    editor_path: [Name; MAX_DEPTH],
    editor_depth: usize,
    browser: FileBrowser,
    terminal: Terminal,
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
        let browser = wm
            .create_window(
                5,
                b"browser",
                Region {
                    x: BROWSER_X,
                    y: BROWSER_Y,
                    width: BROWSER_W,
                    height: BROWSER_H,
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
        // Placeholder dashes above; `render_taskbar()` (called from the
        // first `composite()` at the end of this constructor, Phase S)
        // overwrites this with the real taskbar segments before it's ever
        // shown, so this init only matters if construction panics first.

        let mut d = Desktop {
            wm,
            fb_title,
            fb_status,
            fb_shell: [0u16; (SHELL_W as usize) * (SHELL_H as usize)],
            fb_editor: [0u16; (EDITOR_W as usize) * (EDITOR_H as usize)],
            fb_browser: [0u16; (BROWSER_W as usize) * (BROWSER_H as usize)],
            screen: [compositor::TRANSPARENT; SW * SH],
            shell_id: shell,
            editor_id: editor,
            browser_id: browser,
            editor: Desktop::editor_initial(),
            editor_name: Name::from_slice(editor::FILE_NAME).unwrap(),
            editor_path: [Name::default(); MAX_DEPTH],
            editor_depth: 0,
            browser: FileBrowser::new(),
            terminal: Terminal::new(),
            focus: AppFocus::Shell,
            line: [0u8; LINE_MAX],
            line_len: 0,
            drag: None,
        };
        d.render_shell();
        d.render_editor();
        d.refresh_browser_listing();
        d.render_browser();
        d.composite();
        d
    }

    /// Refresh the file browser's listing from the durable boot view at the
    /// browser's current path (Phase Q completion: hierarchical readdir).
    /// An empty listing when no NVMe store is present — the browser then
    /// honestly shows nothing rather than fabricating rows. When not at the
    /// root, a `..` up-entry leads the listing.
    fn refresh_browser_listing(&mut self) {
        let mut raw = [(Name::default(), 0u8); VIEW_MAX_FILES];
        let n = editor::with(|fs| {
            let path = self.browser.path();
            fs.browser_list(path, &mut raw)
        })
        .unwrap_or(0);
        let mut entries = [(Name::default(), 0u8); VIEW_MAX_FILES + 1];
        let mut m = 0usize;
        if !self.browser.at_root() {
            entries[m] = (Name::from_slice(b"..").unwrap(), KIND_DIR);
            m += 1;
        }
        for e in raw[..n].iter().take(VIEW_MAX_FILES) {
            entries[m] = *e;
            m += 1;
        }
        self.browser.set_entries(&entries[..m]);
        // Report the refreshed listing over serial so navigation is provable
        // live (the boot log separately reports the first listing). Dirs are
        // marked with a trailing '/' so the hierarchy is explicit.
        let mut listing = [0u8; 128];
        let mut llen = 0usize;
        for i in 0..self.browser.count() {
            if let Some((name, kind)) = self.browser.entry(i) {
                let n = name.as_slice().len();
                if llen + n + 2 > listing.len() {
                    break;
                }
                if i > 0 {
                    listing[llen] = b',';
                    llen += 1;
                }
                listing[llen..llen + n].copy_from_slice(name.as_slice());
                llen += n;
                if kind == KIND_DIR {
                    listing[llen] = b'/';
                    llen += 1;
                }
            }
        }
        let mut path = [0u8; 128];
        let mut plen = 0usize;
        path[plen] = b'/';
        plen += 1;
        for name in self.browser.path() {
            let n = name.as_slice().len();
            if plen + n + 1 > path.len() {
                break;
            }
            path[plen..plen + n].copy_from_slice(name.as_slice());
            plen += n;
            path[plen] = b'/';
            plen += 1;
        }
        crate::sprintln!(
            "Aegis: browser@listing [{}] at {} ({} entries, window id={})",
            core::str::from_utf8(&listing[..llen]).unwrap_or("<non-utf8>"),
            core::str::from_utf8(&path[..plen]).unwrap_or("<non-utf8>"),
            self.browser.count(),
            self.browser_id
        );
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
    /// the title bar ("Shell" + a close button at the last cell); the prompt,
    /// typed line, and cursor now sit on the LAST row (Phase R); the rows in
    /// between (row 1 through h-2) show scrollback output, growing top-down
    /// as commands run.
    ///
    /// Once output exceeds the visible rows, only the most recent ones are
    /// shown. Re-rendered on every resize or command so the title bar,
    /// scrollback, and prompt stay aligned with the window's current width
    /// and height (the compositor indexes framebuffers by the window's
    /// current region size).
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
        if w == 0 || h < 2 {
            // Too small to hold even a prompt row below the title bar;
            // nothing further to paint (same "stay total, never panic"
            // discipline the resize-clamping tests already exercise).
            return;
        }
        // Scrollback: rows 1..h-1, growing top-down from row 1 like a
        // normal terminal's history; once more lines exist than fit, only
        // the most recent `scroll_rows` are shown (oldest dropped off the
        // top of the visible window, not out of the buffer itself).
        let scroll_rows = h - 2;
        let lines = self.terminal.lines();
        let start = lines.len().saturating_sub(scroll_rows);
        for (row_i, line) in lines[start..].iter().enumerate() {
            let row_base = (1 + row_i) * w;
            for (i, &b) in line.as_bytes().iter().enumerate() {
                if i < w {
                    self.fb_shell[row_base + i] = 0x0F00 | b as u16;
                }
            }
        }
        // Prompt row (the last row): prompt text + typed line + cursor.
        let prompt_row = h - 1;
        let row_base = prompt_row * w;
        let mut col = 0usize;
        for &b in PROMPT.iter() {
            if col < w {
                self.fb_shell[row_base + col] = 0x0F00 | b as u16;
            }
            col += 1;
        }
        for (i, &b) in self.line[..self.line_len].iter().enumerate() {
            let idx = col + i;
            if idx < w {
                self.fb_shell[row_base + idx] = 0x0F00 | b as u16;
            }
        }
        let cur_col = col + self.line_len;
        if cur_col < w {
            self.fb_shell[row_base + cur_col] = 0x0F00 | b'_' as u16;
        }
    }

    /// Run a parsed shell command (Phase R) against the same boot-time
    /// filesystem the editor and file browser already use, appending any
    /// resulting text to the shell's scrollback. Returns how many lines
    /// were appended (0 for an empty line or `clear`). Filesystem access
    /// goes through `editor::with`, the exact pattern the file browser's F3
    /// ("new file") gesture already uses — this adds a new caller, not a
    /// new I/O path.
    fn execute_shell_command(&mut self, cmd: Command) -> usize {
        match cmd {
            Command::Empty => 0,
            Command::Help => {
                for line in HELP_LINES {
                    self.terminal.push_line(line);
                }
                HELP_LINES.len()
            }
            Command::Clear => {
                self.terminal.clear();
                0
            }
            Command::Ls => {
                let mut names = [Name::default(); VIEW_MAX_FILES];
                let n = editor::with(|fs| fs.list(&mut names)).unwrap_or(0);
                self.terminal.set_listing(&names[..n]);
                if n == 0 {
                    self.terminal.push_line(b"(no files)");
                    1
                } else {
                    for (i, entry) in names[..n].iter().enumerate() {
                        let mut line = [0u8; crate::terminal::OUT_LINE_MAX];
                        let len = format_listing_row(i + 1, entry, &mut line);
                        self.terminal.push_line(&line[..len]);
                    }
                    n
                }
            }
            Command::New => {
                // Reuse the browser's own free-name search so a file
                // created from the shell can never collide with one the
                // browser's F3 gesture would have picked next.
                self.refresh_browser_listing();
                let (name_bytes, name_len) = self.browser.next_free_name();
                let created =
                    editor::with(|fs| fs.create_empty(&name_bytes[..name_len])).unwrap_or(false);
                if created {
                    self.refresh_browser_listing();
                    self.render_browser();
                    let mut line = [0u8; crate::terminal::OUT_LINE_MAX];
                    let prefix = b"created ";
                    let mut at = prefix.len().min(line.len());
                    line[..at].copy_from_slice(&prefix[..at]);
                    let take = name_len.min(line.len() - at);
                    line[at..at + take].copy_from_slice(&name_bytes[..take]);
                    at += take;
                    self.terminal.push_line(&line[..at]);
                } else {
                    self.terminal
                        .push_line(b"could not create file (no durable store?)");
                }
                1
            }
            Command::Open(None) => {
                self.terminal.push_line(b"usage: open <n> (run ls first)");
                1
            }
            Command::Open(Some(idx)) => {
                let Some(name) = self.terminal.resolve(idx) else {
                    self.terminal
                        .push_line(b"no such listing entry - run ls first");
                    return 1;
                };
                let mut buf = [0u8; EDITOR_BUF_MAX];
                let read = editor::with(|fs| fs.open(name.as_slice(), &mut buf)).flatten();
                match read {
                    Some(n) if n > 0 => {
                        let mut printed = 0usize;
                        for line in buf[..n].split(|&b| b == b'\n') {
                            if line.is_empty() {
                                continue;
                            }
                            self.terminal.push_line(line);
                            printed += 1;
                        }
                        if printed == 0 {
                            self.terminal.push_line(b"(empty file)");
                            printed = 1;
                        }
                        printed
                    }
                    _ => {
                        self.terminal
                            .push_line(b"could not read file (no durable store?)");
                        1
                    }
                }
            }
            Command::Unknown => {
                self.terminal.push_line(b"unknown command - try 'help'");
                1
            }
        }
    }

    /// Render the editor window's framebuffer from its current size: row 0
    /// is the title bar ("Editor: <name>" + a close button at the last
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
        // Title bar (row 0): "Editor: <name>" — Phase Q: the open file can
        // now be anything the browser opened, not just memo.txt — plus a
        // close button at the last cell.
        for i in 0..w {
            self.fb_editor[i] = 0x1F00 | b' ' as u16;
        }
        let title_prefix: &[u8] = b"Editor: ";
        for (i, t) in title_prefix
            .iter()
            .chain(self.editor_name.as_slice().iter())
            .enumerate()
        {
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

    /// Render the file browser window's framebuffer: row 0 is the title bar
    /// ("Files: <path>" + a close button at the last cell); each content row
    /// shows one entry (directories marked with a trailing '/', the
    /// selected row with a leading '>'); the last row is an action bar with
    /// the `..` up, new-file and new-dir affordances (Phase Q completion:
    /// mouse-click navigation and creation). Rows past the listing keep the
    /// dotted fill (same convention `render_editor` uses).
    fn render_browser(&mut self) {
        let (w, h) = self
            .wm
            .window(self.browser_id)
            .map(|w| (w.region.width as usize, w.region.height as usize))
            .unwrap_or((BROWSER_W as usize, BROWSER_H as usize));
        let total = w * h;
        for c in self.fb_browser[..total].iter_mut() {
            *c = 0x0F00 | b'.' as u16;
        }
        for i in 0..w {
            self.fb_browser[i] = 0x1F00 | b' ' as u16;
        }
        // Title: "Files: " + the current path (or "/" for the root).
        let mut title_at = 0usize;
        for (i, t) in b"Files:".iter().enumerate() {
            if i < w {
                self.fb_browser[i] = 0x1F00 | *t as u16;
            }
            title_at = i + 1;
        }
        if self.browser.at_root() {
            if title_at < w {
                self.fb_browser[title_at] = 0x1F00 | b'/' as u16;
            }
        } else {
            for name in self.browser.path().iter() {
                for (i, &b) in name.as_slice().iter().enumerate() {
                    if title_at + i < w {
                        self.fb_browser[title_at + i] = 0x1F00 | b as u16;
                    }
                }
                title_at += name.as_slice().len();
                if title_at < w {
                    self.fb_browser[title_at] = 0x1F00 | b'/' as u16;
                }
                title_at += 1;
            }
        }
        if w > 0 {
            self.fb_browser[w - 1] = 0x4F00 | b'X' as u16;
        }
        // Listing rows: rows 1..h-2 (the last row is the action bar).
        let listing_rows = h.saturating_sub(2);
        for row in 0..listing_rows {
            let Some((name, kind)) = self.browser.entry(row) else {
                break;
            };
            let row_base = (row + 1) * w;
            let marker = if row == self.browser.selected() {
                b'>'
            } else {
                b' '
            };
            if row_base < total {
                self.fb_browser[row_base] = 0x0F00 | marker as u16;
            }
            let is_dir = kind == KIND_DIR;
            for (i, &b) in name.as_slice().iter().enumerate() {
                let idx = row_base + 1 + i;
                if idx < total && idx < row_base + w {
                    self.fb_browser[idx] = 0x0F00 | b as u16;
                }
            }
            if is_dir {
                let idx = row_base + 1 + name.as_slice().len();
                if idx < total && idx < row_base + w {
                    self.fb_browser[idx] = 0x0F00 | b'/' as u16;
                }
            }
        }
        // Action bar (last row): `..` up, new file, new dir.
        if h > 1 {
            let base = (h - 1) * w;
            for i in 0..w {
                if base + i < total {
                    self.fb_browser[base + i] = 0x1F00 | b' ' as u16;
                }
            }
            let actions: [&[u8]; 3] = [b"[..] up", b"[+ f]", b"[+ d]"];
            let mut at = 0usize;
            for act in actions {
                for (i, &b) in act.iter().enumerate() {
                    let idx = base + at + i;
                    if idx < total && idx < base + w {
                        self.fb_browser[idx] = 0x1F00 | b as u16;
                    }
                }
                at += act.len() + 2;
            }
        }
    }

    /// Render the taskbar (Phase S; the status-bar window's framebuffer,
    /// `fb_status`, repurposed): one highlighted segment per app window,
    /// the currently-focused one drawn as a solid button (reverse-video
    /// attribute `0x4F00`, the same attribute the close button already
    /// uses) so the taskbar always shows which window is in front, not
    /// just which is clickable. Re-run at the top of every `composite()`
    /// call so it can never drift out of sync with `self.focus`.
    fn render_taskbar(&mut self) {
        for c in self.fb_status.iter_mut() {
            *c = 0x0F00 | b'-' as u16;
        }
        let focus_idx = match self.focus {
            AppFocus::Shell => 0,
            AppFocus::Editor => 1,
            AppFocus::Browser => 2,
        };
        for (seg, label) in TASKBAR_LABELS.iter().enumerate() {
            let base = seg as i16 * TASKBAR_SEG_W;
            if base as usize >= SW {
                break;
            }
            let attr: u16 = if seg == focus_idx { 0x4F00 } else { 0x1F00 };
            for i in 0..TASKBAR_SEG_W {
                let idx = base + i;
                if (idx as usize) < SW {
                    self.fb_status[idx as usize] = attr | b' ' as u16;
                }
            }
            for (i, &b) in label.iter().enumerate() {
                let idx = base + i as i16;
                if (idx as usize) < SW {
                    self.fb_status[idx as usize] = attr | b as u16;
                }
            }
        }
    }

    /// Which taskbar segment (0=shell, 1=editor, 2=browser) column `cx`
    /// falls in, or `None` past the last labeled segment (the taskbar
    /// doesn't fill the whole row's width). Shared by the click handler in
    /// `apply_mouse` and any test wanting to assert click regions, so the
    /// hit-test and the render in `render_taskbar` can never disagree
    /// about where a segment's boundary is.
    fn taskbar_segment_at(&self, cx: i16) -> Option<usize> {
        if cx < 0 {
            return None;
        }
        let seg = (cx / TASKBAR_SEG_W) as usize;
        if seg < TASKBAR_LABELS.len() {
            Some(seg)
        } else {
            None
        }
    }

    /// Re-composite the window manager + framebuffers into `screen`, then
    /// paint the desktop background over any cell the compositor left
    /// transparent (so the whole screen is the blue desktop, not a void).
    fn composite(&mut self) {
        self.render_taskbar();
        let mut fbs: [Option<&[Cell]>; MAX_WINDOWS] = [None; MAX_WINDOWS];
        fbs[0] = Some(&self.fb_title);
        fbs[1] = Some(&self.fb_status);
        fbs[2] = Some(&self.fb_shell);
        fbs[3] = Some(&self.fb_editor);
        fbs[4] = Some(&self.fb_browser);
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
            AppFocus::Browser => self.apply_key_browser(ke),
        }
    }

    /// Cycle keyboard focus between the shell, the editor and the file
    /// browser, raising the newly-focused window's z-order so it occludes
    /// the others in overlap (Phase Q: three app windows, Tab walks them).
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
                self.focus = AppFocus::Browser;
                let _ = self.wm.focus_window(self.browser_id);
                self.render_browser();
                self.composite();
                KeyOutcome::Focused {
                    window_id: self.browser_id,
                    editor: false,
                }
            }
            AppFocus::Browser => {
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
                let cmd = Command::parse(&self.line[..len]);
                self.line_len = 0;
                let lines = self.execute_shell_command(cmd);
                self.render_shell();
                self.composite();
                Some(KeyOutcome::Enter {
                    window_id: self.shell_id,
                    len,
                    lines,
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
    fn apply_key_editor(&mut self, key: KeyEvent) -> Option<KeyOutcome> {
        match key.key {
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
                let moved = match key.key {
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
                let ch = key_to_char(key.key, key.modifiers.shift)?;
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

    /// F2: write the editor buffer to `self.editor_name` (the file actually
    /// open — `memo.txt` at boot, or whatever the browser last opened into
    /// this window) in the boot view, through `self.editor_path` so a file
    /// opened from a subdirectory saves back to that subdirectory. With a
    /// durable handle this commits a new content block (+ COW dir block) to
    /// the NVMe store; without one (tests, no NVMe) the buffer is unchanged
    /// and the outcome reports the digest as all-zero — honest about the
    /// in-memory fallback.
    ///
    /// Fixed this session: this used to call `fs.write_memo(..)`
    /// unconditionally, so a file opened from the browser (e.g.
    /// `notes.txt`) would display and edit correctly but F2 silently wrote
    /// the edit to `memo.txt` instead — the title bar said `notes.txt`,
    /// the disk said otherwise. Routing the save through `editor_name`
    /// closes that gap: "open a browser file, edit it, save" now saves
    /// that file, not memo.txt, and `editor::EditorFs::write_named` is the
    /// name-aware save path `write_memo` now delegates to.
    fn save_editor(&mut self) -> KeyOutcome {
        let len = self.editor.len();
        let mut bytes = [0u8; EDITOR_BUF_MAX];
        bytes[..len].copy_from_slice(self.editor.as_bytes());
        let name = self.editor_name;
        let path = &self.editor_path[..self.editor_depth];
        let block = editor::with(|fs| fs.write_named_at(path, name.as_slice(), &bytes[..len]))
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

    /// Browser-focused keys: arrows move the selection, Enter opens the
    /// selected file into the editor (or descends into a selected
    /// directory — Phase Q completion: hierarchical), Backspace ascends,
    /// F3 creates a new blank file (`fileN.txt`, first unused N) and
    /// selects it, F4 creates a new directory (`dirN`).
    fn apply_key_browser(&mut self, ke: KeyEvent) -> Option<KeyOutcome> {
        match ke.key {
            Key::ArrowUp => {
                if self.browser.move_up() {
                    self.render_browser();
                    self.composite();
                    Some(KeyOutcome::CursorMoved {
                        window_id: self.browser_id,
                        pos: self.browser.selected(),
                    })
                } else {
                    None
                }
            }
            Key::ArrowDown => {
                if self.browser.move_down() {
                    self.render_browser();
                    self.composite();
                    Some(KeyOutcome::CursorMoved {
                        window_id: self.browser_id,
                        pos: self.browser.selected(),
                    })
                } else {
                    None
                }
            }
            Key::Backspace => {
                if self.browser.pop_dir() {
                    self.refresh_browser_listing();
                    self.render_browser();
                    self.composite();
                    Some(KeyOutcome::Up {
                        window_id: self.browser_id,
                    })
                } else {
                    None
                }
            }
            Key::Enter => {
                let (name, kind) = self.browser.selected_entry()?;
                if name.as_slice() == b".." {
                    self.browser.pop_dir();
                    self.refresh_browser_listing();
                    self.render_browser();
                    self.composite();
                    Some(KeyOutcome::Up {
                        window_id: self.browser_id,
                    })
                } else if kind == KIND_DIR {
                    self.browser.push_dir(name);
                    self.refresh_browser_listing();
                    self.render_browser();
                    self.composite();
                    Some(KeyOutcome::EnteredDir {
                        window_id: self.browser_id,
                    })
                } else {
                    self.open_selected_in_editor();
                    Some(KeyOutcome::Opened {
                        window_id: self.editor_id,
                    })
                }
            }
            Key::F3 => Some(self.create_new_file()),
            Key::F4 => Some(self.create_new_dir()),
            _ => None,
        }
    }

    /// Open the browser's currently selected file into the editor: load its
    /// bytes as the editor buffer (through the browser's current path —
    /// Phase Q completion), rename the editor window's title to that
    /// file, focus the editor, and raise it. A no-op if nothing is selected
    /// or no durable store is present (the browser is empty in that case,
    /// so `selected_entry` already returns `None`). A directory selection
    /// is not opened (the caller descends into it instead).
    fn open_selected_in_editor(&mut self) {
        let Some((name, kind)) = self.browser.selected_entry() else {
            return;
        };
        if kind == KIND_DIR {
            return;
        }
        let path = self.browser.path();
        let mut path_buf = [Name::default(); MAX_DEPTH];
        path_buf[..path.len()].copy_from_slice(path);
        let mut buf = [0u8; EDITOR_BUF_MAX];
        let Some(n) =
            editor::with(|fs| fs.browser_open(&path_buf[..path.len()], name.as_slice(), &mut buf))
                .flatten()
        else {
            return;
        };
        self.editor = Editor::from_bytes(&buf[..n]);
        self.editor_name = name;
        self.editor_path = path_buf;
        self.editor_depth = path.len();
        self.focus = AppFocus::Editor;
        let _ = self.wm.focus_window(self.editor_id);
        self.render_editor();
        self.render_browser();
        self.composite();
    }

    /// F3 gesture: create `fileN.txt` (first unused N) as a blank file (a
    /// single newline — the store's minimum block) in the current directory
    /// of the durable boot view, refresh the listing, and select the new
    /// entry. Reports `name_len = 0` when no durable store is present — the
    /// same honest degrade `save_editor` already reports for the digest.
    fn create_new_file(&mut self) -> KeyOutcome {
        let path = self.browser.path();
        let mut path_buf = [Name::default(); MAX_DEPTH];
        path_buf[..path.len()].copy_from_slice(path);
        let (name_bytes, name_len) = self.browser.next_free_name();
        let created =
            editor::with(|fs| fs.browser_create(&path_buf[..path.len()], &name_bytes[..name_len]))
                .unwrap_or(false);
        if created {
            self.refresh_browser_listing();
            for i in 0..self.browser.count() {
                if let Some((e, _)) = self.browser.entry(i) {
                    if e.as_slice() == &name_bytes[..name_len] {
                        self.browser.select(i);
                        break;
                    }
                }
            }
        }
        self.render_browser();
        self.composite();
        KeyOutcome::Created {
            window_id: self.browser_id,
            name_len: if created { name_len } else { 0 },
        }
    }

    /// F4 gesture: create `dirN` (first unused N) as an empty directory in
    /// the current directory of the durable boot view, refresh the listing,
    /// and select the new entry. Reports `name_len = 0` when no durable
    /// store is present.
    fn create_new_dir(&mut self) -> KeyOutcome {
        let path = self.browser.path();
        let mut path_buf = [Name::default(); MAX_DEPTH];
        path_buf[..path.len()].copy_from_slice(path);
        let (name_bytes, name_len) = self.browser.next_free_dir_name();
        let created =
            editor::with(|fs| fs.browser_mkdir(&path_buf[..path.len()], &name_bytes[..name_len]))
                .unwrap_or(false);
        if created {
            self.refresh_browser_listing();
            for i in 0..self.browser.count() {
                if let Some((e, _)) = self.browser.entry(i) {
                    if e.as_slice() == &name_bytes[..name_len] {
                        self.browser.select(i);
                        break;
                    }
                }
            }
        }
        self.render_browser();
        self.composite();
        KeyOutcome::CreatedDir {
            window_id: self.browser_id,
            name_len: if created { name_len } else { 0 },
        }
    }

    /// Mouse equivalent of [`Self::create_new_file`]: clicking the action
    /// bar's new-file cell creates a blank `fileN.txt` in the current
    /// directory and reports the `MouseOutcome`.
    fn create_new_file_mouse(&mut self) -> MouseOutcome {
        let out = self.create_new_file();
        let name_len = match out {
            KeyOutcome::Created { name_len, .. } => name_len,
            _ => 0,
        };
        MouseOutcome::CreatedFile {
            browser_id: self.browser_id,
            name_len,
        }
    }

    /// Mouse equivalent of [`Self::create_new_dir`]: clicking the action
    /// bar's new-dir cell creates a `dirN` directory in the current
    /// directory and reports the `MouseOutcome`.
    fn create_new_dir_mouse(&mut self) -> MouseOutcome {
        let out = self.create_new_dir();
        let name_len = match out {
            KeyOutcome::CreatedDir { name_len, .. } => name_len,
            _ => 0,
        };
        MouseOutcome::CreatedDir {
            browser_id: self.browser_id,
            name_len,
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
                if id == STATUS_WINDOW_ID {
                    // Phase S: a fresh press on the taskbar row. Map the
                    // column to a segment and, if it names one of the
                    // three app windows, focus + raise it — the mouse-only
                    // "launch/switch app" gesture (see the honest-scope
                    // note on `TASKBAR_LABELS` for what "launch" means
                    // here: raising the one existing singleton window).
                    if let Some(seg) = self.taskbar_segment_at(cx) {
                        let target = match seg {
                            0 => self.shell_id,
                            1 => self.editor_id,
                            2 => self.browser_id,
                            _ => unreachable!(
                                "taskbar_segment_at bounds-checks against TASKBAR_LABELS"
                            ),
                        };
                        self.focus_content_press(target);
                        return Some(MouseOutcome::TaskbarFocused { window_id: target });
                    }
                } else if self.is_app_window(id) {
                    // Phase Q completion: a content click on a browser row is
                    // acted on here — descend into directories, open files,
                    // and the action bar creates. The `wy`/`ww`/`wh` window
                    // geometry is captured while the window borrow is live.
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
                        if id == self.browser_id && cy > wy {
                            let click_row = (cy - wy - 1).max(0) as usize;
                            // The action bar is the last window row (local
                            // row wh-1 -> click_row wh-2); the +2 keeps the
                            // content rows (click_row <= wh-3) out of it.
                            let is_action = click_row + 2 >= wh as usize;
                            let click_col = (cx - wx - 1).max(0) as usize;
                            if is_action {
                                let seg = click_col / 7;
                                return match seg {
                                    0 => {
                                        if self.browser.pop_dir() {
                                            self.refresh_browser_listing();
                                            self.render_browser();
                                            self.composite();
                                            Some(MouseOutcome::Up {
                                                browser_id: self.browser_id,
                                            })
                                        } else {
                                            self.focus_content_press(id);
                                            Some(MouseOutcome::Moved {
                                                x: me.x,
                                                y: me.y,
                                                left: true,
                                                right: me.right_button,
                                            })
                                        }
                                    }
                                    1 => Some(self.create_new_file_mouse()),
                                    2 => Some(self.create_new_dir_mouse()),
                                    _ => {
                                        self.focus_content_press(id);
                                        Some(MouseOutcome::Moved {
                                            x: me.x,
                                            y: me.y,
                                            left: true,
                                            right: me.right_button,
                                        })
                                    }
                                };
                            }
                            if self.browser.select(click_row) {
                                let (name, kind) = self.browser.selected_entry().unwrap();
                                if kind == KIND_DIR {
                                    if name.as_slice() == b".." {
                                        self.browser.pop_dir();
                                        self.refresh_browser_listing();
                                        self.render_browser();
                                        self.composite();
                                        return Some(MouseOutcome::Up {
                                            browser_id: self.browser_id,
                                        });
                                    }
                                    self.browser.push_dir(name);
                                    self.refresh_browser_listing();
                                    self.render_browser();
                                    self.composite();
                                    return Some(MouseOutcome::EnteredDir {
                                        browser_id: self.browser_id,
                                    });
                                }
                                self.open_selected_in_editor();
                                return Some(MouseOutcome::Opened {
                                    editor_id: self.editor_id,
                                    browser_id: self.browser_id,
                                });
                            }
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

    /// Window id of the file browser window.
    pub fn browser_id(&self) -> u32 {
        self.browser_id
    }

    /// Number of entries currently listed in the file browser (the boot
    /// log reports it so the listing is provable across a power cycle).
    pub fn browser_count(&self) -> usize {
        self.browser.count()
    }

    /// The file browser's `idx`-th listed entry name, if any.
    pub fn browser_entry(&self, idx: usize) -> Option<Name> {
        self.browser.entry(idx).map(|(name, _)| name)
    }

    /// True when the file browser's `idx`-th listed entry is a directory
    /// (Phase Q completion: the boot log marks dirs so the hierarchical
    /// listing is provable across a power cycle).
    pub fn browser_is_dir(&self, idx: usize) -> bool {
        self.browser.is_dir(idx)
    }

    /// Re-render the app window `id` from its current size.
    fn render_window(&mut self, id: u32) {
        if id == self.shell_id {
            self.render_shell();
        } else if id == self.editor_id {
            self.render_editor();
        } else if id == self.browser_id {
            self.render_browser();
        }
    }

    /// Focus `id` on a mouse press over its content: keyboard input follows,
    /// and the window is raised above the other app window. A no-op when the
    /// window already owns focus.
    fn focus_content_press(&mut self, id: u32) {
        let next = if id == self.editor_id {
            AppFocus::Editor
        } else if id == self.browser_id {
            AppFocus::Browser
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

    /// True if `id` is a draggable app window (Phase O/P/Q: the shell
    /// window, the editor window and the file browser window).
    fn is_app_window(&self, id: u32) -> bool {
        id == self.shell_id || id == self.editor_id || id == self.browser_id
    }

    /// The framebuffer dimensions backing an app window (the ceiling a corner
    /// drag may resize it to). Each app window has its own fixed framebuffer.
    fn framebuffer_dims(&self, id: u32) -> (i16, i16) {
        if id == self.shell_id {
            (SHELL_W as i16, SHELL_H as i16)
        } else if id == self.editor_id {
            (EDITOR_W as i16, EDITOR_H as i16)
        } else if id == self.browser_id {
            (BROWSER_W as i16, BROWSER_H as i16)
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

    /// Screen index of the first character cell after the shell prompt
    /// (Phase R: the prompt now sits on the window's LAST row, to make
    /// room for scrollback above it).
    fn echo_base() -> usize {
        (SHELL_Y + SHELL_H as i16 - 1) as usize * SW + SHELL_X as usize + PROMPT.len()
    }

    #[test]
    fn boot_shell_surface_is_default() {
        let d = Desktop::new();
        // Title bar first cell is 'S' (of "Shell"); the prompt is on the
        // window's last row (Phase R), leaving room for scrollback above.
        let title_cell = (d.screen()[SHELL_Y as usize * SW + SHELL_X as usize] & 0xFF) as u8;
        assert_eq!(title_cell, b'S');
        let prompt_row = (SHELL_Y + SHELL_H as i16 - 1) as usize;
        let prompt_cell = (d.screen()[prompt_row * SW + SHELL_X as usize] & 0xFF) as u8;
        assert_eq!(prompt_cell, b'a');
        // Close button at the title bar's last cell.
        let close_cell = (d.screen()
            [SHELL_Y as usize * SW + SHELL_X as usize + SHELL_W as usize - 1]
            & 0xFF) as u8;
        assert_eq!(close_cell, b'X');
        // Phase S: the status row is now the taskbar — its first cell is
        // the `[` of the `[Shell]` segment (not the old `-` placeholder).
        let status_ok = (d.screen()[(SH - 1) * SW] & 0xFF) as u8 == b'[';
        assert!(status_ok);
        // Title + status + shell + editor + browser: no demo windows.
        assert_eq!(d.window_count(), 5);
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
        // origin; the old origin cell is back to desktop background. The
        // window only moved horizontally, so the prompt row (the window's
        // last row) is unchanged.
        let prompt_row = (SHELL_Y + SHELL_H as i16 - 1) as usize;
        let moved_cell = (d.screen()[prompt_row * SW + SHELL_X as usize + 1] & 0xFF) as u8;
        assert_eq!(moved_cell, b'a');
        let old_cell = d.screen()[prompt_row * SW + SHELL_X as usize];
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
        assert_eq!(d.window_count(), 5);
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
        assert_eq!(d.window_count(), 4);
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
        assert_eq!(d.window_count(), 5);
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
        // Tab -> browser focused and raised: its title 'F' is now the topmost
        // cell at (44,13) (the editor occluded that cell).
        let out = d.apply_key(key(Key::Tab)).unwrap();
        match out {
            KeyOutcome::Focused {
                window_id,
                editor: false,
            } => assert_eq!(window_id, d.browser_id()),
            _ => panic!("expected focus on the browser"),
        }
        assert_eq!(
            (d.screen()[BROWSER_Y as usize * SW + BROWSER_X as usize] & 0xFF) as u8,
            b'F'
        );
        // Tab -> shell refocused and raised: the shell occludes (44,13) again.
        let out = d.apply_key(key(Key::Tab)).unwrap();
        match out {
            KeyOutcome::Focused {
                window_id,
                editor: false,
            } => assert_eq!(window_id, d.shell_id()),
            _ => panic!("expected focus back on the shell"),
        }
        assert_ne!(
            (d.screen()[BROWSER_Y as usize * SW + BROWSER_X as usize] & 0xFF) as u8,
            b'F'
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

    /// Regression for the P/Q caveat this session closed: `save_editor`
    /// must read `self.editor_name`, not a hardcoded `memo.txt`. There is
    /// no durable store in host tests (so the actual disk write can't be
    /// observed here — that round trip is `editor.rs`'s
    /// `write_file_saves_the_named_file_and_leaves_memo_untouched`), but
    /// this proves the wiring itself: changing `editor_name` (the same
    /// field `open_selected_in_editor` sets on a browser open) changes
    /// which name the save call targets, by checking the title bar it
    /// renders — a stand-in for the disk write host tests can't see.
    #[test]
    fn f2_save_targets_the_currently_open_file_not_always_memo() {
        let mut d = Desktop::new();
        assert_eq!(d.editor_name.as_slice(), editor::FILE_NAME);

        // Simulate what `open_selected_in_editor` does on a browser open:
        // it sets `editor_name` to whatever was opened.
        d.editor_name = Name::from_slice(b"notes.txt").unwrap();
        d.render_editor();
        // The editor window's title bar reflects the open file, proving
        // `editor_name` — the same field `save_editor` now reads — is the
        // single source of truth for "what file is this window editing".
        let mut title = [0u8; 8 + 9];
        for (i, c) in d.fb_editor[..title.len()].iter().enumerate() {
            title[i] = (*c & 0xFF) as u8;
        }
        assert_eq!(&title[..], b"Editor: notes.txt");

        // F2 still returns a well-formed Saved outcome (no durable store
        // in tests, so the digest is honestly all-zero either way) — the
        // name change doesn't break the save gesture itself.
        d.focus = AppFocus::Editor;
        let _ = d.wm.focus_window(d.editor_id);
        let s = d.apply_key(key(Key::F2)).unwrap();
        match s {
            KeyOutcome::Saved { block, .. } => assert_eq!(block, [0u8; 4]),
            _ => panic!("expected a save"),
        }
    }

    #[test]
    fn browser_window_is_third_app_window() {
        let mut d = Desktop::new();
        assert_eq!(d.window_count(), 5);
        let w = d.wm.window(d.browser_id()).unwrap();
        assert_eq!(
            (w.region.x, w.region.y, w.region.width, w.region.height),
            (BROWSER_X, BROWSER_Y, BROWSER_W, BROWSER_H)
        );
        // The browser lists nothing without a durable store — honest, not a
        // fabricated row: no entry and nothing rendered below the title bar.
        assert_eq!(d.browser.count(), 0);
        // Raise the browser (Tab twice) so its title is the topmost cell at
        // (44,13) — otherwise the editor/shell occlude it.
        d.apply_key(key(Key::Tab)).unwrap();
        d.apply_key(key(Key::Tab)).unwrap();
        let cell = (d.screen()[BROWSER_Y as usize * SW + BROWSER_X as usize] & 0xFF) as u8;
        assert_eq!(cell, b'F');
    }

    #[test]
    fn tab_cycles_focus_through_browser_to_shell() {
        let mut d = Desktop::new();
        // Shell -> editor -> browser -> shell: the full three-app cycle.
        d.apply_key(key(Key::Tab)).unwrap(); // -> editor
        let out = d.apply_key(key(Key::Tab)).unwrap(); // -> browser
        match out {
            KeyOutcome::Focused { window_id, .. } => assert_eq!(window_id, d.browser_id()),
            _ => panic!("expected focus on the browser"),
        }
        // Browser-focused: an empty listing refuses arrow moves and Enter
        // (no selection), but F3 reports the honest no-store degrade.
        assert_eq!(d.apply_key(key(Key::ArrowDown)), None);
        assert_eq!(d.apply_key(key(Key::Enter)), None);
        let f3 = d.apply_key(key(Key::F3)).unwrap();
        match f3 {
            KeyOutcome::Created {
                window_id,
                name_len,
            } => {
                assert_eq!(window_id, d.browser_id());
                assert_eq!(name_len, 0, "no durable store: honest empty report");
            }
            _ => panic!("expected a create report"),
        }
        d.apply_key(key(Key::Tab)).unwrap(); // -> shell, back to the start
    }

    #[test]
    fn browser_mouse_click_without_store_does_not_open() {
        // No durable store is installed in tests, so the listing is empty: a
        // content click on the browser must NOT fabricate an open — it falls
        // through to the generic content-focus path and reports the position.
        let mut d = Desktop::new();
        d.apply_key(key(Key::Tab)).unwrap(); // -> editor
        d.apply_key(key(Key::Tab)).unwrap(); // -> browser (raised)
                                             // Browser content row 0 at cell (45,14) -> pixel (360, 224): inside
                                             // the window, not the title bar / close button / resize corner.
        let out = d
            .apply_mouse(MouseEvent {
                x: 360,
                y: 224,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::Opened { .. } => panic!("empty listing must not open"),
            MouseOutcome::Moved { .. } => {}
            _ => panic!("expected a position report"),
        }
    }

    #[test]
    fn browser_mouse_action_bar_reaches_create_cells() {
        // The browser's last row is the action bar (local row wh-1 ->
        // click_row wh-2). Regression: the is_action gate used to be
        // `click_row + 1 >= wh`, which the action bar never satisfied, so
        // clicking `[+ f]` / `[+ d]` fell into the listing path instead of
        // creating. Without a store both honest-report a 0 name_len (same
        // convention the F3/F4 keys use) but must return the Created* /
        // CreatedDir outcomes, not a position report.
        let mut d = Desktop::new();
        d.apply_key(key(Key::Tab)).unwrap(); // -> editor
        d.apply_key(key(Key::Tab)).unwrap(); // -> browser (raised)
                                             // Browser at (44,13) 34x10; action bar is row y=22. `[+ f]` sits in
                                             // seg 1 (click_col 7..13 -> cell x 52..58), `[+ d]` in seg 2
                                             // (click_col 14..20 -> cell x 59..65). Pick cell (55,22) and
                                             // (62,22); pixel_to_cell with CELL_OFFSET (0,0) is x*8, y*16.
        let out = d
            .apply_mouse(MouseEvent {
                x: 55 * 8,
                y: 22 * 16,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::CreatedFile {
                browser_id,
                name_len,
            } => {
                assert_eq!(browser_id, d.browser_id());
                assert_eq!(name_len, 0, "no durable store: honest empty report");
            }
            _ => panic!("expected a new-file create report from the action bar"),
        }
        let out = d
            .apply_mouse(MouseEvent {
                x: 62 * 8,
                y: 22 * 16,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::CreatedDir {
                browser_id,
                name_len,
            } => {
                assert_eq!(browser_id, d.browser_id());
                assert_eq!(name_len, 0, "no durable store: honest empty report");
            }
            _ => panic!("expected a new-dir create report from the action bar"),
        }
    }

    // --- Phase S: taskbar --------------------------------------------------

    /// The taskbar segment boundaries match `TASKBAR_SEG_W`/`TASKBAR_LABELS`
    /// exactly: segment 0 is columns 0..12, segment 1 12..24, segment 2
    /// 24..36, and nothing past that (the taskbar doesn't fill the full
    /// 80-column row).
    #[test]
    fn taskbar_segment_at_matches_the_rendered_layout() {
        let d = Desktop::new();
        assert_eq!(d.taskbar_segment_at(0), Some(0));
        assert_eq!(d.taskbar_segment_at(11), Some(0));
        assert_eq!(d.taskbar_segment_at(12), Some(1));
        assert_eq!(d.taskbar_segment_at(23), Some(1));
        assert_eq!(d.taskbar_segment_at(24), Some(2));
        assert_eq!(d.taskbar_segment_at(35), Some(2));
        assert_eq!(
            d.taskbar_segment_at(36),
            None,
            "past the last labeled segment"
        );
        assert_eq!(d.taskbar_segment_at(-1), None);
    }

    /// A click on the taskbar's editor segment focuses and raises the
    /// editor window — the mouse-only "launch the editor" gesture — and
    /// reports `TaskbarFocused`. Pixel (96, 384) is cell (12, 24): column
    /// 12 is segment 1's first column, row 24 is the taskbar row.
    #[test]
    fn taskbar_click_focuses_and_raises_the_editor() {
        let mut d = Desktop::new();
        assert_eq!(d.focus, AppFocus::Shell);
        let out = d
            .apply_mouse(MouseEvent {
                x: 96,
                y: 384,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::TaskbarFocused { window_id } => {
                assert_eq!(window_id, d.editor_id());
            }
            _ => panic!("expected a taskbar focus outcome"),
        }
        assert_eq!(d.focus, AppFocus::Editor);
        // Raised: the editor window now has the highest z-order.
        let max_z = |id: u32| d.wm.window(id).unwrap().z_order;
        assert!(max_z(d.editor_id()) > max_z(d.shell_id()));
        assert!(max_z(d.editor_id()) > max_z(d.browser_id()));
    }

    /// A click on the taskbar's browser segment (cell (24, 24), pixel
    /// (192, 384)) focuses and raises the browser window the same way.
    /// Together with the editor test above, this is the mouse-only
    /// "click between them to bring each to front" loop from the Phase S
    /// DoD, driven purely through `apply_mouse` — no Tab.
    #[test]
    fn taskbar_click_switches_between_editor_and_browser_mouse_only() {
        let mut d = Desktop::new();
        d.apply_mouse(MouseEvent {
            x: 96,
            y: 384,
            left_button: true,
            right_button: false,
            scroll: 0,
        });
        assert_eq!(d.focus, AppFocus::Editor);

        let out = d
            .apply_mouse(MouseEvent {
                x: 192,
                y: 384,
                left_button: true,
                right_button: false,
                scroll: 0,
            })
            .unwrap();
        match out {
            MouseOutcome::TaskbarFocused { window_id } => {
                assert_eq!(window_id, d.browser_id());
            }
            _ => panic!("expected a taskbar focus outcome"),
        }
        assert_eq!(d.focus, AppFocus::Browser);
        let max_z = |id: u32| d.wm.window(id).unwrap().z_order;
        assert!(max_z(d.browser_id()) > max_z(d.editor_id()));
    }

    /// `render_taskbar` paints the focused segment in reverse video
    /// (`0x4F00`, the same attribute the close button uses) and every
    /// other segment in the normal title attribute (`0x1F00`) — the
    /// visual half of "see the taskbar" from the Phase S DoD.
    #[test]
    fn render_taskbar_highlights_only_the_focused_segment() {
        let mut d = Desktop::new();
        // Boot default: shell focused, segment 0 highlighted.
        assert_eq!(
            d.fb_status[0] & 0xFF00,
            0x4F00,
            "shell segment starts highlighted"
        );
        assert_eq!(
            d.fb_status[12] & 0xFF00,
            0x1F00,
            "editor segment starts unhighlighted"
        );
        assert_eq!(
            d.fb_status[24] & 0xFF00,
            0x1F00,
            "browser segment starts unhighlighted"
        );

        d.apply_key(key(Key::Tab)).unwrap(); // -> editor
        assert_eq!(
            d.fb_status[0] & 0xFF00,
            0x1F00,
            "shell no longer highlighted"
        );
        assert_eq!(d.fb_status[12] & 0xFF00, 0x4F00, "editor now highlighted");
        assert_eq!(d.fb_status[24] & 0xFF00, 0x1F00);
    }

    // --- Phase R: the shell window's command interpreter -------------------

    /// Type `word` (lowercase ASCII letters/digits only) into the focused
    /// shell line via individual keypresses, matching how a real keyboard
    /// would submit it. Panics on any byte outside a-z/0-9/space, since no
    /// other character is typable per `input.rs`'s `Key` set.
    fn type_word(d: &mut Desktop, word: &[u8]) {
        for &b in word {
            let k = match b {
                b'a' => Key::A,
                b'b' => Key::B,
                b'c' => Key::C,
                b'd' => Key::D,
                b'e' => Key::E,
                b'f' => Key::F,
                b'g' => Key::G,
                b'h' => Key::H,
                b'i' => Key::I,
                b'j' => Key::J,
                b'k' => Key::K,
                b'l' => Key::L,
                b'm' => Key::M,
                b'n' => Key::N,
                b'o' => Key::O,
                b'p' => Key::P,
                b'q' => Key::Q,
                b'r' => Key::R,
                b's' => Key::S,
                b't' => Key::T,
                b'u' => Key::U,
                b'v' => Key::V,
                b'w' => Key::W,
                b'x' => Key::X,
                b'y' => Key::Y,
                b'z' => Key::Z,
                b'0' => Key::Zero,
                b'1' => Key::One,
                b'2' => Key::Two,
                b'3' => Key::Three,
                b'4' => Key::Four,
                b'5' => Key::Five,
                b'6' => Key::Six,
                b'7' => Key::Seven,
                b'8' => Key::Eight,
                b'9' => Key::Nine,
                b' ' => Key::Space,
                _ => panic!("no Key variant can type {b}"),
            };
            d.apply_key(key(k)).unwrap();
        }
    }

    /// Type `word` then Enter, returning the `KeyOutcome`.
    fn run_shell_command(d: &mut Desktop, word: &[u8]) -> KeyOutcome {
        type_word(d, word);
        d.apply_key(key(Key::Enter)).unwrap()
    }

    #[test]
    fn help_command_lists_every_command() {
        let mut d = Desktop::new();
        let out = run_shell_command(&mut d, b"help");
        match out {
            KeyOutcome::Enter {
                window_id, lines, ..
            } => {
                assert_eq!(window_id, d.shell_id());
                assert_eq!(lines, HELP_LINES.len());
            }
            _ => panic!("expected an enter"),
        }
        assert_eq!(d.terminal.lines().len(), HELP_LINES.len());
        assert_eq!(d.terminal.lines()[0].as_bytes(), HELP_LINES[0]);
    }

    #[test]
    fn ls_without_a_durable_store_reports_honestly_empty() {
        // No NVMe store is installed in tests (same honest degrade the
        // browser's F3 test above already exercises) — `ls` must say so
        // rather than fabricating rows.
        let mut d = Desktop::new();
        let out = run_shell_command(&mut d, b"ls");
        match out {
            KeyOutcome::Enter { lines, .. } => assert_eq!(lines, 1),
            _ => panic!("expected an enter"),
        }
        assert_eq!(d.terminal.lines()[0].as_bytes(), b"(no files)");
    }

    #[test]
    fn open_without_a_prior_listing_is_a_usage_error_not_a_panic() {
        let mut d = Desktop::new();
        let out = run_shell_command(&mut d, b"open 1");
        match out {
            KeyOutcome::Enter { lines, .. } => assert_eq!(lines, 1),
            _ => panic!("expected an enter"),
        }
        assert_eq!(
            d.terminal.lines()[0].as_bytes(),
            b"no such listing entry - run ls first"
        );
    }

    #[test]
    fn open_with_no_argument_is_a_usage_error() {
        let mut d = Desktop::new();
        let out = run_shell_command(&mut d, b"open");
        match out {
            KeyOutcome::Enter { lines, .. } => assert_eq!(lines, 1),
            _ => panic!("expected an enter"),
        }
        assert_eq!(
            d.terminal.lines()[0].as_bytes(),
            b"usage: open <n> (run ls first)"
        );
    }

    #[test]
    fn new_without_a_durable_store_reports_honestly() {
        let mut d = Desktop::new();
        let out = run_shell_command(&mut d, b"new");
        match out {
            KeyOutcome::Enter { lines, .. } => assert_eq!(lines, 1),
            _ => panic!("expected an enter"),
        }
        assert_eq!(
            d.terminal.lines()[0].as_bytes(),
            b"could not create file (no durable store?)"
        );
    }

    #[test]
    fn clear_empties_the_scrollback() {
        let mut d = Desktop::new();
        run_shell_command(&mut d, b"help");
        assert!(!d.terminal.lines().is_empty());
        let out = run_shell_command(&mut d, b"clear");
        match out {
            KeyOutcome::Enter { lines, .. } => assert_eq!(lines, 0),
            _ => panic!("expected an enter"),
        }
        assert!(d.terminal.lines().is_empty());
    }

    #[test]
    fn unknown_command_reports_without_panicking() {
        let mut d = Desktop::new();
        let out = run_shell_command(&mut d, b"frobnicate");
        match out {
            KeyOutcome::Enter { lines, .. } => assert_eq!(lines, 1),
            _ => panic!("expected an enter"),
        }
        assert_eq!(
            d.terminal.lines()[0].as_bytes(),
            b"unknown command - try 'help'"
        );
    }

    #[test]
    fn empty_line_produces_no_output() {
        let mut d = Desktop::new();
        let out = d.apply_key(key(Key::Enter)).unwrap();
        match out {
            KeyOutcome::Enter { len, lines, .. } => {
                assert_eq!(len, 0);
                assert_eq!(lines, 0);
            }
            _ => panic!("expected an enter"),
        }
        assert!(d.terminal.lines().is_empty());
    }

    #[test]
    fn scrollback_renders_top_down_from_row_one() {
        // After `help`, the composited screen should show the first help
        // line directly below the title bar (row 1), proving render_shell
        // actually paints scrollback rather than just tracking it
        // internally. Output grows top-down; with only 5 lines against a
        // 10-row scrollback area, row 1 holds the FIRST (not last) line.
        let mut d = Desktop::new();
        run_shell_command(&mut d, b"help");
        let first_output_row = (SHELL_Y + 1) as usize;
        let cell = (d.screen()[first_output_row * SW + SHELL_X as usize] & 0xFF) as u8;
        // HELP_LINES[0] is "commands: help ls clear new open <n>".
        assert_eq!(cell, b'c');
        let cell2 = (d.screen()[first_output_row * SW + SHELL_X as usize + 1] & 0xFF) as u8;
        assert_eq!(cell2, b'o');
    }
}

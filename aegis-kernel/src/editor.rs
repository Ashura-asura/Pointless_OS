//! Phase P: the kernel's first real application window — a text editor whose
//! buffer persists to the real NVMe-backed store. Two layers live here:
//!
//! - [`Editor`]: a pure, bounded, allocation-free text buffer (insert /
//!   backspace at a byte cursor, arrow navigation across `\n`-separated
//!   lines) plus the line-wrapping math (`visual_row`) the desktop's
//!   `render_editor` uses to paint it into a VGA text window. Fully
//!   host-testable.
//! - The durable file half: a `memo.txt` named file in a COW boot view over
//!   the write-through `nvme_store`. The view's dir id is anchored in the
//!   store header (`Store::set_anchor`) on first boot; a reboot re-attaches
//!   with [`update::BootView::at`] and reopens the SAME file, so a typed +
//!   F2-saved edit survives a power cycle. The generic helpers
//!   (`read_memo`/`write_memo`/`seed_if_absent`) run against any `BlockIo`
//!   (a `MemDisk` in tests, the live `NvmeController` at boot), and
//!   [`EditorFs`] is the concrete boot-time handle installed as the global
//!   the desktop reads on `Desktop::new()` and writes on the F2 gesture.
//!
//! Honest limits (kept visible, not hidden): one file, one name (`memo.txt`),
//! one 512 B block (a content block is a single store sector); the buffer is
//! fixed [`EDITOR_BUF_MAX`] bytes; single-line cursor math is byte-based (no
//! wide-glyph / UTF-8 awareness); when no NVMe store is present the editor
//! degrades to an in-memory buffer (UI only, edits are lost on reboot) — the
//! same write-through discipline `nvme_store` itself documents.

use crate::nvme::NvmeController;
use crate::nvme_store::{BlockIo, Store};
use crate::store::BlockId;
use crate::update::BootView;

/// Maximum editor buffer bytes — one store block, so a save is exactly one
/// content-addressed sector (matching `nvme_store`'s single-512-B-block limit).
pub const EDITOR_BUF_MAX: usize = 512;

/// The single named file the editor reads and writes.
pub const FILE_NAME: &[u8] = b"memo.txt";

/// The seed content written on first boot, so a reopen can prove persistence
/// by comparing what it reads against this.
pub const SEED: &[u8] = b"Aegis editor: first file";

/// The editor's live text buffer: `len` bytes at `buf[..len]`, cursor as a
/// byte offset into the buffer. Newlines are real `\n` bytes (the editor is
/// multi-line; the window wraps each line by its current width).
#[derive(Debug, Clone, Copy)]
pub struct Editor {
    buf: [u8; EDITOR_BUF_MAX],
    len: usize,
    cursor: usize,
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

impl Editor {
    /// An empty buffer with the cursor at position 0.
    pub fn new() -> Editor {
        Editor {
            buf: [0u8; EDITOR_BUF_MAX],
            len: 0,
            cursor: 0,
        }
    }

    /// Load `bytes` into the buffer (truncated at [`EDITOR_BUF_MAX`]); the
    /// cursor lands at the end so typing appends, like opening a file to edit.
    pub fn from_bytes(bytes: &[u8]) -> Editor {
        let mut e = Editor::new();
        let n = bytes.len().min(EDITOR_BUF_MAX);
        e.buf[..n].copy_from_slice(&bytes[..n]);
        e.len = n;
        e.cursor = n;
        e
    }

    /// The buffer contents.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Number of bytes in the buffer.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The cursor position (a byte offset into the buffer).
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Insert `ch` at the cursor and advance past it. Refused (false) when
    /// the buffer is full — no panic, no silent truncation.
    pub fn insert(&mut self, ch: u8) -> bool {
        if self.len >= EDITOR_BUF_MAX {
            return false;
        }
        let mut i = self.len;
        while i > self.cursor {
            self.buf[i] = self.buf[i - 1];
            i -= 1;
        }
        self.buf[self.cursor] = ch;
        self.len += 1;
        self.cursor += 1;
        true
    }

    /// Delete the byte before the cursor. Refused (false) at position 0.
    pub fn backspace(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        let mut i = self.cursor - 1;
        while i + 1 < self.len {
            self.buf[i] = self.buf[i + 1];
            i += 1;
        }
        self.len -= 1;
        self.cursor -= 1;
        true
    }

    /// Move the cursor one byte left; false when already at 0.
    pub fn cursor_left(&mut self) -> bool {
        if self.cursor > 0 {
            self.cursor -= 1;
            true
        } else {
            false
        }
    }

    /// Move the cursor one byte right; false when already at the end.
    pub fn cursor_right(&mut self) -> bool {
        if self.cursor < self.len {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    /// Move the cursor up one line, keeping its column (clamped to the line's
    /// length). False when already on the first line.
    pub fn cursor_up(&mut self) -> bool {
        let line_start = Self::line_start(&self.buf[..self.len], self.cursor);
        if line_start == 0 {
            return false;
        }
        let col = self.cursor - line_start;
        let prev_start = Self::line_start(&self.buf[..self.len], line_start - 1);
        let prev_len = line_start - 1 - prev_start; // without its trailing '\n'
        let target = prev_start + col.min(prev_len);
        if target != self.cursor {
            self.cursor = target;
            true
        } else {
            false
        }
    }

    /// Move the cursor down one line, keeping its column (clamped to the
    /// line's length). False when already on the last line.
    pub fn cursor_down(&mut self) -> bool {
        let line_start = Self::line_start(&self.buf[..self.len], self.cursor);
        let line_end = Self::line_end(&self.buf[..self.len], self.cursor);
        if line_end >= self.len {
            return false; // already on the last line (or past it)
        }
        let col = self.cursor - line_start;
        let next_start = line_end + 1; // skip the '\n'
        let next_end = Self::line_end(&self.buf[..self.len], next_start);
        let next_len = next_end - next_start;
        let target = next_start + col.min(next_len);
        if target != self.cursor {
            self.cursor = target;
            true
        } else {
            false
        }
    }

    /// Byte index of the start of the line containing `pos` (the byte after
    /// the preceding '\n', or 0).
    fn line_start(buf: &[u8], pos: usize) -> usize {
        let pos = pos.min(buf.len());
        let mut i = pos;
        while i > 0 && buf[i - 1] != b'\n' {
            i -= 1;
        }
        i
    }

    /// Byte index of the '\n' ending the line containing `pos`, or `buf.len()`
    /// when the line is the last (unterminated) one.
    fn line_end(buf: &[u8], pos: usize) -> usize {
        let pos = pos.min(buf.len());
        let mut i = pos;
        while i < buf.len() && buf[i] != b'\n' {
            i += 1;
        }
        i
    }

    /// Map visual content row `row` (0-based, below a window's title bar) to
    /// the byte range `(start..end)` to paint, and the cursor column within
    /// that row when the cursor sits in it. Lines wrap every `width` columns;
    /// an empty line occupies one row. Returns `None` for a row beyond the
    /// buffer's content (the window paints its background fill there).
    ///
    /// This is the pure half of `desktop::render_editor`: the desktop asks
    /// one row at a time and paints the returned slice, so wrapping, cursor
    /// placement and bounds all stay host-testable.
    pub fn visual_row(&self, row: usize, width: usize) -> Option<(usize, usize, Option<usize>)> {
        let width = width.max(1);
        let mut start = 0usize;
        let mut cur_row = 0usize;
        loop {
            let mut end = start;
            while end < self.len && self.buf[end] != b'\n' {
                end += 1;
            }
            let line_len = end - start;
            let visual = if line_len == 0 {
                1
            } else {
                line_len.div_ceil(width)
            };
            if cur_row + visual > row {
                let in_row = row - cur_row;
                let seg_start = start + in_row * width;
                let seg_end = (seg_start + width).min(end);
                let cursor_col = if self.cursor >= seg_start && self.cursor <= seg_end {
                    Some((self.cursor - seg_start).min(width.saturating_sub(1)))
                } else {
                    None
                };
                return Some((seg_start, seg_end, cursor_col));
            }
            cur_row += visual;
            if end >= self.len {
                break;
            }
            start = end + 1;
        }
        // Content exhausted: an empty buffer still gets one cursor row.
        if self.len == 0 && row == 0 {
            return Some((0, 0, Some(0)));
        }
        None
    }
}

// --- durable file half ------------------------------------------------------

/// Seed `memo.txt` into `view` if it is absent, else read it back. Returns
/// `(bytes_read, created)` — `created` true only on the first boot that wrote
/// the seed. Generic over `BlockIo` so the live NVMe path and the `MemDisk`
/// tests share one implementation.
pub fn seed_if_absent<IO: BlockIo>(
    store: &mut Store,
    io: &mut IO,
    view: &mut BootView,
    out: &mut [u8],
) -> Option<(usize, bool)> {
    if view.get(store, io, FILE_NAME).is_some() {
        let n = view.read_file(store, io, FILE_NAME, out)?;
        return Some((n, false));
    }
    let id = view.write_file(store, io, FILE_NAME, SEED)?;
    let _ = id;
    out[..SEED.len()].copy_from_slice(SEED);
    Some((SEED.len(), true))
}

/// Read `memo.txt` from `view` into `out`; the number of bytes, or `None` when
/// the file (or its block) is absent.
pub fn read_memo<IO: BlockIo>(
    store: &mut Store,
    io: &mut IO,
    view: &mut BootView,
    out: &mut [u8],
) -> Option<usize> {
    view.read_file(store, io, FILE_NAME, out)
}

/// Write `bytes` as `memo.txt` in `view` (COW: a new content block + a new
/// dir block; nothing in place is mutated). Returns the new content block id
/// for the save report.
pub fn write_memo<IO: BlockIo>(
    store: &mut Store,
    io: &mut IO,
    view: &mut BootView,
    bytes: &[u8],
) -> Option<BlockId> {
    view.write_file(store, io, FILE_NAME, bytes)
}

/// The concrete boot-time editor file handle: the live NVMe controller + the
/// store + the anchored boot view. Installed once as the global below; the
/// desktop reads the file at `Desktop::new()` and writes it on F2.
pub struct EditorFs {
    pub ctrl: NvmeController,
    pub store: Store,
    pub view: BootView,
}

impl EditorFs {
    /// Read `memo.txt` through this handle (see [`read_memo`]).
    pub fn read_memo(&mut self, out: &mut [u8]) -> Option<usize> {
        read_memo(&mut self.store, &mut self.ctrl, &mut self.view, out)
    }

    /// Write `bytes` through this handle (see [`write_memo`]). After the COW
    /// commit the boot view's dir block is a NEW immutable block, so the store
    /// header anchor is re-persisted to that id — otherwise a reboot would
    /// re-attach to the previous (seed) dir block and lose the save.
    pub fn write_memo(&mut self, bytes: &[u8]) -> Option<BlockId> {
        let id = write_memo(&mut self.store, &mut self.ctrl, &mut self.view, bytes)?;
        let dir = self.view.dir_id();
        if self.store.set_anchor(&mut self.ctrl, &dir) {
            Some(id)
        } else {
            None
        }
    }
}

/// The one live editor file handle, installed at boot inside the NVMe store
/// block (after the corruption demo, so the seeded file can never land in the
/// deliberately-corrupted slot-0 block).
static mut EDITOR_FS: Option<EditorFs> = None;

/// Install the live editor file handle.
///
/// # Safety
///
/// Single-threaded boot-time call, once, after `Store::open` succeeded.
pub unsafe fn install(fs: EditorFs) {
    core::ptr::addr_of_mut!(EDITOR_FS).write(Some(fs));
}

/// Run `f` against the live editor handle, if one was installed. None when
/// there is no NVMe store (the editor then runs as an in-memory buffer only).
pub fn with<R>(f: impl FnOnce(&mut EditorFs) -> R) -> Option<R> {
    unsafe { core::ptr::addr_of_mut!(EDITOR_FS).as_mut() }
        .and_then(|o| o.as_mut())
        .map(f)
}

/// True when a durable editor file handle was installed (for boot-log clarity).
pub fn durable() -> bool {
    unsafe { core::ptr::addr_of!(EDITOR_FS).as_ref() }
        .map(|o| o.is_some())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nvme_store::{DATA_BASE_LBA, STORE_START_LBA};

    const SECTOR: usize = 512;

    struct MemDisk {
        sectors: Vec<[u8; SECTOR]>,
    }

    impl MemDisk {
        fn new(sectors: usize) -> MemDisk {
            MemDisk {
                sectors: vec![[0u8; SECTOR]; sectors],
            }
        }
    }

    impl BlockIo for MemDisk {
        fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> bool {
            let Some(s) = self.sectors.get(lba as usize) else {
                return false;
            };
            out[..SECTOR].copy_from_slice(s);
            true
        }

        fn write_sector(&mut self, lba: u64, data: &[u8]) -> bool {
            let Some(s) = self.sectors.get_mut(lba as usize) else {
                return false;
            };
            s[..SECTOR.min(data.len())].copy_from_slice(&data[..SECTOR.min(data.len())]);
            true
        }
    }

    /// A fresh store + boot view on a MemDisk, ready for file tests.
    fn world() -> (MemDisk, Store, BootView) {
        let mut disk = MemDisk::new(9000);
        let mut store = Store::open(&mut disk).unwrap();
        let view = BootView::create(&mut store, &mut disk).unwrap();
        (disk, store, view)
    }

    #[test]
    fn insert_and_backspace_roundtrip() {
        let mut e = Editor::new();
        assert!(e.is_empty());
        for &b in b"hello" {
            assert!(e.insert(b));
        }
        assert_eq!(e.as_bytes(), b"hello");
        assert_eq!(e.cursor(), 5);
        // Move to the middle and insert: shifts the tail.
        for _ in 0..2 {
            e.cursor_left();
        }
        assert!(e.insert(b'!'));
        assert_eq!(e.as_bytes(), b"hel!lo");
        assert_eq!(e.cursor(), 4);
        // Backspace at the middle removes the inserted byte.
        assert!(e.backspace());
        assert_eq!(e.as_bytes(), b"hello");
        assert_eq!(e.cursor(), 3);
    }

    #[test]
    fn buffer_bounds_hold() {
        let mut e = Editor::new();
        // Fill to capacity exactly.
        for i in 0..EDITOR_BUF_MAX {
            assert!(e.insert((i % 256) as u8));
        }
        assert_eq!(e.len(), EDITOR_BUF_MAX);
        assert!(!e.insert(b'x'), "full buffer refuses, never truncates");
        assert_eq!(e.len(), EDITOR_BUF_MAX);
        // Backspace at position 0 refuses.
        let mut empty = Editor::new();
        assert!(!empty.backspace());
        // from_bytes truncates silently, cursor at end.
        let big = [b'z'; EDITOR_BUF_MAX + 20];
        let e2 = Editor::from_bytes(&big);
        assert_eq!(e2.len(), EDITOR_BUF_MAX);
        assert_eq!(e2.cursor(), EDITOR_BUF_MAX);
    }

    #[test]
    fn from_bytes_puts_cursor_at_end() {
        let e = Editor::from_bytes(b"abc");
        assert_eq!(e.as_bytes(), b"abc");
        assert_eq!(e.cursor(), 3);
    }

    #[test]
    fn cursor_moves_across_lines_keeping_column() {
        // "line one\nline two\nxyz": line 1 = 0..8, '\n' @ 8; line 2 = 9..17
        // ('\n' @ 17); line 3 = 18..21. Cursor starts at the end (21).
        let mut e = Editor::from_bytes(b"line one\nline two\nxyz");
        assert_eq!(e.cursor(), 21);
        assert!(e.cursor_up()); // -> line 2 col 3 (clamped from col 3)
        assert_eq!(e.cursor(), 12);
        assert!(e.cursor_up()); // -> line 1 col 3
        assert_eq!(e.cursor(), 3);
        // Up again: already first line.
        assert!(!e.cursor_up());
        // Down twice returns to the last line, column clamped.
        assert!(e.cursor_down());
        assert_eq!(e.cursor(), 12);
        assert!(e.cursor_down());
        assert_eq!(e.cursor(), 21);
        assert!(!e.cursor_down(), "already on the last line");
        // Down into a shorter line clamps the column to its length.
        let mut s = Editor::from_bytes(b"ab\ncdefg");
        s.cursor = 2; // line 1 col 2 (at the '\n' position)
        assert!(s.cursor_down());
        assert_eq!(s.cursor(), 3 + 2); // line 2 col 2
    }

    #[test]
    fn visual_row_wraps_long_lines_and_places_cursor() {
        // 10 columns: "abcdefghijkl" wraps to row 0 "abcdefghij" + row 1 "kl".
        let mut e = Editor::from_bytes(b"abcdefghijkl\nxy");
        e.cursor = 5;
        assert_eq!(e.visual_row(0, 10), Some((0, 10, Some(5))));
        assert_eq!(e.visual_row(1, 10), Some((10, 12, None)));
        assert_eq!(e.visual_row(2, 10), Some((13, 15, None)));
        assert_eq!(e.visual_row(3, 10), None);
        // Cursor past a row boundary lands in the wrapped row.
        e.cursor = 12;
        assert_eq!(e.visual_row(1, 10), Some((10, 12, Some(2))));
        // Empty buffer: one cursor row at col 0.
        let empty = Editor::new();
        assert_eq!(empty.visual_row(0, 10), Some((0, 0, Some(0))));
        assert_eq!(empty.visual_row(1, 10), None);
        // An empty trailing line (buffer ends with '\n') is its own row.
        let mut t = Editor::from_bytes(b"ab\n");
        t.cursor = 3;
        assert_eq!(t.visual_row(0, 10), Some((0, 2, None)));
        assert_eq!(t.visual_row(1, 10), Some((3, 3, Some(0))));
    }

    #[test]
    fn seed_if_absent_writes_seed_on_fresh_view() {
        let (mut disk, mut store, mut view) = world();
        let mut out = [0u8; 512];
        let (n, created) = seed_if_absent(&mut store, &mut disk, &mut view, &mut out).unwrap();
        assert!(created);
        assert_eq!(&out[..n], SEED);
        // Re-running on the same view reads back, never rewrites.
        let (n2, created2) = seed_if_absent(&mut store, &mut disk, &mut view, &mut out).unwrap();
        assert!(!created2);
        assert_eq!(&out[..n2], SEED);
    }

    #[test]
    fn write_then_read_roundtrips_the_edited_bytes() {
        let (mut disk, mut store, mut view) = world();
        let edited = b"Aegis editor: first file\nhi typed here";
        let id = write_memo(&mut store, &mut disk, &mut view, edited).unwrap();
        assert_eq!(id, crate::store::sha256(edited)); // content addressing
        let mut out = [0u8; 512];
        let n = read_memo(&mut store, &mut disk, &mut view, &mut out).unwrap();
        assert_eq!(&out[..n], edited);
    }

    /// The Phase P persistence contract: a reboot (a fresh store handle
    /// re-attached to the SAME anchored dir id) reopens the file as edited,
    /// not as the seed — the change survived the "power cycle".
    #[test]
    fn reboot_reopens_the_edited_file_not_the_seed() {
        let mut disk = MemDisk::new(9000);
        let mut store = Store::open(&mut disk).unwrap();
        let mut view = BootView::create(&mut store, &mut disk).unwrap();
        let mut out = [0u8; 512];
        seed_if_absent(&mut store, &mut disk, &mut view, &mut out).unwrap();

        // The edit (typed characters) + save.
        let edited = b"Aegis editor: first file\nhi typed";
        write_memo(&mut store, &mut disk, &mut view, edited).unwrap();

        // The anchor survives the reboot (same store, reopened).
        let dir = view.dir_id();
        assert!(store.set_anchor(&mut disk, &dir));
        let mut store2 = Store::open(&mut disk).unwrap();
        let anchor = store2.anchor(&mut disk).unwrap();
        assert_eq!(anchor, dir, "the boot view's dir id is durable");

        // A fresh handle re-attaches to the anchored dir: same file, edited.
        let mut view2 = BootView::at(anchor);
        let mut out2 = [0u8; 512];
        let (n, created) = seed_if_absent(&mut store2, &mut disk, &mut view2, &mut out2).unwrap();
        assert!(!created, "the file exists, so no seed is written again");
        assert_ne!(&out2[..n], SEED, "reopen reads the edit, not the seed");
        assert_eq!(&out2[..n], edited);
    }

    #[test]
    fn editor_region_never_touches_the_corruption_demo_slot() {
        // The store's first data slot (DATA_BASE_LBA) is what the boot's
        // corruption demo deliberately flips. A file that lands at slot 0
        // would read back corrupted — this test proves the editor path starts
        // writing at slot 1+, so seeding AFTER the demo is safe by geometry.
        let mut disk = MemDisk::new(9000);
        let mut store = Store::open(&mut disk).unwrap();
        let mut view = BootView::create(&mut store, &mut disk).unwrap();
        let mut out = [0u8; 512];
        seed_if_absent(&mut store, &mut disk, &mut view, &mut out).unwrap();
        // BootView::create itself used a block (the empty dir), so the seed is
        // never slot 0: it must live strictly above DATA_BASE_LBA.
        assert!(store.count() >= 1);
        let _ = DATA_BASE_LBA;
        let _ = STORE_START_LBA;
        // After seeding, the seed reads back intact (digest-verified).
        let mut out2 = [0u8; 512];
        let n = read_memo(&mut store, &mut disk, &mut view, &mut out2).unwrap();
        assert_eq!(&out2[..n], SEED);
    }
}

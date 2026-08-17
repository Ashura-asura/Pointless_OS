//! Phase Q: the kernel's third real application window — a file browser
//! over the boot view the Phase P text editor already reads and writes
//! (`editor::EditorFs`'s `BootView`, NVMe-backed and durable). This module
//! is the pure, host-testable half — a bounded, allocation-free browsing
//! widget — mirroring the split `editor.rs` already uses (a pure `Editor`
//! buffer + a durable file half installed at boot). `desktop.rs` owns the
//! durable half: it lists entries through
//! `editor::with(|fs| fs.browser_list(path, ...))`, feeds them to
//! `FileBrowser::set_entries`, and drives selection from mouse clicks /
//! arrow keys, exactly the way it already drives `Editor` from keystrokes.
//!
//! **Phase Q (completion): the widget is now hierarchical.** The durable
//! boot view (`update::BootView`) itself nests directories (entry `kind` 1 =
//! dir, 0 = file — see `update::KIND_DIR`/`KIND_FILE`), so the browser
//! tracks a `&[Name]` path from the root, shows a `..` pseudo-entry when not
//! at the root, and lists `(name, kind)` pairs. This closes the Phase Q
//! audit deviation: the browser lists the same durable POSIX projection the
//! editor and shell share — there is no separate in-memory view in the
//! browser path.
//!
//! Honest limits (kept visible, not hidden): entries are capped at
//! [`MAX_ENTRIES`] = [`update::VIEW_MAX_FILES`] + 1 (one `..` pseudo-entry
//! plus a full directory's worth of real entries — the browser cannot show
//! more names than the view can hold, plus the up-gesture); path depth is
//! capped at [`MAX_DEPTH`] like the store's own tree; a "new file"/"new
//! dir" gesture picks the first unused `fileN.txt`/`dirN` name rather than
//! prompting for one (no text-entry dialog exists yet).

use crate::store::{Name, MAX_DEPTH};
use crate::update::{KIND_DIR, KIND_FILE, VIEW_MAX_FILES};

/// Maximum entries the browser can hold — one more than the view's own cap,
/// so a `..` up-gesture can lead a full directory without hiding an entry.
pub const MAX_ENTRIES: usize = VIEW_MAX_FILES + 1;

/// A bounded, allocation-free listing of `(name, kind)` pairs with a
/// selection cursor plus a path stack into the hierarchical boot view. Pure
/// UI state: no I/O, no store access — `desktop.rs` populates it from
/// `editor::EditorFs::browser_list` and reads the path/selection to decide
/// what to open or create.
#[derive(Debug, Clone, Copy)]
pub struct FileBrowser {
    entries: [(Name, u8); MAX_ENTRIES],
    count: usize,
    selected: usize,
    path: [Name; MAX_DEPTH],
    depth: usize,
}

impl Default for FileBrowser {
    fn default() -> Self {
        Self::new()
    }
}

impl FileBrowser {
    /// An empty listing at the root, selection at 0.
    pub fn new() -> FileBrowser {
        FileBrowser {
            entries: [(Name::default(), KIND_FILE); MAX_ENTRIES],
            count: 0,
            selected: 0,
            path: [Name::default(); MAX_DEPTH],
            depth: 0,
        }
    }

    /// Replace the listing with `entries[..entries.len().min(MAX_ENTRIES)]`.
    /// Never panics on an oversized slice — the tail is simply dropped, the
    /// same "bounded, never silently overrun a documented cap" discipline as
    /// the rest of this codebase's parsers. Clamps the selection back into
    /// range (or to 0 on an empty listing).
    pub fn set_entries(&mut self, entries: &[(Name, u8)]) {
        let n = entries.len().min(MAX_ENTRIES);
        self.entries[..n].copy_from_slice(&entries[..n]);
        for e in self.entries[n..].iter_mut() {
            *e = (Name::default(), KIND_FILE);
        }
        self.count = n;
        if self.selected >= self.count {
            self.selected = self.count.saturating_sub(1);
        }
    }

    /// Number of entries currently listed.
    pub fn count(&self) -> usize {
        self.count
    }

    /// The current selection index (0 when the listing is empty).
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// The `(name, kind)` pair at `idx`, or `None` if out of range.
    pub fn entry(&self, idx: usize) -> Option<(Name, u8)> {
        if idx < self.count {
            Some(self.entries[idx])
        } else {
            None
        }
    }

    /// The pair currently selected, or `None` on an empty listing.
    pub fn selected_entry(&self) -> Option<(Name, u8)> {
        self.entry(self.selected)
    }

    /// True when the entry at `idx` is a directory.
    pub fn is_dir(&self, idx: usize) -> bool {
        matches!(self.entry(idx), Some((_, KIND_DIR)))
    }

    /// The current path components from the root (empty slice = root).
    pub fn path(&self) -> &[Name] {
        &self.path[..self.depth]
    }

    /// True when the browser is at the root directory (no path to pop).
    pub fn at_root(&self) -> bool {
        self.depth == 0
    }

    /// Descend one level: append `name` to the path. False if the path is
    /// already at [`MAX_DEPTH`] (the store's own depth cap).
    pub fn push_dir(&mut self, name: Name) -> bool {
        if self.depth >= MAX_DEPTH {
            return false;
        }
        self.path[self.depth] = name;
        self.depth += 1;
        self.selected = 0;
        true
    }

    /// Ascend one level: pop the last path component. False at the root.
    pub fn pop_dir(&mut self) -> bool {
        if self.depth == 0 {
            return false;
        }
        self.depth -= 1;
        self.path[self.depth] = Name::default();
        self.selected = 0;
        true
    }

    /// Move the selection up one row. False (no-op) already at the top or
    /// on an empty listing.
    pub fn move_up(&mut self) -> bool {
        if self.selected > 0 {
            self.selected -= 1;
            true
        } else {
            false
        }
    }

    /// Move the selection down one row. False (no-op) already at the
    /// bottom or on an empty listing.
    pub fn move_down(&mut self) -> bool {
        if self.count > 0 && self.selected + 1 < self.count {
            self.selected += 1;
            true
        } else {
            false
        }
    }

    /// Select `idx` directly (a mouse click on row `idx`). False if out of
    /// range; the selection is left unchanged.
    pub fn select(&mut self, idx: usize) -> bool {
        if idx < self.count {
            self.selected = idx;
            true
        } else {
            false
        }
    }

    /// The first name of the form `fileN.txt` (N = 1, 2, ...) not already
    /// present in the listing, for the "new file" gesture. Bounded search
    /// (the view caps at `VIEW_MAX_FILES` names, so a free name always
    /// exists at or before `VIEW_MAX_FILES + 1` candidates). Returns the
    /// name bytes and how many of them are meaningful.
    pub fn next_free_name(&self) -> ([u8; 16], usize) {
        let mut out = [0u8; 16];
        for n in 1..=(VIEW_MAX_FILES + 1) {
            let len = format_n(b"file", b".txt", n, &mut out);
            let taken = self.entries[..self.count]
                .iter()
                .any(|(e, _)| e.as_slice() == &out[..len]);
            if !taken {
                return (out, len);
            }
        }
        // Unreachable in practice (a free slot exists within the search
        // bound above), but stay total rather than panicking.
        let len = format_n(b"file", b".txt", 0, &mut out);
        (out, len)
    }

    /// The first name of the form `dirN` (N = 1, 2, ...) not already present
    /// in the listing, for the "new directory" gesture. Same bounded search
    /// as [`Self::next_free_name`].
    pub fn next_free_dir_name(&self) -> ([u8; 16], usize) {
        let mut out = [0u8; 16];
        for n in 1..=(VIEW_MAX_FILES + 1) {
            let len = format_n(b"dir", b"", n, &mut out);
            let taken = self.entries[..self.count]
                .iter()
                .any(|(e, _)| e.as_slice() == &out[..len]);
            if !taken {
                return (out, len);
            }
        }
        let len = format_n(b"dir", b"", 0, &mut out);
        (out, len)
    }
}

/// Render `<prefix><n><suffix>` into `out`, returning how many bytes were
/// written (a pure, allocation-free decimal formatter — the same discipline
/// `update::write_u64` already uses for descriptor encoding).
fn format_n(prefix: &[u8], suffix: &[u8], n: usize, out: &mut [u8; 16]) -> usize {
    let mut at = 0usize;
    out[at..at + prefix.len()].copy_from_slice(prefix);
    at += prefix.len();
    if n == 0 {
        out[at] = b'0';
        at += 1;
    } else {
        let mut digits = [0u8; 6];
        let mut d = 0usize;
        let mut v = n;
        while v > 0 {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
        for i in (0..d).rev() {
            out[at] = digits[i];
            at += 1;
        }
    }
    out[at..at + suffix.len()].copy_from_slice(suffix);
    at += suffix.len();
    at
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        Name::from_slice(s.as_bytes()).unwrap()
    }

    #[test]
    fn empty_listing_has_no_selection() {
        let b = FileBrowser::new();
        assert_eq!(b.count(), 0);
        assert_eq!(b.selected(), 0);
        assert!(b.selected_entry().is_none());
        assert!(b.at_root());
        assert!(b.path().is_empty());
    }

    #[test]
    fn set_entries_populates_and_clamps_selection() {
        let mut b = FileBrowser::new();
        assert!(!b.select(0), "no-op on an empty listing");
        let entries = [
            (name("a.txt"), KIND_FILE),
            (name("b.txt"), KIND_FILE),
            (name("c"), KIND_DIR),
        ];
        b.set_entries(&entries);
        assert_eq!(b.count(), 3);
        assert_eq!(b.selected_entry().unwrap().0.as_slice(), b"a.txt");
        assert!(b.is_dir(2));
        b.select(2);
        assert_eq!(b.selected_entry().unwrap().0.as_slice(), b"c");
        // Shrinking the listing clamps the selection back into range.
        b.set_entries(&entries[..1]);
        assert_eq!(b.count(), 1);
        assert_eq!(b.selected(), 0);
    }

    #[test]
    fn move_up_down_bounded_at_the_edges() {
        let mut b = FileBrowser::new();
        let entries = [
            (name("a.txt"), KIND_FILE),
            (name("b.txt"), KIND_FILE),
            (name("c.txt"), KIND_FILE),
        ];
        b.set_entries(&entries);
        assert!(!b.move_up(), "already at the top");
        assert!(b.move_down());
        assert_eq!(b.selected(), 1);
        assert!(b.move_down());
        assert_eq!(b.selected(), 2);
        assert!(!b.move_down(), "already at the bottom");
        assert!(b.move_up());
        assert_eq!(b.selected(), 1);
    }

    #[test]
    fn select_rejects_out_of_range() {
        let mut b = FileBrowser::new();
        let entries = [(name("a.txt"), KIND_FILE), (name("b.txt"), KIND_FILE)];
        b.set_entries(&entries);
        assert!(!b.select(5));
        assert_eq!(b.selected(), 0);
        assert!(b.select(1));
        assert_eq!(b.selected(), 1);
    }

    #[test]
    fn oversized_listing_is_dropped_not_panicked() {
        let mut b = FileBrowser::new();
        let entries = [(name("a.txt"), KIND_FILE); MAX_ENTRIES + 3];
        b.set_entries(&entries);
        assert_eq!(b.count(), MAX_ENTRIES);
    }

    #[test]
    fn next_free_name_skips_taken_names() {
        let mut b = FileBrowser::new();
        let entries = [
            (name("file1.txt"), KIND_FILE),
            (name("file2.txt"), KIND_FILE),
        ];
        b.set_entries(&entries);
        let (buf, len) = b.next_free_name();
        assert_eq!(&buf[..len], b"file3.txt");
    }

    #[test]
    fn next_free_name_on_empty_listing_is_file1() {
        let b = FileBrowser::new();
        let (buf, len) = b.next_free_name();
        assert_eq!(&buf[..len], b"file1.txt");
    }

    #[test]
    fn next_free_dir_name_is_dir1_then_dir2() {
        let mut b = FileBrowser::new();
        let (buf, len) = b.next_free_dir_name();
        assert_eq!(&buf[..len], b"dir1");
        let entries = [(name("dir1"), KIND_DIR)];
        b.set_entries(&entries);
        let (buf2, len2) = b.next_free_dir_name();
        assert_eq!(&buf2[..len2], b"dir2");
    }

    #[test]
    fn path_push_pop_is_bounded_by_max_depth() {
        let mut b = FileBrowser::new();
        for i in 0..MAX_DEPTH {
            let n = Name::from_slice(format!("d{i}").as_bytes()).unwrap();
            assert!(b.push_dir(n));
        }
        assert!(!b.push_dir(name("overflow")), "at the depth cap");
        assert!(!b.at_root());
        assert_eq!(b.path().len(), MAX_DEPTH);
        for _ in 0..MAX_DEPTH {
            assert!(b.pop_dir());
        }
        assert!(!b.pop_dir(), "already at the root");
        assert!(b.at_root());
    }
}

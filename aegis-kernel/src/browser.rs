//! Phase Q: the kernel's third real application window — a file browser
//! over the boot view the Phase P text editor already reads and writes
//! (`editor::EditorFs`'s `BootView`, NVMe-backed and durable). This module
//! is the pure, host-testable half — a bounded, allocation-free browsing
//! widget over a fixed list of names — mirroring the split `editor.rs`
//! already uses (a pure `Editor` buffer + a durable file half installed at
//! boot). `desktop.rs` owns the durable half: it lists names through
//! `editor::with(|fs| fs.list(...))`, feeds them to `FileBrowser::set_entries`,
//! and drives selection from mouse clicks / arrow keys, exactly the way it
//! already drives `Editor` from keystrokes.
//!
//! Honest limits (kept visible, not hidden): entries are capped at
//! [`MAX_ENTRIES`] (mirrors the boot view's own `VIEW_MAX_FILES` cap — the
//! browser cannot show more names than the view can hold); there is no
//! subdirectory nesting (the boot view Phase P's editor uses is a flat
//! namespace, not the separate in-memory `store::TreeView` — those are two
//! different projections in this codebase today, see `update.rs`'s module
//! docs); a "new file" gesture picks the first unused `fileN.txt` name
//! rather than prompting for one (no text-entry dialog exists yet).

use crate::store::Name;
use crate::update::VIEW_MAX_FILES;

/// Maximum entries the browser can hold — mirrors the boot view's own cap,
/// so the browser never claims to show more than the view can name.
pub const MAX_ENTRIES: usize = VIEW_MAX_FILES;

/// A bounded, allocation-free list of file names with a selection cursor.
/// Pure UI state: no I/O, no store access — `desktop.rs` populates it from
/// `editor::EditorFs::list` and reads `selected_name` to decide what to
/// open.
#[derive(Debug, Clone, Copy)]
pub struct FileBrowser {
    entries: [Name; MAX_ENTRIES],
    count: usize,
    selected: usize,
}

impl Default for FileBrowser {
    fn default() -> Self {
        Self::new()
    }
}

impl FileBrowser {
    /// An empty listing, selection at 0.
    pub fn new() -> FileBrowser {
        FileBrowser {
            entries: [Name::default(); MAX_ENTRIES],
            count: 0,
            selected: 0,
        }
    }

    /// Replace the listing with `names[..names.len().min(MAX_ENTRIES)]`.
    /// Never panics on an oversized slice — the tail is simply dropped,
    /// the same "bounded, never silently overrun a documented cap"
    /// discipline as the rest of this codebase's parsers. Clamps the
    /// selection back into range (or to 0 on an empty listing).
    pub fn set_entries(&mut self, names: &[Name]) {
        let n = names.len().min(MAX_ENTRIES);
        self.entries[..n].copy_from_slice(&names[..n]);
        for e in self.entries[n..].iter_mut() {
            *e = Name::default();
        }
        self.count = n;
        if self.selected >= self.count {
            self.selected = self.count.saturating_sub(1);
        }
    }

    /// Number of names currently listed.
    pub fn count(&self) -> usize {
        self.count
    }

    /// The current selection index (0 when the listing is empty).
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// The name at `idx`, or `None` if out of range.
    pub fn entry(&self, idx: usize) -> Option<Name> {
        if idx < self.count {
            Some(self.entries[idx])
        } else {
            None
        }
    }

    /// The name currently selected, or `None` on an empty listing.
    pub fn selected_name(&self) -> Option<Name> {
        self.entry(self.selected)
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
    /// (the view caps at `MAX_ENTRIES` names, so a free name always exists
    /// at or before `MAX_ENTRIES + 1` candidates). Returns the name bytes
    /// and how many of them are meaningful.
    pub fn next_free_name(&self) -> ([u8; 16], usize) {
        let mut out = [0u8; 16];
        for n in 1..=(MAX_ENTRIES + 1) {
            let len = format_file_n(n, &mut out);
            let taken = self.entries[..self.count]
                .iter()
                .any(|e| e.as_slice() == &out[..len]);
            if !taken {
                return (out, len);
            }
        }
        // Unreachable in practice (a free slot exists within the search
        // bound above), but stay total rather than panicking.
        let len = format_file_n(0, &mut out);
        (out, len)
    }
}

/// Render `fileN.txt` into `out`, returning how many bytes were written (a
/// pure, allocation-free decimal formatter — the same discipline
/// `update::write_u64` already uses for descriptor encoding).
fn format_file_n(n: usize, out: &mut [u8; 16]) -> usize {
    let prefix = b"file";
    let suffix = b".txt";
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
        assert!(b.selected_name().is_none());
    }

    #[test]
    fn set_entries_populates_and_clamps_selection() {
        let mut b = FileBrowser::new();
        assert!(!b.select(0), "no-op on an empty listing");
        let names = [name("a.txt"), name("b.txt"), name("c.txt")];
        b.set_entries(&names);
        assert_eq!(b.count(), 3);
        assert_eq!(b.selected_name().unwrap().as_slice(), b"a.txt");
        b.select(2);
        assert_eq!(b.selected_name().unwrap().as_slice(), b"c.txt");
        // Shrinking the listing clamps the selection back into range.
        b.set_entries(&names[..1]);
        assert_eq!(b.count(), 1);
        assert_eq!(b.selected(), 0);
    }

    #[test]
    fn move_up_down_bounded_at_the_edges() {
        let mut b = FileBrowser::new();
        let names = [name("a.txt"), name("b.txt"), name("c.txt")];
        b.set_entries(&names);
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
        let names = [name("a.txt"), name("b.txt")];
        b.set_entries(&names);
        assert!(!b.select(5));
        assert_eq!(b.selected(), 0);
        assert!(b.select(1));
        assert_eq!(b.selected(), 1);
    }

    #[test]
    fn oversized_listing_is_dropped_not_panicked() {
        let mut b = FileBrowser::new();
        let names = [name("a.txt"); MAX_ENTRIES + 3];
        b.set_entries(&names);
        assert_eq!(b.count(), MAX_ENTRIES);
    }

    #[test]
    fn next_free_name_skips_taken_names() {
        let mut b = FileBrowser::new();
        let names = [name("file1.txt"), name("file2.txt")];
        b.set_entries(&names);
        let (buf, len) = b.next_free_name();
        assert_eq!(&buf[..len], b"file3.txt");
    }

    #[test]
    fn next_free_name_on_empty_listing_is_file1() {
        let b = FileBrowser::new();
        let (buf, len) = b.next_free_name();
        assert_eq!(&buf[..len], b"file1.txt");
    }
}

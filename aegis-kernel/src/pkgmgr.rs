//! Phase AA: the kernel's sixth real application window — the package-manager
//! model. The desktop keeps a [`PkgList`] of up to [`MAX_PACKAGES`] installed
//! packages, each a `pkg-...` object file in the NVMe store (an honest Phase-7
//! mechanism: "packages" are store objects named `pkg-<name>.txt`), and renders
//! them as a scrollable, selectable list inside the `pkgmgr` window. The
//! desktop exposes `install_selected`/`remove_selected` to the window mouse
//! handler, which clone and attach to a new store root exactly like the
//! editor's COW `write_named`, so a package install/remove is a real object-store
//! mutation with a serial-log outcome.
//!
//! The model is pure data + index arithmetic: the desktop decides what the
//! store actually contains and calls [`PkgList::set_entries`] to reconcile the
//! model to it, and `main.rs` prints the `pkgmgr@install`/`pkgmgr@remove`
//! evidence lines from the outcomes.

/// Maximum number of packages the model tracks (bounds the fixed-size arrays).
pub const MAX_PACKAGES: usize = 8;

/// Width of a package name cell in the list, `[u8; 16]` — store `Name` fields
/// are 32 bytes but 16 fits the 44-column window with the `*` selection
/// marker.
pub const NAME_WIDTH: usize = 16;

/// The package list model: NUL-padded name cells, a cursor, and the windows
/// of the list that the desktop may render. `set_entries` reconciles it to a
/// live store listing (clamped to [`MAX_PACKAGES`]); the cursor never leaves
/// bounds (an empty list selects nothing, wrapping is modulo the count).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PkgList {
    /// NUL-padded, NUL-truncated package names (bytes past the first NUL are
    /// zero). The desktop renders a window of these rows.
    pub names: [[u8; NAME_WIDTH]; MAX_PACKAGES],
    /// The number of live entries (`0..=MAX_PACKAGES`).
    pub count: usize,
    /// The selected row index, `< count` when non-empty.
    pub selected: usize,
    /// The list model re-validates itself on every mutation, so a foreign
    /// `selected` (e.g. set directly in a test) never survives a
    /// `set_entries`/`select_*` call.
    pub ceilings: usize,
}

impl Default for PkgList {
    fn default() -> Self {
        Self::new()
    }
}

impl PkgList {
    /// An empty list with nothing selected.
    pub fn new() -> PkgList {
        PkgList {
            names: [[0u8; NAME_WIDTH]; MAX_PACKAGES],
            count: 0,
            selected: 0,
            ceilings: 0,
        }
    }

    /// Reconcile the model to a live listing: copy at most [`MAX_PACKAGES`]
    /// names (each truncated/NUL-padded to [`NAME_WIDTH`]) and clamp the
    /// cursor so it always points at a live row. Returns true if the listing
    /// changed the model's entries at all.
    pub fn set_entries(&mut self, names: &[&[u8]]) {
        let n = names.len().min(MAX_PACKAGES);
        self.names = [[0u8; NAME_WIDTH]; MAX_PACKAGES];
        for (i, name) in names.iter().take(n).enumerate() {
            let w = name.len().min(NAME_WIDTH);
            self.names[i][..w].copy_from_slice(&name[..w]);
        }
        self.count = n;
        self.ceilings = self.count;
        if self.selected >= self.count {
            self.selected = self.count.saturating_sub(1);
        }
    }

    /// The NUL-truncated name at `i` (or `None` out of bounds / empty slot).
    pub fn name(&self, i: usize) -> Option<&[u8]> {
        if i >= self.count {
            return None;
        }
        let n = self.names[i]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.names[i].len());
        Some(&self.names[i][..n])
    }

    /// The selected row's name (or `None` when the list is empty).
    pub fn selected_name(&self) -> Option<&[u8]> {
        self.name(self.selected)
    }

    /// True if row `i` is the selected row.
    pub fn is_selected(&self, i: usize) -> bool {
        self.count > 0 && i < self.count && i == self.selected
    }

    /// Move the cursor to `idx`, clamped to the live rows. Returns true when
    /// the cursor moved.
    pub fn select_to(&mut self, idx: usize) -> bool {
        if self.count == 0 {
            return false;
        }
        let prev = self.selected;
        self.selected = idx.min(self.count - 1);
        prev != self.selected
    }

    /// Move the cursor one row down, wrapping to the top.
    pub fn select_next(&mut self) -> bool {
        if self.count == 0 {
            return false;
        }
        let prev = self.selected;
        self.selected = (self.selected + 1) % self.count;
        prev != self.selected
    }

    /// Move the cursor one row up, wrapping to the bottom.
    pub fn select_prev(&mut self) -> bool {
        if self.count == 0 {
            return false;
        }
        let prev = self.selected;
        self.selected = (self.selected + self.count - 1) % self.count;
        prev != self.selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_selects_nothing() {
        let mut l = PkgList::new();
        assert_eq!(l.count, 0);
        assert_eq!(l.selected, 0);
        assert!(l.selected_name().is_none());
        assert!(!l.select_next());
        assert!(!l.select_prev());
        assert!(!l.select_to(0));
    }

    #[test]
    fn select_wraps() {
        let mut l = PkgList::new();
        l.set_entries(&[b"pkg-a".as_slice(), b"pkg-b", b"pkg-c"]);
        assert_eq!(l.count, 3);
        l.select_to(2);
        assert!(l.is_selected(2));
        assert!(l.select_next()); // wraps to 0
        assert!(l.is_selected(0));
        assert!(l.select_prev()); // wraps back to 2
        assert!(l.is_selected(2));
    }

    #[test]
    fn set_entries_populates_and_clamps() {
        let mut l = PkgList::new();
        let owned: Vec<Vec<u8>> = (0..MAX_PACKAGES + 2)
            .map(|i| format!("pkg-this-is-a-long-package-name-{}", i).into_bytes())
            .collect();
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        l.set_entries(&refs);
        assert_eq!(l.count, MAX_PACKAGES);
        // Names are truncated to NAME_WIDTH.
        assert_eq!(l.name(0).unwrap().len(), NAME_WIDTH);
        // A cursor left past the live rows is clamped to the last one.
        l.selected = usize::MAX;
        l.set_entries(&refs);
        assert_eq!(l.selected, MAX_PACKAGES - 1);
    }

    #[test]
    fn bounds_checked() {
        let mut l = PkgList::new();
        l.set_entries(&[b"pkg-a".as_slice(), b"pkg-b"]);
        assert!(l.name(2).is_none());
        assert!(l.name(usize::MAX).is_none());
        // select_to clamps instead of panicking.
        l.select_to(1000);
        assert_eq!(l.selected, 1);
        assert!(!l.is_selected(2));
        assert!(l.is_selected(1));
    }
}

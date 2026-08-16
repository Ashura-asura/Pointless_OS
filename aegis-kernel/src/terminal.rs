//! Phase R: the shell window's command interpreter backend — a bounded
//! output scrollback plus the parser that turns one submitted line into a
//! [`Command`]. `desktop` owns a [`Terminal`] on the shell window (id 3):
//! Enter parses the typed line (`Command::parse`), runs it against the same
//! boot-time filesystem the editor and file browser use, and pushes the
//! resulting text lines here for `render_shell` to paint above the prompt.
//!
//! Honest limit, inherited from `input.rs`: a real PS/2 keyboard can type
//! only lowercase ASCII letters, digits, and Space — there is no `Key` for
//! `.` or any other punctuation, so a file name like `memo.txt` can never be
//! typed. The shell works around this the same way the file browser's
//! click-to-open does: `ls` prints every name in the boot view as a numbered
//! row (1-based, matching [`Terminal::resolve`]), and `open <n>` / `cat <n>`
//! reference an entry by its listing number, never by its name. Names are
//! still *displayed* — [`Terminal::set_listing`] snapshots the real
//! [`Name`]s `ls` printed — they just are not *typable*. Any other byte in a
//! submitted line yields [`Command::Unknown`] (the shell reports it) rather
//! than a panic.
//!
//! The scrollback is bounded: [`MAX_LINES`] lines, each [`OUT_LINE_MAX`]
//! bytes; once the buffer is full the oldest line is dropped. `clear` empties
//! it. [`Terminal::resolve`] never panics on an out-of-range / empty index —
//! `open` without a prior `ls` is a usage error, not a crash.

use crate::store::Name;
use crate::update::VIEW_MAX_FILES;

/// Maximum bytes in one scrollback line (matches the composited screen
/// width in cells; the 60-wide shell window clips longer lines at render
/// time, never at capture time).
pub const OUT_LINE_MAX: usize = 80;

/// Maximum scrollback lines the shell keeps; older lines are dropped once
/// the buffer is full.
const MAX_LINES: usize = 64;

/// One scrollback line: bounded bytes plus their length.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Line {
    bytes: [u8; OUT_LINE_MAX],
    len: usize,
}

impl Default for Line {
    fn default() -> Line {
        Line {
            bytes: [0u8; OUT_LINE_MAX],
            len: 0,
        }
    }
}

impl Line {
    /// The line's bytes (its captured length only, never the padding).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The shell window's bounded output scrollback plus the snapshot of the
/// last `ls` listing (`open <n>` resolves against exactly what `ls` printed).
pub struct Terminal {
    lines: [Line; MAX_LINES],
    count: usize,
    listing: [Name; VIEW_MAX_FILES],
    listing_count: usize,
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Terminal {
    /// An empty scrollback with no listing snapshot.
    pub fn new() -> Terminal {
        Terminal {
            lines: [Line::default(); MAX_LINES],
            count: 0,
            listing: [Name::default(); VIEW_MAX_FILES],
            listing_count: 0,
        }
    }

    /// The buffered lines, oldest first.
    pub fn lines(&self) -> &[Line] {
        &self.lines[..self.count]
    }

    /// Append `bytes` as a new line, truncated to `OUT_LINE_MAX` bytes.
    /// Once the buffer is full the oldest line is dropped first.
    pub fn push_line(&mut self, bytes: &[u8]) {
        if self.count == MAX_LINES {
            for i in 1..MAX_LINES {
                self.lines[i - 1] = self.lines[i];
            }
            self.count -= 1;
        }
        let n = bytes.len().min(OUT_LINE_MAX);
        let mut line = Line {
            len: n,
            ..Line::default()
        };
        line.bytes[..n].copy_from_slice(&bytes[..n]);
        self.lines[self.count] = line;
        self.count += 1;
    }

    /// Drop every buffered line.
    pub fn clear(&mut self) {
        self.count = 0;
    }

    /// Snapshot the last `ls` listing (`names[..names.len().min(VIEW_MAX_FILES)]`)
    /// so a later `open <n>` resolves against what `ls` actually printed.
    /// Never panics on an oversized slice — the tail is dropped.
    pub fn set_listing(&mut self, names: &[Name]) {
        let n = names.len().min(VIEW_MAX_FILES);
        self.listing[..n].copy_from_slice(&names[..n]);
        for e in self.listing[n..].iter_mut() {
            *e = Name::default();
        }
        self.listing_count = n;
    }

    /// The `ls` listing entry at 1-based index `idx` (the number `ls`
    /// printed on the row), or `None` for 0 / out of range / an empty entry.
    pub fn resolve(&self, idx: usize) -> Option<Name> {
        if idx == 0 || idx > self.listing_count {
            return None;
        }
        let name = self.listing[idx - 1];
        if name.as_slice().is_empty() {
            return None;
        }
        Some(name)
    }
}

/// A parsed shell command line (Phase R).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Command {
    /// An empty (or whitespace-only) line: no output.
    Empty,
    /// `help` — print the command list.
    Help,
    /// `clear` — empty the scrollback.
    Clear,
    /// `ls` — list every name in the boot view, numbered.
    Ls,
    /// `new` — create the next unused `fileN.txt`.
    New,
    /// `open <n>` / `cat <n>` — print listing entry n; `None` when the
    /// argument is missing.
    Open(Option<usize>),
    /// Anything else: an unknown command.
    Unknown,
}

impl Command {
    /// Parse one submitted shell line. Accepts only lowercase ASCII letters,
    /// digits, and Space (what a real PS/2 keyboard can type here); anything
    /// else in a token makes the line `Unknown` rather than panicking.
    pub fn parse(line: &[u8]) -> Command {
        let mut start = 0;
        while start < line.len() && line[start] == b' ' {
            start += 1;
        }
        let mut end = start;
        while end < line.len() && line[end] != b' ' {
            end += 1;
        }
        let cmd = &line[start..end];
        let mut arg = end;
        while arg < line.len() && line[arg] == b' ' {
            arg += 1;
        }
        let arg = &line[arg..];
        match cmd {
            b"" => Command::Empty,
            b"help" => Command::Help,
            b"clear" => Command::Clear,
            b"ls" => Command::Ls,
            b"new" => Command::New,
            b"open" | b"cat" => {
                if arg.is_empty() {
                    Command::Open(None)
                } else if arg.iter().all(|&b| b.is_ascii_digit()) {
                    let mut n = 0usize;
                    for &b in arg {
                        n = n.saturating_mul(10).saturating_add((b - b'0') as usize);
                    }
                    Command::Open(Some(n))
                } else {
                    Command::Unknown
                }
            }
            _ => Command::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &[u8]) -> Name {
        Name::from_slice(s).unwrap()
    }

    #[test]
    fn parse_recognizes_each_builtin_command() {
        assert_eq!(Command::parse(b"help"), Command::Help);
        assert_eq!(Command::parse(b"ls"), Command::Ls);
        assert_eq!(Command::parse(b"new"), Command::New);
        assert_eq!(Command::parse(b"clear"), Command::Clear);
        assert_eq!(Command::parse(b"  ls"), Command::Ls);
        assert_eq!(Command::parse(b""), Command::Empty);
        assert_eq!(Command::parse(b" "), Command::Empty);
    }

    #[test]
    fn parse_open_takes_an_optional_numeric_argument() {
        assert_eq!(Command::parse(b"open"), Command::Open(None));
        assert_eq!(Command::parse(b"open 3"), Command::Open(Some(3)));
        assert_eq!(Command::parse(b"cat 2"), Command::Open(Some(2)));
        assert_eq!(Command::parse(b"open 0"), Command::Open(Some(0)));
        assert_eq!(Command::parse(b"open 10"), Command::Open(Some(10)));
    }

    #[test]
    fn parse_open_requires_a_pure_number() {
        assert_eq!(Command::parse(b"open 3x"), Command::Unknown);
        assert_eq!(Command::parse(b"open 3 4"), Command::Unknown);
        assert_eq!(Command::parse(b"cat 1a"), Command::Unknown);
    }

    #[test]
    fn parse_rejects_unknown_and_untypable_lines() {
        assert_eq!(Command::parse(b"frobnicate"), Command::Unknown);
        assert_eq!(Command::parse(b"Help"), Command::Unknown);
        assert_eq!(Command::parse(b"ls.txt"), Command::Unknown);
    }

    #[test]
    fn push_line_then_lines_returns_oldest_first() {
        let mut t = Terminal::new();
        t.push_line(b"one");
        t.push_line(b"two");
        assert_eq!(t.lines().len(), 2);
        assert_eq!(t.lines()[0].as_bytes(), b"one");
        assert_eq!(t.lines()[1].as_bytes(), b"two");
    }

    #[test]
    fn push_line_truncates_to_out_line_max() {
        let mut t = Terminal::new();
        let long = [b'x'; OUT_LINE_MAX + 10];
        t.push_line(&long);
        assert_eq!(t.lines().len(), 1);
        assert_eq!(t.lines()[0].as_bytes().len(), OUT_LINE_MAX);
    }

    #[test]
    fn full_scrollback_drops_the_oldest_line() {
        let mut t = Terminal::new();
        for i in 0..=MAX_LINES {
            t.push_line(&[i as u8]);
        }
        assert_eq!(t.lines().len(), MAX_LINES);
        assert_eq!(t.lines()[0].as_bytes(), &[1]);
        assert_eq!(t.lines()[MAX_LINES - 1].as_bytes(), &[MAX_LINES as u8]);
    }

    #[test]
    fn clear_empties_the_scrollback() {
        let mut t = Terminal::new();
        t.push_line(b"x");
        assert_eq!(t.lines().len(), 1);
        t.clear();
        assert!(t.lines().is_empty());
    }

    #[test]
    fn set_listing_and_resolve_are_one_based() {
        let mut t = Terminal::new();
        let a = name(b"aaa");
        let b = name(b"bbb");
        t.set_listing(&[a, b]);
        assert_eq!(t.resolve(1), Some(a));
        assert_eq!(t.resolve(2), Some(b));
        assert_eq!(t.resolve(0), None);
        assert_eq!(t.resolve(3), None);
    }

    #[test]
    fn resolve_reflects_the_most_recent_listing() {
        let mut t = Terminal::new();
        t.set_listing(&[name(b"old")]);
        t.set_listing(&[name(b"new1"), name(b"new2")]);
        assert_eq!(t.resolve(1), Some(name(b"new1")));
        assert_eq!(t.resolve(2), Some(name(b"new2")));
    }

    #[test]
    fn set_listing_clamps_oversized_input() {
        let mut t = Terminal::new();
        let mut names = [Name::default(); VIEW_MAX_FILES + 3];
        for (i, n) in names.iter_mut().enumerate() {
            *n = name(&[b'a' + (i % 26) as u8]);
        }
        t.set_listing(&names);
        assert_eq!(t.resolve(VIEW_MAX_FILES), Some(names[VIEW_MAX_FILES - 1]));
        assert_eq!(t.resolve(VIEW_MAX_FILES + 1), None);
    }
}

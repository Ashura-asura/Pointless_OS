// Extracted verbatim from aegis-kernel/src/store.rs (decode_entries + the
// Name/FileEntry types it depends on) for standalone fuzzing — see
// PHASE_M_STATUS.md for why (MSRV blocker on the real crate).

pub const NAME_BYTES: usize = 32;
pub const MAX_FILES: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Name {
    bytes: [u8; NAME_BYTES],
    len: usize,
}

impl Name {
    pub fn from_slice(s: &[u8]) -> Option<Name> {
        if s.is_empty() || s.len() > NAME_BYTES {
            return None;
        }
        let mut bytes = [0u8; NAME_BYTES];
        bytes[..s.len()].copy_from_slice(s);
        Some(Name {
            bytes,
            len: s.len(),
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Default for Name {
    fn default() -> Name {
        Name {
            bytes: [0; NAME_BYTES],
            len: 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileEntry {
    pub name: Name,
    pub node: u64,
}

impl Default for FileEntry {
    fn default() -> FileEntry {
        FileEntry {
            name: Name::default(),
            node: 0,
        }
    }
}

/// Decode at most `MAX_FILES` entries; returns how many were decoded.
pub fn decode_entries(bytes: &[u8], out: &mut [FileEntry; MAX_FILES]) -> usize {
    let mut written = 0usize;
    if bytes.len() < 4 {
        return 0;
    }
    let mut at = 0usize;
    let count = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
    at += 4;
    for _ in 0..count.min(MAX_FILES) {
        if at + 4 > bytes.len() {
            break;
        }
        let nlen = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        if at + nlen > bytes.len() {
            break;
        }
        let Some(name) = Name::from_slice(&bytes[at..at + nlen]) else {
            break;
        };
        at += nlen;
        if at + 8 > bytes.len() {
            break;
        }
        let node = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        at += 8;
        out[written] = FileEntry { name, node };
        written += 1;
    }
    written
}

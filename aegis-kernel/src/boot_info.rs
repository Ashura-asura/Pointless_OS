//! Boot-info handoff received from the UEFI bootloader.
//!
//! After `ExitBootServices` the loader writes its final memory map to a
//! fixed physical address (see `BOOT_INFO_ADDR`) and jumps to the kernel.
//! The kernel must read it early — it is the only record of what physical
//! memory exists once firmware services are gone.
//!
//! Layout contract (both sides must match exactly):
//!   offset 0:  magic u64 = 0x4145_4753_4841_4E44 ("AEGSHAND")
//!   offset 8:  entry_count u32
//!   offset 12: pad u32
//!   offset 16: entries, each 20 bytes (ty u32, base u64, pages u64)
//!
//! Only the first `entry_count` entries are valid; the loader zero-fills
//! the page so stale entries read as ty=0 (reserved).

use core::mem::size_of;

/// Fixed physical address agreed with uefi-boot. Chosen because the kernel
/// image + BSS + stack occupy 0x0..0xF000, so 0x10000 is the first free
/// page below the 1 MB mark.
pub const BOOT_INFO_ADDR: u64 = 0x10000;

const MAGIC: u64 = 0x4145_4753_4841_4E44;
const MAX_ENTRIES: usize = 256;

pub const TYPE_CONVENTIONAL: u32 = 7;

/// One UEFI memory-map descriptor, flattened to the fields the kernel needs.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MapEntry {
    pub ty: u32,
    pub base: u64,
    pub pages: u64,
}

impl MapEntry {
    pub const fn size() -> usize {
        size_of::<MapEntry>()
    }

    pub const fn bytes(&self) -> u64 {
        self.pages * 4096
    }
}

/// Validated view over the raw handoff page bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct BootInfo<'a> {
    /// Valid entries, slice into the raw page.
    pub entries: &'a [MapEntry],
}

/// Parse and validate a raw handoff page. Pure and total: any garbage
/// input yields `None`, never a panic.
pub fn parse(raw: &[u8]) -> Option<BootInfo<'_>> {
    let magic = read_u64(raw, 0)?;
    if magic != MAGIC {
        return None;
    }
    let count_raw = read_u32(raw, 8)?;
    if count_raw as usize > MAX_ENTRIES {
        return None;
    }
    let count = count_raw as usize;
    let needed = 16 + MapEntry::size() * count;
    if raw.len() < needed {
        return None;
    }
    // MapEntry is repr(packed) (align 1), so the unaligned offset is fine.
    let entries_ptr = unsafe { raw.as_ptr().add(16).cast::<MapEntry>() };
    let entries = unsafe { core::slice::from_raw_parts(entries_ptr, count) };
    Some(BootInfo { entries })
}

/// Total bytes in entries of the given type.
pub fn total_by_type<'a>(info: &BootInfo<'a>, ty: u32) -> u64 {
    info.entries
        .iter()
        .filter(|e| e.ty == ty)
        .map(MapEntry::bytes)
        .sum()
}

/// Read the handoff page from its fixed physical address.
///
/// # Safety
/// Must be called before anything that could repurpose the page, and only
/// after the bootloader has actually written the handoff (or with a
/// validated magic).
pub unsafe fn locate() -> Option<BootInfo<'static>> {
    let raw = core::slice::from_raw_parts(
        BOOT_INFO_ADDR as *const u8,
        16 + MapEntry::size() * MAX_ENTRIES,
    );
    parse(raw)
}

fn read_u32(raw: &[u8], off: usize) -> Option<u32> {
    if raw.len() < off + 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        raw[off],
        raw[off + 1],
        raw[off + 2],
        raw[off + 3],
    ]))
}

fn read_u64(raw: &[u8], off: usize) -> Option<u64> {
    if raw.len() < off + 8 {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&raw[off..off + 8]);
    Some(u64::from_le_bytes(b))
}

/// Build a handoff page image (used by tests; the bootloader writes its own
/// matching struct at runtime).
pub fn build_image(entries: &[MapEntry]) -> [u8; 16 + MapEntry::size() * MAX_ENTRIES] {
    let mut img = [0u8; 16 + MapEntry::size() * MAX_ENTRIES];
    img[0..8].copy_from_slice(&MAGIC.to_le_bytes());
    img[8..12].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (i, e) in entries.iter().enumerate() {
        let base = 16 + i * MapEntry::size();
        let mut src = [0u8; 20];
        src[0..4].copy_from_slice(&e.ty.to_le_bytes());
        src[4..12].copy_from_slice(&e.base.to_le_bytes());
        src[12..20].copy_from_slice(&e.pages.to_le_bytes());
        img[base..base + 20].copy_from_slice(&src);
    }
    img
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<MapEntry> {
        vec![
            MapEntry {
                ty: TYPE_CONVENTIONAL,
                base: 0x100000,
                pages: 0x1000,
            },
            MapEntry {
                ty: 1,
                base: 0x10000,
                pages: 1,
            },
            MapEntry {
                ty: 3,
                base: 0x200000,
                pages: 0x40,
            },
        ]
    }

    #[test]
    fn parses_valid_image() {
        let entries = sample_entries();
        let img = build_image(&entries);
        let info = parse(&img).expect("valid image must parse");
        assert_eq!(info.entries.len(), 3);
        assert_eq!(info.entries[0], entries[0]);
        assert_eq!(info.entries[1], entries[1]);
        assert_eq!(info.entries[2], entries[2]);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut img = build_image(&sample_entries());
        img[0] ^= 0xFF;
        assert_eq!(parse(&img), None);
    }

    #[test]
    fn rejects_absurd_entry_count() {
        let mut img = build_image(&sample_entries());
        img[8..12].copy_from_slice(&(u32::MAX).to_le_bytes());
        assert_eq!(parse(&img), None);
    }

    #[test]
    fn rejects_short_buffer() {
        let entries = sample_entries();
        let img = build_image(&entries);
        let (need, cut) = (16 + 20 * entries.len(), 16 + 20 * 2 + 1);
        assert!(cut < need);
        assert_eq!(parse(&img[..cut]), None);
    }

    #[test]
    fn rejects_empty_garbage() {
        assert_eq!(parse(&[0u8; 64]), None);
    }

    #[test]
    fn counts_conventional_bytes() {
        let entries = sample_entries();
        let img = build_image(&entries);
        let info = parse(&img).unwrap();
        assert_eq!(total_by_type(&info, TYPE_CONVENTIONAL), 0x1000 * 4096);
        assert_eq!(total_by_type(&info, 99), 0);
    }

    #[test]
    fn entry_layout_is_exactly_20_bytes() {
        assert_eq!(MapEntry::size(), 20);
    }

    #[test]
    fn max_entries_boundary_ok() {
        let entries: Vec<MapEntry> = (0..MAX_ENTRIES)
            .map(|i| MapEntry {
                ty: 7,
                base: i as u64 * 4096,
                pages: 1,
            })
            .collect();
        let img = build_image(&entries);
        let info = parse(&img).expect("max-size image must parse");
        assert_eq!(info.entries.len(), MAX_ENTRIES);
    }
}

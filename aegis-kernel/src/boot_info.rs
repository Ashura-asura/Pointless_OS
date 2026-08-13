//! Boot-info handoff received from the UEFI bootloader.
//!
//! After `ExitBootServices` the loader writes its final memory map to a
//! physical page and jumps to the kernel, passing that page's address to
//! `_start` in `%rdi` (the first sysv64 argument). The kernel must read it
//! early — it is the only record of what physical memory exists once
//! firmware services are gone.
//!
//! The handoff page's location is deliberately *dynamic*: the loader places
//! it on the first page strictly above the kernel image (`image_end`), so it
//! can never collide with the image — no matter where the linker lays out
//! `.text`/`.rodata`/`.data`/`.got`. A fixed low address like 0x10000 grows
//! into the image as the kernel does, and the loader's handoff write then
//! silently corrupts live data (e.g. the `.got`), producing a boot-time
//! #PF at a garbage address. Passing the address in `%rdi` removes the
//! fixed-address contract entirely.
//!
//! Layout contract (both sides must match exactly):
//!   offset 0:  magic u64 = 0x4145_4753_4841_4E44 ("AEGSHAND")
//!   offset 8:  entry_count u32
//!   offset 12: pad u32
//!   offset 16: image_end u64 — first page above the loaded kernel image
//!              (loader rounds max(segment vaddr+memsz) up to 4 KiB)
//!   offset 24: entries, each 20 bytes (ty u32, base u64, pages u64)
//!
//! Only the first `entry_count` entries are valid; the loader zero-fills
//! the page so stale entries read as ty=0 (reserved).

use core::mem::size_of;

/// Pages a full 256-entry handoff can span, starting at the handoff address
/// (`image_end`): 24 + 256 * 20 = 5144 bytes, so 2 pages suffice. The frame
/// allocator reserves this many pages so it never hands the handoff out.
pub const HANDOFF_PAGES: u64 = 2;

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
    /// First byte above the loaded kernel image (4 KiB aligned).
    pub image_end: u64,
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
    let image_end = read_u64(raw, 16)?;
    if image_end == 0 || image_end > 0x1_0000_0000 {
        return None;
    }
    let needed = 24 + MapEntry::size() * count;
    if raw.len() < needed {
        return None;
    }
    // MapEntry is repr(packed) (align 1), so the unaligned offset is fine.
    let entries_ptr = unsafe { raw.as_ptr().add(24).cast::<MapEntry>() };
    let entries = unsafe { core::slice::from_raw_parts(entries_ptr, count) };
    Some(BootInfo { entries, image_end })
}

/// Total bytes in entries of the given type.
pub fn total_by_type<'a>(info: &BootInfo<'a>, ty: u32) -> u64 {
    info.entries
        .iter()
        .filter(|e| e.ty == ty)
        .map(MapEntry::bytes)
        .sum()
}

/// Read the handoff page from the physical address the loader passed in
/// `%rdi`.
///
/// # Safety
/// Must be called before anything that could repurpose the page, and only
/// after the bootloader has actually written the handoff (or with a
/// validated magic).
pub unsafe fn locate_at(addr: u64) -> Option<BootInfo<'static>> {
    let raw = core::slice::from_raw_parts(addr as *const u8, 24 + MapEntry::size() * MAX_ENTRIES);
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
pub fn build_image(
    entries: &[MapEntry],
    image_end: u64,
) -> [u8; 24 + MapEntry::size() * MAX_ENTRIES] {
    let mut img = [0u8; 24 + MapEntry::size() * MAX_ENTRIES];
    img[0..8].copy_from_slice(&MAGIC.to_le_bytes());
    img[8..12].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    img[16..24].copy_from_slice(&image_end.to_le_bytes());
    for (i, e) in entries.iter().enumerate() {
        let base = 24 + i * MapEntry::size();
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
        let img = build_image(&entries, 0x1_1000);
        let info = parse(&img).expect("valid image must parse");
        assert_eq!(info.entries.len(), 3);
        assert_eq!(info.entries[0], entries[0]);
        assert_eq!(info.entries[1], entries[1]);
        assert_eq!(info.entries[2], entries[2]);
        assert_eq!(info.image_end, 0x1_1000);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut img = build_image(&sample_entries(), 0x1_1000);
        img[0] ^= 0xFF;
        assert_eq!(parse(&img), None);
    }

    #[test]
    fn rejects_absurd_entry_count() {
        let mut img = build_image(&sample_entries(), 0x1_1000);
        img[8..12].copy_from_slice(&(u32::MAX).to_le_bytes());
        assert_eq!(parse(&img), None);
    }

    #[test]
    fn rejects_zero_or_absurd_image_end() {
        let entries = sample_entries();
        let ok = build_image(&entries, 0x1_1000);
        assert!(parse(&ok).is_some());
        let mut zero = build_image(&entries, 0x1_1000);
        zero[16..24].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(parse(&zero), None);
        let mut huge = build_image(&entries, 0x1_1000);
        huge[16..24].copy_from_slice(&0x2_0000_0000u64.to_le_bytes());
        assert_eq!(parse(&huge), None);
    }

    #[test]
    fn rejects_short_buffer() {
        let entries = sample_entries();
        let img = build_image(&entries, 0x1_1000);
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
        let img = build_image(&entries, 0x1_1000);
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
        let img = build_image(&entries, 0x1_1000);
        let info = parse(&img).expect("max-size image must parse");
        assert_eq!(info.entries.len(), MAX_ENTRIES);
    }

    #[test]
    fn locate_at_reads_handoff_from_any_address() {
        let entries = sample_entries();
        let img = build_image(&entries, 0x5_2000);
        let (total, handoff_pages) = (img.len(), HANDOFF_PAGES);
        assert!(total as u64 <= handoff_pages * 4096);
        let info = unsafe { locate_at(&img as *const _ as u64) }.expect("handoff must locate");
        assert_eq!(info.entries.len(), 3);
        assert_eq!(info.image_end, 0x5_2000);
        assert_eq!(total_by_type(&info, TYPE_CONVENTIONAL), 0x1000 * 4096);
    }
}

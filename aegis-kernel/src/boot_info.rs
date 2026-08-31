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
//!   offset 5144 (= 24 + 256*20): optional `FleetConfig` block. If
//!              `present == 1` the block is valid and the kernel's fleet
//!              demo is driven by it (role, NodeIds, IPs, stale window,
//!              shared key) instead of the compile-time feature defaults.
//!   offset 5199 (= 5144 + 55): optional `GopHandoff` block. If
//!              `present == 1` the block is valid and the kernel's display
//!              driver uses the UEFI Graphics Output Protocol framebuffer
//!              the loader queried before `ExitBootServices` (real
//!              hardware has no Bochs VBE dispi interface), instead of
//!              falling back to the Bochs-VBE PCI probe.
//!
//! Only the first `entry_count` entries are valid; the loader zero-fills
//! the page so stale entries read as ty=0 (reserved). The FleetConfig block
//! sits after the entries; `present == 0` means "no FLEET.CFG was found".

use core::mem::size_of;

/// Pages a full 256-entry handoff can span, starting at the handoff address
/// (`image_end`): 24 + 256 * 20 = 5144 bytes, so 2 pages suffice. The frame
/// allocator reserves this many pages so it never hands the handoff out.
pub const HANDOFF_PAGES: u64 = 2;

const MAGIC: u64 = 0x4145_4753_4841_4E44;
const MAX_ENTRIES: usize = 256;

pub const TYPE_CONVENTIONAL: u32 = 7;

/// UEFI `EfiACPIReclaimMemory` — where firmware installs the ACPI tables
/// (RSDP/RSDT/XSDT/FADT/MADT). OVMF keeps them at high physical addresses,
/// far above the legacy EBDA/F-seg locations.
pub const TYPE_ACPI_RECLAIM: u32 = 9;

/// UEFI `EfiACPIMemoryNVS` — firmware ACPI runtime NVS; may also hold parts
/// of the ACPI table set.
pub const TYPE_ACPI_NVS: u32 = 10;

/// Byte offset of the optional `FleetConfig` block in the handoff page.
pub const FLEET_OFFSET: usize = 24 + MapEntry::size() * MAX_ENTRIES;

/// Byte offset of the optional `GopHandoff` block in the handoff page:
/// directly after the 55-byte fleet block.
pub const GOP_OFFSET: usize = FLEET_OFFSET + FleetConfig::size();

/// Runtime fleet configuration parsed from `\FLEET.CFG` on the boot volume.
/// The loader writes this block at `FLEET_OFFSET`; `present == 0` means no
/// FLEET.CFG was found and the kernel falls back to compile-time defaults.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FleetConfig {
    /// 1 = block valid, 0 = absent.
    pub present: u32,
    /// 0 = issuer (mints/delegates/executes), 1 = invoker (verifies/invokes).
    pub role: u8,
    /// First byte of this node's 32-byte `NodeId` (replicated).
    pub my_id_byte: u8,
    /// First byte of the peer's 32-byte `NodeId` (replicated).
    pub peer_id_byte: u8,
    pub my_ip: [u8; 4],
    pub peer_ip: [u8; 4],
    /// Stale window in scaled ticks; 0 = use default.
    pub stale_after: u64,
    /// Shared key; all zero = use the demo default key.
    pub shared_key: [u8; 32],
}

impl FleetConfig {
    pub const fn size() -> usize {
        size_of::<FleetConfig>()
    }

    pub const fn role_is_issuer(&self) -> bool {
        self.role == 0
    }
}

/// Parse the optional `FleetConfig` block from a raw handoff page. Pure and
/// total: returns `None` if absent, truncated, or invalid.
pub fn parse_fleet(raw: &[u8]) -> Option<FleetConfig> {
    let off = FLEET_OFFSET;
    if raw.len() < off + FleetConfig::size() {
        return None;
    }
    let present = read_u32(raw, off)?;
    if present != 1 {
        return None;
    }
    let role = raw[off + 4];
    if role > 1 {
        return None;
    }
    let my_id_byte = raw[off + 5];
    let peer_id_byte = raw[off + 6];
    if my_id_byte == 0 || peer_id_byte == 0 {
        return None;
    }
    let my_ip = [raw[off + 7], raw[off + 8], raw[off + 9], raw[off + 10]];
    let peer_ip = [raw[off + 11], raw[off + 12], raw[off + 13], raw[off + 14]];
    let stale_after = read_u64(raw, off + 15)?;
    let mut shared_key = [0u8; 32];
    shared_key.copy_from_slice(&raw[off + 23..off + 55]);
    Some(FleetConfig {
        present,
        role,
        my_id_byte,
        peer_id_byte,
        my_ip,
        peer_ip,
        stale_after,
        shared_key,
    })
}

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
    let raw = core::slice::from_raw_parts(addr as *const u8, (HANDOFF_PAGES * 4096) as usize);
    parse(raw)
}

/// Read the optional `FleetConfig` block from a live handoff page.
///
/// # Safety
/// Must be called after the bootloader has written the handoff, before
/// anything repurposes the page.
pub unsafe fn fleet_at(addr: u64) -> Option<FleetConfig> {
    let raw = core::slice::from_raw_parts(addr as *const u8, (HANDOFF_PAGES * 4096) as usize);
    parse_fleet(raw)
}

/// Stashed runtime fleet config, extracted from the handoff at boot and read
/// later by the fleet demo. The kernel is single-threaded at boot (the same
/// global-mut discipline as the rest of the kernel), so a `static mut` with
/// unsafe access is safe here.
static mut FLEET_CONFIG: Option<FleetConfig> = None;

/// Stashed kernel handoff address, set at boot so any module can paint
/// diagnostics via `gop_at` without threading the address through call
/// chains (same single-threaded global-mut discipline as FLEET_CONFIG).
static mut BOOT_HANDOFF: u64 = 0;

/// # Safety
/// Single-threaded boot path only.
pub unsafe fn set_boot_handoff(addr: u64) {
    BOOT_HANDOFF = addr;
}

/// # Safety
/// Single-threaded boot path only.
pub unsafe fn boot_handoff() -> u64 {
    BOOT_HANDOFF
}

/// Record the fleet config (or `None`) for the boot demo to read later.
///
/// # Safety
/// Single-threaded boot path only; must not run concurrently with reads.
pub unsafe fn set_fleet_config(cfg: Option<FleetConfig>) {
    FLEET_CONFIG = cfg;
}

/// The currently-stashed fleet config, if any.
pub fn fleet_config() -> Option<FleetConfig> {
    unsafe { FLEET_CONFIG }
}

/// UEFI Graphics Output Protocol handoff: the framebuffer + mode the
/// loader queried from GOP before `ExitBootServices`, for the kernel's
/// display driver to consume on machines where the Bochs VBE dispi
/// interface does not exist (all real hardware).
///
/// Mirrored byte-for-byte by `uefi-boot/src/gop.rs` — the loader writes
/// this block at `GOP_OFFSET`; `present == 0` means the loader found no
/// usable GOP (or a Blt-only/bitmask framebuffer) and the kernel falls
/// back to the Bochs-VBE PCI probe.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GopHandoff {
    /// 1 = block valid, 0 = absent/unusable.
    pub present: u32,
    /// GOP `PixelFormat` flattened: 0 = Rgb (RGBX8888), 1 = Bgr (BGRX8888).
    /// Anything else (Bitmask, BltOnly) means the framebuffer is not
    /// directly CPU-writable — the loader refuses to report it.
    pub pixel_format: u32,
    pub width: u32,
    pub height: u32,
    /// Pixels per scan line (GOP `stride` — often wider than `width`).
    pub stride_px: u32,
    /// Bits per pixel of the framebuffer (32 for both Rgb/Bgr formats).
    pub bpp: u32,
    pub framebuffer_base: u64,
    pub framebuffer_size: u64,
}

impl GopHandoff {
    pub const fn size() -> usize {
        size_of::<GopHandoff>()
    }
}

/// Parse the optional `GopHandoff` block from a raw handoff page. Pure and
/// total: returns `None` if absent, truncated, or any field is unusable.
pub fn parse_gop(raw: &[u8]) -> Option<GopHandoff> {
    let off = GOP_OFFSET;
    if raw.len() < off + GopHandoff::size() {
        return None;
    }
    let present = read_u32(raw, off)?;
    if present != 1 {
        return None;
    }
    let pixel_format = read_u32(raw, off + 4)?;
    if pixel_format > 1 {
        // Bitmask/BltOnly framebuffers are not directly CPU-writable.
        return None;
    }
    let width = read_u32(raw, off + 8)?;
    let height = read_u32(raw, off + 12)?;
    let stride_px = read_u32(raw, off + 16)?;
    let bpp = read_u32(raw, off + 20)?;
    if width == 0 || height == 0 || stride_px == 0 || stride_px < width || bpp != 32 {
        return None;
    }
    let framebuffer_base = read_u64(raw, off + 24)?;
    let framebuffer_size = read_u64(raw, off + 32)?;
    // The loader's identity map covers the first 4 GiB only; a framebuffer
    // above that is not mapped and would fault on first pixel write. The
    // kernel rejects it here rather than guessing (documented honest limit:
    // covering >4 GiB framebuffers needs an extended identity map).
    if framebuffer_base == 0 || framebuffer_base >= 0x1_0000_0000 {
        return None;
    }
    let stride_bytes = (stride_px as u64).checked_mul((bpp / 8) as u64)?;
    let needed = stride_bytes.checked_mul(height as u64)?;
    if needed > framebuffer_size {
        return None;
    }
    Some(GopHandoff {
        present,
        pixel_format,
        width,
        height,
        stride_px,
        bpp,
        framebuffer_base,
        framebuffer_size,
    })
}

/// Read the optional `GopHandoff` block from a live handoff page.
///
/// # Safety
/// Must be called after the bootloader has written the handoff, before
/// anything repurposes the page.
pub unsafe fn gop_at(addr: u64) -> Option<GopHandoff> {
    let raw = core::slice::from_raw_parts(addr as *const u8, (HANDOFF_PAGES * 4096) as usize);
    parse_gop(raw)
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

/// Build a handoff page image that additionally carries a `FleetConfig`
/// block (used by tests; the bootloader writes its own at runtime).
pub fn build_image_with_fleet(
    entries: &[MapEntry],
    image_end: u64,
    fleet: &FleetConfig,
) -> [u8; (HANDOFF_PAGES * 4096) as usize] {
    let img = build_image(entries, image_end);
    let mut out = [0u8; (HANDOFF_PAGES * 4096) as usize];
    out[..img.len()].copy_from_slice(&img);
    out[FLEET_OFFSET..FLEET_OFFSET + FleetConfig::size()].copy_from_slice(&fleet_to_bytes(fleet));
    out
}

fn fleet_to_bytes(f: &FleetConfig) -> [u8; FleetConfig::size()] {
    let mut b = [0u8; FleetConfig::size()];
    b[0..4].copy_from_slice(&f.present.to_le_bytes());
    b[4] = f.role;
    b[5] = f.my_id_byte;
    b[6] = f.peer_id_byte;
    b[7..11].copy_from_slice(&f.my_ip);
    b[11..15].copy_from_slice(&f.peer_ip);
    b[15..23].copy_from_slice(&f.stale_after.to_le_bytes());
    b[23..].copy_from_slice(&f.shared_key);
    b
}

fn gop_to_bytes(g: &GopHandoff) -> [u8; GopHandoff::size()] {
    let mut b = [0u8; GopHandoff::size()];
    b[0..4].copy_from_slice(&g.present.to_le_bytes());
    b[4..8].copy_from_slice(&g.pixel_format.to_le_bytes());
    b[8..12].copy_from_slice(&g.width.to_le_bytes());
    b[12..16].copy_from_slice(&g.height.to_le_bytes());
    b[16..20].copy_from_slice(&g.stride_px.to_le_bytes());
    b[20..24].copy_from_slice(&g.bpp.to_le_bytes());
    b[24..32].copy_from_slice(&g.framebuffer_base.to_le_bytes());
    b[32..40].copy_from_slice(&g.framebuffer_size.to_le_bytes());
    b
}

/// Build a handoff page image that additionally carries a `GopHandoff`
/// block (used by tests; the bootloader writes its own at runtime).
pub fn build_image_with_gop(
    entries: &[MapEntry],
    image_end: u64,
    gop: &GopHandoff,
) -> [u8; (HANDOFF_PAGES * 4096) as usize] {
    let img = build_image(entries, image_end);
    let mut out = [0u8; (HANDOFF_PAGES * 4096) as usize];
    out[..img.len()].copy_from_slice(&img);
    out[GOP_OFFSET..GOP_OFFSET + GopHandoff::size()].copy_from_slice(&gop_to_bytes(gop));
    out
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
        let small = build_image(&entries, 0x5_2000);
        let mut img = [0u8; (HANDOFF_PAGES * 4096) as usize];
        img[..small.len()].copy_from_slice(&small);
        let (total, handoff_pages) = (small.len(), HANDOFF_PAGES);
        assert!(total as u64 <= handoff_pages * 4096);
        let info = unsafe { locate_at(img.as_ptr() as u64) }.expect("handoff must locate");
        assert_eq!(info.entries.len(), 3);
        assert_eq!(info.image_end, 0x5_2000);
        assert_eq!(total_by_type(&info, TYPE_CONVENTIONAL), 0x1000 * 4096);
    }

    fn sample_fleet() -> FleetConfig {
        FleetConfig {
            present: 1,
            role: 0,
            my_id_byte: 0xA1,
            peer_id_byte: 0xB2,
            my_ip: [10, 0, 3, 1],
            peer_ip: [10, 0, 3, 2],
            stale_after: 50000,
            shared_key: [0u8; 32],
        }
    }

    #[test]
    fn fleet_block_roundtrips() {
        let fleet = sample_fleet();
        let img = build_image_with_fleet(&sample_entries(), 0x5_2000, &fleet);
        let parsed = parse_fleet(&img).expect("fleet block must parse");
        assert_eq!(parsed, fleet);
        assert!(parsed.role_is_issuer());
    }

    #[test]
    fn fleet_block_absent_when_present_zero() {
        let entries = sample_entries();
        let img = build_image(&entries, 0x5_2000).to_vec();
        let parsed = parse_fleet(&img);
        assert_eq!(parsed, None);
    }

    #[test]
    fn fleet_block_rejects_invalid_role() {
        let mut fleet = sample_fleet();
        fleet.role = 2;
        let img = build_image_with_fleet(&sample_entries(), 0x5_2000, &fleet);
        assert_eq!(parse_fleet(&img), None);
    }

    #[test]
    fn fleet_block_rejects_zero_node_ids() {
        let mut fleet = sample_fleet();
        fleet.peer_id_byte = 0;
        let img = build_image_with_fleet(&sample_entries(), 0x5_2000, &fleet);
        assert_eq!(parse_fleet(&img), None);
    }

    #[test]
    fn fleet_block_reads_invoker_role() {
        let mut fleet = sample_fleet();
        fleet.role = 1;
        fleet.my_id_byte = 0xB2;
        fleet.peer_id_byte = 0xA1;
        fleet.my_ip = [10, 0, 3, 2];
        fleet.peer_ip = [10, 0, 3, 1];
        let img = build_image_with_fleet(&sample_entries(), 0x5_2000, &fleet);
        let parsed = parse_fleet(&img).expect("fleet block must parse");
        assert_eq!(parsed, fleet);
        assert!(!parsed.role_is_issuer());
    }

    #[test]
    fn fleet_block_fits_within_handoff_pages() {
        let total = FLEET_OFFSET + FleetConfig::size();
        assert!(total as u64 <= HANDOFF_PAGES * 4096);
    }

    #[test]
    fn fleet_at_reads_from_live_page() {
        let fleet = sample_fleet();
        let img = build_image_with_fleet(&sample_entries(), 0x5_2000, &fleet);
        let parsed = unsafe { fleet_at(img.as_ptr() as u64) }.expect("fleet must locate");
        assert_eq!(parsed, fleet);
    }

    fn sample_gop() -> GopHandoff {
        GopHandoff {
            present: 1,
            pixel_format: 1, // Bgr (BGRX8888)
            width: 800,
            height: 600,
            stride_px: 800,
            bpp: 32,
            framebuffer_base: 0xE000_0000,
            framebuffer_size: 800 * 600 * 4,
        }
    }

    #[test]
    fn gop_block_roundtrips() {
        let gop = sample_gop();
        let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
        let parsed = parse_gop(&img).expect("gop block must parse");
        assert_eq!(parsed, gop);
    }

    #[test]
    fn gop_block_absent_when_present_zero() {
        let entries = sample_entries();
        let img = build_image(&entries, 0x5_2000).to_vec();
        assert_eq!(parse_gop(&img), None);
    }

    #[test]
    fn gop_block_rejects_non_writable_pixel_formats() {
        for fmt in [2u32, 3u32, 4u32] {
            let mut gop = sample_gop();
            gop.pixel_format = fmt;
            let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
            assert_eq!(
                parse_gop(&img),
                None,
                "pixel_format={} must be rejected",
                fmt
            );
        }
    }

    #[test]
    fn gop_block_accepts_rgb_format() {
        let mut gop = sample_gop();
        gop.pixel_format = 0; // Rgb (RGBX8888)
        let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
        let parsed = parse_gop(&img).expect("rgb gop block must parse");
        // `GopHandoff` is packed; copy the field out before asserting.
        let fmt = parsed.pixel_format;
        assert_eq!(fmt, 0);
    }

    #[test]
    fn gop_block_rejects_framebuffer_above_4gb() {
        let mut gop = sample_gop();
        gop.framebuffer_base = 0x1_0000_0000;
        let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
        assert_eq!(parse_gop(&img), None);
    }

    #[test]
    fn gop_block_rejects_undersized_framebuffer() {
        let mut gop = sample_gop();
        gop.framebuffer_size = 800 * 600 * 4 - 1;
        let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
        assert_eq!(parse_gop(&img), None);
    }

    #[test]
    fn gop_block_rejects_zero_or_shrunken_stride() {
        let mut gop = sample_gop();
        gop.stride_px = 0;
        let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
        assert_eq!(parse_gop(&img), None);

        let mut gop = sample_gop();
        gop.stride_px = gop.width - 1; // stride narrower than width: impossible
        let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
        assert_eq!(parse_gop(&img), None);
    }

    #[test]
    fn gop_block_rejects_non_32bpp() {
        let mut gop = sample_gop();
        gop.bpp = 24;
        let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
        assert_eq!(parse_gop(&img), None);
    }

    #[test]
    fn gop_block_accepts_padded_stride() {
        let mut gop = sample_gop();
        gop.stride_px = 832; // common GOP stride padding
        gop.framebuffer_size = 832 * 600 * 4;
        let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
        let parsed = parse_gop(&img).expect("padded-stride gop block must parse");
        // `GopHandoff` is packed; copy the field out before asserting.
        let stride = parsed.stride_px;
        assert_eq!(stride, 832);
    }

    #[test]
    fn gop_block_fits_within_handoff_pages() {
        let total = GOP_OFFSET + GopHandoff::size();
        assert!(total as u64 <= HANDOFF_PAGES * 4096);
    }

    #[test]
    fn gop_at_reads_from_live_page() {
        let gop = sample_gop();
        let img = build_image_with_gop(&sample_entries(), 0x5_2000, &gop);
        let parsed = unsafe { gop_at(img.as_ptr() as u64) }.expect("gop must locate");
        assert_eq!(parsed, gop);
    }
}

//! Minimal read-only FAT16 reader over live NVMe block I/O.
//!
//! Mirrors the exact on-disk layout `uefi-boot/build_image.py` writes (BPB
//! field offsets, root-directory geometry, 16-bit FAT cluster chaining).
//! Read-only, no allocation, no_std. Every offset computation that touches
//! attacker/disk-controlled values uses checked arithmetic and returns
//! `None` on anything unexpected rather than trusting the layout blindly —
//! same discipline as `elf_loader.rs`/`pe_loader.rs` after the audit fixes.

use crate::nvme::NvmeController;

const BYTES_PER_SECTOR: usize = 512;

/// Parsed BIOS Parameter Block fields needed to walk the filesystem.
/// Plain data, no borrowed state, so callers can hold this across separate
/// `&mut NvmeController` calls without fighting the borrow checker.
#[derive(Clone, Copy)]
pub struct Fat16Info {
    part_start_lba: u64,
    sec_per_clus: u8,
    reserved: u16,
    num_fats: u8,
    root_entries: u16,
    fat_size: u16,
}

impl Fat16Info {
    fn root_dir_start_lba(&self) -> Option<u64> {
        let fats_lba = (self.num_fats as u64).checked_mul(self.fat_size as u64)?;
        let offset = (self.reserved as u64).checked_add(fats_lba)?;
        self.part_start_lba.checked_add(offset)
    }

    fn root_dir_sectors(&self) -> usize {
        // 32-byte entries, rounded up to a whole sector.
        ((self.root_entries as usize * 32) + BYTES_PER_SECTOR - 1) / BYTES_PER_SECTOR
    }

    fn data_area_start_lba(&self) -> Option<u64> {
        let root_lba = self.root_dir_start_lba()?;
        root_lba.checked_add(self.root_dir_sectors() as u64)
    }

    /// LBA of the first sector of `cluster` (clusters are numbered from 2).
    fn cluster_lba(&self, cluster: u16) -> Option<u64> {
        if cluster < 2 {
            return None;
        }
        let data_start = self.data_area_start_lba()?;
        let clus_index = (cluster as u64).checked_sub(2)?;
        let sectors_in = clus_index.checked_mul(self.sec_per_clus as u64)?;
        data_start.checked_add(sectors_in)
    }
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read the BPB at `part_start_lba` and validate it's a sane FAT16 volume.
/// Returns `None` on any read failure, bad boot signature, or a field
/// combination that doesn't add up (mirrors the ELF/PE loaders' policy of
/// rejecting rather than guessing on malformed input).
pub fn mount(ctrl: &mut NvmeController, part_start_lba: u64) -> Option<Fat16Info> {
    if !ctrl.read_lba(part_start_lba) {
        return None;
    }
    let bpb = ctrl.lba_data();
    if bpb.get(510..512) != Some(&[0x55, 0xAA]) {
        return None;
    }
    let bytes_per_sec = u16_at(bpb, 11)?;
    if bytes_per_sec as usize != BYTES_PER_SECTOR {
        return None; // this reader only handles 512 B sectors
    }
    let sec_per_clus = *bpb.get(13)?;
    let reserved = u16_at(bpb, 14)?;
    let num_fats = *bpb.get(16)?;
    let root_entries = u16_at(bpb, 17)?;
    let fat_size = u16_at(bpb, 22)?;
    if sec_per_clus == 0 || num_fats == 0 || fat_size == 0 || root_entries == 0 {
        return None;
    }
    Some(Fat16Info {
        part_start_lba,
        sec_per_clus,
        reserved,
        num_fats,
        root_entries,
        fat_size,
    })
}

/// One resolved 8.3 directory entry: starting cluster and byte size.
pub struct DirEntry {
    pub cluster: u16,
    pub size: u32,
}

/// Scan a directory's entries (root, or any cluster already known to hold a
/// subdirectory) for an exact 8.3 `name`/`ext` match (space-padded, upper
/// case, e.g. `b"EFI     "`, `b"   "`).
fn scan_dir_sectors(
    ctrl: &mut NvmeController,
    start_lba: u64,
    sector_count: usize,
    name: &[u8; 8],
    ext: &[u8; 3],
) -> Option<DirEntry> {
    for i in 0..sector_count {
        let lba = start_lba.checked_add(i as u64)?;
        if !ctrl.read_lba(lba) {
            return None;
        }
        let sector = ctrl.lba_data();
        for entry_off in (0..BYTES_PER_SECTOR).step_by(32) {
            let entry = sector.get(entry_off..entry_off + 32)?;
            let first = entry[0];
            if first == 0x00 {
                return None; // end of directory, no more entries anywhere
            }
            if first == 0xE5 {
                continue; // deleted entry
            }
            let attr = entry[11];
            if attr == 0x0F {
                continue; // long-filename entry, not handled by this reader
            }
            if &entry[0..8] == name && &entry[8..11] == ext {
                let cluster = u16_at(entry, 26)?;
                let size = u32_at(entry, 28)?;
                return Some(DirEntry { cluster, size });
            }
        }
    }
    None
}

/// Look up `name`/`ext` in the volume's root directory.
pub fn find_in_root(
    ctrl: &mut NvmeController,
    fs: &Fat16Info,
    name: &[u8; 8],
    ext: &[u8; 3],
) -> Option<DirEntry> {
    let root_lba = fs.root_dir_start_lba()?;
    scan_dir_sectors(ctrl, root_lba, fs.root_dir_sectors(), name, ext)
}

/// Look up `name`/`ext` inside a subdirectory whose first cluster is
/// `dir_cluster`. Only follows the first cluster of the directory (enough
/// for the small, single-cluster `EFI`/`BOOT` directories this image
/// actually creates); returns `None` rather than guessing on anything
/// larger, same "reject, don't misparse" policy as the rest of this reader.
pub fn find_in_subdir(
    ctrl: &mut NvmeController,
    fs: &Fat16Info,
    dir_cluster: u16,
    name: &[u8; 8],
    ext: &[u8; 3],
) -> Option<DirEntry> {
    let lba = fs.cluster_lba(dir_cluster)?;
    scan_dir_sectors(ctrl, lba, fs.sec_per_clus as usize, name, ext)
}

/// Read just the first sector of a file's first cluster into `out`. Enough
/// to verify a file's magic bytes without needing heap allocation or a full
/// cluster-chain walk (the FAT table itself is not consulted here).
pub fn read_first_sector(
    ctrl: &mut NvmeController,
    fs: &Fat16Info,
    entry: &DirEntry,
    out: &mut [u8; BYTES_PER_SECTOR],
) -> bool {
    let Some(lba) = fs.cluster_lba(entry.cluster) else {
        return false;
    };
    if !ctrl.read_lba(lba) {
        return false;
    }
    // lba_data() returns the full 4 KiB DMA buffer; only the first sector
    // (512 B) holds this read, so copy just that slice.
    out.copy_from_slice(&ctrl.lba_data()[..BYTES_PER_SECTOR]);
    true
}

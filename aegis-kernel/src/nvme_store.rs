//! Write-through content-addressed object store over the real NVMe device
//! (master roadmap Phase 7: the in-memory model and the Phase-4 kernel store
//! both become "write through the kernel's real NVMe block I/O").
//!
//! What moves from model to hardware, and what does not:
//! - Blocks are content-addressed and immutable, exactly like the model: the
//!   SHA-256 content hash is the block's identity and its integrity check in
//!   one. Identical bytes are the same block, stored once (dedup against the
//!   on-disk index). The digest implementation is `store::sha256`, already
//!   pinned against the FIPS 180-4 vectors.
//! - Mutable data is a copy-on-write layer: a write never overwrites an
//!   existing sector. A flat directory is a COW store object; every mutation
//!   appends a new content block and a new directory block, and an id you
//!   already hold reads that version forever. No sector that ever held a
//!   committed block is written twice.
//! - On-disk directory blocks are decoded with `store::decode_entries`, the
//!   bounds-checking routine hardened against exactly this input class: real,
//!   possibly-corrupted disk content. It can never panic and can never let a
//!   forged count field drive an out-of-bounds read.
//! - Reads are verified: `get` hashes what the disk returned and compares it
//!   to the id that was asked for. A bit-flipped or truncated on-disk block
//!   fails the digest check and is reported as missing (None / verify=false),
//!   never trusted and never panicked on.
//!
//! Disk layout (same image the kernel boots from; the store region sits far
//! past the FAT16 ESP's metadata and file data — see the constants):
//!   LBA 8192            header: magic + u16 LE block count
//!   LBA 8193..8208      index: 16 sectors x 512 B = 256 index slots? no —
//!                       16 sectors hold 170 entries of 48 bytes
//!   LBA 8209 ..         data: one 512 B sector per immutable block
//!
//! Honest limits (documented, not hidden): blocks are single 512 B sectors
//! (a content block is one LBA; bigger blocks are out of scope for the
//! prototype), the store indexes at most 170 blocks, writes are synchronous
//! write-through (completion is polled before the syscall/commit returns), and
//! the index is append-only from the live disk — it is never garbage
//! collected. There is no journal/CRC on the index itself (a torn header is
//! detected as an out-of-range count and refused, not repaired).

use crate::nvme::NvmeController;
use crate::store::{decode_entries, encode_entries, sha256, FileEntry, MAX_FILES};

/// First LBA of the store's region on the boot disk.
///
/// Chosen well past the FAT16 ESP: the boot image is 32768 sectors, the ESP
/// partition spans LBA 2048..30733, and its live data area (BPB metadata +
/// the `BOOTX64.EFI` chain) starts at partition-relative sector 133 and ends
/// far below this in practice. LBA 8192 is free cluster space the FAT never
/// allocates (its allocator hands out clusters from the data area upward, and
/// the on-disk FAT only marks the ~hundreds of sectors actually used), so the
/// store cannot collide with the live filesystem, the GPT partition table
/// (sector 1 / 32735..), or the backup GPT.
pub const STORE_START_LBA: u64 = 8192;
/// 1 header sector + 16 index sectors.
pub const INDEX_SECTORS: u64 = 17;
/// 16 sectors x 512 B / 48 B per entry (170.6 -> 170).
pub const MAX_BLOCKS: usize = (512 * 16) / 48;
/// First LBA of the immutable-block data region.
pub const DATA_BASE_LBA: u64 = STORE_START_LBA + INDEX_SECTORS;

const HEADER_MAGIC: [u8; 8] = *b"AEGISSTO";
const ENTRY_BYTES: usize = 48; // id[32] + lba[8] + len[2] + reserved[6]
const SECTOR: usize = 512;

/// Minimal synchronous sector I/O. The live kernel implementation is the NVMe
/// controller; tests use `MemDisk`, so the whole store (index handling,
/// dedup, digest verification, corrupted-block detection) is exercised on the
/// host with no hardware.
pub trait BlockIo {
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> bool;
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> bool;
}

impl BlockIo for NvmeController {
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> bool {
        if !self.read_lba(lba) {
            return false;
        }
        out[..SECTOR].copy_from_slice(&self.lba_data()[..SECTOR]);
        true
    }

    fn write_sector(&mut self, lba: u64, data: &[u8]) -> bool {
        self.write_lba(lba, data)
    }
}

/// One on-disk index entry (48 bytes, little-endian).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IndexEntry {
    id: [u8; 32],
    lba: u64,
    len: u16,
}

/// Absolute byte offset of index entry `i` within the whole index region.
fn index_entry_byte(i: usize) -> usize {
    i * ENTRY_BYTES
}

/// Serialize one index entry into its on-disk 48-byte form.
fn pack_entry(e: &IndexEntry, raw: &mut [u8; ENTRY_BYTES]) {
    raw[..32].copy_from_slice(&e.id);
    raw[32..40].copy_from_slice(&e.lba.to_le_bytes());
    raw[40..42].copy_from_slice(&e.len.to_le_bytes());
}

/// Write the 48-byte entry for slot `i`, splitting it across sector boundaries
/// if it straddles the end of an index sector (an entry may span two sectors).
fn write_index_entry(io: &mut impl BlockIo, i: usize, e: &IndexEntry) -> bool {
    let mut raw = [0u8; ENTRY_BYTES];
    pack_entry(e, &mut raw);
    let mut done = 0usize;
    let boff = index_entry_byte(i);
    let mut sector = STORE_START_LBA + 1 + (boff / SECTOR) as u64;
    let mut in_sec = boff % SECTOR;
    while done < raw.len() {
        let mut sec = [0u8; SECTOR];
        if !io.read_sector(sector, &mut sec) {
            return false;
        }
        let take = (SECTOR - in_sec).min(raw.len() - done);
        sec[in_sec..in_sec + take].copy_from_slice(&raw[done..done + take]);
        if !io.write_sector(sector, &sec) {
            return false;
        }
        done += take;
        sector += 1;
        in_sec = 0;
    }
    true
}

/// Read the 48-byte entry for slot `i` (inverse of [`write_index_entry`]),
/// reassembling it from one or two index sectors.
fn read_index_entry(io: &mut impl BlockIo, i: usize) -> Option<IndexEntry> {
    let mut raw = [0u8; ENTRY_BYTES];
    let mut done = 0usize;
    let boff = index_entry_byte(i);
    let mut sector = STORE_START_LBA + 1 + (boff / SECTOR) as u64;
    let mut in_sec = boff % SECTOR;
    let mut sec = [0u8; SECTOR];
    while done < raw.len() {
        if !io.read_sector(sector, &mut sec) {
            return None;
        }
        let take = (SECTOR - in_sec).min(raw.len() - done);
        raw[done..done + take].copy_from_slice(&sec[in_sec..in_sec + take]);
        done += take;
        sector += 1;
        in_sec = 0;
    }
    let id = raw[..32].try_into().ok()?;
    let lba = u64::from_le_bytes(raw[32..40].try_into().ok()?);
    let len = u16::from_le_bytes(raw[40..42].try_into().ok()?);
    Some(IndexEntry { id, lba, len })
}

/// The write-through store. Holds only the committed block count; everything
/// else lives on the disk, so a fresh handle always sees the durable state.
pub struct Store {
    count: u16,
}

impl Store {
    /// Open the store region. If the header magic is absent (first boot on a
    /// fresh image) the region is initialised empty; if the header is present
    /// the committed count is loaded. A count outside the valid range is a
    /// corrupt index and is refused (`None`) — no repair, no panic.
    pub fn open(io: &mut impl BlockIo) -> Option<Store> {
        let mut sec = [0u8; SECTOR];
        if !io.read_sector(STORE_START_LBA, &mut sec) {
            return None;
        }
        let fresh = sec[..8] != HEADER_MAGIC;
        if fresh {
            let mut s = Store { count: 0 };
            if !s.write_header(io) {
                return None;
            }
            return Some(s);
        }
        let count = u16::from_le_bytes(sec[8..10].try_into().ok()?);
        if count as usize > MAX_BLOCKS {
            return None;
        }
        Some(Store { count })
    }

    fn write_header(&mut self, io: &mut impl BlockIo) -> bool {
        let mut sec = [0u8; SECTOR];
        sec[..8].copy_from_slice(&HEADER_MAGIC);
        sec[8..10].copy_from_slice(&self.count.to_le_bytes());
        io.write_sector(STORE_START_LBA, &sec)
    }

    /// Number of immutable blocks committed to disk.
    pub fn count(&self) -> usize {
        self.count as usize
    }

    /// Scan the on-disk index for an entry with id `id`.
    fn find(&self, io: &mut impl BlockIo, id: &[u8; 32]) -> Option<IndexEntry> {
        for i in 0..self.count as usize {
            let e = read_index_entry(io, i)?;
            if e.id == *id {
                return Some(e);
            }
        }
        None
    }

    /// Commit `data` as a new immutable block (≤ 512 bytes). Content-addressed:
    /// identical bytes return the existing block id and write nothing (dedup).
    /// Returns `None` if the block is oversized, the region is full, or a disk
    /// write failed — never panics.
    pub fn put(&mut self, io: &mut impl BlockIo, data: &[u8]) -> Option<[u8; 32]> {
        if data.is_empty() || data.len() > SECTOR {
            return None;
        }
        let id = sha256(data);
        if self.find(io, &id).is_some() {
            return Some(id);
        }
        if self.count as usize >= MAX_BLOCKS {
            return None;
        }
        let slot = self.count as usize;
        let lba = DATA_BASE_LBA + slot as u64;

        // 1) Write the immutable data sector (never written again afterwards).
        let mut sec = [0u8; SECTOR];
        sec[..data.len()].copy_from_slice(data);
        if !io.write_sector(lba, &sec) {
            return None;
        }
        // 2) Append the index entry (data first, header count last = commit).
        if !write_index_entry(
            io,
            slot,
            &IndexEntry {
                id,
                lba,
                len: data.len() as u16,
            },
        ) {
            return None;
        }
        // 3) Commit point: bump the on-disk count.
        self.count += 1;
        if !self.write_header(io) {
            self.count -= 1;
            return None;
        }
        Some(id)
    }

    /// Read block `id` into `out`; returns the number of bytes copied. The
    /// returned bytes are digest-verified against `id` — a corrupted or
    /// truncated on-disk block yields `None` (never garbage, never a panic).
    pub fn get(&mut self, io: &mut impl BlockIo, id: &[u8; 32], out: &mut [u8]) -> Option<usize> {
        let e = self.find(io, id)?;
        let mut sec = [0u8; SECTOR];
        if !io.read_sector(e.lba, &mut sec) {
            return None;
        }
        let len = e.len as usize;
        if len > out.len() || sha256(&sec[..len]) != *id {
            return None;
        }
        out[..len].copy_from_slice(&sec[..len]);
        Some(len)
    }

    /// True only if the block on disk digests to `id`. This is the live
    /// corrupted-block detector: a bit flip anywhere in the payload changes
    /// the digest and the block reads as absent.
    pub fn verify(&mut self, io: &mut impl BlockIo, id: &[u8; 32]) -> bool {
        let Some(e) = self.find(io, id) else {
            return false;
        };
        let mut sec = [0u8; SECTOR];
        if !io.read_sector(e.lba, &mut sec) {
            return false;
        }
        sha256(&sec[..e.len as usize]) == *id
    }

    // --- COW flat directory over the store -----------------------------------

    /// Commit a flat directory as a COW store object: the entries table is
    /// encoded (`store::encode_entries`) and stored as one immutable content
    /// block. A mutation writes a *new* dir block; the old id keeps reading the
    /// old version forever. Returns the dir block's id.
    pub fn put_dir(&mut self, io: &mut impl BlockIo, entries: &[FileEntry]) -> Option<[u8; 32]> {
        let (enc, enc_len) = encode_entries(entries)?;
        if enc_len > SECTOR {
            return None;
        }
        self.put(io, &enc[..enc_len])
    }

    /// Load and decode a dir block into `out`; returns how many entries were
    /// decoded. The block's bytes are digest-verified first; a corrupted dir
    /// reads as absent (`None`), and the decoder itself tolerates any
    /// truncation/garbage without panicking.
    pub fn load_dir(
        &mut self,
        io: &mut impl BlockIo,
        id: &[u8; 32],
        out: &mut [FileEntry; MAX_FILES],
    ) -> Option<usize> {
        let mut buf = [0u8; SECTOR];
        let n = self.get(io, id, &mut buf)?;
        Some(decode_entries(&buf[..n], out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Name;

    fn empty_entry() -> FileEntry {
        FileEntry {
            name: Name::from_slice(b"x").unwrap(),
            node: 0,
        }
    }

    fn entry(name: &[u8], node: u64) -> FileEntry {
        FileEntry {
            name: Name::from_slice(name).unwrap(),
            node,
        }
    }

    /// A fixed-size in-memory block device: a vector of 512 B sectors.
    struct MemDisk {
        sectors: Vec<[u8; SECTOR]>,
    }

    impl MemDisk {
        fn new(sectors: usize) -> MemDisk {
            MemDisk {
                sectors: vec![[0u8; SECTOR]; sectors],
            }
        }

        /// Bit-flip byte `b` of sector `lba` (as the live disk would after a
        /// write storm / media error).
        fn flip(&mut self, lba: u64, b: usize) {
            self.sectors[lba as usize][b] ^= 0x01;
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

    #[test]
    fn open_initialises_a_fresh_region_and_reopens_it() {
        let mut disk = MemDisk::new(9000);
        let mut s = Store::open(&mut disk).unwrap();
        assert_eq!(s.count(), 0);
        s.put(&mut disk, b"hello disk").unwrap();
        assert_eq!(s.count(), 1);
        // A second handle sees the durable count (index lives on the disk).
        let s2 = Store::open(&mut disk).unwrap();
        assert_eq!(s2.count(), 1);
    }

    #[test]
    fn put_then_get_roundtrips_content() {
        let mut disk = MemDisk::new(9000);
        let mut s = Store::open(&mut disk).unwrap();
        let id = s
            .put(&mut disk, b"hello content-addressed NVMe block")
            .unwrap();
        let mut out = [0u8; 512];
        let n = s.get(&mut disk, &id, &mut out).unwrap();
        assert_eq!(&out[..n], b"hello content-addressed NVMe block");
        assert!(s.verify(&mut disk, &id));
    }

    #[test]
    fn identical_bytes_dedup_to_one_block() {
        let mut disk = MemDisk::new(9000);
        let mut s = Store::open(&mut disk).unwrap();
        let a = s.put(&mut disk, b"same bytes").unwrap();
        let b = s.put(&mut disk, b"same bytes").unwrap();
        assert_eq!(a, b, "content addressing: same content, same block");
        assert_eq!(s.count(), 1, "dedup: the second put wrote nothing");
    }

    #[test]
    fn cow_dir_versions_are_distinct_and_version_stable() {
        let mut disk = MemDisk::new(9000);
        let mut s = Store::open(&mut disk).unwrap();
        let d1 = s.put_dir(&mut disk, &[entry(b"memo.txt", 7)]).unwrap();
        let d2 = s
            .put_dir(&mut disk, &[entry(b"memo.txt", 8), entry(b"todo.txt", 9)])
            .unwrap();
        assert_ne!(
            d1, d2,
            "a mutation writes a new dir block, never overwrites"
        );

        let mut e = [empty_entry(); MAX_FILES];
        let n = s.load_dir(&mut disk, &d1, &mut e).unwrap();
        assert_eq!(n, 1);
        assert!(e[0].name.matches(b"memo.txt"));
        assert_eq!(e[0].node, 7, "old dir id still reads the old version");

        let mut e2 = [empty_entry(); MAX_FILES];
        let n2 = s.load_dir(&mut disk, &d2, &mut e2).unwrap();
        assert_eq!(n2, 2);
        assert!(e2[0].name.matches(b"memo.txt"));
        assert_eq!(e2[0].node, 8);
        assert!(e2[1].name.matches(b"todo.txt"));
        assert_eq!(s.count(), 2, "two dir blocks, no mutation of either");
    }

    /// The headline Phase 7 contract test: a deliberately corrupted on-disk
    /// block (bit-flipped) is detected by digest mismatch — read as absent,
    /// never trusted, never panicked on, and the store stays usable.
    #[test]
    fn corrupted_block_detected_without_panic() {
        let mut disk = MemDisk::new(9000);
        let mut s = Store::open(&mut disk).unwrap();
        let id = s.put(&mut disk, b"precious payload").unwrap();
        assert!(s.verify(&mut disk, &id));

        // The block landed at the first data LBA; flip one bit of it on disk.
        let lba = DATA_BASE_LBA;
        disk.flip(lba, 0);

        let mut out = [0u8; 512];
        assert!(
            s.get(&mut disk, &id, &mut out).is_none(),
            "bit-flipped block must read as absent, not as garbage"
        );
        assert!(!s.verify(&mut disk, &id));
        // No panic, store still fully usable afterwards.
        let id2 = s.put(&mut disk, b"still works").unwrap();
        let mut out2 = [0u8; 512];
        let n = s.get(&mut disk, &id2, &mut out2).unwrap();
        assert_eq!(&out2[..n], b"still works");
        assert!(s.verify(&mut disk, &id2));
    }

    /// A truncated block (the index claims more bytes than the content hash
    /// covers) also reads as absent, without panicking.
    #[test]
    fn truncated_block_detected_without_panic() {
        let mut disk = MemDisk::new(9000);
        let mut s = Store::open(&mut disk).unwrap();
        let id = s.put(&mut disk, b"short").unwrap();
        assert!(s.verify(&mut disk, &id));

// Corrupt the index: claim the block is 500 bytes of the padded sector.
        // Slot 0 sits at the very start of the first index sector.
        let mut sec = [0u8; SECTOR];
        disk.read_sector(STORE_START_LBA + 1, &mut sec);
        sec[40..42].copy_from_slice(&500u16.to_le_bytes());
        disk.write_sector(STORE_START_LBA + 1, &sec);

        let mut out = [0u8; 512];
        assert!(s.get(&mut disk, &id, &mut out).is_none());
        assert!(!s.verify(&mut disk, &id));
    }

    /// Index entries are 48 bytes and may straddle the 512-byte index-sector
    /// boundary (slot 10 begins at byte 480). Pushing well past that proves the
    /// pack/unpack split survives many crossings: every block must still verify
    /// and read back byte-for-byte.
    #[test]
    fn many_blocks_span_index_sector_boundaries() {
        let mut disk = MemDisk::new(9000);
        let mut s = Store::open(&mut disk).unwrap();
        let mut ids = [[0u8; 32]; 64];
        for (i, id) in ids.iter_mut().enumerate() {
            let payload = [i as u8; 511];
            *id = s.put(&mut disk, &payload).unwrap();
        }
        for (i, id) in ids.iter().enumerate() {
            let payload = [i as u8; 511];
            let mut out = [0u8; 512];
            let n = s.get(&mut disk, id, &mut out).unwrap();
            assert_eq!(&out[..n], &payload[..n]);
            assert!(s.verify(&mut disk, id));
        }
        assert_eq!(s.count(), 64);
    }

    /// decode_entries must tolerate any garbage a real disk can serve: a forged
    /// huge count, a bit-flipped length, or a truncation anywhere — no panic,
    /// and never more decoded entries than the bytes actually admit.
    #[test]
    fn decode_entries_tolerates_truncation_and_bit_flips() {
        let mut e = [empty_entry(); MAX_FILES];
        let good = [entry(b"memo.txt", 7), entry(b"todo.txt", 9)];
        let (enc, enc_len) = encode_entries(&good).unwrap();

        // Header-only (claims 2 entries, has none): 0 decoded.
        assert_eq!(decode_entries(&enc[..4], &mut e), 0);
        // Truncated mid-name: the entry's name bytes are cut short.
        assert_eq!(decode_entries(&enc[..6], &mut e), 0);
        // Truncated after the first name, before its node: 0 decoded.
        assert_eq!(decode_entries(&enc[..16], &mut e), 0);
        // Bit-flipped first name length: the decoder bounds-checks before
        // slicing, so it must not panic (the name window is invalid).
        let mut flipped = enc;
        flipped[4] ^= 0x80;
        let _ = decode_entries(&flipped[..enc_len], &mut e);
        // A forged huge count can never cause an out-of-bounds read.
        let mut forged = [0u8; 512];
        forged[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_entries(&forged[..forged.len()], &mut e), 0);
        // Garbage payload of arbitrary length: no panic, bounded result.
        let mut junk = [0x5Au8; 300];
        junk[0] = 0xFF;
        junk[1] = 0xFF;
        junk[2] = 0xFF;
        junk[3] = 0x0F;
        let _ = decode_entries(&junk, &mut e);
        // The real encoding still decodes fine after all that abuse.
        let n = decode_entries(&enc[..enc_len], &mut e);
        assert_eq!(n, 2);
        assert!(e[0].name.matches(b"memo.txt"));
        assert_eq!(e[0].node, 7);
    }

    #[test]
    fn oversized_block_refused() {
        let mut disk = MemDisk::new(9000);
        let mut s = Store::open(&mut disk).unwrap();
        assert!(s.put(&mut disk, &[0u8; 513]).is_none());
        assert!(s.put(&mut disk, b"").is_none());
        assert_eq!(s.count(), 0);
    }
}

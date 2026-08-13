//! Package install + staged generation updates over the **Phase-7 NVMe object
//! store** (master roadmap §10 "package/update polish" — packages sit on top
//! of object-store, now the real one). This is the model crate
//! `packages`/`system-update` logic, ported to run against the kernel's own
//! write-through store so a full install → stage → activate → rollback cycle
//! persists to the boot device.
//!
//! What moves from the model to hardware, and what does not:
//! - A **package** is a manifest (name + declared capability ceiling) plus a
//!   set of named **content-addressed payload blocks**, committed through
//!   `nvme_store::Store::put`. Identical payload bytes across packages are the
//!   same block (dedup against the on-disk index); every read is
//!   digest-verified. This mirrors `packages::PackageManager::install`: the
//!   payload is immutable content blocks in the store.
//! - An **update** is a staged, health-gated, transactional generation, exactly
//!   like `system_update::UpdateManager`:
//!   * `stage` installs a candidate generation and writes its descriptor
//!     (`gen-N`) into the boot view **without touching `current`**;
//!   * `activate` **flips the boot target** — a single COW write to the
//!     `current` dir entry — only after a caller-supplied health check passes;
//!   * `rollback` flips `current` back to the last applied generation that
//!     passed health at activation, and drops the dethroned generation.
//! - The **boot view** is a COW directory held as one content-addressed block:
//!   entries `(name -> block id)`. Every mutation appends a NEW dir block; an
//!   id you already hold (a pre-activation `current`) reads the old target
//!   forever. Same semantics as the model's `FlatView`.
//!
//! Honest limits (same discipline as `nvme_store`): blocks are single 512 B
//! sectors and the view indexes at most [`VIEW_MAX_FILES`] names; the
//! descriptor carries the generation number + package name only (no signature
//! — the model's signing chain stays out of scope here); health is supplied by
//! the caller ([`payloads_verify`] verifies every payload block against the
//! live disk).

use crate::nvme_store::{BlockIo, Store};
use crate::store::{BlockId, Name, MAX_FILES};

/// Maximum number of names the COW boot view can hold.
pub const VIEW_MAX_FILES: usize = MAX_FILES;

/// Maximum encoded dir-block bytes (a single 512 B store block).
const DIR_BUF: usize = 512;

/// One package manifest declared by the host before install.
#[derive(Clone, Copy, Debug)]
pub struct Manifest {
    pub name: Name,
    /// Declared capability ceiling (informational here — the model
    /// `capability_audit::Manifest` is the enforced one).
    pub ceiling: u32,
}

/// A named payload file: `name` in the boot view, bytes stored as a
/// content-addressed block through `nvme_store`.
#[derive(Clone, Copy, Debug)]
pub struct PayloadFile {
    pub name: Name,
    pub bytes: &'static [u8],
}

/// One installed generation descriptor: which generation is bootable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationDescriptor {
    pub n: u64,
    pub package: Name,
}

/// Decimal rendering of `n` into `out` (no_std-safe); returns the slice used.
fn write_u64(mut n: u64, out: &mut [u8]) -> &[u8] {
    if out.is_empty() {
        return &[];
    }
    let mut tmp = [0u8; 20];
    let mut i = 0usize;
    if n == 0 {
        tmp[i] = b'0';
        i += 1;
    } else {
        while n > 0 {
            tmp[i] = b'0' + (n % 10) as u8;
            i += 1;
            n /= 10;
        }
    }
    // Reverse digits into out.
    let len = i.min(out.len());
    for j in 0..len {
        out[j] = tmp[i - 1 - j];
    }
    &out[..len]
}

/// Descriptor ↔ bytes: the same tiny "n\nname" envelope the model uses.
/// Returns the bytes and how many are actually meaningful (the tail is
/// padding; decode [`decode_descriptor`] on the slice `[..len]`).
pub fn encode_descriptor(d: &GenerationDescriptor) -> ([u8; 64], usize) {
    let mut out = [0u8; 64];
    let mut dec = [0u8; 20];
    let n = write_u64(d.n, &mut dec);
    let mut at = 0usize;
    out[at..at + n.len()].copy_from_slice(n);
    at = n.len();
    out[at] = b'\n';
    at += 1;
    let name = d.package.as_slice();
    out[at..at + name.len()].copy_from_slice(name);
    at += name.len();
    (out, at)
}

/// Inverse of [`encode_descriptor`]; None on any malformed input.
pub fn decode_descriptor(b: &[u8]) -> Option<GenerationDescriptor> {
    let s = core::str::from_utf8(b).ok()?;
    let (n, name) = s.split_once('\n')?;
    Some(GenerationDescriptor {
        n: n.parse().ok()?,
        package: Name::from_slice(name.as_bytes())?,
    })
}

// --- COW boot view ----------------------------------------------------------

/// The directory encoding stored as one content-addressed block:
/// `count u16 LE` then per entry `name_len u8`, `name`, `block id [u8; 32]`.
#[derive(Clone, Copy, Default)]
pub(crate) struct DirEntry {
    pub name: Name,
    pub id: BlockId,
}

pub(crate) fn encode_dir(entries: &[DirEntry]) -> Option<([u8; DIR_BUF], usize)> {
    let mut out = [0u8; DIR_BUF];
    if entries.len() > u16::MAX as usize {
        return None;
    }
    out[..2].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    let mut at = 2usize;
    for e in entries {
        let name = e.name.as_slice();
        if at + 1 + name.len() + 32 > DIR_BUF {
            return None;
        }
        out[at] = name.len() as u8;
        at += 1;
        out[at..at + name.len()].copy_from_slice(name);
        at += name.len();
        out[at..at + 32].copy_from_slice(&e.id);
        at += 32;
    }
    Some((out, at))
}

/// Decode at most `VIEW_MAX_FILES` entries; never panics on garbage.
pub(crate) fn decode_dir(bytes: &[u8], out: &mut [DirEntry; VIEW_MAX_FILES]) -> usize {
    let mut written = 0usize;
    if bytes.len() < 2 {
        return 0;
    }
    let mut at = 0usize;
    let count = u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
    at += 2;
    for _ in 0..count.min(VIEW_MAX_FILES) {
        let Some(&nlen) = bytes.get(at) else { break };
        at += 1;
        let nlen = nlen as usize;
        let Some(name_bytes) = bytes.get(at..at + nlen) else {
            break;
        };
        let Some(name) = Name::from_slice(name_bytes) else {
            break;
        };
        at += nlen;
        let Some(id_bytes) = bytes.get(at..at + 32) else {
            break;
        };
        let mut id = [0u8; 32];
        id.copy_from_slice(id_bytes);
        at += 32;
        out[written] = DirEntry { name, id };
        written += 1;
    }
    written
}

/// The COW boot view. `dir` is the block id of the current encoded directory;
/// every mutation (`activate`, `rollback`, package file writes) commits a NEW
/// dir block and repoints `dir`. A saved `current` id from before any mutation
/// still reads the old directory (version-stable, like the model's FlatView).
#[derive(Clone, Copy)]
pub struct BootView {
    dir: BlockId,
}

impl BootView {
    /// Create a fresh empty boot view: one directory block with zero entries.
    pub fn create(store: &mut Store, io: &mut impl BlockIo) -> Option<BootView> {
        let (enc, len) = encode_dir(&[])?;
        let dir = store.put(io, &enc[..len])?;
        Some(BootView { dir })
    }

    pub fn dir_id(&self) -> BlockId {
        self.dir
    }

    fn read_dir(&self, store: &mut Store, io: &mut impl BlockIo) -> [DirEntry; VIEW_MAX_FILES] {
        let mut out = [DirEntry::default(); VIEW_MAX_FILES];
        let mut buf = [0u8; DIR_BUF];
        if let Some(n) = store.get(io, &self.dir, &mut buf) {
            decode_dir(&buf[..n], &mut out);
        }
        out
    }

    /// Resolve `name` to its content block id in this view (None if absent).
    pub fn get(&self, store: &mut Store, io: &mut impl BlockIo, name: &[u8]) -> Option<BlockId> {
        let entries = self.read_dir(store, io);
        entries.iter().find(|e| e.name.matches(name)).map(|e| e.id)
    }

    /// Read the bytes named `name` in this view (digest-verified by the store).
    pub fn read_file(
        &self,
        store: &mut Store,
        io: &mut impl BlockIo,
        name: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        let id = self.get(store, io, name)?;
        store.get(io, &id, out)
    }

    /// A mutation: commit a new directory block with `name -> id` bound (COW).
    /// The old dir block is untouched and keeps reading the old table forever.
    fn set(&mut self, store: &mut Store, io: &mut impl BlockIo, name: Name, id: BlockId) -> bool {
        let cur = self.read_dir(store, io);
        let mut out = [DirEntry::default(); VIEW_MAX_FILES];
        let mut n = 0usize;
        let mut replaced = false;
        for e in cur.iter() {
            if e.name.as_slice().is_empty() {
                continue;
            }
            if e.name.matches(name.as_slice()) && !replaced {
                out[n] = DirEntry { name, id };
                replaced = true;
            } else {
                out[n] = *e;
            }
            n += 1;
        }
        if !replaced {
            if n >= VIEW_MAX_FILES {
                return false;
            }
            out[n] = DirEntry { name, id };
            n += 1;
        }
        let Some((enc, len)) = encode_dir(&out[..n]) else {
            return false;
        };
        let Some(new_dir) = store.put(io, &enc[..len]) else {
            return false;
        };
        self.dir = new_dir;
        true
    }

    /// Store `bytes` as a content block and bind `name` to it (COW).
    pub fn write_file(
        &mut self,
        store: &mut Store,
        io: &mut impl BlockIo,
        name: &[u8],
        bytes: &[u8],
    ) -> Option<BlockId> {
        let id = store.put(io, bytes)?;
        if self.set(store, io, Name::from_slice(name)?, id) {
            Some(id)
        } else {
            None
        }
    }

    /// Names present in this view, decoded into `out`; returns how many.
    pub fn list(
        &self,
        store: &mut Store,
        io: &mut impl BlockIo,
        out: &mut [Name; VIEW_MAX_FILES],
    ) -> usize {
        let entries = self.read_dir(store, io);
        let mut n = 0usize;
        for e in entries.iter() {
            if e.name.as_slice().is_empty() {
                continue;
            }
            out[n] = e.name;
            n += 1;
        }
        n
    }
}

// --- Update manager ---------------------------------------------------------

/// A staged, not-yet-activated candidate generation.
pub struct StagedGen {
    pub n: u64,
    pub manifest: Manifest,
    pub payload: [BlockId; VIEW_MAX_FILES],
    pub payload_count: usize,
    /// The block id of this generation's descriptor in the boot view.
    pub descriptor_block: BlockId,
    pub descriptor: GenerationDescriptor,
}

/// Health gate for activation: staged payload must still digest to its content
/// hash on the live disk.
pub fn payloads_verify<IO: BlockIo>(store: &mut Store, io: &mut IO, s: &StagedGen) -> bool {
    s.payload[..s.payload_count]
        .iter()
        .all(|id| store.verify(io, id))
}

/// Staged, health-gated, transactional generations over the NVMe boot view.
pub struct UpdateManager {
    view: BootView,
    applied: [GenerationDescriptor; VIEW_MAX_FILES],
    applied_count: usize,
    next_n: u64,
}

impl UpdateManager {
    /// Attach to an existing (or freshly created) boot view. The next
    /// generation number starts after the highest `gen-N` descriptor present,
    /// so a rebooted system continues numbering.
    pub fn attach(store: &mut Store, io: &mut impl BlockIo, view: BootView) -> UpdateManager {
        let mut next_n = 1u64;
        let mut names = [Name::from_slice(b"x").unwrap(); VIEW_MAX_FILES];
        let n = view.list(store, io, &mut names);
        for name in names.iter().take(n) {
            if let Some(rest) = name.as_slice().strip_prefix(b"gen-") {
                let s = core::str::from_utf8(rest).unwrap_or("");
                if let Ok(v) = s.parse::<u64>() {
                    next_n = next_n.max(v + 1);
                }
            }
        }
        UpdateManager {
            view,
            applied: [GenerationDescriptor {
                n: 0,
                package: Name::from_slice(b"x").unwrap(),
            }; VIEW_MAX_FILES],
            applied_count: 0,
            next_n,
        }
    }

    /// What the bootloader would boot: the descriptor pinned in the store as
    /// `current` (None before the first activation). The boot target is durable
    /// store content, not memory.
    pub fn boot_target(
        &self,
        store: &mut Store,
        io: &mut impl BlockIo,
    ) -> Option<GenerationDescriptor> {
        let mut buf = [0u8; 64];
        let n = self.view.read_file(store, io, b"current", &mut buf)?;
        decode_descriptor(&buf[..n])
    }

    /// Install `pkg` as a candidate generation: commit the manifest + payload
    /// blocks and write the `gen-N` descriptor into the boot view — `current`
    /// is never touched.
    pub fn stage(
        &mut self,
        store: &mut Store,
        io: &mut impl BlockIo,
        manifest: Manifest,
        payload: &[PayloadFile],
    ) -> Option<StagedGen> {
        if payload.len() > VIEW_MAX_FILES {
            return None;
        }
        let n = self.next_n;
        self.next_n += 1;
        let mut ids = [BlockId::default(); VIEW_MAX_FILES];
        for (i, pf) in payload.iter().enumerate() {
            ids[i] = store.put(io, pf.bytes)?;
        }
        let descriptor = GenerationDescriptor {
            n,
            package: manifest.name,
        };
        let (desc_bytes, desc_len) = encode_descriptor(&descriptor);
        let gen_name = gen_name(n);
        let descriptor_block =
            self.view
                .write_file(store, io, &gen_name, &desc_bytes[..desc_len])?;
        Some(StagedGen {
            n,
            manifest,
            payload: ids,
            payload_count: payload.len(),
            descriptor_block,
            descriptor,
        })
    }

    /// Flip the boot target to the staged generation, but only if it passes
    /// `health`. On success `current` names the staged descriptor (a single COW
    /// dir write); the staged app stays installed either way.
    pub fn activate<IO, F>(
        &mut self,
        store: &mut Store,
        io: &mut IO,
        staged: &StagedGen,
        health: F,
    ) -> bool
    where
        IO: BlockIo,
        F: Fn(&mut Store, &mut IO, &StagedGen) -> bool,
    {
        if !health(store, io, staged) {
            return false;
        }
        let current = Name::from_slice(b"current").unwrap();
        if !self.view.set(store, io, current, staged.descriptor_block) {
            return false;
        }
        if self.applied_count < VIEW_MAX_FILES {
            self.applied[self.applied_count] = staged.descriptor;
            self.applied_count += 1;
        }
        true
    }

    /// Flip the boot target back to the last applied generation that is not the
    /// current boot target. The old generation's blocks stay installed; the
    /// dethroned generation leaves the applied history, so a second rollback
    /// has nothing more to restore.
    pub fn rollback(&mut self, store: &mut Store, io: &mut impl BlockIo) -> Option<u64> {
        if self.applied_count == 0 {
            return None;
        }
        let latest = self.applied[self.applied_count - 1];
        let target = self.applied[..self.applied_count]
            .iter()
            .rfind(|g| g.n != latest.n)
            .copied()?;
        let (desc_bytes, desc_len) = encode_descriptor(&target);
        let current = Name::from_slice(b"current").unwrap();
        let desc_id = store.put(io, &desc_bytes[..desc_len])?;
        if !self.view.set(store, io, current, desc_id) {
            return None;
        }
        let mut keep = 0usize;
        let mut copy = [GenerationDescriptor {
            n: 0,
            package: Name::from_slice(b"x").unwrap(),
        }; VIEW_MAX_FILES];
        let mut copied = 0usize;
        for g in self.applied[..self.applied_count].iter() {
            if g.n <= target.n {
                copy[copied] = *g;
                copied += 1;
                keep += 1;
            }
        }
        self.applied[..copied].copy_from_slice(&copy[..copied]);
        self.applied_count = keep;
        Some(target.n)
    }

    /// The boot view's block id (for audit/reporting in demos).
    pub fn view_id(&self) -> BlockId {
        self.view.dir_id()
    }
}

/// Descriptor file name for generation `n`: "gen-N".
fn gen_name(n: u64) -> [u8; 7] {
    let mut b = *b"gen-000";
    let mut dec = [0u8; 20];
    let s = write_u64(n, &mut dec);
    let start = 4 + 3 - s.len();
    b[start..start + s.len()].copy_from_slice(s);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECTOR: usize = 512;

    struct MemDisk {
        sectors: Vec<[u8; SECTOR]>,
    }

    impl MemDisk {
        fn new(sectors: usize) -> MemDisk {
            MemDisk {
                sectors: vec![[0u8; SECTOR]; sectors],
            }
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

    fn man(name: &[u8]) -> Manifest {
        Manifest {
            name: Name::from_slice(name).unwrap(),
            ceiling: 0,
        }
    }

    fn payload(name: &[u8], bytes: &'static [u8]) -> PayloadFile {
        PayloadFile {
            name: Name::from_slice(name).unwrap(),
            bytes,
        }
    }

    fn health_ok(_: &mut Store, _: &mut MemDisk, _: &StagedGen) -> bool {
        true
    }

    fn health_bad(_: &mut Store, _: &mut MemDisk, _: &StagedGen) -> bool {
        false
    }

    /// A full world: a store on a MemDisk, a fresh boot view, and the manager.
    fn world() -> (MemDisk, Store, UpdateManager) {
        let mut disk = MemDisk::new(9000);
        let mut store = Store::open(&mut disk).unwrap();
        let view = BootView::create(&mut store, &mut disk).unwrap();
        let um = UpdateManager::attach(&mut store, &mut disk, view);
        (disk, store, um)
    }

    #[test]
    fn descriptor_roundtrips() {
        let d = GenerationDescriptor {
            n: 42,
            package: Name::from_slice(b"editor").unwrap(),
        };
        let (b, len) = encode_descriptor(&d);
        let got = decode_descriptor(&b[..len]).unwrap();
        assert_eq!(got, d);
        assert!(decode_descriptor(b"garbage").is_none());
        assert!(decode_descriptor(b"x").is_none());
        assert!(decode_descriptor(b"noparse\neditor").is_none());
    }

    #[test]
    fn decode_dir_tolerates_truncation_and_bit_flips() {
        let mut out = [DirEntry::default(); VIEW_MAX_FILES];
        let a = Name::from_slice(b"memo.txt").unwrap();
        let e = [DirEntry {
            name: a,
            id: [7u8; 32],
        }];
        let (enc, len) = encode_dir(&e).unwrap();
        // Header-only (claims 1, has none): 0 decoded.
        assert_eq!(decode_dir(&enc[..2], &mut out), 0);
        // Truncated mid-name: 0 decoded.
        assert_eq!(decode_dir(&enc[..4], &mut out), 0);
        // Bit-flipped name length: must not panic.
        let mut flipped = enc;
        flipped[2] ^= 0xFF;
        let _ = decode_dir(&flipped[..len], &mut out);
        // Forged huge count: bounded, no out-of-bounds read.
        let mut forged = [0u8; SECTOR];
        forged[..2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(decode_dir(&forged, &mut out), 0);
        // The real encoding still decodes after all that abuse.
        assert_eq!(decode_dir(&enc[..len], &mut out), 1);
    }

    #[test]
    fn staging_a_candidate_does_not_disturb_the_boot_target() {
        let (mut disk, mut store, mut um) = world();
        let s1 = um
            .stage(
                &mut store,
                &mut disk,
                man(b"editor"),
                &[payload(b"main.bin", b"editor v1 payload")],
            )
            .unwrap();
        assert_eq!(s1.n, 1);
        // Staged, not booted: current is still absent.
        assert!(um.boot_target(&mut store, &mut disk).is_none());
        let s2 = um
            .stage(
                &mut store,
                &mut disk,
                man(b"editor"),
                &[payload(b"main.bin", b"editor v2 payload")],
            )
            .unwrap();
        assert_eq!(s2.n, 2);
        assert!(um.boot_target(&mut store, &mut disk).is_none());
    }

    #[test]
    fn activation_is_health_gated() {
        let (mut disk, mut store, mut um) = world();
        let staged = um
            .stage(
                &mut store,
                &mut disk,
                man(b"editor"),
                &[payload(b"main.bin", b"editor v1 payload")],
            )
            .unwrap();
        // A failing health check leaves the boot target untouched.
        assert!(!um.activate(&mut store, &mut disk, &staged, health_bad));
        assert!(um.boot_target(&mut store, &mut disk).is_none());
        // A passing check flips it.
        assert!(um.activate(&mut store, &mut disk, &staged, health_ok));
        assert_eq!(um.boot_target(&mut store, &mut disk).unwrap().n, 1);
    }

    #[test]
    fn activation_is_a_content_flip_and_version_stable() {
        let (mut disk, mut store, mut um) = world();
        let staged = um
            .stage(
                &mut store,
                &mut disk,
                man(b"editor"),
                &[payload(b"main.bin", b"editor v1 payload")],
            )
            .unwrap();
        let before = um.view_id();
        assert!(um.activate(&mut store, &mut disk, &staged, health_ok));
        let after = um.view_id();
        assert_ne!(
            before, after,
            "activation writes a new dir block, never in place"
        );
        // Version-stable: the pre-activation view id still reads the old empty
        // table (no 'current'), because no block was mutated.
        let old = BootView { dir: before };
        assert!(old.get(&mut store, &mut disk, b"current").is_none());
        // The new view sees the flip.
        assert!(um.boot_target(&mut store, &mut disk).is_some());
    }

    #[test]
    fn rollback_restores_last_known_good_and_drop_dethroned() {
        let (mut disk, mut store, mut um) = world();
        let g1 = um
            .stage(
                &mut store,
                &mut disk,
                man(b"editor"),
                &[payload(b"main.bin", b"editor v1 payload")],
            )
            .unwrap();
        let g2 = um
            .stage(
                &mut store,
                &mut disk,
                man(b"editor"),
                &[payload(b"main.bin", b"editor v2 payload")],
            )
            .unwrap();
        assert!(um.activate(&mut store, &mut disk, &g1, health_ok));
        assert_eq!(um.boot_target(&mut store, &mut disk).unwrap().n, 1);
        assert!(um.activate(&mut store, &mut disk, &g2, health_ok));
        assert_eq!(um.boot_target(&mut store, &mut disk).unwrap().n, 2);
        // Rollback returns to 1, the last known good.
        assert_eq!(um.rollback(&mut store, &mut disk), Some(1));
        assert_eq!(um.boot_target(&mut store, &mut disk).unwrap().n, 1);
        // The dethroned generation leaves history: nothing more to roll back to.
        assert_eq!(um.rollback(&mut store, &mut disk), None);
    }

    #[test]
    fn rollback_preserves_generations_up_to_the_target() {
        let (mut disk, mut store, mut um) = world();
        let g1 = um
            .stage(&mut store, &mut disk, man(b"editor"), &[])
            .unwrap();
        let g2 = um
            .stage(&mut store, &mut disk, man(b"editor"), &[])
            .unwrap();
        let g3 = um
            .stage(&mut store, &mut disk, man(b"editor"), &[])
            .unwrap();
        for g in [&g1, &g2, &g3] {
            assert!(um.activate(&mut store, &mut disk, g, health_ok));
        }
        assert_eq!(um.boot_target(&mut store, &mut disk).unwrap().n, 3);
        assert_eq!(um.rollback(&mut store, &mut disk), Some(2));
        assert_eq!(um.boot_target(&mut store, &mut disk).unwrap().n, 2);
        assert_eq!(um.rollback(&mut store, &mut disk), Some(1));
        assert_eq!(um.rollback(&mut store, &mut disk), None);
    }

    #[test]
    fn identical_payloads_dedup_to_one_block() {
        let (mut disk, mut store, mut um) = world();
        let base = store.count();
        let g1 = um
            .stage(
                &mut store,
                &mut disk,
                man(b"pkg-a"),
                &[payload(b"data.bin", b"shared payload bytes")],
            )
            .unwrap();
        let g2 = um
            .stage(
                &mut store,
                &mut disk,
                man(b"pkg-b"),
                &[payload(b"data.bin", b"shared payload bytes")],
            )
            .unwrap();
        assert_eq!(g1.payload[0], g2.payload[0], "same content, same block");
        // Two payload writes dedup: only the dir blocks + descriptors are new.
        let new_blocks = store.count() - base;
        // Two identical payload writes cost ONE data block (the second dedups):
        // 1 payload + 2 descriptors + 2 COW dirs = 5, not 6.
        assert_eq!(
            new_blocks, 5,
            "payload dedup keeps an install cheap: {} blocks",
            new_blocks
        );
    }

    #[test]
    fn reopen_dedups_payloads_and_continues_numbering() {
        let (mut disk, mut store, mut um) = world();
        let g1 = um
            .stage(
                &mut store,
                &mut disk,
                man(b"editor"),
                &[payload(b"main.bin", b"editor v1 payload")],
            )
            .unwrap();
        assert!(um.activate(&mut store, &mut disk, &g1, health_ok));
        // Reopen the store as a fresh manager (a reboot) attached to the SAME
        // boot-view dir the previous session wrote: the content blocks are
        // durable on disk, so re-installing the SAME payload dedups — identical
        // bytes are still one block, no new data block is written.
        let boot_dir = um.view_id();
        let mut store2 = Store::open(&mut disk).unwrap();
        let mut um2 = UpdateManager::attach(&mut store2, &mut disk, BootView { dir: boot_dir });
        // Numbering continues past generation 1.
        assert_eq!(um2.next_n, 2, "attach resumes gen numbering from the dir");
        let count_before = store2.count();
        let g_re = um2
            .stage(
                &mut store2,
                &mut disk,
                man(b"editor"),
                &[payload(b"main.bin", b"editor v1 payload")],
            )
            .unwrap();
        assert_eq!(
            g_re.payload[0], g1.payload[0],
            "content addressing is durable: same bytes, same block across a reboot"
        );
        // The re-install added only the new descriptor + COW dir block, not the
        // payload.
        assert_eq!(store2.count() - count_before, 2);
    }
}

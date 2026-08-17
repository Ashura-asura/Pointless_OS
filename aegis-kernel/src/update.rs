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
//!   entries `(name -> kind -> block id)`. Every mutation appends a NEW dir
//!   block; an id you already hold (a pre-activation `current`) reads the old
//!   target forever. Same semantics as the model's `FlatView`.
//!
//! **Phase Q (completion): the boot view is now hierarchical.** Entries carry
//! a kind byte (file vs dir); a dir entry points at another encoded dir block,
//! so the durable store the editor/browser/shell all share nests directories
//! exactly like the design doc's POSIX projection. Path-based operations
//! ([`BootView::mkdir_at`], [`BootView::create_file_at`],
//! [`BootView::list_entries`], [`BootView::read_file_at`]) resolve a
//! `&[Name]` path from the root and COW-propagate the new root up the
//! ancestor chain on mutation — the same commit-to-root discipline
//! `store::TreeView` already documents, now over the NVMe-backed view. The
//! editor's `memo.txt`, the update manager's `gen-N`/`current`, and the
//! shell's `ls`/`open`/`new` all operate at the root (empty path), unchanged.
//!
//! Honest limits (same discipline as `nvme_store`): blocks are single 512 B
//! sectors and the view indexes at most [`VIEW_MAX_FILES`] entries per
//! directory; the descriptor carries the generation number + package name only
//! (no signature — the model's signing chain stays out of scope here); health
//! is supplied by the caller ([`payloads_verify`] verifies every payload block
//! against the live disk). Directory depth is capped at [`MAX_DEPTH`], the
//! same bound the in-memory `store::TreeView` uses.

use crate::nvme_store::{BlockIo, Store};
use crate::store::{BlockId, Name, MAX_DEPTH, MAX_FILES};

/// Entry kind byte: a regular file.
pub const KIND_FILE: u8 = 0;
/// Entry kind byte: a directory (its id points at another encoded dir block).
pub const KIND_DIR: u8 = 1;

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
/// `count u16 LE` then per entry `name_len u8`, `kind u8`, `name`, `block id [u8; 32]`.
#[derive(Clone, Copy, Default)]
pub(crate) struct DirEntry {
    pub name: Name,
    pub kind: u8,
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
        if at + 2 + name.len() + 32 > DIR_BUF {
            return None;
        }
        out[at] = name.len() as u8;
        at += 1;
        out[at] = e.kind;
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
        let Some(&kind) = bytes.get(at) else { break };
        at += 1;
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
        out[written] = DirEntry { name, kind, id };
        written += 1;
    }
    written
}

/// Decode a dir block by id; an unreadable/missing block yields an empty table.
fn read_dir_block(
    store: &mut Store,
    io: &mut impl BlockIo,
    id: &BlockId,
) -> [DirEntry; VIEW_MAX_FILES] {
    let mut out = [DirEntry::default(); VIEW_MAX_FILES];
    let mut buf = [0u8; DIR_BUF];
    if let Some(n) = store.get(io, id, &mut buf) {
        decode_dir(&buf[..n], &mut out);
    }
    out
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

    /// Attach to an existing boot view by its durable dir id (Phase P: the
    /// editor anchors this id in the store header on first boot, then
    /// re-attaches to it after a reboot to reopen the same directory).
    pub fn at(dir: BlockId) -> BootView {
        BootView { dir }
    }

    pub fn dir_id(&self) -> BlockId {
        self.dir
    }

    fn read_dir(&self, store: &mut Store, io: &mut impl BlockIo) -> [DirEntry; VIEW_MAX_FILES] {
        read_dir_block(store, io, &self.dir)
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
        let Some(new_dir) = set_entry_block(store, io, self.dir, name, KIND_FILE, id) else {
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

    /// Walk `path` from the root, returning the final directory block plus the
    /// ancestor chain needed to COW-propagate a mutation back to the root.
    fn resolve(&self, store: &mut Store, io: &mut impl BlockIo, path: &[Name]) -> Option<Resolved> {
        let mut dir = self.dir;
        let mut levels = [(BlockId::default(), Name::default()); MAX_DEPTH];
        let mut nl = 0usize;
        for name in path.iter() {
            let entries = read_dir_block(store, io, &dir);
            let e = entries.iter().find(|e| e.name == *name)?;
            if e.kind != KIND_DIR {
                return None;
            }
            if nl >= MAX_DEPTH {
                return None;
            }
            levels[nl] = (dir, *name);
            nl += 1;
            dir = e.id;
        }
        Some(Resolved {
            parent: dir,
            levels,
            nlevels: nl,
        })
    }

    /// COW the subtree change `parent_new` (the rewritten final dir block) up
    /// the ancestor chain, returning the new root block id.
    fn commit_tree(
        store: &mut Store,
        io: &mut impl BlockIo,
        r: &Resolved,
        parent_new: BlockId,
    ) -> Option<BlockId> {
        let mut cur = parent_new;
        for i in (0..r.nlevels).rev() {
            let (dir, name) = r.levels[i];
            cur = rewrite_entry_block(store, io, dir, name, cur)?;
        }
        Some(cur)
    }

    /// Add `name -> (kind, id)` to the dir block `dir` (COW, no aliasing),
    /// returning the new dir block id.
    fn add_entry_block(
        store: &mut Store,
        io: &mut impl BlockIo,
        dir: BlockId,
        name: Name,
        kind: u8,
        id: BlockId,
    ) -> Option<BlockId> {
        let entries = read_dir_block(store, io, &dir);
        let mut out = [DirEntry::default(); VIEW_MAX_FILES];
        let mut n = 0usize;
        for e in entries.iter() {
            if e.name.as_slice().is_empty() {
                continue;
            }
            if e.name == name {
                return None;
            }
            out[n] = *e;
            n += 1;
        }
        if n >= VIEW_MAX_FILES {
            return None;
        }
        out[n] = DirEntry { name, kind, id };
        n += 1;
        let (enc, len) = encode_dir(&out[..n])?;
        store.put(io, &enc[..len])
    }

    /// The entries of the directory at `path` as `(name, kind)` pairs, decoded
    /// into `out`; returns how many (0 if the path does not resolve).
    pub fn list_entries(
        &self,
        store: &mut Store,
        io: &mut impl BlockIo,
        path: &[Name],
        out: &mut [(Name, u8); VIEW_MAX_FILES],
    ) -> usize {
        let Some(r) = self.resolve(store, io, path) else {
            return 0;
        };
        let entries = read_dir_block(store, io, &r.parent);
        let mut n = 0usize;
        for e in entries.iter() {
            if e.name.as_slice().is_empty() {
                continue;
            }
            out[n] = (e.name, e.kind);
            n += 1;
        }
        n
    }

    /// Read the bytes of the file `name` inside the directory at `path`.
    pub fn read_file_at(
        &self,
        store: &mut Store,
        io: &mut impl BlockIo,
        path: &[Name],
        name: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        let r = self.resolve(store, io, path)?;
        let entries = read_dir_block(store, io, &r.parent);
        let e = entries.iter().find(|e| e.name.matches(name))?;
        if e.kind != KIND_FILE {
            return None;
        }
        store.get(io, &e.id, out)
    }

    /// Create an empty directory `name` inside the directory at `path` (COW to
    /// root). Returns false if the path does not resolve, the name is taken, or
    /// the directory is full.
    pub fn mkdir_at(
        &mut self,
        store: &mut Store,
        io: &mut impl BlockIo,
        path: &[Name],
        name: &[u8],
    ) -> bool {
        if path.len() >= MAX_DEPTH {
            return false;
        }
        let Some(r) = self.resolve(store, io, path) else {
            return false;
        };
        let Some(cname) = Name::from_slice(name) else {
            return false;
        };
        let (empty, elen) = match encode_dir(&[]) {
            Some(x) => x,
            None => return false,
        };
        let Some(new_dir) = store.put(io, &empty[..elen]) else {
            return false;
        };
        let Some(parent_new) = Self::add_entry_block(store, io, r.parent, cname, KIND_DIR, new_dir)
        else {
            return false;
        };
        let Some(root_new) = Self::commit_tree(store, io, &r, parent_new) else {
            return false;
        };
        self.dir = root_new;
        true
    }

    /// Create a file `name` inside the directory at `path` holding `bytes`
    /// (COW to root). Returns the content block id, or None.
    pub fn create_file_at(
        &mut self,
        store: &mut Store,
        io: &mut impl BlockIo,
        path: &[Name],
        name: &[u8],
        bytes: &[u8],
    ) -> Option<BlockId> {
        let r = self.resolve(store, io, path)?;
        let cname = Name::from_slice(name)?;
        let id = store.put(io, bytes)?;
        let parent_new = Self::add_entry_block(store, io, r.parent, cname, KIND_FILE, id)?;
        let root_new = Self::commit_tree(store, io, &r, parent_new)?;
        self.dir = root_new;
        Some(id)
    }
}

/// A resolved path: the final directory block plus each ancestor `(dir, name)`
/// pair needed to COW-propagate a mutation up to the root.
struct Resolved {
    parent: BlockId,
    levels: [(BlockId, Name); MAX_DEPTH],
    nlevels: usize,
}

/// Replace the entry `name` in the dir block `dir` to point at `new_child`
/// (COW), returning the new dir block id.
fn rewrite_entry_block(
    store: &mut Store,
    io: &mut impl BlockIo,
    dir: BlockId,
    name: Name,
    new_child: BlockId,
) -> Option<BlockId> {
    let entries = read_dir_block(store, io, &dir);
    let mut out = [DirEntry::default(); VIEW_MAX_FILES];
    let mut n = 0usize;
    let mut done = false;
    for e in entries.iter() {
        if e.name.as_slice().is_empty() {
            continue;
        }
        if e.name == name && !done {
            out[n] = DirEntry {
                name,
                kind: e.kind,
                id: new_child,
            };
            done = true;
        } else {
            out[n] = *e;
        }
        n += 1;
    }
    if !done {
        return None;
    }
    let (enc, len) = encode_dir(&out[..n])?;
    store.put(io, &enc[..len])
}

/// Replace-or-add `name -> (kind, id)` in the dir block `dir` (COW),
/// returning the new dir block id. Unlike [`rewrite_entry_block`] this also
/// appends the entry when absent (the general write path, used by root
/// `set` and path-aware `write_file_at`).
fn set_entry_block(
    store: &mut Store,
    io: &mut impl BlockIo,
    dir: BlockId,
    name: Name,
    kind: u8,
    id: BlockId,
) -> Option<BlockId> {
    let entries = read_dir_block(store, io, &dir);
    let mut out = [DirEntry::default(); VIEW_MAX_FILES];
    let mut n = 0usize;
    let mut replaced = false;
    for e in entries.iter() {
        if e.name.as_slice().is_empty() {
            continue;
        }
        if e.name.matches(name.as_slice()) && !replaced {
            out[n] = DirEntry { name, kind, id };
            replaced = true;
        } else {
            out[n] = *e;
        }
        n += 1;
    }
    if !replaced {
        if n >= VIEW_MAX_FILES {
            return None;
        }
        out[n] = DirEntry { name, kind, id };
        n += 1;
    }
    let (enc, len) = encode_dir(&out[..n])?;
    store.put(io, &enc[..len])
}

/// Write `bytes` to the file `name` inside the directory at `path` (COW to
/// root) — replace-or-add, so this is the save path for a file the editor
/// opened from a subdirectory, not just the root. Returns the content block
/// id.
pub fn write_file_at<IO: BlockIo>(
    view: &mut BootView,
    store: &mut Store,
    io: &mut IO,
    path: &[Name],
    name: &[u8],
    bytes: &[u8],
) -> Option<BlockId> {
    let r = view.resolve(store, io, path)?;
    let cname = Name::from_slice(name)?;
    let id = store.put(io, bytes)?;
    let parent_new = set_entry_block(store, io, r.parent, cname, KIND_FILE, id)?;
    let root_new = BootView::commit_tree(store, io, &r, parent_new)?;
    view.dir = root_new;
    Some(id)
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
            kind: KIND_FILE,
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
        assert_eq!(out[0].kind, KIND_FILE);
    }

    #[test]
    fn boot_view_hierarchy_is_durable_and_cow() {
        let _g = crate::kernel_state_guard();
        let (mut disk, mut store, _um) = world();
        let mut view = BootView::create(&mut store, &mut disk).unwrap();
        // mkdir at root.
        assert!(view.mkdir_at(&mut store, &mut disk, &[], b"docs"));
        // A file inside docs (path depth 1).
        let sub = [Name::from_slice(b"docs").unwrap()];
        assert!(view
            .create_file_at(&mut store, &mut disk, &sub, b"readme.txt", b"hi")
            .is_some());
        // list root: docs shows up as a dir.
        let mut root = [(Name::default(), 0u8); VIEW_MAX_FILES];
        assert_eq!(view.list_entries(&mut store, &mut disk, &[], &mut root), 1);
        assert_eq!(root[0], (Name::from_slice(b"docs").unwrap(), KIND_DIR));
        // list inside docs: readme.txt shows up as a file.
        let mut inside = [(Name::default(), 0u8); VIEW_MAX_FILES];
        assert_eq!(
            view.list_entries(&mut store, &mut disk, &sub, &mut inside),
            1
        );
        assert_eq!(
            inside[0],
            (Name::from_slice(b"readme.txt").unwrap(), KIND_FILE)
        );
        // read through the path.
        let mut buf = [0u8; SECTOR];
        assert_eq!(
            view.read_file_at(&mut store, &mut disk, &sub, b"readme.txt", &mut buf)
                .unwrap(),
            2
        );
        assert_eq!(&buf[..2], b"hi");
        // A file deep in the tree: docs/logs/today.
        let logs = [
            Name::from_slice(b"docs").unwrap(),
            Name::from_slice(b"logs").unwrap(),
        ];
        assert!(view.mkdir_at(&mut store, &mut disk, &sub, b"logs"));
        assert!(view
            .create_file_at(&mut store, &mut disk, &logs, b"today", b"ok")
            .is_some());
        // Reading via the deep path resolves.
        assert_eq!(
            view.read_file_at(&mut store, &mut disk, &logs, b"today", &mut buf)
                .unwrap(),
            2
        );
        // Mutating a subdir must not clobber the sibling at root (COW root).
        assert_eq!(
            view.list_entries(
                &mut store,
                &mut disk,
                &[],
                &mut [(Name::default(), 0); VIEW_MAX_FILES]
            ),
            1
        );
        // The path resolving to a file (not a dir) must not resolve.
        let through_file = [
            Name::from_slice(b"docs").unwrap(),
            Name::from_slice(b"readme.txt").unwrap(),
        ];
        assert!(!view.mkdir_at(&mut store, &mut disk, &through_file, b"oops"));
        // COW: the pre-mutation root id still reads only the old table.
        let pre = view.dir_id();
        assert!(view.mkdir_at(&mut store, &mut disk, &[], b"images"));
        let old = BootView::at(pre);
        let mut oldroot = [(Name::default(), 0u8); VIEW_MAX_FILES];
        assert_eq!(
            old.list_entries(&mut store, &mut disk, &[], &mut oldroot),
            1
        );
        let mut newroot = [(Name::default(), 0u8); VIEW_MAX_FILES];
        assert_eq!(
            view.list_entries(&mut store, &mut disk, &[], &mut newroot),
            2
        );
    }

    #[test]
    fn staging_a_candidate_does_not_disturb_the_boot_target() {
        let _g = crate::kernel_state_guard();
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
        let _g = crate::kernel_state_guard();
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
        let _g = crate::kernel_state_guard();
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
        let _g = crate::kernel_state_guard();
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
        let _g = crate::kernel_state_guard();
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
        let _g = crate::kernel_state_guard();
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
        let _g = crate::kernel_state_guard();
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
        let mut um2 = UpdateManager::attach(&mut store2, &mut disk, BootView::at(boot_dir));
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

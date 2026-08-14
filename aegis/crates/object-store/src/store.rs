//! The object store (design doc §8 Storage + §10 [CLOSED]).
//!
//! Claims made executable here:
//! - Ground truth is content-addressed, immutable blocks; identical bytes are the
//!   same block, stored once (dedup). Integrity is the SHA-256 content hash itself
//!   (self-contained implementation in this crate, pinned against known vectors).
//! - Blocks are capability-addressed kernel objects: knowing a block's id grants
//!   nothing — reading requires a region cap in *your* CSpace, granted by the store
//!   (kernel enforcement, already verified). That is the "capability address".
//! - Mutable data is a copy-on-write layer over the immutable blocks: a write never
//!   mutates an existing block or node region; it creates new ones. A reader holding
//!   an old node keeps seeing the old version.
//! - Every commit appends to a write-ahead log. The relationship index (§8) is a
//!   *consumer* of that log, never a participant: no commit signature has an index
//!   parameter, no commit touches index state, index failure or lag cannot affect
//!   storage, and the index is fully rebuildable from the log.
//!
//! Known simplifications (honest): blocks are single kernel regions (no multi-block
//! files), the WAL is in-memory (there is no disk in the prototype), the POSIX view
//! is a flat namespace, and "durable" means "survives while the kernel process
//! lives" — real durability needs a block device (Phase 3/4).

use capability_core::{CapHandle, Kernel, ObjectId, Rights, TaskHandle};
use std::collections::HashMap;

pub use crate::sha256::sha256;

pub type BlockId = [u8; 32];

/// One recorded mutation of the store. The only thing the index may consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalOp {
    /// A new immutable block entered the store.
    Put { id: BlockId, len: u64 },
    /// A COW version node now derives from another node (causal/derivation edge).
    Link { child: u64, parent: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRec {
    pub seq: u64,
    pub op: WalOp,
}

/// The write-ahead log. Append-only in the store; consumed asynchronously, after
/// the fact, by the index. The store never reads it to serve reads or commits.
#[derive(Debug, Default)]
pub struct Wal {
    recs: Vec<WalRec>,
}

impl Wal {
    pub fn len(&self) -> usize {
        self.recs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }

    pub fn recs(&self) -> impl Iterator<Item = &WalRec> {
        self.recs.iter()
    }

    #[cfg(test)]
    pub(crate) fn push(&mut self, rec: WalRec) {
        self.recs.push(rec);
    }
}

struct BlockLoc {
    obj: ObjectId,
    service_cap: CapHandle,
    len: u64,
    refs: u64,
}

/// The storage service. All kernel access happens under one service identity
/// holding one Creator cap; consumers never create kernel objects themselves.
pub struct Store {
    service: TaskHandle,
    creator: CapHandle,
    blocks: HashMap<BlockId, BlockLoc>,
    nodes: HashMap<u64, CapHandle>,
    wal: Wal,
    seq: u64,
}

// Node encoding: a version node region holds [flags u8][prev: u64 LE if bit0]
// [block hash 32B if bit1]. Nodes and blocks are regions created once and never
// mutated (COW); a node naming a block is that version of the object.
fn encode_node(prev: Option<u64>, block: Option<BlockId>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + 32);
    let mut flags = 0u8;
    if prev.is_some() {
        flags |= 1;
    }
    if block.is_some() {
        flags |= 2;
    }
    out.push(flags);
    if let Some(p) = prev {
        out.extend_from_slice(&p.to_le_bytes());
    }
    if let Some(b) = block {
        out.extend_from_slice(&b);
    }
    out
}

fn decode_node(bytes: &[u8]) -> (Option<u64>, Option<BlockId>) {
    let flags = bytes.first().copied().unwrap_or(0);
    let mut at = 1usize;
    let prev = if flags & 1 != 0 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[at..at + 8]);
        at += 8;
        Some(u64::from_le_bytes(b))
    } else {
        None
    };
    let block = if flags & 2 != 0 {
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes[at..at + 32]);
        Some(b)
    } else {
        None
    };
    (prev, block)
}

fn encode_entries(entries: &[(String, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (name, node) in entries {
        let nb = name.as_bytes();
        out.extend_from_slice(&(nb.len() as u32).to_le_bytes());
        out.extend_from_slice(nb);
        out.extend_from_slice(&node.to_le_bytes());
    }
    out
}

fn decode_entries(bytes: &[u8]) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    if bytes.len() < 4 {
        return out;
    }
    let mut at = 0usize;
    let Some(count_bytes) = bytes.get(at..at + 4) else {
        return out;
    };
    let count = u32::from_le_bytes(count_bytes.try_into().unwrap()) as usize;
    at += 4;
    for _ in 0..count {
        let Some(nlen_bytes) = bytes.get(at..at + 4) else {
            break;
        };
        let nlen = u32::from_le_bytes(nlen_bytes.try_into().unwrap()) as usize;
        at += 4;
        let Some(name_bytes) = bytes.get(at..at + nlen) else {
            break;
        };
        let Ok(name) = String::from_utf8(name_bytes.to_vec()) else {
            break;
        };
        at += nlen;
        let Some(node_bytes) = bytes.get(at..at + 8) else {
            break;
        };
        let node = u64::from_le_bytes(node_bytes.try_into().unwrap());
        at += 8;
        out.push((name, node));
    }
    out
}

impl Store {
    pub fn new(service: TaskHandle, creator: CapHandle) -> Store {
        Store {
            service,
            creator,
            blocks: HashMap::new(),
            nodes: HashMap::new(),
            wal: Wal::default(),
            seq: 0,
        }
    }

    pub fn wal(&self) -> &Wal {
        &self.wal
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Commit `data` as a new immutable block. Content-addressed: identical bytes
    /// are the same block, stored once. The signature is the §10 [CLOSED] contract:
    /// it mentions no index — no way for a write to await, block on, or depend on
    /// one. `None` only if the kernel refused creation (e.g. creator revoked).
    pub fn commit(&mut self, k: &mut Kernel, data: &[u8]) -> Option<BlockId> {
        let id = sha256(data);
        if let Some(loc) = self.blocks.get_mut(&id) {
            loc.refs += 1;
            return Some(id);
        }
        let cap = k
            .create_mem(self.service, self.creator, data.to_vec())
            .ok()?;
        let obj = k.cap_info(self.service, cap).ok()?.obj;
        self.blocks.insert(
            id,
            BlockLoc {
                obj,
                service_cap: cap,
                len: data.len() as u64,
                refs: 1,
            },
        );
        self.seq += 1;
        self.wal.recs.push(WalRec {
            seq: self.seq,
            op: WalOp::Put {
                id,
                len: data.len() as u64,
            },
        });
        Some(id)
    }

    pub fn block_obj(&self, id: &BlockId) -> Option<ObjectId> {
        self.blocks.get(id).map(|l| l.obj)
    }

    pub fn block_len(&self, id: &BlockId) -> Option<u64> {
        self.blocks.get(id).map(|l| l.len)
    }

    /// The store's own cap for a block's region, in the store's CSpace. A caller
    /// holding it (the store's host) may derive narrower copies; delivery under
    /// an external grant anchor is the packager's job (§8: payload caps die with
    /// the install, not with a bare `grant`).
    pub fn block_cap(&self, id: &BlockId) -> Option<CapHandle> {
        self.blocks.get(id).map(|l| l.service_cap)
    }

    /// The capability address itself: grant the recipient READ of the block's
    /// region, placed in the recipient's own CSpace. `recipient_name` is a cap in
    /// the *service's* CSpace naming the recipient task (where the service can see
    /// it — grant resolves all handles against the grantor's table). Returns the
    /// recipient's granted slot. Unknown block or refused authority: `None`.
    pub fn grant_read(
        &mut self,
        k: &mut Kernel,
        recipient_task: TaskHandle,
        recipient_name: CapHandle,
        id: &BlockId,
    ) -> Option<u32> {
        let loc = self.blocks.get(id)?;
        k.grant(
            self.service,
            loc.service_cap,
            recipient_name,
            Rights::READ,
            None,
        )
        .ok()?;
        for slot in 0..256u32 {
            if let Ok(info) = k.cap_info(recipient_task, CapHandle(slot)) {
                if info.obj == loc.obj {
                    return Some(slot);
                }
            }
        }
        None
    }

    /// Create a fresh, empty COW object. Returns its head node's object id.
    pub fn new_object(&mut self, k: &mut Kernel) -> Option<u64> {
        self.create_node(k, None, None)
    }

    fn create_node(
        &mut self,
        k: &mut Kernel,
        prev: Option<u64>,
        block: Option<BlockId>,
    ) -> Option<u64> {
        let cap = k
            .create_mem(self.service, self.creator, encode_node(prev, block))
            .ok()?;
        let obj = k.cap_info(self.service, cap).ok()?.obj;
        let id = obj.as_u64();
        self.nodes.insert(id, cap);
        Some(id)
    }

    /// The bytes of the version that `node` names — snapshots are version-stable
    /// because no region is ever mutated: whatever node id you hold, you read that
    /// version forever.
    pub fn snapshot(&mut self, k: &mut Kernel, node: u64) -> Option<Vec<u8>> {
        let cap = *self.nodes.get(&node)?;
        let len = k.mem_len(self.service, cap).ok()?;
        let bytes = k.mem_read(self.service, cap, 0, len).ok()?;
        let (_, block) = decode_node(&bytes);
        match block {
            None => Some(Vec::new()),
            Some(id) => {
                let loc = self.blocks.get(&id)?;
                k.mem_read(self.service, loc.service_cap, 0, loc.len as usize)
                    .ok()
            }
        }
    }

    /// COW write: a new block plus a new node derived from `cur`; nothing is
    /// mutated. Returns the new head node id (older nodes stay readable forever).
    pub fn write_version(&mut self, k: &mut Kernel, cur: u64, data: &[u8]) -> Option<u64> {
        let block = self.commit(k, data)?;
        let next = self.create_node(k, Some(cur), Some(block))?;
        self.seq += 1;
        self.wal.recs.push(WalRec {
            seq: self.seq,
            op: WalOp::Link {
                child: next,
                parent: cur,
            },
        });
        Some(next)
    }
}

/// The POSIX file-view projection (design doc §8): a flat namespace over store
/// objects. Files are nothing but store objects; there is exactly one place bytes
/// live. The "directory" is itself a COW store object.
pub struct FlatView {
    dir: u64,
}

impl FlatView {
    pub fn new(k: &mut Kernel, store: &mut Store) -> Option<FlatView> {
        store.new_object(k).map(|dir| FlatView { dir })
    }

    fn read_dir(&mut self, k: &mut Kernel, store: &mut Store) -> Vec<(String, u64)> {
        store
            .snapshot(k, self.dir)
            .map(|b| decode_entries(&b))
            .unwrap_or_default()
    }

    fn write_dir(&mut self, k: &mut Kernel, store: &mut Store, entries: &[(String, u64)]) -> bool {
        match store.write_version(k, self.dir, &encode_entries(entries)) {
            Some(next) => {
                self.dir = next;
                true
            }
            None => false,
        }
    }

    pub fn list(&mut self, k: &mut Kernel, store: &mut Store) -> Vec<String> {
        self.read_dir(k, store)
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    }

    pub fn create_file(&mut self, k: &mut Kernel, store: &mut Store, name: &str) -> bool {
        let mut entries = self.read_dir(k, store);
        if entries.iter().any(|(n, _)| n == name) {
            return false;
        }
        let node = match store.new_object(k) {
            Some(n) => n,
            None => return false,
        };
        entries.push((name.to_string(), node));
        self.write_dir(k, store, &entries)
    }

    pub fn write_file(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        name: &str,
        data: &[u8],
    ) -> bool {
        let mut entries = self.read_dir(k, store);
        let pos = match entries.iter().position(|(n, _)| n == name) {
            Some(p) => p,
            None => return false,
        };
        let next = match store.write_version(k, entries[pos].1, data) {
            Some(n) => n,
            None => return false,
        };
        entries[pos].1 = next;
        self.write_dir(k, store, &entries)
    }

    pub fn read_file(&mut self, k: &mut Kernel, store: &mut Store, name: &str) -> Option<Vec<u8>> {
        let entries = self.read_dir(k, store);
        let node = entries.into_iter().find(|(n, _)| n == name)?.1;
        store.snapshot(k, node)
    }

    pub fn delete_file(&mut self, k: &mut Kernel, store: &mut Store, name: &str) -> bool {
        let mut entries = self.read_dir(k, store);
        if !entries.iter().any(|(n, _)| n == name) {
            return false;
        }
        entries.retain(|(n, _)| n != name);
        self.write_dir(k, store, &entries)
    }
}

// ---------------------------------------------------------------------------
// TreeView: the full POSIX file-tree projection (design doc §8) — the
// hierarchical upgrade over `FlatView`'s flat namespace. Directories and files
// are nothing but store objects; the root is a COW dir node, every
// subdirectory is a COW dir node, every file is a COW file node. A mutation
// commits new versions of the target's parent dir AND of every dir up to the
// root (path persistence); a node id you hold reads that version forever.
//
// Paths are absolute (`/a/b/c.txt`) or relative to the working directory; `.`
// and `..` resolve; the cwd is tracked as a path (re-resolved from the root,
// since node ids move under COW). Entries carry POSIX mode/uid as projection
// metadata; the authority that actually gates access stays capability-shaped
// (region caps), per the design-doc position that permission bits are
// subsumed by capabilities.
// ---------------------------------------------------------------------------

// (The kernel's `TreeView` enforces an in-kernel `MAX_DEPTH` bound; this std
// mirror is unbounded, which is the honest divergence between an implementation
// ceiling and a design's semantics.)

/// POSIX-compat mode metadata for a regular file (S_IFREG | 0644).
pub const MODE_FILE: u16 = 0o100644;
/// POSIX-compat mode metadata for a directory (S_IFDIR | 0755).
pub const MODE_DIR: u16 = 0o040755;

/// POSIX entry kind in the hierarchical view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
}

/// One entry of the hierarchical POSIX projection: a name, kind, mode/uid
/// metadata, and the store-node it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PEntry {
    pub name: String,
    pub kind: EntryKind,
    pub mode: u16,
    pub uid: u32,
    pub node: u64,
}

fn encode_posix_entries(entries: &[PEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let name = e.name.as_bytes();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name);
        out.push(match e.kind {
            EntryKind::File => 0,
            EntryKind::Dir => 1,
        });
        out.extend_from_slice(&e.mode.to_le_bytes());
        out.extend_from_slice(&e.uid.to_le_bytes());
        out.extend_from_slice(&e.node.to_le_bytes());
    }
    out
}

fn decode_posix_entries(bytes: &[u8]) -> Vec<PEntry> {
    let mut out = Vec::new();
    if bytes.len() < 4 {
        return out;
    }
    let mut at = 0usize;
    let count = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
    at += 4;
    for _ in 0..count {
        let Some(nlen_bytes) = bytes.get(at..at + 4) else {
            break;
        };
        let nlen = u32::from_le_bytes(nlen_bytes.try_into().unwrap()) as usize;
        at += 4;
        let Some(name_bytes) = bytes.get(at..at + nlen) else {
            break;
        };
        let Ok(name) = String::from_utf8(name_bytes.to_vec()) else {
            break;
        };
        at += nlen;
        let Some(&kind_byte) = bytes.get(at) else {
            break;
        };
        at += 1;
        let Some(mode_bytes) = bytes.get(at..at + 2) else {
            break;
        };
        let mode = u16::from_le_bytes(mode_bytes.try_into().unwrap());
        at += 2;
        let Some(uid_bytes) = bytes.get(at..at + 4) else {
            break;
        };
        let uid = u32::from_le_bytes(uid_bytes.try_into().unwrap());
        at += 4;
        let Some(node_bytes) = bytes.get(at..at + 8) else {
            break;
        };
        let node = u64::from_le_bytes(node_bytes.try_into().unwrap());
        at += 8;
        out.push(PEntry {
            name,
            kind: if kind_byte == 1 {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            mode,
            uid,
            node,
        });
    }
    out
}

/// Split `path` on `/`, dropping empty segments. `.`/`..` resolve later.
fn split_path(path: &str) -> (bool, Vec<String>) {
    let absolute = path.starts_with('/');
    let comps = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    (absolute, comps)
}

/// Apply `.` (skip) and `..` (pop) over the full component list.
fn normalize(comps: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for c in comps {
        if c == "." {
            continue;
        }
        if c == ".." {
            out.pop();
            continue;
        }
        out.push(c);
    }
    out
}

/// The hierarchical POSIX projection over the store.
pub struct TreeView {
    root: u64,
    cwd: Vec<String>,
}

struct Resolved {
    parent: u64,
    target: PEntry,
    found: bool,
    /// (dir node, child name) for every dir descended through, root-down.
    levels: Vec<(u64, String)>,
}

impl TreeView {
    pub fn new(k: &mut Kernel, store: &mut Store) -> Option<TreeView> {
        store.new_object(k).map(|root| TreeView {
            root,
            cwd: Vec::new(),
        })
    }

    pub fn root(&self) -> u64 {
        self.root
    }

    fn read_dir(&mut self, k: &mut Kernel, store: &mut Store, node: u64) -> Option<Vec<PEntry>> {
        let bytes = store.snapshot(k, node)?;
        Some(decode_posix_entries(&bytes))
    }

    fn resolve_components(&self, path: &str) -> Vec<String> {
        let (abs, raw) = split_path(path);
        let mut full = Vec::new();
        if !abs {
            full.extend(self.cwd.iter().cloned());
        }
        full.extend(raw);
        normalize(full)
    }

    fn resolve(&mut self, k: &mut Kernel, store: &mut Store, path: &str) -> Option<Resolved> {
        let comps = self.resolve_components(path);
        let mut dir = self.root;
        let mut levels = Vec::new();
        for (i, name) in comps.iter().enumerate() {
            let entries = self.read_dir(k, store, dir)?;
            if i == comps.len() - 1 {
                let pos = entries.iter().position(|e| &e.name == name);
                let target = pos.map(|p| entries[p].clone()).unwrap_or(PEntry {
                    name: name.clone(),
                    kind: EntryKind::File,
                    mode: 0,
                    uid: 0,
                    node: 0,
                });
                return Some(Resolved {
                    parent: dir,
                    target,
                    found: pos.is_some(),
                    levels,
                });
            }
            let sub = entries.iter().find(|e| &e.name == name)?;
            if sub.kind != EntryKind::Dir {
                return None;
            }
            levels.push((dir, name.clone()));
            dir = sub.node;
        }
        let target = PEntry {
            name: String::new(),
            kind: EntryKind::Dir,
            mode: MODE_DIR,
            uid: 0,
            node: dir,
        };
        Some(Resolved {
            parent: dir,
            target,
            found: true,
            levels,
        })
    }

    /// The working directory node, re-resolved from the root.
    pub fn cwd(&mut self, k: &mut Kernel, store: &mut Store) -> Option<u64> {
        let mut dir = self.root;
        let cwd = self.cwd.clone();
        for name in &cwd {
            let entries = self.read_dir(k, store, dir)?;
            let sub = entries.iter().find(|e| &e.name == name)?;
            if sub.kind != EntryKind::Dir {
                return None;
            }
            dir = sub.node;
        }
        Some(dir)
    }

    fn rewrite_entry(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        dir: u64,
        name: &str,
        node: u64,
    ) -> Option<u64> {
        let mut entries = self.read_dir(k, store, dir)?;
        let pos = entries.iter().position(|e| e.name == name)?;
        entries[pos].node = node;
        store.write_version(k, dir, &encode_posix_entries(&entries))
    }

    fn add_entry(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        dir: u64,
        entry: PEntry,
    ) -> Option<u64> {
        let mut entries = self.read_dir(k, store, dir)?;
        if entries.iter().any(|e| e.name == entry.name) {
            return None;
        }
        entries.push(entry);
        store.write_version(k, dir, &encode_posix_entries(&entries))
    }

    fn remove_entry(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        dir: u64,
        name: &str,
    ) -> Option<u64> {
        let mut entries = self.read_dir(k, store, dir)?;
        let pos = entries.iter().position(|e| e.name == name)?;
        entries.remove(pos);
        store.write_version(k, dir, &encode_posix_entries(&entries))
    }

    /// Install a mutated parent dir into the tree, committing new versions of
    /// every dir on the root→parent path. Returns the new root node id (the
    /// old root keeps reading the old tree — COW all the way up).
    fn commit_tree(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        parent_new: u64,
        levels: &[(u64, String)],
    ) -> Option<u64> {
        if levels.is_empty() {
            return Some(parent_new);
        }
        let mut cur = parent_new;
        for (dir, name) in levels.iter().rev() {
            cur = self.rewrite_entry(k, store, *dir, name, cur)?;
        }
        Some(cur)
    }

    fn commit(&mut self, k: &mut Kernel, store: &mut Store, parent_new: u64, r: &Resolved) -> bool {
        match self.commit_tree(k, store, parent_new, &r.levels) {
            Some(new_root) => {
                self.root = new_root;
                true
            }
            None => false,
        }
    }

    pub fn cd(&mut self, k: &mut Kernel, store: &mut Store, path: &str) -> bool {
        let comps = self.resolve_components(path);
        let mut dir = self.root;
        for name in &comps {
            let entries = self.read_dir(k, store, dir).unwrap_or_default();
            let Some(sub) = entries.iter().find(|e| &e.name == name) else {
                return false;
            };
            if sub.kind != EntryKind::Dir {
                return false;
            }
            dir = sub.node;
        }
        self.cwd = comps;
        true
    }

    pub fn mkdir(&mut self, k: &mut Kernel, store: &mut Store, path: &str, mode: u16) -> bool {
        let Some(r) = self.resolve(k, store, path) else {
            return false;
        };
        if r.found {
            return false;
        }
        let node = match store.new_object(k) {
            Some(n) => n,
            None => return false,
        };
        let parent_new = match self.add_entry(
            k,
            store,
            r.parent,
            PEntry {
                name: r.target.name.clone(),
                kind: EntryKind::Dir,
                mode,
                uid: 0,
                node,
            },
        ) {
            Some(n) => n,
            None => return false,
        };
        self.commit(k, store, parent_new, &r)
    }

    pub fn create_file(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        path: &str,
        mode: u16,
    ) -> bool {
        let Some(r) = self.resolve(k, store, path) else {
            return false;
        };
        if r.found {
            return false;
        }
        let node = match store.new_object(k) {
            Some(n) => n,
            None => return false,
        };
        let parent_new = match self.add_entry(
            k,
            store,
            r.parent,
            PEntry {
                name: r.target.name.clone(),
                kind: EntryKind::File,
                mode,
                uid: 0,
                node,
            },
        ) {
            Some(n) => n,
            None => return false,
        };
        self.commit(k, store, parent_new, &r)
    }

    pub fn write_file(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        path: &str,
        data: &[u8],
    ) -> bool {
        let Some(r) = self.resolve(k, store, path) else {
            return false;
        };
        if !r.found || r.target.kind != EntryKind::File {
            return false;
        }
        let file_new = match store.write_version(k, r.target.node, data) {
            Some(n) => n,
            None => return false,
        };
        let parent_new = match self.rewrite_entry(k, store, r.parent, &r.target.name, file_new) {
            Some(n) => n,
            None => return false,
        };
        self.commit(k, store, parent_new, &r)
    }

    pub fn read_file(&mut self, k: &mut Kernel, store: &mut Store, path: &str) -> Option<Vec<u8>> {
        let r = self.resolve(k, store, path)?;
        if !r.found || r.target.kind != EntryKind::File {
            return None;
        }
        store.snapshot(k, r.target.node)
    }

    pub fn node_of(&mut self, k: &mut Kernel, store: &mut Store, path: &str) -> Option<u64> {
        let r = self.resolve(k, store, path)?;
        if !r.found {
            return None;
        }
        Some(r.target.node)
    }

    /// Entries of the *historical* dir node `node` (a node id from an earlier
    /// `root()`), decoded exactly as live dirs — version-stable COW.
    pub fn snapshot_dir(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        node: u64,
    ) -> Option<Vec<PEntry>> {
        self.read_dir(k, store, node)
    }

    pub fn list(&mut self, k: &mut Kernel, store: &mut Store, path: &str) -> Option<Vec<PEntry>> {
        let r = self.resolve(k, store, path)?;
        if r.target.kind != EntryKind::Dir {
            return None;
        }
        self.read_dir(k, store, r.target.node)
    }

    pub fn unlink(&mut self, k: &mut Kernel, store: &mut Store, path: &str) -> bool {
        let Some(r) = self.resolve(k, store, path) else {
            return false;
        };
        if !r.found || r.target.kind != EntryKind::File {
            return false;
        }
        let parent_new = match self.remove_entry(k, store, r.parent, &r.target.name) {
            Some(n) => n,
            None => return false,
        };
        self.commit(k, store, parent_new, &r)
    }

    pub fn rmdir(&mut self, k: &mut Kernel, store: &mut Store, path: &str) -> bool {
        let Some(r) = self.resolve(k, store, path) else {
            return false;
        };
        if !r.found || r.target.kind != EntryKind::Dir {
            return false;
        }
        if r.target.node == self.root {
            return false;
        }
        if !self
            .read_dir(k, store, r.target.node)
            .unwrap_or_default()
            .is_empty()
        {
            return false;
        }
        let parent_new = match self.remove_entry(k, store, r.parent, &r.target.name) {
            Some(n) => n,
            None => return false,
        };
        self.commit(k, store, parent_new, &r)
    }

    /// `(kind, mode, uid, size)` where size is bytes for a file and entry
    /// count for a directory.
    pub fn stat(
        &mut self,
        k: &mut Kernel,
        store: &mut Store,
        path: &str,
    ) -> Option<(EntryKind, u16, u32, usize)> {
        let r = self.resolve(k, store, path)?;
        if !r.found {
            return None;
        }
        match r.target.kind {
            EntryKind::File => {
                let size = store.snapshot(k, r.target.node)?.len();
                Some((EntryKind::File, r.target.mode, r.target.uid, size))
            }
            EntryKind::Dir => {
                let count = self.read_dir(k, store, r.target.node)?.len();
                Some((EntryKind::Dir, r.target.mode, r.target.uid, count))
            }
        }
    }
}

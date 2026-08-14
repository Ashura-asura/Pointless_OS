//! Capability-addressed object store (Phase 4): the kernel-side close contract
//! of the design doc §8 Storage + §10 [CLOSED].
//!
//! Claims made executable here, mirroring the `object-store` model crate but
//! over the real kernel's region table and capability gates:
//! - Ground truth is content-addressed, immutable blocks; identical bytes are
//!   the same block, stored once (dedup). Integrity is the SHA-256 content hash
//!   itself (self-contained implementation in this module, pinned against the
//!   FIPS 180-4 vectors).
//! - Blocks are capability-addressed kernel `MemRegion`s: knowing a block's
//!   hash grants nothing — reading requires a region cap in *your* CSpace.
//!   `grant_read` installs a narrowed READ-only copy of the block's region cap
//!   into the recipient's table; the ordinary `mem::mem_read` gate then serves
//!   the bytes and `mem::mem_write` refuses (the granted cap holds READ only).
//! - Mutable data is a copy-on-write layer over the immutable blocks: a write
//!   never mutates an existing block or node region; it creates new ones. A
//!   node id you already hold reads that version forever.
//! - Every commit appends to a write-ahead log. The relationship index (§8) is
//!   a *consumer* of that log, never a participant: the commit signatures
//!   (`commit`, `write_version`) mention no index — no commit can await, block
//!   on, or depend on one — and the index is fully rebuildable from the log.
//!
//! Honest limits: this is a kernel-resident service with a fixed in-kernel byte
//! arena (block/node contents live in kernel memory, not on a block device —
//! the NVMe/FAT path of Phase 3 is a separate driver, not wired to this store);
//! the region table and arena are bounded (`MAX_REGIONS`, `ARENA_BYTES`); the
//! POSIX view is hierarchical (`TreeView`: nested directories, path resolution,
//! mode/uid metadata) but still bounded (`MAX_DEPTH`, `MAX_FILES` per dir) and
//! has no symlinks or hard links; permission *bits* are projection metadata —
//! the authority that gates access is capability-shaped, so the view does not
//! re-enforce ACLs (the design doc subsumes them under capabilities); the WAL
//! is in-memory — "durable" means "survives while the kernel process lives",
//! real durability needs the block device (Phase 4's own roadmap note).
//!
//! Contract tests exercise the gate + COW + WAL/index logic in-process, binding
//! region records to real in-test memory (the frame allocator has no pool in
//! the test host, so real-frame allocation is proven by the live boot, not
//! here).

use crate::cap::{Cap, CapSlot, Rights};
use crate::mem;

pub const NAME_BYTES: usize = 32;
pub const MAX_FILES: usize = 8;
pub const MAX_BLOCKS: usize = 48;
pub const MAX_NODES: usize = 48;
pub const MAX_WAL: usize = 128;
const ENTRY_BUF: usize = 1024;

/// Maximum path depth (components) in the hierarchical POSIX view. The root
/// is depth 0, so `/a/b/c.txt` is 3 components.
pub const MAX_DEPTH: usize = 8;

/// POSIX-compat mode metadata for a regular file (S_IFREG | 0644).
pub const MODE_FILE: u16 = 0o100644;
/// POSIX-compat mode metadata for a directory (S_IFDIR | 0755).
pub const MODE_DIR: u16 = 0o040755;

/// 32-byte content hash; a block's identity and its integrity check combined.
pub type BlockId = [u8; 32];

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), no allocation, no dependencies.
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn compress(h: &mut [u32; 8], block: &[u8; 64], w: &mut [u32; 64]) {
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Hash `data` and return the 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut w = [0u32; 64];
    let mut block = [0u8; 64];
    let mut pad = [0u8; 64];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut at = 0usize;
    while at + 64 <= data.len() {
        block.copy_from_slice(&data[at..at + 64]);
        compress(&mut h, &block, &mut w);
        at += 64;
    }

    // Final block: remaining bytes + 0x80 + zeros (+ length, possibly in a
    // second block when the tail overflows the 8-byte length field).
    let rem = data.len() - at;
    pad[..rem].copy_from_slice(&data[at..]);
    pad[rem] = 0x80;
    if rem + 1 + 8 > 64 {
        compress(&mut h, &pad, &mut w);
        pad = [0u8; 64];
    }
    pad[56..64].copy_from_slice(&bit_len.to_be_bytes());
    compress(&mut h, &pad, &mut w);

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Write-ahead log.
// ---------------------------------------------------------------------------

/// One recorded mutation of the store. The only thing the index may consume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalOp {
    /// A new immutable block entered the store.
    Put { id: BlockId, len: u64 },
    /// A COW version node now derives from another node (causal/derivation edge).
    Link { child: u64, parent: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalRec {
    pub seq: u64,
    pub op: WalOp,
}

/// The write-ahead log. Append-only in the store; consumed asynchronously,
/// after the fact, by the index. The store never reads it to serve reads or
/// commits.
#[derive(Debug)]
pub struct Wal {
    recs: [Option<WalRec>; MAX_WAL],
    len: usize,
}

impl Wal {
    fn new() -> Wal {
        Wal {
            recs: [None; MAX_WAL],
            len: 0,
        }
    }

    /// Records currently in the log.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Record `i` (`0..len`), or `None` past the end.
    pub fn rec(&self, i: usize) -> Option<WalRec> {
        self.recs.get(i).copied().flatten()
    }

    fn push(&mut self, rec: WalRec) -> bool {
        if self.len >= MAX_WAL {
            return false;
        }
        self.recs[self.len] = Some(rec);
        self.len += 1;
        true
    }
}

// ---------------------------------------------------------------------------
// The store's byte arena: the kernel-resident memory that backs block/node
// contents. Real bytes the kernel addresses; binding a block to a slice of it
// creates a real `MemRegion`, served to readers through the capability gates.
// ---------------------------------------------------------------------------

const ARENA_BYTES: usize = 49152;

static mut ARENA: [u8; ARENA_BYTES] = [0u8; ARENA_BYTES];
static mut ARENA_CURSOR: usize = 0;

fn arena_alloc(len: usize) -> Option<u64> {
    if len == 0 {
        return None;
    }
    unsafe {
        let cur = core::ptr::read(core::ptr::addr_of_mut!(ARENA_CURSOR));
        let next = cur.checked_add(len)?;
        if next > ARENA_BYTES {
            return None;
        }
        let base = core::ptr::addr_of_mut!(ARENA) as u64 + cur as u64;
        core::ptr::write(core::ptr::addr_of_mut!(ARENA_CURSOR), next);
        Some(base)
    }
}

/// Copy `data` into the arena at `base` (kernel-internal staging: the store
/// owns this memory; consumers reach it only through a granted region cap).
fn arena_store(base: u64, data: &[u8]) {
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), base as *mut u8, data.len());
    }
}

/// Copy `len` bytes at `base` into `out`.
fn arena_load(base: u64, len: usize, out: &mut [u8]) -> bool {
    if len > out.len() {
        return false;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(base as *const u8, out.as_mut_ptr(), len);
    }
    true
}

/// Test-only: reset arena + region table so contract tests start deterministic.
#[cfg(test)]
fn reset_store_arena() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(ARENA_CURSOR), 0);
        let buf = core::ptr::addr_of_mut!(ARENA) as *mut u8;
        for i in 0..ARENA_BYTES {
            core::ptr::write(buf.add(i), 0);
        }
    }
    mem::reset_regions_for_test();
}

// ---------------------------------------------------------------------------
// Node encoding: a version-node region holds [flags u8][prev 8 LE if bit0]
// [block hash 32B if bit1]. Block and node regions are created once and never
// mutated (COW); a node naming a block is that version of the object.
// ---------------------------------------------------------------------------

fn encode_node(prev: Option<u64>, block: Option<BlockId>) -> [u8; 41] {
    let mut out = [0u8; 41];
    let mut flags = 0u8;
    if prev.is_some() {
        flags |= 1;
    }
    if block.is_some() {
        flags |= 2;
    }
    out[0] = flags;
    if let Some(p) = prev {
        out[1..9].copy_from_slice(&p.to_le_bytes());
    }
    if let Some(b) = block {
        out[9..41].copy_from_slice(&b);
    }
    out
}

fn decode_node(bytes: &[u8]) -> (Option<u64>, Option<BlockId>) {
    let flags = bytes.first().copied().unwrap_or(0);
    let prev = if flags & 1 != 0 {
        if bytes.len() < 9 {
            return (None, None);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[1..9]);
        Some(u64::from_le_bytes(b))
    } else {
        None
    };
    let block = if flags & 2 != 0 {
        if bytes.len() < 41 {
            return (prev, None);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes[9..41]);
        Some(b)
    } else {
        None
    };
    (prev, block)
}

// ---------------------------------------------------------------------------
// Directory entries encoding (FlatView's flat namespace is itself a COW store
// object): [(count u32)((name_len u32)(name bytes)(node u64))*].
// ---------------------------------------------------------------------------

/// A fixed-size file name (bounded to `NAME_BYTES`).
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

    pub fn matches(&self, s: &[u8]) -> bool {
        self.len == s.len() && self.bytes[..self.len] == s[..]
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

/// One entry of the flat POSIX projection: a name and the store-node it names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileEntry {
    pub name: Name,
    pub node: u64,
}

pub(crate) fn encode_entries(entries: &[FileEntry]) -> Option<([u8; ENTRY_BUF], usize)> {
    let mut out = [0u8; ENTRY_BUF];
    let mut at = 0usize;
    out[at..at + 4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    at += 4;
    for e in entries {
        let name = e.name.as_slice();
        if at + 4 + name.len() + 8 > ENTRY_BUF {
            return None;
        }
        out[at..at + 4].copy_from_slice(&(name.len() as u32).to_le_bytes());
        at += 4;
        out[at..at + name.len()].copy_from_slice(name);
        at += name.len();
        out[at..at + 8].copy_from_slice(&e.node.to_le_bytes());
        at += 8;
    }
    Some((out, at))
}

/// Decode at most `MAX_FILES` entries; returns how many were decoded.
pub(crate) fn decode_entries(bytes: &[u8], out: &mut [FileEntry; MAX_FILES]) -> usize {
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

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct BlockLoc {
    id: BlockId,
    /// Kernel MemRegion id backing this block's bytes (content, immutable).
    region: u32,
    len: u64,
    refs: u64,
}

#[derive(Clone, Copy)]
struct NodeLoc {
    id: u64,
    /// Kernel MemRegion id backing this node's encoded bytes (immutable).
    region: u32,
}

/// The storage service. Blocks and nodes are created as kernel `MemRegion`s
/// over the store's own arena and reach callers only as narrowed capability
/// copies installed in their CSpace (`grant_read`); the ordinary capability
/// gates (`mem::mem_read` etc.) then enforce access — the store itself keeps no
/// per-caller table to get wrong.
pub struct Store {
    next_node: u64,
    blocks: [Option<BlockLoc>; MAX_BLOCKS],
    nodes: [Option<NodeLoc>; MAX_NODES],
    wal: Wal,
    seq: u64,
}

impl Store {
    /// A fresh store.
    pub fn new() -> Store {
        Store {
            next_node: 1,
            blocks: [None; MAX_BLOCKS],
            nodes: [None; MAX_NODES],
            wal: Wal::new(),
            seq: 0,
        }
    }

    pub fn wal(&self) -> &Wal {
        &self.wal
    }

    pub fn block_count(&self) -> usize {
        self.blocks.iter().filter(|b| b.is_some()).count()
    }

    /// Commit `data` as a new immutable block. Content-addressed: identical
    /// bytes are the same block, stored once. The signature is the §10 [CLOSED]
    /// contract: it mentions no index — no way for a write to await, block on,
    /// or depend on one. `None` if the region table or arena is exhausted.
    pub fn commit(&mut self, data: &[u8]) -> Option<BlockId> {
        let id = sha256(data);
        if let Some(loc) = self.blocks.iter_mut().flatten().find(|b| b.id == id) {
            loc.refs += 1;
            return Some(id);
        }
        // New block: stage the bytes then bind a real region over them.
        let base = arena_alloc(data.len())?;
        arena_store(base, data);
        let region = unsafe { mem::claim_region(base, data.len()) }?;
        let idx = self.blocks.iter().position(|b| b.is_none())?;
        self.blocks[idx] = Some(BlockLoc {
            id,
            region,
            len: data.len() as u64,
            refs: 1,
        });
        self.seq += 1;
        self.wal.push(WalRec {
            seq: self.seq,
            op: WalOp::Put {
                id,
                len: data.len() as u64,
            },
        });
        Some(id)
    }

    /// The kernel-object id for a block (a *name*, not an address: a caller who
    /// knows it cannot read until a cap is granted into its own table).
    pub fn block_obj(&self, id: &BlockId) -> Option<u64> {
        self.blocks
            .iter()
            .flatten()
            .find(|b| b.id == *id)
            .map(|b| b.region as u64)
    }

    pub fn block_len(&self, id: &BlockId) -> Option<u64> {
        self.blocks
            .iter()
            .flatten()
            .find(|b| b.id == *id)
            .map(|b| b.len)
    }

    /// The capability address: install a narrowed READ-only copy of the block's
    /// region cap into `recipient`'s own table. Returns the recipient's granted
    /// slot, or `None` for an unknown block or a full recipient table. Reading
    /// then flows through `mem::mem_read` (READ required); writing is refused —
    /// the granted copy cannot widen itself (I2).
    pub fn grant_read(&mut self, recipient: usize, id: &BlockId) -> Option<u32> {
        let loc = self.blocks.iter().flatten().find(|b| b.id == *id)?;
        let free = (0..crate::tasks::MAX_CAPS)
            .find(|&s| crate::tasks::task_cap(recipient, s).cap == Cap::None)?;
        crate::tasks::set_task_cap(
            recipient,
            free,
            CapSlot {
                cap: Cap::MemRegion(loc.region),
                rights: Rights::READ,
            },
        );
        Some(free as u32)
    }

    /// Create a fresh, empty COW object. Returns its head node's id.
    pub fn new_object(&mut self) -> Option<u64> {
        self.create_node(None, None)
    }

    fn create_node(&mut self, prev: Option<u64>, block: Option<BlockId>) -> Option<u64> {
        let enc = encode_node(prev, block);
        let base = arena_alloc(enc.len())?;
        arena_store(base, &enc);
        let region = unsafe { mem::claim_region(base, enc.len()) }?;
        let id = self.next_node;
        self.next_node += 1;
        let idx = self.nodes.iter().position(|n| n.is_none())?;
        self.nodes[idx] = Some(NodeLoc { id, region });
        Some(id)
    }

    /// The bytes of the version that `node` names — snapshots are version-stable
    /// because no region is ever mutated: whatever node id you hold, you read
    /// that version forever. Returns the number of bytes copied into `out`.
    pub fn snapshot(&mut self, node: u64, out: &mut [u8]) -> Option<usize> {
        let loc = *self.nodes.iter().flatten().find(|n| n.id == node)?;
        let (base, len) = mem::region_base_len(loc.region)?;
        let mut node_bytes = [0u8; 64];
        if !arena_load(base, len.min(64), &mut node_bytes) {
            return None;
        }
        let (_, block) = decode_node(&node_bytes);
        let Some(block) = block else {
            // A node naming no block is an empty object.
            return Some(0);
        };
        let bloc = *self.blocks.iter().flatten().find(|b| b.id == block)?;
        let (bbase, blen) = mem::region_base_len(bloc.region)?;
        let n = blen.min(out.len());
        if arena_load(bbase, n, out) {
            Some(n)
        } else {
            None
        }
    }

    /// COW write: a new block plus a new node derived from `cur`; nothing is
    /// mutated. Returns the new head node id (older nodes stay readable
    /// forever). Signature has no index (see `commit`).
    pub fn write_version(&mut self, cur: u64, data: &[u8]) -> Option<u64> {
        let block = self.commit(data)?;
        let next = self.create_node(Some(cur), Some(block))?;
        self.seq += 1;
        self.wal.push(WalRec {
            seq: self.seq,
            op: WalOp::Link {
                child: next,
                parent: cur,
            },
        });
        Some(next)
    }

    /// Content length (bytes) of the version `node` names, without copying the
    /// content (used by the POSIX view's `stat`).
    pub fn node_len(&mut self, node: u64) -> Option<usize> {
        let loc = *self.nodes.iter().flatten().find(|n| n.id == node)?;
        let (base, len) = mem::region_base_len(loc.region)?;
        let mut node_bytes = [0u8; 64];
        if !arena_load(base, len.min(64), &mut node_bytes) {
            return None;
        }
        let (_, block) = decode_node(&node_bytes);
        let Some(block) = block else {
            // A node naming no block is an empty object.
            return Some(0);
        };
        let bloc = *self.blocks.iter().flatten().find(|b| b.id == block)?;
        Some(bloc.len as usize)
    }
}

impl Default for Store {
    fn default() -> Store {
        Store::new()
    }
}

// ---------------------------------------------------------------------------
// FlatView: the POSIX file-view projection (design doc §8) — a flat namespace
// over store objects. Files are nothing but store objects; there is exactly one
// place bytes live. The "directory" is itself a COW store object (the dir node
// holds encoded `FileEntry`s).
// ---------------------------------------------------------------------------

pub struct FlatView {
    dir: u64,
}

impl FlatView {
    pub fn new(store: &mut Store) -> Option<FlatView> {
        store.new_object().map(|dir| FlatView { dir })
    }

    /// Entries in the flat namespace, decoded from the dir node (max
    /// `MAX_FILES`); returns how many.
    fn read_dir(&mut self, store: &mut Store, out: &mut [FileEntry; MAX_FILES]) -> usize {
        let mut buf = [0u8; ENTRY_BUF];
        match store.snapshot(self.dir, &mut buf) {
            Some(n) => decode_entries(&buf[..n], out),
            None => 0,
        }
    }

    fn write_dir(&mut self, store: &mut Store, entries: &[FileEntry]) -> bool {
        let Some((enc, enc_len)) = encode_entries(entries) else {
            return false;
        };
        match store.write_version(self.dir, &enc[..enc_len]) {
            Some(next) => {
                self.dir = next;
                true
            }
            None => false,
        }
    }

    /// Names currently in the flat namespace (max `MAX_FILES`); returns how many.
    pub fn list(&mut self, store: &mut Store, out: &mut [Name; MAX_FILES]) -> usize {
        let mut entries = [empty_entry(); MAX_FILES];
        let n = self.read_dir(store, &mut entries);
        for (i, e) in entries[..n].iter().enumerate() {
            out[i] = e.name;
        }
        n
    }

    pub fn create_file(&mut self, store: &mut Store, name: &[u8]) -> bool {
        let Some(name) = Name::from_slice(name) else {
            return false;
        };
        let mut entries = [empty_entry(); MAX_FILES];
        let n = self.read_dir(store, &mut entries);
        if entries[..n].iter().any(|e| e.name == name) {
            return false;
        }
        let node = match store.new_object() {
            Some(nnd) => nnd,
            None => return false,
        };
        let mut next = [empty_entry(); MAX_FILES];
        next[..n].copy_from_slice(&entries[..n]);
        next[n] = FileEntry { name, node };
        self.write_dir(store, &next[..n + 1])
    }

    pub fn write_file(&mut self, store: &mut Store, name: &[u8], data: &[u8]) -> bool {
        let Some(name) = Name::from_slice(name) else {
            return false;
        };
        let mut entries = [empty_entry(); MAX_FILES];
        let n = self.read_dir(store, &mut entries);
        let Some(pos) = entries[..n]
            .iter()
            .position(|e| e.name.matches(&name.bytes[..name.len]))
        else {
            return false;
        };
        let next_node = match store.write_version(entries[pos].node, data) {
            Some(nn) => nn,
            None => return false,
        };
        entries[pos].node = next_node;
        self.write_dir(store, &entries[..n])
    }

    /// Read `name` into `out`; returns the number of bytes copied.
    pub fn read_file(&mut self, store: &mut Store, name: &[u8], out: &mut [u8]) -> Option<usize> {
        let mut entries = [empty_entry(); MAX_FILES];
        let n = self.read_dir(store, &mut entries);
        let found = entries[..n].iter().find(|e| e.name.matches(name))?;
        store.snapshot(found.node, out)
    }

    pub fn delete_file(&mut self, store: &mut Store, name: &[u8]) -> bool {
        let Some(want) = Name::from_slice(name) else {
            return false;
        };
        let mut entries = [empty_entry(); MAX_FILES];
        let n = self.read_dir(store, &mut entries);
        let before = n;
        let mut kept = [empty_entry(); MAX_FILES];
        let mut k = 0usize;
        for e in &entries[..n] {
            if !e.name.matches(&want.bytes[..want.len]) {
                kept[k] = *e;
                k += 1;
            }
        }
        if k == before {
            return false;
        }
        self.write_dir(store, &kept[..k])
    }
}

fn empty_entry() -> FileEntry {
    FileEntry {
        name: Name {
            bytes: [0; NAME_BYTES],
            len: 0,
        },
        node: 0,
    }
}

// ---------------------------------------------------------------------------
// TreeView: the full POSIX file-tree projection (design doc §8). The upgrade
// from `FlatView`'s flat single-level namespace: a hierarchical namespace over
// store objects. The root is a COW dir node; every subdirectory is a COW dir
// node; every file is a COW file node — files and directories are nothing but
// store objects, there is exactly one place bytes live.
//
// A mutation commits a new version of the target's parent dir AND of every dir
// node on the path up to the root (path persistence); a node id you already
// hold reads that version forever, so snapshots are version-stable at every
// level of the tree.
//
// Paths: absolute (`/a/b/c.txt`) or relative to the working directory; `.`
// and `..` components resolve; a trailing slash is irrelevant (empty segments
// are dropped). The cwd is tracked as a path — a real POSIX shell's cwd is a
// path, not a node id — and survives COW exactly because it is re-resolved
// from the root on demand.
//
// Permission bits: entries carry POSIX `mode`/`uid` as projection metadata
// (so POSIX tools see a familiar `st_mode`), but the authority that actually
// gates access is capability-shaped — reads/writes flow through the store's
// region caps (READ/WRITE rights). This is the design-doc position that
// ACL-style permission bits are subsumed by capabilities; the view does not
// add a second, ambient authority.
// ---------------------------------------------------------------------------

/// POSIX entry kind in the hierarchical view.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind {
    File,
    Dir,
}

/// One entry of the hierarchical POSIX projection: a name, kind, mode bits and
/// owner as metadata, and the store-node it names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PEntry {
    pub name: Name,
    pub kind: EntryKind,
    pub mode: u16,
    pub uid: u32,
    pub node: u64,
}

fn empty_pentry() -> PEntry {
    PEntry {
        name: Name::default(),
        kind: EntryKind::File,
        mode: 0,
        uid: 0,
        node: 0,
    }
}

/// Encode `entries` (max `MAX_FILES`) as a directory node block:
/// [(count u32)((name_len u32)(name)(kind u8)(mode u16 LE)(uid u32 LE)(node u64))*].
pub(crate) fn encode_posix_entries(entries: &[PEntry]) -> Option<([u8; ENTRY_BUF], usize)> {
    let mut out = [0u8; ENTRY_BUF];
    let mut at = 0usize;
    out[at..at + 4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    at += 4;
    for e in entries {
        let name = e.name.as_slice();
        if at + 4 + name.len() + 1 + 2 + 4 + 8 > ENTRY_BUF {
            return None;
        }
        out[at..at + 4].copy_from_slice(&(name.len() as u32).to_le_bytes());
        at += 4;
        out[at..at + name.len()].copy_from_slice(name);
        at += name.len();
        out[at] = match e.kind {
            EntryKind::File => 0,
            EntryKind::Dir => 1,
        };
        at += 1;
        out[at..at + 2].copy_from_slice(&e.mode.to_le_bytes());
        at += 2;
        out[at..at + 4].copy_from_slice(&e.uid.to_le_bytes());
        at += 4;
        out[at..at + 8].copy_from_slice(&e.node.to_le_bytes());
        at += 8;
    }
    Some((out, at))
}

/// Decode at most `MAX_FILES` entries; returns how many were decoded.
pub(crate) fn decode_posix_entries(bytes: &[u8], out: &mut [PEntry; MAX_FILES]) -> usize {
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
        if at + 1 > bytes.len() {
            break;
        }
        let kind = if bytes[at] == 1 {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        at += 1;
        if at + 2 > bytes.len() {
            break;
        }
        let mode = u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        at += 2;
        if at + 4 > bytes.len() {
            break;
        }
        let uid = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        at += 4;
        if at + 8 > bytes.len() {
            break;
        }
        let node = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        at += 8;
        out[written] = PEntry {
            name,
            kind,
            mode,
            uid,
            node,
        };
        written += 1;
    }
    written
}

/// Split `path` on `/`, dropping empty segments (leading/trailing/repeated
/// slashes). Returns `(absolute, components)`. `.` and `..` are NOT resolved
/// here — `normalize` resolves them against the full component list (which
/// includes the cwd components for relative paths).
fn split_path(path: &[u8]) -> Option<(bool, [Name; MAX_DEPTH], usize)> {
    if path.contains(&0) {
        return None;
    }
    let absolute = path.first() == Some(&b'/');
    let mut comps = [Name::default(); MAX_DEPTH];
    let mut n = 0usize;
    let mut i = 0usize;
    while i <= path.len() {
        let end = path[i..]
            .iter()
            .position(|b| *b == b'/')
            .map(|p| i + p)
            .unwrap_or(path.len());
        if end > i {
            let seg = &path[i..end];
            if n >= MAX_DEPTH {
                return None;
            }
            comps[n] = Name::from_slice(seg)?;
            n += 1;
        }
        if end >= path.len() {
            break;
        }
        i = end + 1;
    }
    Some((absolute, comps, n))
}

/// Apply `.` (skip) and `..` (pop) over the full component list; pops below
/// the root floor at the root.
fn normalize(comps: &[Name], n: usize) -> Option<([Name; MAX_DEPTH], usize)> {
    let mut out = [Name::default(); MAX_DEPTH];
    let mut m = 0usize;
    for c in &comps[..n] {
        let s = c.as_slice();
        if s == b"." {
            continue;
        }
        if s == b".." {
            m = m.saturating_sub(1);
            continue;
        }
        if m >= MAX_DEPTH {
            return None;
        }
        out[m] = *c;
        m += 1;
    }
    Some((out, m))
}

/// A resolved path: where the target lives and how to get back to the root.
struct Resolved {
    /// The dir node containing the target (for a path with >= 1 component, the
    /// last dir on the walk; for an empty path, the resolved dir itself).
    parent: u64,
    /// The target entry as resolved; when not found, carries the last
    /// component's name so create operations can use it.
    target: PEntry,
    found: bool,
    /// (dir node, child name) for every dir descended through, in root-down
    /// order: `levels[i].0` is the dir at depth i, `levels[i].1` is the name
    /// of its child that the walk followed.
    levels: [(u64, Name); MAX_DEPTH],
    nlevels: usize,
}

/// The hierarchical POSIX projection over the store.
pub struct TreeView {
    root: u64,
    cwd: [Name; MAX_DEPTH],
    cwd_n: usize,
}

fn read_dir_entries(store: &mut Store, node: u64, out: &mut [PEntry; MAX_FILES]) -> Option<usize> {
    let mut buf = [0u8; ENTRY_BUF];
    let n = store.snapshot(node, &mut buf)?;
    Some(decode_posix_entries(&buf[..n], out))
}

fn write_dir_entries(store: &mut Store, dir: u64, entries: &[PEntry]) -> Option<u64> {
    let (enc, enc_len) = encode_posix_entries(entries)?;
    store.write_version(dir, &enc[..enc_len])
}

/// Commit a new version of `dir` with the entry `name` now pointing at `node`.
fn rewrite_entry(store: &mut Store, dir: u64, name: Name, node: u64) -> Option<u64> {
    let mut entries = [empty_pentry(); MAX_FILES];
    let n = read_dir_entries(store, dir, &mut entries)?;
    let pos = entries[..n].iter().position(|e| e.name == name)?;
    entries[pos].node = node;
    write_dir_entries(store, dir, &entries[..n])
}

/// Commit a new version of `dir` with `entry` added (refused if the name is
/// taken or the dir is full).
fn add_entry(store: &mut Store, dir: u64, entry: PEntry) -> Option<u64> {
    let mut entries = [empty_pentry(); MAX_FILES];
    let n = read_dir_entries(store, dir, &mut entries)?;
    if entries[..n].iter().any(|e| e.name == entry.name) || n >= MAX_FILES {
        return None;
    }
    let mut next = [empty_pentry(); MAX_FILES];
    next[..n].copy_from_slice(&entries[..n]);
    next[n] = entry;
    write_dir_entries(store, dir, &next[..n + 1])
}

/// Commit a new version of `dir` with the entry `name` removed.
fn remove_entry(store: &mut Store, dir: u64, name: Name) -> Option<u64> {
    let mut entries = [empty_pentry(); MAX_FILES];
    let n = read_dir_entries(store, dir, &mut entries)?;
    let pos = entries[..n].iter().position(|e| e.name == name)?;
    let mut kept = [empty_pentry(); MAX_FILES];
    kept[..pos].copy_from_slice(&entries[..pos]);
    kept[pos..n - 1].copy_from_slice(&entries[pos + 1..n]);
    write_dir_entries(store, dir, &kept[..n - 1])
}

impl TreeView {
    pub fn new(store: &mut Store) -> Option<TreeView> {
        store.new_object().map(|root| TreeView {
            root,
            cwd: [Name::default(); MAX_DEPTH],
            cwd_n: 0,
        })
    }

    /// The current root node id (changes as COW rewrites the tree).
    pub fn root(&self) -> u64 {
        self.root
    }

    /// The working directory, re-resolved from the root — its node id changes
    /// as COW rewrites the tree; the path it lives at does not.
    pub fn cwd(&mut self, store: &mut Store) -> Option<u64> {
        let mut dir = self.root;
        for i in 0..self.cwd_n {
            let name = self.cwd[i];
            let mut entries = [empty_pentry(); MAX_FILES];
            let n = read_dir_entries(store, dir, &mut entries)?;
            let sub = entries[..n].iter().find(|e| e.name == name)?;
            if sub.kind != EntryKind::Dir {
                return None;
            }
            dir = sub.node;
        }
        Some(dir)
    }

    /// Resolve the full normalized component list for `path`, combining the
    /// cwd (for relative paths) before applying `.`/`..`.
    fn resolve_components(&self, path: &[u8]) -> Option<(bool, [Name; MAX_DEPTH], usize)> {
        let (abs, raw, raw_n) = split_path(path)?;
        let mut full = [Name::default(); MAX_DEPTH];
        let mut m = 0usize;
        if !abs {
            for i in 0..self.cwd_n {
                if m >= MAX_DEPTH {
                    return None;
                }
                full[m] = self.cwd[i];
                m += 1;
            }
        }
        for r in &raw[..raw_n] {
            if m >= MAX_DEPTH {
                return None;
            }
            full[m] = *r;
            m += 1;
        }
        let (norm, nn) = normalize(&full[..m], m)?;
        Some((abs, norm, nn))
    }

    /// Resolve `path` to its parent dir and target entry, recording the
    /// root→parent dir chain for COW propagation. `None` if any intermediate
    /// component is missing or names a file.
    fn resolve(&mut self, store: &mut Store, path: &[u8]) -> Option<Resolved> {
        let (_, comps, n) = self.resolve_components(path)?;
        let mut dir = self.root;
        let mut levels = [(0u64, Name::default()); MAX_DEPTH];
        let mut nl = 0usize;
        for (i, name) in comps[..n].iter().enumerate() {
            let mut entries = [empty_pentry(); MAX_FILES];
            let count = self.read_dir(store, dir, &mut entries)?;
            if i == n - 1 {
                let pos = entries[..count].iter().position(|e| e.name == *name);
                let target = match pos {
                    Some(p) => entries[p],
                    None => PEntry {
                        name: *name,
                        kind: EntryKind::File,
                        mode: 0,
                        uid: 0,
                        node: 0,
                    },
                };
                return Some(Resolved {
                    parent: dir,
                    target,
                    found: pos.is_some(),
                    levels,
                    nlevels: nl,
                });
            }
            let sub = entries[..count].iter().find(|e| e.name == *name)?;
            if sub.kind != EntryKind::Dir {
                return None;
            }
            levels[nl] = (dir, *name);
            nl += 1;
            dir = sub.node;
        }
        // Empty path: the target is the resolved dir itself (the root).
        let target = PEntry {
            name: Name::default(),
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
            nlevels: nl,
        })
    }

    fn read_dir(
        &mut self,
        store: &mut Store,
        node: u64,
        out: &mut [PEntry; MAX_FILES],
    ) -> Option<usize> {
        read_dir_entries(store, node, out)
    }

    /// Install a mutated parent dir into the tree, committing new versions of
    /// every dir on the root→parent path. Returns the new root node id (the
    /// old root keeps reading the old tree — COW all the way up).
    fn commit_tree(
        &mut self,
        store: &mut Store,
        parent_new: u64,
        levels: &[(u64, Name)],
        nlevels: usize,
    ) -> Option<u64> {
        if nlevels == 0 {
            // The parent IS the root: the new root is the rewritten parent.
            return Some(parent_new);
        }
        let mut cur = parent_new;
        for i in (0..nlevels).rev() {
            let (dir, name) = levels[i];
            cur = rewrite_entry(store, dir, name, cur)?;
        }
        Some(cur)
    }

    fn commit(&mut self, store: &mut Store, parent_new: u64, r: &Resolved) -> bool {
        match self.commit_tree(store, parent_new, &r.levels, r.nlevels) {
            Some(new_root) => {
                self.root = new_root;
                true
            }
            None => false,
        }
    }

    /// Change the working directory. `false` if the path does not resolve to a
    /// directory.
    pub fn cd(&mut self, store: &mut Store, path: &[u8]) -> bool {
        let (_, comps, n) = match self.resolve_components(path) {
            Some(x) => x,
            None => return false,
        };
        let mut dir = self.root;
        for name in &comps[..n] {
            let mut entries = [empty_pentry(); MAX_FILES];
            let Some(count) = read_dir_entries(store, dir, &mut entries) else {
                return false;
            };
            let Some(sub) = entries[..count].iter().find(|e| e.name == *name) else {
                return false;
            };
            if sub.kind != EntryKind::Dir {
                return false;
            }
            dir = sub.node;
        }
        self.cwd[..n].copy_from_slice(&comps[..n]);
        self.cwd_n = n;
        true
    }

    /// Create an empty directory at `path` (parents must exist). `false` if
    /// the path is taken or the parent is missing/full.
    pub fn mkdir(&mut self, store: &mut Store, path: &[u8], mode: u16) -> bool {
        let Some(r) = self.resolve(store, path) else {
            return false;
        };
        if r.found {
            return false;
        }
        let node = match store.new_object() {
            Some(n) => n,
            None => return false,
        };
        let parent_new = match add_entry(
            store,
            r.parent,
            PEntry {
                name: r.target.name,
                kind: EntryKind::Dir,
                mode,
                uid: 0,
                node,
            },
        ) {
            Some(n) => n,
            None => return false,
        };
        self.commit(store, parent_new, &r)
    }

    /// Create an empty regular file at `path` (parents must exist). `false` if
    /// the path is taken or the parent is missing/full.
    pub fn create_file(&mut self, store: &mut Store, path: &[u8], mode: u16) -> bool {
        let Some(r) = self.resolve(store, path) else {
            return false;
        };
        if r.found {
            return false;
        }
        let node = match store.new_object() {
            Some(n) => n,
            None => return false,
        };
        let parent_new = match add_entry(
            store,
            r.parent,
            PEntry {
                name: r.target.name,
                kind: EntryKind::File,
                mode,
                uid: 0,
                node,
            },
        ) {
            Some(n) => n,
            None => return false,
        };
        self.commit(store, parent_new, &r)
    }

    /// Overwrite `path` with `data` (COW: a new file version plus new versions
    /// of every dir up to the root).
    pub fn write_file(&mut self, store: &mut Store, path: &[u8], data: &[u8]) -> bool {
        let Some(r) = self.resolve(store, path) else {
            return false;
        };
        if !r.found || r.target.kind != EntryKind::File {
            return false;
        }
        let file_new = match store.write_version(r.target.node, data) {
            Some(n) => n,
            None => return false,
        };
        let parent_new = match rewrite_entry(store, r.parent, r.target.name, file_new) {
            Some(n) => n,
            None => return false,
        };
        self.commit(store, parent_new, &r)
    }

    /// Read `path` into `out`; returns the number of bytes copied.
    pub fn read_file(&mut self, store: &mut Store, path: &[u8], out: &mut [u8]) -> Option<usize> {
        let r = self.resolve(store, path)?;
        if !r.found || r.target.kind != EntryKind::File {
            return None;
        }
        store.snapshot(r.target.node, out)
    }

    /// The store-node id of the object `path` names (a name, not authority —
    /// reading it still needs a region cap).
    pub fn node_of(&mut self, store: &mut Store, path: &[u8]) -> Option<u64> {
        let r = self.resolve(store, path)?;
        if !r.found {
            return None;
        }
        Some(r.target.node)
    }

    /// Entries of the *historical* dir node `node` (a node id captured from an
    /// earlier `root()`), decoded exactly as live dirs — version-stable COW.
    pub fn snapshot_dir(
        &mut self,
        store: &mut Store,
        node: u64,
        out: &mut [PEntry; MAX_FILES],
    ) -> Option<usize> {
        read_dir_entries(store, node, out)
    }

    /// Entries of the dir at `path` (or the cwd when `path` is empty).
    pub fn list(
        &mut self,
        store: &mut Store,
        path: &[u8],
        out: &mut [PEntry; MAX_FILES],
    ) -> Option<usize> {
        let r = self.resolve(store, path)?;
        if r.target.kind != EntryKind::Dir {
            return None;
        }
        read_dir_entries(store, r.target.node, out)
    }

    /// Remove the regular file at `path`. `false` if missing or a directory.
    pub fn unlink(&mut self, store: &mut Store, path: &[u8]) -> bool {
        let Some(r) = self.resolve(store, path) else {
            return false;
        };
        if !r.found || r.target.kind != EntryKind::File {
            return false;
        }
        let parent_new = match remove_entry(store, r.parent, r.target.name) {
            Some(n) => n,
            None => return false,
        };
        self.commit(store, parent_new, &r)
    }

    /// Remove the *empty* directory at `path` (POSIX `rmdir`). The root itself
    /// cannot be removed.
    pub fn rmdir(&mut self, store: &mut Store, path: &[u8]) -> bool {
        let Some(r) = self.resolve(store, path) else {
            return false;
        };
        if !r.found || r.target.kind != EntryKind::Dir {
            return false;
        }
        if r.target.node == self.root {
            return false; // the root is not removable
        }
        let mut entries = [empty_pentry(); MAX_FILES];
        let Some(count) = read_dir_entries(store, r.target.node, &mut entries) else {
            return false;
        };
        if count != 0 {
            return false; // POSIX: rmdir requires an empty dir
        }
        let parent_new = match remove_entry(store, r.parent, r.target.name) {
            Some(n) => n,
            None => return false,
        };
        self.commit(store, parent_new, &r)
    }

    /// `(kind, mode, uid, size)` where size is bytes for a file and entry
    /// count for a directory.
    pub fn stat(&mut self, store: &mut Store, path: &[u8]) -> Option<(EntryKind, u16, u32, usize)> {
        let r = self.resolve(store, path)?;
        if !r.found {
            return None;
        }
        match r.target.kind {
            EntryKind::File => {
                let size = store.node_len(r.target.node)?;
                Some((EntryKind::File, r.target.mode, r.target.uid, size))
            }
            EntryKind::Dir => {
                let mut entries = [empty_pentry(); MAX_FILES];
                let count = read_dir_entries(store, r.target.node, &mut entries)?;
                Some((EntryKind::Dir, r.target.mode, r.target.uid, count))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RelationshipIndex: the §8 "graph as index, not ground truth". A rebuildable
// cache over the store's WAL: it learns *only* from `Wal` records, after the
// fact, never from commits. Its correctness is not load-bearing: losing it
// costs search/relationship queries, never data.
// ---------------------------------------------------------------------------

const MAX_EDGES: usize = 64;
const MAX_IDX_NODES: usize = 64;

#[derive(Debug)]
pub struct RelationshipIndex {
    children: [(u64, u64); MAX_EDGES], // (parent, child) derivation edges
    edges: usize,
    nodes: [u64; MAX_IDX_NODES],
    n_nodes: usize,
    blocks: [BlockId; MAX_BLOCKS],
    n_blocks: usize,
    consumed: u64,
}

impl RelationshipIndex {
    pub fn new() -> RelationshipIndex {
        RelationshipIndex {
            children: [(0, 0); MAX_EDGES],
            edges: 0,
            nodes: [0; MAX_IDX_NODES],
            n_nodes: 0,
            blocks: [[0; 32]; MAX_BLOCKS],
            n_blocks: 0,
            consumed: 0,
        }
    }

    /// Consume every WAL record the log has grown to. Async by construction:
    /// whatever the index has not yet consumed, the store has already committed
    /// without waiting for it.
    pub fn ingest(&mut self, wal: &Wal) {
        for i in 0..wal.len() {
            let Some(rec) = wal.rec(i) else { continue };
            if rec.seq <= self.consumed {
                continue;
            }
            match &rec.op {
                WalOp::Put { id, .. } => {
                    if self.n_blocks < MAX_BLOCKS && !self.blocks[..self.n_blocks].contains(id) {
                        self.blocks[self.n_blocks] = *id;
                        self.n_blocks += 1;
                    }
                }
                WalOp::Link { child, parent } => {
                    self.add_node(*child);
                    self.add_node(*parent);
                    if self.edges < MAX_EDGES {
                        self.children[self.edges] = (*parent, *child);
                        self.edges += 1;
                    }
                }
            }
            self.consumed = rec.seq;
        }
    }

    fn add_node(&mut self, id: u64) {
        if self.n_nodes < MAX_IDX_NODES && !self.nodes[..self.n_nodes].contains(&id) {
            self.nodes[self.n_nodes] = id;
            self.n_nodes += 1;
        }
    }

    /// Drop everything and re-derive purely from the log (the WinFS-proof
    /// property: the index is disposable).
    pub fn rebuild(&mut self, wal: &Wal) {
        self.children = [(0, 0); MAX_EDGES];
        self.edges = 0;
        self.nodes = [0; MAX_IDX_NODES];
        self.n_nodes = 0;
        self.blocks = [[0; 32]; MAX_BLOCKS];
        self.n_blocks = 0;
        self.consumed = 0;
        self.ingest(wal);
    }

    pub fn consumed_seq(&self) -> u64 {
        self.consumed
    }

    pub fn node_count(&self) -> usize {
        self.n_nodes
    }

    pub fn block_count(&self) -> usize {
        self.n_blocks
    }

    /// Direct children of `parent` (node ids), in WAL order. Returns how many
    /// were written into `out`.
    pub fn children_of(&self, parent: u64, out: &mut [u64]) -> usize {
        let mut written = 0usize;
        for (p, c) in self.children[..self.edges].iter() {
            if *p == parent {
                if written < out.len() {
                    out[written] = *c;
                }
                written += 1;
            }
        }
        written.min(out.len())
    }

    /// Is `node` reachable from `ancestor` through derivation edges? (BFS)
    pub fn is_derived_from(&self, ancestor: u64, node: u64) -> bool {
        if ancestor == node {
            return true;
        }
        let mut seen = [false; MAX_IDX_NODES];
        let mut stack = [0u64; MAX_IDX_NODES];
        let mut sp = 0usize;
        stack[sp] = node;
        sp += 1;
        while sp > 0 {
            sp -= 1;
            let cur = stack[sp];
            let Some(i) = self.nodes[..self.n_nodes].iter().position(|n| *n == cur) else {
                continue;
            };
            if seen[i] {
                continue;
            }
            seen[i] = true;
            for (p, c) in self.children[..self.edges].iter() {
                if *c == cur && *p == ancestor {
                    return true;
                }
                if *c == cur && sp < MAX_IDX_NODES {
                    stack[sp] = *p;
                    sp += 1;
                }
            }
        }
        false
    }
}

impl Default for RelationshipIndex {
    fn default() -> RelationshipIndex {
        RelationshipIndex::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A clean world: store service at task index 7, fresh arena + region table.
    fn world() -> (Store, usize) {
        reset_store_arena();
        crate::tasks::reset_table_for_test();
        crate::tasks::set_current_for_test(7);
        (Store::new(), 7)
    }

    #[test]
    fn sha256_known_vectors() {
        // Published FIPS 180-4 vectors (same as the model crate, cross-checked
        // against the host's hash tool at authoring time).
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&million_a)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn identical_bytes_are_one_block() {
        let _g = crate::kernel_state_guard();
        let (mut store, _svc) = world();
        let a = store.commit(b"same bytes").unwrap();
        let b = store.commit(b"same bytes").unwrap();
        assert_eq!(a, b, "content addressing: same content, same block");
        assert_eq!(store.block_count(), 1, "dedup: one block for both commits");
    }

    #[test]
    fn blocks_are_capability_addressed() {
        let _g = crate::kernel_state_guard();
        let (mut store, _svc) = world();
        let id = store.commit(b"classified payload").unwrap();
        let _obj = store.block_obj(&id).unwrap();

        // The reader holds NO region cap: knowing the hash/obj grants nothing.
        let reader = 0usize;
        crate::tasks::set_current_for_test(reader);
        let slot0 = 0u64;
        assert_eq!(
            unsafe { mem::mem_len(slot0) },
            -1,
            "fabricated slot without a region cap must be denied"
        );

        // grant_read installs a narrowed READ-only copy in the READER's table.
        let granted = store.grant_read(reader, &id).unwrap() as usize;
        crate::tasks::set_current_for_test(reader);
        let mut out = [0u8; 18];
        assert_eq!(
            unsafe { mem::mem_read(granted as u64, 0, 18, out.as_mut_ptr() as u64) },
            18
        );
        assert_eq!(&out, &b"classified payload"[..]);
        assert_eq!(
            unsafe { mem::mem_write(granted as u64, 0, 1, 0x2000) },
            -1,
            "a READ-only granted cap cannot widen itself to write"
        );
    }

    #[test]
    fn cow_write_versions_are_immutable_snapshots() {
        let _g = crate::kernel_state_guard();
        let (mut store, _svc) = world();
        let v0 = store.new_object().unwrap();
        let v1 = store.write_version(v0, b"draft one").unwrap();
        let mut out = [0u8; 64];
        let n = store.snapshot(v0, &mut out).unwrap();
        assert_eq!(&out[..n], b"");
        let n = store.snapshot(v1, &mut out).unwrap();
        assert_eq!(&out[..n], b"draft one");

        let v2 = store.write_version(v1, b"draft two, bigger").unwrap();
        let n = store.snapshot(v1, &mut out).unwrap();
        assert_eq!(&out[..n], b"draft one");
        let n = store.snapshot(v2, &mut out).unwrap();
        assert_eq!(&out[..n], b"draft two, bigger");
        assert_eq!(store.block_count(), 2, "two content blocks, zero mutations");
    }

    #[test]
    fn index_is_a_consumer_of_the_wal_and_rebuilds_from_it() {
        let _g = crate::kernel_state_guard();
        let (mut store, _svc) = world();
        let v0 = store.new_object().unwrap();
        let v1 = store.write_version(v0, b"v1").unwrap();
        let v2 = store.write_version(v1, b"v2").unwrap();
        let v3 = store.write_version(v2, b"v3").unwrap();

        let mut idx = RelationshipIndex::new();
        idx.ingest(store.wal());
        assert_eq!(idx.consumed_seq(), store.wal().len() as u64);
        assert_eq!(idx.node_count(), 4, "v0..v3 all present");
        let mut kids = [0u64; 8];
        let n = idx.children_of(v0, &mut kids);
        assert_eq!(&kids[..n], &[v1]);
        assert!(idx.is_derived_from(v0, v3));
        assert!(!idx.is_derived_from(v3, v0), "derivation is not symmetric");

        let mut fresh = RelationshipIndex::new();
        fresh.rebuild(store.wal());
        assert_eq!(fresh.node_count(), idx.node_count());
        let mut fresh_kids = [0u64; 8];
        let fn2 = fresh.children_of(v0, &mut fresh_kids);
        assert_eq!(&fresh_kids[..fn2], &kids[..n]);
        assert_eq!(fresh.consumed_seq(), idx.consumed_seq());
    }

    #[test]
    fn the_index_can_never_participate_in_a_write() {
        // (a) If `commit` or `write_version` took or returned anything
        // index-shaped, these assignments could not compile.
        let _commit: fn(&mut Store, &[u8]) -> Option<BlockId> = Store::commit;
        let _write: fn(&mut Store, u64, &[u8]) -> Option<u64> = Store::write_version;

        // (b) A full workload with no index registered anywhere.
        let _g = crate::kernel_state_guard();
        let (mut store, _svc) = world();
        let mut view = FlatView::new(&mut store).unwrap();
        view.create_file(&mut store, b"memo.txt");
        view.write_file(
            &mut store,
            b"memo.txt",
            b"appears even though no index exists",
        );
        let mut out = [0u8; 128];
        let n = view.read_file(&mut store, b"memo.txt", &mut out).unwrap();
        assert_eq!(&out[..n], b"appears even though no index exists");

        // (c) The index "comes online" after all of it, consuming only the log.
        let mut idx = RelationshipIndex::new();
        idx.ingest(store.wal());
        assert_eq!(
            idx.block_count(),
            3,
            "three content blocks: the memo body, the dir after create, the dir after write"
        );
    }

    #[test]
    fn posix_view_is_a_projection_with_no_second_source_of_truth() {
        let _g = crate::kernel_state_guard();
        let (mut store, _svc) = world();
        let wal_before = store.wal().len();
        let mut view = FlatView::new(&mut store).unwrap();
        view.create_file(&mut store, b"a.txt");
        view.write_file(&mut store, b"a.txt", b"alpha");
        view.create_file(&mut store, b"b.txt");
        view.write_file(&mut store, b"b.txt", b"beta");

        let mut names = [Name {
            bytes: [0; NAME_BYTES],
            len: 0,
        }; MAX_FILES];
        assert_eq!(view.list(&mut store, &mut names), 2);
        let mut out = [0u8; 64];
        let n = view.read_file(&mut store, b"a.txt", &mut out).unwrap();
        assert_eq!(&out[..n], b"alpha");
        assert!(view.delete_file(&mut store, b"a.txt"));
        let mut names2 = [Name {
            bytes: [0; NAME_BYTES],
            len: 0,
        }; MAX_FILES];
        let n2 = view.list(&mut store, &mut names2);
        assert_eq!(n2, 1);
        assert!(names2[0].matches(b"b.txt"));

        // The bytes live only in the store: the WAL grew at every mutation.
        assert!(store.wal().len() > wal_before);
    }

    #[test]
    fn index_rebuilds_identically_from_the_log() {
        let mut wal = Wal::new();
        wal.push(WalRec {
            seq: 1,
            op: WalOp::Put {
                id: [1u8; 32],
                len: 5,
            },
        });
        wal.push(WalRec {
            seq: 2,
            op: WalOp::Link {
                child: 9,
                parent: 7,
            },
        });

        let mut idx = RelationshipIndex::new();
        idx.ingest(&wal);
        let count = idx.node_count();
        let mut kids = [0u64; 8];
        let n = idx.children_of(7, &mut kids);
        assert_eq!(count, 2);
        assert_eq!(&kids[..n], &[9]);

        idx.rebuild(&wal);
        assert_eq!(idx.node_count(), count);
        let mut kids2 = [0u64; 8];
        let n2 = idx.children_of(7, &mut kids2);
        assert_eq!(&kids2[..n2], &[9]);
    }

    // keep helpers used by tests referenced to avoid dead-code warnings
    #[test]
    fn name_helpers() {
        assert!(empty_entry().name.len == 0);
        assert!(Name::from_slice(b"").is_none());
        assert!(Name::from_slice(b"x").is_some());
        assert!(Name::from_slice(&[0u8; NAME_BYTES + 1]).is_none());
        assert!(empty_pentry().name.len == 0);
        assert_eq!(MODE_FILE & 0o777, 0o644);
        assert_eq!(MODE_DIR & 0o777, 0o755);
    }

    fn tree_world() -> (Store, TreeView) {
        reset_store_arena();
        crate::tasks::reset_table_for_test();
        crate::tasks::set_current_for_test(7);
        let mut store = Store::new();
        let view = TreeView::new(&mut store).unwrap();
        (store, view)
    }

    fn read_str(store: &mut Store, view: &mut TreeView, path: &[u8]) -> String {
        let mut buf = [0u8; 256];
        let n = view.read_file(store, path, &mut buf).unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn treeview_creates_nested_dirs_and_files_with_modes() {
        let _g = crate::kernel_state_guard();
        let (mut store, mut view) = tree_world();
        assert!(view.mkdir(&mut store, b"/docs", MODE_DIR));
        assert!(view.create_file(&mut store, b"/docs/report.txt", MODE_FILE));
        assert!(view.write_file(
            &mut store,
            b"/docs/report.txt",
            b"Phase C: nested POSIX view"
        ));

        assert_eq!(
            read_str(&mut store, &mut view, b"/docs/report.txt"),
            "Phase C: nested POSIX view"
        );
        let (kind, mode, uid, size) = view.stat(&mut store, b"/docs/report.txt").unwrap();
        assert_eq!(kind, EntryKind::File);
        assert_eq!(mode, MODE_FILE);
        assert_eq!(uid, 0);
        assert_eq!(size, 26);
        let (dkind, dmode, _, dsize) = view.stat(&mut store, b"/docs").unwrap();
        assert_eq!(dkind, EntryKind::Dir);
        assert_eq!(dmode, MODE_DIR);
        assert_eq!(dsize, 1, "docs holds one entry");

        // Duplicate creation refused; missing parents refused.
        assert!(!view.mkdir(&mut store, b"/docs", MODE_DIR));
        assert!(!view.create_file(&mut store, b"/docs/report.txt", MODE_FILE));
        assert!(!view.create_file(&mut store, b"/missing/a.txt", MODE_FILE));
    }

    #[test]
    fn treeview_path_resolution_handles_abs_dot_dotdot_and_cwd() {
        let _g = crate::kernel_state_guard();
        let (mut store, mut view) = tree_world();
        assert!(view.mkdir(&mut store, b"/home", MODE_DIR));
        assert!(view.mkdir(&mut store, b"/home/alice", MODE_DIR));
        assert!(view.create_file(&mut store, b"/home/alice/notes.txt", MODE_FILE));
        assert!(view.write_file(&mut store, b"/home/alice/notes.txt", b"alpha"));

        assert_eq!(
            read_str(&mut store, &mut view, b"/home/alice/notes.txt"),
            "alpha"
        );
        assert!(view.cd(&mut store, b"/home/alice"));
        assert_eq!(read_str(&mut store, &mut view, b"notes.txt"), "alpha");
        assert_eq!(read_str(&mut store, &mut view, b"./notes.txt"), "alpha");
        assert_eq!(read_str(&mut store, &mut view, b"././notes.txt"), "alpha");
        assert_eq!(
            view.list(&mut store, b"..", &mut [empty_pentry(); MAX_FILES])
                .unwrap(),
            1,
            ".. from /home/alice resolves to /home"
        );
        assert_eq!(
            read_str(&mut store, &mut view, b"../alice/notes.txt"),
            "alpha"
        );
        assert_eq!(
            read_str(&mut store, &mut view, b"/home/alice/notes.txt"),
            "alpha"
        );

        // cd back to root, then relative .. cannot escape the root.
        assert!(view.cd(&mut store, b"/"));
        assert!(view.cd(&mut store, b".."));
        assert_eq!(view.cwd(&mut store).unwrap(), view.root());

        // A file cannot be cd'd into.
        assert!(!view.cd(&mut store, b"/home/alice/notes.txt"));
    }

    #[test]
    fn treeview_cow_rewrites_the_whole_root_path_version_stably() {
        let _g = crate::kernel_state_guard();
        let (mut store, mut view) = tree_world();
        assert!(view.mkdir(&mut store, b"/a", MODE_DIR));
        assert!(view.mkdir(&mut store, b"/a/b", MODE_DIR));
        assert!(view.create_file(&mut store, b"/a/b/f.txt", MODE_FILE));
        assert!(view.write_file(&mut store, b"/a/b/f.txt", b"v1"));

        // Every level is a COW object: hold old node ids, then mutate.
        let root_v1 = view.root();
        let file_v1 = view.node_of(&mut store, b"/a/b/f.txt").unwrap();
        let mut dir_old = [empty_pentry(); MAX_FILES];
        let n_root_v1 = view
            .snapshot_dir(&mut store, root_v1, &mut dir_old)
            .unwrap();

        assert!(view.write_file(&mut store, b"/a/b/f.txt", b"v2 - longer"));
        let root_v2 = view.root();
        assert_ne!(root_v1, root_v2, "the root is rewritten by a deep write");
        assert_eq!(
            read_str(&mut store, &mut view, b"/a/b/f.txt"),
            "v2 - longer"
        );

        // Old ids still read the old versions.
        let mut out = [0u8; 64];
        let n = store.snapshot(file_v1, &mut out).unwrap();
        assert_eq!(&out[..n], b"v1");
        let mut old_dir = [empty_pentry(); MAX_FILES];
        let n_old = view
            .snapshot_dir(&mut store, root_v1, &mut old_dir)
            .unwrap();
        assert_eq!(n_old, n_root_v1, "old root dir block still decodes");
        assert!(old_dir[..n_old].iter().any(|e| e.name.matches(b"a")));
    }

    #[test]
    fn treeview_unlink_and_rmdir_enforce_emptiness_and_existence() {
        let _g = crate::kernel_state_guard();
        let (mut store, mut view) = tree_world();
        assert!(view.mkdir(&mut store, b"/d", MODE_DIR));
        assert!(view.create_file(&mut store, b"/d/x.txt", MODE_FILE));
        assert!(view.write_file(&mut store, b"/d/x.txt", b"x"));

        // rmdir of a non-empty dir refused.
        assert!(!view.rmdir(&mut store, b"/d"));
        // unlink a missing file refused.
        assert!(!view.unlink(&mut store, b"/d/missing.txt"));
        assert!(view.unlink(&mut store, b"/d/x.txt"));
        assert!(view.rmdir(&mut store, b"/d"));
        assert!(!view.stat(&mut store, b"/d").is_some(), "dir is gone");
        assert_eq!(
            view.list(&mut store, b"/", &mut [empty_pentry(); MAX_FILES])
                .unwrap(),
            0
        );

        // The root itself cannot be removed.
        assert!(!view.rmdir(&mut store, b"/"));
        assert!(view.stat(&mut store, b"/").is_some());
    }

    #[test]
    fn treeview_relationship_index_rebuilds_after_nested_ops() {
        let _g = crate::kernel_state_guard();
        let (mut store, mut view) = tree_world();
        let root_v0 = view.root();
        assert!(view.mkdir(&mut store, b"/home", MODE_DIR));
        assert!(view.mkdir(&mut store, b"/home/alice", MODE_DIR));
        assert!(view.create_file(&mut store, b"/home/alice/a.txt", MODE_FILE));
        let file_v0 = view.node_of(&mut store, b"/home/alice/a.txt").unwrap();
        assert!(view.write_file(&mut store, b"/home/alice/a.txt", b"body"));
        let file_v1 = view.node_of(&mut store, b"/home/alice/a.txt").unwrap();
        assert!(view.write_file(&mut store, b"/home/alice/a.txt", b"body two"));
        let file_v2 = view.node_of(&mut store, b"/home/alice/a.txt").unwrap();

        let mut idx = RelationshipIndex::new();
        idx.ingest(store.wal());
        assert_eq!(idx.consumed_seq(), store.wal().len() as u64);
        // COW version chains are derived-from edges in the graph: the root's
        // latest version derives from its first, and each file write chains
        // off the previous file version.
        assert!(idx.is_derived_from(root_v0, view.root()));
        assert!(idx.is_derived_from(file_v0, file_v1));
        assert!(idx.is_derived_from(file_v0, file_v2));

        let mut fresh = RelationshipIndex::new();
        fresh.rebuild(store.wal());
        assert_eq!(fresh.node_count(), idx.node_count());
        assert_eq!(fresh.block_count(), idx.block_count());
        assert_eq!(fresh.consumed_seq(), idx.consumed_seq());
        assert!(fresh.is_derived_from(root_v0, view.root()));
    }

    #[test]
    fn treeview_entries_respect_the_bounds() {
        let _g = crate::kernel_state_guard();
        let (mut store, mut view) = tree_world();
        // MAX_FILES per dir.
        for i in 0..MAX_FILES {
            let name = format!("f{i}.txt");
            assert!(
                view.create_file(&mut store, name.as_bytes(), MODE_FILE),
                "file {i}"
            );
        }
        assert!(!view.create_file(&mut store, b"overflow.txt", MODE_FILE));
        assert_eq!(
            view.list(&mut store, b"/", &mut [empty_pentry(); MAX_FILES])
                .unwrap(),
            MAX_FILES
        );

        // Depth bound: more than MAX_DEPTH components is refused up front.
        assert!(split_path(b"/a/b/c/d/e/f/g/h/i").is_none());
        // NUL bytes are refused outright.
        assert!(!view.create_file(&mut store, b"bad\0name", MODE_FILE));
    }
}

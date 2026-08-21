//! Track 1 foundation (Phase RoleLib): a versioned object store.
//!
//! This is the missing data substrate the §9 delegation task
//! *"summarize what changed in this object-store subtree since a given
//! point"* needs. The kernel's capability model (`cap.rs`) has no object
//! capability today and `object_graph.rs` is an in-memory relationship graph
//! with no change history — so before any role can be granted over "a subtree",
//! the store itself must exist with versioning and a subtree-diff query.
//!
//! Scope of THIS module (honest closed/reduced):
//! - **Closed:** create objects in a tree (parent links), append versions
//!   (monotonic per-object + global sequence), enumerate a subtree by BFS, and
//!   summarize what changed in that subtree since a sequence number — total
//!   and pure, no allocation beyond fixed arrays, no panics.
//! - **Reduced (noted, do more later):** only a per-object version *count* and
//!   *last* sequence are retained, not full content history, so
//!   `subtree_changed_since` reports *whether* and *how much* each object
//!   changed (version count + current size), not a byte-level diff. A later
//!   increment can keep a bounded ring of recent versions if a finer diff is
//!   wanted. No persistence (NVMe) yet — the store is in-memory; wiring it to
//!   `nvme_store` is a separate increment.
//! - **Inherent:** bounded to `MAX_OBJECTS` objects (fixed array), matching the
//!   kernel's other fixed-capacity tables; this is a deliberate small-TCB
//!   choice, not a gap to paper over.

pub type ObjId = u64;

/// Maximum objects the store holds (fixed array — small TCB, like the rest of
/// the kernel's tables).
pub const MAX_OBJECTS: usize = 64;

/// One stored object: identity, tree position, and a rolling version summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Object {
    pub id: ObjId,
    pub parent: Option<ObjId>,
    pub cur_len: usize,
    pub cur_hash: u32,
    pub first_seq: u64,
    pub last_seq: u64,
    pub versions: u64,
}

/// A single object's change record, the unit the "summarize changes" task
/// emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change {
    pub id: ObjId,
    /// Versions appended at or after `since_seq` (0 if unchanged since).
    pub versions_since: u64,
    pub cur_len: usize,
    pub prev_len: usize,
}

/// Result of a subtree-changed-since query. An object counts as changed iff
/// its `last_seq > since_seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubtreeDiff {
    pub root: ObjId,
    pub since_seq: u64,
    pub members: u32,
    pub changed_count: u32,
    pub changed: [Change; MAX_OBJECTS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjStore {
    objects: [Option<Object>; MAX_OBJECTS],
    count: usize,
    /// Global, monotonically increasing version counter.
    seq: u64,
}

impl ObjStore {
    pub fn new() -> Self {
        Self {
            objects: [None; MAX_OBJECTS],
            count: 0,
            seq: 0,
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    fn slot_of(&self, id: ObjId) -> Option<usize> {
        self.objects
            .iter()
            .position(|s| s.as_ref().is_some_and(|o| o.id == id))
    }

    /// Create an object with an optional parent (forming a tree). Errors if
    /// the table is full or the parent does not exist.
    pub fn create(&mut self, id: ObjId, parent: Option<ObjId>) -> Result<(), &'static str> {
        if self.slot_of(id).is_some() {
            return Err("object id already exists");
        }
        if self.count >= MAX_OBJECTS {
            return Err("store full");
        }
        if let Some(p) = parent {
            if self.slot_of(p).is_none() {
                return Err("parent does not exist");
            }
        }
        self.objects[self.count] = Some(Object {
            id,
            parent,
            cur_len: 0,
            cur_hash: 0,
            first_seq: 0,
            last_seq: 0,
            versions: 0,
        });
        self.count += 1;
        Ok(())
    }

    /// Append a new version of `id` with the given content summary. Bumps the
    /// global sequence and this object's version count. Errors on unknown id.
    pub fn write(&mut self, id: ObjId, len: usize, hash: u32) -> Result<u64, &'static str> {
        let slot = match self.slot_of(id) {
            Some(s) => s,
            None => return Err("unknown object"),
        };
        self.seq += 1;
        let seq = self.seq;
        let obj = self.objects[slot].as_mut().unwrap();
        if obj.versions == 0 {
            obj.first_seq = seq;
        }
        obj.last_seq = seq;
        obj.versions += 1;
        obj.cur_len = len;
        obj.cur_hash = hash;
        Ok(seq)
    }

    pub fn get(&self, id: ObjId) -> Option<&Object> {
        self.slot_of(id).and_then(|s| self.objects[s].as_ref())
    }

    /// Subtree membership by BFS over parent links. Returns the root itself
    /// plus every descendant. Bounded to `MAX_OBJECTS` entries.
    pub fn subtree_members(&self, root: ObjId) -> [ObjId; MAX_OBJECTS] {
        let mut out = [0u64; MAX_OBJECTS];
        let mut n = 0usize;
        if self.slot_of(root).is_none() {
            return out;
        }
        out[n] = root;
        n += 1;
        let mut frontier = 0usize;
        while frontier < n {
            let cur = out[frontier];
            frontier += 1;
            for s in self.objects.iter().flatten() {
                if s.parent == Some(cur) && n < MAX_OBJECTS && !out[..n].contains(&s.id) {
                    out[n] = s.id;
                    n += 1;
                }
            }
        }
        out
    }

    /// Summarize what changed in `root`'s subtree since `since_seq`. An object
    /// counts as changed iff its `last_seq > since_seq`; `versions_since` is
    /// this object's full version count when changed (the store retains only a
    /// count, not per-sequence history — see module "Reduced" note).
    pub fn subtree_changed_since(&self, root: ObjId, since_seq: u64) -> SubtreeDiff {
        let mut diff = SubtreeDiff {
            root,
            since_seq,
            members: 0,
            changed_count: 0,
            changed: [Change {
                id: 0,
                versions_since: 0,
                cur_len: 0,
                prev_len: 0,
            }; MAX_OBJECTS],
        };
        let members = self.subtree_members(root);
        for &m in members.iter() {
            if m == 0 {
                continue;
            }
            diff.members += 1;
            if let Some(o) = self.get(m) {
                if o.last_seq > since_seq {
                    let idx = diff.changed_count as usize;
                    if idx < MAX_OBJECTS {
                        diff.changed[idx] = Change {
                            id: m,
                            versions_since: o.versions,
                            cur_len: o.cur_len,
                            prev_len: 0,
                        };
                        diff.changed_count += 1;
                    }
                }
            }
        }
        diff
    }
}

impl Default for ObjStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(s: &str) -> u32 {
        let mut h: u32 = 0;
        for b in s.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u32);
        }
        h
    }

    #[test]
    fn create_and_write_bumps_sequences() {
        let mut s = ObjStore::new();
        s.create(1, None).unwrap();
        let a = s.write(1, 10, hash_of("v1")).unwrap();
        let b = s.write(1, 20, hash_of("v2")).unwrap();
        assert!(b > a);
        assert_eq!(s.seq(), b);
        let o = s.get(1).unwrap();
        assert_eq!(o.versions, 2);
        assert_eq!(o.cur_len, 20);
        assert_eq!(o.last_seq, b);
        assert_eq!(o.first_seq, a);
    }

    #[test]
    fn create_rejects_unknown_parent_and_full() {
        let mut s = ObjStore::new();
        assert_eq!(s.create(2, Some(99)), Err("parent does not exist"));
        for i in 0..MAX_OBJECTS as u64 {
            s.create(i, None).unwrap();
        }
        assert_eq!(s.create(999, None), Err("store full"));
        // re-create existing id rejected
        assert_eq!(s.create(0, None), Err("object id already exists"));
    }

    #[test]
    fn write_unknown_object_fails() {
        let mut s = ObjStore::new();
        assert_eq!(s.write(7, 1, 0), Err("unknown object"));
    }

    #[test]
    fn subtree_members_walks_tree() {
        let mut s = ObjStore::new();
        s.create(1, None).unwrap();
        s.create(2, Some(1)).unwrap();
        s.create(3, Some(1)).unwrap();
        s.create(4, Some(2)).unwrap();
        let m = s.subtree_members(1);
        let set: std::collections::BTreeSet<u64> = m.iter().copied().filter(|&x| x != 0).collect();
        assert_eq!(set, [1u64, 2, 3, 4].into_iter().collect());
        // subtree of a leaf is just itself
        let leaf = s.subtree_members(4);
        assert_eq!(leaf[0], 4);
        assert_eq!(leaf[1], 0);
        // unknown root -> empty
        assert_eq!(s.subtree_members(42)[0], 0);
    }

    #[test]
    fn subtree_changed_since_reports_only_newer() {
        let mut s = ObjStore::new();
        s.create(1, None).unwrap();
        s.create(2, Some(1)).unwrap();
        s.create(3, Some(1)).unwrap();
        let w1 = s.write(2, 10, hash_of("a")).unwrap(); // seq 1
        let _w2 = s.write(3, 5, hash_of("b")).unwrap(); // seq 2
                                                        // since before any write -> both changed
        let d = s.subtree_changed_since(1, 0);
        assert_eq!(d.members, 3);
        assert_eq!(d.changed_count, 2);
        // since after w1 -> only object 3 (written at seq 2) changed
        let d2 = s.subtree_changed_since(1, w1);
        assert_eq!(d2.changed_count, 1);
        assert_eq!(d2.changed[0].id, 3);
        assert_eq!(d2.changed[0].versions_since, 1);
        // unknown root -> no members, no changes
        let d3 = s.subtree_changed_since(99, 0);
        assert_eq!(d3.members, 0);
        assert_eq!(d3.changed_count, 0);
    }
}

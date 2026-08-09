//! The relationship index (design doc §8 "graph as index, not ground truth").
//! A rebuildable cache over the store's write-ahead log: it learns *only* from
//! `Wal` records, after the fact, never from commits. Its correctness is not
//! load-bearing: losing it costs search/relationship queries, never data.

use crate::store::{BlockId, Wal, WalOp};
use std::collections::{BTreeMap, BTreeSet};

/// One machine's relationship graph. Parent->children edges come from COW
/// derivation (Link records); blocks are counted so "what exists" is answerable.
#[derive(Debug, Default)]
pub struct RelationshipIndex {
    children: BTreeMap<u64, Vec<u64>>,
    nodes: BTreeSet<u64>,
    blocks: BTreeSet<BlockId>,
    consumed: u64,
}

impl RelationshipIndex {
    pub fn new() -> RelationshipIndex {
        RelationshipIndex::default()
    }

    /// Consume every WAL record up to and including the log's current end.
    /// Async by construction: whatever the index has not yet consumed, the store
    /// has already committed without waiting for it.
    pub fn ingest(&mut self, wal: &Wal) {
        for rec in wal.recs() {
            if rec.seq <= self.consumed {
                continue;
            }
            match &rec.op {
                WalOp::Put { id, .. } => {
                    self.blocks.insert(*id);
                }
                WalOp::Link { child, parent } => {
                    self.nodes.insert(*child);
                    self.nodes.insert(*parent);
                    self.children.entry(*parent).or_default().push(*child);
                }
            }
            self.consumed = rec.seq;
        }
    }

    /// Drop everything and re-derive purely from the log (the WinFS-proof
    /// property: the index is disposable).
    pub fn rebuild(&mut self, wal: &Wal) {
        self.children.clear();
        self.nodes.clear();
        self.blocks.clear();
        self.consumed = 0;
        self.ingest(wal);
    }

    pub fn consumed_seq(&self) -> u64 {
        self.consumed
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Direct children of `parent` (object ids).
    pub fn children_of(&self, parent: u64) -> Vec<u64> {
        self.children
            .get(&parent)
            .cloned()
            .unwrap_or_default()
    }

    /// Is `node` reachable from `ancestor` through derivation edges? (BFS)
    pub fn is_derived_from(&self, ancestor: u64, node: u64) -> bool {
        if ancestor == node {
            return true;
        }
        let mut seen = BTreeSet::new();
        let mut stack = vec![node];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            for (p, kids) in &self.children {
                if kids.contains(&cur) && *p == ancestor {
                    return true;
                }
                if kids.contains(&cur) {
                    stack.push(*p);
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_rebuilds_identically_from_the_log() {
        let mut wal = Wal::default();
        let mut recs = Vec::new();
        let mut seq = 0u64;
        seq += 1;
        recs.push(crate::store::WalRec {
            seq,
            op: WalOp::Put { id: [1u8; 32], len: 5 },
        });
        seq += 1;
        recs.push(crate::store::WalRec {
            seq,
            op: WalOp::Link { child: 9, parent: 7 },
        });
        for r in recs {
            wal.push(r);
        }

        let mut idx = RelationshipIndex::new();
        idx.ingest(&wal);
        let count = idx.node_count();
        let edges = idx.children_of(7);
        assert_eq!(count, 2);
        assert_eq!(edges, vec![9]);

        // Drop and rebuild: identical graph, purely from the log.
        idx.rebuild(&wal);
        assert_eq!(idx.node_count(), count);
        assert_eq!(idx.children_of(7), edges);
    }
}
//! Capability-addressed object store: content-addressed immutable blocks over
//! kernel regions, a COW layer for mutable data, a POSIX file-view projection,
//! and a rebuildable relationship index that consumes only the write-ahead log.
//! Design doc §8 Storage; the §10 [CLOSED] "index cannot block a write" contract.

pub mod index;
pub mod sha256;
mod store;

pub use index::RelationshipIndex;
pub use store::{sha256, BlockId, FlatView, Store, Wal, WalOp, WalRec};
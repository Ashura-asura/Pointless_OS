//! Kernel capability type. A capability is an unforgeable reference to a kernel
//! object (endpoint, task, or memory region) carried in a task's capability
//! table, together with a fixed rights set. This is the only authority token the
//! kernel understands — there is no ambient authority, no UID/root.
//!
//! Phase 1 (capability-aware IPC): a slot is now `(Cap, Rights)` — the object
//! kind is explicit (`Endpoint`, `Task`, `MemRegion`) and every IPC entry point
//! checks the caller's rights on the referenced capability (`ipc_call` requires
//! SEND, `ipc_serve`/`ipc_reply` require RECV, `ipc_cap_grant` requires GRANT).
//! The kernel enforces at delivery time; it never trusts the caller to state its
//! own authority.
//!
//! Honest limits: this is a teaching kernel, not a formally-verified seL4-class
//! microkernel. Capabilities are records in a per-task slot array; they are not
//! cryptographically sealed, and there is no revocation tree yet (phase 1 adds
//! rights, not grant-root chains). The capability *mechanism* is real; the
//! isolation guarantees that would make it meaningful are a later phase.

use crate::tasks::MAX_CAPS;

/// Capability rights. A rights set is a monotone quantity over the delegation
/// graph: a granted/copied capability always carries a subset of its source's
/// rights (spec invariants I2/I3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rights(u8);

impl Rights {
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const CONTROL: Rights = Rights(1 << 2);
    pub const SEND: Rights = Rights(1 << 3);
    pub const RECV: Rights = Rights(1 << 4);
    pub const GRANT: Rights = Rights(1 << 5);

    pub const NONE: Rights = Rights(0);
    pub const ALL: Rights = Rights(0b0011_1111);

    /// True iff `self` grants everything `other` does.
    pub const fn contains(self, other: Rights) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set intersection: the rights both caps carry (I2 clamping).
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    /// Set union.
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }
}

impl core::fmt::Display for Rights {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut any = false;
        for (bit, name) in [
            (Self::READ, 'R'),
            (Self::WRITE, 'W'),
            (Self::CONTROL, 'C'),
            (Self::SEND, 'S'),
            (Self::RECV, 'V'),
            (Self::GRANT, 'G'),
        ] {
            if self.contains(bit) {
                write!(f, "{name}")?;
                any = true;
            }
        }
        if !any {
            write!(f, "-")?;
        }
        Ok(())
    }
}

/// A kernel-object reference held in a task's capability table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cap {
    None,
    /// Reference to an IPC endpoint with the given id.
    Endpoint(u32),
    /// Reference to a task (execution context) with the given id.
    Task(u32),
    /// Reference to a memory region with the given id.
    MemRegion(u32),
    /// Reference to an asynchronous message channel (FIFO box) with the given
    /// id. The design's second IPC primitive (§8: an async notification/queue
    /// primitive besides the synchronous rendezvous endpoint); the loopback
    /// netstack's sockets ARE these objects.
    Channel(u32),
}

/// One occupied row of a capability table: the object and the rights held on it.
/// `Cap::None` with `Rights::NONE` is an empty slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CapSlot {
    pub cap: Cap,
    pub rights: Rights,
}

impl CapSlot {
    /// An empty slot: no object, no rights.
    pub const fn empty() -> CapSlot {
        CapSlot {
            cap: Cap::None,
            rights: Rights::NONE,
        }
    }
}

impl Cap {
    /// The object id a non-`None` cap names, if any. Used by the audit log to
    /// attribute the target of an operation.
    pub fn id(self) -> Option<u32> {
        match self {
            Cap::None => None,
            Cap::Endpoint(id) => Some(id),
            Cap::Task(id) => Some(id),
            Cap::MemRegion(id) => Some(id),
            Cap::Channel(id) => Some(id),
        }
    }
}

/// A task's capability table: a fixed slot array.
pub type CapTable = [CapSlot; MAX_CAPS];

/// Build an empty capability table.
pub const fn new_cap_table() -> CapTable {
    [CapSlot::empty(); MAX_CAPS]
}

/// The rights a fresh endpoint capability grants its holder (SEND/RECV to use
/// the mailbox, GRANT to delegate it onward). Mirrors the model crate's
/// `create_endpoint`.
pub const ENDPOINT_RIGHTS: Rights = Rights::SEND.union(Rights::RECV).union(Rights::GRANT);

/// The rights a fresh channel capability grants its holder (SEND/RECV to push
/// and pop messages; a channel is minted without GRANT — the netstack narrows
/// copies into subscriber CSpaces as SEND|RECV, and nothing may delegate a
/// channel onward). Mirrors the model's socket channel.
pub const CHANNEL_RIGHTS: Rights = Rights::SEND.union(Rights::RECV);

/// The rights a fresh memory-region capability grants its holder (READ/WRITE
/// to touch the frames, GRANT to delegate it onward). Mirrors the model
/// crate's `create_mem`.
pub const MEM_RIGHTS: Rights = Rights::READ.union(Rights::WRITE).union(Rights::GRANT);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slot_is_no_object_no_rights() {
        let s = CapSlot::empty();
        assert_eq!(s.cap, Cap::None);
        assert_eq!(s.rights, Rights::NONE);
    }

    #[test]
    fn new_cap_table_is_all_empty() {
        let t = new_cap_table();
        assert_eq!(t.len(), MAX_CAPS);
        assert!(t
            .iter()
            .all(|s| s.cap == Cap::None && s.rights == Rights::NONE));
    }

    #[test]
    fn rights_contains_is_subset_semantics() {
        let full = Rights::ALL;
        assert!(full.contains(Rights::SEND));
        assert!(full.contains(full));
        assert!(full.contains(Rights::NONE));
        assert!(!Rights::SEND.contains(Rights::RECV));
        assert!(!Rights::SEND.contains(full));
    }

    #[test]
    fn rights_intersect_narrows_and_union_grows() {
        let sr = Rights::SEND.union(Rights::RECV);
        let rv = Rights::RECV.union(Rights::GRANT);
        assert_eq!(sr.intersect(rv), Rights::RECV);
        assert_eq!(
            sr.union(rv),
            Rights::SEND.union(Rights::RECV).union(Rights::GRANT)
        );
        // I2: a narrowed copy never gains rights.
        assert!(sr.intersect(rv).contains(sr.intersect(rv)));
        assert!(!sr.intersect(rv).contains(Rights::SEND));
    }

    #[test]
    fn endpoint_rights_are_the_mailbox_role() {
        assert!(ENDPOINT_RIGHTS.contains(Rights::SEND));
        assert!(ENDPOINT_RIGHTS.contains(Rights::RECV));
        assert!(ENDPOINT_RIGHTS.contains(Rights::GRANT));
        assert!(!ENDPOINT_RIGHTS.contains(Rights::CONTROL));
    }

    #[test]
    fn mem_rights_are_the_region_role() {
        assert!(MEM_RIGHTS.contains(Rights::READ));
        assert!(MEM_RIGHTS.contains(Rights::WRITE));
        assert!(MEM_RIGHTS.contains(Rights::GRANT));
        assert!(!MEM_RIGHTS.contains(Rights::SEND));
        assert!(!MEM_RIGHTS.contains(Rights::CONTROL));
    }

    #[test]
    fn rights_display_names_bits() {
        assert_eq!(format!("{}", Rights::SEND.union(Rights::GRANT)), "SG");
        assert_eq!(format!("{}", Rights::NONE), "-");
        assert_eq!(format!("{}", Rights::ALL), "RWCSVG");
    }
}

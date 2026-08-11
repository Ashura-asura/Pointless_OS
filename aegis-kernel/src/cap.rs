//! Minimal kernel capability type. A capability is an unforgeable reference
//! to a kernel object (here: an IPC endpoint) carried in a task's capability
//! table. This is the only authority token the kernel understands — there is
//! no ambient authority, no UID/root.
//!
//! Honest limits: this is a teaching kernel, not a formally-verified
//! seL4-class microkernel. Capabilities are integers in a per-task table;
//! they are not cryptographically sealed, and there is no per-process address
//! space yet (all tasks share the identity map), so a malicious task could
//! still read kernel memory. The capability *mechanism* is real; the
//! isolation guarantees that would make it meaningful are a later phase.

use crate::tasks::MAX_CAPS;

/// A kernel-object reference held in a task's capability table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    None,
    /// Reference to endpoint with the given id.
    Endpoint(u32),
}

/// A task's capability table: a fixed slot array.
pub type CapTable = [Cap; MAX_CAPS];

/// Build an empty capability table.
pub const fn new_cap_table() -> CapTable {
    [Cap::None; MAX_CAPS]
}

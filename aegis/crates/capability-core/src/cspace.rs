//! Per-task capability table (CSpace). Kernel-owned: no code outside the kernel module
//! can construct, read, or mutate a slot. A task names capabilities only by slot index
//! (`CapHandle`); an index resolves exclusively against the *caller's own* CSpace, so a
//! fabricated index either points at the caller's own slot or fails (invariant I1).

use crate::error::{KernelError, KernelResult};
use crate::objects::{CapId, ObjectId};
use crate::rights::Rights;

/// An untrusted index into the caller's own CSpace. Constructible by anyone — that is
/// safe, because the kernel resolves it against the *caller*'s table, never anyone
/// else's. (This mirrors how a real microkernel treats userspace capability pointers.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapHandle(pub u32);

impl CapHandle {
    pub const INVALID: CapHandle = CapHandle(u32::MAX);
}

/// A live capability instance as stored in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapInstance {
    pub obj: ObjectId,
    pub rights: Rights,
    /// The capability this one was derived from (None for minted-fresh caps).
    pub parent: Option<CapId>,
    /// Death of this cap: `Some(t)` means the cap is unusable once the kernel clock
    /// passes `t`. Inherited by all descendants, never extendible (I5).
    pub expires_at: Option<u64>,
}

/// Fixed-size slot table per task.
pub(crate) struct CSpace {
    slots: Vec<Option<CapInstance>>,
}

impl CSpace {
    pub const SLOTS: usize = 256;

    pub fn new() -> CSpace {
        CSpace {
            slots: vec![None; Self::SLOTS],
        }
    }

    /// Place `cap` into the first free slot.
    pub fn insert(&mut self, cap: CapInstance) -> KernelResult<u32> {
        if let Some(i) = self.slots.iter().position(|s| s.is_none()) {
            self.slots[i] = Some(cap);
            Ok(i as u32)
        } else {
            Err(KernelError::CspaceFull)
        }
    }

    pub fn get(&self, slot: u32) -> Option<&CapInstance> {
        self.slots.get(slot as usize).and_then(|s| s.as_ref())
    }

    /// Remove the cap in `slot` and return it, if any.
    pub fn take(&mut self, slot: u32) -> Option<CapInstance> {
        let slotref = self.slots.get_mut(slot as usize)?;
        slotref.take()
    }

    /// Iterate all occupied slots: (slot, cap).
    pub fn iter(&self) -> impl Iterator<Item = (u32, &CapInstance)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|c| (i as u32, c)))
    }
}

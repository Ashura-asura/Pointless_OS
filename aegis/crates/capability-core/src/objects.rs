//! Kernel object types. Object ids are kernel-owned names: they are a plain counter
//! (see spec §5.3 — authority does not rest on nonce secrecy; it rests on the fact that
//! an id alone grants nothing: you still need a slot in your own CSpace, and slots are
//! kernel-owned state that only kernel ops may touch).

use std::collections::VecDeque;

/// Kernel-only capability id. Distinguishes *capability instances* (derivation nodes),
/// not objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapId(u64);

impl CapId {
    pub(crate) fn from_raw(raw: u64) -> CapId {
        CapId(raw)
    }
}

/// Kernel-only object id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(u64);

impl ObjectId {
    /// The numeric form of the id, for persistence/serialization into object
    /// bytes (the id alone grants nothing — see module docs).
    pub fn as_u64(self) -> u64 {
        self.0
    }

    pub fn from_raw(raw: u64) -> ObjectId {
        ObjectId(raw)
    }
}

/// What kind of object a capability refers to — used for introspection and error
/// reporting, never as an authority check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObjectKind {
    Task,
    Endpoint,
    MemRegion,
    GrantRoot,
    /// Creation cap: without one you cannot create new kernel objects (mirrors untyped
    /// caps in seL4; the design doc's "boot-time capability delegated downward").
    Creator,
}

impl core::fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ObjectKind::Task => write!(f, "task"),
            ObjectKind::Endpoint => write!(f, "endpoint"),
            ObjectKind::MemRegion => write!(f, "mem-region"),
            ObjectKind::GrantRoot => write!(f, "grant-root"),
            ObjectKind::Creator => write!(f, "creator"),
        }
    }
}

/// A message exchanged over an endpoint. The real design moves capability *grants*
/// through IPC; in this model the transfer of authority is the separate `grant` kernel
/// op (the capability is never inside the message bytes — that is the point).
pub type Message = Vec<u8>;

pub(crate) struct TaskObj {
    pub label: String,
    pub running: bool,
}

pub(crate) struct EndpointObj {
    pub queue: VecDeque<Message>,
}

pub(crate) struct MemRegionObj {
    pub data: Vec<u8>,
}

/// GrantRoot: the anchor node for a grant. All caps minted under a grant are its
/// descendants; revoking the root removes every one of them from every CSpace (I4).
pub(crate) struct GrantRootObj;

/// Creator: the right to create new kernel objects. Minted into the root task at
/// boot; delegated downward; never granted by a role.
pub(crate) struct CreatorObj;

pub(crate) enum Object {
    Task(TaskObj),
    Endpoint(EndpointObj),
    MemRegion(MemRegionObj),
    GrantRoot(GrantRootObj),
    Creator(CreatorObj),
}

impl Object {
    pub fn kind(&self) -> ObjectKind {
        match self {
            Object::Task(_) => ObjectKind::Task,
            Object::Endpoint(_) => ObjectKind::Endpoint,
            Object::MemRegion(_) => ObjectKind::MemRegion,
            Object::GrantRoot(_) => ObjectKind::GrantRoot,
            Object::Creator(_) => ObjectKind::Creator,
        }
    }
}

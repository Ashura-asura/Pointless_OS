//! Aegis capability model — executable reference for `../../../../../Docs/spec/capability-model.md`.
//!
//! Design doc: `../../../../../Docs/os-from-first-principles.md`, Phases 0–1.
//! The kernel is the boundary: everything in this crate outside `kernel::Kernel` is
//! either a pure type or a test.

pub mod audit;
pub mod batch;
pub mod cspace;
pub mod error;
pub mod kernel;
pub mod objects;
pub mod rights;

pub use audit::{AuditFilter, AuditLog, AuditRecord, OpKind};
pub use batch::{BatchEntry, BatchResult};
pub use cspace::CapHandle;
pub use error::{KernelError, KernelResult};
pub use kernel::{AuthorizedCap, CapInfo, CapView, Kernel, TaskHandle};
pub use objects::{Message, ObjectId, ObjectKind};
pub use rights::Rights;

//! The reachable-authority auditor (design doc §10 [CLOSED] "TCB creep").
//!
//! Every service ships a capability manifest declaring the (object kind, rights)
//! pairs it may ever hold. The auditor computes the authority a task actually holds
//! from the kernel state and fails the build on any pair the manifest did not
//! declare; it also refuses kernel-equivalent capability requests from any
//! repository other than the kernel/bootloader one. This is the mechanism that turns
//! "keep AI/drivers/compat layers out of the TCB" from a promise into a build
//! failure.
//!
//! # Checked quantities (honesty notes)
//!
//! - **Reachable authority** is *holdings*: the pairs a task currently holds and can
//!   exercise (own CSpace, liveness-filtered by the kernel), with the task's own
//!   mandatory self cap treated as structural infrastructure rather than declared
//!   authority (a task may always control its own lifecycle; it confers nothing
//!   outside the task).
//! - **Delivery overhang** (a warning, not a violation): if a grantor holds a GRANT
//!   right on a cap naming a task, it *could* push copies of everything it holds
//!   into that task's table. The auditor warns when that theoretical ceiling exceeds
//!   the target's manifest. It is a warning because the ceiling is latent — the
//!   exercised set stays manifest-bounded (I2/I6 narrow every actual delivery).
//! - **Kernel-equivalent capability**: naming `Creator`/`GrantRoot`, or full rights.
//!   Only a kernel-repo manifest may declare it.

pub mod audit;
pub mod manifest;
pub mod manifests;
pub mod reach;

pub use audit::{AuditReport, AuditWarning, Violation};
pub use manifest::{Declared, Manifest, Repo};
pub use reach::{delivery_edges, holdings, snapshot};

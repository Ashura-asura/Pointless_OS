//! Kernel error type. Every op returns exactly one of these or a value; a failed op
//! never mutates state and is always recorded in the audit log.

use crate::rights::Rights;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    /// The slot does not contain a cap (or the slot number is out of range).
    NoCap,
    /// The cap exists but is not authorized for this caller right now
    /// (wrong rights, or an ephemeral grant that has expired).
    InsufficientRights(Rights),
    /// Operation requires a right the caller does not hold on this cap.
    CapExpired,
    /// Wrong object type for the operation (e.g. sending on a MemRegion cap).
    WrongObjectType,
    /// Objects referenced by id could not be found (forgery attempt or dangling ref).
    NoSuchObject,
    /// Creation attempted without holding a Creator cap.
    NoCreationRight,
    /// Revoking a grant root that is not a grant root, etc.
    InvalidOperation,
    /// A cap has no more free slots in the destination CSpace.
    CspaceFull,
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::NoCap => write!(f, "no capability in slot"),
            KernelError::InsufficientRights(r) => {
                write!(f, "insufficient rights (need {r})")
            }
            KernelError::CapExpired => write!(f, "capability has expired"),
            KernelError::WrongObjectType => write!(f, "wrong object type"),
            KernelError::NoSuchObject => write!(f, "no such object"),
            KernelError::NoCreationRight => write!(f, "no creation right held"),
            KernelError::InvalidOperation => write!(f, "invalid operation"),
            KernelError::CspaceFull => write!(f, "destination cspace is full"),
        }
    }
}

impl std::error::Error for KernelError {}

pub type KernelResult<T> = Result<T, KernelError>;
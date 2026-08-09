//! The batched-submission types (the io_uring pattern from the design doc:
//! "submit many operations, one kernel crossing, collect results
//! asynchronously"). The submission carries many entries; the kernel crossing
//! is one audited Batch record; every entry still passes the caller's own
//! capability checks, and results come back per entry, in submission order.

use crate::cspace::CapHandle;
use crate::error::KernelError;

/// One operation in a submission queue. Capabilities are referenced by the
/// caller's own slot numbers: batching the crossing never removes the
/// per-operation capability mediation.
#[derive(Debug, Clone)]
pub enum BatchEntry {
    MemRead {
        region: CapHandle,
        offset: usize,
        len: usize,
    },
    MemWrite {
        region: CapHandle,
        offset: usize,
        bytes: Vec<u8>,
    },
}

/// One slot of the completion queue, in submission order.
#[derive(Debug, Clone, PartialEq)]
pub enum BatchResult {
    Read(Vec<u8>),
    Write,
    Failed(KernelError),
}
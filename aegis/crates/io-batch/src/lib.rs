//! Batched submission queues — the io_uring pattern from the design doc:
//! "submit many operations, one kernel crossing, collect results
//! asynchronously" for high-frequency operations like file I/O.
//!
//! The submission queue accumulates operations on the caller's side at zero
//! kernel cost; the crossing happens once, when the queue is submitted. The
//! kernel executes every entry against the caller's own CSpace with the full
//! per-operation capability checks (batching the crossing, never the
//! authorization) and produces one completion queue with per-entry results in
//! submission order. The caller drains completions at its own pace — that
//! isolation between accumulating submissions and reading completions is the
//! "collect results asynchronously" half of the pattern; the kernel model
//! itself is synchronous (there is no interrupt system), so completions are
//! materialized at submit and drained later, never awaited.
//!
//! Honest limits: the "one kernel crossing" is one audited `Batch` record —
//! there is no real syscall boundary in this model, and the design doc's own
//! honesty clause holds here too: no parity with a bare syscall is claimed,
//! only that the crossing is O(1) instead of O(ops); entries are collected
//! and replayed in-process, with no hardware queue and no async completion
//! notification; and speed is measured in crossings, not wall time.

use capability_core::{CapHandle, Kernel, TaskHandle};

/// The batch types from the kernel: submissions are built from these, and
/// completions arrive as these.
pub use capability_core::{BatchEntry, BatchResult};

/// The submission queue: a caller-side accumulation of operations that costs
/// nothing at the kernel until `submit` is called.
#[derive(Debug, Default)]
pub struct SubmissionQueue {
    entries: Vec<BatchEntry>,
}

/// The completion queue: per-entry results in submission order, drained at
/// the caller's own pace.
#[derive(Debug)]
pub struct CompletionQueue {
    results: Vec<BatchResult>,
    drained: usize,
}

impl SubmissionQueue {
    pub fn new() -> SubmissionQueue {
        SubmissionQueue::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Queue a read from a region the caller holds (file I/O: a block read).
    pub fn read(&mut self, region: CapHandle, offset: usize, len: usize) -> &mut Self {
        self.entries.push(BatchEntry::MemRead {
            region,
            offset,
            len,
        });
        self
    }

    /// Queue a write into a region the caller holds (file I/O: a block
    /// write). Bounds and rights are re-checked by the kernel at execution.
    pub fn write(&mut self, region: CapHandle, offset: usize, bytes: Vec<u8>) -> &mut Self {
        self.entries.push(BatchEntry::MemWrite {
            region,
            offset,
            bytes,
        });
        self
    }

    /// The kernel crossing: drain the whole queue in one `batch_submit` call
    /// — one audited Batch record no matter how many entries — and hand back
    /// a completion queue with per-entry results in submission order.
    pub fn submit(&mut self, k: &mut Kernel, caller: TaskHandle) -> CompletionQueue {
        let entries = std::mem::take(&mut self.entries);
        let results = k.batch_submit(caller, entries).unwrap_or_default();
        CompletionQueue {
            results,
            drained: 0,
        }
    }
}

impl CompletionQueue {
    /// Peek the next unconsumed completion.
    pub fn peek(&self) -> Option<&BatchResult> {
        self.results.get(self.drained)
    }

    /// Collect one completion. Outstanding entries stay in the queue — the
    /// caller decides when to drain, which is the asynchronous half.
    pub fn collect(&mut self) -> Option<BatchResult> {
        let r = self.results.get(self.drained).cloned();
        if r.is_some() {
            self.drained += 1;
        }
        r
    }

    pub fn remaining(&self) -> usize {
        self.results.len() - self.drained
    }
}

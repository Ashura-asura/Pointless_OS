//! Executable checks for the batched-submission claim (the io_uring pattern:
//! "submit many operations, one kernel crossing, collect results
//! asynchronously"): N queued I/O operations cross the kernel exactly once —
//! one audited Batch record, zero individual records on the success path —
//! while every entry still passes the caller's own capability checks, and
//! failures land in the completion queue per entry, in submission order.

use capability_core::{AuditFilter, CapHandle, Kernel, OpKind, TaskHandle};
use io_batch::{BatchResult, SubmissionQueue};

fn boot() -> (Kernel, TaskHandle, CapHandle, CapHandle) {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("client").unwrap();
    let region = k.create_mem(root, creator, vec![0u8; 4096]).unwrap();
    (k, root, creator, region)
}

fn batch_records(k: &Kernel, caller: TaskHandle) -> Vec<(OpKind, bool, String)> {
    k.audit()
        .query(Some(caller.id()), AuditFilter::All)
        .filter(|r| r.op == OpKind::Batch)
        .map(|r| (r.op, r.ok, r.detail.clone()))
        .collect()
}

fn caller_ops(k: &Kernel, caller: TaskHandle, op: OpKind) -> usize {
    k.audit()
        .query(Some(caller.id()), AuditFilter::All)
        .filter(|r| r.op == op)
        .count()
}

#[test]
fn many_queued_operations_cross_the_kernel_once() {
    let (mut k, root, _, region) = boot();

    // A file-like workload: 64 mixed sector reads and writes, queued at zero
    // kernel cost, then submitted as one crossing.
    let mut sq = SubmissionQueue::new();
    for i in 0..32 {
        sq.write(region, i * 9, format!("sector-{i:02}").into_bytes());
    }
    for i in 0..32 {
        sq.read(region, i * 9, 9);
    }
    assert_eq!(sq.len(), 64);
    assert_eq!(
        caller_ops(&k, root, OpKind::Batch),
        0,
        "queued entries cost nothing"
    );

    let mut cq = sq.submit(&mut k, root);
    assert!(sq.is_empty(), "entries are consumed by the submission");

    // Exactly one kernel crossing: one Batch record, no individual
    // MemRead/MemWrite records from the queued entries.
    assert_eq!(batch_records(&k, root).len(), 1);
    assert_eq!(
        caller_ops(&k, root, OpKind::MemRead),
        0,
        "reads rode the one crossing"
    );
    assert_eq!(
        caller_ops(&k, root, OpKind::MemWrite),
        0,
        "writes rode the one crossing"
    );

    // Per-entry results, in submission order, drained at the caller's pace.
    assert_eq!(cq.remaining(), 64);
    for _ in 0..32 {
        assert_eq!(cq.collect(), Some(BatchResult::Write));
    }
    for i in 0..32 {
        let bytes = format!("sector-{i:02}").into_bytes();
        assert_eq!(cq.collect(), Some(BatchResult::Read(bytes)));
    }
    assert_eq!(cq.remaining(), 0);
    assert_eq!(cq.collect(), None, "queue is drained");

    // The one crossing really did the work: the region holds every entry's
    // effect, verified through ordinary single ops afterwards.
    let probe = k.mem_read(root, region, 9, 9).unwrap();
    assert_eq!(probe, "sector-01".as_bytes());
}

#[test]
fn capability_mediation_rides_every_entry_not_just_the_submission() {
    let (mut k, root, creator, region) = boot();
    let (intruder, intruder_cap) = k.create_task(root, creator, "intruder").unwrap();
    let _ = (intruder, intruder_cap);

    // The submission mixes a legal write with entries the caller never held:
    // an out-of-range read, a read of a capability slot it does not own, and
    // a write past the region end. The kernel mediates each one.
    let mut sq = SubmissionQueue::new();
    sq.write(region, 0, b"ok".to_vec());
    sq.write(region, 4090, vec![0u8; 16]); // exceeds the region: refused
    sq.write(region, 0, vec![0u8; 4097]); // past the end entirely: refused
    sq.read(intruder_cap, 0, 8); // a task-cap handle, not a region: refused

    let mut cq = sq.submit(&mut k, root);

    // The legal entry completed; every unlawful entry failed in its slot —
    // and none of the refused writes touched the region.
    assert_eq!(cq.collect(), Some(BatchResult::Write));
    assert!(matches!(cq.collect(), Some(BatchResult::Failed(_))));
    assert!(matches!(cq.collect(), Some(BatchResult::Failed(_))));
    assert!(matches!(cq.collect(), Some(BatchResult::Failed(_))));
    let probe = k.mem_read(root, region, 0, 2).unwrap();
    assert_eq!(probe, b"ok", "refused entries had zero effect");

    // Failures are exactly as visible as successes: one Batch record for the
    // crossing, plus one Failed record per refused entry — the kernel's own
    // refusals, not a silently swallowed completion.
    assert_eq!(batch_records(&k, root).len(), 1);
    assert_eq!(
        caller_ops(&k, root, OpKind::MemWrite),
        2,
        "the two refused writes are Failed records of their own kind"
    );
    assert!(k
        .audit()
        .query(Some(root.id()), AuditFilter::All)
        .any(|r| r.op == OpKind::MemWrite && !r.ok));
}

#[test]
fn completions_are_drained_apart_from_submission() {
    let (mut k, root, _, region) = boot();

    // Submission and completion are separate queues: ops accumulate while the
    // previous batch's completions are still in the completion queue.
    let mut sq = SubmissionQueue::new();
    sq.write(region, 0, b"one".to_vec());
    let mut cq = sq.submit(&mut k, root);

    sq.write(region, 3, b"two".to_vec());
    sq.write(region, 6, b"three".to_vec());
    // The first completion is still unconsumed when the second crossing
    // happens ("collect results asynchronously").
    let mut cq2 = sq.submit(&mut k, root);

    assert_eq!(cq.collect(), Some(BatchResult::Write));
    assert_eq!(cq2.collect(), Some(BatchResult::Write));
    assert_eq!(cq2.collect(), Some(BatchResult::Write));
    assert_eq!(cq2.remaining(), 0);

    // Two crossings, two Batch records — each submission is one, never one
    // per queued entry.
    assert_eq!(batch_records(&k, root).len(), 2);
    let text: Vec<u8> = b"one"
        .iter()
        .chain(b"two")
        .chain(b"three")
        .copied()
        .collect();
    assert_eq!(
        k.mem_read(root, region, 0, text.len()).unwrap().to_vec(),
        text
    );
}

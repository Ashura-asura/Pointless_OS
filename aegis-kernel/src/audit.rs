//! Kernel audit log (design doc §9: "classified as kernel truth"). Every gated
//! operation — successful or refused — appends one attributed record:
//! `(tick, caller, op, target, ok)`. This is what the behavioral anomaly
//! monitor (`monitor.rs`) reads: its baseline is the agent's *actual* usage as
//! attributed by the real gates, never a policy's opinion. It also closes the
//! Phase-5 honest limit ("the kernel keeps no audit log"): the netstack's every
//! hop through `ch_send_as`/`ch_recv_as` now lands here with the caller
//! attributed.
//!
//! Honest limits: a bounded in-memory ring (oldest records evicted, so the
//! histogram is over recent history only), one global kernel log rather than a
//! per-service ledger, and no durability. The op set is exactly what the kernel
//! gates record today (task lifecycle, channel send/recv, memory read/write,
//! delegation, revoke) — it will grow as gates do.

/// Bounded ring capacity: recent kernel truth, not history.
pub const MAX_AUDIT: usize = 512;

/// The attributed operation kinds the kernel records. Each one is emitted by a
/// real capability gate; there is no programmatic way for a task to write here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    /// `supervisor::task_state` (READ on a task cap).
    TaskState,
    /// `supervisor::task_kill` (CONTROL on a task cap).
    TaskKill,
    /// `supervisor::task_restart` (CONTROL on a task cap).
    TaskSpawn,
    /// `channel::ch_send_as` (SEND on a channel cap).
    Send,
    /// `channel::ch_recv_as` (RECV on a channel cap).
    Recv,
    /// `mem::mem_read` (READ on a region cap).
    MemRead,
    /// `mem::mem_write` (WRITE on a region cap).
    MemWrite,
    /// `supervisor::revoke_slot` (GRANT on the source cap).
    Revoke,
    /// `ipc::ipc_cap_grant` (GRANT on the source slot). Also the first gate the
    /// suspension ledger freezes: a suspended agent cannot delegate onward.
    Grant,
    /// `role::role_grant` (grantor holds the role's exact rights over the
    /// target). Every role grant — approved and refused — lands here with the
    /// target task attributed; this is the append-only trail the Phase 6 grant
    /// flow is built on.
    RoleGrant,
}

impl OpKind {
    /// Count of variants — the histogram width.
    pub const COUNT: usize = 10;

    /// Stable index for fixed-size histograms.
    pub fn index(self) -> usize {
        match self {
            OpKind::TaskState => 0,
            OpKind::TaskKill => 1,
            OpKind::TaskSpawn => 2,
            OpKind::Send => 3,
            OpKind::Recv => 4,
            OpKind::MemRead => 5,
            OpKind::MemWrite => 6,
            OpKind::Revoke => 7,
            OpKind::Grant => 8,
            OpKind::RoleGrant => 9,
        }
    }

    /// Every variant, in index order.
    pub const ALL: [OpKind; OpKind::COUNT] = [
        OpKind::TaskState,
        OpKind::TaskKill,
        OpKind::TaskSpawn,
        OpKind::Send,
        OpKind::Recv,
        OpKind::MemRead,
        OpKind::MemWrite,
        OpKind::Revoke,
        OpKind::Grant,
        OpKind::RoleGrant,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRecord {
    pub tick: u64,
    pub caller: usize,
    pub op: OpKind,
    pub target: Option<u32>,
    pub ok: bool,
}

const EMPTY: Option<AuditRecord> = None;

static mut TICK: u64 = 0;
static mut HEAD: usize = 0;
static mut LEN: usize = 0;
static mut RECORDS: [Option<AuditRecord>; MAX_AUDIT] = [EMPTY; MAX_AUDIT];

fn now() -> u64 {
    unsafe { core::ptr::read(core::ptr::addr_of_mut!(TICK)) }
}

fn read_records() -> &'static [Option<AuditRecord>; MAX_AUDIT] {
    unsafe { &*core::ptr::addr_of_mut!(RECORDS) }
}

fn write_records_mut() -> &'static mut [Option<AuditRecord>; MAX_AUDIT] {
    unsafe { &mut *core::ptr::addr_of_mut!(RECORDS) }
}

/// Append one attributed record. `caller` is the task index resolved by the
/// gate; `target` is the object id when resolution succeeded (so refusals
/// still name what was aimed at, and `None` means nothing was aimed at).
pub fn record(caller: usize, op: OpKind, target: Option<u32>, ok: bool) {
    let tick = {
        let t = now();
        unsafe { core::ptr::write(core::ptr::addr_of_mut!(TICK), t + 1) };
        t
    };
    let head = unsafe { core::ptr::read(core::ptr::addr_of_mut!(HEAD)) };
    let len = unsafe { core::ptr::read(core::ptr::addr_of_mut!(LEN)) };
    write_records_mut()[head] = Some(AuditRecord {
        tick,
        caller,
        op,
        target,
        ok,
    });
    let next = (head + 1) % MAX_AUDIT;
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(HEAD), next) };
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(LEN), (len + 1).min(MAX_AUDIT)) };
}

/// Read the current tick (monotonic log position; the monitor's time base).
pub fn tick() -> u64 {
    now()
}

/// Number of records currently in the ring.
pub fn len() -> usize {
    unsafe { core::ptr::read(core::ptr::addr_of_mut!(LEN)) }
}

/// Per-op histogram of everything one caller has done (successes and refusals
/// alike). Indexed by `OpKind::index`.
pub fn op_counts(caller: usize) -> [u32; OpKind::COUNT] {
    let mut counts = [0u32; OpKind::COUNT];
    let head = unsafe { core::ptr::read(core::ptr::addr_of_mut!(HEAD)) };
    let len = unsafe { core::ptr::read(core::ptr::addr_of_mut!(LEN)) };
    let records = read_records();
    for i in 0..len {
        let idx = (head + MAX_AUDIT - len + i) % MAX_AUDIT;
        if let Some(r) = &records[idx] {
            if r.caller == caller {
                counts[r.op.index()] += 1;
            }
        }
    }
    counts
}

/// Has `caller` ever successfully performed `op` with this exact target?
pub fn ever_succeeded(caller: usize, op: OpKind, target: u32) -> bool {
    let head = unsafe { core::ptr::read(core::ptr::addr_of_mut!(HEAD)) };
    let len = unsafe { core::ptr::read(core::ptr::addr_of_mut!(LEN)) };
    let records = read_records();
    for i in 0..len {
        let idx = (head + MAX_AUDIT - len + i) % MAX_AUDIT;
        if let Some(r) = &records[idx] {
            if r.caller == caller && r.op == op && r.ok && r.target == Some(target) {
                return true;
            }
        }
    }
    false
}

/// Number of `Revoke` records for `caller` (the model's "nothing was revoked"
/// invariant is checked as exactly this count being zero).
pub fn revoke_count(caller: usize) -> usize {
    let head = unsafe { core::ptr::read(core::ptr::addr_of_mut!(HEAD)) };
    let len = unsafe { core::ptr::read(core::ptr::addr_of_mut!(LEN)) };
    let records = read_records();
    let mut n = 0;
    for i in 0..len {
        let idx = (head + MAX_AUDIT - len + i) % MAX_AUDIT;
        if let Some(r) = &records[idx] {
            if r.caller == caller && r.op == OpKind::Revoke {
                n += 1;
            }
        }
    }
    n
}

/// Print every `RoleGrant` record plus every record attributed to `agent`, in
/// ring order, for the live Phase-6 demo ("the kernel prints audit log").
/// Successes and refusals alike — this is the append-only grant trail.
pub fn dump_agent_flow(agent: usize) {
    let head = unsafe { core::ptr::read(core::ptr::addr_of_mut!(HEAD)) };
    let len = unsafe { core::ptr::read(core::ptr::addr_of_mut!(LEN)) };
    let records = read_records();
    crate::sprintln!("Aegis: audit: Phase-6 role-grant flow (kernel truth):");
    for i in 0..len {
        let idx = (head + MAX_AUDIT - len + i) % MAX_AUDIT;
        if let Some(r) = &records[idx] {
            if r.op == OpKind::RoleGrant || r.caller == agent {
                crate::sprintln!(
                    "Aegis: audit: tick={} caller={} op={:?} target={:?} ok={}",
                    r.tick,
                    r.caller,
                    r.op,
                    r.target,
                    r.ok
                );
            }
        }
    }
}

/// Test-only: clear the whole log so contract tests start from a deterministic,
/// empty ring.
#[cfg(test)]
pub fn reset_for_test() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(TICK), 0);
        core::ptr::write(core::ptr::addr_of_mut!(HEAD), 0);
        core::ptr::write(core::ptr::addr_of_mut!(LEN), 0);
        for s in write_records_mut().iter_mut() {
            *s = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_attributed_and_ordered() {
        let _g = crate::kernel_state_guard();
        reset_for_test();
        record(1, OpKind::TaskState, Some(2), true);
        record(1, OpKind::TaskState, Some(2), true);
        record(1, OpKind::Send, None, false);
        assert_eq!(len(), 3);
        assert_eq!(op_counts(1)[OpKind::TaskState.index()], 2);
        assert_eq!(op_counts(1)[OpKind::Send.index()], 1);
        assert_eq!(op_counts(2)[OpKind::TaskState.index()], 0);
        assert!(ever_succeeded(1, OpKind::TaskState, 2));
        assert!(!ever_succeeded(1, OpKind::Send, 0));
    }

    #[test]
    fn ring_evicts_oldest_when_full() {
        let _g = crate::kernel_state_guard();
        reset_for_test();
        for i in 0..(MAX_AUDIT + 10) {
            record(0, OpKind::TaskState, Some(i as u32), true);
        }
        assert_eq!(len(), MAX_AUDIT);
        // The whole ring belongs to caller 0, so the histogram sees all of it.
        assert_eq!(op_counts(0)[OpKind::TaskState.index()], MAX_AUDIT as u32);
    }

    #[test]
    fn revoke_count_tracks_only_revokes() {
        let _g = crate::kernel_state_guard();
        reset_for_test();
        record(1, OpKind::Revoke, Some(3), true);
        record(1, OpKind::TaskState, Some(3), true);
        record(1, OpKind::Revoke, Some(9), false);
        assert_eq!(revoke_count(1), 2);
        assert_eq!(revoke_count(2), 0);
    }
}

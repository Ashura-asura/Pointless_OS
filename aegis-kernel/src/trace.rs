//! Phase 4 conformance trace: a replayable record of every capability-relevant
//! operation the kernel authorized (or denied).
//!
//! With the `trace` feature enabled, the syscall dispatch choke point emits one
//! `C:op` line to COM1 per capability-relevant syscall, and every task spawn
//! emits one `C:spawn` line. The lines carry the caller task index, the
//! operation name, the capability slot it named, the object id the slot
//! resolves to, the rights held on the slot, and the verdict (`ok`/`denied`).
//! The conformance harness (`aegis/conformance`) replays this stream against
//! the capability-core model and asserts that the model's authorization
//! verdict agrees with the kernel's recorded verdict at every step.
//!
//! All functions are no-ops without the feature: the default kernel image
//! carries no trace lines, no trace state, and no extra serial output. Traces
//! are emitted with `crate::sprintln!`, the same unbuffered COM1 writer the
//! boot log uses, so ordering is preserved and no kernel allocation is needed.

#[cfg(feature = "trace")]
use crate::cap::{Cap, CapSlot, Rights};
#[cfg(feature = "trace")]
use crate::tasks::{current_idx, task_cap, MAX_CAPS};

/// The right the traced operation requires on the resolved cap. Documented in
/// the trace for readability; the model recomputes authorization from its own
/// state, so this field is advisory, not authoritative.
#[cfg(feature = "trace")]
fn required(num: u64) -> Rights {
    match num {
        // ipc_call pushes a message onto the endpoint.
        5 => Rights::SEND,
        // ipc_reply pushes the reply message (kernel gates it on RECV).
        6 | 7 => Rights::RECV,
        // mem_len / mem_read / task_state are reads.
        11 | 12 | 14 => Rights::READ,
        // mem_write is a write.
        13 => Rights::WRITE,
        // task_kill / task_restart take CONTROL.
        15 | 16 => Rights::CONTROL,
        // grant / revoke take GRANT (delegation and revocation are the same
        // right).
        9 | 17 => Rights::GRANT,
        // endpoint create / mem create mint fresh caps and need no right on a
        // pre-existing slot.
        _ => Rights::NONE,
    }
}

/// Emit the verdict line for one capability-relevant syscall at the dispatch
/// choke point.
#[cfg(feature = "trace")]
pub fn op(num: u64, arg1: u64, arg2: u64, arg3: u64, _arg4: u64, result: i64) {
    let cur = current_idx();
    if cur == usize::MAX {
        return;
    }
    let (name, slot_arg) = match num {
        5 => ("call", arg1),
        6 => ("serve", arg1),
        7 => ("reply", arg1),
        // endpoint / mem resolve the fresh object from the RETURNED slot.
        8 => ("endpoint", result.max(0) as u64),
        10 => ("mem", result.max(0) as u64),
        11 => ("mem_len", arg1),
        12 => ("mem_read", arg1),
        13 => ("mem_write", arg1),
        14 => ("task_state", arg1),
        15 => ("task_kill", arg1),
        16 => ("task_restart", arg1),
        // grant resolves the grantor's source slot; revoke resolves the
        // grantor's own copy of the source slot.
        9 => ("grant", arg2),
        17 => ("revoke", arg3),
        _ => return,
    };
    let slot = slot_arg as usize;
    let caps: CapSlot = if slot < MAX_CAPS {
        task_cap(cur, slot)
    } else {
        CapSlot::empty()
    };
    let (kind, id) = match caps.cap {
        Cap::None => ("-", 0u32),
        Cap::Endpoint(i) => ("e", i),
        Cap::Task(i) => ("t", i),
        Cap::MemRegion(i) => ("m", i),
        Cap::Channel(i) => ("c", i),
    };
    let y = if result >= 0 { "ok" } else { "denied" };
    let req = required(num).bits();
    let rg = caps.rights.bits();
    match num {
        9 => crate::sprintln!(
            "C:op p=grant o={} s={} k={} j={} r={} rg={} d={} ds={} y={}",
            cur,
            slot_arg,
            kind,
            id,
            req,
            rg,
            arg1,
            arg3,
            y,
        ),
        17 => crate::sprintln!(
            "C:op p=revoke o={} s={} k={} j={} r={} rg={} d={} ds={} y={}",
            cur,
            slot_arg,
            kind,
            id,
            req,
            rg,
            arg1,
            arg3,
            y,
        ),
        10 => crate::sprintln!(
            "C:op p=mem o={} s={} k={} j={} r={} rg={} pg={} y={}",
            cur,
            slot_arg,
            kind,
            id,
            req,
            rg,
            arg1,
            y,
        ),
        _ => crate::sprintln!(
            "C:op p={} o={} s={} k={} j={} r={} rg={} y={}",
            name,
            cur,
            slot_arg,
            kind,
            id,
            req,
            rg,
            y,
        ),
    }
}

/// Emit the spawn record for a newly registered task.
#[cfg(feature = "trace")]
pub fn spawn(idx: usize, label: &str) {
    crate::sprintln!("C:spawn idx={} label={}", idx, label);
}

/// No-op stubs for the default (no-trace) build.
#[cfg(not(feature = "trace"))]
pub fn op(_num: u64, _arg1: u64, _arg2: u64, _arg3: u64, _arg4: u64, _result: i64) {}

/// No-op stub for the default (no-trace) build.
#[cfg(not(feature = "trace"))]
pub fn spawn(_idx: usize, _label: &str) {}

//! Phase AC — systematic syscall-boundary audit. One adversarial test per
//! syscall number (0..=23 plus the unknown-number path), each following the
//! pattern `cap_grant_refuses_out_of_range_recipient` established in `ipc.rs`:
//! hostile / boundary values for every ring-3 argument, assert refusal, and
//! assert the refusal is audited (where the gate records an op).
//!
//! The companion committed artifact is `Docs/SYSCALL_BOUNDARY_AUDIT.md`, the
//! syscall → argument → check-or-justification table this module proves.
//!
//! Test-harness caveats honored here (hostile-audit Phase 1, see
//! `hardening_fuzz.rs`): in host tests `reset_table_for_test` leaves
//! `pml4_phys == 0`, so the user-pointer gate runs in kernel-context bypass
//! (`validate_range(0, va, len)` = `va != 0`) and pointer arguments must be
//! pinned to live scratch buffers — hostile *ranges* are proven at the gate
//! level by `user_ptr_gate_never_panics_on_hostile_ranges`, not here. Null
//! (`va == 0`) is refused even under the bypass, which is what the Write test
//! leans on. Each test pins a distinct CURRENT index, takes the kernel state
//! guard, and resets the audit log + task table so `op_counts` is exact.

#![cfg(test)]

use std::sync::MutexGuard;

use crate::audit::OpKind;
use crate::syscall::dispatch;

const BAD_SLOT: u64 = crate::tasks::MAX_CAPS as u64 + 5;
const BAD_TASK: u64 = crate::tasks::MAX_TASKS as u64 + 5;

/// Take the state guard, reset shared kernel state, and pin CURRENT to a
/// caller-chosen task index (callers use distinct indices so the sweep never
/// collides with ipc/mem/supervisor/net/role tests that reuse 0..=10).
fn setup(idx: usize) -> MutexGuard<'static, ()> {
    let g = crate::kernel_state_guard();
    crate::audit::reset_for_test();
    crate::tasks::reset_table_for_test();
    crate::mem::reset_regions_for_test();
    crate::tasks::set_current_for_test(idx);
    g
}

fn writes_for(idx: usize, op: OpKind) -> u32 {
    crate::audit::op_counts(idx)[op.index()]
}

#[test]
fn syscall_0_exit_returns_minus_one() {
    let _g = setup(11);
    // Exit takes no ring-3 arguments; every hostile register value must be
    // ignored and the call refused (-1), never a panic.
    assert_eq!(dispatch(0, u64::MAX, u64::MAX, u64::MAX, u64::MAX), -1);
    assert_eq!(dispatch(0, 0, 0, 0, 0), -1);
    assert_eq!(crate::tasks::current_idx(), 11);
}

#[test]
fn syscall_1_write_refuses_null_buffer_and_is_audited() {
    let _g = setup(12);
    // A null buffer is refused even under the host test's kernel-context
    // bypass (`validate_range(0, 0, len)` = `va != 0` → false).
    assert_eq!(dispatch(1, 0, 4, 0, 0), -1, "null buffer must be refused");
    assert_eq!(
        writes_for(12, OpKind::Write),
        1,
        "the Write gate refusal is audited"
    );
    // Boundary: len=0 with a live buffer writes nothing and succeeds; the
    // clamp is proven at function level by `write_length_is_capped_at_the_maximum`.
    static SCRATCH: [u8; 16] = [0u8; 16];
    assert_eq!(
        dispatch(1, SCRATCH.as_ptr() as u64, 0, 0, 0),
        0,
        "zero-length write against a live buffer must succeed"
    );
    assert_eq!(
        crate::syscall::clamp_write_len(u64::MAX),
        crate::syscall::WRITE_MAX_LEN
    );
    assert_eq!(crate::tasks::current_idx(), 12);
}

#[test]
fn syscall_2_read_returns_minus_one() {
    let _g = setup(13);
    // Read is not implemented; hostile arguments must be ignored.
    assert_eq!(dispatch(2, u64::MAX, u64::MAX, u64::MAX, u64::MAX), -1);
    assert_eq!(crate::tasks::current_idx(), 13);
}

#[test]
fn syscall_3_yield_returns_zero() {
    let _g = setup(13);
    assert_eq!(dispatch(3, u64::MAX, u64::MAX, u64::MAX, u64::MAX), 0);
    assert_eq!(crate::tasks::current_idx(), 13);
}

#[test]
fn syscall_4_fork_returns_minus_one() {
    let _g = setup(13);
    assert_eq!(dispatch(4, u64::MAX, u64::MAX, u64::MAX, u64::MAX), -1);
    assert_eq!(crate::tasks::current_idx(), 13);
}

#[test]
fn syscall_5_call_refuses_hostile_ep_slot_and_is_audited() {
    let _g = setup(14);
    static SCRATCH: [u8; 16] = [0u8; 16];
    let va = SCRATCH.as_ptr() as u64;
    // Hostile ep_slot: out-of-range slot must be refused before any pointer
    // is touched, and the refusal is audited (Send).
    assert_eq!(dispatch(5, BAD_SLOT, va, 0, va), -1);
    assert_eq!(dispatch(5, u64::MAX, va, 0, va), -1);
    assert_eq!(
        writes_for(14, OpKind::Send),
        2,
        "both hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 14);
}

#[test]
fn syscall_6_serve_refuses_hostile_ep_slot_and_is_audited() {
    let _g = setup(15);
    static SCRATCH: [u8; 16] = [0u8; 16];
    let va = SCRATCH.as_ptr() as u64;
    assert_eq!(dispatch(6, BAD_SLOT, va, 0, 0), -1);
    assert_eq!(dispatch(6, u64::MAX, va, 0, 0), -1);
    assert_eq!(
        writes_for(15, OpKind::Recv),
        2,
        "both hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 15);
}

#[test]
fn syscall_7_reply_refuses_hostile_ep_slot_and_is_audited() {
    let _g = setup(16);
    static SCRATCH: [u8; 16] = [0u8; 16];
    let va = SCRATCH.as_ptr() as u64;
    // Hostile ep_slot: the caps_endpoint gate refuses before the caller-id
    // cross-check, and the refusal is audited (Send).
    assert_eq!(dispatch(7, BAD_SLOT, 0, va, 0), -1);
    assert_eq!(dispatch(7, u64::MAX, 0, va, 0), -1);
    assert_eq!(
        writes_for(16, OpKind::Send),
        2,
        "both hostile-slot refusals are audited"
    );
    // A hostile caller id against a valid-but-unseeded endpoint: the caller
    // index is bounded before the ledger/slot tables are touched.
    assert_eq!(dispatch(7, BAD_SLOT, u64::MAX, va, 0), -1);
    assert_eq!(crate::tasks::current_idx(), 16);
}

#[test]
fn syscall_8_endpoint_create_ignores_hostile_args() {
    let _g = setup(11);
    // EndpointCreate takes no ring-3 arguments; hostile registers must be
    // ignored. It succeeds (installs a Send|Recv|Grant cap) or returns -1 on
    // a full endpoint table — never a panic, never a corrupt cap.
    let slot = dispatch(8, u64::MAX, u64::MAX, u64::MAX, u64::MAX);
    if slot >= 0 {
        let s = crate::tasks::task_cap(11, slot as usize);
        assert!(s.rights.contains(crate::cap::Rights::SEND));
        assert!(s.rights.contains(crate::cap::Rights::RECV));
        assert!(s.rights.contains(crate::cap::Rights::GRANT));
    }
    assert_eq!(crate::tasks::current_idx(), 11);
}

#[test]
fn syscall_9_cap_grant_refuses_hostile_indices_and_is_audited() {
    let _g = setup(12);
    // The caller holds GRANT on a live slot it could legitimately delegate;
    // only the recipient's *indices* are hostile (mirrors
    // `cap_grant_refuses_out_of_range_recipient` at dispatch level).
    crate::tasks::set_task_cap(
        12,
        1,
        crate::cap::CapSlot {
            cap: crate::cap::Cap::Task(crate::cap::Oid::new(2, 0)),
            rights: crate::cap::Rights::ALL,
        },
    );
    assert_eq!(dispatch(9, BAD_TASK, 1, 0, 0), -1);
    assert_eq!(dispatch(9, 0, 1, BAD_SLOT, 0), -1);
    assert_eq!(dispatch(9, u64::MAX, 1, u64::MAX, 0), -1);
    assert_eq!(
        writes_for(12, OpKind::Grant),
        3,
        "three hostile-index refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 12);
}

#[test]
fn syscall_10_mem_create_refuses_zero_and_huge_frame_counts() {
    let _g = setup(13);
    // MemCreate(frames): the argument is a resource *count*, validated by the
    // allocator (0 → -1, and `alloc_contiguous_global` returns None when the
    // free list can't satisfy it). There is no capability gate and no audit
    // op for create (nothing is refused at a rights boundary); the contract
    // proven here is fail-closed: hostile counts return -1 and leave no
    // region installed, never a panic.
    assert_eq!(dispatch(10, 0, 0, 0, 0), -1, "zero frames refused");
    assert_eq!(dispatch(10, u64::MAX, 0, 0, 0), -1, "huge frames refused");
    assert_eq!(
        dispatch(10, 1, 0, 0, 0),
        -1,
        "in this host harness no frames are free, so even 1 is refused"
    );
    assert_eq!(crate::tasks::current_idx(), 13);
}

#[test]
fn syscall_11_mem_len_refuses_hostile_slot_and_is_audited() {
    let _g = setup(14);
    assert_eq!(dispatch(11, BAD_SLOT, 0, 0, 0), -1);
    assert_eq!(dispatch(11, u64::MAX, 0, 0, 0), -1);
    assert_eq!(
        writes_for(14, OpKind::MemRead),
        2,
        "hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 14);
}

#[test]
fn syscall_12_mem_read_refuses_hostile_args_and_is_audited() {
    let _g = setup(15);
    static SCRATCH: [u8; 16] = [0u8; 16];
    let va = SCRATCH.as_ptr() as u64;
    // Hostile slot: refused before any pointer is touched.
    assert_eq!(dispatch(12, BAD_SLOT, 0, 0, va), -1);
    // Hostile offset+len: `checked_add` overflows → refused, audited.
    assert_eq!(dispatch(12, 0, u64::MAX, u64::MAX, va), -1);
    assert_eq!(
        writes_for(15, OpKind::MemRead),
        2,
        "both refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 15);
}

#[test]
fn syscall_13_mem_write_refuses_hostile_args_and_is_audited() {
    let _g = setup(16);
    static SCRATCH: [u8; 16] = [0u8; 16];
    let va = SCRATCH.as_ptr() as u64;
    assert_eq!(dispatch(13, BAD_SLOT, 0, 0, va), -1);
    assert_eq!(dispatch(13, 0, u64::MAX, u64::MAX, va), -1);
    assert_eq!(
        writes_for(16, OpKind::MemWrite),
        2,
        "both refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 16);
}

#[test]
fn syscall_14_task_state_refuses_hostile_slot_and_is_audited() {
    let _g = setup(11);
    assert_eq!(dispatch(14, BAD_SLOT, 0, 0, 0), -1);
    assert_eq!(dispatch(14, u64::MAX, 0, 0, 0), -1);
    assert_eq!(
        writes_for(11, OpKind::TaskState),
        2,
        "hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 11);
}

#[test]
fn syscall_15_task_kill_refuses_hostile_slot_and_is_audited() {
    let _g = setup(12);
    assert_eq!(dispatch(15, BAD_SLOT, 0, 0, 0), -1);
    assert_eq!(dispatch(15, u64::MAX, 0, 0, 0), -1);
    assert_eq!(
        writes_for(12, OpKind::TaskKill),
        2,
        "hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 12);
}

#[test]
fn syscall_16_task_restart_refuses_hostile_slot_and_is_audited() {
    let _g = setup(13);
    assert_eq!(dispatch(16, BAD_SLOT, 0, 0, 0), -1);
    assert_eq!(dispatch(16, u64::MAX, 0, 0, 0), -1);
    assert_eq!(
        writes_for(13, OpKind::TaskSpawn),
        2,
        "hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 13);
}

#[test]
fn syscall_17_cap_revoke_refuses_hostile_indices_and_is_audited() {
    let _g = setup(14);
    // The caller holds GRANT on a live slot; only the recipient's indices are
    // hostile (mirrors `cap_grant_refuses_out_of_range_recipient`).
    crate::tasks::set_task_cap(
        14,
        1,
        crate::cap::CapSlot {
            cap: crate::cap::Cap::Task(crate::cap::Oid::new(2, 0)),
            rights: crate::cap::Rights::ALL,
        },
    );
    assert_eq!(dispatch(17, BAD_TASK, 0, 1, 0), -1);
    assert_eq!(dispatch(17, 0, BAD_SLOT, 1, 0), -1);
    assert_eq!(dispatch(17, u64::MAX, u64::MAX, 1, 0), -1);
    assert_eq!(
        writes_for(14, OpKind::Revoke),
        3,
        "three hostile-index refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 14);
}

#[test]
fn syscall_18_role_grant_refuses_garbage_and_is_audited() {
    let _g = setup(15);
    // An unknown role id is refused (fail closed), audited as RoleGrant.
    assert_eq!(dispatch(18, 0xDEAD, 0, 0, 0), -1);
    // A known role id with out-of-range grantee/target/dst_slot is refused.
    assert_eq!(dispatch(18, 0, BAD_TASK, 0, 0), -1);
    assert_eq!(dispatch(18, 0, 0, BAD_TASK, 0), -1);
    assert_eq!(dispatch(18, 0, 0, 0, BAD_SLOT), -1);
    assert_eq!(
        writes_for(15, OpKind::RoleGrant),
        4,
        "all four hostile-argument refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 15);
}

#[test]
fn syscall_19_net_socket_refuses_bad_kind_and_is_audited() {
    let _g = setup(16);
    // kind must be 1 (TCP) or 2 (UDP); anything else is refused and audited
    // as NetOpen. The capless caller is also refused (no NetRoot cap), still
    // audited — this harness leaves all cap slots empty.
    assert_eq!(dispatch(19, 0, 0, 0, 0), -1);
    assert_eq!(dispatch(19, 3, 0, 0, 0), -1);
    assert_eq!(dispatch(19, u64::MAX, 0, 0, 0), -1);
    assert_eq!(
        writes_for(16, OpKind::NetOpen),
        3,
        "every refused mint is audited"
    );
    assert_eq!(crate::tasks::current_idx(), 16);
}

#[test]
fn syscall_20_net_connect_refuses_hostile_slot_and_is_audited() {
    let _g = setup(11);
    assert_eq!(dispatch(20, BAD_SLOT, 0, 0, 0), -1);
    assert_eq!(dispatch(20, u64::MAX, 0, 0, 0), -1);
    assert_eq!(
        writes_for(11, OpKind::NetIo),
        2,
        "hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 11);
}

#[test]
fn syscall_21_net_send_refuses_hostile_slot_and_is_audited() {
    let _g = setup(12);
    static SCRATCH: [u8; 16] = [0u8; 16];
    let va = SCRATCH.as_ptr() as u64;
    assert_eq!(dispatch(21, BAD_SLOT, va, 0, 0), -1);
    assert_eq!(dispatch(21, u64::MAX, va, 0, 0), -1);
    assert_eq!(
        writes_for(12, OpKind::NetIo),
        2,
        "hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 12);
}

#[test]
fn syscall_22_net_recv_refuses_hostile_slot_and_is_audited() {
    let _g = setup(13);
    static SCRATCH: [u8; 16] = [0u8; 16];
    let va = SCRATCH.as_ptr() as u64;
    assert_eq!(dispatch(22, BAD_SLOT, va, 0, 0), -1);
    assert_eq!(dispatch(22, u64::MAX, va, 0, 0), -1);
    assert_eq!(
        writes_for(13, OpKind::NetIo),
        2,
        "hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 13);
}

#[test]
fn syscall_23_net_close_refuses_hostile_slot_and_is_audited() {
    let _g = setup(14);
    assert_eq!(dispatch(23, BAD_SLOT, 0, 0, 0), -1);
    assert_eq!(dispatch(23, u64::MAX, 0, 0, 0), -1);
    assert_eq!(
        writes_for(14, OpKind::NetIo),
        2,
        "hostile-slot refusals are audited"
    );
    assert_eq!(crate::tasks::current_idx(), 14);
}

#[test]
fn unknown_syscall_numbers_are_refused() {
    let _g = setup(15);
    // No documented handler; any unknown number is refused. Nothing is
    // audited (no gate fires — there is no operation to attribute).
    assert_eq!(dispatch(24, 0, 0, 0, 0), -1);
    assert_eq!(dispatch(99, u64::MAX, u64::MAX, u64::MAX, u64::MAX), -1);
    assert_eq!(dispatch(u64::MAX, 0, 0, 0, 0), -1);
    assert_eq!(crate::tasks::current_idx(), 15);
}

#[test]
fn dispatch_never_moves_the_current_task_on_hostile_args() {
    let _g = setup(16);
    static SCRATCH: [u8; 16] = [0u8; 16];
    let va = SCRATCH.as_ptr() as u64;
    // Pin pointer positions to a live scratch buffer and index positions to
    // hostile values (the harness rule established in `hardening_fuzz.rs`:
    // under kernel-context bypass a non-null pointer passes the gate, so a
    // hostile *pointer* would be dereferenced). This pins the deterministic
    // sweep's guarantee that hostile index/len arguments never move CURRENT.
    for num in 0u64..=30 {
        if num == 8 {
            continue; // EndpointCreate mints; nothing to fuzz and a side effect
        }
        let (fuzz, zero): (&[usize], &[usize]) = match num {
            1 => (&[], &[1]),        // Write: buf=va, len=0
            5 => (&[0], &[2]),       // Call: ep_slot fuzzed; msg_va=va, len=0, reply=va
            6 => (&[0], &[]),        // Serve: ep_slot fuzzed; recvbuf=va
            7 => (&[0, 1], &[3]),    // Reply: ep_slot+caller fuzzed; reply=va, rlen=0
            9 => (&[0, 1, 2], &[]),  // CapGrant: dst, src_slot, dst_slot
            10 => (&[], &[0]),       // MemCreate: frames=0 (no free frames anyway)
            11 => (&[0], &[]),       // MemLen: slot
            12 => (&[0, 1, 2], &[]), // MemRead: slot/offset/len; dst=va
            13 => (&[0, 1, 2], &[]), // MemWrite: slot/offset/len; src=va
            14..=16 => (&[0], &[]),  // TaskState/Kill/Restart: slot
            17 => (&[0, 1, 2], &[]), // CapRevoke: dst, dst_slot, src_slot
            18 => (&[0, 1, 3], &[]), // RoleGrant: role/grantee/dst_slot; target=va
            19 => (&[0], &[]),       // NetSocket: kind fuzzed (no NetRoot -> denied)
            20 | 23 => (&[0], &[]),  // NetConnect/Close: slot
            21 | 22 => (&[0], &[2]), // NetSend/Recv: slot fuzzed; va=va, len=0
            _ => (&[], &[]),
        };
        let mut args = [va; 4];
        for &i in fuzz {
            args[i] = u64::MAX;
        }
        for &i in zero {
            args[i] = 0;
        }
        let _ = dispatch(num, args[0], args[1], args[2], args[3]);
    }
    assert_eq!(crate::tasks::current_idx(), 16);
}

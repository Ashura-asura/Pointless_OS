//! Kernel IPC: endpoints + synchronous call/reply, the microkernel message-
//! passing primitive. A task creating an endpoint gets a capability to it; that
//! capability can be granted to another task. A client does `ipc_call` (blocks
//! until the server replies); a server does `ipc_serve` (blocks until a call
//! arrives) then `ipc_reply`.
//!
//! The kernel mediates the message: it copies the payload between the caller's
//! and server's buffers and blocks/unblocks tasks via the scheduler, so a call
//! looks like a single cross-task function call to userspace.
//!
//! Honest limits: tasks still share one address space (no per-process page
//! tables yet), so the user-buffer copies below are not yet cross-address-space
//! copies — they are the same mechanism that *will* become cross-space copies
//! once isolation lands. Capability revocation is slot clearing only: the
//! GRANT-gated `ipc_cap_revoke` takes back a named granted instance, but the
//! flat per-task CSpace tracks no grant-root derivation tree (model I4), so it
//! cannot reach copies in CSpaces the grantor cannot name. No async/notify
//! variant yet (only synchronous call/reply).

use crate::cap::{Cap, CapSlot, Rights};
use crate::tasks::{
    block_current, context_frame, current_idx, set_task_cap, switch_away_from, task_cap,
    unblock_task,
};

const IPC_BUF: usize = 256;
pub const MAX_ENDPOINTS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum EpState {
    Idle,
    /// A caller is waiting; its message sits in `buf`, awaiting a server.
    SendWaiting,
    /// A server is waiting in `ipc_serve`; `server`/`server_recvbuf_va` set.
    RecvWaiting,
}

#[derive(Clone, Copy)]
struct Endpoint {
    active: bool,
    state: EpState,
    buf: [u8; IPC_BUF],
    msg_len: usize,
    caller: usize,
    caller_reply_va: u64,
    server: usize,
    server_recvbuf_va: u64,
}

impl Endpoint {
    const fn new() -> Self {
        Endpoint {
            active: false,
            state: EpState::Idle,
            buf: [0u8; IPC_BUF],
            msg_len: 0,
            caller: usize::MAX,
            caller_reply_va: 0,
            server: usize::MAX,
            server_recvbuf_va: 0,
        }
    }
}

static mut ENDPOINTS: [Endpoint; MAX_ENDPOINTS] = [Endpoint::new(); MAX_ENDPOINTS];

/// Set the return value (rax) of a task's saved frame, so it resumes with it.
/// Offset 112 is the rax slot in the switch_frame save/restore layout
/// (switch_frame saves rax to offset 112, restore pops rax from offset 112).
unsafe fn set_ret(idx: usize, val: u64) {
    let f = context_frame(idx) as *mut u64;
    *f.add(112 / 8) = val;
}

unsafe fn copy_in(va: u64, dst: &mut [u8]) {
    core::ptr::copy_nonoverlapping(va as *const u8, dst.as_mut_ptr(), dst.len());
}

unsafe fn copy_out(src: &[u8], va: u64) {
    core::ptr::copy_nonoverlapping(src.as_ptr(), va as *mut u8, src.len());
}

unsafe fn copy_user(src_va: u64, dst_va: u64, len: usize) {
    core::ptr::copy_nonoverlapping(src_va as *const u8, dst_va as *mut u8, len);
}

/// Resolve a capability slot to an endpoint, requiring the caller to hold the
/// given rights on it. `None` both when the slot is empty or names a non-endpoint
/// object, and when the held rights are insufficient (Phase 1: capability-aware
/// IPC — a cap is a (object, rights) pair, and the kernel enforces the rights at
/// delivery time, never trusting the caller to state its own authority).
fn caps_endpoint(cur: usize, slot: u64, need: Rights) -> Option<usize> {
    if slot as usize >= crate::tasks::MAX_CAPS {
        return None;
    }
    match task_cap(cur, slot as usize) {
        CapSlot {
            cap: Cap::Endpoint(id),
            rights,
        } if rights.contains(need) => Some(id as usize),
        _ => None,
    }
}

/// Syscall: create an endpoint, returning the capability slot in the caller's
/// table (or -1 on failure).
///
/// # Safety
/// Must be called via syscall from ring-3 with valid task context.
pub unsafe fn ipc_endpoint_create() -> i64 {
    let cur = current_idx();
    let id = (0..MAX_ENDPOINTS).find(|&i| !ENDPOINTS[i].active);
    let id = match id {
        Some(i) => i,
        None => return -1,
    };
    ENDPOINTS[id] = Endpoint::new();
    ENDPOINTS[id].active = true;
    let slot = (0..crate::tasks::MAX_CAPS).find(|&s| task_cap(cur, s).cap == Cap::None);
    let slot = match slot {
        Some(s) => s,
        None => {
            ENDPOINTS[id].active = false;
            return -1;
        }
    };
    set_task_cap(
        cur,
        slot,
        CapSlot {
            cap: Cap::Endpoint(id as u32),
            rights: crate::cap::ENDPOINT_RIGHTS,
        },
    );
    slot as i64
}

/// Syscall: grant the caller's capability `src_slot` to task `dst` at its
/// slot `dst_slot` (so the destination knows where to find it). Requires the
/// caller to hold GRANT on the source slot (Phase 1: delegation is gated on the
/// GRANT right — a caller can only copy authority it is entitled to delegate).
/// Returns `dst_slot` on success, or -1. A suspended agent's grant flow is
/// frozen by the anomaly monitor's ledger (§9): it cannot delegate new
/// authority until a human resumes it.
///
/// # Safety
/// Must be called via syscall from ring-3 with valid task context.
pub unsafe fn ipc_cap_grant(dst: u64, src_slot: u64, dst_slot: u64) -> i64 {
    let cur = current_idx();
    let slot = if (src_slot as usize) < crate::tasks::MAX_CAPS {
        task_cap(cur, src_slot as usize)
    } else {
        CapSlot::empty()
    };
    let target = slot.cap.id();
    if crate::monitor::ledger().is_suspended(cur)
        || slot.cap == Cap::None
        || !slot.rights.contains(Rights::GRANT)
    {
        crate::audit::record(cur, crate::audit::OpKind::Grant, target, false);
        return -1;
    }
    set_task_cap(dst as usize, dst_slot as usize, slot);
    crate::audit::record(cur, crate::audit::OpKind::Grant, target, true);
    0
}

/// Syscall: revoke a capability the caller previously granted — invalidate the
/// copy task `dst` holds at `dst_slot`. The caller must hold GRANT on its own
/// copy `src_slot` naming the *same* object (this mirrors the model's `revoke`,
/// which is GRANT-gated; the existing `revoke_slot` self-revoke uses the same
/// right). The recipient's slot is cleared, so every subsequent gated op on it
/// returns -1 — never a panic, never a silent success. Revocation is permanent
/// (Phase 2: a grantor takes back what it granted). Returns 0 or -1.
///
/// Honest limit: the flat per-task CSpace tracks no grant-root derivation tree
/// (the model's I4), so this revokes a *named* instance only — the grantor must
/// be able to name recipient and slot, and cannot reach copies in CSpaces it
/// cannot name.
///
/// # Safety
/// Must be called via syscall from ring-3 with valid task context.
pub unsafe fn ipc_cap_revoke(dst: u64, dst_slot: u64, src_slot: u64) -> i64 {
    let cur = current_idx();
    let slot = if (src_slot as usize) < crate::tasks::MAX_CAPS {
        task_cap(cur, src_slot as usize)
    } else {
        CapSlot::empty()
    };
    let target = slot.cap.id();
    // The caller must still hold GRANT on a live copy of the object it is
    // revoking (delegation and revocation are the same right).
    if slot.cap == Cap::None || !slot.rights.contains(Rights::GRANT) {
        crate::audit::record(cur, crate::audit::OpKind::Revoke, target, false);
        return -1;
    }
    // Bounds-check the recipient's table before touching it (a malformed
    // argument must be refused, never a panic).
    if (dst as usize) >= crate::tasks::MAX_TASKS || (dst_slot as usize) >= crate::tasks::MAX_CAPS {
        crate::audit::record(cur, crate::audit::OpKind::Revoke, target, false);
        return -1;
    }
    let granted = task_cap(dst as usize, dst_slot as usize);
    // Only take back what the grantor actually granted: the recipient's slot
    // must name the same object. An empty or foreign slot is refused.
    if granted.cap == Cap::None || granted.cap != slot.cap {
        crate::audit::record(cur, crate::audit::OpKind::Revoke, target, false);
        return -1;
    }
    set_task_cap(dst as usize, dst_slot as usize, CapSlot::empty());
    crate::audit::record(cur, crate::audit::OpKind::Revoke, target, true);
    0
}

/// Syscall: `int 0x80` with rax=5. Blocks the caller until the server replies.
/// `ep_slot` = capability slot, `msg_va`/`len` = request, `reply_va` = where
/// the reply is written. Returns the reply length (delivered via the caller's
/// frame rax when it is resumed).
///
/// # Safety
/// Must be called via syscall from ring-3 with valid task context and
/// user-space virtual addresses for msg_va and reply_va.
pub unsafe fn ipc_call(ep_slot: u64, msg_va: u64, len: u64, reply_va: u64) -> i64 {
    let cur = current_idx();
    crate::sprintln!("Aegis: ipc_call cur={} ep_slot={}", cur, ep_slot);
    let ep = match caps_endpoint(cur, ep_slot, Rights::SEND) {
        Some(e) => e,
        None => return -1,
    };
    let len = core::cmp::min(len as usize, IPC_BUF);
    copy_in(msg_va, &mut ENDPOINTS[ep].buf[..len]);
    ENDPOINTS[ep].msg_len = len;

    if ENDPOINTS[ep].state == EpState::RecvWaiting {
        let srv = ENDPOINTS[ep].server;
        copy_out(&ENDPOINTS[ep].buf[..len], ENDPOINTS[ep].server_recvbuf_va);
        ENDPOINTS[ep].server = usize::MAX;
        ENDPOINTS[ep].server_recvbuf_va = 0;
        ENDPOINTS[ep].state = EpState::Idle;
        // Caller now waits for the server's reply.
        ENDPOINTS[ep].caller = cur;
        ENDPOINTS[ep].caller_reply_va = reply_va;
        // Hand the server its return value and unblock it.
        set_ret(srv, ((cur as u64) << 32) | (len as u64));
        unblock_task(srv);
        block_current(ep);
        switch_away_from(cur);
        // Resumed: the reply length was written into our rax by ipc_reply.
        resume_ret(cur)
    } else {
        ENDPOINTS[ep].state = EpState::SendWaiting;
        ENDPOINTS[ep].caller = cur;
        ENDPOINTS[ep].caller_reply_va = reply_va;
        block_current(ep);
        switch_away_from(cur);
        // Resumed: the reply length was written into our rax by ipc_reply.
        resume_ret(cur)
    }
}

/// Read the return value that a later `set_ret` wrote into this task's
/// saved `rax` slot. After `switch_away_from` resumes a blocked task the
/// live `rax` register may have been clobbered by intervening code, so we
/// read the value straight out of the saved frame (memory), which is exactly
/// what `set_ret` modified. Offset 112 = rax slot in switch_frame layout.
unsafe fn resume_ret(cur: usize) -> i64 {
    let f = context_frame(cur) as *const u64;
    *f.add(112 / 8) as i64
}

/// Syscall: `int 0x80` with rax=6. Blocks the server until a call arrives,
/// delivering the request into `recvbuf_va`. Returns `(caller_id << 32) | len`.
///
/// # Safety
/// Must be called via syscall from ring-3 with valid task context and
/// user-space virtual address for recvbuf_va.
pub unsafe fn ipc_serve(ep_slot: u64, recvbuf_va: u64) -> i64 {
    let cur = current_idx();
    crate::sprintln!("Aegis: ipc_serve cur={} ep_slot={}", cur, ep_slot);
    let ep = match caps_endpoint(cur, ep_slot, Rights::RECV) {
        Some(e) => e,
        None => return -1,
    };
    match ENDPOINTS[ep].state {
        EpState::SendWaiting => {
            let caller = ENDPOINTS[ep].caller;
            let len = ENDPOINTS[ep].msg_len;
            copy_out(&ENDPOINTS[ep].buf[..len], recvbuf_va);
            // Caller stays blocked, now awaiting the reply.
            ENDPOINTS[ep].state = EpState::Idle;
            set_ret(cur, ((caller as u64) << 32) | (len as u64));
            (((caller as u64) << 32) | (len as u64)) as i64
        }
        _ => {
            ENDPOINTS[ep].state = EpState::RecvWaiting;
            ENDPOINTS[ep].server = cur;
            ENDPOINTS[ep].server_recvbuf_va = recvbuf_va;
            block_current(ep);
            switch_away_from(cur);
            // Resumed: the caller id + length were written into our rax by
            // ipc_call when it delivered the waiting call.
            resume_ret(cur)
        }
    }
}

/// Syscall: `int 0x80` with rax=7. Server sends `reply_va`/`rlen` back to the
/// caller identified by `caller_id` (from the `ipc_serve` return).
///
/// # Safety
/// Must be called via syscall from ring-3 with valid task context and
/// user-space virtual address for reply_va.
pub unsafe fn ipc_reply(ep_slot: u64, caller_id: u64, reply_va: u64, rlen: u64) -> i64 {
    let cur = current_idx();
    let ep = match caps_endpoint(cur, ep_slot, Rights::RECV) {
        Some(e) => e,
        None => return -1,
    };
    let caller = caller_id as usize;
    let rlen = core::cmp::min(rlen as usize, IPC_BUF);
    copy_user(reply_va, ENDPOINTS[ep].caller_reply_va, rlen);
    set_ret(caller, rlen as u64);
    ENDPOINTS[ep].caller = usize::MAX;
    ENDPOINTS[ep].caller_reply_va = 0;
    ENDPOINTS[ep].state = EpState::Idle;
    unblock_task(caller);
    0
}

/// Force a task runnable (used by diagnostics). Kept for completeness.
///
/// # Safety
/// `idx` must be a valid task index. Only use for debugging/testing.
#[allow(dead_code)]
pub unsafe fn force_unblock(idx: usize) {
    unblock_task(idx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::new_cap_table;
    use crate::tasks::MAX_CAPS;

    // Global-state tests each pin a task index so they never collide with the
    // other tests sharing CURRENT/TASKS: 0 = grants+call, 1 = endpoint create,
    // 2 = serve/reply, 3 = non-endpoint, 4 = out-of-range.

    fn seed_endpoint(idx: usize, rights: Rights) {
        set_task_cap(
            idx,
            0,
            CapSlot {
                cap: Cap::Endpoint(7),
                rights,
            },
        );
    }

    #[test]
    fn blank_table_has_only_empty_slots() {
        let _g = crate::kernel_state_guard();
        let caps = new_cap_table();
        assert!(caps
            .iter()
            .all(|s| s.cap == Cap::None && s.rights == Rights::NONE));
    }

    #[test]
    fn endpoint_create_installs_send_recv_grant_rights() {
        let _g = crate::kernel_state_guard();
        // Task 1 owns slot 0 here; no other test touches task 1.
        crate::tasks::set_current_for_test(1);
        let slot = unsafe { ipc_endpoint_create() };
        assert!(slot >= 0, "endpoint create must succeed");
        let s = task_cap(1, slot as usize);
        assert!(s.rights.contains(Rights::SEND));
        assert!(s.rights.contains(Rights::RECV));
        assert!(s.rights.contains(Rights::GRANT));
        assert!(!s.rights.contains(Rights::CONTROL));
    }

    #[test]
    fn grants_require_grant_right_on_source() {
        let _g = crate::kernel_state_guard();
        // Task 0 slot 0 is seeded with RECV only; slot 3 stays empty.
        crate::tasks::set_current_for_test(0);
        seed_endpoint(0, Rights::RECV);
        // Empty slot must fail.
        assert_eq!(unsafe { ipc_cap_grant(1, 3, 0) }, -1);
        // Slot without GRANT right must fail.
        assert_eq!(unsafe { ipc_cap_grant(1, 0, 0) }, -1);
    }

    #[test]
    fn grant_copies_slot_verbatim() {
        let _g = crate::kernel_state_guard();
        // Task 1 owns slot 2 here (endpoint create writes task 1 slot 0 only).
        crate::tasks::set_current_for_test(1);
        let mut caps = new_cap_table();
        caps[2] = CapSlot {
            cap: Cap::Endpoint(3),
            rights: Rights::RECV.union(Rights::GRANT),
        };
        set_task_cap(1, 2, caps[2]);
        assert_eq!(unsafe { ipc_cap_grant(0, 2, 0) }, 0);
        let got = task_cap(0, 0);
        assert_eq!(got, caps[2]);
    }

    #[test]
    fn call_requires_send_right_on_endpoint() {
        let _g = crate::kernel_state_guard();
        // Task 0 slot 0 RECV-only (same seed value as grants test, so the two
        // stay consistent even if they interleave).
        crate::tasks::set_current_for_test(0);
        seed_endpoint(0, Rights::RECV);
        assert_eq!(
            caps_endpoint(0, 0, Rights::SEND),
            None,
            "call with RECV-only must be denied"
        );
    }

    #[test]
    fn serve_and_reply_require_recv_right_on_endpoint() {
        let _g = crate::kernel_state_guard();
        // Task 2 slot 0 SEND-only.
        crate::tasks::set_current_for_test(2);
        seed_endpoint(2, Rights::SEND);
        assert_eq!(
            caps_endpoint(2, 0, Rights::RECV),
            None,
            "serve/reply with SEND-only must be denied"
        );
    }

    #[test]
    fn non_endpoint_caps_are_not_deliverable() {
        let _g = crate::kernel_state_guard();
        // Task 3 slots 1,2 hold Task/MemRegion caps.
        crate::tasks::set_current_for_test(3);
        set_task_cap(
            3,
            1,
            CapSlot {
                cap: Cap::Task(1),
                rights: Rights::ALL,
            },
        );
        set_task_cap(
            3,
            2,
            CapSlot {
                cap: Cap::MemRegion(4),
                rights: Rights::ALL,
            },
        );
        assert_eq!(caps_endpoint(3, 1, Rights::SEND), None);
        assert_eq!(caps_endpoint(3, 2, Rights::RECV), None);
    }

    #[test]
    fn out_of_range_slot_is_denied_not_panic() {
        let _g = crate::kernel_state_guard();
        // Task 4 pins CURRENT; nothing else touches it.
        crate::tasks::set_current_for_test(4);
        assert_eq!(caps_endpoint(4, MAX_CAPS as u64 + 100, Rights::SEND), None);
    }
}

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
//! cannot reach copies in CSpaces the grantor cannot name. The only async
//! variant is the kernel → task kill notification on the reserved endpoint
//! (`notify_task_kill`), a single-slot mailbox: two deaths before the
//! supervisor serves keep the last record.

use crate::cap::{Cap, CapSlot, Rights};
use crate::tasks::{
    block_current, context_frame, current_idx, set_task_cap, switch_away_from, task_cap,
    unblock_task,
};

const IPC_BUF: usize = 256;
pub const MAX_ENDPOINTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Identity generation of this slot. `ipc_endpoint_create` bumps it on
    /// every create so a capability minted against a previous incarnation of
    /// this index cannot resolve to the replacement (generation-safe identity;
    /// endpoints have no destroy syscall today, but the identity must not be
    /// re-openable by a future one).
    generation: u32,
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
            generation: 0,
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

/// Identity generation of the endpoint currently occupying index `id`.
/// Bounds-guarded: an out-of-range index yields `u32::MAX`, which no
/// capability's generation can equal, so every resolve fails closed.
pub fn endpoint_generation(id: u32) -> u32 {
    if (id as usize) >= MAX_ENDPOINTS {
        return u32::MAX;
    }
    unsafe { ENDPOINTS[id as usize].generation }
}

/// Reserved kill-notification endpoint (Phase 5 supervision tree). The kernel
/// parks the death of a ring-3 task here instead of only killing it, so a
/// ring-3 supervisor task can observe TaskKill events via `ipc_serve`. The
/// last endpoint slot is never handed to user `ipc_endpoint_create` because it
/// stays active from boot.
pub const NOTIFY_EP: usize = MAX_ENDPOINTS - 1;
/// Notification record length in bytes: [0..4] = child task index (LE),
/// [4..8] = kill reason code.
pub const NOTIFY_REC_LEN: usize = 8;
/// Kill-reason code: a ring-3 page fault from a U/S violation (isolation).
pub const REASON_PF_ISOLATION: u32 = 0;
/// Kill-reason code: a ring-3 instruction fetch from a non-executable page.
pub const REASON_NX: u32 = 1;

/// Activate the reserved kill-notification endpoint. Idempotent. Called at
/// boot, before the ring-3 supervisor task is spawned, so the supervisor's
/// first `ipc_serve` can observe deaths from the first crash onward.
pub fn init_notify_endpoint() {
    unsafe {
        ENDPOINTS[NOTIFY_EP] = Endpoint::new();
        ENDPOINTS[NOTIFY_EP].active = true;
    }
}

/// Park a TaskKill notification record for `child` into the reserved endpoint:
/// the kernel-side half of the supervision tree's death signal. If a server
/// (the ring-3 supervisor) is already blocked in `ipc_serve` on the reserved
/// endpoint, the record is delivered immediately and the server is unblocked
/// (mirrors `ipc_call`'s RecvWaiting delivery); otherwise the record sits in
/// the mailbox until the next `ipc_serve` picks it up.
///
/// Returns true when a waiting server received the record, false when it was
/// parked (single-slot mailbox, honest limit).
///
/// # Safety
/// Single-threaded kernel; callers must be kernel-mode (this is the
/// kernel → task direction, never a ring-3 syscall).
pub fn notify_task_kill(child: usize, reason: u32) -> bool {
    let rec: [[u8; 4]; 2] = [(child as u32).to_le_bytes(), reason.to_le_bytes()];
    let len = NOTIFY_REC_LEN;
    unsafe {
        if NOTIFY_EP >= MAX_ENDPOINTS || !ENDPOINTS[NOTIFY_EP].active {
            return false;
        }
        for (i, b) in rec.iter().flatten().copied().enumerate() {
            ENDPOINTS[NOTIFY_EP].buf[i] = b;
        }
        ENDPOINTS[NOTIFY_EP].msg_len = len;
        if ENDPOINTS[NOTIFY_EP].state == EpState::RecvWaiting {
            let srv = ENDPOINTS[NOTIFY_EP].server;
            if copy_out(
                crate::tasks::task_user_pml4(srv),
                &ENDPOINTS[NOTIFY_EP].buf[..len],
                ENDPOINTS[NOTIFY_EP].server_recvbuf_va,
            ) {
                ENDPOINTS[NOTIFY_EP].server = usize::MAX;
                ENDPOINTS[NOTIFY_EP].server_recvbuf_va = 0;
                ENDPOINTS[NOTIFY_EP].state = EpState::Idle;
                ENDPOINTS[NOTIFY_EP].caller = child;
                set_ret(srv, ((child as u64) << 32) | (len as u64));
                unblock_task(srv);
                return true;
            }
            // The waiting server's buffer failed the pointer gate: reset the
            // endpoint and park the record so a later serve can pick it up —
            // a poisoned buffer must never corrupt kernel memory.
            ENDPOINTS[NOTIFY_EP].server = usize::MAX;
            ENDPOINTS[NOTIFY_EP].server_recvbuf_va = 0;
            ENDPOINTS[NOTIFY_EP].state = EpState::SendWaiting;
            ENDPOINTS[NOTIFY_EP].caller = child;
            return false;
        } else {
            ENDPOINTS[NOTIFY_EP].state = EpState::SendWaiting;
            ENDPOINTS[NOTIFY_EP].caller = child;
            false
        }
    }
}

/// Set the return value (rax) of a task's saved frame, so it resumes with it.
/// Offset 112 is the rax slot in the switch_frame save/restore layout
/// (switch_frame saves rax to offset 112, restore pops rax from offset 112).
unsafe fn set_ret(idx: usize, val: u64) {
    let f = context_frame(idx) as *mut u64;
    *f.add(112 / 8) = val;
}

/// Copy `len` bytes from the caller's buffer at `va` into kernel `dst`,
/// validating `va` against the address space rooted at `pml4_phys` first.
/// False on an invalid range (nothing copied).
unsafe fn copy_in(pml4_phys: u64, va: u64, dst: &mut [u8]) -> bool {
    crate::user_ptr::copy_from_user(pml4_phys, dst, va)
}

/// Copy `src` into the caller's buffer at `va`, validating `va` against the
/// address space rooted at `pml4_phys` first (writable required). False on an
/// invalid range (nothing copied).
unsafe fn copy_out(pml4_phys: u64, src: &[u8], va: u64) -> bool {
    crate::user_ptr::copy_to_user(pml4_phys, va, src)
}

/// Copy `len` bytes between two caller buffers, validating BOTH sides against
/// their own address spaces (`pml4_src` for `src_va`, `pml4_dst` for
/// `dst_va`). False on any invalid range (nothing copied).
unsafe fn copy_user(pml4_src: u64, src_va: u64, pml4_dst: u64, dst_va: u64, len: usize) -> bool {
    if !crate::user_ptr::validate_range(pml4_src, src_va, len, false)
        || !crate::user_ptr::validate_range(pml4_dst, dst_va, len, true)
    {
        return false;
    }
    core::ptr::copy_nonoverlapping(src_va as *const u8, dst_va as *mut u8, len);
    true
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
            cap: Cap::Endpoint(oid),
            rights,
        } if rights.contains(need)
            && (oid.index as usize) < MAX_ENDPOINTS
            && endpoint_generation(oid.index) == oid.generation =>
        {
            Some(oid.index as usize)
        }
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
    // A create mints a NEW identity for this index: bump the generation so a
    // stale capability (minted against a previous incarnation) fails closed.
    let generation = ENDPOINTS[id].generation.wrapping_add(1);
    ENDPOINTS[id] = Endpoint::new();
    ENDPOINTS[id].generation = generation;
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
            cap: Cap::Endpoint(crate::cap::Oid::new(id as u32, generation)),
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
    // Bounds-check the recipient's table before touching it (mirrors
    // `ipc_cap_revoke`). `dst` and `dst_slot` are ring-3 arguments; without
    // this a caller holding GRANT on *any* slot could write past the task
    // table into arbitrary kernel memory. A malformed argument is refused,
    // never a panic, and the refusal is audited.
    if (dst as usize) >= crate::tasks::MAX_TASKS || (dst_slot as usize) >= crate::tasks::MAX_CAPS {
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
        None => {
            crate::audit::record(cur, crate::audit::OpKind::Send, None, false);
            return -1;
        }
    };
    let len = core::cmp::min(len as usize, IPC_BUF);
    if !copy_in(crate::user_ptr::current_user_pml4(), msg_va, &mut ENDPOINTS[ep].buf[..len]) {
        crate::audit::record(cur, crate::audit::OpKind::Send, None, false);
        return -1;
    }
    ENDPOINTS[ep].msg_len = len;

    if ENDPOINTS[ep].state == EpState::RecvWaiting {
        let srv = ENDPOINTS[ep].server;
        // The waiting server's receive buffer is the SERVER's address space,
        // not the caller's: validate the deferred copy against it.
        if !copy_out(
            crate::tasks::task_user_pml4(srv),
            &ENDPOINTS[ep].buf[..len],
            ENDPOINTS[ep].server_recvbuf_va,
        ) {
            crate::audit::record(cur, crate::audit::OpKind::Send, None, false);
            return -1;
        }
        ENDPOINTS[ep].server = usize::MAX;
        ENDPOINTS[ep].server_recvbuf_va = 0;
        ENDPOINTS[ep].state = EpState::Idle;
        // Caller now waits for the server's reply.
        ENDPOINTS[ep].caller = cur;
        // The reply target is the CALLER's own buffer; validate it now (and
        // again at reply time, against the caller's address space) so a
        // poisoned pointer is refused before it can be stored.
        if !crate::user_ptr::validate_range(
            crate::user_ptr::current_user_pml4(),
            reply_va,
            IPC_BUF,
            true,
        ) {
            crate::audit::record(cur, crate::audit::OpKind::Send, None, false);
            return -1;
        }
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
        // Validate the reply target before storing it (same reasoning as the
        // RecvWaiting fast path above).
        if !crate::user_ptr::validate_range(
            crate::user_ptr::current_user_pml4(),
            reply_va,
            IPC_BUF,
            true,
        ) {
            crate::audit::record(cur, crate::audit::OpKind::Send, None, false);
            return -1;
        }
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
        None => {
            crate::audit::record(cur, crate::audit::OpKind::Recv, None, false);
            return -1;
        }
    };
    match ENDPOINTS[ep].state {
        EpState::SendWaiting => {
            let caller = ENDPOINTS[ep].caller;
            let len = ENDPOINTS[ep].msg_len;
            // The caller's message is delivered into the SERVER's buffer: the
            // deferred copy is validated against the server's address space.
            if !copy_out(
                crate::user_ptr::current_user_pml4(),
                &ENDPOINTS[ep].buf[..len],
                recvbuf_va,
            ) {
                crate::audit::record(cur, crate::audit::OpKind::Recv, None, false);
                return -1;
            }
            // Caller stays blocked, now awaiting the reply.
            ENDPOINTS[ep].state = EpState::Idle;
            set_ret(cur, ((caller as u64) << 32) | (len as u64));
            (((caller as u64) << 32) | (len as u64)) as i64
        }
        _ => {
            // Park the receive buffer only after the pointer gate approves it:
            // a poisoned recvbuf_va must never be stored for a later copy_out.
            if !crate::user_ptr::validate_range(
                crate::user_ptr::current_user_pml4(),
                recvbuf_va,
                IPC_BUF,
                true,
            ) {
                crate::audit::record(cur, crate::audit::OpKind::Recv, None, false);
                return -1;
            }
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
        None => {
            crate::audit::record(cur, crate::audit::OpKind::Send, None, false);
            return -1;
        }
    };
    let caller = caller_id as usize;
    // The caller index is a ring-3 argument (the server echoes back the value
    // `ipc_serve` returned). Validate it twice: the index must name a real
    // task, and it must be the task actually blocked awaiting a reply on this
    // endpoint. Without this a malicious server could write a forged return
    // value into an arbitrary task's saved frame and force it runnable —
    // `set_ret`/`unblock_task` both index the task table from `caller`.
    if caller >= crate::tasks::MAX_TASKS || ENDPOINTS[ep].caller != caller {
        crate::audit::record(
            cur,
            crate::audit::OpKind::Send,
            Some(ENDPOINTS[ep].caller as u32),
            false,
        );
        return -1;
    }
    let rlen = core::cmp::min(rlen as usize, IPC_BUF);
    // The reply flows server buffer -> caller buffer: both sides are validated
    // against their OWN address spaces (the caller's reply buffer belongs to
    // the caller's space, even though the server is the one running).
    if !copy_user(
        crate::user_ptr::current_user_pml4(),
        reply_va,
        crate::tasks::task_user_pml4(caller),
        ENDPOINTS[ep].caller_reply_va,
        rlen,
    ) {
        crate::audit::record(
            cur,
            crate::audit::OpKind::Send,
            Some(caller as u32),
            false,
        );
        return -1;
    }
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
                cap: Cap::Endpoint(crate::cap::Oid::new(7, 0)),
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
            cap: Cap::Endpoint(crate::cap::Oid::new(3, 0)),
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
                cap: Cap::Task(crate::cap::Oid::new(1, 0)),
                rights: Rights::ALL,
            },
        );
        set_task_cap(
            3,
            2,
            CapSlot {
                cap: Cap::MemRegion(crate::cap::Oid::new(4, 0)),
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

    // ---- Phase 5: reserved TaskKill notification endpoint ----

    #[test]
    fn reserved_notify_endpoint_init_activates_last_slot() {
        let _g = crate::kernel_state_guard();
        super::init_notify_endpoint();
        assert_eq!(NOTIFY_EP, MAX_ENDPOINTS - 1);
        assert!(unsafe { ENDPOINTS[NOTIFY_EP].active });
        // Ordinary endpoint create never steals the reserved slot.
        crate::tasks::set_current_for_test(0);
        let slot = unsafe { ipc_endpoint_create() };
        assert!(slot >= 0);
        let cap = task_cap(0, slot as usize);
        match cap.cap {
            Cap::Endpoint(id) => {
                assert_ne!(id.index as usize, NOTIFY_EP, "reserved slot leaks")
            }
            _ => unreachable!("endpoint create installs an Endpoint cap"),
        }
    }

    #[test]
    fn notify_task_kill_mailboxes_without_a_waiting_server() {
        let _g = crate::kernel_state_guard();
        unsafe {
            super::init_notify_endpoint();
            // No server is waiting: the record must park in the mailbox.
            assert!(!super::notify_task_kill(5, REASON_PF_ISOLATION));
            assert_eq!(ENDPOINTS[NOTIFY_EP].state, EpState::SendWaiting);
            assert_eq!(ENDPOINTS[NOTIFY_EP].msg_len, NOTIFY_REC_LEN);
            assert_eq!(ENDPOINTS[NOTIFY_EP].caller, 5);
            assert_eq!(
                u32::from_le_bytes(ENDPOINTS[NOTIFY_EP].buf[0..4].try_into().unwrap()),
                5
            );
            assert_eq!(
                u32::from_le_bytes(ENDPOINTS[NOTIFY_EP].buf[4..8].try_into().unwrap()),
                REASON_PF_ISOLATION
            );
        }
    }

    #[test]
    fn notify_task_kill_delivers_to_a_waiting_server() {
        let _g = crate::kernel_state_guard();
        unsafe {
            // A host-side scratch buffer stands in for the ring-3 server's
            // recv buffer; copy_out must land the record there.
            static mut SCRATCH: [u8; 16] = [0u8; 16];
            crate::tasks::reset_table_for_test();
            crate::tasks::spawn("srv", crate::tasks::tests_dummy, 0x100000).unwrap();
            super::init_notify_endpoint();
            // Pin task 0 as the waiting server, blocked on the notify ep.
            crate::tasks::set_current_for_test(0);
            block_current(NOTIFY_EP);
            ENDPOINTS[NOTIFY_EP].state = EpState::RecvWaiting;
            ENDPOINTS[NOTIFY_EP].server = 0;
            ENDPOINTS[NOTIFY_EP].server_recvbuf_va = (&raw mut SCRATCH) as u64;
            // The kill is parked and delivered to the waiting server.
            assert!(super::notify_task_kill(5, REASON_NX));
            assert_eq!(
                u32::from_le_bytes(SCRATCH[0..4].try_into().unwrap()),
                5,
                "record child index must reach the server buffer"
            );
            assert_eq!(
                u32::from_le_bytes(SCRATCH[4..8].try_into().unwrap()),
                REASON_NX
            );
            // The server is runnable again with (child << 32) | len in rax.
            assert!(crate::tasks::is_task_alive(0));
            assert_eq!(
                crate::tasks::task_state_of(0),
                crate::tasks::TaskState::Ready
            );
            let f = crate::tasks::context_frame(0) as *const u64;
            assert_eq!(*f.add(112 / 8), (5u64 << 32) | NOTIFY_REC_LEN as u64);
            // Endpoint is idle again (single-slot box consumed).
            assert_eq!(ENDPOINTS[NOTIFY_EP].state, EpState::Idle);
        }
    }

    #[test]
    fn cap_grant_refuses_out_of_range_recipient() {
        let _g = crate::kernel_state_guard();
        crate::audit::reset_for_test();
        crate::tasks::reset_table_for_test();
        crate::tasks::set_current_for_test(5);
        // The caller holds GRANT on a live capability it could legitimately
        // delegate; only the recipient's *indices* are hostile.
        set_task_cap(
            5,
            1,
            CapSlot {
                cap: Cap::Task(crate::cap::Oid::new(2, 0)),
                rights: Rights::ALL,
            },
        );
        // dst task index out of range.
        assert_eq!(
            unsafe { ipc_cap_grant(crate::tasks::MAX_TASKS as u64, 1, 0) },
            -1
        );
        // dst slot out of range.
        assert_eq!(
            unsafe { ipc_cap_grant(0, 1, crate::tasks::MAX_CAPS as u64) },
            -1
        );
        // Both indices huge.
        assert_eq!(unsafe { ipc_cap_grant(u64::MAX, 1, u64::MAX) }, -1);
        // The refusals are audited, and a well-formed grant still succeeds.
        assert_eq!(unsafe { ipc_cap_grant(3, 1, 0) }, 0);
        assert_eq!(
            crate::audit::op_counts(5)[crate::audit::OpKind::Grant.index()],
            4,
            "three refusals + one success are all in the audit log"
        );
        assert_eq!(
            task_cap(3, 0).cap,
            Cap::Task(crate::cap::Oid::new(2, 0)),
            "the valid grant must still land"
        );
    }

    #[test]
    fn reply_refuses_forged_and_out_of_range_callers() {
        let _g = crate::kernel_state_guard();
        crate::audit::reset_for_test();
        crate::tasks::reset_table_for_test();
        crate::tasks::set_current_for_test(2);
        unsafe {
            // A server holds RECV on endpoint 0.
            set_task_cap(
                2,
                0,
                CapSlot {
                    cap: Cap::Endpoint(crate::cap::Oid::new(0, 0)),
                    rights: Rights::ALL,
                },
            );
            ENDPOINTS[0] = Endpoint::new();
            ENDPOINTS[0].active = true;
            // A caller index out of range must be refused (never an OOB write
            // into the task table via set_ret/unblock_task).
            assert_eq!(ipc_reply(0, crate::tasks::MAX_TASKS as u64, 0, 4), -1);
            // A forged in-range caller that is NOT the task blocked awaiting a
            // reply on this endpoint must be refused too.
            assert_eq!(ipc_reply(0, 7, 0, 4), -1);
            // Only the matching blocked caller is accepted.
            // Raw buffers (Box::into_raw) so `copy_user`'s integer->pointer
            // write keeps valid provenance under Miri — an `as_ptr()`-derived
            // address would point at a popped shared-ref tag.
            let src = Box::into_raw(Box::new([0xAAu8; 4])) as *mut u8 as u64;
            let dst = Box::into_raw(Box::new([0u8; 16])) as *mut u8 as u64;
            ENDPOINTS[0].caller = 7;
            ENDPOINTS[0].caller_reply_va = dst;
            assert_eq!(ipc_reply(0, 7, src, 4), 0);
            assert_eq!(
                core::slice::from_raw_parts(dst as *const u8, 4),
                &[0xAAu8; 4],
                "the reply bytes land in the caller's buffer"
            );
            drop(Box::from_raw(src as *mut [u8; 4]));
            drop(Box::from_raw(dst as *mut [u8; 16]));
        }
        assert_eq!(
            crate::audit::op_counts(2)[crate::audit::OpKind::Send.index()],
            2,
            "both forged/out-of-range reply attempts are audited"
        );
    }
}

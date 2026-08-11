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
//! once isolation lands. There is no capability sealing/revocation yet beyond
//! the per-task table; no async/notify variant yet (only synchronous call/reply).

use crate::cap::Cap;
use crate::tasks::{current_idx, context_frame, task_cap, set_task_cap, unblock_task, block_current, switch_away_from};

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

fn cap_to_ep(cur: usize, slot: u64) -> Option<usize> {
    if slot as usize >= crate::tasks::MAX_CAPS {
        return None;
    }
    match task_cap(cur, slot as usize) {
        Cap::Endpoint(id) => Some(id as usize),
        Cap::None => None,
    }
}

/// Syscall: create an endpoint, returning the capability slot in the caller's
/// table (or -1 on failure).
pub unsafe fn ipc_endpoint_create() -> i64 {
    let cur = current_idx();
    let id = (0..MAX_ENDPOINTS).find(|&i| !ENDPOINTS[i].active);
    let id = match id {
        Some(i) => i,
        None => return -1,
    };
    ENDPOINTS[id] = Endpoint::new();
    ENDPOINTS[id].active = true;
    let slot = (0..crate::tasks::MAX_CAPS).find(|&s| task_cap(cur, s) == Cap::None);
    let slot = match slot {
        Some(s) => s,
        None => {
            ENDPOINTS[id].active = false;
            return -1;
        }
    };
    set_task_cap(cur, slot, Cap::Endpoint(id as u32));
    slot as i64
}

/// Syscall: grant the caller's capability `src_slot` to task `dst` at its
/// slot `dst_slot` (so the destination knows where to find it). Returns
/// `dst_slot` on success, or -1.
pub unsafe fn ipc_cap_grant(dst: u64, src_slot: u64, dst_slot: u64) -> i64 {
    let cur = current_idx();
    let cap = task_cap(cur, src_slot as usize);
    if cap == Cap::None {
        return -1;
    }
    set_task_cap(dst as usize, dst_slot as usize, cap);
    0
}

/// Syscall: `int 0x80` with rax=5. Blocks the caller until the server replies.
/// `ep_slot` = capability slot, `msg_va`/`len` = request, `reply_va` = where
/// the reply is written. Returns the reply length (delivered via the caller's
/// frame rax when it is resumed).
pub unsafe fn ipc_call(ep_slot: u64, msg_va: u64, len: u64, reply_va: u64) -> i64 {
    let cur = current_idx();
    crate::sprintln!("Aegis: ipc_call cur={} ep_slot={}", cur, ep_slot);
    let ep = match cap_to_ep(cur, ep_slot) {
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
pub unsafe fn ipc_serve(ep_slot: u64, recvbuf_va: u64) -> i64 {
    let cur = current_idx();
    crate::sprintln!("Aegis: ipc_serve cur={} ep_slot={}", cur, ep_slot);
    let ep = match cap_to_ep(cur, ep_slot) {
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
pub unsafe fn ipc_reply(ep_slot: u64, caller_id: u64, reply_va: u64, rlen: u64) -> i64 {
    let cur = current_idx();
    let ep = match cap_to_ep(cur, ep_slot) {
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
#[allow(dead_code)]
pub unsafe fn force_unblock(idx: usize) {
    unblock_task(idx);
}

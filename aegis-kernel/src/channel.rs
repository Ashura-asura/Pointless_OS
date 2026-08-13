//! Asynchronous message channel (FIFO box) — the design doc §8 second IPC
//! primitive: "an asynchronous notification/queue primitive for events and
//! streaming data", alongside the synchronous rendezvous endpoint.
//!
//! A channel is a kernel object (`Cap::Channel(id)`) whose holder can push
//! bounded messages with SEND and pop them with RECV, non-blocking. It is what
//! the loopback netstack (`netstack.rs`) uses as a socket: a socket is a
//! channel capability, so "holding a network capability" is exactly "holding a
//! specific channel cap" — never ambient networking authority.
//!
//! Honest limits: fixed, bounded message size (`CHANNEL_BUF`) and depth
//! (`CHANNEL_DEPTH`) in a fixed channel table (`MAX_CHANNELS`) — no zero-copy,
//! no out-of-order, no multicast; blocking is a userspace-scheduling concern
//! and deliberately absent (matching the kernel's single-threaded model and
//! the model crate's non-blocking `ep_recv`).

use crate::audit::OpKind as AuditedOp;
use crate::cap::{Cap, CapSlot, Rights};
use crate::tasks::{set_task_cap, task_cap};

pub const MAX_CHANNELS: usize = 16;
pub const CHANNEL_BUF: usize = 64;
pub const CHANNEL_DEPTH: usize = 8;

/// One channel object. A fixed circular FIFO of bounded messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Channel {
    active: bool,
    msgs: [[u8; CHANNEL_BUF]; CHANNEL_DEPTH],
    lens: [u16; CHANNEL_DEPTH],
    head: usize,
    count: usize,
}

impl Channel {
    const INACTIVE: Channel = Channel {
        active: false,
        msgs: [[0; CHANNEL_BUF]; CHANNEL_DEPTH],
        lens: [0; CHANNEL_DEPTH],
        head: 0,
        count: 0,
    };
}

static mut CHANNELS: [Channel; MAX_CHANNELS] = [Channel::INACTIVE; MAX_CHANNELS];

unsafe fn channel_mut(id: usize) -> *mut Channel {
    (core::ptr::addr_of_mut!(CHANNELS) as *mut Channel).add(id)
}

/// Resolve `slot` in task `cur`'s CSpace to a channel id, requiring `need`.
/// `None` when the slot is out of range, empty, names a non-channel object,
/// holds insufficient rights, or references an inactive (destroyed) channel.
fn caps_channel(cur: usize, slot: u64, need: Rights) -> Option<usize> {
    if slot as usize >= crate::tasks::MAX_CAPS {
        return None;
    }
    let cs = task_cap(cur, slot as usize);
    match cs.cap {
        Cap::Channel(id) if cs.rights.contains(need) => {
            let id = id as usize;
            unsafe {
                if (*channel_mut(id)).active {
                    Some(id)
                } else {
                    None
                }
            }
        }
        _ => None,
    }
}

/// Resolve `slot` in task `cur`'s CSpace to a live channel id regardless of
/// rights. `None` for an out-of-range, missing, non-channel/inactive object.
fn caps_channel_any(cur: usize, slot: u64) -> Option<usize> {
    if slot as usize >= crate::tasks::MAX_CAPS {
        return None;
    }
    let cs = task_cap(cur, slot as usize);
    match cs.cap {
        Cap::Channel(id) => {
            let id = id as usize;
            unsafe {
                if (*channel_mut(id)).active {
                    Some(id)
                } else {
                    None
                }
            }
        }
        _ => None,
    }
}

/// Kernel-internal (explicit identity): resolve `slot` to a live channel id in
/// `cur`'s CSpace regardless of rights (the netstack's routing check; the real
/// SEND/RECV authorization still happens at send/recv).
pub(crate) fn channel_of(cur: usize, slot: u64) -> Option<u32> {
    caps_channel_any(cur, slot).map(|id| id as u32)
}

/// Syscall: create a channel, installing a SEND|RECV capability in the
/// caller's table. Returns the capability slot, or -1 on any failure (no free
/// channel, no free capability slot).
///
/// # Safety
/// Must be called via syscall with valid task context.
pub unsafe fn ch_create() -> i64 {
    let cur = crate::tasks::current_idx();
    let id = (0..MAX_CHANNELS).find(|&i| !(*channel_mut(i)).active);
    let id = match id {
        Some(i) => i,
        None => return -1,
    };
    (*channel_mut(id)).active = true;
    let slot = (0..crate::tasks::MAX_CAPS).find(|&s| task_cap(cur, s).cap == Cap::None);
    let slot = match slot {
        Some(s) => s,
        None => {
            (*channel_mut(id)).active = false;
            return -1;
        }
    };
    set_task_cap(
        cur,
        slot,
        CapSlot {
            cap: Cap::Channel(id as u32),
            rights: crate::cap::CHANNEL_RIGHTS,
        },
    );
    slot as i64
}

/// Kernel-internal (explicit identity): push `data` onto the channel `slot`
/// resolves to in `caller`'s CSpace, requiring the caller hold SEND. Bounded:
/// a message larger than `CHANNEL_BUF` or a full queue leaves no message.
/// Every attempt — granted or refused — is one attributed `Send` record.
pub(crate) unsafe fn ch_send_as(caller: usize, slot: u64, data: &[u8]) -> bool {
    let id = match caps_channel(caller, slot, Rights::SEND) {
        Some(i) => i,
        None => {
            crate::audit::record(caller, AuditedOp::Send, None, false);
            return false;
        }
    };
    if data.len() > CHANNEL_BUF {
        crate::audit::record(caller, AuditedOp::Send, Some(id as u32), false);
        return false;
    }
    let c = &mut *channel_mut(id);
    if c.count >= CHANNEL_DEPTH {
        crate::audit::record(caller, AuditedOp::Send, Some(id as u32), false);
        return false;
    }
    let tail = (c.head + c.count) % CHANNEL_DEPTH;
    c.msgs[tail][..data.len()].copy_from_slice(data);
    c.lens[tail] = data.len() as u16;
    c.count += 1;
    crate::audit::record(caller, AuditedOp::Send, Some(id as u32), true);
    true
}

/// Kernel-internal (explicit identity): pop the oldest message from the
/// channel `slot` resolves to in `caller`'s CSpace (caller must hold RECV)
/// into `out`. Returns `-1` on a gate failure, `0` on an empty queue, or the
/// message length with `out[..n]` holding the bytes.
pub(crate) unsafe fn ch_recv_as(caller: usize, slot: u64, out: &mut [u8]) -> i64 {
    let id = match caps_channel(caller, slot, Rights::RECV) {
        Some(i) => i,
        None => {
            crate::audit::record(caller, AuditedOp::Recv, None, false);
            return -1;
        }
    };
    let c = &mut *channel_mut(id);
    if c.count == 0 {
        crate::audit::record(caller, AuditedOp::Recv, Some(id as u32), true);
        return 0;
    }
    let len = c.lens[c.head] as usize;
    let n = len.min(out.len());
    out[..n].copy_from_slice(&c.msgs[c.head][..n]);
    c.head = (c.head + 1) % CHANNEL_DEPTH;
    c.count -= 1;
    crate::audit::record(caller, AuditedOp::Recv, Some(id as u32), true);
    n as i64
}

/// Syscall: push one message onto channel `slot` (current task, SEND
/// required). `0` on success, `-1` on a gate failure, an oversized message, or
/// a full queue.
///
/// # Safety
/// Must be called via syscall; `src_va` must be a readable caller buffer.
pub unsafe fn ch_send(slot: u64, len: u64, src_va: u64) -> i64 {
    if len > CHANNEL_BUF as u64 {
        return -1;
    }
    let data = core::slice::from_raw_parts(src_va as *const u8, len as usize);
    if !ch_send_as(crate::tasks::current_idx(), slot, data) {
        return -1;
    }
    0
}

/// Syscall: pop the oldest message from channel `slot` (current task, RECV
/// required) into `dst_va`, returning its length; `0` when the queue is empty;
/// `-1` when the caller does not hold RECV on a live channel.
///
/// # Safety
/// Must be called via syscall; `dst_va` must be a writable caller buffer of at
/// least `CHANNEL_BUF` bytes.
pub unsafe fn ch_recv(slot: u64, dst_va: u64) -> i64 {
    let out = core::slice::from_raw_parts_mut(dst_va as *mut u8, CHANNEL_BUF);
    ch_recv_as(crate::tasks::current_idx(), slot, out)
}

/// Destroy a channel (kernel-internal, trusted — the netstack tears sockets
/// down with this). The object stops accepting any operation; capabilities
/// still held on it become dangling and every gated operation on them fails.
pub fn ch_destroy(id: u32) -> bool {
    if (id as usize) >= MAX_CHANNELS {
        return false;
    }
    unsafe {
        let c = &mut *channel_mut(id as usize);
        if !c.active {
            return false;
        }
        *c = Channel::INACTIVE;
    }
    true
}

/// Test-only: clear every channel so contract tests start deterministic.
#[cfg(test)]
pub(crate) fn reset_channels_for_test() {
    unsafe {
        for i in 0..MAX_CHANNELS {
            *channel_mut(i) = Channel::INACTIVE;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::reset_table_for_test;

    fn clear_all_caps() {
        for i in 0..crate::tasks::MAX_TASKS {
            for s in 0..crate::tasks::MAX_CAPS {
                crate::tasks::set_task_cap(i, s, crate::cap::CapSlot::empty());
            }
        }
    }

    #[test]
    fn fifo_order_is_preserved_and_drain_is_exact() {
        let _g = crate::kernel_state_guard();
        unsafe {
            reset_channels_for_test();
            reset_table_for_test();
            clear_all_caps();
            crate::tasks::set_current_for_test(0);
            let a = ch_create();
            assert!(a >= 0, "channel mints");
            let slot = a as u64;
            let mut out = [0u8; CHANNEL_BUF];
            let payloads: [&[u8]; 3] = [b"one".as_slice(), b"two", b"three"];
            for payload in payloads.iter() {
                assert_eq!(
                    ch_send(slot, payload.len() as u64, payload.as_ptr() as u64),
                    0
                );
            }
            for payload in payloads.iter() {
                let n = ch_recv(slot, out.as_mut_ptr() as u64);
                assert_eq!(n as usize, payload.len(), "received a whole message");
                assert_eq!(&out[..n as usize], *payload, "bytes intact");
            }
            assert_eq!(
                ch_recv(slot, out.as_mut_ptr() as u64),
                0,
                "queue drained exactly"
            );
        }
    }

    #[test]
    fn send_requires_send_and_oversized_messages_are_refused() {
        let _g = crate::kernel_state_guard();
        unsafe {
            reset_channels_for_test();
            reset_table_for_test();
            clear_all_caps();
            crate::tasks::set_current_for_test(0);
            // A fabricated slot carries no channel cap: -1.
            assert_eq!(ch_send(0, 1, 0x1000), -1, "no cap, no send");
            assert_eq!(ch_recv(0, 0x2000), -1, "no cap, no recv");
            // An oversized message is refused even with a live channel.
            let slot = ch_create() as u64;
            assert_eq!(ch_send(slot, (CHANNEL_BUF + 1) as u64, 0x1000), -1);
            assert_eq!(ch_send(slot, 0, 0x1000), 0, "empty message is legal");
        }
    }
}

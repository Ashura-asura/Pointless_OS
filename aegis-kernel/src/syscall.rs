//! Ring-3 syscall entry: an IDT gate at `SYS_VECTOR` (int 0x80) with a
//! naked stub that mirrors the exception-frame layout, a Rust handler that
//! reads the syscall number and arguments out of the saved frame, and a
//! small `dispatch` table.
//!
//! Calling convention (user side, all args in registers):
//!   rax = syscall number, rsi = arg1 (e.g. buffer pointer), rcx = arg2
//!   (e.g. length), rdx = arg3. The handler stores the return value back
//!   into the saved `rax` slot, so the `iretq` tail returns it to the
//!   caller.
//!
//! Honest limits: the gate is an INTERRUPT gate (IF cleared for the
//! handler, restored by iretq), so a syscall is never preempted
//! mid-handler and the shared CPL0 stack stays consistent. Verified under
//! QEMU/TCG only.

use core::arch::naked_asm;

/// IDT vector used for the syscall gate (int 0x80).
pub const SYS_VECTOR: u8 = 0x80;

/// Syscall numbers
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNum {
    Exit = 0,
    Write = 1,
    Read = 2,
    Yield = 3,
    Fork = 4,
    /// IPC: blocking call to an endpoint (rax=5, rsi=ep_slot, rdx=msg_va,
    /// rcx=len, r8=reply_va). Returns reply length.
    Call = 5,
    /// IPC: server blocks until a call arrives (rax=6, rsi=ep_slot,
    /// rdx=recvbuf_va). Returns (caller_id<<32)|len.
    Serve = 6,
    /// IPC: server sends the reply (rax=7, rsi=ep_slot, rdx=caller_id,
    /// rcx=reply_va, r8=rlen).
    Reply = 7,
    /// IPC: create an endpoint, returns the capability slot. (rax=8)
    EndpointCreate = 8,
    /// IPC: grant a capability to another task (rax=9, rsi=dst_task,
    /// rcx=src_slot, rdx=dst_slot). Returns 0 or -1.
    CapGrant = 9,
    /// Memory: create a region of `rsi` pages, installs a READ|WRITE|GRANT
    /// capability, returns its slot (rax=10).
    MemCreate = 10,
    /// Memory: byte length of region `rsi` (rax=11). Requires READ.
    MemLen = 11,
    /// Memory: copy `rdx` bytes from region `rsi` at `rcx` into `r8` (rax=12).
    /// Requires READ. Returns bytes copied or -1.
    MemRead = 12,
    /// Memory: copy `rdx` bytes from `r8` into region `rsi` at `rcx` (rax=13).
    /// Requires WRITE. Returns 0 or -1.
    MemWrite = 13,
    /// Supervisor: state of task `rsi` (rax=14). Requires READ: 1 alive, 0
    /// dead, -1 not a task cap.
    TaskState = 14,
    /// Supervisor: kill task `rsi` (rax=15). Requires CONTROL.
    TaskKill = 15,
    /// Supervisor: restart a killed task `rsi` (rax=16). Requires CONTROL.
    TaskRestart = 16,
    /// IPC: revoke a capability previously granted (rax=17, rsi=dst_task,
    /// rcx=dst_slot, rdx=src_slot). Requires GRANT on the source. Returns 0 or -1.
    CapRevoke = 17,
    /// Role: grant role `rsi` over task `rcx` to task `rdx` at `r8` (rax=18).
    /// The grantor must hold the role's exact rights over the target; the
    /// grantee receives exactly the role's capability set. Returns 0 or -1.
    RoleGrant = 18,
}

/// Maximum bytes a user `Write` may ask to print per call (defensive cap
/// on the untrusted length argument).
pub const WRITE_MAX_LEN: usize = 256;

/// Clamp an untrusted user length to `WRITE_MAX_LEN`.
pub const fn clamp_write_len(raw: u64) -> usize {
    if raw as usize > WRITE_MAX_LEN {
        WRITE_MAX_LEN
    } else {
        raw as usize
    }
}

/// Dispatch a system call.
/// Returns -1 for unimplemented syscalls, 0 for Yield and Write success.
///
/// `arg1`..`arg4` are the raw user-supplied arguments (pointers are
/// NOT validated — the demo kernel maps the whole first 1 GB with U/S).
/// Register layout: arg1=rsi, arg2=rcx, arg3=rdx, arg4=r8.
pub fn dispatch(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret = dispatch_impl(num, arg1, arg2, arg3, arg4);
    crate::trace::op(num, arg1, arg2, arg3, arg4, ret);
    ret
}

fn dispatch_impl(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    match num {
        0 => -1, // Exit — not implemented
        1 => {
            // Write: print arg2 bytes from the buffer at arg1 to COM1
            // (and mirror them to the VGA text console).
            let buf =
                unsafe { core::slice::from_raw_parts(arg1 as *const u8, clamp_write_len(arg2)) };
            let mut w = crate::serial::SerialWriter;
            w.write_bytes(buf);
            crate::vga::vga_write_bytes(buf);
            0
        }
        2 => -1, // Read — not implemented
        3 => 0,  // Yield — returns success
        4 => -1, // Fork — not implemented
        // IPC: Call(ep_slot, msg_va, len, reply_va)
        5 => unsafe { crate::ipc::ipc_call(arg1, arg2, arg3, arg4) },
        // IPC: Serve(ep_slot, recvbuf_va)
        6 => unsafe { crate::ipc::ipc_serve(arg1, arg2) },
        // IPC: Reply(ep_slot, caller_id, reply_va, rlen)
        7 => unsafe { crate::ipc::ipc_reply(arg1, arg2, arg3, arg4) },
        // IPC: EndpointCreate()
        8 => unsafe { crate::ipc::ipc_endpoint_create() },
        // IPC: CapGrant(dst_task, src_slot, dst_slot)
        9 => unsafe { crate::ipc::ipc_cap_grant(arg1, arg2, arg3) },
        // Memory: MemCreate(frames)
        10 => unsafe { crate::mem::mem_create(arg1) },
        // Memory: MemLen(slot)
        11 => unsafe { crate::mem::mem_len(arg1) },
        // Memory: MemRead(slot, offset, len, dst_va)
        12 => unsafe { crate::mem::mem_read(arg1, arg2, arg3, arg4) },
        // Memory: MemWrite(slot, offset, len, src_va)
        13 => unsafe { crate::mem::mem_write(arg1, arg2, arg3, arg4) },
        // Supervisor: TaskState(task_slot)
        14 => crate::supervisor::task_state(arg1),
        // Supervisor: TaskKill(task_slot)
        15 => crate::supervisor::task_kill(arg1),
        // Supervisor: TaskRestart(task_slot)
        16 => crate::supervisor::task_restart(arg1),
        // IPC: CapRevoke(dst_task, dst_slot, src_slot)
        17 => unsafe { crate::ipc::ipc_cap_revoke(arg1, arg2, arg3) },
        // Role: RoleGrant(role_id, grantee, target, dst_slot)
        18 => crate::role::role_grant(arg1, arg2, arg3, arg4),
        // Net: NetSocket(kind, ip_packed, port) — mint a destination-scoped
        // NetEndpoint cap. kind 1 = TCP, 2 = UDP.
        19 => unsafe { crate::netif::sys_net_socket(arg1, arg2, arg3) },
        // Net: NetConnect(slot) — SEND-gated; 3-way handshake to the bound dst.
        20 => unsafe { crate::netif::sys_net_connect(arg1) },
        // Net: NetSend(slot, va, len) — SEND-gated; queue + transmit.
        21 => unsafe { crate::netif::sys_net_send(arg1, arg2, arg3) },
        // Net: NetRecv(slot, va, len) — RECV-gated; drain the socket buffer.
        22 => unsafe { crate::netif::sys_net_recv(arg1, arg2, arg3) },
        // Net: NetClose(slot) — close + clear the cap slot.
        23 => unsafe { crate::netif::sys_net_close(arg1) },
        _ => -1, // Unknown syscall
    }
}

/// Rust side of the syscall stub: `frame` points at the saved register
/// block on the stack (layout: [0] error slot, [1..11] rax rbx rcx rdx
/// rsi rdi r8 r9 r10 r11, then the interrupt frame). Reads the number from
/// the rax slot and the arguments from the rsi/rcx/rdx slots, and writes
/// the return value back into the rax slot.
///
/// # Safety
///
/// `frame` must point at the live syscall regs block pushed by the stub on
/// the current kernel stack.
#[no_mangle]
pub unsafe extern "sysv64" fn syscall_trap_rust(frame: *mut u64) {
    // Stub push order: `push 0`, then `rax rbx rcx rdx rsi rdi r8 r9 r10 r11`,
    // then `sub rsp,8`. `rdi` (the frame base) points at the lowest address,
    // so the saved registers sit at: r11=1, r10=2, r9=3, r8=4, rdi=5,
    // rsi=6, rdx=7, rcx=8, rbx=9, rax=10, error-slot=11.
    // The Phase J Linux task runs a real Linux ELF that traps via int 0x80
    // with the Linux register convention (rdi/rsi/rdx/r10/r8/r9) and Linux
    // syscall numbers — a genuinely separate path from native dispatch, so
    // it is routed before the native `dispatch` is ever reached.
    let ret = if crate::linux_compat_elf::linux_task_idx() == crate::tasks::current_idx() {
        crate::linux_compat_elf::dispatch_linux_syscall(frame)
    } else {
        let num = unsafe { *frame.add(10) }; // rax
        let arg1 = unsafe { *frame.add(6) }; // rsi
        let arg2 = unsafe { *frame.add(8) }; // rcx
        let arg3 = unsafe { *frame.add(7) }; // rdx
        let arg4 = unsafe { *frame.add(4) }; // r8
        dispatch(num, arg1, arg2, arg3, arg4)
    };
    unsafe { *frame.add(10) = ret as u64 }; // rax
}

/// Interrupt-gate stub for the syscall vector. The CPU performs the
/// ring-3 -> ring-0 stack switch (TSS.RSP0), pushes the 5-word interrupt
/// frame, and clears IF; this stub then saves the GPR block (with the
/// syscall args in rax/rsi/rcx/rdx), calls `syscall_trap_rust`, restores
/// the block (rax now carries the return value), and returns to ring 3.
///
/// Stack alignment at the `call` follows the exception-stub discipline:
/// the CPU's entry stack is 8 mod 16, so push error + 10 GPRs (88 bytes)
/// leaves it 0 mod 16 and `sub rsp, 8` re-aligns it for the call.
#[unsafe(naked)]
#[no_mangle]
pub extern "sysv64" fn syscall_stub() -> ! {
    naked_asm!(
        "push 0",
        "push rax", "push rbx", "push rcx", "push rdx",
        "push rsi", "push rdi", "push r8", "push r9",
        "push r10", "push r11",
        "sub rsp, 8",
        "mov rdi, rsp",
        "call {trap}",
        "add rsp, 8",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rbx", "pop rax",
        "add rsp, 8",
        "iretq",
        trap = sym syscall_trap_rust,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_numbers_match_the_enum() {
        assert_eq!(SyscallNum::Exit as u64, 0);
        assert_eq!(SyscallNum::Write as u64, 1);
        assert_eq!(SyscallNum::Read as u64, 2);
        assert_eq!(SyscallNum::Yield as u64, 3);
        assert_eq!(SyscallNum::Fork as u64, 4);
        assert_eq!(SyscallNum::CapRevoke as u64, 17);
        assert_eq!(SyscallNum::RoleGrant as u64, 18);
    }

    #[test]
    fn unknown_syscalls_return_minus_one() {
        assert_eq!(dispatch(99, 0, 0, 0, 0), -1);
        assert_eq!(dispatch(SyscallNum::Read as u64, 0, 0, 0, 0), -1);
        assert_eq!(dispatch(SyscallNum::Exit as u64, 0, 0, 0, 0), -1);
        assert_eq!(dispatch(SyscallNum::Fork as u64, 0, 0, 0, 0), -1);
    }

    #[test]
    fn yield_returns_zero() {
        assert_eq!(dispatch(SyscallNum::Yield as u64, 0, 0, 0, 0), 0);
    }

    #[test]
    fn write_length_is_capped_at_the_maximum() {
        assert_eq!(clamp_write_len(u64::MAX), WRITE_MAX_LEN);
        assert_eq!(clamp_write_len(WRITE_MAX_LEN as u64), WRITE_MAX_LEN);
        assert_eq!(clamp_write_len(3), 3);
        assert_eq!(clamp_write_len(0), 0);
    }

    #[test]
    fn write_with_zero_length_returns_zero() {
        // No bytes requested: the buffer pointer is never dereferenced.
        assert_eq!(dispatch(SyscallNum::Write as u64, 0x1000, 0, 0, 0), 0);
    }
}

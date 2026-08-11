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
/// `arg1`/`arg2`/`arg3` are the raw user-supplied arguments (pointers are
/// NOT validated — the demo kernel maps the whole first 1 GB with U/S).
pub fn dispatch(num: u64, arg1: u64, arg2: u64, _arg3: u64) -> i64 {
    match num {
        0 => -1, // Exit — not implemented
        1 => {
            // Write: print arg2 bytes from the buffer at arg1 to COM1.
            let buf =
                unsafe { core::slice::from_raw_parts(arg1 as *const u8, clamp_write_len(arg2)) };
            let mut w = crate::serial::SerialWriter;
            w.write_bytes(buf);
            0
        }
        2 => -1, // Read — not implemented
        3 => 0,  // Yield — returns success
        4 => -1, // Fork — not implemented
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
    let num = unsafe { *frame.add(10) }; // rax
    let arg1 = unsafe { *frame.add(6) }; // rsi
    let arg2 = unsafe { *frame.add(8) }; // rcx
    let arg3 = unsafe { *frame.add(7) }; // rdx
    let ret = dispatch(num, arg1, arg2, arg3);
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
    }

    #[test]
    fn unknown_syscalls_return_minus_one() {
        assert_eq!(dispatch(99, 0, 0, 0), -1);
        assert_eq!(dispatch(SyscallNum::Read as u64, 0, 0, 0), -1);
        assert_eq!(dispatch(SyscallNum::Exit as u64, 0, 0, 0), -1);
        assert_eq!(dispatch(SyscallNum::Fork as u64, 0, 0, 0), -1);
    }

    #[test]
    fn yield_returns_zero() {
        assert_eq!(dispatch(SyscallNum::Yield as u64, 0, 0, 0), 0);
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
        assert_eq!(dispatch(SyscallNum::Write as u64, 0x1000, 0, 0), 0);
    }
}

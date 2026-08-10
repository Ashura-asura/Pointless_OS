/// System call numbers
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNum {
    Exit = 0,
    Write = 1,
    Read = 2,
    Yield = 3,
    Fork = 4,
}

/// Dispatch a system call.
/// Returns -1 for unimplemented syscalls, 0 for Yield.
pub fn dispatch(num: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    match num {
        0 => -1, // Exit — not implemented
        1 => -1, // Write — not implemented
        2 => -1, // Read — not implemented
        3 => 0,  // Yield — returns success
        4 => -1, // Fork — not implemented
        _ => -1, // Unknown syscall
    }
}

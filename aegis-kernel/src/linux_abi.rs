// Linux x86-64 syscall ABI translation (Phase 8).
//
// Design doc §5: Linux compatibility is a syscall/ABI translation layer
// running as an unprivileged, capability-scoped userspace service (the
// WSL2-lineage approach). This module is the translator: Linux syscall numbers
// plus the System V x86-64 register convention become Aegis operations that
// can then be gated on a capability scope (see linux_compat.rs).
// Honest limits: only a finite subset of the Linux syscall surface is mapped;
// the translation is model logic, not a real ring-3 syscall trap, and the
// lightweight-VM execution vehicle is not built (needs a hypervisor).

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETPID: u64 = 39;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_BIND: u64 = 49;
pub const SYS_CLONE: u64 = 56;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_EXIT_GROUP: u64 = 231;

/// The six argument registers of the System V x86-64 calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyscallArgs {
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub arg6: u64,
}

/// A capability-scoped operation that a translated Linux syscall becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AegisOperation {
    Read { fd: u64, count: u64 },
    Write { fd: u64, count: u64 },
    Open { path_ptr: u64, flags: u64 },
    Close { fd: u64 },
    MapMemory { size: u64, prot: u64 },
    UnmapMemory { addr: u64, size: u64 },
    Exit { code: u64 },
    GetPid,
    Sleep { timespec_ptr: u64 },
    Socket { domain: u64, kind: u64 },
    Connect { fd: u64 },
    Send { fd: u64 },
    Receive { fd: u64 },
    Exec { path_ptr: u64 },
    Unsupported { num: u64 },
}

/// Translate a Linux x86-64 syscall number and its register args into an
/// Aegis operation. Unknown numbers yield `AegisOperation::Unsupported`.
pub fn translate(num: u64, args: SyscallArgs) -> AegisOperation {
    match num {
        SYS_READ => AegisOperation::Read {
            fd: args.arg1,
            count: args.arg3,
        },
        SYS_WRITE => AegisOperation::Write {
            fd: args.arg1,
            count: args.arg3,
        },
        SYS_OPEN => AegisOperation::Open {
            path_ptr: args.arg1,
            flags: args.arg2,
        },
        SYS_CLOSE => AegisOperation::Close { fd: args.arg1 },
        SYS_MMAP => AegisOperation::MapMemory {
            size: args.arg2,
            prot: args.arg3,
        },
        SYS_MUNMAP => AegisOperation::UnmapMemory {
            addr: args.arg1,
            size: args.arg2,
        },
        SYS_NANOSLEEP => AegisOperation::Sleep {
            timespec_ptr: args.arg1,
        },
        SYS_GETPID => AegisOperation::GetPid,
        SYS_SOCKET => AegisOperation::Socket {
            domain: args.arg1,
            kind: args.arg2,
        },
        SYS_CONNECT => AegisOperation::Connect { fd: args.arg1 },
        SYS_SENDTO => AegisOperation::Send { fd: args.arg1 },
        SYS_RECVFROM => AegisOperation::Receive { fd: args.arg1 },
        SYS_EXECVE => AegisOperation::Exec {
            path_ptr: args.arg1,
        },
        SYS_EXIT | SYS_EXIT_GROUP => AegisOperation::Exit { code: args.arg1 },
        _ => AegisOperation::Unsupported { num },
    }
}

/// True if the syscall number has a translation in this layer.
pub fn is_known(num: u64) -> bool {
    !matches!(
        translate(num, SyscallArgs::default()),
        AegisOperation::Unsupported { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_maps_fd_and_count() {
        let op = translate(
            SYS_READ,
            SyscallArgs {
                arg1: 3,
                arg3: 4096,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::Read { fd: 3, count: 4096 });
    }

    #[test]
    fn write_maps_fd_and_count() {
        let op = translate(
            SYS_WRITE,
            SyscallArgs {
                arg1: 1,
                arg3: 64,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::Write { fd: 1, count: 64 });
    }

    #[test]
    fn open_maps_path_and_flags() {
        let op = translate(
            SYS_OPEN,
            SyscallArgs {
                arg1: 0x1000,
                arg2: 0x42,
                ..Default::default()
            },
        );
        assert_eq!(
            op,
            AegisOperation::Open {
                path_ptr: 0x1000,
                flags: 0x42
            }
        );
    }

    #[test]
    fn close_maps_fd() {
        let op = translate(
            SYS_CLOSE,
            SyscallArgs {
                arg1: 5,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::Close { fd: 5 });
    }

    #[test]
    fn mmap_maps_size_and_prot() {
        let op = translate(
            SYS_MMAP,
            SyscallArgs {
                arg1: 0,
                arg2: 0x2000,
                arg3: 3,
                ..Default::default()
            },
        );
        assert_eq!(
            op,
            AegisOperation::MapMemory {
                size: 0x2000,
                prot: 3
            }
        );
    }

    #[test]
    fn munmap_maps_addr_and_size() {
        let op = translate(
            SYS_MUNMAP,
            SyscallArgs {
                arg1: 0x1000,
                arg2: 0x1000,
                ..Default::default()
            },
        );
        assert_eq!(
            op,
            AegisOperation::UnmapMemory {
                addr: 0x1000,
                size: 0x1000
            }
        );
    }

    #[test]
    fn exit_maps_code() {
        let op = translate(
            SYS_EXIT,
            SyscallArgs {
                arg1: 7,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::Exit { code: 7 });
    }

    #[test]
    fn exit_group_aliases_exit() {
        let op = translate(
            SYS_EXIT_GROUP,
            SyscallArgs {
                arg1: 3,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::Exit { code: 3 });
    }

    #[test]
    fn getpid_has_no_args() {
        let op = translate(SYS_GETPID, SyscallArgs::default());
        assert_eq!(op, AegisOperation::GetPid);
    }

    #[test]
    fn socket_maps_domain_and_kind() {
        let op = translate(
            SYS_SOCKET,
            SyscallArgs {
                arg1: 2,
                arg2: 1,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::Socket { domain: 2, kind: 1 });
    }

    #[test]
    fn exec_maps_path() {
        let op = translate(
            SYS_EXECVE,
            SyscallArgs {
                arg1: 0x3000,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::Exec { path_ptr: 0x3000 });
    }

    #[test]
    fn unsupported_syscall_is_rejected() {
        let op = translate(0xDEAD, SyscallArgs::default());
        assert_eq!(op, AegisOperation::Unsupported { num: 0xDEAD });
        assert!(!is_known(0xDEAD));
        assert!(is_known(SYS_READ));
    }
}

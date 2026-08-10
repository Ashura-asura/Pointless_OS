// Windows NT syscall ABI translation (Phase 9).
//
// Design doc §5/§7 Phase 9: Windows compatibility is a VM-based full-fidelity
// path first, plus a *thinner* translation layer for a narrow, well-behaved
// Win32/UWP app subset that does not poke at undocumented internals. This
// module is that translation layer's ABI half: NT syscall numbers plus the
// x64 NT argument convention (rcx, rdx, r8, r9, stack) become Aegis
// operations that can be gated on a capability scope (see win_compat.rs).
// Honest limits: the design doc is explicit that full Windows compatibility
// without licensing Windows or running a real Windows kernel is not a solved
// problem anywhere; this is the narrow-subset translator, model logic only,
// and the VM-based full-fidelity vehicle is not built.

pub const NT_CREATE_FILE: u64 = 0x54;
pub const NT_READ_FILE: u64 = 0x67;
pub const NT_WRITE_FILE: u64 = 0x68;
pub const NT_CLOSE: u64 = 0x16;
pub const NT_CREATE_SECTION: u64 = 0x4B;
pub const NT_MAP_VIEW_OF_SECTION: u64 = 0x2E;
pub const NT_UNMAP_VIEW_OF_SECTION: u64 = 0x2F;
pub const NT_CREATE_PROCESS: u64 = 0x48;
pub const NT_TERMINATE_PROCESS: u64 = 0x5D;
pub const NT_QUERY_INFORMATION_PROCESS: u64 = 0x4C;
pub const NT_DEVICE_IO_CONTROL_FILE: u64 = 0x1D;
pub const NT_QUERY_SYSTEM_TIME: u64 = 0xD7;
pub const NT_SET_INFORMATION_FILE: u64 = 0x5E;

/// The four register arguments of the x64 Windows NT calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NtArgs {
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
}

/// A capability-scoped operation that a translated NT syscall becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AegisOperation {
    CreateFile { path_ptr: u64, desired_access: u64 },
    ReadFile { handle: u64, count: u64 },
    WriteFile { handle: u64, count: u64 },
    CloseHandle { handle: u64 },
    CreateSection { max_size: u64 },
    MapViewOfSection { size: u64 },
    UnmapViewOfSection { base_addr: u64 },
    CreateProcess { image_ptr: u64 },
    TerminateProcess { exit_code: u64 },
    QueryProcessInfo { info_class: u64 },
    DeviceIoControl { handle: u64 },
    QuerySystemTime,
    SetFileInfo { handle: u64 },
    Unsupported { num: u64 },
}

/// Translate an NT syscall number and its register args into an Aegis
/// operation. Unknown numbers yield `AegisOperation::Unsupported`.
pub fn translate(num: u64, args: NtArgs) -> AegisOperation {
    match num {
        NT_CREATE_FILE => AegisOperation::CreateFile {
            path_ptr: args.arg1,
            desired_access: args.arg2,
        },
        NT_READ_FILE => AegisOperation::ReadFile {
            handle: args.arg1,
            count: args.arg3,
        },
        NT_WRITE_FILE => AegisOperation::WriteFile {
            handle: args.arg1,
            count: args.arg3,
        },
        NT_CLOSE => AegisOperation::CloseHandle { handle: args.arg1 },
        NT_CREATE_SECTION => AegisOperation::CreateSection {
            max_size: args.arg3,
        },
        NT_MAP_VIEW_OF_SECTION => AegisOperation::MapViewOfSection { size: args.arg3 },
        NT_UNMAP_VIEW_OF_SECTION => AegisOperation::UnmapViewOfSection {
            base_addr: args.arg1,
        },
        NT_CREATE_PROCESS => AegisOperation::CreateProcess {
            image_ptr: args.arg1,
        },
        NT_TERMINATE_PROCESS => AegisOperation::TerminateProcess {
            exit_code: args.arg1,
        },
        NT_QUERY_INFORMATION_PROCESS => AegisOperation::QueryProcessInfo {
            info_class: args.arg2,
        },
        NT_DEVICE_IO_CONTROL_FILE => AegisOperation::DeviceIoControl { handle: args.arg1 },
        NT_QUERY_SYSTEM_TIME => AegisOperation::QuerySystemTime,
        NT_SET_INFORMATION_FILE => AegisOperation::SetFileInfo { handle: args.arg1 },
        _ => AegisOperation::Unsupported { num },
    }
}

/// True if the syscall number has a translation in this narrow subset.
pub fn is_known(num: u64) -> bool {
    !matches!(
        translate(num, NtArgs::default()),
        AegisOperation::Unsupported { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_file_maps_path_and_access() {
        let op = translate(
            NT_CREATE_FILE,
            NtArgs {
                arg1: 0x1000,
                arg2: 0x0012_0000,
                ..Default::default()
            },
        );
        assert_eq!(
            op,
            AegisOperation::CreateFile {
                path_ptr: 0x1000,
                desired_access: 0x0012_0000
            }
        );
    }

    #[test]
    fn read_file_maps_handle_and_count() {
        let op = translate(
            NT_READ_FILE,
            NtArgs {
                arg1: 5,
                arg3: 4096,
                ..Default::default()
            },
        );
        assert_eq!(
            op,
            AegisOperation::ReadFile {
                handle: 5,
                count: 4096
            }
        );
    }

    #[test]
    fn write_file_maps_handle_and_count() {
        let op = translate(
            NT_WRITE_FILE,
            NtArgs {
                arg1: 1,
                arg3: 64,
                ..Default::default()
            },
        );
        assert_eq!(
            op,
            AegisOperation::WriteFile {
                handle: 1,
                count: 64
            }
        );
    }

    #[test]
    fn close_maps_handle() {
        let op = translate(
            NT_CLOSE,
            NtArgs {
                arg1: 7,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::CloseHandle { handle: 7 });
    }

    #[test]
    fn create_section_maps_max_size() {
        let op = translate(
            NT_CREATE_SECTION,
            NtArgs {
                arg3: 0x2000,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::CreateSection { max_size: 0x2000 });
    }

    #[test]
    fn map_view_maps_size() {
        let op = translate(
            NT_MAP_VIEW_OF_SECTION,
            NtArgs {
                arg3: 0x1000,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::MapViewOfSection { size: 0x1000 });
    }

    #[test]
    fn unmap_view_maps_base() {
        let op = translate(
            NT_UNMAP_VIEW_OF_SECTION,
            NtArgs {
                arg1: 0x7F00_0000,
                ..Default::default()
            },
        );
        assert_eq!(
            op,
            AegisOperation::UnmapViewOfSection {
                base_addr: 0x7F00_0000
            }
        );
    }

    #[test]
    fn terminate_process_maps_code() {
        let op = translate(
            NT_TERMINATE_PROCESS,
            NtArgs {
                arg1: 3,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::TerminateProcess { exit_code: 3 });
    }

    #[test]
    fn query_process_maps_info_class() {
        let op = translate(
            NT_QUERY_INFORMATION_PROCESS,
            NtArgs {
                arg2: 27,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::QueryProcessInfo { info_class: 27 });
    }

    #[test]
    fn device_io_control_maps_handle() {
        let op = translate(
            NT_DEVICE_IO_CONTROL_FILE,
            NtArgs {
                arg1: 9,
                ..Default::default()
            },
        );
        assert_eq!(op, AegisOperation::DeviceIoControl { handle: 9 });
    }

    #[test]
    fn query_system_time_has_no_args() {
        let op = translate(NT_QUERY_SYSTEM_TIME, NtArgs::default());
        assert_eq!(op, AegisOperation::QuerySystemTime);
    }

    #[test]
    fn unsupported_syscall_is_rejected() {
        let op = translate(0xDEAD, NtArgs::default());
        assert_eq!(op, AegisOperation::Unsupported { num: 0xDEAD });
        assert!(!is_known(0xDEAD));
        assert!(is_known(NT_READ_FILE));
    }
}

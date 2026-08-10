// Windows compatibility personality layer (Phase 9).
//
// Design doc §5/§7 Phase 9: Windows compatibility is a VM-based full-fidelity
// path first, plus a thinner translation layer for a narrow, well-behaved
// Win32/UWP subset. This module owns the personality boundary: a Windows-compat
// context translates NT syscalls (nt_abi.rs) and gates each translated
// operation on the context's capability scope — the same AI/agent ceiling that
// applies to native and Linux-compat code. Honest limits: model logic only;
// no real ring-3 trap, no hypervisor, and the design doc is explicit that
// full Windows fidelity is not achieved by translation alone.

use crate::agent::CapabilityScope;
use crate::nt_abi::{translate, AegisOperation, NtArgs};

/// Capability-category indices matching linux_compat.rs: file, memory,
/// process, network, exec, time.
pub const CAP_FILE: u32 = 0;
pub const CAP_MEMORY: u32 = 1;
pub const CAP_PROCESS: u32 = 2;
pub const CAP_NETWORK: u32 = 3;
pub const CAP_EXEC: u32 = 4;
pub const CAP_TIME: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Personality {
    Native,
    WindowsCompat,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WinCompatContext {
    pub id: u32,
    pub personality: Personality,
    pub scope: CapabilityScope,
    pub syscall_denials: u64,
    pub last_operation: Option<AegisOperation>,
}

impl WinCompatContext {
    pub fn new(id: u32, personality: Personality, scope: CapabilityScope) -> Self {
        Self {
            id,
            personality,
            scope,
            syscall_denials: 0,
            last_operation: None,
        }
    }

    /// Translate an NT syscall and gate it on the context's capability scope.
    pub fn translate_and_check(
        &mut self,
        num: u64,
        args: NtArgs,
    ) -> Result<AegisOperation, &'static str> {
        if self.personality != Personality::WindowsCompat {
            self.syscall_denials += 1;
            return Err("windows personality does not translate nt syscalls");
        }
        let op = translate(num, args);
        if matches!(op, AegisOperation::Unsupported { .. }) {
            self.syscall_denials += 1;
            return Err("unsupported nt syscall");
        }
        if !self.op_allowed(&op) {
            self.syscall_denials += 1;
            return Err("syscall denied by capability scope");
        }
        self.last_operation = Some(op);
        Ok(op)
    }

    fn op_allowed(&self, op: &AegisOperation) -> bool {
        match op {
            AegisOperation::CreateFile { .. }
            | AegisOperation::ReadFile { .. }
            | AegisOperation::WriteFile { .. }
            | AegisOperation::CloseHandle { .. }
            | AegisOperation::SetFileInfo { .. } => self.scope.is_allowed(CAP_FILE),
            AegisOperation::CreateSection { .. }
            | AegisOperation::MapViewOfSection { .. }
            | AegisOperation::UnmapViewOfSection { .. } => self.scope.is_allowed(CAP_MEMORY),
            AegisOperation::CreateProcess { .. }
            | AegisOperation::TerminateProcess { .. }
            | AegisOperation::QueryProcessInfo { .. } => self.scope.is_allowed(CAP_PROCESS),
            AegisOperation::DeviceIoControl { .. } => {
                self.scope.is_allowed(CAP_NETWORK) || self.scope.is_allowed(CAP_FILE)
            }
            AegisOperation::QuerySystemTime => self.scope.is_allowed(CAP_TIME),
            AegisOperation::Unsupported { .. } => false,
        }
    }
}

impl Default for WinCompatContext {
    fn default() -> Self {
        Self::new(0, Personality::Native, CapabilityScope::restrictive())
    }
}

pub struct WindowsCompatLayer {
    contexts: [Option<WinCompatContext>; 16],
    count: usize,
    next_id: u32,
}

impl WindowsCompatLayer {
    pub fn new() -> Self {
        const NONE: Option<WinCompatContext> = None;
        Self {
            contexts: [NONE; 16],
            count: 0,
            next_id: 1,
        }
    }

    pub fn register(
        &mut self,
        personality: Personality,
        scope: CapabilityScope,
    ) -> Result<u32, &'static str> {
        if self.count >= self.contexts.len() {
            return Err("maximum compat contexts reached");
        }
        let id = self.next_id;
        self.next_id += 1;
        let ctx = WinCompatContext::new(id, personality, scope);
        for slot in self.contexts.iter_mut() {
            if slot.is_none() {
                *slot = Some(ctx);
                self.count += 1;
                return Ok(id);
            }
        }
        Err("register failed")
    }

    pub fn dispatch(
        &mut self,
        id: u32,
        num: u64,
        args: NtArgs,
    ) -> Result<AegisOperation, &'static str> {
        let ctx = self
            .contexts
            .iter_mut()
            .flatten()
            .find(|c| c.id == id)
            .ok_or("context not found")?;
        ctx.translate_and_check(num, args)
    }

    pub fn denials(&self, id: u32) -> Option<u64> {
        self.contexts
            .iter()
            .flatten()
            .find(|c| c.id == id)
            .map(|c| c.syscall_denials)
    }

    pub fn context_count(&self) -> usize {
        self.count
    }
}

impl Default for WindowsCompatLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_args() -> NtArgs {
        NtArgs {
            arg1: 1,
            arg3: 64,
            ..Default::default()
        }
    }

    fn map_args() -> NtArgs {
        NtArgs {
            arg1: 2,
            arg3: 0x1000,
            ..Default::default()
        }
    }

    #[test]
    fn register_assigns_ids() {
        let mut layer = WindowsCompatLayer::new();
        let id1 = layer
            .register(Personality::WindowsCompat, CapabilityScope::permissive())
            .unwrap();
        let id2 = layer
            .register(Personality::Native, CapabilityScope::restrictive())
            .unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(layer.context_count(), 2);
    }

    #[test]
    fn dispatch_translates_allowed_syscall() {
        let mut layer = WindowsCompatLayer::new();
        let id = layer
            .register(Personality::WindowsCompat, CapabilityScope::permissive())
            .unwrap();
        let op = layer
            .dispatch(id, crate::nt_abi::NT_WRITE_FILE, write_args())
            .unwrap();
        assert_eq!(
            op,
            AegisOperation::WriteFile {
                handle: 1,
                count: 64
            }
        );
    }

    #[test]
    fn dispatch_denies_out_of_scope_syscall() {
        let mut layer = WindowsCompatLayer::new();
        let mut scope = CapabilityScope::restrictive();
        scope.allowed_syscalls[CAP_MEMORY as usize] = false;
        let id = layer.register(Personality::WindowsCompat, scope).unwrap();
        let err = layer.dispatch(id, crate::nt_abi::NT_MAP_VIEW_OF_SECTION, map_args());
        assert!(err.is_err());
        assert_eq!(layer.denials(id), Some(1));
    }

    #[test]
    fn native_personality_rejects_nt_translation() {
        let mut layer = WindowsCompatLayer::new();
        let id = layer
            .register(Personality::Native, CapabilityScope::permissive())
            .unwrap();
        assert_eq!(
            layer.dispatch(id, crate::nt_abi::NT_WRITE_FILE, write_args()),
            Err("windows personality does not translate nt syscalls")
        );
    }

    #[test]
    fn unsupported_syscall_rejected_and_counted() {
        let mut layer = WindowsCompatLayer::new();
        let id = layer
            .register(Personality::WindowsCompat, CapabilityScope::permissive())
            .unwrap();
        assert_eq!(
            layer.dispatch(id, 0xDEAD, NtArgs::default()),
            Err("unsupported nt syscall")
        );
        assert_eq!(layer.denials(id), Some(1));
    }

    #[test]
    fn dispatch_unknown_context_fails() {
        let mut layer = WindowsCompatLayer::new();
        assert_eq!(
            layer.dispatch(99, crate::nt_abi::NT_READ_FILE, NtArgs::default()),
            Err("context not found")
        );
    }

    #[test]
    fn device_io_control_requires_some_scope() {
        let mut layer = WindowsCompatLayer::new();
        let mut scope = CapabilityScope::permissive();
        scope.allowed_syscalls[CAP_FILE as usize] = false;
        scope.allowed_syscalls[CAP_NETWORK as usize] = false;
        let id = layer.register(Personality::WindowsCompat, scope).unwrap();
        let err = layer.dispatch(id, crate::nt_abi::NT_DEVICE_IO_CONTROL_FILE, map_args());
        assert!(err.is_err());
    }

    #[test]
    fn query_system_time_needs_time_scope() {
        let mut layer = WindowsCompatLayer::new();
        let mut scope = CapabilityScope::permissive();
        scope.allowed_syscalls[CAP_TIME as usize] = false;
        let id = layer.register(Personality::WindowsCompat, scope).unwrap();
        let err = layer.dispatch(id, crate::nt_abi::NT_QUERY_SYSTEM_TIME, NtArgs::default());
        assert!(err.is_err());
        assert_eq!(layer.denials(id), Some(1));
    }
}

// Linux compatibility personality layer (Phase 8).
//
// Design doc §5/§7 Phase 8: Linux compatibility is a syscall/ABI translation
// layer running as an unprivileged, capability-scoped userspace service. This
// module owns the personality boundary: a Linux-compat context translates
// Linux syscalls (linux_abi.rs) and gates each translated operation on the
// context's capability scope — the AI/agent ceiling applies to compat code the
// same way it applies to native code. Honest limits: model logic only; no
// real ring-3 trap, no lightweight-VM execution vehicle (needs a hypervisor).

use crate::agent::CapabilityScope;
use crate::linux_abi::{translate, AegisOperation, SyscallArgs};

/// Capability-category indices used to map Linux operations onto the Aegis
/// syscall bitmap carried by `CapabilityScope::allowed_syscalls`.
pub const CAP_FILE: u32 = 0;
pub const CAP_MEMORY: u32 = 1;
pub const CAP_PROCESS: u32 = 2;
pub const CAP_NETWORK: u32 = 3;
pub const CAP_EXEC: u32 = 4;
pub const CAP_TIME: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Personality {
    Native,
    LinuxCompat,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompatContext {
    pub id: u32,
    pub personality: Personality,
    pub scope: CapabilityScope,
    pub syscall_denials: u64,
    pub last_operation: Option<AegisOperation>,
}

impl CompatContext {
    pub fn new(id: u32, personality: Personality, scope: CapabilityScope) -> Self {
        Self {
            id,
            personality,
            scope,
            syscall_denials: 0,
            last_operation: None,
        }
    }

    /// Translate a Linux syscall and gate it on the context's capability scope.
    pub fn translate_and_check(
        &mut self,
        num: u64,
        args: SyscallArgs,
    ) -> Result<AegisOperation, &'static str> {
        if self.personality != Personality::LinuxCompat {
            self.syscall_denials += 1;
            return Err("native personality does not translate linux syscalls");
        }
        let op = translate(num, args);
        if matches!(op, AegisOperation::Unsupported { .. }) {
            self.syscall_denials += 1;
            return Err("unsupported linux syscall");
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
            AegisOperation::Read { .. }
            | AegisOperation::Write { .. }
            | AegisOperation::Open { .. }
            | AegisOperation::Close { .. } => self.scope.is_allowed(CAP_FILE),
            AegisOperation::MapMemory { .. } | AegisOperation::UnmapMemory { .. } => {
                self.scope.is_allowed(CAP_MEMORY)
            }
            AegisOperation::Exit { .. } | AegisOperation::GetPid => {
                self.scope.is_allowed(CAP_PROCESS)
            }
            AegisOperation::Socket { .. }
            | AegisOperation::Connect { .. }
            | AegisOperation::Send { .. }
            | AegisOperation::Receive { .. } => {
                self.scope.network_allowed && self.scope.is_allowed(CAP_NETWORK)
            }
            AegisOperation::Exec { .. } => self.scope.is_allowed(CAP_EXEC),
            AegisOperation::Sleep { .. } => self.scope.is_allowed(CAP_TIME),
            AegisOperation::Unsupported { .. } => false,
        }
    }
}

impl Default for CompatContext {
    fn default() -> Self {
        Self::new(0, Personality::Native, CapabilityScope::restrictive())
    }
}

pub struct LinuxCompatLayer {
    contexts: [Option<CompatContext>; 16],
    count: usize,
    next_id: u32,
}

impl LinuxCompatLayer {
    pub fn new() -> Self {
        const NONE: Option<CompatContext> = None;
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
        let ctx = CompatContext::new(id, personality, scope);
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
        args: SyscallArgs,
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

    pub fn personalities(&self) -> [Personality; 16] {
        let mut out = [Personality::Native; 16];
        for (i, c) in self.contexts.iter().enumerate() {
            if let Some(c) = c {
                out[i] = c.personality;
            }
        }
        out
    }
}

impl Default for LinuxCompatLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_args() -> SyscallArgs {
        SyscallArgs {
            arg1: 1,
            arg3: 64,
            ..Default::default()
        }
    }

    fn network_args() -> SyscallArgs {
        SyscallArgs {
            arg1: 2,
            arg2: 1,
            ..Default::default()
        }
    }

    #[test]
    fn register_assigns_ids() {
        let mut layer = LinuxCompatLayer::new();
        let id1 = layer
            .register(Personality::LinuxCompat, CapabilityScope::permissive())
            .unwrap();
        let id2 = layer
            .register(Personality::Native, CapabilityScope::restrictive())
            .unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(layer.context_count(), 2);
        assert_eq!(layer.personalities()[0], Personality::LinuxCompat);
    }

    #[test]
    fn dispatch_translates_allowed_syscall() {
        let mut layer = LinuxCompatLayer::new();
        let id = layer
            .register(Personality::LinuxCompat, CapabilityScope::permissive())
            .unwrap();
        let op = layer
            .dispatch(id, crate::linux_abi::SYS_WRITE, write_args())
            .unwrap();
        assert_eq!(op, AegisOperation::Write { fd: 1, count: 64 });
    }

    #[test]
    fn dispatch_denies_out_of_scope_syscall() {
        let mut layer = LinuxCompatLayer::new();
        // restrictive scope only allows CAP_FILE (index 0) — write is CAP_FILE
        let mut scope = CapabilityScope::restrictive();
        scope.allowed_syscalls[CAP_MEMORY as usize] = false;
        let id = layer.register(Personality::LinuxCompat, scope).unwrap();
        let err = layer.dispatch(id, crate::linux_abi::SYS_MMAP, SyscallArgs::default());
        assert!(err.is_err());
        assert_eq!(layer.denials(id), Some(1));
    }

    #[test]
    fn network_blocked_without_network_scope() {
        let mut layer = LinuxCompatLayer::new();
        let mut scope = CapabilityScope::permissive();
        scope.network_allowed = false;
        let id = layer.register(Personality::LinuxCompat, scope).unwrap();
        let err = layer.dispatch(id, crate::linux_abi::SYS_SOCKET, network_args());
        assert_eq!(err, Err("syscall denied by capability scope"));
    }

    #[test]
    fn native_personality_rejects_linux_translation() {
        let mut layer = LinuxCompatLayer::new();
        let id = layer
            .register(Personality::Native, CapabilityScope::permissive())
            .unwrap();
        assert_eq!(
            layer.dispatch(id, crate::linux_abi::SYS_WRITE, write_args()),
            Err("native personality does not translate linux syscalls")
        );
    }

    #[test]
    fn unsupported_syscall_rejected_and_counted() {
        let mut layer = LinuxCompatLayer::new();
        let id = layer
            .register(Personality::LinuxCompat, CapabilityScope::permissive())
            .unwrap();
        assert_eq!(
            layer.dispatch(id, 0xDEAD, SyscallArgs::default()),
            Err("unsupported linux syscall")
        );
        assert_eq!(layer.denials(id), Some(1));
    }

    #[test]
    fn dispatch_unknown_context_fails() {
        let mut layer = LinuxCompatLayer::new();
        assert_eq!(
            layer.dispatch(99, crate::linux_abi::SYS_READ, SyscallArgs::default()),
            Err("context not found")
        );
    }

    #[test]
    fn permissive_scope_accepts_network() {
        let mut layer = LinuxCompatLayer::new();
        let id = layer
            .register(Personality::LinuxCompat, CapabilityScope::permissive())
            .unwrap();
        let op = layer
            .dispatch(id, crate::linux_abi::SYS_SOCKET, network_args())
            .unwrap();
        assert_eq!(op, AegisOperation::Socket { domain: 2, kind: 1 });
    }
}

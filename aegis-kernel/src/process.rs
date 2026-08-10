/// Process ID
pub type Pid = u32;

/// Process state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
    Blocked,
    Zombie,
}

/// CPU register state for context switching
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CpuState {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// A process
pub struct Process {
    pub pid: Pid,
    pub state: ProcessState,
    pub cpu_state: CpuState,
    pub kernel_stack_top: u64,
    pub user_stack_top: u64,
    pub pml4_phys: u64,
}

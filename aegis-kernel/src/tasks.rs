//! Minimal cooperative kernel tasks: each task runs on its own 16 KiB
//! stack, and control moves between tasks (and the idle loop) by swapping
//! full interrupt-style frames with `iretq`.
//!
//! Honest limits: scheduling is cooperative (`yield_now` only) plus
//! preemption by the LAPIC timer, which round-robins on every tick. The
//! `switch_frame` assembler primitive is verified under QEMU/TCG only,
//! not on physical hardware.

use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::cap::{Cap, CapSlot, CapTable};

pub const TASK_STACK_SIZE: u64 = 16384;
/// Task table capacity. Bumped to 12 in Phase 6: the Phase-6 demo adds a
/// zero-capability agent task and a crashable service task on top of the
/// Phase-5 set (alpha/beta/server/client/supervisor/iso/nx/denied).
pub const MAX_TASKS: usize = 12;
/// Slots in each task's capability table.
pub const MAX_CAPS: usize = 16;

/// Scheduling state of a task. `Blocked` tasks are skipped by the scheduler
/// (e.g. while waiting for an IPC reply). `Zombie` tasks are killed (they
/// faulted as ring-3 isolation/NX victims) and never scheduled again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Blocked,
    Zombie,
}

/// Full register context of a running task. The `#[repr(C)]` layout
/// defines the memory offsets that `switch_frame` uses to save/restore:
///
/// ```text
/// offset  register    offset  register
/// 0       r15         112     rax
/// 8       r14         120     error slot
/// 16      r13         128     rip
/// 24      r12         136     cs
/// 32      rbx         144     rflags
/// 40      r11         152     rsp (pre-call rbp-based)
/// 48      r10         160     ss
/// 56      r9          168     saved_to (unused by switch_frame)
/// 64      r8
/// 72      rbp
/// 80      rdi
/// 88      rsi
/// 96      rdx
/// 104     rcx
/// ```
///
/// Note: the struct field names (rax, rcx, ...) define `#[repr(C)]` offsets,
/// but `switch_frame` maps them to different registers via explicit offsets.
/// Only the offsets matter; the field names are for debugger readability.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TaskFrame {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    /// Reserved scheduler scratch: the switch path no longer reads this
    /// field (it uses `SWITCH_SCRATCH` because popping the target's GPR
    /// block clobbers `rdi`). Kept so `TaskFrame` stays explicit.
    pub saved_to: u64,
}

impl TaskFrame {
    pub const fn size() -> usize {
        core::mem::size_of::<TaskFrame>()
    }

    /// Frame for a fresh task about to enter `entry` on the given stack.
    /// RSP is set so that after the switch's iretq (which pops 40 bytes of
    /// its own frame) the entry sees the SysV-required `rsp % 16 == 8`,
    /// and RFLAGS has IF set (timer interrupts fire on the task's stack).
    #[allow(clippy::missing_const_for_fn)] // fn-pointer-to-int cast is not const
    pub fn fresh(entry: extern "sysv64" fn() -> !, stack_top: u64) -> TaskFrame {
        TaskFrame {
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            error: 0,
            rip: entry as usize as u64,
            cs: crate::gdt::KERNEL_CODE_SELECTOR as u64,
            rflags: 0x202,
            rsp: stack_top - 40,
            ss: crate::gdt::KERNEL_DATA_SELECTOR as u64,
            saved_to: 0,
        }
    }

    /// Frame for a fresh RING-3 task: same shape as `fresh`, but the iretq
    /// words carry the user selectors (CS=0x1B, SS=0x23 with RPL=3), so the
    /// first switch drops the CPU to CPL3 with the user stack live.
    /// RFLAGS keeps IF set (IOPL=0: `sti`/`cli` from user mode would #GP,
    /// which the demo user code never attempts).
    #[allow(clippy::missing_const_for_fn)] // fn-pointer-to-int cast is not const
    pub fn fresh_user(entry: extern "sysv64" fn() -> !, stack_top: u64) -> TaskFrame {
        TaskFrame {
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            error: 0,
            rip: entry as usize as u64,
            cs: crate::gdt::USER_CODE_SELECTOR as u64,
            rflags: 0x202,
            rsp: stack_top - 40,
            ss: crate::gdt::USER_DATA_SELECTOR as u64,
            saved_to: 0,
        }
    }
}

/// A scheduled kernel task.
pub struct Task {
    pub name: &'static str,
    /// Entry point, remembered so a supervised restart can re-enter a task
    /// image (the supervision tree respawns against the same code, not a
    /// re-fork of arbitrary state).
    pub entry: extern "sysv64" fn() -> !,
    pub frame: TaskFrame,
    /// Physical address of the stack region (16 KiB).
    pub stack_base: u64,
    /// Top of the task's dedicated CPL0 (ring-3 -> ring-0 transition)
    /// stack, or 0 for kernel-only tasks (which never transition into the
    /// kernel — their interrupts nest on their own 16 KiB execution
    /// stack). Every task entering ring 3 needs one: the TSS.RSP0 is read
    /// at transition time, and the single shared kernel stack would be
    /// overwritten by interleaved transitions of other tasks.
    pub cpl0_stack_top: u64,
    /// Physical address of this task's per-user PML4 (0 for kernel tasks
    /// that use the shared kernel PML4). On context switch to a user task,
    /// CR3 is loaded with this value to enforce memory isolation.
    pub pml4_phys: u64,
    /// Capability table (the only authority token the task holds).
    pub caps: CapTable,
    /// Scheduling state.
    pub state: TaskState,
    /// Endpoint id this task is blocked on (usize::MAX when not blocked).
    pub blocked_ep: usize,
}

impl Task {
    pub fn new(name: &'static str, entry: extern "sysv64" fn() -> !, stack_base: u64) -> Task {
        Task {
            name,
            entry,
            frame: TaskFrame::fresh(entry, stack_base + TASK_STACK_SIZE),
            stack_base,
            cpl0_stack_top: 0,
            pml4_phys: 0,
            caps: crate::cap::new_cap_table(),
            state: TaskState::Ready,
            blocked_ep: usize::MAX,
        }
    }

    pub fn new_user(
        name: &'static str,
        entry: extern "sysv64" fn() -> !,
        stack_base: u64,
        cpl0_stack_base: u64,
    ) -> Task {
        // Create per-user-task page tables with memory isolation:
        // only this task's stack region is USER-accessible.
        let user_pml4 = unsafe { crate::page_tables::create_user_pml4(stack_base) };
        Task {
            name,
            entry,
            frame: TaskFrame::fresh_user(entry, stack_base + TASK_STACK_SIZE),
            stack_base,
            cpl0_stack_top: cpl0_stack_base + TASK_STACK_SIZE,
            pml4_phys: user_pml4,
            caps: crate::cap::new_cap_table(),
            state: TaskState::Ready,
            blocked_ep: usize::MAX,
        }
    }
}

/// Swap the CPU onto `to`'s saved frame, saving the current context into
/// `from` first. Control returns to this call site later, when the `from`
/// frame is resumed (coroutine semantics: the naked body ends in a switch
/// into the target frame, not a `ret`).
///
/// # Safety
/// Both pointers must point at live `TaskFrame`s; the target's stack must
/// be valid. Only callable from scheduling code.
#[unsafe(naked)]
pub(crate) extern "sysv64" fn switch_frame(from: *mut TaskFrame, to: *const TaskFrame) {
    naked_asm!(
        // -------- save current context into the [rdi] slots --------
        // Registers are stored INTO the frame structure (not pushed); the
        // load path then pops them straight back out of the slots. Flags
        // are captured BEFORE `cli` so the saved RFLAGS keeps IF set and
        // the later iretq re-enables interrupts.
        //
        // Frame layout (offsets): r15=0, r14=8, ..., rax=112, error=120,
        // rip=128, cs=136, rflags=144, rsp=152, ss=160, saved_to=168.
        // The save path stores each register at its struct field offset.
        "mov [rdi+112], rax", // rax slot first (rax is clobbered below)
        "pushfq",             // flags with IF still set
        "cli",
        "lea rax, [rip + {}]", // SWITCH_SCRATCH
        "mov [rax], rsi", // stashed target pointer (all GPRs get clobbered)
        "pop rax",
        "mov [rdi+144], rax", // rflags (IF=1)
        "mov ax, cs",
        "movzx rax, ax",
        "mov [rdi+136], rax", // cs
        "mov ax, ss",
        "movzx rax, ax",
        "mov [rdi+160], rax", // ss
        "mov rax, [rsp]",     // return address = resume RIP
        "mov [rdi+128], rax",
        "mov qword ptr [rdi+120], 0", // error slot
        "mov [rdi], r15",
        "mov [rdi+8], r14",
        "mov [rdi+16], r13",
        "mov [rdi+24], r12",
        "mov [rdi+32], rbx",
        "mov [rdi+40], r11",
        "mov [rdi+48], r10",
        "mov [rdi+56], r9",
        "mov [rdi+64], r8",
        "mov [rdi+72], rbp",
        "mov [rdi+80], rdi",
        "mov [rdi+88], rsi",
        "mov [rdi+96], rdx",
        "mov [rdi+104], rcx",
        "lea rax, [rsp+8]",   // pre-call rsp: the `call` pushed a return
                              // address below it, so skipping 8 bytes keeps
                              // the resume stack depth constant per round
        "mov [rdi+152], rax",
        // -------- load target frame: GPR slots, then the iretq words --------
        // Popping the slots works for BOTH fresh targets (all-zero slots)
        // and saved targets (their last switch spilled actual registers).
        "lea rcx, [rip + {}]", // SWITCH_SCRATCH (entry rcx is not `to`)
        "mov rcx, [rcx]", // target frame pointer
        "mov rsp, rcx", // pop the GPR block off the frame slots
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx", // clobbers the target pointer
        "pop rax",
        "lea rcx, [rip + {}]", // SWITCH_SCRATCH
        "mov rcx, [rcx]", // target frame pointer again
        "mov rsp, [rcx+152]", // pre-iret rsp (fresh: stack_top-40; resume: no-op)
        "push qword ptr [rcx+160]", // ss
        "push qword ptr [rcx+152]", // rsp
        "push qword ptr [rcx+144]", // rflags
        "push qword ptr [rcx+136]", // cs
        "push qword ptr [rcx+128]", // rip
        "iretq",
        sym SWITCH_SCRATCH,
        sym SWITCH_SCRATCH,
        sym SWITCH_SCRATCH,
    )
}

/// Idle-loop frame pointer the switch path stashes before clobbering every
/// GP register with the target's block.
static mut SWITCH_SCRATCH: u64 = 0;

/// The idle loop's own frame (the "scheduler" context).
static mut IDLE_FRAME: core::mem::MaybeUninit<TaskFrame> = core::mem::MaybeUninit::uninit();

/// Initialise `IDLE_FRAME` with a self-contained idle-loop context so the
/// scheduler can switch to idle before the first timer preemption has saved
/// one. The idle loop runs on its own stack (`idle_stack_top`), so this
/// frame's `rsp` points at private, never-clobbered memory.
///
/// # Safety
/// Call once at boot, before interrupts are enabled / any task runs.
pub unsafe fn init_idle_frame(idle_entry: extern "sysv64" fn() -> !) {
    let f = TaskFrame::fresh(idle_entry, crate::cpu::idle_stack_top());
    core::ptr::write(core::ptr::addr_of_mut!(IDLE_FRAME).cast::<TaskFrame>(), f);
}

/// Task table; slots filled by `spawn`.
static mut TASKS: [core::mem::MaybeUninit<Task>; MAX_TASKS] =
    [const { core::mem::MaybeUninit::uninit() }; MAX_TASKS];

static mut SPAWNED: usize = 0;
static mut CURRENT: usize = usize::MAX; // index into TASKS while a task runs

/// Raw pointer to task `i`'s `TaskFrame` (offset past the `name` field).
fn task_frame_ptr(i: usize) -> *mut TaskFrame {
    unsafe {
        core::ptr::addr_of_mut!(TASKS)
            .byte_add(i * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, frame))
            .cast()
    }
}

/// Register a task. Returns `None` when the table is full.
///
/// # Safety
/// `stack_base` must point at a 16 KiB region owned by the kernel (e.g.
/// four consecutive frames from the allocator), and `entry` must never
/// return.
pub unsafe fn spawn(
    name: &'static str,
    entry: extern "sysv64" fn() -> !,
    stack_base: u64,
) -> Option<usize> {
    spawn_impl(name, entry, stack_base, 0)
}

/// Register a RING-3 task. In addition to `spawn`'s requirements,
/// `cpl0_stack_base` must point at a second 16 KiB region owned by the
/// kernel; it becomes the task's dedicated CPL0 stack (TSS.RSP0 target)
/// for every interrupt/syscall that enters the kernel from ring 3.
///
/// # Safety
/// See `spawn`; additionally both stacks must be regions the kernel
/// retains for the task's lifetime.
pub unsafe fn spawn_user(
    name: &'static str,
    entry: extern "sysv64" fn() -> !,
    stack_base: u64,
    cpl0_stack_base: u64,
) -> Option<usize> {
    let idx = spawn_impl(name, entry, stack_base, cpl0_stack_base);
    if let Some(i) = idx {
        crate::trace::spawn(i, name);
    }
    idx
}

unsafe fn spawn_impl(
    name: &'static str,
    entry: extern "sysv64" fn() -> !,
    stack_base: u64,
    cpl0_stack_base: u64,
) -> Option<usize> {
    let spawned = core::ptr::read(core::ptr::addr_of_mut!(SPAWNED));
    if spawned >= MAX_TASKS {
        // Full at the high-water mark: reuse a dead (Zombie) slot if any.
        let reuse = (0..MAX_TASKS).find(|&i| task_state(i) == TaskState::Zombie);
        let slot = reuse?;
        let task = if cpl0_stack_base != 0 {
            Task::new_user(name, entry, stack_base, cpl0_stack_base)
        } else {
            Task::new(name, entry, stack_base)
        };
        core::ptr::write(
            core::ptr::addr_of_mut!(TASKS)
                .cast::<core::mem::MaybeUninit<Task>>()
                .add(slot),
            core::mem::MaybeUninit::new(task),
        );
        return Some(slot);
    }
    let task = if cpl0_stack_base != 0 {
        Task::new_user(name, entry, stack_base, cpl0_stack_base)
    } else {
        Task::new(name, entry, stack_base)
    };
    core::ptr::write(
        core::ptr::addr_of_mut!(TASKS)
            .cast::<core::mem::MaybeUninit<Task>>()
            .add(spawned),
        core::mem::MaybeUninit::new(task),
    );
    core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), spawned + 1);
    Some(spawned)
}

/// Number of spawned tasks.
pub fn spawned_count() -> usize {
    unsafe { core::ptr::read(core::ptr::addr_of_mut!(SPAWNED)) }
}

/// Index of the currently running context (`usize::MAX` = the idle loop).
pub fn current_idx() -> usize {
    unsafe { core::ptr::read(core::ptr::addr_of_mut!(CURRENT)) }
}

/// Test-only: pin `CURRENT` to a task index so ipc capability-gate tests can
/// exercise the syscall entries without a live scheduler context.
#[cfg(test)]
pub fn set_current_for_test(idx: usize) {
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(CURRENT), idx) }
}

/// Test-only: reset the task table so supervisor/reap contract tests can spawn
/// fresh tasks in an otherwise empty, deterministic table. Also clears the
/// monitor's global grant ledger: `ipc_cap_grant` is gated on
/// `ledger.is_suspended(current)`, and a monitor contract test that leaves a
/// task suspended must not leak that state into a later grant test (it made
/// the revocation contract flaky depending on test order).
#[cfg(test)]
pub fn reset_table_for_test() {
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), 0);
        core::ptr::write(core::ptr::addr_of_mut!(CURRENT), usize::MAX);
        crate::monitor::ledger().clear_for_test();
        for i in 0..MAX_TASKS {
            let slot = core::ptr::addr_of_mut!(TASKS)
                .cast::<core::mem::MaybeUninit<Task>>()
                .add(i);
            core::ptr::write(slot, core::mem::MaybeUninit::uninit());
        }
    }
}

/// Test-only: an entry function other modules can spawn in unit tests
/// (mirrors the private `dummy` in this module's own test suite).
#[cfg(test)]
pub extern "sysv64" fn tests_dummy() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Current scheduling state of task `idx` (public read for tests and the
/// notification-delivery contract).
pub fn task_state_of(idx: usize) -> TaskState {
    task_state(idx)
}

/// Next context in round-robin order: idle -> task 0 -> ... -> last task
/// -> idle. Returns `None` when no tasks are spawned. Pure (ignores blocked
/// state) — used by unit tests.
#[cfg(test)]
fn next_after(cur: usize, spawned: usize) -> Option<usize> {
    match (spawned, cur) {
        (0, _) => None,
        (_, usize::MAX) => Some(0),
        (n, c) if c + 1 >= n => Some(usize::MAX),
        (_, c) => Some(c + 1),
    }
}

/// Pick the next *runnable* context (skips `Blocked` tasks). If every task
/// is blocked, returns the idle loop (`usize::MAX`) so the CPU has something
/// to run while IPC completes.
pub fn schedule_next(cur: usize) -> Option<usize> {
    let spawned = spawned_count();
    if spawned == 0 {
        return None;
    }
    let mut checked = 0;
    let mut i = cur;
    loop {
        i = match i {
            usize::MAX => 0,
            c if c + 1 >= spawned => 0,
            c => c + 1,
        };
        checked += 1;
        if task_state(i) == TaskState::Ready {
            return Some(i);
        }
        if checked >= spawned {
            return Some(usize::MAX);
        }
    }
}

fn task_state(idx: usize) -> TaskState {
    unsafe {
        let p = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, state))
            .cast::<TaskState>();
        *p
    }
}

fn set_task_state(idx: usize, s: TaskState) {
    unsafe {
        let p = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, state))
            .cast::<TaskState>();
        *p = s;
    }
}

/// Capability slot `slot` of task `idx`.
pub fn task_cap(idx: usize, slot: usize) -> CapSlot {
    unsafe {
        let p = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, caps))
            .cast::<CapTable>();
        (*p)[slot]
    }
}

pub fn set_task_cap(idx: usize, slot: usize, cap: CapSlot) {
    unsafe {
        let p = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, caps))
            .cast::<CapTable>();
        (*p)[slot] = cap;
    }
}

/// Copy a capability from `src` task's slot into `dst` task's table (first
/// free slot). Returns the destination slot, or `usize::MAX` if full.
pub fn grant_cap(dst: usize, src: usize, src_slot: usize) -> usize {
    let slot = task_cap(src, src_slot);
    if slot.cap == Cap::None {
        return usize::MAX;
    }
    let free = (0..MAX_CAPS).find(|&s| task_cap(dst, s).cap == Cap::None);
    match free {
        Some(s) => {
            set_task_cap(dst, s, slot);
            s
        }
        None => usize::MAX,
    }
}

/// Mark the current task blocked on endpoint `ep`.
pub fn block_current(ep: usize) {
    let cur = current_idx();
    set_task_state(cur, TaskState::Blocked);
    unsafe {
        let p = core::ptr::addr_of_mut!(TASKS)
            .byte_add(cur * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, blocked_ep))
            .cast::<usize>();
        *p = ep;
    }
}

/// Mark task `idx` runnable again.
pub fn unblock_task(idx: usize) {
    set_task_state(idx, TaskState::Ready);
    unsafe {
        let p = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, blocked_ep))
            .cast::<usize>();
        *p = usize::MAX;
    }
}

/// One-shot demo hook: hold task `idx` blocked until the LAPIC tick counter
/// reaches `tick`, then unblock it. Lets the IPC demo (server/client) finish
/// before the isolation test runs, so the two demos don't race for the
/// first slice. `tick = u64::MAX` disarms the hook.
pub static ISO_ARM_TICK: AtomicU64 = AtomicU64::new(u64::MAX);
static ISO_ARM_IDX: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Arm the one-shot unblock hook for the isolation-test demo task.
pub fn arm_isolation_test(idx: usize, tick: u64) {
    set_task_state(idx, TaskState::Blocked);
    ISO_ARM_IDX.store(idx, Ordering::Relaxed);
    ISO_ARM_TICK.store(tick, Ordering::Relaxed);
}

/// One-shot demo hook for the NX-test task (same pattern as ISO_ARM_*):
/// hold task `idx` blocked until the LAPIC tick counter reaches `tick`.
pub static NX_ARM_TICK: AtomicU64 = AtomicU64::new(u64::MAX);
static NX_ARM_IDX: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Arm the one-shot unblock hook for the NX-test demo task.
pub fn arm_nx_test(idx: usize, tick: u64) {
    set_task_state(idx, TaskState::Blocked);
    NX_ARM_IDX.store(idx, Ordering::Relaxed);
    NX_ARM_TICK.store(tick, Ordering::Relaxed);
}

/// One-shot demo hook for the Phase-6 service task (same pattern as the
/// ISO/NX hooks): hold task `idx` blocked until the LAPIC tick counter reaches
/// `tick`, then let it run and fault.
pub static SERVICE_ARM_TICK: AtomicU64 = AtomicU64::new(u64::MAX);
static SERVICE_ARM_IDX: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Arm the one-shot unblock hook for the Phase-6 service demo task.
pub fn arm_service_test(idx: usize, tick: u64) {
    set_task_state(idx, TaskState::Blocked);
    SERVICE_ARM_IDX.store(idx, Ordering::Relaxed);
    SERVICE_ARM_TICK.store(tick, Ordering::Relaxed);
}

/// One-shot Phase-6 hook: once the LAPIC tick counter passes `tick`, dump the
/// kernel audit trail for the role-grant flow (`audit::dump_agent_flow`) naming
/// `agent`. Armed by boot code so the "kernel prints audit log" step of the
/// Phase-6 demo is a kernel-side print, not a ring-3 claim.
pub static AUDIT_DUMP_TICK: AtomicU64 = AtomicU64::new(u64::MAX);
static AUDIT_DUMP_AGENT: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Arm the one-shot audit-dump hook for the Phase-6 demo.
pub fn arm_audit_dump(agent: usize, tick: u64) {
    AUDIT_DUMP_AGENT.store(agent, Ordering::Relaxed);
    AUDIT_DUMP_TICK.store(tick, Ordering::Relaxed);
}

/// Kill the currently running task: it faulted in ring 3 (page-fault-driven
/// isolation/NX demo) and must never be scheduled again. The scheduler skips
/// non-Ready tasks, so Zombie is permanent.
pub fn kill_current() {
    let cur = current_idx();
    if cur != usize::MAX {
        kill_task(cur);
    }
}

/// Kill task `idx` (supervision CONTROL-right path). Marks it `Zombie`;
/// the scheduler skips it thereafter.
pub fn kill_task(idx: usize) {
    if idx < MAX_TASKS {
        set_task_state(idx, TaskState::Zombie);
    }
}

/// True if task `idx` is still schedulable.
pub fn is_task_alive(idx: usize) -> bool {
    idx < MAX_TASKS && task_state(idx) != TaskState::Zombie
}

/// Rebuild a `Zombie` task's frame to its original entry point and stack so a
/// supervised restart can re-run it (the supervision-tree respawn primitive).
/// Leaves the task `Ready` once more. Returns false if `idx` is out of range
/// or not a `Zombie` (so restarts can't be minted on live tasks).
pub fn restart_task(idx: usize) -> bool {
    if idx >= MAX_TASKS || task_state(idx) != TaskState::Zombie {
        return false;
    }
    unsafe {
        let p = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, entry))
            .cast::<extern "sysv64" fn() -> !>();
        let entry: extern "sysv64" fn() -> ! = *p;
        let top = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, stack_base))
            .cast::<u64>()
            .read()
            + TASK_STACK_SIZE;
        let cpl0 = core::ptr::addr_of_mut!(TASKS)
            .byte_add(
                idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, cpl0_stack_top),
            )
            .cast::<u64>()
            .read();
        // Ring-3 tasks restart into the user frame (their page tables and
        // CPL0 stack still live); kernel tasks into the ring-0 frame.
        let frame = if cpl0 != 0 {
            TaskFrame::fresh_user(entry, top)
        } else {
            TaskFrame::fresh(entry, top)
        };
        core::ptr::write(
            core::ptr::addr_of_mut!(TASKS)
                .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, frame))
                .cast::<TaskFrame>(),
            frame,
        );
    }
    set_task_state(idx, TaskState::Ready);
    unsafe {
        let p = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, blocked_ep))
            .cast::<usize>();
        *p = usize::MAX;
    }
    true
}

/// Free the frames backing `Zombie` task `idx`, so a later `spawn` can reuse
/// the slot (supervision reaping closes the leak where killed tasks previously
/// occupied a table slot forever). The slot stays a `Zombie` row — the
/// scheduler skips it — and `spawn_impl` reuses `Zombie` slots by index.
pub fn reap_task(idx: usize) -> bool {
    if idx >= MAX_TASKS || task_state(idx) != TaskState::Zombie {
        return false;
    }
    unsafe {
        let stack_base = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, stack_base))
            .cast::<u64>()
            .read();
        for off in (0..TASK_STACK_SIZE).step_by(crate::frame::PAGE_SIZE as usize) {
            crate::frame::free_global(stack_base + off);
        }
    }
    true
}

/// Switch away from `cur` to the next runnable context. Does not return to
/// `cur` (the caller is resumed later by a future switch). Used by both the
/// timer preemption path and the blocking IPC syscalls.
///
/// Swaps CR3 when switching between kernel and user tasks to enforce
/// per-task memory isolation.
///
/// # Safety
/// `cur` must be the currently executing task index. Interrupts must be
/// disabled. The caller will not return until rescheduled.
pub unsafe fn switch_away_from(cur: usize) {
    let Some(next) = schedule_next(cur) else {
        return;
    };
    if next == cur {
        return; // nothing else runnable (idle is the only option)
    }
    crate::sprintln!("Aegis: switch {} -> {}", cur, next);
    core::ptr::write(core::ptr::addr_of_mut!(CURRENT), next);
    crate::cpu::set_tss_rsp0(context_cpl0_top(next));
    // Swap CR3 to enforce per-task memory isolation before loading the
    // target context (the target's iretq words use the new address space).
    let next_pml4 = context_pml4(next);
    crate::page_tables::switch_to(next_pml4);
    crate::sprintln!(
        "Aegis: switch_frame from={} to={} rsp0=0x{:X}",
        cur,
        next,
        crate::cpu::get_tss_rsp0()
    );
    switch_frame(context_frame(cur), context_frame(next));
}

/// Frame pointer of a context: a numeric task index, or the idle loop for
/// `usize::MAX`.
pub fn context_frame(idx: usize) -> *mut TaskFrame {
    if idx == usize::MAX {
        core::ptr::addr_of_mut!(IDLE_FRAME).cast::<TaskFrame>()
    } else {
        task_frame_ptr(idx)
    }
}

/// TSS.RSP0 value for a context: its dedicated CPL0 stack for ring-3
/// tasks, or the kernel stack top for kernel/idle contexts (which never
/// transition into the kernel, so the value is only a safe default).
pub(crate) fn context_cpl0_top(idx: usize) -> u64 {
    if idx == usize::MAX {
        return crate::cpu::idle_stack_top();
    }
    unsafe {
        let top = core::ptr::addr_of_mut!(TASKS)
            .byte_add(
                idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, cpl0_stack_top),
            )
            .cast::<u64>()
            .read();
        if top != 0 {
            top
        } else {
            crate::cpu::stack_top()
        }
    }
}

/// Physical address of a context's page table: the per-user PML4 for
/// ring-3 tasks, or the kernel PML4 for kernel/idle contexts.
pub(crate) fn context_pml4(idx: usize) -> u64 {
    if idx == usize::MAX {
        return crate::page_tables::kernel_pml4_phys();
    }
    unsafe {
        let pml4 = core::ptr::addr_of_mut!(TASKS)
            .byte_add(idx * core::mem::size_of::<Task>() + core::mem::offset_of!(Task, pml4_phys))
            .cast::<u64>()
            .read();
        if pml4 != 0 {
            pml4
        } else {
            crate::page_tables::kernel_pml4_phys()
        }
    }
}

/// Preemptive round-robin tick hook, called from the timer stub on every
/// timer interrupt, with the interrupt frame on the current context's
/// stack. Saves the interrupted context (including this call's own stub
/// frame) and resumes the next context; `CURRENT` is advanced before the
/// switch so the save-load bookkeeping stays consistent.
///
/// # Safety
/// Must run with at least one spawned task and a valid `CURRENT`; the
/// timer stub calls it with interrupts masked.
pub unsafe fn timer_preempt() {
    let spawned = spawned_count();
    if spawned == 0 {
        return;
    }
    // Release the isolation-test task once the IPC demo has finished.
    if crate::cpu::timer_ticks() >= ISO_ARM_TICK.load(Ordering::Relaxed) {
        ISO_ARM_TICK.store(u64::MAX, Ordering::Relaxed);
        unblock_task(ISO_ARM_IDX.load(Ordering::Relaxed));
    }
    // Same one-shot hook for the NX-test task.
    if crate::cpu::timer_ticks() >= NX_ARM_TICK.load(Ordering::Relaxed) {
        NX_ARM_TICK.store(u64::MAX, Ordering::Relaxed);
        unblock_task(NX_ARM_IDX.load(Ordering::Relaxed));
    }
    // Same one-shot hook for the Phase-6 service task (its fault is what the
    // zero-capability agent restarts).
    if crate::cpu::timer_ticks() >= SERVICE_ARM_TICK.load(Ordering::Relaxed) {
        SERVICE_ARM_TICK.store(u64::MAX, Ordering::Relaxed);
        unblock_task(SERVICE_ARM_IDX.load(Ordering::Relaxed));
    }
    // Phase-6 hook: once the role-grant flow has settled, print the kernel's
    // audit trail for it (the kernel prints audit log, one shot).
    if crate::cpu::timer_ticks() >= AUDIT_DUMP_TICK.load(Ordering::Relaxed) {
        AUDIT_DUMP_TICK.store(u64::MAX, Ordering::Relaxed);
        let agent = AUDIT_DUMP_AGENT.load(Ordering::Relaxed);
        if agent != usize::MAX {
            crate::audit::dump_agent_flow(agent);
        }
    }
    let cur = current_idx();
    let Some(next) = schedule_next(cur) else {
        return;
    };
    if next == cur {
        return;
    }
    crate::sprintln!(
        "Aegis: preempt {} -> {} tick={}",
        cur,
        next,
        crate::cpu::timer_ticks()
    );
    core::ptr::write(core::ptr::addr_of_mut!(CURRENT), next);
    // Point TSS.RSP0 at the next context's CPL0 stack so ITS ring-3
    // transitions (and only theirs) use it, never the stack another
    // task's kernel frame is parked on.
    crate::cpu::set_tss_rsp0(context_cpl0_top(next));
    // Swap CR3 to the next context's address space for memory isolation.
    crate::page_tables::switch_to(context_pml4(next));
    let from = context_frame(cur);
    let to = context_frame(next);
    switch_frame(from, to)
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "sysv64" fn dummy() -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    fn dummy_addr() -> u64 {
        let p: extern "sysv64" fn() -> ! = dummy;
        p as usize as u64
    }

    #[test]
    fn frame_size_is_176_bytes() {
        let _g = crate::kernel_state_guard();
        assert_eq!(TaskFrame::size(), 176);
    }

    #[test]
    fn next_after_round_robins_tasks_and_idle() {
        let _g = crate::kernel_state_guard();
        assert_eq!(next_after(usize::MAX, 2), Some(0));
        assert_eq!(next_after(0, 2), Some(1));
        assert_eq!(next_after(1, 2), Some(usize::MAX));
        assert_eq!(next_after(usize::MAX, 3), Some(0));
        assert_eq!(next_after(1, 3), Some(2));
        assert_eq!(next_after(2, 3), Some(usize::MAX));
    }

    #[test]
    fn next_after_without_tasks_returns_none() {
        let _g = crate::kernel_state_guard();
        assert_eq!(next_after(usize::MAX, 0), None);
        assert_eq!(next_after(0, 0), None);
    }

    #[test]
    fn fresh_frame_zeroes_saved_to() {
        let _g = crate::kernel_state_guard();
        let f = TaskFrame::fresh(dummy, 0x4000);
        assert_eq!(f.saved_to, 0);
    }

    #[test]
    fn fresh_frame_is_well_formed() {
        let _g = crate::kernel_state_guard();
        let f = TaskFrame::fresh(dummy, 0x4000);
        assert_eq!(f.rip, dummy_addr());
        assert_eq!(f.cs, 0x08);
        assert_eq!(f.ss, 0x10);
        assert_eq!(f.rflags, 0x202); // IF set
        assert_eq!(f.error, 0);
        assert_eq!(f.rsp, 0x4000 - 40); // SysV: rsp % 16 == 8 after iretq
        assert_eq!(f.rax | f.rbx | f.r12 | f.r15, 0); // general regs zeroed
        assert_eq!(f.rsp % 16, 8);
    }

    #[test]
    fn fresh_user_frame_uses_ring3_selectors() {
        let _g = crate::kernel_state_guard();
        let f = TaskFrame::fresh_user(dummy, 0x4000);
        assert_eq!(f.rip, dummy_addr());
        assert_eq!(f.cs, crate::gdt::USER_CODE_SELECTOR as u64); // 0x1B
        assert_eq!(f.ss, crate::gdt::USER_DATA_SELECTOR as u64); // 0x23
        assert_eq!(f.rflags, 0x202); // IF set, IOPL 0
        assert_eq!(f.rsp, 0x4000 - 40);
        assert_eq!(f.rsp % 16, 8);
    }

    #[test]
    fn fresh_rsp_sits_inside_stack_region() {
        let _g = crate::kernel_state_guard();
        let stack_base = 0x4000;
        let f = TaskFrame::fresh(dummy, stack_base + TASK_STACK_SIZE);
        assert!(f.rsp > stack_base && f.rsp < stack_base + TASK_STACK_SIZE);
        let room = f.rsp - stack_base;
        assert!(room >= 40, "iretq frame must fit below entry rsp: {}", room);
    }

    #[test]
    fn task_new_places_stack_top_correctly() {
        let _g = crate::kernel_state_guard();
        let t = Task::new("t", dummy, 0x8000);
        assert_eq!(t.name, "t");
        assert_eq!(t.stack_base, 0x8000);
        assert_eq!(t.cpl0_stack_top, 0);
        assert_eq!(t.frame.rip, dummy_addr());
        assert_eq!(t.frame.rsp, 0x8000 + TASK_STACK_SIZE - 40);
    }

    #[test]
    fn task_new_user_places_both_stack_tops_correctly() {
        let _g = crate::kernel_state_guard();
        let t = Task::new_user("u", dummy, 0x8000, 0xC000);
        assert_eq!(t.stack_base, 0x8000);
        assert_eq!(t.cpl0_stack_top, 0xC000 + TASK_STACK_SIZE);
        assert_eq!(t.frame.cs, crate::gdt::USER_CODE_SELECTOR as u64);
        assert_eq!(t.frame.ss, crate::gdt::USER_DATA_SELECTOR as u64);
        assert_eq!(t.frame.rsp, 0x8000 + TASK_STACK_SIZE - 40);
    }

    #[test]
    fn spawn_respects_table_capacity() {
        let _g = crate::kernel_state_guard();
        unsafe {
            // Reset global state for the test.
            core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), 0);
            for i in 0..MAX_TASKS {
                let slot = core::ptr::addr_of_mut!(TASKS)
                    .cast::<core::mem::MaybeUninit<Task>>()
                    .add(i);
                core::ptr::write(slot, core::mem::MaybeUninit::uninit());
            }
            for i in 0..MAX_TASKS {
                assert!(spawn("t", dummy, 0x8000 + i as u64 * TASK_STACK_SIZE).is_some());
            }
            assert_eq!(spawn("full", dummy, 0x90000), None);
            assert_eq!(spawned_count(), MAX_TASKS);
            // Leave the table empty for other tests.
            core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), 0);
        }
    }

    #[test]
    fn spawned_frames_hold_unique_stacks() {
        let _g = crate::kernel_state_guard();
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), 0);
            let a = spawn("a", dummy, 0x8000).unwrap();
            let b = spawn("b", dummy, 0xC000).unwrap();
            let ta = core::ptr::addr_of_mut!(TASKS)
                .cast::<core::mem::MaybeUninit<Task>>()
                .add(a)
                .cast::<Task>()
                .read()
                .frame;
            let tb = core::ptr::addr_of_mut!(TASKS)
                .cast::<core::mem::MaybeUninit<Task>>()
                .add(b)
                .cast::<Task>()
                .read()
                .frame;
            assert_ne!(ta.rsp, tb.rsp);
            assert_eq!(ta.rsp % 16, 8);
            assert_eq!(tb.rsp % 16, 8);
            core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), 0);
        }
    }

    /// Phase 2 least-authority contract: a freshly spawned task starts with a
    /// completely empty CSpace — spawn grants no implicit authority, every
    /// capability must be explicitly granted by another task (or installed by
    /// the kernel for a named demo role).
    #[test]
    fn least_authority_new_task_starts_with_an_empty_cspace() {
        let _g = crate::kernel_state_guard();
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), 0);
            let t = spawn("fresh", dummy, 0x8000).unwrap();
            for s in 0..MAX_CAPS {
                assert_eq!(
                    task_cap(t, s),
                    CapSlot::empty(),
                    "spawn must never implicitly grant authority (least authority)"
                );
            }
            core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), 0);
        }
    }

    /// Phase 5 least-authority contract: the respawn primitive only rebuilds a
    /// task that is already a `Zombie` — restarting a live task is refused, so
    /// a supervisor can never mint a reset on a running child.
    #[test]
    fn restart_refuses_live_tasks() {
        let _g = crate::kernel_state_guard();
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), 0);
            let t = spawn("live", dummy, 0x8000).unwrap();
            assert_eq!(restart_task(t), false, "Ready tasks are never resettable");
            assert!(is_task_alive(t));
            core::ptr::write(core::ptr::addr_of_mut!(SPAWNED), 0);
        }
    }
}

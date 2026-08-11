//! Minimal cooperative kernel tasks: each task runs on its own 16 KiB
//! stack, and control moves between tasks (and the idle loop) by swapping
//! full interrupt-style frames with `iretq`.
//!
//! Honest limits: scheduling is cooperative (`yield_now` only) — the LAPIC
//! timer drives the wall-clock tick counter but does not preempt tasks yet.
//! The `switch_frame` assembler primitive is verified under QEMU/TCG only,
//! not on physical hardware.

use core::arch::naked_asm;

pub const TASK_STACK_SIZE: u64 = 16384;
pub const MAX_TASKS: usize = 4;

/// Full register context of a running task, in the same order as the
/// timer-stub saves: 15 GP registers, error slot, then the iretq frame
/// (RIP, CS, RFLAGS, RSP, SS).
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
}

impl Task {
    pub fn new(name: &'static str, entry: extern "sysv64" fn() -> !, stack_base: u64) -> Task {
        Task {
            name,
            frame: TaskFrame::fresh(entry, stack_base + TASK_STACK_SIZE),
            stack_base,
            cpl0_stack_top: 0,
        }
    }

    pub fn new_user(
        name: &'static str,
        entry: extern "sysv64" fn() -> !,
        stack_base: u64,
        cpl0_stack_base: u64,
    ) -> Task {
        Task {
            name,
            frame: TaskFrame::fresh_user(entry, stack_base + TASK_STACK_SIZE),
            stack_base,
            cpl0_stack_top: cpl0_stack_base + TASK_STACK_SIZE,
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
    spawn_impl(name, entry, stack_base, cpl0_stack_base)
}

unsafe fn spawn_impl(
    name: &'static str,
    entry: extern "sysv64" fn() -> !,
    stack_base: u64,
    cpl0_stack_base: u64,
) -> Option<usize> {
    let spawned = core::ptr::read(core::ptr::addr_of_mut!(SPAWNED));
    if spawned >= MAX_TASKS {
        return None;
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
fn current_idx() -> usize {
    unsafe { core::ptr::read(core::ptr::addr_of_mut!(CURRENT)) }
}

/// Next context in round-robin order: idle -> task 0 -> ... -> last task
/// -> idle. Returns `None` when no tasks are spawned.
fn next_after(cur: usize, spawned: usize) -> Option<usize> {
    match (spawned, cur) {
        (0, _) => None,
        (_, usize::MAX) => Some(0),
        (n, c) if c + 1 >= n => Some(usize::MAX),
        (_, c) => Some(c + 1),
    }
}

/// Frame pointer of a context: a numeric task index, or the idle loop for
/// `usize::MAX`.
fn context_frame(idx: usize) -> *mut TaskFrame {
    if idx == usize::MAX {
        core::ptr::addr_of_mut!(IDLE_FRAME).cast::<TaskFrame>()
    } else {
        task_frame_ptr(idx)
    }
}

/// TSS.RSP0 value for a context: its dedicated CPL0 stack for ring-3
/// tasks, or the kernel stack top for kernel/idle contexts (which never
/// transition into the kernel, so the value is only a safe default).
fn context_cpl0_top(idx: usize) -> u64 {
    if idx == usize::MAX {
        return crate::cpu::stack_top();
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
    let cur = current_idx();
    let Some(next) = next_after(cur, spawned) else {
        return;
    };
    if next == cur {
        return;
    }
    core::ptr::write(core::ptr::addr_of_mut!(CURRENT), next);
    // Point TSS.RSP0 at the next context's CPL0 stack so ITS ring-3
    // transitions (and only theirs) use it, never the stack another
    // task's kernel frame is parked on.
    crate::cpu::set_tss_rsp0(context_cpl0_top(next));
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
        assert_eq!(TaskFrame::size(), 176);
    }

    #[test]
    fn next_after_round_robins_tasks_and_idle() {
        assert_eq!(next_after(usize::MAX, 2), Some(0));
        assert_eq!(next_after(0, 2), Some(1));
        assert_eq!(next_after(1, 2), Some(usize::MAX));
        assert_eq!(next_after(usize::MAX, 3), Some(0));
        assert_eq!(next_after(1, 3), Some(2));
        assert_eq!(next_after(2, 3), Some(usize::MAX));
    }

    #[test]
    fn next_after_without_tasks_returns_none() {
        assert_eq!(next_after(usize::MAX, 0), None);
        assert_eq!(next_after(0, 0), None);
    }

    #[test]
    fn fresh_frame_zeroes_saved_to() {
        let f = TaskFrame::fresh(dummy, 0x4000);
        assert_eq!(f.saved_to, 0);
    }

    #[test]
    fn fresh_frame_is_well_formed() {
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
        let stack_base = 0x4000;
        let f = TaskFrame::fresh(dummy, stack_base + TASK_STACK_SIZE);
        assert!(f.rsp > stack_base && f.rsp < stack_base + TASK_STACK_SIZE);
        let room = f.rsp - stack_base;
        assert!(room >= 40, "iretq frame must fit below entry rsp: {}", room);
    }

    #[test]
    fn task_new_places_stack_top_correctly() {
        let t = Task::new("t", dummy, 0x8000);
        assert_eq!(t.name, "t");
        assert_eq!(t.stack_base, 0x8000);
        assert_eq!(t.cpl0_stack_top, 0);
        assert_eq!(t.frame.rip, dummy_addr());
        assert_eq!(t.frame.rsp, 0x8000 + TASK_STACK_SIZE - 40);
    }

    #[test]
    fn task_new_user_places_both_stack_tops_correctly() {
        let t = Task::new_user("u", dummy, 0x8000, 0xC000);
        assert_eq!(t.stack_base, 0x8000);
        assert_eq!(t.cpl0_stack_top, 0xC000 + TASK_STACK_SIZE);
        assert_eq!(t.frame.cs, crate::gdt::USER_CODE_SELECTOR as u64);
        assert_eq!(t.frame.ss, crate::gdt::USER_DATA_SELECTOR as u64);
        assert_eq!(t.frame.rsp, 0x8000 + TASK_STACK_SIZE - 40);
    }

    #[test]
    fn spawn_respects_table_capacity() {
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
}

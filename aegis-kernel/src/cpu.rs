//! CPU bring-up: kernel stack, GDT, IDT, LAPIC timer, legacy PIC masking.
//!
//! Honest limits: these are bare-metal operations verified under QEMU/OVMF
//! only; not tested on physical hardware. The timer is a raw tick counter
//! (division/initial-count chosen arbitrarily, no calibration against a
//! wall-clock source), so tick rate is machine-dependent.

use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicU64, Ordering};

/// Vector used for the LAPIC periodic timer (above the 0-31 exception range).
pub const TIMER_VECTOR: u8 = 0x30;

static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Number of timer interrupts received since the timer was armed.
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

/// Kernel stack, in its own `.bss.stack` section. The linker places an
/// orphan section after `.bss` in the RW segment, so the stack sits at the
/// top of the kernel's BSS and grows down — it can never collide with the
/// page tables or other BSS below it.
#[unsafe(link_section = ".bss.stack")]
static mut KERNEL_STACK: [u8; KERNEL_STACK_SIZE] = [0u8; KERNEL_STACK_SIZE];

const KERNEL_STACK_SIZE: usize = 16384;

/// Top of the dedicated idle stack, allocated from the frame allocator at
/// boot (see `set_idle_stack_top`). The idle loop runs here so its saved
/// scheduler frame's `rsp` points at private, never-clobbered memory; if
/// idle shared `KERNEL_STACK`, later timer/syscall entries for other tasks
/// would overwrite that region and restoring idle would pop garbage — which
/// QEMU/TCG tolerated but real hardware (VMware) faults on. Zero until set.
static mut IDLE_STACK_TOP: u64 = 0;

/// Top (highest address) of the kernel stack, 16-aligned downwards.
pub fn stack_top() -> u64 {
    let mut top: u64;
    unsafe {
        asm!(
            "lea {}, [rip + {stack} + {size}]",
            out(reg) top,
            stack = sym KERNEL_STACK,
            size = const KERNEL_STACK_SIZE,
            options(nostack, preserves_flags),
        );
    }
    top & !15
}

/// Top (highest address) of the idle stack, 16-aligned downwards. Returns 0
/// before the idle stack has been allocated.
pub fn idle_stack_top() -> u64 {
    unsafe { core::ptr::addr_of!(IDLE_STACK_TOP).read() }
}

/// Record the idle stack top (allocated from the frame allocator at boot).
///
/// # Safety
/// Must be called exactly once, before `idle_stack_top` / `switch_to_idle_stack`.
pub unsafe fn set_idle_stack_top(top: u64) {
    core::ptr::addr_of_mut!(IDLE_STACK_TOP).write(top);
}

/// Switch the CPU onto the idle stack and jump into the idle loop. Used
/// once, after boot init, to take the idle loop off the shared kernel
/// stack. `entry` is the idle-loop function; it never returns.
///
/// # Safety
///
/// Call only once, after interrupts are enabled and all init is done, and
/// after `set_idle_stack_top`. `entry` must be a valid, never-returning fn.
pub unsafe fn switch_to_idle_stack(entry: extern "sysv64" fn() -> !) -> ! {
    asm!(
        "mov rsp, {top}",
        "and rsp, -16",
        "mov rax, {entry}",
        "jmp rax",
        top = in(reg) idle_stack_top(),
        entry = in(reg) entry,
        options(noreturn),
    );
}

/// Disable SMEP (bit 20) and SMAP (bit 21) in CR4. The firmware (OVMF)
/// leaves these on under `-cpu max`; with SMEP set, a supervisor-mode
/// fetch of a user-accessible page #PFs — which would kill our `iretq`
/// into ring-3 the instant it tried to fetch the first user instruction.
///
/// # Safety
///
/// Must be called once at boot, before any ring-3 transition. Reads and
/// writes CR4; the caller must guarantee no concurrent uses of CR4.
pub unsafe fn disable_smep_smap() {
    let mut cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4, options(nomem, preserves_flags));
    crate::sprintln!("Aegis: CR4 before = 0x{:016X}", cr4);
    cr4 &= !((1u64 << 20) | (1u64 << 21));
    asm!("mov cr4, {}", in(reg) cr4, options(nomem, preserves_flags));
    let after: u64;
    asm!("mov {}, cr4", out(reg) after, options(nomem, preserves_flags));
    crate::sprintln!("Aegis: CR4 after  = 0x{:016X} (SMEP/SMAP cleared)", after);
}

/// Switch the CPU onto the kernel's own stack.
///
/// # Safety
///
/// The old (loader-provided) stack is abandoned; callers must not rely on
/// it afterwards. Intended to be called once, very early in boot.
pub unsafe fn switch_to_kernel_stack() {
    asm!(
        "lea rsp, [rip + {stack} + {size}]",
        "and rsp, -16",
        stack = sym KERNEL_STACK,
        size = const KERNEL_STACK_SIZE,
        options(nostack),
    );
}

/// Mask all legacy PIC interrupts (master 0x21, slave 0xA1). The LAPIC is
/// the only interrupt source the kernel keeps.
///
/// # Safety
///
/// Concurrent/unexpected PIC usage is undefined; boot-time call only.
pub unsafe fn mask_pic() {
    asm!("out dx, al", in("dx") 0x21u16, in("al") 0xFFu8, options(nomem, preserves_flags));
    asm!("out dx, al", in("dx") 0xA1u16, in("al") 0xFFu8, options(nomem, preserves_flags));
}

static mut KERNEL_GDT: crate::gdt::Gdt = crate::gdt::Gdt::new();

/// Load the kernel GDT (and TSS).
///
/// # Safety
///
/// Single-threaded boot only; the static GDT must never move while loaded.
pub unsafe fn init_gdt() {
    let gdt = (&raw mut KERNEL_GDT).as_mut().unwrap();
    gdt.install();
    // Ring-3 -> ring-0 transitions (interrupts/syscalls from user tasks) use
    // TSS.RSP0 as the initial kernel stack. Point it at the kernel stack
    // top until the first preemptive switch installs the scheduled task's
    // own CPL0 stack.
    gdt.tss_mut().rsp0 = stack_top();
}

/// Point TSS.RSP0 at the CPL0 stack of the task about to run. Called by the
/// scheduler on every preemptive switch; the CPU reads RSP0 only when a
/// ring-3 context enters the kernel, so the value must track the running
/// task.
///
/// # Safety
///
/// Must run in interrupt context (switches happen with IF cleared); the
/// static GDT must be loaded and never moved.
pub unsafe fn set_tss_rsp0(top: u64) {
    (&raw mut KERNEL_GDT).as_mut().unwrap().tss_mut().rsp0 = top;
}

/// Diagnostic: the current TSS.RSP0 value (used by the exception printer
/// to report the kernel stack pointer in force when a fault fired).
/// Layout: `Gdt` = 8 GDT entries (64 bytes) then the packed `TssStruct`,
/// whose `rsp0` sits at offset 4 (reserved u32 first).
pub fn get_tss_rsp0() -> u64 {
    unsafe {
        (&raw const KERNEL_GDT)
            .byte_add(64 + 4)
            .cast::<u64>()
            .read()
    }
}

static mut KERNEL_IDT: crate::idt::Idt = crate::idt::Idt::new();

/// Load the kernel IDT: exception handlers for vectors 0-31, the LAPIC
/// timer gate at `TIMER_VECTOR`, and the DPL-3 syscall gate at `SYS_VECTOR`.
///
/// # Safety
///
/// Single-threaded boot only; the static IDT must never move while loaded.
pub unsafe fn init_idt() {
    let idt = (&raw mut KERNEL_IDT).as_mut().unwrap();
    crate::idt::install_exception_handlers(idt);
    idt.set_irq_handler(TIMER_VECTOR as usize, timer_stub as *const () as u64);
    idt.set_handler(
        crate::syscall::SYS_VECTOR as usize,
        crate::syscall::syscall_stub as *const () as u64,
        crate::gdt::KERNEL_CODE_SELECTOR,
        3,
    );
    idt.install();
}

static mut LAPIC_BASE: u64 = 0;

/// Local APIC base address from MSR 0x1B (masked to the 4 KB page).
fn lapic_base() -> u64 {
    let mut lo: u32;
    let mut hi: u32;
    unsafe {
        asm!("rdmsr", in("ecx") 0x1Bu32, out("eax") lo, out("edx") hi, options(nomem, preserves_flags));
    }
    (((hi as u64) << 32) | lo as u64) & 0xFFFF_F000
}

unsafe fn lapic_write(reg: u32, val: u32) {
    core::ptr::write_volatile((LAPIC_BASE + reg as u64) as *mut u32, val);
}

unsafe fn lapic_read(reg: u32) -> u32 {
    core::ptr::read_volatile((LAPIC_BASE + reg as u64) as *const u32)
}

/// Enable the local APIC and arm its periodic timer at `TIMER_VECTOR`.
/// Returns the APIC base address found via MSR 0x1B.
///
/// # Safety
///
/// Must be called after the IDT is installed (assembler stubs + EOI path
/// must be live), after the kernel page tables map the LAPIC page with 4 KB
/// pages (QEMU TCG cannot take MMIO writes through a 1 GB huge page), and
/// before `sti`.
pub unsafe fn init_lapic_timer() -> u64 {
    LAPIC_BASE = lapic_base();
    let svr = lapic_read(0xF0);
    lapic_write(0xF0, svr | 0x100); // software enable
    lapic_write(0x320, 0x2_0030); // LVT timer: periodic (bit 17), vector 0x30, unmasked
    lapic_write(0x3E0, 0x3); // divide configuration: 16
                             // Quantum length: initial count 0x40000 (~16 ms at the QEMU APIC bus).
                             // Long enough that the ring-3 IPC demo's server completes its endpoint
                             // setup + grant before the first preemption (TCG timing is bursty).
    lapic_write(0x380, 0x4_0000); // initial count
    LAPIC_BASE
}

/// Index of the interrupted RIP within an exception frame, given whether
/// the vector pushes an architectural error code. Stub layout: `push 0`,
/// then `rax rbx rcx rdx rsi rdi r8 r9 r10 r11`, then `sub rsp,8`; the
/// 12 qwords below `rdi` (the frame base) are: gap, r11..rax, error-slot.
/// The CPU-pushed interrupt frame begins at index 12.
pub const fn frame_rip_index(has_err: bool) -> usize {
    12 + has_err as usize
}

/// Index of the interrupted RSP within an exception frame.
pub const fn frame_rsp_index(has_err: bool) -> usize {
    15 + has_err as usize
}

/// Rust side of the exception stubs: print vector/err/RIP/RSP/CR2, then
/// halt. Never returns.
#[no_mangle]
pub(crate) extern "sysv64" fn exception_trap_rust(vector: u64, has_err: u64, frame: *const u64) {
    let raw = [
        unsafe { *frame.add(0) },
        unsafe { *frame.add(1) },
        unsafe { *frame.add(2) },
        unsafe { *frame.add(3) },
        unsafe { *frame.add(4) },
        unsafe { *frame.add(5) },
        unsafe { *frame.add(6) },
        unsafe { *frame.add(7) },
        unsafe { *frame.add(8) },
        unsafe { *frame.add(9) },
        unsafe { *frame.add(10) },
        unsafe { *frame.add(11) },
        unsafe { *frame.add(12) },
        unsafe { *frame.add(13) },
        unsafe { *frame.add(14) },
        unsafe { *frame.add(15) },
    ];
    let err = if has_err != 0 {
        unsafe { *frame.add(12) }
    } else {
        0
    };
    let rip = unsafe { *frame.add(frame_rip_index(has_err != 0)) };
    let rsp = unsafe { *frame.add(frame_rsp_index(has_err != 0)) };
    let mut cr2: u64 = 0;
    let mut cr3: u64 = 0;
    unsafe {
        asm!("mov {}, cr2", out(reg) cr2, options(nomem, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, preserves_flags));
    }

    // Page-fault-driven isolation: a ring-3 task faulted (U/S violation in
    // the isolation demo, or an NX violation in the NX demo). Kill the task
    // and let the kernel continue; the vector-14 stub resumes the scheduler.
    if vector == 0x0E {
        let cs = unsafe { *frame.add(frame_rip_index(has_err != 0) + 1) };
        if (cs & 3) == 3 {
            if err & (1 << 4) != 0 {
                crate::sprintln!(
                    "Aegis: NX violation: instruction fetch at CR2=0x{:016X} - non-executable page verified (task killed, kernel survives)",
                    cr2
                );
            } else {
                crate::sprintln!(
                    "Aegis: PAGE FAULT at CR2=0x{:016X} - memory isolation verified (task killed, kernel survives)",
                    cr2
                );
            }
            crate::tasks::kill_current();
            return;
        }
    }

    crate::sprintln!(
        "KERNEL EXCEPTION vector=0x{:02X} err=0x{:X} RIP=0x{:016X} RSP=0x{:016X} CR2=0x{:016X} CR3=0x{:016X}",
        vector,
        err,
        rip,
        rsp,
        cr2,
        cr3
    );
    crate::sprintln!(
        "frame ptr=0x{:016X} rsp0=0x{:016X} ticks={}",
        frame as u64,
        crate::cpu::get_tss_rsp0(),
        crate::cpu::timer_ticks()
    );
    crate::sprintln!(
        "frame: 0x{:016X} 0x{:016X} 0x{:016X} 0x{:016X}",
        raw[0],
        raw[1],
        raw[2],
        raw[3]
    );
    crate::sprintln!(
        "frame: 0x{:016X} 0x{:016X} 0x{:016X} 0x{:016X}",
        raw[4],
        raw[5],
        raw[6],
        raw[7]
    );
    crate::sprintln!(
        "frame: 0x{:016X} 0x{:016X} 0x{:016X} 0x{:016X}",
        raw[8],
        raw[9],
        raw[10],
        raw[11]
    );
    crate::sprintln!(
        "frame: 0x{:016X} 0x{:016X} 0x{:016X} 0x{:016X}",
        raw[12],
        raw[13],
        raw[14],
        raw[15]
    );

    if vector == 0x0E {
        crate::sprintln!("Aegis: KERNEL page fault at CR2=0x{:016X} - halting", cr2);
    }

    loop {
        unsafe { asm!("hlt", options(nomem, preserves_flags)) }
    }
}

/// Rust side of the LAPIC timer stub: count the tick and send the EOI.
#[no_mangle]
pub extern "sysv64" fn timer_trap_rust() {
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
    unsafe {
        lapic_write(0xB0, 0);
    }
}

/// Interrupt gate stub for the LAPIC timer: count the tick, send the EOI,
/// then preemptively switch to the next task (round-robin). When the
/// switch lands back here on a later tick, the pop/iretq tail resumes the
/// interrupted context.
#[unsafe(naked)]
#[no_mangle]
pub extern "sysv64" fn timer_stub() -> ! {
    naked_asm!(
        "cli",
        "push rax", "push rcx", "push rdx", "push rsi", "push rdi",
        "push r8", "push r9", "push r10", "push r11",
        "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
        "sub rsp, 8",
        "call {trap}",
        "call {preempt}",
        "add rsp, 8",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
        "iretq",
        trap = sym crate::cpu::timer_trap_rust,
        preempt = sym crate::tasks::timer_preempt,
    )
}

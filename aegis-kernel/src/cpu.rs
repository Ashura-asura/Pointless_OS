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
    (&raw mut KERNEL_GDT).as_mut().unwrap().install();
}

static mut KERNEL_IDT: crate::idt::Idt = crate::idt::Idt::new();

/// Load the kernel IDT: exception handlers for vectors 0-31 plus the LAPIC
/// timer gate at `TIMER_VECTOR`.
///
/// # Safety
///
/// Single-threaded boot only; the static IDT must never move while loaded.
pub unsafe fn init_idt() {
    let idt = (&raw mut KERNEL_IDT).as_mut().unwrap();
    crate::idt::install_exception_handlers(idt);
    idt.set_irq_handler(TIMER_VECTOR as usize, timer_stub as *const () as u64);
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
    lapic_write(0x380, 0x1_0000); // initial count
    LAPIC_BASE
}

/// Index of the interrupted RIP within an exception frame, given whether
/// the vector pushes an architectural error code.
pub const fn frame_rip_index(has_err: bool) -> usize {
    10 + has_err as usize
}

/// Index of the interrupted RSP within an exception frame.
pub const fn frame_rsp_index(has_err: bool) -> usize {
    13 + has_err as usize
}

/// Rust side of the exception stubs: print vector/err/RIP/RSP/CR2, then
/// halt. Never returns.
#[no_mangle]
pub(crate) extern "sysv64" fn exception_trap_rust(vector: u64, has_err: u64, frame: *const u64) {
    let err = if has_err != 0 {
        unsafe { *frame.add(10) }
    } else {
        0
    };
    let rip = unsafe { *frame.add(frame_rip_index(has_err != 0)) };
    let rsp = unsafe { *frame.add(frame_rsp_index(has_err != 0)) };
    let mut cr2: u64 = 0;
    unsafe {
        asm!("mov {}, cr2", out(reg) cr2, options(nomem, preserves_flags));
    }
    crate::sprintln!(
        "KERNEL EXCEPTION vector=0x{:02X} err=0x{:X} RIP=0x{:016X} RSP=0x{:016X} CR2=0x{:016X}",
        vector,
        err,
        rip,
        rsp,
        cr2
    );
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

/// Interrupt gate stub for the LAPIC timer.
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
        "add rsp, 8",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
        "iretq",
        trap = sym crate::cpu::timer_trap_rust,
    )
}

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

const KERNEL_STACK_SIZE: usize = 65536;

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

/// Size of the dedicated kernel stack, in bytes.
pub const fn stack_size() -> usize {
    KERNEL_STACK_SIZE
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

/// Switch the CPU onto the kernel's own stack and jump to a never-returning
/// `entry`.
///
/// This *jumps* (never returns) so the compiler's frame-pointer-relative
/// addressing in everything that runs from the kernel stack stays below the
/// stack top. A plain in-function `mov rsp, ...` leaves the C prologue's
/// `%rsp`-relative slots pointing ABOVE the new stack top, spilling into
/// whatever BSS statics the linker happened to place just above the stack —
/// which is exactly how the syscall gate disappeared (whole-IDT-zeroed +
/// #GP/double-fault on the first ring-3 `int 0x80`) whenever code-size
/// shifts placed KERNEL_IDT / vga state directly above KERNEL_STACK.
///
/// # Safety
///
/// Must be the very first thing `_start` does. The old (loader-provided)
/// stack is abandoned; `entry` must never return.
pub unsafe fn switch_to_kernel_stack_and_jump(entry: extern "sysv64" fn(u64) -> !, arg: u64) -> ! {
    asm!(
        "lea rsp, [rip + {stack} + {size}]",
        "and rsp, -16",
        "mov rax, {entry}",
        "jmp rax",
        stack = sym KERNEL_STACK,
        size = const KERNEL_STACK_SIZE,
        entry = in(reg) entry,
        in("rdi") arg,
        options(noreturn),
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

/// Remap the legacy PICs (master base 0x20, slave base 0x28), unmask IRQ1
/// (keyboard) on the master, and configure LAPIC LVT0 for ExtINT delivery so
/// the software-enabled LAPIC passes the PIC's INTR through (virtual-wire
/// mode). The LAPIC timer remains the only tick source: IRQ0 and the slave
/// stay masked.
///
/// # Safety
///
/// Must run after `init_lapic_timer` (so LAPIC_BASE is known and the LAPIC is
/// software-enabled) and after `init_idt` (the IRQ1 gate must be live).
/// Boot-time, single-threaded.
pub unsafe fn init_legacy_pic_irq1() {
    // Master 8259A: ICW1-4. Vector base 0x20 so IRQ1 -> 0x21.
    asm!("out dx, al", in("dx") 0x20u16, in("al") 0x11u8, options(nomem, preserves_flags)); // ICW1: init, edge, cascade
    asm!("out dx, al", in("dx") 0x21u16, in("al") 0x20u8, options(nomem, preserves_flags)); // ICW2: base vector 0x20
    asm!("out dx, al", in("dx") 0x21u16, in("al") 0x04u8, options(nomem, preserves_flags)); // ICW3: slave on IR2
    asm!("out dx, al", in("dx") 0x21u16, in("al") 0x01u8, options(nomem, preserves_flags)); // ICW4: 8086 mode
                                                                                            // Slave 8259A: remapped for correctness, kept fully masked.
    asm!("out dx, al", in("dx") 0xA0u16, in("al") 0x11u8, options(nomem, preserves_flags));
    asm!("out dx, al", in("dx") 0xA1u16, in("al") 0x28u8, options(nomem, preserves_flags));
    asm!("out dx, al", in("dx") 0xA1u16, in("al") 0x02u8, options(nomem, preserves_flags));
    asm!("out dx, al", in("dx") 0xA1u16, in("al") 0x01u8, options(nomem, preserves_flags));
    // IMR: master = 0xFD (all masked except IRQ1), slave fully masked.
    asm!("out dx, al", in("dx") 0x21u16, in("al") 0xFDu8, options(nomem, preserves_flags));
    asm!("out dx, al", in("dx") 0xA1u16, in("al") 0xFFu8, options(nomem, preserves_flags));
    // LVT0 (0x350): delivery mode ExtINT (bits 10:8 = 111), unmasked.
    let lvt0 = lapic_read(0x350);
    lapic_write(0x350, (lvt0 | 0x700) & !0x1_0000);
}

/// Unmask IRQ12 (PS/2 mouse) on the slave 8259A: IRQ12 maps to vector
/// 0x2C (slave base 0x28 plus 4) and arrives through the IRQ2 cascade,
/// which is unmasked on the master here too. Everything else on both PICs
/// stays masked; the LAPIC timer remains the only tick source.
///
/// # Safety
///
/// Must run after `init_legacy_pic_irq1` (the PICs are already remapped
/// there, with the slave fully masked) and after `init_idt` (the 0x2C gate
/// must be live). Boot-time, single-threaded.
pub unsafe fn init_legacy_pic_irq12() {
    // Master IMR: 0xF9 = 1111 1001 — IRQ2 (the slave cascade) unmasked, all
    // else (including IRQ1) masked. Slave IMR: 0xEF = 1110 1111 — IRQ12
    // unmasked, all else masked.
    asm!("out dx, al", in("dx") 0x21u16, in("al") 0xF9u8, options(nomem, preserves_flags));
    asm!("out dx, al", in("dx") 0xA1u16, in("al") 0xEFu8, options(nomem, preserves_flags));
}

/// I/O APIC register window (physical address). Identity-mapped in the
/// kernel page tables — GB3 (0xC0000000–0xFFFFFFFF) covers 0xFEC00000. Zero
/// until `init_ioapic` records the MADT address.
static mut IOAPIC_BASE: u64 = 0;

/// Record the I/O APIC's MMIO base for later redirection-entry programming.
///
/// # Safety
/// Boot-only; called once during device interrupt setup.
pub unsafe fn init_ioapic(base: u64) {
    IOAPIC_BASE = base;
}

/// Indirect I/O APIC access: write the register index to IOREGSEL (+0x00),
/// then read/write the data at IOWIN (+0x10). All registers are 32-bit.
unsafe fn ioapic_write(reg: u32, val: u32) {
    let base = IOAPIC_BASE as *mut u32;
    core::ptr::write_volatile(base.add(0), reg);
    core::ptr::write_volatile(base.add(0x10 / 4), val);
}

unsafe fn ioapic_read(reg: u32) -> u32 {
    let base = IOAPIC_BASE as *mut u32;
    core::ptr::write_volatile(base.add(0), reg);
    core::ptr::read_volatile(base.add(0x10 / 4))
}

/// Route one global system interrupt (GSI) to `vector` on the BSP's LAPIC.
/// Preserves the firmware-chosen polarity/trigger (bits 10–11 of the low
/// dword) so the wiring matches the hardware; forces fixed delivery (bits
/// 8–9 = 0) and un-masks the entry (bit 12 = 0).
///
/// # Safety
/// Boot-only; called once during device interrupt setup.
unsafe fn route_ioapic_gsi(gsi: u8, vector: u8, lapic_id: u8) {
    if IOAPIC_BASE == 0 {
        return;
    }
    let low = ioapic_read(0x10 + 2 * gsi as u32);
    let polarity_trigger = low & 0x0C00; // bits 10 (polarity), 11 (trigger)
    let new_low = (vector as u32) | polarity_trigger; // fixed delivery, unmasked
    ioapic_write(0x10 + 2 * gsi as u32, new_low);
    // Physical destination = the 8-bit LAPIC ID (low byte of the x2APIC ID).
    let new_high = (lapic_id as u32) << 24;
    ioapic_write(0x11 + 2 * gsi as u32, new_high);
}

/// Paint a solid `w`x`h` rectangle at (`x`,`y`); used for boot-time liveness
/// indicators that must survive the desktop's full-frame repaint.
///
/// # Safety
/// Framebuffer must be initialised (`init_diag_fb`).
pub unsafe fn diag_fill(x: usize, y: usize, w: usize, h: usize, r: u8, g: u8, b: u8) {
    if DIAG_FB == 0 {
        return;
    }
    let fb = DIAG_FB as *mut u8;
    let stride = DIAG_STRIDE as usize;
    for dy in 0..h {
        for dx in 0..w {
            let off = (((y + dy) * stride) + (x + dx)) * 4;
            core::ptr::write_volatile(fb.add(off), b);
            core::ptr::write_volatile(fb.add(off + 1), g);
            core::ptr::write_volatile(fb.add(off + 2), r);
        }
    }
}

/// Minimal 3x5 hex glyphs (one u8 per row, low 3 bits = pixels), so a fault
/// on the TP201S (whose display shows only direct framebuffer writes) can
/// print vector/CR2/RIP without any console/font.
const HEX_FONT: [[u8; 5]; 16] = [
    [0b111, 0b101, 0b101, 0b101, 0b111], // 0
    [0b010, 0b110, 0b010, 0b010, 0b111], // 1
    [0b111, 0b001, 0b111, 0b100, 0b111], // 2
    [0b111, 0b001, 0b111, 0b001, 0b111], // 3
    [0b101, 0b101, 0b111, 0b001, 0b001], // 4
    [0b111, 0b100, 0b111, 0b001, 0b111], // 5
    [0b111, 0b100, 0b111, 0b101, 0b111], // 6
    [0b111, 0b001, 0b001, 0b010, 0b010], // 7
    [0b111, 0b101, 0b111, 0b101, 0b111], // 8
    [0b111, 0b101, 0b111, 0b001, 0b111], // 9
    [0b111, 0b101, 0b111, 0b101, 0b101], // A
    [0b110, 0b101, 0b110, 0b101, 0b110], // B
    [0b111, 0b100, 0b100, 0b100, 0b111], // C
    [0b110, 0b101, 0b101, 0b101, 0b110], // D
    [0b111, 0b100, 0b111, 0b100, 0b111], // E
    [0b111, 0b100, 0b111, 0b100, 0b100], // F
];

/// Draw the low `n` hex digits of `val` to the framebuffer starting at
/// column `x` (pixels), row `y`, scaled by `scale` pixels per font bit.
/// Uses the framebuffer base/stride recorded by `init_diag_fb`.
///
/// # Safety
/// Requires `init_diag_fb` to have run (guarded internally).
pub unsafe fn fb_hex(x: usize, y: usize, val: u64, n: usize, scale: usize, r: u8, g: u8, b: u8) {
    if DIAG_FB == 0 {
        return;
    }
    let fb = DIAG_FB as *mut u8;
    let stride = DIAG_STRIDE as usize;
    for i in 0..n {
        let digit = ((val >> ((n - 1 - i) * 4)) & 0xF) as usize;
        let glyph = HEX_FONT[digit];
        let ox = x + i * (3 * scale + scale);
        for row in 0..5 {
            let bits = glyph[row];
            for col in 0..3 {
                if bits & (1 << (2 - col)) != 0 {
                    for sy in 0..scale {
                        for sx in 0..scale {
                            let px = ox + col * scale + sx;
                            let py = y + row * scale + sy;
                            let off = (py * stride + px) * 4;
                            core::ptr::write_volatile(fb.add(off), b);
                            core::ptr::write_volatile(fb.add(off + 1), g);
                            core::ptr::write_volatile(fb.add(off + 2), r);
                        }
                    }
                }
            }
        }
    }
}

/// Program the I/O APIC (parsed from the MADT; fallback 0xFEC00000) to deliver
/// the PS/2 keyboard (IRQ1) and mouse (IRQ12) to the BSP via the kernel's
/// fixed vectors. This is the "CPU selection" for those interrupts: the
/// redirection entry's destination field now points at the BSP LAPIC instead
/// of whatever the firmware left. MADT IRQ overrides are honoured when mapping
/// a source IRQ to a GSI.
///
/// # Safety
/// Boot-only; call after `init_idt` and `init_lapic_timer`.
pub unsafe fn init_ioapic_legacy() {
    let base = match crate::acpi::discovered().and_then(|d| d.smp.ioapic) {
        Some(io) => io.address as u64,
        None => 0xFEC0_0000,
    };
    init_ioapic(base);
    // BSP LAPIC ID. In x2APIC the 32-bit ID's relevant 8 bits for I/O APIC
    // physical destination are the LOW byte (not the high byte).
    let bsp = (lapic_read(0x20) & 0xFF) as u8;

    // Build a source-IRQ -> GSI map from MADT overrides (identity if absent).
    let mut ov_src = [0u8; 8];
    let mut ov_gsi = [0u32; 8];
    let mut on = 0usize;
    if let Some(m) = crate::acpi::discovered().and_then(|d| d.madt) {
        on = m.override_count.min(8);
        for i in 0..on {
            ov_src[i] = m.overrides[i].source;
            ov_gsi[i] = m.overrides[i].global_interrupt;
        }
    }
    let gsi_for = |src: u8| -> u8 {
        for i in 0..on {
            if ov_src[i] == src {
                return ov_gsi[i] as u8;
            }
        }
        src
    };

    route_ioapic_gsi(gsi_for(1), crate::ps2::KEYBOARD_VECTOR, bsp);
    route_ioapic_gsi(gsi_for(12), crate::ps2_mouse::MOUSE_VECTOR, bsp);

    // Boot latch: read back IRQ1's redirection entry and confirm the I/O APIC
    // accepted our routing (vector=KEYBOARD_VECTOR, unmasked, dest=BSP).
    let g = gsi_for(1) as u32;
    let low = ioapic_read(0x10 + 2 * g);
    let high = ioapic_read(0x11 + 2 * g);
    let ok = (low & 0xFF) == crate::ps2::KEYBOARD_VECTOR as u32
        && (low & 0x1000) == 0
        && (high >> 24) == bsp as u32;
    set_ioapic_ok(ok);
}

/// EOI an I/O APIC interrupt (write to the I/O APIC EOI register). Harmless
/// when the I/O APIC is not the active controller; pair with the PIC EOI.
///
/// # Safety
/// Call only from an interrupt context delivered by the I/O APIC.
pub unsafe fn ioapic_eoi() {
    if IOAPIC_BASE != 0 {
        let base = IOAPIC_BASE as *mut u32;
        core::ptr::write_volatile(base.add(0x40 / 4), 0);
    }
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

/// Physical address of the loaded IDT. The IDT is NOT a linker-placed BSS
/// static: the linker freely reorders BSS symbols when code size changes, and
/// in some layouts the IDT landed immediately above the kernel stack top,
/// where a boot-time writer zeroed it and the first ring-3 `int 0x80`
/// faulted. Allocating a dedicated frame instead pins the IDT to allocator
/// memory that no other structure touches. Zero until `init_idt` runs.
static mut IDT_FRAME: u64 = 0;

/// Load the kernel IDT: exception handlers for vectors 0-31, the LAPIC
/// timer gate at `TIMER_VECTOR`, and the DPL-3 syscall gate at `SYS_VECTOR`.
///
/// The IDT lives in a frame allocated from the kernel's frame allocator
/// (never in BSS), so its address is page-aligned and stable across builds.
///
/// # Safety
///
/// Single-threaded boot only, after `frame::init_global`; the allocated
/// frame must never be freed while the IDT is loaded.
pub unsafe fn init_idt() {
    let Some(frame) = crate::frame::alloc_global() else {
        crate::sprintln!("Aegis: FATAL could not allocate IDT frame");
        loop {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    };
    IDT_FRAME = frame;
    let idt = &mut *(frame as *mut crate::idt::Idt);
    core::ptr::write(idt, crate::idt::Idt::new());
    crate::idt::install_exception_handlers(idt);
    idt.set_irq_handler(TIMER_VECTOR as usize, timer_stub as *const () as u64);
    idt.set_irq_handler(
        crate::ps2::KEYBOARD_VECTOR as usize,
        crate::ps2::keyboard_stub as *const () as u64,
    );
    idt.set_irq_handler(
        crate::ps2_mouse::MOUSE_VECTOR as usize,
        crate::ps2_mouse::mouse_stub as *const () as u64,
    );
    idt.set_handler(
        crate::syscall::SYS_VECTOR as usize,
        crate::syscall::syscall_stub as *const () as u64,
        crate::gdt::KERNEL_CODE_SELECTOR,
        3,
    );
    idt.install();
}

static mut LAPIC_BASE: u64 = 0;

/// Whether the local APIC is being driven via the x2APIC MSR interface
/// (`true`) or the legacy xAPIC MMIO window (`false`). On many real machines
/// the firmware enables x2APIC and the mode *cannot* be disabled in software
/// without a reset, so any MMIO `lapic_write` is a silent no-op there — which
/// is exactly why the timer (and therefore the scheduler) never armed. When
/// this is `true` we translate every register access to its x2APIC MSR
/// (0x800 + reg>>4) instead of touching the MMIO page.
static mut LAPIC_X2: bool = false;

// Framebuffer handle for the timer-ISR "alive" indicator (see `init_diag_fb`
// and `timer_trap_rust`). Lets us prove on real hardware whether the LAPIC
// timer ISR actually fires without needing serial capture.
static mut DIAG_FB: u64 = 0;
static mut DIAG_STRIDE: u32 = 0;
static mut DIAG_W: u32 = 0;
static mut DIAG_H: u32 = 0;

/// Hand the timer ISR the framebuffer so it can paint a persistent "timer
/// alive" block. Called once at boot from the GOP handoff.
///
/// # Safety
///
/// Must be called exactly once at boot (before any timer interrupt paints)
/// with `base` equal to the identity-mapped framebuffer address from the
/// GOP handoff.
pub unsafe fn init_diag_fb(base: u64, stride: u32, w: u32, h: u32) {
    DIAG_FB = base;
    DIAG_STRIDE = stride;
    DIAG_W = w;
    DIAG_H = h;
}

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
    if LAPIC_X2 {
        // x2APIC register `reg` lives at MSR 0x800 + (reg >> 4); the full
        // 32-bit value is the low dword of the MSR.
        let msr = 0x800u32 + (reg >> 4);
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") val,
            in("edx") 0u32,
            options(nomem, preserves_flags)
        );
    } else {
        core::ptr::write_volatile((LAPIC_BASE + reg as u64) as *mut u32, val);
    }
}

unsafe fn lapic_read(reg: u32) -> u32 {
    if LAPIC_X2 {
        let msr = 0x800u32 + (reg >> 4);
        let mut lo: u32;
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") _,
            options(nomem, preserves_flags)
        );
        lo
    } else {
        core::ptr::read_volatile((LAPIC_BASE + reg as u64) as *const u32)
    }
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
    // The firmware (we skipped ExitBootServices on the TP201S because it
    // hangs) may have left the local APIC in x2APIC mode (MSR 0x1B bit 10).
    // This file programs the LAPIC via MMIO, which is DISABLED under x2APIC,
    // so every `lapic_read`/`lapic_write` below would be a silent no-op and
    // the timer would never arm (no scheduler -> no input, no blink). Drop
    // back to xAPIC (MMIO) mode first; the switch x2APIC -> xAPIC is allowed
    // by clearing the EXTD bit.
    let mut lo: u32;
    let mut hi: u32;
    asm!("rdmsr", in("ecx") 0x1Bu32, out("eax") lo, out("edx") hi, options(nomem, preserves_flags));
    if lo & (1u32 << 10) != 0 {
        let disabled = lo & !(1u32 << 10);
        asm!("wrmsr", in("ecx") 0x1Bu32, in("eax") disabled, in("edx") hi, options(nomem, preserves_flags));
        // Re-read: x2APIC frequently cannot be turned off in software (no
        // reset), so the firmware's enable bit may simply ignore our write.
        // If it's still set, MMIO is dead and we must use the x2APIC MSR
        // interface for every register access.
        let mut lo2: u32;
        let mut _hi2: u32;
        asm!("rdmsr", in("ecx") 0x1Bu32, out("eax") lo2, out("edx") _hi2, options(nomem, preserves_flags));
        if lo2 & (1u32 << 10) != 0 {
            LAPIC_X2 = true;
        }
    }
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

/// Signal end-of-interrupt to the local APIC (write 0 to the EOI register),
/// clearing the in-service latch so the next interrupt can be delivered.
/// The VMX run loop calls this after an external-interrupt VM-exit
/// (EXT_INT_EXITING) before re-entering the guest.
///
/// # Safety
/// Requires the local APIC to be enabled with `LAPIC_BASE` set
/// (`init_lapic_timer` runs before this can ever be called).
pub unsafe fn lapic_eoi() {
    lapic_write(0xB0, 0);
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
            // Phase 2 supervision hook: a supervised, budgeted task is
            // restarted by the kernel-resident supervisor instead of left
            // dead; unsupervised tasks keep the existing kill-and-continue
            // behavior.
            let cur = crate::tasks::current_idx();
            if crate::supervisor::handle_fault(cur) {
                return;
            }
            crate::tasks::kill_current();
            // Phase 5 supervision tree: the fault-kill also parks the death
            // on the reserved notification endpoint, so a ring-3 supervisor
            // task (policy out of the kernel) can observe the TaskKill and
            // apply its own bounded-restart / escalation policy.
            let reason = if err & (1 << 4) != 0 {
                crate::ipc::REASON_NX
            } else {
                crate::ipc::REASON_PF_ISOLATION
            };
            crate::ipc::notify_task_kill(cur, reason);
            return;
        }
    }

    // Paint the fault to the framebuffer FIRST — before any serial I/O that
    // could itself stall. The TP201S displays only direct framebuffer writes,
    // so this is the one readable fault dump. A full-width red banner plus
    // three rows of hex at the top-left: VECTOR, CR2, RIP.
    unsafe {
        if DIAG_W > 0 {
            diag_fill(0, 0, DIAG_W as usize, 64, 0xFF, 0x00, 0x00);
        }
        fb_hex(8, 8, vector, 2, 3, 0xFF, 0xFF, 0xFF); // vector (white on red)
        fb_hex(8, 24, cr2, 16, 3, 0xFF, 0xFF, 0x00); // CR2 (yellow)
        fb_hex(8, 40, rip, 16, 3, 0xFF, 0x80, 0x00); // RIP (orange)
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

/// Set when the keyboard ISR has fired at least once (latch, not cleared).
/// The timer ISR repaints the red block every tick so it survives the
/// desktop's full-frame repaint, proving the keyboard vector reached the CPU.
static mut KEY_FIRED: bool = false;
/// Same latch for the mouse IRQ12 ISR (green block).
static mut MOUSE_FIRED: bool = false;
/// Latch set when the PS/2 controller probe responds (true) or not (false).
/// Repainted every tick so the user can tell PS/2 vs USB input at a glance.
static mut PS2_PRESENT: bool = false;
/// Latch set when the I/O APIC IRQ1 redirection entry verified as accepted.
static mut IOAPIC_OK: bool = false;

/// Latch that the keyboard vector fired (called from `keyboard_trap_rust`).
///
/// # Safety
/// Called only from the keyboard interrupt context.
pub unsafe fn mark_key_fired() {
    KEY_FIRED = true;
}

/// Latch that the mouse vector fired (called from `mouse_trap_rust`).
///
/// # Safety
/// Called only from the mouse interrupt context.
pub unsafe fn mark_mouse_fired() {
    MOUSE_FIRED = true;
}

/// Record whether a PS/2 controller responded to the probe.
///
/// # Safety
/// Boot-time call.
pub unsafe fn set_ps2_present(v: bool) {
    PS2_PRESENT = v;
}

/// Record whether the I/O APIC IRQ1 routing verified as accepted.
///
/// # Safety
/// Boot-time call.
pub unsafe fn set_ioapic_ok(v: bool) {
    IOAPIC_OK = v;
}

/// True if a PS/2 controller responded to the probe.
///
/// # Safety
/// Read after boot init.
pub unsafe fn ps2_present() -> bool {
    PS2_PRESENT
}

/// True if the I/O APIC IRQ1 routing verified as accepted.
///
/// # Safety
/// Read after boot init.
pub unsafe fn ioapic_ok() -> bool {
    IOAPIC_OK
}

/// True once the keyboard ISR has fired.
///
/// # Safety
/// Read after boot init.
pub unsafe fn key_fired() -> bool {
    KEY_FIRED
}

/// True once the mouse ISR has fired.
///
/// # Safety
/// Read after boot init.
pub unsafe fn mouse_fired() -> bool {
    MOUSE_FIRED
}

/// Set when an XHCI (USB) host controller is discovered.
static mut USB_XHCI_FOUND: bool = false;

/// Record whether an XHCI host controller was found.
///
/// # Safety
/// Boot-time call.
pub unsafe fn set_usb_xhci_found(v: bool) {
    USB_XHCI_FOUND = v;
}

/// True if an XHCI host controller was discovered.
///
/// # Safety
/// Read after boot init.
pub unsafe fn usb_xhci_found() -> bool {
    USB_XHCI_FOUND
}

static mut USB_EHCI_FOUND: bool = false;

/// Record whether an EHCI (USB-2.0) host controller was discovered.
///
/// # Safety
/// Boot-time call.
pub unsafe fn set_usb_ehci_found(v: bool) {
    USB_EHCI_FOUND = v;
}

/// True if an EHCI host controller was discovered.
///
/// # Safety
/// Read after boot init.
pub unsafe fn usb_ehci_found() -> bool {
    USB_EHCI_FOUND
}

// ---- USB-HID pipeline diagnostics (surfaced on the on-screen status line) ----
// These let us see *where* the input pipeline breaks on real hardware that has
// no serial output: did enumeration find boot HID devices? were any HID
// interfaces present at all (vs. none / EHCI / hub)? do transfer completions
// arrive, and do they decode+inject?
static mut HID_ENUM_COUNT: usize = 0; // boot-HID devices armed for polling
static mut HID_ANY_SEEN: bool = false; // any HID-class interface seen at all
static mut HID_POLL_EVENTS: u64 = 0; // transfer events drained in poll_hid
static mut HID_CC_FAIL: u64 = 0; // of those, completion code != success
static mut HID_INJECTED: u64 = 0; // reports handed to the PS/2 ring

// ---- xHCI enumeration diagnostics (why did `enumerate_hid_devices` find 0?) ----
static mut XHCI_PORTS: usize = 0; // HCSPARAMS1 max ports
static mut XHCI_CONN: usize = 0; // root ports reporting Connect Status
static mut XHCI_DEV: bool = false; // a device descriptor was successfully read
static mut XHCI_DEV_CLS: u8 = 0; // device/interface class of first device read
static mut XHCI_HUB: bool = false; // a hub (class 9) was seen on a root port
static mut XHCI_PP: usize = 0; // ports we explicitly powered on (PP set)
static mut XHCI_PHASE: u8 = 0; // furthest enumeration phase reached (1..11)
static mut XHCI_NSLOT: u16 = 0; // enable_slot command successes
static mut XHCI_NADDR: u16 = 0; // address_device(BSR) command successes
static mut XHCI_NCMD: u16 = 0; // command-completion events received
static mut XHCI_NTR: u16 = 0; // control transfers attempted
static mut XHCI_NTO: u16 = 0; // control transfers that timed out (no event)
static mut XHCI_LAST_CC: u8 = 0; // completion code of the last command-completion event
static mut XHCI_CC_FAIL: u16 = 0; // command completions with a non-success code
static mut XHCI_CC_SUCCESS: u16 = 0; // command completions with CC=2 (Success)
static mut XHCI_NATT: u16 = 0; // command TRBs posted (attempts)
static mut XHCI_NEVT: u16 = 0; // total event TRBs observed on the event ring
static mut XHCI_CSTS: u32 = 0; // USBSTS snapshot after Run was requested
static mut XHCI_CRCR_LO: u32 = 0; // CRCR low DWORD readback after init
static mut XHCI_CRCR_HI: u32 = 0; // CRCR high DWORD readback after init
static mut XHCI_CRCR_WLO: u32 = 0; // CRCR low DWORD readback right after write (halted)
static mut XHCI_CRCR_WHI: u32 = 0; // CRCR high DWORD readback right after write (halted)
static mut XHCI_CMD_RING: u64 = 0; // command-ring physical address we wrote
static mut XHCI_LEGACY: u32 = 0; // USB Legacy Support cap register value (post-handoff)
static mut XHCI_LEGACY_ST: u8 = 0; // 0=no xECP 1=no legcap 2=already-OS 3=handed 4=forced
static mut XHCI_CAPLEN: u32 = 0; // CAPLENGTH (operational register base offset)
static mut XHCI_CRCR_PRE_LO: u32 = 0; // CRCR low read back immediately BEFORE our write
static mut XHCI_CRCR_PRE_HI: u32 = 0; // CRCR high read back immediately BEFORE our write
static mut XHCI_HCH0: u8 = 0; // 1 if Halted was observed after clearing Run
static mut XHCI_HRST: u8 = 0; // 1 if HCRST bit was observed set after writing it
static mut XHCI_USBSTS_PRE: u32 = 0; // raw USBSTS read immediately before the CRCR write
static mut XHCI_USBSTS_POST: u32 = 0; // raw USBSTS read after Run was requested
static mut XHCI_BAR: u64 = 0; // physical address of the xHCI MMIO BAR (for diag)

/// # Safety
/// Boot-time call from the USB-HID driver.
pub unsafe fn set_hid_enum_count(n: usize) {
    HID_ENUM_COUNT = n;
}
/// # Safety
/// Boot-time call from the USB-HID driver.
pub unsafe fn set_hid_any_seen(v: bool) {
    HID_ANY_SEEN = v;
}
/// # Safety
/// Called from the USB-HID driver's poll path.
pub unsafe fn inc_hid_poll_event() {
    HID_POLL_EVENTS += 1;
}
/// # Safety
/// Called from the USB-HID driver's poll path.
pub unsafe fn inc_hid_cc_fail() {
    HID_CC_FAIL += 1;
}
/// # Safety
/// Called from the USB-HID driver's report handler.
pub unsafe fn inc_hid_injected() {
    HID_INJECTED += 1;
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn hid_enum_count() -> usize {
    HID_ENUM_COUNT
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn hid_any_seen() -> bool {
    HID_ANY_SEEN
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn hid_poll_events() -> u64 {
    HID_POLL_EVENTS
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn hid_cc_fail() -> u64 {
    HID_CC_FAIL
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn hid_injected() -> u64 {
    HID_INJECTED
}

/// # Safety
/// Set from the USB-HID xHCI driver during enumeration.
pub unsafe fn set_xhci_ports(n: usize) {
    XHCI_PORTS = n;
}
/// # Safety
/// Set from the USB-HID xHCI driver during enumeration.
pub unsafe fn set_xhci_conn(n: usize) {
    XHCI_CONN = n;
}
/// # Safety
/// Set from the USB-HID xHCI driver during enumeration.
pub unsafe fn set_xhci_dev(v: bool) {
    XHCI_DEV = v;
}
/// # Safety
/// Set from the USB-HID xHCI driver during enumeration.
pub unsafe fn set_xhci_dev_cls(c: u8) {
    XHCI_DEV_CLS = c;
}
/// # Safety
/// Set from the USB-HID xHCI driver during enumeration.
pub unsafe fn set_xhci_hub(v: bool) {
    XHCI_HUB = v;
}
/// # Safety
/// Set from the USB-HID xHCI driver during enumeration.
pub unsafe fn set_xhci_pp(n: usize) {
    XHCI_PP = n;
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_ports() -> usize {
    XHCI_PORTS
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_conn() -> usize {
    XHCI_CONN
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_dev() -> bool {
    XHCI_DEV
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_dev_cls() -> u8 {
    XHCI_DEV_CLS
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_hub() -> bool {
    XHCI_HUB
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_pp() -> usize {
    XHCI_PP
}
/// # Safety
/// Set from the USB-HID xHCI driver during enumeration.
pub unsafe fn set_xhci_phase(p: u8) {
    if p > XHCI_PHASE {
        XHCI_PHASE = p;
    }
    diag_phase_block(p);
    // Also paint a big solid block in the centre whose colour encodes the
    // phase (same palette as the bottom strip), so it is easy to read even
    // when the desktop never renders.
    let (r, g, b) = PHASE_COLOR(p);
    diag_fill((DIAG_W as usize).saturating_sub(160) / 2, (DIAG_H as usize).saturating_sub(160) / 2, 160, 160, r, g, b);
}

/// Phase -> colour, shared by `diag_phase_block` (bottom strip) and the
/// centred phase indicator.
const fn PHASE_COLOR(phase: u8) -> (u8, u8, u8) {
    const PALETTE: [(u8, u8, u8); 16] = [
        (0xFF, 0x00, 0x00), // 1  red
        (0xFF, 0xFF, 0xFF), // 2  white
        (0x00, 0x00, 0xFF), // 3  blue
        (0xFF, 0xFF, 0x00), // 4  yellow
        (0x00, 0xFF, 0x00), // 5  green
        (0xFF, 0x00, 0xFF), // 6  magenta
        (0x00, 0xFF, 0xFF), // 7  cyan
        (0xFF, 0x80, 0x00), // 8  orange
        (0x80, 0x00, 0x80), // 9  purple
        (0xFF, 0x80, 0x80), // 10 salmon
        (0x80, 0xFF, 0x00), // 11 lime
        (0x00, 0x80, 0x80), // 12 teal
        (0xFF, 0xFF, 0x80), // 13 light yellow
        (0x80, 0x80, 0x80), // 14 grey
        (0x80, 0xFF, 0xFF), // 15 light cyan
        (0xFF, 0xC0, 0x00), // 16 dark orange
    ];
    let idx = if (phase as usize) > 15 { 15 } else { phase as usize };
    PALETTE[idx]
}

/// Paint `val`'s hex digits huge (scale 12, ~36 px tall) centred near the
/// top of the framebuffer. Used to make the xHCI phase / command-completion
/// counters readable on the TP201S without the desktop shell.
///
/// # Safety
/// Requires `init_diag_fb` to have run (guarded internally).
pub unsafe fn diag_center_hex(val: u64, scale: usize, r: u8, g: u8, b: u8) {
    if DIAG_FB == 0 {
        return;
    }
    let n = if val > 0xFF { 8 } else if val > 0xF { 2 } else { 1 };
    let wpx = n * (3 * scale + scale);
    let x = (DIAG_W as usize).saturating_sub(wpx) / 2;
    let y = (DIAG_H as usize).saturating_sub(30) / 2;
    fb_hex(x, y, val, n, scale, r, g, b);
}
/// # Safety
/// Called from the USB-HID xHCI driver on a successful enable_slot.
pub unsafe fn inc_xhci_nslot() {
    XHCI_NSLOT += 1;
}
/// # Safety
/// Called from the USB-HID xHCI driver on a successful BSR address.
pub unsafe fn inc_xhci_naddr() {
    XHCI_NADDR += 1;
}
/// # Safety
/// Called from the USB-HID xHCI driver when a command-completion event arrives.
pub unsafe fn inc_xhci_ncmd() {
    XHCI_NCMD += 1;
    // Paint the running command-completion count below the centre phase
    // number, so we can see events arrive even without the shell.
    diag_center_hex(XHCI_NCMD as u64, 8, 0xFF, 0xFF, 0x00);
}
/// # Safety
/// Called from the USB-HID xHCI driver when a command TRB is posted.
pub unsafe fn inc_xhci_natt() {
    XHCI_NATT += 1;
}
/// # Safety
/// Called from the USB-HID xHCI driver whenever an event TRB is observed on
/// the event ring (any type) — distinguishes "controller posts no events at
/// all" from "posts events but not command completions".
pub unsafe fn inc_xhci_nevt() {
    XHCI_NEVT += 1;
}
/// # Safety
/// Snapshot USBSTS after Run was requested (to confirm the controller is
/// actually running: HCH bit 0 clear, CNR bit 1 clear).
pub unsafe fn set_xhci_csts(v: u32) {
    XHCI_CSTS = v;
}
/// # Safety
/// Snapshot the CRCR readback after init (to confirm our 64-bit command-ring
/// pointer actually landed).
pub unsafe fn set_xhci_crcr(lo: u32, hi: u32) {
    XHCI_CRCR_LO = lo;
    XHCI_CRCR_HI = hi;
}
/// # Safety
/// Snapshot the CRCR readback taken immediately after the write, while the
/// controller is still Halted (before Run) — proves whether the write itself
/// landed vs. the controller ignoring it.
pub unsafe fn set_xhci_crcr_w(lo: u32, hi: u32) {
    XHCI_CRCR_WLO = lo;
    XHCI_CRCR_WHI = hi;
}
/// # Safety
/// Record the command-ring physical address we intended to program.
pub unsafe fn set_xhci_cmd_ring(v: u64) {
    XHCI_CMD_RING = v;
}
/// # Safety
/// Record the USB Legacy Support capability register value and handoff outcome
/// (0=no xECP list, 1=no legacy cap, 2=already OS-owned, 3=handed off ok,
/// 4=forced). Lets the on-screen diagnostic show whether the OS actually owns
/// the controller — if BIOS still owns it, CRCR/operational writes are dropped.
pub unsafe fn set_xhci_legacy(v: u32, st: u8) {
    XHCI_LEGACY = v;
    XHCI_LEGACY_ST = st;
}
/// # Safety
/// Record the reset/wrote-CRCR diagnostic: CAPLENGTH, the CRCR readback taken
/// immediately before our write, whether Halted was ever observed, whether the
/// HCRST bit was ever observed set, and the raw USBSTS before the write and
/// after Run. This tells us definitively whether the controller was actually in
/// the Halted state when we wrote CRCR (a CRCR write is only accepted while
/// Halted; if it isn't, the write is silently dropped and CRCR stays 0).
pub unsafe fn set_xhci_reset_diag(
    caplen: u32,
    pre_lo: u32,
    pre_hi: u32,
    hch0: bool,
    hrst: bool,
    sts_pre: u32,
    sts_post: u32,
) {
    XHCI_CAPLEN = caplen;
    XHCI_CRCR_PRE_LO = pre_lo;
    XHCI_CRCR_PRE_HI = pre_hi;
    XHCI_HCH0 = if hch0 { 1 } else { 0 };
    XHCI_HRST = if hrst { 1 } else { 0 };
    XHCI_USBSTS_PRE = sts_pre;
    XHCI_USBSTS_POST = sts_post;
}
/// # Safety
/// Record the xHCI MMIO BAR physical address so the on-screen diagnostic can
/// show which address space the controller lives in (and therefore which
/// page-table mapping must be uncacheable).
pub unsafe fn set_xhci_bar(v: u64) {
    XHCI_BAR = v;
}
/// # Safety
/// Record the completion code of a command-completion event, plus whether it
/// was Success (CC=2) or not. Lets the on-screen diagnostics answer "why did
/// the command fail" instead of just "did it fail".
pub unsafe fn set_xhci_last_cc(cc: u8) {
    XHCI_LAST_CC = cc;
    // xHCI Completion Code 1 = Success (matches `CC_SUCCESS` in usbhcd.rs).
    // A prior copy used `cc == 2`, which miscounted every real success as a
    // failure in the CS/CF counters (cosmetic to the counters only; `cmd()`
    // itself checks the correct `CC_SUCCESS` constant for its return value).
    if cc == 1 {
        XHCI_CC_SUCCESS += 1;
    } else {
        XHCI_CC_FAIL += 1;
    }
}
/// # Safety
/// Called from the USB-HID xHCI driver when a control transfer is attempted.
pub unsafe fn inc_xhci_ntr() {
    XHCI_NTR += 1;
}
/// # Safety
/// Called from the USB-HID xHCI driver when a control transfer times out.
pub unsafe fn inc_xhci_nto() {
    XHCI_NTO += 1;
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_phase() -> u8 {
    XHCI_PHASE
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_nslot() -> u16 {
    XHCI_NSLOT
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_naddr() -> u16 {
    XHCI_NADDR
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_ncmd() -> u16 {
    XHCI_NCMD
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_ntr() -> u16 {
    XHCI_NTR
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_nto() -> u16 {
    XHCI_NTO
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_last_cc() -> u8 {
    XHCI_LAST_CC
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_cc_fail() -> u16 {
    XHCI_CC_FAIL
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_cc_success() -> u16 {
    XHCI_CC_SUCCESS
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_natt() -> u16 {
    XHCI_NATT
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_nevt() -> u16 {
    XHCI_NEVT
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_csts() -> u32 {
    XHCI_CSTS
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_crcr_lo() -> u32 {
    XHCI_CRCR_LO
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_crcr_hi() -> u32 {
    XHCI_CRCR_HI
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_crcr_wlo() -> u32 {
    XHCI_CRCR_WLO
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_crcr_whi() -> u32 {
    XHCI_CRCR_WHI
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_cmd_ring() -> u64 {
    XHCI_CMD_RING
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_legacy() -> u32 {
    XHCI_LEGACY
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_legacy_st() -> u8 {
    XHCI_LEGACY_ST
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_caplen() -> u32 {
    XHCI_CAPLEN
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_crcr_pre_lo() -> u32 {
    XHCI_CRCR_PRE_LO
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_crcr_pre_hi() -> u32 {
    XHCI_CRCR_PRE_HI
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_hch0() -> u8 {
    XHCI_HCH0
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_hrst() -> u8 {
    XHCI_HRST
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_usbsts_pre() -> u32 {
    XHCI_USBSTS_PRE
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_usbsts_post() -> u32 {
    XHCI_USBSTS_POST
}
/// # Safety
/// Read from the desktop diagnostic renderer.
pub unsafe fn xhci_bar() -> u64 {
    XHCI_BAR
}

/// Snapshot the LAPIC's health for the on-screen boot diagnostic: whether we
/// are in x2APIC (MSR) mode, whether the LAPIC is software-enabled (SVR bit 8),
/// the live timer current-count (if it changes, the timer is running even if
/// the ISR is not firing), and the LAPIC ID.
///
/// # Safety
/// Read after `init_lapic_timer`.
pub unsafe fn lapic_diag() -> (bool, bool, u32, u32) {
    let x2 = LAPIC_X2;
    if LAPIC_BASE == 0 {
        return (x2, false, 0, 0);
    }
    let svr = lapic_read(0xF0);
    let sv = (svr & 0x100) != 0;
    let tc = lapic_read(0x390);
    let id = lapic_read(0x20);
    (x2, sv, tc, id)
}

/// Paint a "timer alive" indicator that is impossible to miss: a thick,
/// full-width horizontal bar that SWEEPS DOWN the screen and CYCLES color every
/// tick. If the LAPIC timer keeps firing, this bar visibly travels down the
/// display; if the system wedges after the first tick, it sits at one position
/// (or the desktop erases it and it never returns). This disambiguates "timer
/// alive" from "fired once then frozen" on real hardware with no serial output.
unsafe fn diag_paint_timer(tick: u64) {
    if DIAG_FB == 0 {
        return;
    }
    let palette: [(u8, u8, u8); 6] = [
        (0xFF, 0xFF, 0xFF), // white
        (0xFF, 0x00, 0x00), // red
        (0x00, 0xFF, 0x00), // green
        (0x00, 0x00, 0xFF), // blue
        (0xFF, 0xFF, 0x00), // yellow
        (0x00, 0xFF, 0xFF), // cyan
    ];
    let (r, g, b) = palette[(tick % 6) as usize];
    let fb = DIAG_FB as *mut u8;
    let stride = DIAG_STRIDE as usize;
    let h = DIAG_H as usize;
    let w = DIAG_W as usize;
    let bar_h = 30usize;
    let span = h.saturating_sub(bar_h).max(1);
    let y0 = ((tick as usize) * 3) % span;
    for dy in 0..bar_h {
        for dx in 0..w {
            let off = (((y0 + dy) * stride) + dx) * 4;
            core::ptr::write_volatile(fb.add(off), b);
            core::ptr::write_volatile(fb.add(off + 1), g);
            core::ptr::write_volatile(fb.add(off + 2), r);
        }
    }
}

/// Repaint the persistent diagnostic blocks from the timer ISR: the sweeping
/// timer block, plus the red/green keyboard/mouse blocks if their vectors have
/// fired. Repainting every tick keeps them visible despite the desktop's
/// full-frame repaint.
unsafe fn tick_repaint_latches() {
    let w = DIAG_W as usize;
    let h = DIAG_H as usize;
    // PS/2 presence: blue (present) vs magenta (absent -> likely USB).
    if PS2_PRESENT {
        diag_fill(10, h - 100, 60, 60, 0x00, 0x00, 0xFF);
    } else {
        diag_fill(10, h - 100, 60, 60, 0xFF, 0x00, 0xFF);
    }
    // I/O APIC routing: yellow (accepted) vs cyan (failed).
    if IOAPIC_OK {
        diag_fill(w / 2 - 30, h - 100, 60, 60, 0xFF, 0xFF, 0x00);
    } else {
        diag_fill(w / 2 - 30, h - 100, 60, 60, 0x00, 0xFF, 0xFF);
    }
}

unsafe fn diag_tick() {
    let tick = crate::cpu::timer_ticks();
    diag_paint_timer(tick);
    if KEY_FIRED {
        diag_paint(1);
    }
    if MOUSE_FIRED {
        diag_paint(2);
    }
    tick_repaint_latches();
}

/// Rust side of the LAPIC timer stub: count the tick and send the EOI.
#[no_mangle]
pub extern "sysv64" fn timer_trap_rust() {
    unsafe {
        TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
        lapic_write(0xB0, 0);
        diag_tick();
    }
}

/// Paint an 8x8 "alive" block for ISR `slot` at the top-right, spaced
/// horizontally. Colors are written in BGR order so they render correctly
/// on the TP201S BGRX framebuffer:
///   0 = white (timer), 1 = red (keyboard IRQ1), 2 = green (mouse IRQ12).
/// Used to prove on real hardware which interrupt vectors actually fire.
///
/// # Safety
///
/// Must only be called after `init_diag_fb` has set the framebuffer base
/// (this guards `DIAG_FB == 0` internally, but the caller is responsible for
/// the framebuffer being mapped).
pub unsafe fn diag_paint(slot: u8) {
    if DIAG_FB == 0 {
        return;
    }
    let (r, g, b) = match slot {
        0 => (0xFFu8, 0xFF, 0xFF),
        1 => (0xFFu8, 0x00, 0x00),
        2 => (0x00u8, 0xFF, 0x00),
        _ => (0x00u8, 0x00, 0xFF),
    };
    let fb = DIAG_FB as *mut u8;
    let stride = DIAG_STRIDE as usize;
    let x = (DIAG_W.saturating_sub(10u32 + (slot as u32) * 12)) as usize;
    for dy in 0..8u32 {
        for dx in 0..8u32 {
            let off = ((dy as usize) * stride + (x + dx as usize)) * 4;
            core::ptr::write_volatile(fb.add(off), b);
            core::ptr::write_volatile(fb.add(off + 1), g);
            core::ptr::write_volatile(fb.add(off + 2), r);
        }
    }
}

/// Paint a 6x6 phase marker for the xHCI enumeration, in a horizontal strip
/// across the bottom-left of the framebuffer, so a TP201S boot that never
/// reaches the desktop shell still shows exactly how far enumeration got.
/// `phase` selects a distinct color from a 16-color palette and a unique
/// column, so "how many colored blocks appear" maps 1:1 to the last phase
/// reached.
///
/// # Safety
/// Requires `init_diag_fb` to have run (guarded internally by DIAG_FB == 0).
pub unsafe fn diag_phase_block(phase: u8) {
    if DIAG_FB == 0 {
        return;
    }
    let (r, g, b) = PHASE_COLOR(phase);
    let fb = DIAG_FB as *mut u8;
    let stride = DIAG_STRIDE as usize;
    let x = (phase as usize % 16) * 14 + 4;
    let y = DIAG_H.saturating_sub(32) as usize;
    for dy in 0..10u32 {
        for dx in 0..10u32 {
            let off = ((y + dy as usize) * stride + (x + dx as usize)) * 4;
            core::ptr::write_volatile(fb.add(off), b);
            core::ptr::write_volatile(fb.add(off + 1), g);
            core::ptr::write_volatile(fb.add(off + 2), r);
        }
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

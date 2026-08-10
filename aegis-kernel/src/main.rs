#![no_std]
#![no_main]

use aegis_kernel::sprintln;
use core::panic::PanicInfo;

#[no_mangle]
pub extern "sysv64" fn _start() -> ! {
    aegis_kernel::serial::SerialWriter::init();

    sprintln!("=== Aegis Phase 2: Bare-Metal Kernel ===");
    sprintln!("Aegis: kernel started (loader handed off at entry)");

    unsafe {
        aegis_kernel::cpu::switch_to_kernel_stack();
    }
    sprintln!(
        "Aegis: kernel stack 0x{:016X} (16 KiB, tail of BSS)",
        aegis_kernel::cpu::stack_top()
    );

    let boot_info = unsafe { aegis_kernel::boot_info::locate() };
    match &boot_info {
        Some(info) => {
            let conv = aegis_kernel::boot_info::total_by_type(
                info,
                aegis_kernel::boot_info::TYPE_CONVENTIONAL,
            );
            sprintln!(
                "Aegis: boot-info @ 0x10000: {} descriptors, {} bytes conventional",
                info.entries.len(),
                conv
            );
        }
        None => {
            sprintln!("Aegis: WARNING no boot-info handoff found");
        }
    }

    unsafe {
        aegis_kernel::cpu::init_gdt();
    }
    sprintln!("Aegis: GDT + TSS loaded (lgdt/ltr)");

    unsafe {
        aegis_kernel::cpu::init_idt();
    }
    sprintln!("Aegis: IDT loaded (exception vectors 0-31 + timer at 0x30)");

    unsafe {
        aegis_kernel::cpu::mask_pic();
    }
    sprintln!("Aegis: legacy PIC masked");

    unsafe {
        aegis_kernel::page_tables::init_kernel_tables();
        aegis_kernel::page_tables::switch_to(aegis_kernel::page_tables::kernel_pml4_phys());
    }
    sprintln!("Aegis: CR3 switched to kernel page tables (identity with 4 KB LAPIC mapping)");

    unsafe {
        aegis_kernel::cpu::init_lapic_timer();
    }
    sprintln!("Aegis: LAPIC timer armed (periodic, vector 0x30)");

    unsafe {
        core::arch::asm!("sti");
    }
    sprintln!("Aegis: interrupts enabled - entering idle loop");

    let mut next_print: u64 = 512;
    loop {
        unsafe { core::arch::asm!("hlt") };
        let t = aegis_kernel::cpu::timer_ticks();
        if t >= next_print {
            next_print = t + 512;
            sprintln!("Aegis: tick = {} (timer alive)", t);
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    aegis_kernel::sprintln!("KERNEL PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

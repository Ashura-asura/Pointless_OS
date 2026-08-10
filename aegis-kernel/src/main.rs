#![no_std]
#![no_main]

use aegis_kernel::sprintln;
use core::panic::PanicInfo;

/// VGA text mode buffer at physical address 0xB8000.
const VGA_BUFFER: *mut u8 = 0xB8000 as *mut u8;

unsafe fn vga_print(msg: &str, row: usize, col: usize, attr: u8) {
    let offset = (row * 80 + col) * 2;
    for (i, byte) in msg.bytes().enumerate() {
        core::ptr::write_volatile(VGA_BUFFER.add(offset + i * 2), byte);
        core::ptr::write_volatile(VGA_BUFFER.add(offset + i * 2 + 1), attr);
    }
}

#[no_mangle]
pub extern "sysv64" fn _start() -> ! {
    aegis_kernel::serial::SerialWriter::init();

    sprintln!("=== Aegis Phase 2: Bare-Metal Kernel ===");
    sprintln!("Aegis: kernel started (loader handed off at entry)");

    unsafe {
        for i in 0..(80 * 25 * 2) {
            core::ptr::write_volatile(VGA_BUFFER.add(i), if i % 2 == 0 { b' ' } else { 0x07 });
        }
        vga_print("Aegis kernel running", 0, 0, 0x0A);
        vga_print("Phase 2: process isolation", 1, 0, 0x07);
    }

    unsafe {
        aegis_kernel::page_tables::init_kernel_tables();
    }
    sprintln!("Aegis: kernel page tables up (4GB identity via 1GB pages)");
    sprintln!(
        "Aegis: CR3 = 0x{:016X}",
        aegis_kernel::page_tables::kernel_pml4_phys()
    );
    sprintln!("Aegis: entering idle loop");

    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

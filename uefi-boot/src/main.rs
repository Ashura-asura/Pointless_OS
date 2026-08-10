#![no_std]
#![no_main]

mod memory_map;
mod page_tables;

use uefi::prelude::*;

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    uefi::println!("=== Aegis Phase 1: Real Hardware Boot ===");
    uefi::println!("Aegis: UEFI boot successful");

    // Print UEFI memory map
    memory_map::print_memory_map();

    // Set up 4-level identity-mapped page tables
    uefi::println!("Aegis: Setting up page tables...");
    unsafe {
        page_tables::setup_identity_mapping();
    }
    let cr3 = page_tables::read_cr3();
    uefi::println!("Aegis: Page tables configured, CR3 = 0x{:016X}", cr3);

    // Summary
    uefi::println!("Aegis: Phase 1 boot complete. Halting.");
    uefi::println!("=== Aegis Phase 1: Done ===");

    // Halt (in real OS, this would jump to the kernel)
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

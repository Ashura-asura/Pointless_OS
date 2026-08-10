#![no_std]
#![no_main]

mod elf;
mod memory_map;
mod page_tables;
mod serial;

use uefi::mem::memory_map::MemoryMap;
use uefi::prelude::*;

/// Embedded kernel binary — linked at build time by build_image.py.
/// In a real boot chain, this would be read from the FAT16 partition.
#[link_section = ".rodata"]
static KERNEL_ELF: &[u8] = include_bytes!("../aegis-kernel.bin");

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    serial::SerialWriter::init();

    sprintln!("=== Aegis Phase 1: Real Hardware Boot ===");
    uefi::println!("=== Aegis Phase 1: Real Hardware Boot ===");
    sprintln!("Aegis: UEFI boot successful");
    uefi::println!("Aegis: UEFI boot successful");

    // Print UEFI memory map
    memory_map::print_memory_map();

    // Set up 4-level identity-mapped page tables
    uefi::println!("Aegis: Setting up page tables...");
    sprintln!("Aegis: Setting up page tables...");
    unsafe {
        page_tables::setup_identity_mapping();
    }
    let cr3 = page_tables::read_cr3();
    uefi::println!("Aegis: Page tables configured, CR3 = 0x{:016X}", cr3);
    sprintln!("Aegis: Page tables configured, CR3 = 0x{:016X}", cr3);

    // Parse kernel ELF
    uefi::println!("Aegis: Parsing kernel ELF ({} bytes)...", KERNEL_ELF.len());
    sprintln!("Aegis: Parsing kernel ELF ({} bytes)...", KERNEL_ELF.len());
    match elf::parse_elf(KERNEL_ELF) {
        Ok(kernel) => {
            uefi::println!("Aegis: Kernel entry point: 0x{:016X}", kernel.entry);
            sprintln!("Aegis: Kernel entry point: 0x{:016X}", kernel.entry);
            uefi::println!("Aegis: Kernel segments: {}", kernel.segment_count);
            sprintln!("Aegis: Kernel segments: {}", kernel.segment_count);
            for i in 0..kernel.segment_count {
                let seg = &kernel.segments[i];
                uefi::println!(
                    "  Segment {}: vaddr=0x{:016X} filesz=0x{:X} memsz=0x{:X} flags=0x{:X}",
                    i,
                    seg.vaddr,
                    seg.filesz,
                    seg.memsz,
                    seg.flags
                );
                sprintln!(
                    "  Segment {}: vaddr=0x{:016X} filesz=0x{:X} memsz=0x{:X} flags=0x{:X}",
                    i,
                    seg.vaddr,
                    seg.filesz,
                    seg.memsz,
                    seg.flags
                );
            }

            // Load segments into memory
            for i in 0..kernel.segment_count {
                let seg = &kernel.segments[i];
                let dst = seg.vaddr as *mut u8;
                let src_start = seg.offset as usize;
                let src_end = src_start + seg.filesz as usize;

                if src_end <= KERNEL_ELF.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            KERNEL_ELF[src_start..src_end].as_ptr(),
                            dst,
                            seg.filesz as usize,
                        );
                        // Zero BSS (memsz > filesz)
                        if seg.memsz > seg.filesz {
                            let bss_start = dst.add(seg.filesz as usize);
                            let bss_len = (seg.memsz - seg.filesz) as usize;
                            core::ptr::write_bytes(bss_start, 0, bss_len);
                        }
                    }
                }
            }

            // Apply base-0 relocations (R_X86_64_RELATIVE). The kernel links
            // with a link-time base of 0, so each slot just receives the
            // addend. Without this, indirect calls through .got/.data tables
            // would read link-time placeholder zeros.
            uefi::println!(
                "Aegis: Applying {} relocations...",
                kernel.relocations.len()
            );
            sprintln!(
                "Aegis: Applying {} relocations...",
                kernel.relocations.len()
            );
            for rel in &kernel.relocations {
                unsafe {
                    core::ptr::write_volatile(rel.offset as *mut u64, rel.addend);
                }
            }

            // Exit boot services: the kernel now owns the machine. The
            // firmware stops servicing events, its boot watchdog is
            // disarmed, and the memory map is finalized. From this point on
            // only raw hardware (serial, LAPIC, paging) remains usable, so
            // all remaining prints go to the polled COM1 port only.
            uefi::println!("Aegis: Calling ExitBootServices...");
            let final_map = unsafe {
                uefi::boot::exit_boot_services(Some(uefi::boot::MemoryType::LOADER_DATA))
            };
            sprintln!(
                "Aegis: ExitBootServices OK — machine handed over to kernel ({} descriptors in final map)",
                final_map.entries().count()
            );

            uefi::println!(
                "Aegis: Kernel loaded. Jumping to 0x{:016X}...",
                kernel.entry
            );
            sprintln!(
                "Aegis: Kernel loaded. Jumping to 0x{:016X}...",
                kernel.entry
            );

            // Jump to kernel entry point
            // UNTESTED on real hardware: requires VMware/QEMU to verify
            let entry_fn: extern "sysv64" fn() -> ! = unsafe { core::mem::transmute(kernel.entry) };
            entry_fn();
        }
        Err(_) => {
            uefi::println!("Aegis: ERROR: Invalid kernel ELF");
            uefi::println!("Aegis: Halting.");
            sprintln!("Aegis: ERROR: Invalid kernel ELF");
            sprintln!("Aegis: Halting.");
        }
    }

    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

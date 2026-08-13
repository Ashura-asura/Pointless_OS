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
            let final_count = final_map.entries().count();
            sprintln!(
                "Aegis: ExitBootServices OK — machine handed over to kernel ({} descriptors in final map)",
                final_count
            );

            // Write the boot-info handoff page. It lives on the first page
            // strictly above the kernel image (`image_end`), so it can never
            // collide with a loaded segment — a fixed low address (0x10000)
            // used to, once the linker grew `.got`/`.relro`/`.data` into it,
            // and the write here silently corrupted those slots, producing a
            // boot-time #PF at a garbage address. The handoff address is
            // passed to the kernel entry in %rdi (first sysv64 argument);
            // the kernel reserves `image_end..+2` pages so nothing reuses it.
            const BOOT_MAGIC: u64 = 0x4145_4753_4841_4E44; // "AEGSHAND"
            const MAX_ENTRIES: usize = 256;

            let mut image_end: u64 = 0;
            for i in 0..kernel.segment_count {
                let seg = &kernel.segments[i];
                let end = seg.vaddr + seg.memsz;
                if end > image_end {
                    image_end = end;
                }
            }
            image_end = (image_end + 4095) & !4095;
            let handoff_addr = image_end;

            #[repr(C, packed)]
            #[derive(Copy, Clone)]
            struct MapEntry {
                ty: u32,
                base: u64,
                pages: u64,
            }

            /// Matches aegis-kernel/src/boot_info.rs layout: magic,
            /// entry_count, pad, image_end, then entries at offset 24.
            #[repr(C, packed)]
            #[derive(Copy, Clone)]
            struct BootHandoff {
                magic: u64,
                entry_count: u32,
                _pad: u32,
                image_end: u64,
                entries: [MapEntry; MAX_ENTRIES],
            }

            let in_conventional = final_map.entries().any(|d| {
                d.phys_start <= handoff_addr
                    && handoff_addr < d.phys_start + d.page_count * 4096
                    && d.ty == uefi::boot::MemoryType::CONVENTIONAL
            });
            sprintln!(
                "Aegis: boot-info page 0x{:X} inside conventional memory: {} (kernel image ends 0x{:X})",
                handoff_addr,
                in_conventional,
                image_end
            );

            let mut handoff = BootHandoff {
                magic: BOOT_MAGIC,
                entry_count: final_count as u32,
                _pad: 0,
                image_end,
                entries: [MapEntry {
                    ty: 0,
                    base: 0,
                    pages: 0,
                }; MAX_ENTRIES],
            };
            for (i, d) in final_map.entries().enumerate().take(MAX_ENTRIES) {
                handoff.entries[i] = MapEntry {
                    ty: d.ty.0,
                    base: d.phys_start,
                    pages: d.page_count,
                };
            }
            unsafe {
                core::ptr::write_volatile(handoff_addr as *mut BootHandoff, handoff);
            }
            let written_count = handoff.entry_count;
            sprintln!(
                "Aegis: boot-info written at 0x{:X} ({} descriptors, image end 0x{:X})",
                handoff_addr,
                written_count,
                image_end
            );

            uefi::println!(
                "Aegis: Kernel loaded. Jumping to 0x{:016X}...",
                kernel.entry
            );
            sprintln!(
                "Aegis: Kernel loaded. Jumping to 0x{:016X}...",
                kernel.entry
            );

            // Jump to kernel entry point, passing the boot-info handoff
            // address in %rdi (first sysv64 argument).
            // UNTESTED on real hardware: requires VMware/QEMU to verify
            let entry_fn: extern "sysv64" fn(u64) -> ! =
                unsafe { core::mem::transmute(kernel.entry) };
            entry_fn(handoff_addr);
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

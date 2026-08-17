#![no_std]
#![no_main]

mod elf;
mod fleet_cfg;
mod gop;
mod memory_map;
mod page_tables;
mod serial;

use uefi::mem::memory_map::MemoryMap;
use uefi::prelude::*;

extern crate alloc;
use alloc::string::String;

fn ip_str(ip: &[u8; 4]) -> String {
    use alloc::format;
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

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

            // Read \FLEET.CFG from the boot volume before firmware services
            // disappear. It carries the runtime role/IP/node-id config that
            // the kernel's fleet demo uses (see fleet_cfg module). Absent or
            // unparsable => the kernel falls back to compile-time defaults.
            let fleet_config = fleet_cfg::read_from_esp();
            match &fleet_config {
                Some(cfg) => {
                    sprintln!(
                        "Aegis: FLEET.CFG loaded (role={} my={} peer={})",
                        if cfg.role == 0 { "issuer" } else { "invoker" },
                        ip_str(&cfg.my_ip),
                        ip_str(&cfg.peer_ip)
                    );
                    uefi::println!(
                        "Aegis: FLEET.CFG loaded (role={} my={} peer={})",
                        if cfg.role == 0 { "issuer" } else { "invoker" },
                        ip_str(&cfg.my_ip),
                        ip_str(&cfg.peer_ip)
                    );
                }
                None => {
                    sprintln!("Aegis: no FLEET.CFG — kernel uses compile-time defaults");
                    uefi::println!("Aegis: no FLEET.CFG — kernel uses compile-time defaults");
                }
            }

            // Exit boot services: the kernel now owns the machine. The
            // firmware stops servicing events, its boot watchdog is
            // disarmed, and the memory map is finalized. From this point on
            // only raw hardware (serial, LAPIC, paging) remains usable, so
            // all remaining prints go to the polled COM1 port only.
            //
            // Query the Graphics Output Protocol BEFORE this point: it is
            // a boot service and dies with the rest of firmware. The
            // framebuffer it hands out survives (it is device memory),
            // so the kernel can keep drawing to it after handover.
            let gop_config = gop::query();
            match &gop_config {
                Some(h) => {
                    // `GopHandoff` is packed; copy fields out before
                    // formatting (no unaligned references).
                    let (w, hgt, stride, fmt, base, size) = (
                        h.width,
                        h.height,
                        h.stride_px,
                        if h.pixel_format == 1 { "BGRX" } else { "RGBX" },
                        h.framebuffer_base,
                        h.framebuffer_size,
                    );
                    sprintln!(
                        "Aegis: GOP: framebuffer {w}x{hgt} stride {stride} fmt {fmt} @ {base:#x} ({size} bytes)"
                    );
                    uefi::println!(
                        "Aegis: GOP: framebuffer {}x{} stride {} fmt {} @ {:#x} ({} bytes)",
                        w,
                        hgt,
                        stride,
                        fmt,
                        base,
                        size
                    );
                }
                None => {
                    sprintln!(
                        "Aegis: GOP: no usable framebuffer - kernel falls back to Bochs VBE probe"
                    );
                    uefi::println!(
                        "Aegis: GOP: no usable framebuffer - kernel falls back to Bochs VBE probe"
                    );
                }
            }

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

            // The image is linked at vaddr 0x0 and loaded into low memory.
            // The handoff spans 2 pages (`HANDOFF_PAGES` in boot_info.rs). If
            // the image now ends so close to 0xA0000 (top of low conventional
            // RAM) that those pages would cross into the VGA/ROM hole — which
            // is not RAM — a handoff written there could not be read back by
            // the kernel. Lift the handoff to the first conventional
            // descriptor at/above `image_end` (0x100000 in the standard OVMF
            // layout).
            const HANDOFF_PAGES: u64 = 2;
            if image_end + HANDOFF_PAGES * 4096 >= 0xA0000 {
                image_end = final_map
                    .entries()
                    .filter(|d| {
                        d.ty == uefi::boot::MemoryType::CONVENTIONAL && d.phys_start >= image_end
                    })
                    .map(|d| d.phys_start)
                    .min()
                    .unwrap_or(image_end);
            }
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
            // Append the optional FleetConfig block right after the entries
            // (offset 5144 = 24 + 256*20), matching boot_info.rs FLEET_OFFSET.
            // Stack-only: the UEFI allocator is dead after ExitBootServices.
            if let Some(fleet_bytes) = fleet_cfg::to_handoff_bytes(&fleet_config) {
                unsafe {
                    core::ptr::write_bytes(
                        (handoff_addr as *mut u8).add(fleet_cfg::FLEET_OFFSET),
                        0,
                        fleet_bytes.len(),
                    );
                    core::ptr::copy_nonoverlapping(
                        fleet_bytes.as_ptr(),
                        (handoff_addr as *mut u8).add(fleet_cfg::FLEET_OFFSET),
                        fleet_bytes.len(),
                    );
                }
                sprintln!(
                    "Aegis: fleet config block written at handoff+{} ({} bytes)",
                    fleet_cfg::FLEET_OFFSET,
                    fleet_bytes.len()
                );
            }
            // Append the GOP handoff block right after the fleet block
            // (offset 5199), matching boot_info.rs GOP_OFFSET. Always
            // written: `present = 0` when no usable GOP was found, so the
            // kernel can tell "no GOP" from "GOP but unusable".
            let gop_bytes = gop::to_handoff_bytes(&gop_config.unwrap_or(gop::GopHandoff {
                present: 0,
                pixel_format: 0,
                width: 0,
                height: 0,
                stride_px: 0,
                bpp: 0,
                framebuffer_base: 0,
                framebuffer_size: 0,
            }));
            unsafe {
                core::ptr::write_bytes(
                    (handoff_addr as *mut u8).add(gop::GOP_OFFSET),
                    0,
                    gop_bytes.len(),
                );
                core::ptr::copy_nonoverlapping(
                    gop_bytes.as_ptr(),
                    (handoff_addr as *mut u8).add(gop::GOP_OFFSET),
                    gop_bytes.len(),
                );
            }
            sprintln!(
                "Aegis: GOP handoff block written at handoff+{} ({} bytes, present={})",
                gop::GOP_OFFSET,
                gop_bytes.len(),
                gop_config.as_ref().map(|_| 1).unwrap_or(0)
            );
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

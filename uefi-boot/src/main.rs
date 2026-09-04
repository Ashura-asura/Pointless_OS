#![no_std]
#![no_main]
#![allow(static_mut_refs)] // single-threaded loader, static MAP_BUF

mod elf;
mod fleet_cfg;
mod gop;
mod memory_map;
mod page_tables;
mod serial;

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

    sprintln!("=== Aegis Phase 1: Real Hardware Boot (loader 381b7db) ===");
    uefi::println!("=== Aegis Phase 1: Real Hardware Boot (loader 381b7db) ===");
    sprintln!("Aegis: UEFI boot successful");
    uefi::println!("Aegis: UEFI boot successful");

    // Print UEFI memory map
    memory_map::print_memory_map();

    // Query GOP BEFORE switching to our own page tables. The firmware's GOP
    // boot services run with the firmware's page tables, which map ALL RAM
    // including above 4 GiB (the TP201S has RAM up there). Once we switch to
    // our 0-4 GiB identity map, the GOP query page-faults when firmware code
    // touches high RAM — that is the crash after "no FLEET.CFG" on real hw.
    uefi::println!("Aegis: GOP: querying display...");
    sprintln!("Aegis: GOP: querying display...");
    let gop_config = gop::query();
    match &gop_config {
        Some(h) => {
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
            sprintln!("Aegis: GOP: no usable framebuffer - kernel falls back to Bochs VBE probe");
            uefi::println!(
                "Aegis: GOP: no usable framebuffer - kernel falls back to Bochs VBE probe"
            );
        }
    }

    // Set up 4-level identity-mapped page tables
    uefi::println!("Aegis: Setting up page tables...");
    sprintln!("Aegis: Setting up page tables...");
    unsafe {
        page_tables::setup_identity_mapping();
    }
    // Make the framebuffer visible to the kernel: if it sits above 4 GiB,
    // map its 1 GiB window(s) into our tables (the base map covers GB0-3).
    if let Some(h) = &gop_config {
        let start_gb = h.framebuffer_base >> 30;
        let end_gb = ((h.framebuffer_base + h.framebuffer_size + 0x3FFF_FFFF) >> 30).min(8);
        if start_gb >= 4 && start_gb < 8 {
            for gb in start_gb..end_gb.min(8) {
                unsafe { page_tables::map_gb(gb) };
            }
        }
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
                } else {
                    // Previously a silent no-op: this segment would just never
                    // be copied, with no log line and no change to the segment
                    // table already printed above, leaving `dst` as whatever
                    // memory happened to be there. A kernel that boots and
                    // then freezes deep inside some later region (exactly what
                    // we're chasing on the TP201S) is indistinguishable, from
                    // the log alone, from this segment having been dropped.
                    // Make it loud instead of invisible.
                    uefi::println!(
                        "Aegis: FATAL: segment {} out of bounds (offset=0x{:X} filesz=0x{:X} elf_len=0x{:X}) — NOT LOADED",
                        i, seg.offset, seg.filesz, KERNEL_ELF.len()
                    );
                    sprintln!(
                        "Aegis: FATAL: segment {} out of bounds (offset=0x{:X} filesz=0x{:X} elf_len=0x{:X}) — NOT LOADED",
                        i, seg.offset, seg.filesz, KERNEL_ELF.len()
                    );
                    panic!("kernel ELF segment {} out of bounds, refusing to boot a partially-loaded kernel", i);
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
            // (The GOP query was already done before the page-table switch.)

            uefi::println!("Aegis: Calling ExitBootServices...");
            // Raw ExitBootServices — single attempt, no retry loop, no pool
            // allocation (the uefi crate's wrapper retries and re-allocates,
            // which hangs this firmware). Get the memory map once into a
            // static buffer, call EBS once with that key, then build the
            // handoff from the stored descriptors.
            #[repr(C)]
            #[derive(Copy, Clone)]
            struct MapDesc {
                ty: u32,
                _pad: u32,
                phys: u64,
                _virt: u64,
                pages: u64,
                _attrs: u64,
            }
            const MAX_MAP: usize = 128;
            // Raw byte buffer — large enough for any UEFI descriptor size.
            // The old code used `MapDesc[128]` (40 bytes each = 5120 bytes)
            // but told the firmware `MAX_MAP * 48` (6144 bytes), causing a
            // potential 1024-byte overflow into adjacent statics. Use a raw
            // byte array sized for the worst case.
            const MAX_DESC_SIZE: usize = 64;
            static mut MAP_BUF: [u8; MAX_MAP * MAX_DESC_SIZE] = [0u8; MAX_MAP * MAX_DESC_SIZE];
            let (final_count, actual_desc_size) = unsafe {
                let st = uefi::table::system_table_raw().unwrap();
                let bs = (*st.as_ptr()).boot_services.as_ref().unwrap();
                let mut size = MAP_BUF.len();
                let mut key = 0usize;
                let mut desc_size = 0usize;
                let mut desc_ver = 0u32;
                let _ = (bs.get_memory_map)(
                    &mut size,
                    MAP_BUF.as_mut_ptr() as *mut uefi::mem::memory_map::MemoryDescriptor,
                    &mut key,
                    &mut desc_size,
                    &mut desc_ver,
                );
                // ExitBootServices SKIPPED — the TP201S firmware hangs on the
                // call (both the uefi crate's wrapper and the raw firmware
                // function pointer). The kernel runs under the firmware's
                // boot services without EBS. The framebuffer and handoff are
                // already set up, so the kernel can print and boot.
                //
                // Use the firmware-returned `desc_size` (not hardcoded 48)
                // so the count is correct regardless of the descriptor layout.
                let ds = if desc_size > 0 { desc_size } else { 48 };
                let count = (size / ds).min(MAX_MAP);
                (count, ds)
            };
            sprintln!(
                "Aegis: ExitBootServices SKIPPED (TP201S workaround) — {} descriptors, handing off",
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
                // CONVENTIONAL memory type = 7.
                image_end = (0..final_count)
                    .map(|i| unsafe { desc_at(MAP_BUF.as_ptr(), actual_desc_size, i) })
                    .filter(|d| d.ty == 7 && d.phys >= image_end)
                    .map(|d| d.phys)
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

            // Helper to read a MapDesc from the raw byte buffer at a given
            // descriptor index, striding by the firmware's actual desc_size.
            unsafe fn desc_at(buf: *const u8, ds: usize, i: usize) -> MapDesc {
                let p = buf.add(i * ds);
                MapDesc {
                    ty: core::ptr::read_unaligned(p.add(0) as *const u32),
                    _pad: core::ptr::read_unaligned(p.add(4) as *const u32),
                    phys: core::ptr::read_unaligned(p.add(8) as *const u64),
                    _virt: core::ptr::read_unaligned(p.add(16) as *const u64),
                    pages: core::ptr::read_unaligned(p.add(24) as *const u64),
                    _attrs: core::ptr::read_unaligned(p.add(32) as *const u64),
                }
            }

            let in_conventional = (0..final_count).any(|i| {
                let d = unsafe { desc_at(MAP_BUF.as_ptr(), actual_desc_size, i) };
                d.phys <= handoff_addr && handoff_addr < d.phys + d.pages * 4096 && d.ty == 7
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
            for i in 0..final_count.min(MAX_ENTRIES) {
                let d = unsafe { desc_at(MAP_BUF.as_ptr(), actual_desc_size, i) };
                handoff.entries[i] = MapEntry {
                    ty: d.ty,
                    base: d.phys,
                    pages: d.pages,
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
            sprintln!(
                "Aegis: Kernel file size: {} bytes (embedded ELF)",
                KERNEL_ELF.len()
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

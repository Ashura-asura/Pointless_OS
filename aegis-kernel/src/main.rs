#![no_std]
#![no_main]

use aegis_kernel::sprintln;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

#[no_mangle]
pub extern "sysv64" fn _start() -> ! {
    // Enter on a freshly-established kernel stack: jump (never return) so
    // boot_kernel's prologue and all its %rsp-relative slots live below the
    // stack top, instead of spilling into BSS statics placed just above it.
    unsafe { aegis_kernel::cpu::switch_to_kernel_stack_and_jump(boot_kernel) }
}

extern "sysv64" fn boot_kernel() -> ! {
    aegis_kernel::serial::SerialWriter::init();
    aegis_kernel::vga::vga_init();

    sprintln!("=== Aegis Phase 2: Bare-Metal Kernel ===");
    sprintln!("Aegis: kernel started (loader handed off at entry)");

    unsafe {
        aegis_kernel::cpu::disable_smep_smap();
    }
    sprintln!(
        "Aegis: kernel stack 0x{:016X} (16 KiB, dedicated BSS region)",
        aegis_kernel::cpu::stack_top()
    );

    let boot_info = unsafe { aegis_kernel::boot_info::locate() };
    match boot_info.as_ref() {
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

            unsafe {
                aegis_kernel::frame::init_global(info);
            }
            // Dedicated idle stack: its saved scheduler frame must point at
            // private, never-clobbered memory. If idle shared KERNEL_STACK,
            // other tasks' timer/syscall entries would overwrite that region
            // and restoring idle would pop garbage (QEMU/TCG tolerated it;
            // VMware faulted). Allocate it like the task stacks.
            let idle_stack = unsafe {
                aegis_kernel::frame::alloc_contiguous_global(
                    aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
                )
            };
            match idle_stack {
                Some(is) => {
                    unsafe {
                        aegis_kernel::cpu::set_idle_stack_top(
                            is + aegis_kernel::tasks::TASK_STACK_SIZE,
                        );
                    }
                    sprintln!(
                        "Aegis: idle stack @ 0x{:X} ({} KiB, private)",
                        is,
                        aegis_kernel::tasks::TASK_STACK_SIZE / 1024
                    );
                }
                None => {
                    sprintln!("Aegis: WARNING could not allocate idle stack");
                }
            }
            let (total, free) = unsafe { aegis_kernel::frame::stats_global() };
            sprintln!(
                "Aegis: frame allocator: {} usable frames ({} MiB), {} free",
                total,
                total * 4 / 1024,
                free
            );

            let f0 = unsafe { aegis_kernel::frame::alloc_global() };
            let f1 = unsafe { aegis_kernel::frame::alloc_global() };
            let f2 = unsafe { aegis_kernel::frame::alloc_global() };
            sprintln!(
                "Aegis: allocator probe: frames @ 0x{:X}, 0x{:X}, 0x{:X}",
                f0.unwrap_or(0),
                f1.unwrap_or(0),
                f2.unwrap_or(0)
            );
            let freed = unsafe {
                let a = aegis_kernel::frame::free_global(f0.unwrap_or(0));
                let b = aegis_kernel::frame::free_global(f2.unwrap_or(0));
                (a, b)
            };
            let (_, free_after) = unsafe { aegis_kernel::frame::stats_global() };
            sprintln!(
                "Aegis: allocator probe: freed f0={}, f2={}, {} free now",
                freed.0,
                freed.1,
                free_after
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
    match aegis_kernel::page_tables::kernel_text_window() {
        Some((ts, te)) => {
            sprintln!(
                "Aegis: NX enabled: kernel text 0x{:X}-0x{:X} executable; all other pages non-executable",
                ts,
                te
            );
        }
        None => {
            sprintln!("Aegis: WARNING could not parse kernel ELF text window (NX state unknown)");
        }
    }

    // Live PCI enumeration over the legacy 0xCF8/0xCFC config ports.
    let mut pci = aegis_kernel::pci::PciDeviceList::new();
    unsafe {
        aegis_kernel::pci::scan_live(&mut pci);
    }
    let found_nvme = pci.find_nvme().is_some();
    sprintln!(
        "Aegis: PCI scan complete: {} device(s) found on bus 0",
        pci.len()
    );
    aegis_kernel::pci::print_report(&pci);
    if found_nvme {
        sprintln!("Aegis: PCI: NVMe controller present");
    }

    // Live NVMe demo: probe BAR0, reset, admin + IO queues, identify, read
    // LBA 0/1 and check the GPT signature (disk image is GPT-partitioned).
    if let Some(mut ctrl) = aegis_kernel::nvme::NvmeController::probe(&pci) {
        sprintln!(
            "Aegis: NVMe: BAR {:x} CAP=0x{:08X} VS=0x{:08X}",
            ctrl.bar_addr,
            ctrl.cap(),
            ctrl.vs()
        );
        let ok = ctrl.reset_and_ready();
        sprintln!("Aegis: NVMe: admin queues ready: {}", ok);
        let ok = ok && ctrl.create_io_queues();
        sprintln!("Aegis: NVMe: IO queues created: {}", ok);
        let ok = ok && ctrl.identify();
        sprintln!("Aegis: NVMe: identify: {}", ok);
        if ok {
            sprintln!("Aegis: NVMe: model {}", ctrl.identify_model());
            sprintln!("Aegis: NVMe: firmware {}", ctrl.identify_firmware());
            sprintln!("Aegis: NVMe: ns 1 x {} B", ctrl.ns_size());
        }
        let l0 = ctrl.read_lba(0);
        let g0 = aegis_kernel::nvme::mbr_protective_ok(ctrl.lba_data());
        let l1 = ctrl.read_lba(1);
        let g1 = aegis_kernel::nvme::gpt_signature_ok(ctrl.lba_data());
        sprintln!("Aegis: NVMe: LBA0: read {}, protective MBR {}", l0, g0);
        sprintln!("Aegis: NVMe: LBA1: read {}, GPT header {}", l1, g1);

        // Real FAT16 read from live hardware: mount the ESP (starts at LBA
        // 2048, matching uefi-boot/build_image.py's PART_START_LBA), walk
        // EFI/BOOT/BOOTX64.EFI, and read back the kernel's own bootloader
        // file's first sector. This is not the userspace object-store
        // model — it's real BPB parsing, real directory-entry scanning,
        // and real NVMe reads, end to end, from the live kernel.
        const ESP_START_LBA: u64 = 2048;
        if let Some(fs) = aegis_kernel::fat::mount(&mut ctrl, ESP_START_LBA) {
            sprintln!("Aegis: FAT16: ESP mounted at LBA {}", ESP_START_LBA);
            if let Some(efi_dir) =
                aegis_kernel::fat::find_in_root(&mut ctrl, &fs, b"EFI     ", b"   ")
            {
                sprintln!("Aegis: FAT16: found EFI/ (cluster {})", efi_dir.cluster);
                if let Some(boot_dir) = aegis_kernel::fat::find_in_subdir(
                    &mut ctrl,
                    &fs,
                    efi_dir.cluster,
                    b"BOOT    ",
                    b"   ",
                ) {
                    sprintln!(
                        "Aegis: FAT16: found EFI/BOOT/ (cluster {})",
                        boot_dir.cluster
                    );
                    if let Some(bootx64) = aegis_kernel::fat::find_in_subdir(
                        &mut ctrl,
                        &fs,
                        boot_dir.cluster,
                        b"BOOTX64 ",
                        b"EFI",
                    ) {
                        sprintln!(
                            "Aegis: FAT16: found BOOTX64.EFI, {} bytes, cluster {}",
                            bootx64.size,
                            bootx64.cluster
                        );
                        let mut first_sector = [0u8; 512];
                        if aegis_kernel::fat::read_first_sector(
                            &mut ctrl,
                            &fs,
                            &bootx64,
                            &mut first_sector,
                        ) {
                            let magic_ok = &first_sector[0..2] == b"MZ";
                            sprintln!(
                                "Aegis: FAT16: read BOOTX64.EFI first sector via NVMe — MZ signature: {}",
                                magic_ok
                            );
                        } else {
                            sprintln!("Aegis: FAT16: read of BOOTX64.EFI data failed");
                        }
                    } else {
                        sprintln!("Aegis: FAT16: BOOTX64.EFI not found in EFI/BOOT/");
                    }
                } else {
                    sprintln!("Aegis: FAT16: BOOT/ not found in EFI/");
                }
            } else {
                sprintln!("Aegis: FAT16: EFI/ not found in root directory");
            }
        } else {
            sprintln!("Aegis: FAT16: mount failed at LBA {}", ESP_START_LBA);
        }
    } else {
        sprintln!("Aegis: NVMe: no controller with a mapped BAR");
    }

    unsafe {
        aegis_kernel::cpu::init_lapic_timer();
    }
    sprintln!("Aegis: LAPIC timer armed (periodic, vector 0x30)");

    // Two kernel tasks, each on a 16 KiB stack carved from the frame
    // allocator (4 consecutive frames per task).
    let stack_alpha = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let stack_beta = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    match (stack_alpha, stack_beta) {
        (Some(sa), Some(sb)) => {
            unsafe {
                aegis_kernel::tasks::spawn("alpha", task_alpha, sa);
                aegis_kernel::tasks::spawn("beta", task_beta, sb);
            }
            sprintln!(
                "Aegis: tasks spawned: alpha @ 0x{:X}, beta @ 0x{:X} ({} tasks)",
                sa,
                sb,
                aegis_kernel::tasks::spawned_count()
            );
        }
        _ => {
            sprintln!("Aegis: WARNING could not allocate task stacks");
        }
    }
    // Ring-3 IPC demo: echo server (task 2) + client (task 3).
    let stack_server = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let cpl0_server = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let stack_client = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let cpl0_client = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    match (stack_server, cpl0_server, stack_client, cpl0_client) {
        (Some(ss), Some(cs), Some(su), Some(cu)) => {
            unsafe {
                aegis_kernel::tasks::spawn_user("server", task_server, ss, cs);
                aegis_kernel::tasks::spawn_user("client", task_client, su, cu);
            }
            sprintln!(
                "Aegis: IPC demo spawned: server@0x{:X}, client@0x{:X} ({} tasks)",
                ss,
                su,
                aegis_kernel::tasks::spawned_count()
            );
        }
        _ => {
            sprintln!("Aegis: WARNING could not allocate ring-3 IPC task stacks");
        }
    }

    // Memory isolation test: a ring-3 task that tries to read kernel memory.
    // If memory isolation works, this triggers a page fault → task killed.
    let stack_iso = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let cpl0_iso = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    match (stack_iso, cpl0_iso) {
        (Some(si), Some(ci)) => {
            unsafe {
                aegis_kernel::tasks::spawn_user("iso-test", task_isolation_test, si, ci);
            }
            sprintln!(
                "Aegis: isolation test spawned @ 0x{:X} ({} tasks total)",
                si,
                aegis_kernel::tasks::spawned_count()
            );
            // Hold the isolation test until the IPC demo (server/client
            // echo) has finished, so the two demos don't race for slices.
            aegis_kernel::tasks::arm_isolation_test(4, 15);
        }
        _ => {
            sprintln!("Aegis: WARNING could not allocate isolation test stack");
        }
    }

    // NX test: a ring-3 task that tries to execute a non-executable page
    // (0xB8000 = VGA text framebuffer: present, USER-readable, but NX). If
    // NX works, the instruction fetch #PFs and the task is killed while the
    // rest of the kernel keeps running.
    let stack_nx = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let cpl0_nx = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    match (stack_nx, cpl0_nx) {
        (Some(sn), Some(cn)) => {
            unsafe {
                aegis_kernel::tasks::spawn_user("nx-test", task_nx_test, sn, cn);
            }
            sprintln!(
                "Aegis: NX test spawned @ 0x{:X} ({} tasks total)",
                sn,
                aegis_kernel::tasks::spawned_count()
            );
            // After the isolation test faults (tick 15), let the NX test run
            // and fault too (tick 22).
            aegis_kernel::tasks::arm_nx_test(5, 22);
        }
        _ => {
            sprintln!("Aegis: WARNING could not allocate NX test stack");
        }
    }

    // Ring-3 capability-denial demo (master roadmap Phase 3): a task that was
    // granted nothing attempts gated ops on slots it does not hold. Least
    // authority means its CSpace is empty from birth, so every op returns -1
    // — denied, never a panic, never a silent success — while the kernel and
    // its peers keep running. The client's slot 0 was granted by the server;
    // this task's slot 0 never was.
    let stack_denied = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let cpl0_denied = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    match (stack_denied, cpl0_denied) {
        (Some(sd), Some(cd)) => {
            unsafe {
                aegis_kernel::tasks::spawn_user("denied", task_denied, sd, cd);
            }
            sprintln!(
                "Aegis: denial demo spawned @ 0x{:X} ({} tasks total)",
                sd,
                aegis_kernel::tasks::spawned_count()
            );
        }
        _ => {
            sprintln!("Aegis: WARNING could not allocate denial demo stack");
        }
    }

    unsafe {
        core::arch::asm!("sti");
    }
    sprintln!("Aegis: interrupts enabled - entering idle loop");

    // Seed the idle scheduler frame with a self-contained context on the
    // dedicated idle stack, then move the idle loop onto that stack so its
    // saved frame can never be clobbered by other tasks' kernel-stack use.
    unsafe {
        aegis_kernel::tasks::init_idle_frame(run_idle);
        aegis_kernel::cpu::switch_to_idle_stack(run_idle);
    }
    // unreachable
}

/// Ring-0 idle loop: halts until the next timer tick. Entered on a private
/// idle stack (see `switch_to_idle_stack`); the scheduler switches back to
/// it whenever no task is runnable.
#[no_mangle]
pub extern "sysv64" fn run_idle() -> ! {
    let mut next_print: u64 = 512;
    loop {
        let t = aegis_kernel::cpu::timer_ticks();
        if t >= next_print {
            next_print = t + 512;
            sprintln!("Aegis: tick = {} (timer alive)", t);
        }
        unsafe { core::arch::asm!("hlt") };
    }
}

static ALPHA_NEXT: AtomicU64 = AtomicU64::new(2048);
static BETA_NEXT: AtomicU64 = AtomicU64::new(4096);

/// Ring-3 syscall invocation (int 0x80): number in rax, args in
/// rsi/rcx/rdx/r8; the return value comes back in rax.
#[inline]
fn user_syscall5(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let mut ret: u64;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("rax") num,
            in("rsi") a1,
            in("rcx") a2,
            in("rdx") a3,
            in("r8") a4,
            lateout("rax") ret,
            options(nostack),
        );
    }
    ret
}

/// Ring-3 printf-equivalent: a `Write` syscall that prints `msg` verbatim.
fn user_print(msg: &[u8]) {
    user_syscall5(1, msg.as_ptr() as u64, msg.len() as u64, 0, 0);
}

// The demo tasks NEVER yield: progress only happens because the timer
// stub preempts them every tick (round-robin). If preemption stops
// working, neither task prints again.

extern "sysv64" fn task_alpha() -> ! {
    loop {
        let t = aegis_kernel::cpu::timer_ticks();
        let n = ALPHA_NEXT.load(Ordering::Relaxed);
        if t >= n {
            ALPHA_NEXT.store(n + 2048, Ordering::Relaxed);
            let mut rsp: u64 = 0;
            unsafe {
                core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, preserves_flags));
            }
            sprintln!("Aegis: [alpha] tick = {} (rsp 0x{:X})", t, rsp);
        }
        core::hint::spin_loop();
    }
}

extern "sysv64" fn task_beta() -> ! {
    loop {
        let t = aegis_kernel::cpu::timer_ticks();
        let n = BETA_NEXT.load(Ordering::Relaxed);
        if t >= n {
            BETA_NEXT.store(n + 2048, Ordering::Relaxed);
            let mut rsp: u64 = 0;
            unsafe {
                core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, preserves_flags));
            }
            sprintln!("Aegis: [beta] tick = {} (rsp 0x{:X})", t, rsp);
        }
        core::hint::spin_loop();
    }
}

/// Ring-3 IPC echo server: creates an endpoint, grants it to the client,
/// then loops calling Serve (blocking) to receive requests and Reply with
/// the same bytes (echo).
extern "sysv64" fn task_server() -> ! {
    // Create an endpoint — returns the capability slot in our table.
    let ep_slot = user_syscall5(8, 0, 0, 0, 0) as i64;
    if ep_slot < 0 {
        user_print(b"Aegis: [server] EndpointCreate failed\r\n");
        loop {
            core::hint::spin_loop();
        }
    }
    let ep_slot = ep_slot as u64;
    user_print(b"Aegis: [server] endpoint created\r\n");

    // Grant the endpoint capability to the client (task index 3, slot 0).
    let client_idx: u64 = 3;
    user_syscall5(9, client_idx, ep_slot, 0, 0);
    user_print(b"Aegis: [server] endpoint granted to client\r\n");

    // Serve loop: block until a call arrives, then reply with the same data.
    let mut recvbuf = [0u8; 256];
    loop {
        // Serve: returns (caller_id << 32) | len.
        let packed = user_syscall5(6, ep_slot, recvbuf.as_mut_ptr() as u64, 0, 0);
        let caller = packed >> 32;
        let rlen = packed & 0xFFFF_FFFF;
        // Echo: reply with the same data we received.
        user_syscall5(7, ep_slot, caller, recvbuf.as_ptr() as u64, rlen);
    }
}

/// Ring-3 IPC echo client: waits for the server to grant the endpoint
/// capability (slot 0), then sends a few messages and prints the replies.
extern "sysv64" fn task_client() -> ! {
    // Wait for the server to grant the capability (slot 0).
    // The server sets up the endpoint and grants before the client
    // typically runs, but we retry briefly just in case.
    let mut retries = 0u64;
    loop {
        let msg = b"ping from client";
        let mut reply = [0u8; 256];
        // Call: ep_slot=0, msg_va, len, reply_va
        let rlen = user_syscall5(
            5,
            0,
            msg.as_ptr() as u64,
            msg.len() as u64,
            reply.as_mut_ptr() as u64,
        );
        if rlen != u64::MAX {
            user_print(b"Aegis: [client] echo reply: ");
            user_print(&reply[..rlen as usize]);
            user_print(b"\r\n");
            break;
        }
        // The server grants the endpoint capability at startup; until it has
        // run and granted, our call fails. Poll (yielding so the server can
        // run) until the grant lands. Large cap guards against a real bug.
        retries += 1;
        if retries > 1_000_000 {
            user_print(b"Aegis: [client] gave up waiting for server\r\n");
            break;
        }
        // Yield briefly to let the server run.
        user_syscall5(3, 0, 0, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Ring-3 memory isolation test: attempts to read a kernel-only address
/// (0x1000000 = 16 MiB) that is NOT within the task's USER regions (low
/// 2 MB identity map + its stack). If memory isolation works, this triggers
/// a page fault → the exception handler reports it and halts.
extern "sysv64" fn task_isolation_test() -> ! {
    user_print(b"Aegis: [isolation-test] attempting illegal kernel read at 0x1000000...\r\n");
    // This address is in the identity map (so it is present) but NOT marked
    // USER. The task's own PML4 has no USER flag on it → page fault.
    unsafe {
        let ptr = 0x1000000 as *const u64;
        let _val = core::ptr::read_volatile(ptr);
        // If we get here, isolation FAILED — this should never happen.
        user_print(b"Aegis: [isolation-test] ISOLATION FAILED - read succeeded!\r\n");
    }
    // Should never reach here — the page fault handler kills us first.
    user_print(b"Aegis: [isolation-test] UNREACHABLE\r\n");
    loop {
        core::hint::spin_loop();
    }
}

/// Ring-3 NX test: attempts to execute an instruction from 0xB8000 (VGA
/// text framebuffer). The page is present and USER-readable, but marked
/// NX — the instruction fetch must #PF, the exception handler kills the
/// task, and the kernel keeps running.
extern "sysv64" fn task_nx_test() -> ! {
    user_print(b"Aegis: [nx-test] attempting to execute 0xB8000 (VGA memory, NX)...\r\n");
    unsafe {
        core::arch::asm!("call rax", in("rax") 0xB8000usize);
    }
    user_print(b"Aegis: [nx-test] NX FAILED - instruction fetch succeeded\r\n");
    loop {
        core::hint::spin_loop();
    }
}

/// Ring-3 capability-denial demo (master roadmap Phase 3): this task was
/// granted no capabilities — its CSpace is empty from birth (least
/// authority). It attempts the gated ops the client and server use (ipc_call
/// on the endpoint slot, mem_len on a memory-region slot, task_state on a
/// task slot). Every one must be refused with -1 while the kernel and its
/// peers keep running.
extern "sysv64" fn task_denied() -> ! {
    user_print(b"Aegis: [denied] I was granted no capabilities (empty CSpace)\r\n");
    // IPC: attempt to call an endpoint at slot 0 — the client's slot 0 is
    // granted by the server, but this task never received a grant.
    let mut reply = [0u8; 64];
    let msg = b"attempt to reach the echo endpoint";
    let rlen = user_syscall5(
        5,
        0,
        msg.as_ptr() as u64,
        msg.len() as u64,
        reply.as_mut_ptr() as u64,
    );
    user_print(b"Aegis: [denied] ipc_call(slot 0) -> ");
    user_print(if rlen == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    // Memory: attempt to read a region at slot 0.
    let r = user_syscall5(11, 0, 0, 0, 0);
    user_print(b"Aegis: [denied] mem_len(slot 0) -> ");
    user_print(if r == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    // Supervision: attempt to query a task at slot 0.
    let s = user_syscall5(14, 0, 0, 0, 0);
    user_print(b"Aegis: [denied] task_state(slot 0) -> ");
    user_print(if s == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    user_print(b"Aegis: [denied] all denied ops refused; kernel and peers continue\r\n");
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    aegis_kernel::sprintln!("KERNEL PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

#![no_std]
#![no_main]

use aegis_kernel::sprintln;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

#[no_mangle]
pub extern "sysv64" fn _start() -> ! {
    aegis_kernel::serial::SerialWriter::init();
    aegis_kernel::vga::vga_init();

    sprintln!("=== Aegis Phase 2: Bare-Metal Kernel ===");
    sprintln!("Aegis: kernel started (loader handed off at entry)");

    unsafe {
        aegis_kernel::cpu::switch_to_kernel_stack();
    }
    unsafe {
        aegis_kernel::cpu::disable_smep_smap();
    }
    sprintln!(
        "Aegis: kernel stack 0x{:016X} (16 KiB, tail of BSS)",
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
        let caller = (packed >> 32) as u64;
        let rlen = (packed & 0xFFFF_FFFF) as u64;
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

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    aegis_kernel::sprintln!("KERNEL PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

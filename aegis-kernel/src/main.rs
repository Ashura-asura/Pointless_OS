#![no_std]
#![no_main]

use aegis_kernel::sprintln;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

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

    unsafe {
        core::arch::asm!("sti");
    }
    sprintln!("Aegis: interrupts enabled - entering idle loop");

    let mut next_print: u64 = 512;
    loop {
        unsafe { aegis_kernel::tasks::run_idle() };
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
        unsafe { aegis_kernel::tasks::yield_now() };
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
        unsafe { aegis_kernel::tasks::yield_now() };
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    aegis_kernel::sprintln!("KERNEL PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

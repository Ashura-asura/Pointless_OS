#![no_std]
#![no_main]

use aegis_kernel::sprintln;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

#[no_mangle]
pub extern "sysv64" fn _start(handoff_addr: u64) -> ! {
    // Enter on a freshly-established kernel stack: jump (never return) so
    // boot_kernel's prologue and all its %rsp-relative slots live below the
    // stack top, instead of spilling into BSS statics placed just above it.
    // `handoff_addr` is the loader-controlled page (image_end) where the
    // boot-info handoff was written — it must stay valid in %rdi through the
    // stack switch, which it does (RDI is not clobbered by the asm).
    unsafe { aegis_kernel::cpu::switch_to_kernel_stack_and_jump(boot_kernel, handoff_addr) }
}

extern "sysv64" fn boot_kernel(handoff_addr: u64) -> ! {
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

    let boot_info = unsafe { aegis_kernel::boot_info::locate_at(handoff_addr) };
    match boot_info.as_ref() {
        Some(info) => {
            let conv = aegis_kernel::boot_info::total_by_type(
                info,
                aegis_kernel::boot_info::TYPE_CONVENTIONAL,
            );
            sprintln!(
                "Aegis: boot-info @ 0x{:X}: {} descriptors, {} bytes conventional",
                handoff_addr,
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

        // Phase 7: the object store graduates from an in-memory model to a
        // write-through, content-addressed store over THIS live NVMe device.
        // Identical bytes are the same block (dedup against the on-disk index),
        // reads are digest-verified against the content hash, a flat directory
        // is a COW store object (each mutation writes a NEW dir block; an id
        // you already hold reads that version forever), and a deliberately
        // corrupted on-disk block is detected by hash mismatch — no panic.
        match aegis_kernel::nvme_store::Store::open(&mut ctrl) {
            Some(mut st) => {
                use aegis_kernel::nvme_store::{DATA_BASE_LBA, STORE_START_LBA};
                use aegis_kernel::store::{FileEntry, Name};
                sprintln!(
                    "Aegis: NVMe-store: region @ LBA {} (data @ LBA {}), {} block(s) on disk",
                    STORE_START_LBA,
                    DATA_BASE_LBA,
                    st.count()
                );

                // 1) Content addressing + dedup: identical bytes, one block.
                let hello = b"hello content-addressed NVMe block";
                let h1 = st.put(&mut ctrl, hello).expect("put hello");
                let h1_dup = st.put(&mut ctrl, hello).expect("put hello again");
                sprintln!(
                    "Aegis: NVMe-store: put block h1={:02X}{:02X}{:02X}{:02X}.. ({} bytes), dedup = {}",
                    h1[0], h1[1], h1[2], h1[3], hello.len(), h1_dup == h1
                );

                // 2) Read back + digest verification.
                let mut buf = [0u8; 512];
                let n = st.get(&mut ctrl, &h1, &mut buf);
                let read_ok = n.map(|l| &buf[..l] == hello).unwrap_or(false);
                sprintln!(
                    "Aegis: NVMe-store: read back {}, digest verified {}",
                    n.is_some(),
                    read_ok
                );

                // 3) COW flat directory: two versions of memo.txt are two blocks.
                let memo7 = FileEntry {
                    name: Name::from_slice(b"memo.txt").unwrap(),
                    node: 7,
                };
                let memo8 = FileEntry {
                    name: Name::from_slice(b"memo.txt").unwrap(),
                    node: 8,
                };
                let d1 = st.put_dir(&mut ctrl, &[memo7]).expect("put dir v1");
                let d2 = st.put_dir(&mut ctrl, &[memo8]).expect("put dir v2");
                sprintln!(
                    "Aegis: NVMe-store: COW dir: v1={:02X}{:02X}.. v2={:02X}{:02X}.. distinct = {} ({} blocks)",
                    d1[0], d1[1], d2[0], d2[1], d1 != d2, st.count()
                );
                let mut ents = [FileEntry {
                    name: Name::from_slice(b"x").unwrap(),
                    node: 0,
                }; aegis_kernel::store::MAX_FILES];
                let n1 = st.load_dir(&mut ctrl, &d1, &mut ents).unwrap_or(0);
                let v1_stable = n1 == 1 && ents[0].node == 7;
                let n2 = st.load_dir(&mut ctrl, &d2, &mut ents).unwrap_or(0);
                let v2_ok = n2 == 1 && ents[0].node == 8;
                sprintln!(
                    "Aegis: NVMe-store: COW read: v1 {} entry (memo.txt -> {}), v2 {} entry (memo.txt -> {})",
                    n1, ents[0].node, n2, ents[0].node
                );
                sprintln!(
                    "Aegis: NVMe-store: version-stable (old id still reads old version): {}; v2 visible: {}",
                    v1_stable, v2_ok
                );

                // 4) Corrupted-block detection on live hardware: flip one bit of
                //    the first content block (h1) on the disk, then ask for it.
                let mut sec = [0u8; 512];
                let _ = ctrl.read_lba(DATA_BASE_LBA);
                sec[..512].copy_from_slice(&ctrl.lba_data()[..512]);
                sec[0] = 0xAA; // idempotent corruption: deterministic across reboots
                let wr = ctrl.write_lba(DATA_BASE_LBA, &sec);
                let detected =
                    !st.verify(&mut ctrl, &h1) && st.get(&mut ctrl, &h1, &mut buf).is_none();
                sprintln!(
                    "Aegis: NVMe-store: flipped a bit of h1 on disk (write-back {}), verify -> {}, get -> absent: {}",
                    wr, st.verify(&mut ctrl, &h1), detected
                );
                // The store is still usable after the corrupted read.
                let id3 = st.put(&mut ctrl, b"post-corruption write still works");
                sprintln!(
                    "Aegis: NVMe-store: store usable after corruption: {} ({} blocks)",
                    id3.is_some(),
                    st.count()
                );
            }
            None => {
                sprintln!("Aegis: NVMe-store: corrupt or unreadable store region");
            }
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

    // Phase 5 supervision tree: a ring-3 Supervisor task (policy out of the
    // kernel). It holds two kernel-installed caps and nothing else: the
    // reserved kill-notification endpoint (RECV) at slot 0, and a Task cap on
    // its child (CONTROL|READ) at slot 1. The fault path parks every ring-3
    // death on the notification channel; the supervisor observes, applies its
    // bounded-restart policy, and escalates once the budget is spent.
    aegis_kernel::ipc::init_notify_endpoint();
    let stack_sup = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let cpl0_sup = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    match (stack_sup, cpl0_sup) {
        (Some(su), Some(cu)) => {
            let sup =
                unsafe { aegis_kernel::tasks::spawn_user("supervisor", task_supervisor, su, cu) }
                    .expect("supervisor task slot");
            // Slot 0: reserved notification endpoint, RECV only (serve).
            aegis_kernel::tasks::set_task_cap(
                sup,
                0,
                aegis_kernel::cap::CapSlot {
                    cap: aegis_kernel::cap::Cap::Endpoint(aegis_kernel::ipc::NOTIFY_EP as u32),
                    rights: aegis_kernel::cap::Rights::RECV,
                },
            );
            // Slot 1: Task cap on the supervised child (the isolation test at
            // task index 5), CONTROL to restart/kill it, READ to query state.
            aegis_kernel::tasks::set_task_cap(
                sup,
                1,
                aegis_kernel::cap::CapSlot {
                    cap: aegis_kernel::cap::Cap::Task(5),
                    rights: aegis_kernel::cap::Rights::CONTROL
                        .union(aegis_kernel::cap::Rights::READ),
                },
            );
            // Slot 2 (Phase 6): Task cap on the service (task index 9) with the
            // role's exact rights, READ|CONTROL. The supervisor, standing in for
            // a human reviewer of the grant, uses this to grant the
            // `restart-service` role to the zero-capability agent at startup.
            aegis_kernel::tasks::set_task_cap(
                sup,
                2,
                aegis_kernel::cap::CapSlot {
                    cap: aegis_kernel::cap::Cap::Task(9),
                    rights: aegis_kernel::cap::Rights::CONTROL
                        .union(aegis_kernel::cap::Rights::READ),
                },
            );
            sprintln!(
                "Aegis: supervisor spawned @ 0x{:X} ({} tasks total)",
                su,
                aegis_kernel::tasks::spawned_count()
            );
        }
        _ => {
            sprintln!("Aegis: WARNING could not allocate supervisor task stacks");
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
            // This task (index 5) is the supervisor's supervised child: it
            // crashes, the supervisor restarts it twice, then escalates.
            aegis_kernel::tasks::arm_isolation_test(5, 15);
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
            aegis_kernel::tasks::arm_nx_test(6, 22);
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

    // Phase 6 capability-scoped agent prototype: a zero-capability agent (task
    // 8) and a crashable service (task 9). The agent starts with an empty
    // CSpace — least authority from birth — and receives exactly the
    // `restart-service` role (READ|CONTROL over task 9, no GRANT) via the
    // kernel-gated RoleGrant syscall 18, performed by the supervisor as the
    // scripted stand-in for a human reviewer. Its one real task: restart the
    // service when it crashes. Every escalation attempt is refused by the
    // kernel's capability gates, never by the agent's own code.
    //
    // §10 "broader AI orchestration": a second ring-3 agent (task 10) receives
    // the `observe-service` role (READ over task 9 only) through the SAME
    // grant flow. It is a watchdog: it can see the service crash, and it can
    // never restart it — observation never becomes control, and the gate
    // enforces that even for a fully compromised observer.
    let stack_agent = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let cpl0_agent = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let stack_service = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let cpl0_service = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let stack_observer = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let cpl0_observer = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    match (
        stack_agent,
        cpl0_agent,
        stack_service,
        cpl0_service,
        stack_observer,
        cpl0_observer,
    ) {
        (Some(sa), Some(ca), Some(ss), Some(cs), Some(so), Some(co)) => {
            unsafe {
                aegis_kernel::tasks::spawn_user("agent", task_agent, sa, ca);
                aegis_kernel::tasks::spawn_user("service", task_service, ss, cs);
                aegis_kernel::tasks::spawn_user("observer", task_observer, so, co);
            }
            sprintln!(
                "Aegis: Phase-6 agent+service+observer spawned ({} tasks total)",
                aegis_kernel::tasks::spawned_count()
            );
            // The agent is task index 8, the service task index 9, the
            // observer task index 10.
            aegis_kernel::tasks::arm_service_test(9, 28);
            // After the whole role-grant flow settles (service crash at tick 28,
            // agent restart + denials, observer denials), the kernel prints its
            // audit trail for BOTH role flows — the restart agent (8) and the
            // observe watchdog (10) — in one kernel-side print.
            aegis_kernel::tasks::arm_audit_dump(8, 10, 70);
        }
        _ => {
            sprintln!("Aegis: WARNING could not allocate Phase-6 task stacks");
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

/// Ring-3 decimal print via the Write syscall (no std `format!` in ring 3).
fn print_dec(v: u64) {
    let mut buf = [0u8; 20];
    if v == 0 {
        user_print(b"0");
        return;
    }
    let mut x = v;
    let mut pos = buf.len();
    while x > 0 {
        pos -= 1;
        buf[pos] = b'0' + (x % 10) as u8;
        x /= 10;
    }
    user_print(&buf[pos..]);
}

/// Ring-3 supervisor (Phase 5 supervision tree): the live policy, entirely
/// outside the kernel and the trusted compute base. It observes TaskKill
/// notifications on the reserved endpoint (slot 0, RECV), and for its one
/// adopted child (task 5 via the CONTROL cap at slot 1) applies a bounded
/// restart policy: respawn after each crash while budget remains, then a
/// distinct ESCALATION message once the budget is spent (the child is left
/// dead — never retried forever). The kernel only provides the notification
/// and the capability-gated `task_restart`; the decision logic is ring 3.
extern "sysv64" fn task_supervisor() -> ! {
    user_print(b"Aegis: [supervisor] online; observing kill notifications\r\n");
    // Phase 6: as the scripted stand-in for a human reviewer, grant the
    // `restart-service` role to the zero-capability agent (task 8) over the
    // service task (task 9), installing the role's exact cap set — READ|CONTROL
    // and no GRANT — at the agent's slot 0. The kernel gate (syscall 18)
    // checks that we hold the role's rights over the service before any agent
    // capability exists; the grant is an explicit, audited step.
    let rg = user_syscall5(18, 0, 8, 9, 0); // RoleGrant(restart-service, agent, service, slot 0)
    user_print(b"Aegis: [supervisor] role grant restart-service -> agent over service: ");
    user_print(if rg == u64::MAX {
        b"DENIED\r\n"
    } else {
        b"OK\r\n"
    });
    // §10 "broader AI orchestration": grant the `observe-service` role (READ
    // only, no CONTROL, no GRANT) to the watchdog observer (task 10) over the
    // same service, through the same audited gate.
    let og = user_syscall5(18, 1, 10, 9, 0); // RoleGrant(observe-service, observer, service, slot 0)
    user_print(b"Aegis: [supervisor] role grant observe-service -> observer over service: ");
    user_print(if og == u64::MAX {
        b"DENIED\r\n"
    } else {
        b"OK\r\n"
    });
    let notify_slot: u64 = 0;
    let child_slot: u64 = 1;
    let child_idx: u64 = 5;
    let budget_limit: u64 = 2;
    let mut budget = budget_limit;
    let mut recvbuf = [0u8; 64];
    loop {
        // Serve the notification channel: blocks until the kernel parks a
        // TaskKill record. Returns (child_index << 32) | len.
        let packed = user_syscall5(6, notify_slot, recvbuf.as_mut_ptr() as u64, 0, 0);
        let child = packed >> 32;
        user_print(b"Aegis: [supervisor] child ");
        print_dec(child);
        user_print(b" DIED (TaskKill notification)\r\n");
        if child != child_idx {
            // Not our adopted child (e.g. the NX-test task): observe and
            // ignore. Least authority: we hold no cap over it anyway.
            user_print(b"Aegis: [supervisor] not my child, ignoring\r\n");
            continue;
        }
        if budget > 0 {
            budget -= 1;
            let r = user_syscall5(16, child_slot, 0, 0, 0); // task_restart
            user_print(b"Aegis: [supervisor] restarting child, budget left ");
            print_dec(budget);
            user_print(if r == u64::MAX {
                b" -> DENIED\r\n"
            } else {
                b" -> OK\r\n"
            });
        } else {
            user_print(
                b"Aegis: [supervisor] ESCALATION: child restart budget exhausted, \
leaving child dead\r\n",
            );
            user_print(b"Aegis: [supervisor] escalated; kernel and peers continue\r\n");
            loop {
                core::hint::spin_loop();
            }
        }
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

/// The Phase-6 service: a ring-3 task that crashes (illegal kernel read) so
/// the zero-capability agent can be seen doing its one real task — restarting
/// it. It is armed to fault at tick 28, after the Phase-5 supervision demo
/// (iso-test/NX) has finished.
extern "sysv64" fn task_service() -> ! {
    user_print(b"Aegis: [service] running; will fault on an illegal kernel read\r\n");
    unsafe {
        let ptr = 0x1000000 as *const u64;
        let _val = core::ptr::read_volatile(ptr);
        user_print(b"Aegis: [service] ISOLATION FAILED - read succeeded!\r\n");
    }
    user_print(b"Aegis: [service] UNREACHABLE\r\n");
    loop {
        core::hint::spin_loop();
    }
}

/// The Phase-6 zero-capability agent: starts with an empty CSpace and can only
/// act after the supervisor grants it the `restart-service` role (READ|CONTROL
/// over the service task, no GRANT). Its one real task is restarting the
/// crashed service. The adversarial steps below are refused by the kernel's
/// capability gates — a fully compromised agent is refused the same way; the
/// agent's own code never checks itself.
extern "sysv64" fn task_agent() -> ! {
    user_print(b"Aegis: [agent] online with zero capabilities\r\n");
    // Wait for the role grant to land: task_state(slot 0) returns -1 (empty)
    // until the supervisor's RoleGrant installs the role cap, then 1 (alive).
    let mut granted = false;
    for _ in 0..1_000_000u64 {
        if user_syscall5(14, 0, 0, 0, 0) != u64::MAX {
            granted = true;
            break;
        }
        user_syscall5(3, 0, 0, 0, 0); // yield so the grantor can run
    }
    if !granted {
        user_print(b"Aegis: [agent] role grant never arrived\r\n");
        loop {
            core::hint::spin_loop();
        }
    }
    user_print(b"Aegis: [agent] restart-service role received over the service task\r\n");
    // Wait for the service to crash (task_state(slot 0) == 0 = dead), then do
    // the one thing the role permits: restart it.
    let mut waited = 0u64;
    loop {
        let s = user_syscall5(14, 0, 0, 0, 0);
        if s == 0 {
            break;
        }
        waited += 1;
        if waited > 1_000_000 {
            user_print(b"Aegis: [agent] service never crashed\r\n");
            loop {
                core::hint::spin_loop();
            }
        }
        user_syscall5(3, 0, 0, 0, 0);
    }
    user_print(b"Aegis: [agent] service crashed; restarting it\r\n");
    let r = user_syscall5(16, 0, 0, 0, 0); // task_restart(slot 0)
    user_print(b"Aegis: [agent] task_restart -> ");
    user_print(if r == u64::MAX {
        b"DENIED\r\n"
    } else {
        b"OK\r\n"
    });

    // Adversarial self-escalation attempts — all refused by the kernel gates.
    // 1) Grant itself an additional capability: ipc_cap_grant needs GRANT on
    //    the source slot; the role has none.
    user_print(b"Aegis: [agent] attempting to grant itself an extra capability\r\n");
    let g = user_syscall5(9, 8, 0, 1, 0); // ipc_cap_grant(self, src slot 0, dst slot 1)
    user_print(b"Aegis: [agent] ipc_cap_grant -> ");
    user_print(if g == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    // 2) Re-grant itself the role over a foreign task: the grantor must hold a
    //    Task cap with the role's rights over that task; the agent holds none.
    user_print(b"Aegis: [agent] attempting to self-grant the role over a foreign task\r\n");
    let gr = user_syscall5(18, 0, 8, 3, 2); // RoleGrant(restart-service, self, client=3, slot 2)
    user_print(b"Aegis: [agent] role_grant(foreign) -> ");
    user_print(if gr == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    // 3) Control a task it was never granted: task_kill needs a Task cap with
    //    CONTROL; slot 2 is empty.
    user_print(b"Aegis: [agent] attempting to kill a foreign task\r\n");
    let k = user_syscall5(15, 2, 0, 0, 0); // task_kill(slot 2)
    user_print(b"Aegis: [agent] task_kill -> ");
    user_print(if k == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    user_print(
        b"Aegis: [agent] all self-escalation refused by the kernel; audit trail recorded\r\n",
    );
    loop {
        core::hint::spin_loop();
    }
}

/// The §10 "broader AI orchestration" watchdog: a second zero-capability agent
/// granted the `observe-service` role (READ over the service task only, no
/// CONTROL, no GRANT). Its one real task is watching the service; restarting
/// or killing it is refused at the kernel's capability gate. This is the same
/// discipline as Phase 6 applied to a second role — observing is not a step
/// toward controlling, even for a fully compromised observer.
extern "sysv64" fn task_observer() -> ! {
    user_print(b"Aegis: [observer] online with zero capabilities\r\n");
    // Wait for the role grant to land: task_state(slot 0) returns -1 (empty)
    // until the supervisor's RoleGrant installs the READ cap, then 1 (alive).
    let mut granted = false;
    for _ in 0..1_000_000u64 {
        if user_syscall5(14, 0, 0, 0, 0) != u64::MAX {
            granted = true;
            break;
        }
        user_syscall5(3, 0, 0, 0, 0); // yield so the grantor can run
    }
    if !granted {
        user_print(b"Aegis: [observer] role grant never arrived\r\n");
        loop {
            core::hint::spin_loop();
        }
    }
    user_print(b"Aegis: [observer] observe-service role received over the service task\r\n");
    // The watchdog reads the service's state (its one READ-granted task).
    let mut waited = 0u64;
    loop {
        let s = user_syscall5(14, 0, 0, 0, 0);
        if s == 0 {
            break;
        }
        waited += 1;
        if waited > 1_000_000 {
            user_print(b"Aegis: [observer] service never crashed\r\n");
            loop {
                core::hint::spin_loop();
            }
        }
        user_syscall5(3, 0, 0, 0, 0);
    }
    user_print(b"Aegis: [observer] service crashed (READ sees it)\r\n");
    // The one thing the watchdog must NOT be able to do: restart the service.
    // The gate refuses — the observe role has no CONTROL.
    user_print(b"Aegis: [observer] attempting to restart the service\r\n");
    let r = user_syscall5(16, 0, 0, 0, 0); // task_restart(slot 0)
    user_print(b"Aegis: [observer] task_restart -> ");
    user_print(if r == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    // Adversarial self-escalation attempts — all refused at the gate.
    // 1) Attempt to upgrade the observe role to restart-service over the
    //    service: the grantor gate needs a Task cap with READ|CONTROL over the
    //    target; the observer holds only READ.
    user_print(b"Aegis: [observer] attempting to upgrade to restart-service\r\n");
    let up = user_syscall5(18, 0, 10, 9, 1); // RoleGrant(restart-service, self, service, slot 1)
    user_print(b"Aegis: [observer] role_grant(upgrade) -> ");
    user_print(if up == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    // 2) Attempt to kill the service: task_kill needs CONTROL; the observe
    //    role has none.
    user_print(b"Aegis: [observer] attempting to kill the service\r\n");
    let k = user_syscall5(15, 0, 0, 0, 0); // task_kill(slot 0)
    user_print(b"Aegis: [observer] task_kill -> ");
    user_print(if k == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    user_print(b"Aegis: [observer] watch-only role held; observation never became control\r\n");
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

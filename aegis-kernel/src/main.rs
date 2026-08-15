#![no_std]
#![no_main]

use aegis_kernel::sprintln;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

/// Write the first four bytes of `id` into `out` as xx:xx (for demo printout).
fn hex_bytes(id: &[u8; 32], out: &mut [u8; 4]) {
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = id[i];
    }
    let _ = out;
}

// Demo task indices, pinned to the boot spawn order (below). The `input`
// task occupies index 2, so every ring-3 demo task sits one slot higher than
// the pre-shell layout; these constants are the single source of truth so a
// future task can never silently shift a hardcoded index again.
const IDX_ALPHA: u64 = 0;
const IDX_BETA: u64 = 1;
const IDX_INPUT: u64 = 2;
const IDX_SERVER: u64 = 3;
const IDX_CLIENT: u64 = 4;
const IDX_SUPERVISOR: u64 = 5;
const IDX_ISO_TEST: u64 = 6;
const IDX_NX_TEST: u64 = 7;
const IDX_DENIED: u64 = 8;
const IDX_AGENT: u64 = 9;
const IDX_SERVICE: u64 = 10;
const IDX_OBSERVER: u64 = 11;
const IDX_MEM_RM: u64 = 12;
const IDX_MEM_CLIENT: u64 = 13;
const IDX_PARENT_SUP: u64 = 14;
const IDX_LINUX_HELLO: u64 = 15;
const IDX_ADVISOR: u64 = 16;

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
    // Extract the runtime fleet config (FLEET.CFG on the boot volume) and
    // point the interface at the configured IP before NetIf::init. Absent =>
    // compile-time defaults apply.
    let fleet_cfg = unsafe { aegis_kernel::boot_info::fleet_at(handoff_addr) };
    unsafe {
        aegis_kernel::boot_info::set_fleet_config(fleet_cfg);
    }
    if let Some(cfg) = fleet_cfg {
        aegis_kernel::netif::set_our_ip(cfg.my_ip);
        sprintln!(
            "Aegis: fleet cfg: role={} my={}.{}.{}.{} peer={}.{}.{}.{}",
            if cfg.role_is_issuer() {
                "issuer"
            } else {
                "invoker"
            },
            cfg.my_ip[0],
            cfg.my_ip[1],
            cfg.my_ip[2],
            cfg.my_ip[3],
            cfg.peer_ip[0],
            cfg.peer_ip[1],
            cfg.peer_ip[2],
            cfg.peer_ip[3],
        );
    } else {
        sprintln!("Aegis: fleet cfg: absent — compile-time defaults");
    }
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
    sprintln!("Aegis: IDT loaded (exception vectors 0-31 + timer at 0x30 + keyboard at 0x21)");

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

    // Phase H (roadmap §5): minimal GPU framebuffer driver. Probe the
    // display device (Bochs VBE "dispi"), set an 800x600x32 linear mode,
    // and install it as the desktop's second output backend so every
    // boot_blit/handle_key re-blit fans the composited screen out to real
    // pixels in addition to the VGA text cells. Strictly additive: if no
    // Bochs-VBE display is present (or it rejects the mode), the desktop
    // falls back to the text backend alone — the pixel output is a
    // superset of the old proof, never a requirement for it.
    {
        use aegis_kernel::desktop::install_gpu;
        match aegis_kernel::gpu::BochsGpu::probe(&pci) {
            Some(mut g) => {
                let ok = g.set_mode(800, 600);
                sprintln!("Aegis: GPU: set_mode(800x600x32) = {}", ok);
                if ok {
                    unsafe {
                        install_gpu(g);
                    }
                    sprintln!("Aegis: GPU: framebuffer backend installed (desktop -> pixels too)");
                } else {
                    sprintln!("Aegis: GPU: mode rejected - text backend only");
                }
            }
            None => {
                sprintln!("Aegis: GPU: no Bochs-VBE display device - text backend only");
            }
        }
    }

    // Live network stack demo: the q35 NIC (Intel 82574L/e1000e) is attached
    // to a QEMU `socket` netdev. The kernel brings the interface up, resolves
    // the host gateway (10.0.2.2) over real ARP, then opens a TCP socket to
    // the host peer on 10.0.2.2:8080 and drives a real three-way handshake,
    // an HTTP request/response, and a close over the wire. An external process
    // on the host captures every frame (SYN → SYN-ACK → ACK → data → FIN) off
    // the emulated wire into a pcap and serves the peer side. This proves real
    // TCP/IP bytes leaving and re-entering the kernel.
    if aegis_kernel::netif::NetIf::init(&pci) {
        unsafe {
            aegis_kernel::netif::NetIf::with(|net| {
                // Resolve the gateway over real ARP (request + reply exchange).
                let gw = net.arp_resolve(aegis_kernel::netif::GW_IP);
                match gw {
                    Some(mac) => {
                        sprintln!(
                        "Aegis: netif: ARP reply received: gateway at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} @ 10.0.2.2",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    );
                    }
                    None => {
                        sprintln!("Aegis: netif: ARP reply timed out - stack demo skipped");
                        return;
                    }
                }

                // Open a TCP socket bound to exactly one destination (the host's
                // demo server) and connect: sends a real SYN.
                let Some((id, _lp)) = net.socket_open(
                    aegis_kernel::netif::SockKind::Tcp,
                    aegis_kernel::netif::GW_IP,
                    8080,
                    None,
                ) else {
                    sprintln!("Aegis: netif: no free socket slot");
                    return;
                };
                if !net.tcp_connect(id) {
                    sprintln!("Aegis: netif: connect failed");
                    return;
                }
                sprintln!("Aegis: netif: TCP SYN sent (10.0.2.15:40000 -> 10.0.2.2:8080)");

                // Poll until the handshake completes (SYN-ACK arrives and is ACKed).
                let mut spins = 0u64;
                while spins < 50_000_000 {
                    net.poll();
                    if net.socket_connected(id) {
                        break;
                    }
                    spins += 1;
                    core::arch::asm!("pause", options(nomem, nostack));
                }
                match net.socket_state(id) {
                    Some(aegis_kernel::netif::TcpState::Established) => {
                        sprintln!("Aegis: netif: TCP handshake complete (Established)");
                    }
                    Some(_) => {
                        sprintln!("Aegis: netif: handshake timed out");
                        return;
                    }
                    None => {
                        sprintln!("Aegis: netif: socket vanished");
                        return;
                    }
                }

                // Send a real HTTP request.
                const HTTP_REQ: &[u8] = b"GET / HTTP/1.0\r\nHost: 10.0.2.2\r\n\r\n";
                let n = net.socket_send(id, HTTP_REQ);
                sprintln!("Aegis: netif: HTTP request sent ({} bytes)", n);

                // Poll until the response arrives.
                let mut resp = [0u8; 1024];
                let mut got = 0usize;
                let mut spins = 0u64;
                while spins < 50_000_000 && got == 0 {
                    net.poll();
                    if let Some(r) = net.socket_recv(id, &mut resp[got..]) {
                        got += r;
                    }
                    spins += 1;
                    core::arch::asm!("pause", options(nomem, nostack));
                }
                sprintln!("Aegis: netif: HTTP response received ({} bytes)", got);
                if got > 0 {
                    let mut ascii = [0u8; 1024];
                    for i in 0..got {
                        let b = resp[i];
                        ascii[i] = if b == b'\r' || b == b'\n' {
                            b' '
                        } else if b.is_ascii_graphic() || b == b' ' {
                            b
                        } else {
                            b'.'
                        };
                    }
                    if let Ok(s) = core::str::from_utf8(&ascii[..got]) {
                        sprintln!("Aegis: netif: body: {}", s);
                    }
                }

                // Close: sends a real FIN.
                if net.socket_close(id) {
                    sprintln!("Aegis: netif: socket closed (FIN sent)");
                }

                // Live TLS 1.3 demo: a second socket to the host peer on port
                // 8443 (a real OpenSSL-backed TLS server behind memory BIOs).
                // The kernel performs the full handshake: real ClientHello,
                // ServerHello + ECDHE, decrypted EncryptedExtensions /
                // Certificate / CertificateVerify / server Finished, sends its
                // own Finished, then exchanges real encrypted application data
                // (an HTTP request and response).
                let Some((tid, _)) = net.socket_open(
                    aegis_kernel::netif::SockKind::Tcp,
                    aegis_kernel::netif::GW_IP,
                    8443,
                    None,
                ) else {
                    sprintln!("Aegis: tls: no free socket slot");
                    return;
                };
                if !net.tcp_connect(tid) {
                    sprintln!("Aegis: tls: connect failed");
                    return;
                }
                sprintln!("Aegis: tls: TCP SYN sent (10.0.2.15:40002 -> 10.0.2.2:8443)");
                let mut spins = 0u64;
                while spins < 50_000_000 {
                    net.poll();
                    if net.socket_connected(tid) {
                        break;
                    }
                    spins += 1;
                    core::arch::asm!("pause", options(nomem, nostack));
                }
                match net.socket_state(tid) {
                    Some(aegis_kernel::netif::TcpState::Established) => {
                        sprintln!("Aegis: tls: TCP handshake complete (Established)");
                    }
                    Some(_) => {
                        sprintln!("Aegis: tls: handshake timed out");
                        return;
                    }
                    None => {
                        sprintln!("Aegis: tls: socket vanished");
                        return;
                    }
                }

                // Derive the client keyshare and send the real ClientHello.
                let keyshare = aegis_kernel::tls::x25519_base(&aegis_kernel::tls::EPHEMERAL_SCALAR);
                let mut ch_buf = [0u8; 600];
                let ch_len = aegis_kernel::tls::build_client_hello(&keyshare, &mut ch_buf);
                let n = net.socket_send(tid, &ch_buf[..ch_len]);
                sprintln!("Aegis: tls: ClientHello sent ({} bytes)", n);
                // Keep the raw ClientHello handshake message (4-byte header +
                // body) for the transcript.
                let ch_msg = &ch_buf[5..ch_len];

                // Receive and parse the server flight. The first record is the
                // plaintext ServerHello; everything after it is encrypted with
                // the server handshake traffic key.
                let mut rbuf = [0u8; 8192];
                let mut rlen = 0usize;
                let mut tls: Option<aegis_kernel::tls::Tls13Client> = None;
                let mut flight_done = false;
                spins = 0;
                while spins < 80_000_000 && !flight_done {
                    net.poll();
                    if let Some(r) = net.socket_recv(tid, &mut rbuf[rlen..]) {
                        rlen += r;
                    }
                    // Try to consume complete records off the head.
                    loop {
                        if rlen < 5 {
                            break;
                        }
                        let rec_len = 5 + (((rbuf[3] as usize) << 8) | rbuf[4] as usize);
                        if rlen < rec_len {
                            break;
                        }
                        let ct = rbuf[0];
                        let frag = &rbuf[5..rec_len];
                        if tls.is_none() {
                            // Expect the plaintext ServerHello handshake.
                            if ct == aegis_kernel::tls::CT_HANDSHAKE
                                && frag.len() >= 4
                                && frag[0] == aegis_kernel::tls::HS_SERVER_HELLO
                            {
                                let body_len = ((frag[1] as usize) << 16)
                                    | ((frag[2] as usize) << 8)
                                    | frag[3] as usize;
                                if 4 + body_len <= frag.len() {
                                    match aegis_kernel::tls::parse_server_hello(&frag[4..]) {
                                        Some(sh) => {
                                            sprintln!(
                                                "Aegis: tls: ServerHello: version 0x{:04X} cipher 0x{:04X} group 0x{:04X}",
                                                sh.version,
                                                sh.cipher_suite,
                                                sh.key_share_group
                                            );
                                            match aegis_kernel::tls::x25519(
                                                &aegis_kernel::tls::EPHEMERAL_SCALAR,
                                                &sh.key_share_key,
                                            ) {
                                                Some(sec) => {
                                                    sprintln!(
                                                        "Aegis: tls: ECDHE shared secret (kernel side): {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                                                        sec[0], sec[1], sec[2], sec[3], sec[4], sec[5], sec[6], sec[7], sec[8], sec[9], sec[10], sec[11], sec[12], sec[13], sec[14], sec[15], sec[16], sec[17], sec[18], sec[19], sec[20], sec[21], sec[22], sec[23], sec[24], sec[25], sec[26], sec[27], sec[28], sec[29], sec[30], sec[31]
                                                    );
                                                    // Build the client with the
                                                    // CH + SH transcript and
                                                    // derive handshake keys.
                                                    let mut trans =
                                                        aegis_kernel::tls::Transcript::new();
                                                    trans.push_message(ch_msg);
                                                    trans.push_message(frag);
                                                    let c = aegis_kernel::tls::Tls13Client::new(
                                                        sec, trans,
                                                    );
                                                    tls = Some(c);
                                                    // hs transcript includes SH
                                                    // (already pushed).
                                                }
                                                None => {
                                                    sprintln!(
                                                        "Aegis: tls: ECDHE rejected (low-order point)"
                                                    );
                                                    flight_done = true;
                                                }
                                            }
                                        }
                                        None => {
                                            sprintln!("Aegis: tls: ServerHello parse failed");
                                            flight_done = true;
                                        }
                                    }
                                }
                            } else {
                                sprintln!(
                                    "Aegis: tls: expected plaintext ServerHello, got ct {} len {}",
                                    ct,
                                    frag.len()
                                );
                                flight_done = true;
                            }
                        } else {
                            // Encrypted flight: unprotect with the server
                            // handshake key.
                            let client = tls.as_mut().unwrap();
                            let mut plain = [0u8; 8192];
                            match client.unprotect_server_hs(&rbuf[..rec_len], &mut plain) {
                                Some((inner_ct, payload)) => {
                                    if inner_ct == aegis_kernel::tls::CT_HANDSHAKE {
                                        if !client.on_server_handshake_payload(payload) {
                                            sprintln!(
                                                "Aegis: tls: server handshake payload rejected"
                                            );
                                            flight_done = true;
                                        } else if client.server_finished_verified {
                                            sprintln!("Aegis: tls: server Finished verified");
                                            flight_done = true;
                                        }
                                    }
                                }
                                None => {
                                    sprintln!("Aegis: tls: server record auth failed");
                                    flight_done = true;
                                }
                            }
                        }
                        rbuf.copy_within(rec_len..rlen, 0);
                        rlen -= rec_len;
                        if flight_done {
                            break;
                        }
                    }
                    spins += 1;
                    core::arch::asm!("pause", options(nomem, nostack));
                }
                sprintln!(
                    "Aegis: tls: server flight processed ({} bytes buffered)",
                    rlen
                );

                let mut tls = match tls {
                    Some(t) => t,
                    None => {
                        sprintln!("Aegis: tls: no TLS client state");
                        return;
                    }
                };
                if !tls.server_finished_verified {
                    sprintln!("Aegis: tls: server Finished never verified");
                    return;
                }

                // Build and send the client Finished (encrypted).
                let mut cfin = [0u8; 64];
                let nfin = tls
                    .build_client_finished(&mut cfin)
                    .expect("client finished");
                let mut cfrec = [0u8; 200];
                let ncf = tls
                    .protect_hs(&cfin[..nfin], &mut cfrec)
                    .expect("protect hs");
                let ns = net.socket_send(tid, &cfrec[..ncf]);
                sprintln!("Aegis: tls: client Finished sent ({} bytes)", ns);

                // Send the encrypted HTTP request.
                const TLS_REQ: &[u8] = b"GET /aegis-tls HTTP/1.0\r\nHost: aegis\r\n\r\n";
                let mut req_rec = [0u8; 400];
                let nrq = tls.protect_app(TLS_REQ, &mut req_rec).expect("protect app");
                let ns = net.socket_send(tid, &req_rec[..nrq]);
                sprintln!("Aegis: tls: encrypted HTTP request sent ({} bytes)", ns);

                // Receive the encrypted response, unprotect with the server
                // application key, and print the plaintext.
                let mut resp_buf = [0u8; 8192];
                let mut got = 0usize;
                let mut app_done = false;
                spins = 0;
                while spins < 80_000_000 && !app_done {
                    net.poll();
                    if let Some(r) = net.socket_recv(tid, &mut resp_buf[got..]) {
                        got += r;
                    }
                    let mut pos = 0usize;
                    while pos + 5 <= got {
                        let rec_len =
                            5 + (((resp_buf[pos + 3] as usize) << 8) | resp_buf[pos + 4] as usize);
                        if pos + rec_len > got {
                            break;
                        }
                        let mut plain = [0u8; 8192];
                        match tls.unprotect_server_app(&resp_buf[pos..pos + rec_len], &mut plain) {
                            Some((inner_ct, payload))
                                if inner_ct == aegis_kernel::tls::CT_APPLICATION_DATA =>
                            {
                                let mut ascii = [0u8; 8192];
                                let pl = payload.len().min(8192);
                                for i in 0..pl {
                                    let b = payload[i];
                                    ascii[i] = if b == b'\r' || b == b'\n' {
                                        b' '
                                    } else if b.is_ascii_graphic() || b == b' ' {
                                        b
                                    } else {
                                        b'.'
                                    };
                                }
                                if let Ok(s) = core::str::from_utf8(&ascii[..pl]) {
                                    sprintln!("Aegis: tls: HTTPS response body: {}", s);
                                }
                                app_done = true;
                            }
                            Some((inner_ct, _)) => {
                                sprintln!(
                                    "Aegis: tls: non-app inner record ct {} (skipped)",
                                    inner_ct
                                );
                            }
                            None => {
                                sprintln!("Aegis: tls: app record auth failed");
                                app_done = true;
                            }
                        }
                        pos += rec_len;
                    }
                    if pos > 0 {
                        resp_buf.copy_within(pos..got, 0);
                        got -= pos;
                    }
                    spins += 1;
                    core::arch::asm!("pause", options(nomem, nostack));
                }

                // Close: sends a real FIN.
                if net.socket_close(tid) {
                    sprintln!("Aegis: tls: socket closed (FIN sent)");
                }
            });
        }
    } else {
        sprintln!("Aegis: e1000: no NIC found - driver skipped");
    }

    // Phase I: two-node fleet demo. Runs only when the image is built as
    // fleet node A or node B (mutually exclusive features); stripped out
    // entirely on a normal build. When `fleet-j3` is also present, the
    // Phase J-3 mesh demo (two-node consensus + remote invocation of a
    // transferred capability) runs instead, still over the same two-node
    // feature-gated images. The mesh demo is gated on `fleet-j3` alone: its
    // two-node role comes from the runtime FLEET.CFG when present, else from
    // the compile-time node feature.
    #[cfg(feature = "fleet-j3")]
    aegis_kernel::mesh::run_boot_demo();
    #[cfg(all(
        any(feature = "fleet-node-a", feature = "fleet-node-b"),
        not(feature = "fleet-j3")
    ))]
    aegis_kernel::fleet::run_boot_demo();

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

        // Phase G (design doc §7 Phase 3, item 1): every DMA address the NVMe
        // and e1000 drivers handed to hardware above went through the IOMMU
        // (`dma_addr` translates on this device's bdf before any PRP/descriptor
        // is written). Now prove the denial path on the live boot: the NVMe
        // device — a real, wired-up requester with a real domain and real
        // buffers mapped — attempts a DMA to an address that was never mapped
        // into its domain (exactly what a corrupted PRP pointer looks like at
        // this boundary). The IOMMU denies it and records a fault; the kernel
        // keeps running (the FAT/store demos below proceed). The e1000 path was
        // exercised just as hard: every TX/RX ring address in the netif demo
        // was a translated, in-domain address.
        let nvme_bdf = ctrl.iommu_bdf();
        let stray = 0x1_0000_0000u64; // never identity-mapped into the NVMe domain
        let (denied, reason, fault_total) = unsafe {
            aegis_kernel::iommu::with(|i| {
                match i.translate(nvme_bdf, stray, aegis_kernel::iommu::PAGE_READ) {
                    Ok(_) => (false, 0u32, i.fault_count()),
                    Err(r) => (true, r as u32, i.fault_count()),
                }
            })
        };
        let reason_str = match reason {
            0 => "DeviceNotAssigned",
            1 => "AddressNotMapped",
            2 => "PermissionDenied",
            _ => "unknown",
        };
        sprintln!(
            "Aegis: IOMMU: NVMe out-of-domain DMA to {:#x} denied at the IOMMU: {} ({}) — fault_total = {}",
            stray, denied, reason_str, fault_total
        );
        sprintln!(
            "Aegis: IOMMU: device {} (NVMe) isolated: in-domain reads above all passed the gate; out-of-domain attempt refused; kernel continues",
            nvme_bdf
        );

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

                // Phase 8 (roadmap §10 item 2): the package/system-update model
                // graduated onto THIS object store. A package is a manifest +
                // named content-addressed payload blocks; the boot view is a COW
                // directory block (every activate/rollback commits a NEW dir);
                // a candidate "generation" is staged as gen-N without touching
                // `current`; activation flips `current` only after a caller
                // health gate; rollback flips back to the last known good.
                use aegis_kernel::update::{
                    payloads_verify, BootView, Manifest, PayloadFile, UpdateManager,
                };
                {
                    let pak = |n: &[u8], bytes: &'static [u8]| PayloadFile {
                        name: Name::from_slice(n).unwrap(),
                        bytes,
                    };
                    let man = |n: &[u8]| Manifest {
                        name: Name::from_slice(n).unwrap(),
                        ceiling: 2,
                    };
                    let boot = BootView::create(&mut st, &mut ctrl).expect("boot view");
                    let mut um = UpdateManager::attach(&mut st, &mut ctrl, boot);
                    let mut hex = [0u8; 4];
                    hex_bytes(&um.view_id(), &mut hex);
                    sprintln!(
                        "Aegis: system-update: boot view {:02X}{:02X}{:02X}{:02X} created, {} block(s) on disk",
                        hex[0], hex[1], hex[2], hex[3], st.count()
                    );
                    // 1) Stage editor v1 (a candidate generation); the boot
                    //    target (`current`) is untouched by staging alone.
                    let g1 = um
                        .stage(
                            &mut st,
                            &mut ctrl,
                            man(b"editor"),
                            &[pak(b"main.bin", b"editor v1: hello update")],
                        )
                        .expect("stage editor v1");
                    sprintln!(
                        "Aegis: system-update: staged gen-1 (editor v1), boot target still empty: {}",
                        um.boot_target(&mut st, &mut ctrl).is_none()
                    );
                    // 2) Activation is health-gated: a health check that refuses
                    //    leaves `current` untouched.
                    let refused = um.activate(&mut st, &mut ctrl, &g1, |_, _, _| false);
                    let still_empty = um.boot_target(&mut st, &mut ctrl).is_none();
                    sprintln!(
                        "Aegis: system-update: health-gated activation refused = {}; boot target unchanged = {}",
                        refused, still_empty
                    );
                    // 3) A real gate: every payload block must digest-verify.
                    let accepted = um.activate(&mut st, &mut ctrl, &g1, payloads_verify);
                    let target1 = um.boot_target(&mut st, &mut ctrl);
                    sprintln!(
                        "Aegis: system-update: payload-verified activate = {}; target = gen-{} package=editor, {} block(s)",
                        accepted,
                        target1.as_ref().map(|d| d.n).unwrap_or(0),
                        st.count()
                    );
                    // 4) Stage editor v2 and activate: candidate stays installed,
                    //    boot flips, and the view is a NEW dir block (COW).
                    let before = um.view_id();
                    let g2 = um
                        .stage(
                            &mut st,
                            &mut ctrl,
                            man(b"editor"),
                            &[pak(b"main.bin", b"editor v2: the upgrade")],
                        )
                        .expect("stage editor v2");
                    let accepted2 = um.activate(&mut st, &mut ctrl, &g2, payloads_verify);
                    let target2 = um.boot_target(&mut st, &mut ctrl);
                    sprintln!(
                        "Aegis: system-update: v2 activate = {}; target = gen-{}; COW: view flipped to a new dir block = {}",
                        accepted2,
                        target2.as_ref().map(|d| d.n).unwrap_or(0),
                        before != um.view_id()
                    );
                    // 5) Rollback: the boot target returns to the last known
                    //    good (gen-1), and the dethroned gen is dropped so a
                    //    second rollback has nothing more to restore.
                    let rolled = um.rollback(&mut st, &mut ctrl);
                    let second = um.rollback(&mut st, &mut ctrl);
                    let target_after = um.boot_target(&mut st, &mut ctrl);
                    sprintln!(
                        "Aegis: system-update: rollback to gen-{}; boot target now gen-{}; second rollback empty = {}",
                        rolled.unwrap_or(0),
                        target_after.as_ref().map(|d| d.n).unwrap_or(0),
                        second.is_none()
                    );
                    // 6) Dedup across packages: installing a SECOND package that
                    //    ships the same payload bytes costs no new data block.
                    let base = st.count();
                    let g3 = um
                        .stage(
                            &mut st,
                            &mut ctrl,
                            man(b"editor"),
                            &[pak(b"main.bin", b"editor v1: hello update")],
                        )
                        .expect("stage editor v1 again");
                    let _ = g3;
                    let mut phex = [0u8; 4];
                    hex_bytes(&g1.payload[0], &mut phex);
                    sprintln!(
                        "Aegis: system-update: reinstall of the same payload dedups: h1={:02X}{:02X}{:02X}{:02X} h2={:02X}{:02X}{:02X}{:02X} equal = {}; {} block(s) added",
                        phex[0], phex[1], phex[2], phex[3],
                        g3.payload[0][0], g3.payload[0][1], g3.payload[0][2], g3.payload[0][3],
                        g3.payload[0] == g1.payload[0],
                        st.count() - base
                    );
                    sprintln!("Aegis: system-update: full install -> stage -> health-gated activate -> rollback cycle persisted to the boot device");
                }
            }
            None => {
                sprintln!("Aegis: NVMe-store: corrupt or unreadable store region");
            }
        }

        // Phase 8/9 (roadmap §10 item 1: Windows/Linux compat) exercised live.
        // Each personality layer translates its ABI syscalls into capability-
        // scoped Aegis operations and gates each on the context's scope — the
        // same AI/agent ceiling that applies to native code. Fully-faithful
        // execution would need a real ring-3 trap (Linux) or a hypervisor
        // (Windows); both are out of this bare-metal substrate, so this is the
        // WSL2-lineage / narrow-Win32-subset translation boundary, proven here
        // end-to-end with capability gating.
        {
            use aegis_kernel::agent::CapabilityScope;
            use aegis_kernel::linux_abi::{
                AegisOperation as LOp, SyscallArgs, SYS_MMAP, SYS_WRITE,
            };
            use aegis_kernel::linux_compat::{LinuxCompatLayer, Personality as LP};
            use aegis_kernel::nt_abi::{
                AegisOperation as WOp, NtArgs, NT_MAP_VIEW_OF_SECTION, NT_WRITE_FILE,
            };
            use aegis_kernel::win_compat::{Personality as WP, WindowsCompatLayer};

            // Linux-compat: a file-scoped context translates write, is refused mmap.
            let mut lin = LinuxCompatLayer::new();
            let lin_id = lin
                .register(LP::LinuxCompat, CapabilityScope::restrictive())
                .unwrap();
            let w = lin
                .dispatch(
                    lin_id,
                    SYS_WRITE,
                    SyscallArgs {
                        arg1: 1,
                        arg3: 64,
                        ..Default::default()
                    },
                )
                .unwrap();
            let m = lin.dispatch(
                lin_id,
                SYS_MMAP,
                SyscallArgs {
                    arg2: 0x1000,
                    arg3: 3,
                    ..Default::default()
                },
            );
            sprintln!(
                "Aegis: compat-linux: translate write -> {}; mmap denied (file-only scope) = {}; denials = {}",
                matches!(w, LOp::Write { fd: 1, count: 64 }),
                m.is_err(),
                lin.denials(lin_id).unwrap_or(0)
            );

            // Windows-compat: same gating, different ABI.
            let mut win = WindowsCompatLayer::new();
            let win_id = win
                .register(WP::WindowsCompat, CapabilityScope::restrictive())
                .unwrap();
            let wf = win
                .dispatch(
                    win_id,
                    NT_WRITE_FILE,
                    NtArgs {
                        arg1: 1,
                        arg3: 64,
                        ..Default::default()
                    },
                )
                .unwrap();
            let mv = win.dispatch(
                win_id,
                NT_MAP_VIEW_OF_SECTION,
                NtArgs {
                    arg3: 0x1000,
                    ..Default::default()
                },
            );
            sprintln!(
                "Aegis: compat-windows: translate NtWriteFile -> {}; NtMapView denied (file-only scope) = {}; denials = {}",
                matches!(wf, WOp::WriteFile { handle: 1, count: 64 }),
                mv.is_err(),
                win.denials(win_id).unwrap_or(0)
            );
            sprintln!(
                "Aegis: compat: both translation layers exercised live with capability gating (no real ring-3 trap / hypervisor in this substrate — inherent limit, per roadmap §10)"
            );
        }
    } else {
        sprintln!("Aegis: NVMe: no controller with a mapped BAR");
    }

    // Phase C: the full POSIX view over the in-kernel object store — a
    // hierarchical namespace (nested directories, path resolution, cwd,
    // mode/uid metadata) replacing the flat single-level projection. Files
    // and directories are nothing but COW store objects; a mutation commits
    // new versions of every dir on the root->parent path (path
    // persistence). The authority that gates access stays capability-shaped
    // (region caps); mode bits are compat metadata for the projection.
    {
        use aegis_kernel::store::{EntryKind, TreeView, MAX_FILES, MODE_DIR, MODE_FILE};
        let mut st = aegis_kernel::store::Store::new();
        let mut view = TreeView::new(&mut st).expect("tree view");
        let mkd = |v: &mut TreeView, s: &mut aegis_kernel::store::Store, p: &[u8]| {
            v.mkdir(s, p, MODE_DIR)
        };
        let ok_home = mkd(&mut view, &mut st, b"/home");
        let ok_alice = mkd(&mut view, &mut st, b"/home/alice");
        let ok_docs = mkd(&mut view, &mut st, b"/home/alice/docs");
        let ok_f = view.create_file(&mut st, b"/home/alice/docs/report.txt", MODE_FILE);
        let ok_w = view.write_file(
            &mut st,
            b"/home/alice/docs/report.txt",
            b"Phase C: nested POSIX view",
        );
        sprintln!(
            "Aegis: POSIX-view: nested /home/alice/docs/report.txt mkdir {}/{}/{} file {} write {} ({} blocks)",
            ok_home, ok_alice, ok_docs, ok_f, ok_w, st.block_count()
        );

        let mut buf = [0u8; 128];
        let n = view
            .read_file(&mut st, b"/home/alice/docs/report.txt", &mut buf)
            .unwrap_or(0);
        sprintln!(
            "Aegis: POSIX-view: read back {} bytes: {}",
            n,
            core::str::from_utf8(&buf[..n]).unwrap_or("?")
        );

        // Relative paths + cwd + `.`/`..` resolution.
        let cd_ok = view.cd(&mut st, b"/home/alice");
        let n_rel = view
            .read_file(&mut st, b"docs/report.txt", &mut buf)
            .unwrap_or(0);
        let n_dot = view
            .read_file(&mut st, b"./docs/../docs/report.txt", &mut buf)
            .unwrap_or(0);
        let n_abs = view
            .read_file(&mut st, b"/home/alice/docs/report.txt", &mut buf)
            .unwrap_or(0);
        sprintln!(
            "Aegis: POSIX-view: cd {} ; relative {} ; ././/.. {} ; absolute {} (same = {})",
            cd_ok,
            n_rel == n,
            n_dot == n,
            n_abs == n,
            n_rel == n && n_dot == n && n_abs == n
        );

        // stat: kind + mode metadata + size.
        let (kind, mode, _uid, size) =
            view.stat(&mut st, b"docs/report.txt")
                .unwrap_or((EntryKind::File, 0, 0, 0));
        sprintln!(
            "Aegis: POSIX-view: stat mode={:04o} kind={} size={}",
            mode,
            if kind == EntryKind::Dir {
                "dir"
            } else {
                "file"
            },
            size
        );

        // COW all the way up: a mutation rewrites the root; the old root
        // still reads the old tree.
        let root_v1 = view.root();
        let ok_notes = view.create_file(&mut st, b"docs/notes.txt", MODE_FILE);
        let root_v2 = view.root();
        let mut old_ents = [aegis_kernel::store::PEntry {
            name: aegis_kernel::store::Name::from_slice(b"x").unwrap(),
            kind: EntryKind::File,
            mode: 0,
            uid: 0,
            node: 0,
        }; MAX_FILES];
        let n_old = view
            .snapshot_dir(&mut st, root_v1, &mut old_ents)
            .unwrap_or(0);
        let still_home = old_ents[..n_old].iter().any(|e| e.name.matches(b"home"));
        sprintln!(
            "Aegis: POSIX-view: COW to the root: root rewritten = {}, old root lists {} entry(s), home still there = {} (notes create {})",
            root_v1 != root_v2, n_old, still_home, ok_notes
        );

        // rmdir/unlink: an empty dir is removable, a non-empty one is not,
        // and the root is never removable.
        let ok_rm_notes = view.unlink(&mut st, b"docs/notes.txt");
        let ok_rm_empty =
            view.mkdir(&mut st, b"docs/tmp", MODE_DIR) && view.rmdir(&mut st, b"docs/tmp");
        let ok_rm_nonempty = view.rmdir(&mut st, b"docs");
        let root_refused = !view.rmdir(&mut st, b"/");
        sprintln!(
            "Aegis: POSIX-view: unlink {} ; rmdir empty {} ; rmdir non-empty {} ; root not removable = {}",
            ok_rm_notes, ok_rm_empty, ok_rm_nonempty, root_refused
        );

        // The relationship index still rebuilds from the WAL after all the
        // tree activity (graph as index, not ground truth).
        let mut idx = aegis_kernel::store::RelationshipIndex::new();
        idx.ingest(st.wal());
        let nodes = idx.node_count();
        let mut fresh = aegis_kernel::store::RelationshipIndex::new();
        fresh.rebuild(st.wal());
        sprintln!(
            "Aegis: POSIX-view: index consumed {} WAL seq(s), {} node(s), rebuild identical = {}",
            idx.consumed_seq(),
            nodes,
            fresh.node_count() == nodes
        );
    }

    // Phase 9/10 (roadmap §10 item 3) + item 4: the graphical shell's live
    // desktop, now the kernel's default post-boot state. A compositor turns
    // the window manager's z-ordered window list plus per-window framebuffers
    // into a single composited screen: higher windows occlude lower ones in
    // overlap, and every surface is clipped to its region and the screen
    // bounds. Honest substrate: the VM's real display is the VGA text-mode
    // buffer, so a "pixel" is one text cell (char | attr<<8). The desktop
    // object is installed here so the PS/2 input path can re-composite and
    // re-blit it live (see `task_input`). The shell window — a prompt with
    // typed-character echo — is what the machine boots into; no demo windows.
    {
        use aegis_kernel::desktop::{Desktop, SH, SHELL_W, SHELL_X, SHELL_Y, SW};
        let d = Desktop::new();
        let screen = d.screen();

        // The default post-boot surface: the focused shell window renders the
        // prompt `aegis:~$ ` at its origin, and the status bar spans the
        // bottom row. Verify the composited screen shows them.
        let prompt_cell = (screen[SHELL_Y as usize * SW + SHELL_X as usize] & 0xFF) as u8;
        let status_ok = (screen[(SH - 1) * SW] & 0xFF) as u8 == b'-';
        sprintln!(
            "Aegis: shell-compositor: boot shell surface: prompt first cell '{}' @ ({},{}), status bar = {}, {} windows",
            prompt_cell as char,
            SHELL_X,
            SHELL_Y,
            status_ok,
            d.window_count()
        );

        // Render three rows of the composited screen as characters so the
        // result is visible in the serial log (shell window is 60x12 @ 2,2).
        for sy in [2usize, 3, 4] {
            let mut rowbuf = [0u8; SW];
            for (sx, cell) in rowbuf.iter_mut().enumerate() {
                *cell = (screen[sy * SW + sx] & 0xFF) as u8;
            }
            let rowstr = core::str::from_utf8(&rowbuf).unwrap_or("");
            sprintln!("Aegis: shell-compositor: row{}: |{}|", sy, rowstr);
        }
        sprintln!(
            "Aegis: shell-compositor: composited {}x{} screen from {} windows (shell window {}x{} @ ({},{}); VGA text substrate; compositor is ordinary userspace-style UI work, per roadmap §10 item 3)",
            SW,
            SH,
            d.window_count(),
            SHELL_W,
            aegis_kernel::desktop::SHELL_H,
            SHELL_X,
            SHELL_Y
        );
        unsafe {
            aegis_kernel::desktop::install(d);
        }
    }

    unsafe {
        aegis_kernel::cpu::init_lapic_timer();
    }
    sprintln!("Aegis: LAPIC timer armed (periodic, vector 0x30)");

    // Phase 10 item 4 (interactive shell): one real input path. Remap the
    // legacy PIC so IRQ1 -> vector 0x21, route it through the LAPIC in
    // virtual-wire mode (LVT0 ExtINT), then bring the PS/2 controller up.
    unsafe {
        aegis_kernel::cpu::init_legacy_pic_irq1();
    }
    sprintln!("Aegis: legacy PIC remapped; IRQ1 (keyboard) -> 0x21 via LAPIC LVT0 ExtINT");
    unsafe {
        aegis_kernel::ps2::init();
    }

    // Two kernel tasks, each on a 16 KiB stack carved from the frame
    // allocator (4 consecutive frames per task).
    let stack_alpha = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let stack_beta = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    let stack_input = unsafe {
        aegis_kernel::frame::alloc_contiguous_global(aegis_kernel::tasks::TASK_STACK_SIZE / 4096)
    };
    match (stack_alpha, stack_beta, stack_input) {
        (Some(sa), Some(sb), Some(si)) => {
            unsafe {
                aegis_kernel::tasks::spawn("alpha", task_alpha, sa);
                aegis_kernel::tasks::spawn("beta", task_beta, sb);
                aegis_kernel::tasks::spawn("input", task_input, si);
            }
            sprintln!(
                "Aegis: tasks spawned: alpha @ 0x{:X}, beta @ 0x{:X}, input @ 0x{:X} ({} tasks)",
                sa,
                sb,
                si,
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
            // task index IDX_ISO_TEST), CONTROL to restart/kill it, READ to query
            // state.
            aegis_kernel::tasks::set_task_cap(
                sup,
                1,
                aegis_kernel::cap::CapSlot {
                    cap: aegis_kernel::cap::Cap::Task(IDX_ISO_TEST as u32),
                    rights: aegis_kernel::cap::Rights::CONTROL
                        .union(aegis_kernel::cap::Rights::READ),
                },
            );
            // Slot 2 (Phase 6): Task cap on the service (task index IDX_SERVICE)
            // with the role's exact rights, READ|CONTROL. The supervisor,
            // standing in for a human reviewer of the grant, uses this to grant
            // the `restart-service` role to the zero-capability agent at startup.
            aegis_kernel::tasks::set_task_cap(
                sup,
                2,
                aegis_kernel::cap::CapSlot {
                    cap: aegis_kernel::cap::Cap::Task(IDX_SERVICE as u32),
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
            // This task (index IDX_ISO_TEST) is the supervisor's supervised
            // child: it crashes, the supervisor restarts it twice, then
            // escalates to its parent (IDX_PARENT_SUP), which adopts the
            // subsystem with a fresh budget.
            aegis_kernel::tasks::arm_isolation_test(IDX_ISO_TEST as usize, 15);
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
            aegis_kernel::tasks::arm_nx_test(IDX_NX_TEST as usize, 22);
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
    // IDX_AGENT) and a crashable service (task IDX_SERVICE). The agent starts
    // with an empty CSpace — least authority from birth — and receives exactly
    // the `restart-service` role (READ|CONTROL over the service, no GRANT) via
    // the kernel-gated RoleGrant syscall 18, performed by the supervisor as the
    // scripted stand-in for a human reviewer. Its one real task: restart the
    // service when it crashes. Every escalation attempt is refused by the
    // kernel's capability gates, never by the agent's own code.
    //
    // §10 "broader AI orchestration": a second ring-3 agent (task
    // IDX_OBSERVER) receives the `observe-service` role (READ over the service
    // only) through the SAME grant flow. It is a watchdog: it can see the
    // service crash, and it can never restart it — observation never becomes
    // control, and the gate enforces that even for a fully compromised observer.
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
            // The agent is task index IDX_AGENT, the service task index
            // IDX_SERVICE, the observer task index IDX_OBSERVER.
            aegis_kernel::tasks::arm_service_test(IDX_SERVICE as usize, 28);
            // After the whole role-grant flow settles (service crash at tick 28,
            // agent restart + denials, observer denials), the kernel prints its
            // audit trail for BOTH role flows — the restart agent (IDX_AGENT)
            // and the observe watchdog (IDX_OBSERVER) — in one kernel-side print.
            aegis_kernel::tasks::arm_audit_dump(IDX_AGENT as usize, IDX_OBSERVER as usize, 70);
        }
        _ => {
            sprintln!("Aegis: WARNING could not allocate Phase-6 task stacks");
        }
    }

    // Phase B: userspace resource managers + hierarchical supervision. Three
    // new ring-3 tasks join the running system:
    //   mem-rm   (IDX_MEM_RM, 12): a userspace memory-PAGE manager. It mints
    //            two regions (its pool), holds their anchors, and hands them
    //            out / recycles them purely through capability-gated IPC —
    //            "alloc" grants a copy, "free" revokes it, so a client's page
    //            returns to the manager the moment the client returns it.
    //   mem-client (IDX_MEM_CLIENT, 13): exercises the manager end-to-end.
    //   parent-sup (IDX_PARENT_SUP, 14): the supervisor ABOVE the existing
    //            ring-3 supervisor. It holds a NOTIFY_EP RECV cap (slot 0)
    //            and a Task cap on the iso-test subsystem (CONTROL|READ,
    //            slot 1), kernel-installed here. When the child supervisor's
    //            restart budget is spent it calls back up; the parent ADOPTS
    //            the subsystem with a fresh budget and keeps supervising it.
    {
        let stack_memrm = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        let cpl0_memrm = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        let stack_memcli = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        let cpl0_memcli = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        let stack_parent = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        let cpl0_parent = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        match (
            stack_memrm,
            cpl0_memrm,
            stack_memcli,
            cpl0_memcli,
            stack_parent,
            cpl0_parent,
        ) {
            (Some(sm), Some(cm), Some(sc), Some(cc), Some(sp), Some(cp)) => {
                unsafe {
                    aegis_kernel::tasks::spawn_user("mem-rm", task_mem_rm, sm, cm);
                    aegis_kernel::tasks::spawn_user("mem-client", task_mem_client, sc, cc);
                    aegis_kernel::tasks::spawn_user("parent-sup", task_parent_supervisor, sp, cp);
                    // parent-sup boots with its supervisor-side caps
                    // kernel-installed: NOTIFY_EP receive (slot 0) and a Task
                    // cap on the iso-test subsystem it will adopt (slot 1).
                    aegis_kernel::tasks::set_task_cap(
                        IDX_PARENT_SUP as usize,
                        0,
                        aegis_kernel::cap::CapSlot {
                            cap: aegis_kernel::cap::Cap::Endpoint(
                                aegis_kernel::ipc::NOTIFY_EP as u32,
                            ),
                            rights: aegis_kernel::cap::Rights::RECV,
                        },
                    );
                    aegis_kernel::tasks::set_task_cap(
                        IDX_PARENT_SUP as usize,
                        1,
                        aegis_kernel::cap::CapSlot {
                            cap: aegis_kernel::cap::Cap::Task(IDX_ISO_TEST as u32),
                            rights: aegis_kernel::cap::Rights::CONTROL
                                .union(aegis_kernel::cap::Rights::READ),
                        },
                    );
                }
                sprintln!(
                    "Aegis: Phase-B mem-rm+mem-client+parent-sup spawned ({} tasks total)",
                    aegis_kernel::tasks::spawned_count()
                );
            }
            _ => {
                sprintln!("Aegis: WARNING could not allocate Phase-B task stacks");
            }
        }
    }

    // Phase J: the real ring-3 execution vehicle. A genuine static Linux
    // ELF binary (linux-hello.elf, built from linux-hello.ll — see
    // build-linux-hello.bat) is parsed by the kernel's own ELF loader,
    // mapped as an executable R+E page in a fresh ring-3 task, and run.
    // Its `int 0x80` syscalls (real Linux numbers + register convention)
    // are routed by syscall.rs to the Linux personality's capability gate
    // (linux_compat_elf.rs). Two 16 KiB regions — task stack + CPL0 stack —
    // are allocated like every other ring-3 task's. Spawned last so the
    // IDX_* spawn-order contract below stays intact.
    {
        let stk = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        let cpl0 = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        match (stk, cpl0) {
            (Some(s), Some(c)) => {
                let idx = unsafe { aegis_kernel::linux_compat_elf::spawn_linux_hello(s, c) };
                match idx {
                    Ok(i) => sprintln!(
                        "Aegis: Phase-J: real Linux ELF binary spawned as ring-3 task {} (stack@0x{:X}) — syscalls will route via int 0x80 to the Linux capability gate",
                        i, s
                    ),
                    Err(e) => sprintln!("Aegis: Phase-J: spawn failed: {}", e),
                }
            }
            _ => sprintln!("Aegis: Phase-J: could not allocate task stacks"),
        }
    }

    // Phase F / J-2: the `query-advisor` role's live wiring. The advisor
    // task is a zero-capability ring-3 task at birth; it only gains a cap
    // when the supervisor grants it the `query-advisor` role (role id 2)
    // over the watched service during its escalation branch. That grant
    // mints a NetEndpoint bound to the kernel-declared advisor host
    // (netif.rs `open_advisor_endpoint`), so the advisor never names a
    // destination — it can only ever talk to the host the kernel declares.
    // Spawned last so the IDX_* spawn-order contract stays intact.
    {
        let stk = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        let cpl0 = unsafe {
            aegis_kernel::frame::alloc_contiguous_global(
                aegis_kernel::tasks::TASK_STACK_SIZE / 4096,
            )
        };
        match (stk, cpl0) {
            (Some(s), Some(c)) => {
                unsafe {
                    aegis_kernel::tasks::spawn_user("advisor", task_advisor, s, c);
                }
                sprintln!(
                    "Aegis: Phase-F J-2: advisor task spawned ({} tasks total)",
                    aegis_kernel::tasks::spawned_count()
                );
            }
            _ => sprintln!("Aegis: Phase-F J-2: could not allocate advisor task stacks"),
        }
    }

    // Guard the spawn-order contract the IDX_* constants document: the task
    // table is built purely by spawn order, so a future task inserted out of
    // line silently shifts every hardcoded index (the exact regression that
    // broke the live demos before these constants existed). Assert both the
    // order and the running count here, so a drift fails at boot instead of
    // surfacing as a dead demo miles later.
    {
        const ORDER: [u64; 17] = [
            IDX_ALPHA,
            IDX_BETA,
            IDX_INPUT,
            IDX_SERVER,
            IDX_CLIENT,
            IDX_SUPERVISOR,
            IDX_ISO_TEST,
            IDX_NX_TEST,
            IDX_DENIED,
            IDX_AGENT,
            IDX_SERVICE,
            IDX_OBSERVER,
            IDX_MEM_RM,
            IDX_MEM_CLIENT,
            IDX_PARENT_SUP,
            IDX_LINUX_HELLO,
            IDX_ADVISOR,
        ];
        for (i, &idx) in ORDER.iter().enumerate() {
            assert_eq!(
                i as u64, idx,
                "spawn-order constant drift at position {}",
                i
            );
        }
        let n = aegis_kernel::tasks::spawned_count();
        assert_eq!(n, ORDER.len(), "task table count != documented spawn order");
        sprintln!(
            "Aegis: spawn-order contract guarded ({} tasks, constants in order)",
            n
        );
    }

    // All boot/demo output has printed; put the composited desktop on the
    // real VGA display and freeze further console mirroring, so the VM
    // display settles on the GUI for the rest of the run.
    if aegis_kernel::desktop::boot_blit() {
        sprintln!("Aegis: compositor desktop shown on the VM display");
        aegis_kernel::vga::vga_dump_buffer();
    }

    // Phase K (feature-gated): VT-x bring-up demo. Last thing before
    // interrupts turn on and the idle loop owns the machine. `vmx_supported()`
    // is a cheap no-op CPUID check; `bringup_demo()` only runs when VT-x is
    // actually present. On a CPU without VT-x this prints and falls through to
    // the normal idle boot — one `if` branch, zero behavior change. On a
    // VMX-capable CPU it launches the real-mode guest and HALTS after the
    // first real VM-exit (single round trip, no vmresume) — that halt is the
    // demo's terminal state, so this must sit after every boot demo a test
    // image still needs, which it does.
    #[cfg(feature = "vmx-demo")]
    {
        if aegis_kernel::vmx::vmx_supported() {
            sprintln!("Aegis: [vmx] VT-x present — running bring-up demo");
            unsafe {
                let _ = aegis_kernel::vmx::bringup_demo();
            }
            // Only reached if bring-up failed before a successful VM-entry.
            sprintln!("Aegis: [vmx] bring-up demo returned (pre-entry failure, see above)");
        } else {
            sprintln!("Aegis: [vmx] no VT-x on this CPU — skipping VMX bring-up demo");
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
/// it whenever no task is runnable. The keyboard ring buffer is drained by
/// the dedicated `task_input` kernel task (which the round-robin actually
/// schedules), so input is serviced even though the demo tasks never block.
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

/// Kernel input task: drains the PS/2 ring buffer and applies each keypress
/// to the live desktop (Tab cycles focus, arrows move the focused window),
/// re-compositing and re-blitting, then prints the outcome over serial —
/// the keypress-driven analogue of the boot-time occlusion assertion. Runs
/// forever like alpha/beta; the timer preempts it round-robin.
extern "sysv64" fn task_input() -> ! {
    sprintln!("Aegis: [input] online (PS/2 -> desktop)");
    loop {
        while let Some(ev) = aegis_kernel::ps2::pop_event() {
            if let aegis_kernel::input::InputEvent::Key(ke) = ev {
                if ke.pressed {
                    if let Some(out) = aegis_kernel::desktop::handle_key(ke) {
                        match out {
                            aegis_kernel::desktop::KeyOutcome::Echoed { window_id, ch, pos } => {
                                sprintln!(
                                    "Aegis: shell-compositor@key: echo '{}' -> window id={} line pos={}",
                                    ch as char,
                                    window_id,
                                    pos
                                );
                            }
                            aegis_kernel::desktop::KeyOutcome::Backspace { window_id, pos } => {
                                sprintln!(
                                    "Aegis: shell-compositor@key: backspace -> window id={} line pos={}",
                                    window_id,
                                    pos
                                );
                            }
                            aegis_kernel::desktop::KeyOutcome::Enter { window_id, len } => {
                                sprintln!(
                                    "Aegis: shell-compositor@key: enter -> window id={} submitted {} char(s)",
                                    window_id,
                                    len
                                );
                            }
                            aegis_kernel::desktop::KeyOutcome::Moved { window_id, x, y } => {
                                sprintln!(
                                    "Aegis: shell-compositor@key: arrow -> window id={} moved to ({},{})",
                                    window_id,
                                    x,
                                    y
                                );
                            }
                        }
                    }
                }
            }
        }
        core::hint::spin_loop();
        // Service the NIC's RX ring when present: the boot demos self-poll,
        // but once they return nothing else would drain frames — and the
        // Phase F/J-2 advisor task's TCP exchange over the kernel-minted
        // endpoint needs that drain to keep making progress. Guarded so the
        // fleet build (no NIC) and a headless probe are unaffected.
        unsafe {
            aegis_kernel::netif::NetIf::with(|net| {
                if net.nic.is_some() {
                    net.poll();
                }
            });
        }
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

    // Grant the endpoint capability to the client (task index IDX_CLIENT,
    // slot 0).
    let client_idx: u64 = IDX_CLIENT;
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
/// adopted child (task IDX_ISO_TEST via the CONTROL cap at slot 1) applies a
/// bounded restart policy: respawn after each crash while budget remains,
/// then a distinct ESCALATION message once the budget is spent — the child
/// is left dead (never retried forever). Phase B: the escalation is now a
/// real surrender — the supervisor hands the subsystem to its ring-3 parent
/// (IDX_PARENT_SUP) via IPC, and the parent adopts it with a fresh budget.
/// The kernel only provides the notification and the capability-gated
/// `task_restart`; the decision logic is ring 3.
extern "sysv64" fn task_supervisor() -> ! {
    user_print(b"Aegis: [supervisor] online; observing kill notifications\r\n");
    // Phase 6: as the scripted stand-in for a human reviewer, grant the
    // `restart-service` role to the zero-capability agent (task IDX_AGENT)
    // over the service task (IDX_SERVICE), installing the role's exact cap set
    // — READ|CONTROL and no GRANT — at the agent's slot 0. The kernel gate
    // (syscall 18) checks that we hold the role's rights over the service
    // before any agent capability exists; the grant is an explicit, audited
    // step.
    let rg = user_syscall5(18, 0, IDX_AGENT, IDX_SERVICE, 0); // RoleGrant(restart-service, agent, service, slot 0)
    user_print(b"Aegis: [supervisor] role grant restart-service -> agent over service: ");
    user_print(if rg == u64::MAX {
        b"DENIED\r\n"
    } else {
        b"OK\r\n"
    });
    // §10 "broader AI orchestration": grant the `observe-service` role (READ
    // only, no CONTROL, no GRANT) to the watchdog observer (task
    // IDX_OBSERVER) over the same service, through the same audited gate.
    let og = user_syscall5(18, 1, IDX_OBSERVER, IDX_SERVICE, 0); // RoleGrant(observe-service, observer, service, slot 0)
    user_print(b"Aegis: [supervisor] role grant observe-service -> observer over service: ");
    user_print(if og == u64::MAX {
        b"DENIED\r\n"
    } else {
        b"OK\r\n"
    });
    let notify_slot: u64 = 0;
    let child_slot: u64 = 1;
    let child_idx: u64 = IDX_ISO_TEST;
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
            // Phase B hierarchical supervision: our restart budget is spent.
            // Leave the child dead and SURRENDER the subsystem upward. The
            // parent supervisor (task IDX_PARENT_SUP) granted us an escalation
            // endpoint at slot 3 at its startup; call it to adopt the
            // subsystem, then stop serving the notification channel so the
            // parent becomes its sole observer under a fresh budget.
            // Phase F / J-2: before surrendering the subsystem upward, consult
            // the advisor. This is advice only — it cannot change whether the
            // restart is allowed (that gate is the supervisor's own
            // `restart-service` capability, untouched). Grant the
            // `query-advisor` role (id 2) to the zero-cap advisor task over
            // the watched service, through the same audited RoleGrant syscall
            // (18) every other role in this demo uses. The kernel mints the
            // NetEndpoint bound to the declared advisor host; the advisor
            // task then runs its own send/recv once it sees the grant land.
            let ag = user_syscall5(18, 2, IDX_ADVISOR, IDX_SERVICE, 0); // RoleGrant(query-advisor, advisor, service, slot 0)
            user_print(b"Aegis: [supervisor] role grant query-advisor -> advisor over service: ");
            user_print(if ag == u64::MAX {
                b"DENIED\r\n"
            } else {
                b"OK\r\n"
            });
            user_print(
                b"Aegis: [supervisor] ESCALATION: child restart budget exhausted, \
leaving child dead\r\n",
            );
            user_print(b"Aegis: [supervisor] escalating to parent supervisor\r\n");
            let msg = b"adopt";
            let mut reply = [0u8; 32];
            let mut tried = 0u64;
            loop {
                // Wait for the parent's grant to land (poll, like the client).
                // Until then ipc_call on the empty slot returns -1.
                let rlen = user_syscall5(
                    5,
                    3,
                    msg.as_ptr() as u64,
                    msg.len() as u64,
                    reply.as_mut_ptr() as u64,
                );
                if rlen != u64::MAX {
                    break;
                }
                tried += 1;
                if tried > 1_000_000 {
                    user_print(b"Aegis: [supervisor] parent escalation endpoint never arrived\r\n");
                    break;
                }
                user_syscall5(3, 0, 0, 0, 0); // yield so the parent can run
            }
            user_print(b"Aegis: [supervisor] subsystem surrendered to parent; peers continue\r\n");
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
    let g = user_syscall5(9, IDX_AGENT, 0, 1, 0); // ipc_cap_grant(self, src slot 0, dst slot 1)
    user_print(b"Aegis: [agent] ipc_cap_grant -> ");
    user_print(if g == u64::MAX {
        b"DENIED (-1)\r\n"
    } else {
        b"UNEXPECTED SUCCESS\r\n"
    });
    // 2) Re-grant itself the role over a foreign task: the grantor must hold a
    //    Task cap with the role's rights over that task; the agent holds none.
    user_print(b"Aegis: [agent] attempting to self-grant the role over a foreign task\r\n");
    let gr = user_syscall5(18, 0, IDX_AGENT, IDX_CLIENT, 2); // RoleGrant(restart-service, self, client, slot 2)
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
    let up = user_syscall5(18, 0, IDX_OBSERVER, IDX_SERVICE, 1); // RoleGrant(restart-service, self, service, slot 1)
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

/// Phase F / J-2: the `query-advisor` task. It starts with ZERO capabilities
/// and cannot mint its own socket — it can only ever use whatever the kernel
/// grants it. When the supervisor's escalation branch grants it the
/// `query-advisor` role (id 2, syscall 18), the kernel mints a NetEndpoint
/// bound to the one kernel-declared advisor host (netif.rs
/// `open_advisor_endpoint`) into its slot 0. This task then polls that slot
/// until the grant lands, sends its advisory query over the (already-open)
/// TCP endpoint, and reads the response. Everything it can do is gated on
/// SEND|RECV over that one host; it holds no Task cap, so it can never
/// restart or kill anything — advice is read, never authority.
extern "sysv64" fn task_advisor() -> ! {
    user_print(b"Aegis: [advisor] online with zero capabilities\r\n");
    // Poll slot 0 until the supervisor's RoleGrant lands the NetEndpoint.
    // Until then every net syscall on the empty slot is refused (-1).
    let mut granted = false;
    for _ in 0..5_000_000u64 {
        let c = user_syscall5(20, 0, 0, 0, 0); // net_connect(slot 0)
        if c != u64::MAX {
            granted = true;
            break;
        }
        user_syscall5(3, 0, 0, 0, 0); // yield so the grantor can run
    }
    if !granted {
        user_print(b"Aegis: [advisor] role grant never arrived\r\n");
        loop {
            core::hint::spin_loop();
        }
    }
    user_print(b"Aegis: [advisor] query-advisor role received; endpoint ready\r\n");
    // Send the advisory query over the kernel-minted endpoint.
    let q = b"restart? y/n";
    let sent = user_syscall5(21, 0, q.as_ptr() as u64, q.len() as u64, 0); // net_send
    user_print(b"Aegis: [advisor] query sent (");
    print_dec(sent as u64);
    user_print(b" bytes)\r\n");
    // Read the response (TCP echo reply from the host listener). The kernel
    // drains the NIC in task_input's round-robin slice, so poll the socket
    // until bytes arrive (bounded), yielding between attempts — the same
    // pattern the boot network demos use.
    let mut resp = [0u8; 64];
    let mut n: u64 = 0;
    let mut polls = 0u64;
    while polls < 50_000_000 {
        let r = user_syscall5(22, 0, resp.as_mut_ptr() as u64, resp.len() as u64, 0); // net_recv
        if r > 0 {
            n = r;
            break;
        }
        user_syscall5(3, 0, 0, 0, 0); // yield so the NIC drainer can run
        polls += 1;
    }
    user_print(b"Aegis: [advisor] response received (");
    print_dec(n);
    user_print(b" bytes): ");
    if n > 0 {
        let n = core::cmp::min(n as usize, resp.len());
        user_print(&resp[..n]);
    }
    user_print(b"\r\n");
    user_print(
        b"Aegis: [advisor] advice read, never authority - no Task cap held; nothing restarted\r\n",
    );
    let _ = user_syscall5(23, 0, 0, 0, 0); // net_close
    loop {
        core::hint::spin_loop();
    }
}

/// Phase B, resource manager 1: a userspace memory-PAGE manager (ring 3). It
/// mints two memory regions (its pool), KEEPS the anchors in its own table,
/// and hands pages out / recycles them purely through capability-gated IPC.
/// "alloc" grants a copy of an anchored page to the caller (at the caller's
/// slot 2); "free" revokes that copy, so the page returns to the pool and the
/// client's slot is empty again — every later use is denied at the kernel's
/// capability gate. The manager, not the kernel, decides when a page is lent.
extern "sysv64" fn task_mem_rm() -> ! {
    user_print(b"Aegis: [mem-rm] online; minting the page pool\r\n");
    // Mint two pages: each installs a READ|WRITE|GRANT cap in OUR table
    // (slots 0, 1) — the manager's pool. Both regions are backed by real
    // frames from the kernel allocator.
    let p0 = user_syscall5(10, 1, 0, 0, 0); // MemCreate(1 frame)
    let p1 = user_syscall5(10, 1, 0, 0, 0);
    if (p0 as i64) < 0 || (p1 as i64) < 0 {
        user_print(b"Aegis: [mem-rm] pool mint failed\r\n");
        loop {
            core::hint::spin_loop();
        }
    }
    user_print(b"Aegis: [mem-rm] pool pages minted\r\n");
    // Create the request endpoint (slot 2) and grant a cap to the mem-client.
    let ep = user_syscall5(8, 0, 0, 0, 0);
    if (ep as i64) < 0 {
        user_print(b"Aegis: [mem-rm] endpoint create failed\r\n");
        loop {
            core::hint::spin_loop();
        }
    }
    user_syscall5(9, IDX_MEM_CLIENT, ep, 0, 0);
    user_print(b"Aegis: [mem-rm] endpoint granted to mem-client\r\n");
    let mut lent = [false; 2];
    let mut recvbuf = [0u8; 16];
    loop {
        let packed = user_syscall5(6, ep, recvbuf.as_mut_ptr() as u64, 0, 0);
        let caller = packed >> 32;
        let rlen = packed & 0xFFFF_FFFF;
        if rlen < 2 {
            continue;
        }
        let op = recvbuf[0];
        let page = (recvbuf[1] as usize) % 2;
        let page_slot = page as u64;
        if op == b'a' {
            // Alloc: grant a copy of the anchored page to the caller at their
            // slot 2. The minted cap carries GRANT, which is what makes this
            // legal for a plain userspace task.
            if lent[page] {
                user_syscall5(7, ep, caller, b"BUSY".as_ptr() as u64, 4);
                continue;
            }
            let r = user_syscall5(9, caller, page_slot, 2, 0); // CapGrant(caller, our slot, their slot 2)
            if r == u64::MAX {
                user_syscall5(7, ep, caller, b"DENIED".as_ptr() as u64, 6);
            } else {
                lent[page] = true;
                user_syscall5(7, ep, caller, b"OK".as_ptr() as u64, 2);
            }
        } else if op == b'f' {
            // Free: revoke the granted copy — the page returns to the pool and
            // the caller's slot 2 is empty again.
            if !lent[page] {
                user_syscall5(7, ep, caller, b"IDLE".as_ptr() as u64, 4);
                continue;
            }
            let r = user_syscall5(17, caller, 2, page_slot, 0); // CapRevoke(caller, their slot 2, our slot)
            if r == u64::MAX {
                user_syscall5(7, ep, caller, b"DENIED".as_ptr() as u64, 6);
            } else {
                lent[page] = false;
                user_syscall5(7, ep, caller, b"OK".as_ptr() as u64, 2);
            }
        } else {
            user_syscall5(7, ep, caller, b"BAD".as_ptr() as u64, 3);
        }
    }
}

/// Phase B, resource client: exercises the ring-3 memory manager end-to-end.
/// For each page: alloc -> mem_len/mem_write/mem_read all succeed while the
/// grant is live; free -> the page is revoked and every later op on the slot
/// returns -1 (DENIED) at the capability gate. Two pages, to show the pool
/// recycling.
extern "sysv64" fn task_mem_client() -> ! {
    user_print(b"Aegis: [mem-client] online; waiting for the mem-rm endpoint\r\n");
    // Wait for the endpoint grant to land: ipc_call(slot 0) returns -1 until
    // the mem-rm's grant installs a cap there.
    let mut reply = [0u8; 32];
    let mut endpoint = false;
    for _ in 0..1_000_000u64 {
        let msg = b"ping";
        let rlen = user_syscall5(
            5,
            0,
            msg.as_ptr() as u64,
            msg.len() as u64,
            reply.as_mut_ptr() as u64,
        );
        if rlen != u64::MAX {
            endpoint = true;
            break;
        }
        user_syscall5(3, 0, 0, 0, 0); // yield so the grantor can run
    }
    if !endpoint {
        user_print(b"Aegis: [mem-client] mem-rm endpoint never arrived\r\n");
        loop {
            core::hint::spin_loop();
        }
    }
    user_print(b"Aegis: [mem-client] mem-rm endpoint received\r\n");
    // ---- page 0: alloc, use, free, re-check (denied) ----
    let req = b"a0";
    let rlen = user_syscall5(5, 0, req.as_ptr() as u64, 2, reply.as_mut_ptr() as u64);
    user_print(b"Aegis: [mem-client] alloc page 0 -> ");
    user_print(&reply[..rlen as usize]);
    user_print(b"\r\n");
    let len = user_syscall5(11, 2, 0, 0, 0); // MemLen(slot 2)
    user_print(b"Aegis: [mem-client] mem_len(slot 2) = ");
    print_dec(len);
    user_print(b"\r\n");
    let data = *b"from RM";
    let w = user_syscall5(13, 2, 0, data.len() as u64, data.as_ptr() as u64); // MemWrite
    user_print(b"Aegis: [mem-client] mem_write -> ");
    user_print(if w == u64::MAX {
        b"DENIED\r\n"
    } else {
        b"OK\r\n"
    });
    let mut buf = [0u8; 16];
    let r = user_syscall5(12, 2, 0, buf.len() as u64, buf.as_mut_ptr() as u64); // MemRead
    user_print(b"Aegis: [mem-client] mem_read -> ");
    user_print(if r == u64::MAX {
        b"DENIED\r\n"
    } else {
        b"OK\r\n"
    });
    let req = b"f0";
    let rlen = user_syscall5(5, 0, req.as_ptr() as u64, 2, reply.as_mut_ptr() as u64);
    user_print(b"Aegis: [mem-client] free page 0 -> ");
    user_print(&reply[..rlen as usize]);
    user_print(b"\r\n");
    let len = user_syscall5(11, 2, 0, 0, 0);
    user_print(b"Aegis: [mem-client] mem_len(slot 2) after free = ");
    print_dec(len);
    user_print(if len == u64::MAX {
        b" (DENIED, recycled)\r\n"
    } else {
        b" (UNEXPECTED)\r\n"
    });
    // ---- page 1: the pool recycles ----
    let req = b"a1";
    let rlen = user_syscall5(5, 0, req.as_ptr() as u64, 2, reply.as_mut_ptr() as u64);
    user_print(b"Aegis: [mem-client] alloc page 1 -> ");
    user_print(&reply[..rlen as usize]);
    user_print(b"\r\n");
    let len = user_syscall5(11, 2, 0, 0, 0);
    user_print(b"Aegis: [mem-client] mem_len(slot 2) = ");
    print_dec(len);
    user_print(b"\r\n");
    let req = b"f1";
    let rlen = user_syscall5(5, 0, req.as_ptr() as u64, 2, reply.as_mut_ptr() as u64);
    user_print(b"Aegis: [mem-client] free page 1 -> ");
    user_print(&reply[..rlen as usize]);
    user_print(b"\r\n");
    let len = user_syscall5(11, 2, 0, 0, 0);
    user_print(b"Aegis: [mem-client] mem_len(slot 2) after free = ");
    print_dec(len);
    user_print(if len == u64::MAX {
        b" (DENIED, recycled)\r\n"
    } else {
        b" (UNEXPECTED)\r\n"
    });
    user_print(b"Aegis: [mem-client] pages granted and recycled through the gate\r\n");
    loop {
        core::hint::spin_loop();
    }
}

/// Phase B, parent supervisor (ring 3): the supervisor ABOVE the existing
/// ring-3 supervisor. Kernel-installed caps: slot 0 = NOTIFY_EP RECV (so it
/// can observe kill notifications once it adopts), slot 1 = Task(iso-test)
/// CONTROL|READ (so it can restart the adopted subsystem). At runtime it
/// creates an escalation endpoint, grants it to the child supervisor (task
/// IDX_SUPERVISOR) at the child's slot 3, and waits. When the child's restart
/// budget is spent it calls back up with "adopt"; the parent ADOPTS the
/// subsystem with a fresh budget, takes over serving the notification
/// channel, and trips only when ITS budget is spent — escalate/adopt
/// semantics, live in ring 3.
extern "sysv64" fn task_parent_supervisor() -> ! {
    user_print(b"Aegis: [parent-sup] online; escalation endpoint ready\r\n");
    // Create the escalation endpoint and hand a cap to the child supervisor.
    let esc = user_syscall5(8, 0, 0, 0, 0);
    if (esc as i64) < 0 {
        user_print(b"Aegis: [parent-sup] endpoint create failed\r\n");
        loop {
            core::hint::spin_loop();
        }
    }
    user_syscall5(9, IDX_SUPERVISOR, esc, 3, 0); // CapGrant(supervisor, our esc, their slot 3)
    user_print(b"Aegis: [parent-sup] escalation endpoint granted to child supervisor\r\n");
    // Wait for the child to escalate (serve blocks until it calls).
    let mut recvbuf = [0u8; 32];
    let packed = user_syscall5(6, esc, recvbuf.as_mut_ptr() as u64, 0, 0);
    let caller = packed >> 32;
    user_print(b"Aegis: [parent-sup] escalation received; adopting subsystem\r\n");
    // Acknowledge (unblocks the child's surrender call), then restart the
    // adopted child under a fresh budget.
    let ok = b"adopted";
    user_syscall5(7, esc, caller, ok.as_ptr() as u64, ok.len() as u64);
    let child_slot: u64 = 1;
    let child_idx: u64 = IDX_ISO_TEST;
    let notify_slot: u64 = 0;
    let budget_limit: u64 = 2;
    let mut budget = budget_limit;
    let r = user_syscall5(16, child_slot, 0, 0, 0); // task_restart(slot 1)
    user_print(b"Aegis: [parent-sup] adopting child restart -> ");
    user_print(if r == u64::MAX {
        b"DENIED\r\n"
    } else {
        b"OK\r\n"
    });
    loop {
        let packed = user_syscall5(6, notify_slot, recvbuf.as_mut_ptr() as u64, 0, 0);
        let child = packed >> 32;
        user_print(b"Aegis: [parent-sup] child ");
        print_dec(child);
        user_print(b" DIED (under parent supervision)\r\n");
        if child != child_idx {
            user_print(b"Aegis: [parent-sup] not my adopted child, ignoring\r\n");
            continue;
        }
        if budget > 0 {
            budget -= 1;
            let r = user_syscall5(16, child_slot, 0, 0, 0);
            user_print(b"Aegis: [parent-sup] restarting adopted child, budget left ");
            print_dec(budget);
            user_print(if r == u64::MAX {
                b" -> DENIED\r\n"
            } else {
                b" -> OK\r\n"
            });
        } else {
            user_print(
                b"Aegis: [parent-sup] PARENT TRIP: adopted child left dead; \
subsystem tripped after a fresh parent budget\r\n",
            );
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    aegis_kernel::sprintln!("KERNEL PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

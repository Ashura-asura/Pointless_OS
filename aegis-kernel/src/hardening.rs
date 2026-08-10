// Production-hardening boundary tests (Phase 12).
//
// Design doc §7 Phase 12: "Production hardening, security audits." This
// test-only module drives every byte-level parser and every syscall/ABI
// translation layer in the kernel with adversarial inputs — truncated
// buffers, zero/oversized counts, garbage bytes, out-of-range indexes —
// and asserts two things: (1) the function returns an error (never
// succeeds on garbage), and (2) it never panics (parsers are total on
// their inputs). Honest limits: these are deterministic boundary tests,
// not fuzzing; they do not cover real hardware, and a no-panic result on
// these inputs is not a proof of no panic on all inputs.

#![cfg(test)]

use std::panic::{catch_unwind, AssertUnwindSafe};

fn no_panic<T>(f: impl FnOnce() -> T) -> Option<T> {
    catch_unwind(AssertUnwindSafe(f)).ok()
}

#[test]
fn elf_loader_survives_truncated_and_garbage_inputs() {
    for len in [0usize, 1, 3, 4, 8, 63, 64, 65, 100] {
        let data = vec![0xFFu8; len];
        assert!(
            no_panic(|| crate::elf_loader::parse_elf(&data)).is_some(),
            "parse_elf panicked on {} bytes of garbage",
            len
        );
    }
    // Valid magic but nothing else
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    let res = no_panic(|| crate::elf_loader::parse_elf(&data)).unwrap();
    assert!(res.is_err());
}

#[test]
fn elf_loader_rejects_absurd_segment_counts() {
    // phnum = 0xFFFF with phentsize 0 must error, not loop
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    data[4] = 2;
    data[5] = 1;
    data[16..18].copy_from_slice(&2u16.to_le_bytes());
    data[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    data[54..56].copy_from_slice(&0u16.to_le_bytes());
    data[56..58].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let res = no_panic(|| crate::elf_loader::parse_elf(&data)).unwrap();
    assert!(res.is_err());
}

#[test]
fn pe_loader_survives_truncated_and_garbage_inputs() {
    for len in [0usize, 1, 63, 64, 128, 200] {
        let data = vec![0xAAu8; len];
        assert!(
            no_panic(|| crate::pe_loader::parse_pe(&data)).is_some(),
            "parse_pe panicked on {} bytes of garbage",
            len
        );
    }
    // MZ magic present, PE pointer points past the end
    let mut data = vec![0u8; 100];
    data[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    data[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    let res = no_panic(|| crate::pe_loader::parse_pe(&data)).unwrap();
    assert!(res.is_err());
}

#[test]
fn pe_loader_rejects_overflowing_section_count() {
    // num_sections huge + section table offset such that arithmetic must not
    // overflow into a panic
    let mut data = vec![0u8; 512];
    data[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());
    data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    data[0x86..0x88].copy_from_slice(&0xFFFFu16.to_le_bytes());
    data[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
    let res = no_panic(|| crate::pe_loader::parse_pe(&data)).unwrap();
    assert!(res.is_err());
}

#[test]
fn syscall_translations_are_total() {
    // Every possible syscall number must map to something (possibly
    // Unsupported) without panicking — translations are pure matches.
    for num in [0u64, 1, 2, 41, 60, 202, 0x54, 0x67, 0xFFFF, u64::MAX] {
        let args = crate::linux_abi::SyscallArgs::default();
        assert!(no_panic(|| crate::linux_abi::translate(num, args)).is_some());
        let nt_args = crate::nt_abi::NtArgs::default();
        assert!(no_panic(|| crate::nt_abi::translate(num, nt_args)).is_some());
    }
    // Known ones resolve to concrete operations, not Unsupported
    assert!(crate::linux_abi::is_known(0));
    assert!(crate::nt_abi::is_known(0x16));
}

#[test]
fn ipv4_checksum_is_total_on_garbage() {
    for len in [0usize, 1, 2, 3, 19, 20, 21, 100] {
        let header = vec![0xABu8; len];
        assert!(no_panic(|| crate::ipv4::IPv4Packet::compute_checksum(&header)).is_some());
    }
}

#[test]
fn ethernet_parse_rejects_short_and_zero_source() {
    // 5 bytes of garbage
    let data = [0x01u8; 5];
    let r = no_panic(|| crate::ethernet::EthernetFrame::parse(&data)).unwrap();
    assert!(r.is_err());
    // 64 bytes with zero source MAC
    let mut data = [0u8; 64];
    data[12] = 0x08;
    data[13] = 0x00;
    let r = no_panic(|| crate::ethernet::EthernetFrame::parse(&data)).unwrap();
    assert!(r.is_err());
}

#[test]
fn ipv4_parse_rejects_short_and_bad_version() {
    let short = [0u8; 4];
    let r = no_panic(|| crate::ipv4::IPv4Packet::parse(&short)).unwrap();
    assert!(r.is_err());
    let mut buf = [0u8; 20];
    buf[0] = 0x60; // version 6
    let r = no_panic(|| crate::ipv4::IPv4Packet::parse(&buf)).unwrap();
    assert!(r.is_err());
}

#[test]
fn arp_parse_rejects_short_packets() {
    for len in 0..28 {
        let data = vec![0u8; len];
        let r = no_panic(|| crate::arp::ArpPacket::parse(&data)).unwrap();
        assert!(
            r.is_none(),
            "arp parse should reject {} bytes (got Some)",
            len
        );
    }
}

#[test]
fn compat_layers_reject_garbage_without_panicking() {
    let mut layer = crate::linux_compat::LinuxCompatLayer::new();
    let id = layer
        .register(
            crate::linux_compat::Personality::LinuxCompat,
            crate::agent::CapabilityScope::permissive(),
        )
        .unwrap();
    for num in [u64::MAX, 0xDEAD_BEEF, 9999] {
        let r = no_panic(|| {
            layer.dispatch(
                id,
                num,
                crate::linux_abi::SyscallArgs {
                    arg1: u64::MAX,
                    arg2: u64::MAX,
                    ..Default::default()
                },
            )
        })
        .unwrap();
        assert!(r.is_err());
    }

    let mut layer = crate::win_compat::WindowsCompatLayer::new();
    let id = layer
        .register(
            crate::win_compat::Personality::WindowsCompat,
            crate::agent::CapabilityScope::permissive(),
        )
        .unwrap();
    for num in [u64::MAX, 0xDEAD_BEEF, 9999] {
        let r = no_panic(|| {
            layer.dispatch(
                id,
                num,
                crate::nt_abi::NtArgs {
                    arg1: u64::MAX,
                    ..Default::default()
                },
            )
        })
        .unwrap();
        assert!(r.is_err());
    }
}

#[test]
fn shell_and_window_managers_reject_bad_ids() {
    let mut shell = crate::shell::ShellRuntime::new();
    assert!(no_panic(|| shell.stop(999)).unwrap().is_err());
    assert!(no_panic(|| shell.restart(999)).unwrap().is_err());

    let mut wm = crate::window::WindowManager::new(800, 600);
    assert!(no_panic(|| wm.destroy_window(999)).unwrap().is_err());
    assert!(no_panic(|| wm.move_window(999, 1, 1)).unwrap().is_err());
    assert!(no_panic(|| wm.resize_window(999, 10, 10)).unwrap().is_err());
    assert!(no_panic(|| wm.set_z_order(999, 5)).unwrap().is_err());
    assert!(no_panic(|| wm.focus_window(999)).unwrap().is_err());
    assert!(no_panic(|| wm.mark_dirty(999)).unwrap().is_err());
    assert!(no_panic(|| wm.hit_test(0, 0)).unwrap().is_none());
}

#[test]
fn object_graph_rejects_missing_nodes() {
    let mut graph = crate::object_graph::ObjectGraph::new();
    assert!(
        no_panic(|| graph.add_relationship(1, 2, crate::object_graph::RelType::Owns, false))
            .unwrap()
            .is_err(),
        "relationship between missing nodes must fail"
    );
    assert!(no_panic(|| graph.remove_node(42)).unwrap().is_err());
    assert!(no_panic(|| graph.remove_relationship(1, 2))
        .unwrap()
        .is_err());
}

#[test]
fn input_buffer_handles_full_overflow() {
    let mut buf = crate::input::InputBuffer::new();
    let ev = crate::input::InputEvent::Key(crate::input::KeyEvent {
        key: crate::input::Key::A,
        pressed: true,
        modifiers: crate::input::KeyModifiers::default(),
    });
    // Fill the ring buffer completely
    while buf.push(ev).is_ok() {}
    assert!(buf.is_full());
    // Overflow push must error, pop must still work
    assert!(no_panic(|| buf.push(ev)).unwrap().is_err());
    assert!(no_panic(|| buf.pop()).unwrap().is_some());
}

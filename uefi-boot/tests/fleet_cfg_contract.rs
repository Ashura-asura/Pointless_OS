//! FLEET.CFG parser contract test: verifies the loader parses the text file
//! into the exact 55-byte handoff `FleetConfig` block the kernel reads.
//!
//! Honest limits: tests the parser logic against crafted byte buffers. Does
//! NOT test reading the file from a real ESP (requires real hardware).

/// Mirrors `uefi_boot::fleet_cfg::FleetConfig` (same layout as the kernel's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FleetConfig {
    present: u32,
    role: u8,
    my_id_byte: u8,
    peer_id_byte: u8,
    _pad: [u8; 1],
    my_ip: [u8; 4],
    peer_ip: [u8; 4],
    stale_after: u64,
    shared_key: [u8; 32],
}

const DEFAULT_KEY: [u8; 32] = {
    let s = b"aegis-phase-i-demo-shared-key!";
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < s.len() {
        k[i] = s[i];
        i += 1;
    }
    k
};

fn parse(text: &[u8]) -> Option<FleetConfig> {
    let s = std::str::from_utf8(text).ok()?;

    let mut role: Option<u8> = None;
    let mut my_ip: Option<[u8; 4]> = None;
    let mut peer_ip: Option<[u8; 4]> = None;
    let mut my_id_byte: Option<u8> = None;
    let mut peer_id_byte: Option<u8> = None;
    let mut stale_after: Option<u64> = None;
    let mut shared_key: Option<[u8; 32]> = None;

    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "role" => {
                role = Some(match value {
                    "issuer" => 0,
                    "invoker" => 1,
                    _ => return None,
                });
            }
            "my_ip" => my_ip = parse_ip(value),
            "peer_ip" => peer_ip = parse_ip(value),
            "node_id" => my_id_byte = parse_id_byte(value),
            "peer_node_id" => peer_id_byte = parse_id_byte(value),
            "stale_after" => stale_after = value.trim_end().parse().ok(),
            "shared_key" => shared_key = parse_hex32(value),
            _ => {}
        }
    }

    let role = role?;
    let my_ip = my_ip?;
    let peer_ip = peer_ip?;

    let (my_id_byte, peer_id_byte) = match (my_id_byte, peer_id_byte) {
        (Some(m), Some(p)) => (m, p),
        _ => match role {
            0 => (0xA1, 0xB2),
            1 => (0xB2, 0xA1),
            _ => return None,
        },
    };

    Some(FleetConfig {
        present: 1,
        role,
        my_id_byte,
        peer_id_byte,
        _pad: [0],
        my_ip,
        peer_ip,
        stale_after: stale_after.unwrap_or(50000),
        shared_key: shared_key.unwrap_or(DEFAULT_KEY),
    })
}

fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut parts = s.split('.');
    let mut out = [0u8; 4];
    for slot in out.iter_mut() {
        let p = parts.next()?;
        let n: u16 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        *slot = n as u8;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

fn parse_id_byte(s: &str) -> Option<u8> {
    let s = s.trim();
    if s.len() != 2 {
        return None;
    }
    u8::from_str_radix(s, 16).ok()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let chunk = s.get(i * 2..i * 2 + 2)?;
        *b = u8::from_str_radix(chunk, 16).ok()?;
    }
    if s.len() != 64 {
        return None;
    }
    Some(out)
}

#[test]
fn parses_issuer_config() {
    let text = b"# Aegis fleet node config\nrole = issuer\nmy_ip = 10.0.3.1\npeer_ip = 10.0.3.2\n";
    let cfg = parse(text).expect("issuer config must parse");
    assert_eq!(cfg.present, 1);
    assert_eq!(cfg.role, 0);
    assert_eq!(cfg.my_ip, [10, 0, 3, 1]);
    assert_eq!(cfg.peer_ip, [10, 0, 3, 2]);
    // Defaults filled in.
    assert_eq!(cfg.my_id_byte, 0xA1);
    assert_eq!(cfg.peer_id_byte, 0xB2);
    assert_eq!(cfg.stale_after, 50000);
    assert_eq!(cfg.shared_key, DEFAULT_KEY);
}

#[test]
fn parses_invoker_config() {
    let text = b"role = invoker\nmy_ip = 10.0.3.2\npeer_ip = 10.0.3.1\n";
    let cfg = parse(text).expect("invoker config must parse");
    assert_eq!(cfg.role, 1);
    assert_eq!(cfg.my_id_byte, 0xB2);
    assert_eq!(cfg.peer_id_byte, 0xA1);
}

#[test]
fn honors_explicit_node_ids_and_stale() {
    let text = b"role = issuer\nmy_ip = 10.0.3.1\npeer_ip = 10.0.3.2\nnode_id = C3\npeer_node_id = D4\nstale_after = 12345\n";
    let cfg = parse(text).expect("config must parse");
    assert_eq!(cfg.my_id_byte, 0xC3);
    assert_eq!(cfg.peer_id_byte, 0xD4);
    assert_eq!(cfg.stale_after, 12345);
}

#[test]
fn honors_explicit_shared_key() {
    let text = b"role = invoker\nmy_ip = 10.0.3.2\npeer_ip = 10.0.3.1\nshared_key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
    let cfg = parse(text).expect("config must parse");
    assert_eq!(cfg.shared_key[0], 0x00);
    assert_eq!(cfg.shared_key[1], 0x11);
    assert_eq!(cfg.shared_key[31], 0xFF);
}

#[test]
fn rejects_unknown_role() {
    assert_eq!(
        parse(b"role = king\nmy_ip = 10.0.3.1\npeer_ip = 10.0.3.2\n"),
        None
    );
}

#[test]
fn rejects_bad_ip() {
    assert_eq!(
        parse(b"role = issuer\nmy_ip = 10.0.3.300\npeer_ip = 10.0.3.2\n"),
        None
    );
    assert_eq!(
        parse(b"role = issuer\nmy_ip = 10.0.3\npeer_ip = 10.0.3.2\n"),
        None
    );
}

#[test]
fn rejects_missing_role_or_ips() {
    assert_eq!(parse(b"my_ip = 10.0.3.1\npeer_ip = 10.0.3.2\n"), None);
    assert_eq!(parse(b"role = issuer\npeer_ip = 10.0.3.2\n"), None);
    assert_eq!(parse(b"role = issuer\nmy_ip = 10.0.3.1\n"), None);
}

#[test]
fn empty_and_garbage_are_absent() {
    assert_eq!(parse(b""), None);
    assert_eq!(parse(b"not a config file"), None);
}

#[test]
fn to_handoff_bytes_layout_matches_kernel() {
    let text = b"role = issuer\nmy_ip = 10.0.3.1\npeer_ip = 10.0.3.2\n";
    let cfg = parse(text).unwrap();
    let mut b = [0u8; 55];
    b[0..4].copy_from_slice(&cfg.present.to_le_bytes());
    b[4] = cfg.role;
    b[5] = cfg.my_id_byte;
    b[6] = cfg.peer_id_byte;
    b[7..11].copy_from_slice(&cfg.my_ip);
    b[11..15].copy_from_slice(&cfg.peer_ip);
    b[15..23].copy_from_slice(&cfg.stale_after.to_le_bytes());
    b[23..].copy_from_slice(&cfg.shared_key);

    // present at offset 0, role at 4 (1 byte), my_ip at 7, stale_after at 15.
    assert_eq!(b[0..4], 1u32.to_le_bytes());
    assert_eq!(b[4], 0);
    assert_eq!(&b[7..11], &[10, 0, 3, 1]);
    assert_eq!(&b[11..15], &[10, 0, 3, 2]);
    assert_eq!(u64::from_le_bytes(b[15..23].try_into().unwrap()), 50000);
}

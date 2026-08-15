//! Runtime fleet configuration read from `\FLEET.CFG` on the boot volume.
//!
//! The file is a simple `key = value` text file on the FAT16 root of the
//! boot stick. The loader reads it before `ExitBootServices` and writes a
//! fixed 55-byte `FleetConfig` block at handoff offset 5144 (see
//! `aegis-kernel/src/boot_info.rs`, `FLEET_OFFSET` + `parse_fleet`). If the
//! file is absent or unparsable the loader writes `present = 0`, so the
//! kernel falls back to its compile-time feature defaults.

extern crate alloc;
use uefi::fs::FileSystem;

/// Fixed serialized size of the FleetConfig handoff block (55 bytes).
pub const FLEET_BLOCK_SIZE: usize = 55;

/// Mirrors `aegis_kernel::boot_info::FleetConfig` byte-for-byte.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FleetConfig {
    pub present: u32,
    pub role: u8,
    pub my_id_byte: u8,
    pub peer_id_byte: u8,
    pub my_ip: [u8; 4],
    pub peer_ip: [u8; 4],
    pub stale_after: u64,
    pub shared_key: [u8; 32],
}

/// Default shared key used when FLEET.CFG omits one (matches the kernel
/// demo key `DEMO_SHARED_KEY` in `aegis-kernel/src/mesh.rs`).
pub const DEFAULT_SHARED_KEY: [u8; 32] = *b"aegis-phase-i-demo-shared-key!!Z";

/// Offset of the fleet block inside the handoff page.
pub const FLEET_OFFSET: usize = 24 + 20 * 256; // 5144

/// Serialize the fleet config into the exact handoff bytes the kernel
/// expects. Returns `None` when the config is absent. Stack-only: this runs
/// after `ExitBootServices`, where the UEFI allocator is dead — never
/// allocate here.
pub fn to_handoff_bytes(cfg: &Option<FleetConfig>) -> Option<[u8; FLEET_BLOCK_SIZE]> {
    let f = cfg.as_ref()?;
    let mut b = [0u8; FLEET_BLOCK_SIZE];
    b[0..4].copy_from_slice(&f.present.to_le_bytes());
    b[4] = f.role;
    b[5] = f.my_id_byte;
    b[6] = f.peer_id_byte;
    b[7..11].copy_from_slice(&f.my_ip);
    b[11..15].copy_from_slice(&f.peer_ip);
    b[15..23].copy_from_slice(&f.stale_after.to_le_bytes());
    b[23..].copy_from_slice(&f.shared_key);
    Some(b)
}

/// Read and parse `\FLEET.CFG` from the boot volume.
pub fn read_from_esp() -> Option<FleetConfig> {
    let image_handle = uefi::boot::image_handle();
    let scoped = uefi::boot::get_image_file_system(image_handle).ok()?;
    let mut fs = FileSystem::new(scoped);

    let path = uefi::CString16::try_from("\\FLEET.CFG").ok()?;
    let contents = fs.read(path.as_ref()).ok()?;
    parse(&contents)
}

/// Parse FLEET.CFG text into a `FleetConfig`. Pure and total: malformed
/// input yields `None`.
pub fn parse(text: &[u8]) -> Option<FleetConfig> {
    let s = core::str::from_utf8(text).ok()?;

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
            "shared_key" => {
                let k = parse_hex32(value)?;
                shared_key = Some(k);
            }
            _ => { /* ignore unknown keys for forward compatibility */ }
        }
    }

    let role = role?;
    let my_ip = my_ip?;
    let peer_ip = peer_ip?;

    // Defaults match the compile-time behavior when the file omits them.
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
        my_ip,
        peer_ip,
        stale_after: stale_after.unwrap_or(50000),
        shared_key: shared_key.unwrap_or(DEFAULT_SHARED_KEY),
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

/// Parse a one-byte node id (2 hex chars, e.g. `A1`).
fn parse_id_byte(s: &str) -> Option<u8> {
    let s = s.trim();
    if s.len() != 2 {
        return None;
    }
    u8::from_str_radix(s, 16).ok()
}

/// Parse a 32-byte hex string (64 chars) into a key.
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

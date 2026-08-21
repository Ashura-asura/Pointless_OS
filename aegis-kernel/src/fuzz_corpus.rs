// Phase AE: corpus-driven continuous fuzzing.
//
// The deterministic sweeps in `hardening_fuzz.rs` and the device-emulation
// sweeps in vmx/vdev/virtio run the same seeded inputs every time. This
// module adds the "growing, committed corpus" half of the phase: a directory
// of binary seed inputs per target (`fuzz-corpus/<target>/`), mutated across
// runs, persisted in git so the corpus grows over time instead of starting
// cold.
//
// How it works (honest limits):
// - The committed corpus is the baseline. Every run loads all seeds, then
//   mutates them (bit flips, byte overwrites, truncation/extension,
//   structure-preserving magic-field edits) and asserts total no-panic —
//   the same discipline as every other fuzz target in this crate.
// - With `AEGIS_FUZZ_GROW=1` the run ALSO appends genuinely interesting new
//   inputs (accepted-verdict differs from the seed, boundary length, or a
//   reserved/edge decoder encoding) to the corpus directory, deduped by
//   content hash. The nightly CI job grows it and commits the growth; push
//   CI and local `cargo test` are read-only, so the working tree stays clean.
// - Iteration budget: `AEGIS_FUZZ_ITERS` (default 50_000; the nightly job
//   raises it). This is NOT coverage-guided (no feedback from the target's
//   internals), a limitation named in SECURITY_AUDIT.md's non-certifications.
//
// `target` input encodings: byte buffers for the network/TLS parsers; 8-byte
// little-endian u64 for the VMX decoder qualifications; 2-byte u16 for the
// exit-reason classifier; 1 byte for the I/O opcode length.

#![cfg(test)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::arp::ArpPacket;
use crate::ethernet::EthernetFrame;
use crate::frame::fuzz_run as frame_fuzz_run;
use crate::hardening_fuzz::{no_panic, Rng, SEED};
use crate::ipv4::IPv4Packet;
use crate::tcp::TcpSegment;
use crate::tls::{parse_record, parse_server_hello};
use crate::udp::UdpDatagram;
use crate::vmx::ExitClass;

/// One corpus target: a pure function from hostile bytes to an accepted/
/// refused verdict, wrapped so panics are detectable.
struct Target {
    name: &'static str,
    /// Total (never panics) run of the decoder; returns whether the input was
    /// accepted (a non-trivial parse / a handled decoder result).
    run: fn(&[u8]) -> bool,
    /// Deterministic base seeds generated on first grow (in addition to any
    /// committed seeds already in the directory).
    base: fn(&mut Rng, &mut Vec<Vec<u8>>),
    /// Structured mutations that preserve the target's "shape" (valid magic
    /// prefixes, valid header layouts) so the parser commits past the header.
    structured: fn(&mut Rng, &[u8]) -> Vec<u8>,
}

fn ethernet_run(b: &[u8]) -> bool {
    EthernetFrame::parse(b).is_ok()
}
fn arp_run(b: &[u8]) -> bool {
    ArpPacket::parse(b).is_some()
}
fn ipv4_run(b: &[u8]) -> bool {
    IPv4Packet::parse(b).is_ok()
}
fn udp_run(b: &[u8]) -> bool {
    UdpDatagram::parse(b, None, None).is_ok()
}
fn tcp_run(b: &[u8]) -> bool {
    TcpSegment::parse(b, None, None).is_ok()
}
fn tls_record_run(b: &[u8]) -> bool {
    parse_record(b).is_some()
}
fn tls_hello_run(b: &[u8]) -> bool {
    parse_server_hello(b).is_some()
}
fn vmx_io_run(b: &[u8]) -> bool {
    decode_io_exit_le(b).is_some()
}
fn vmx_ept_run(b: &[u8]) -> bool {
    decode_ept_le(b).is_some()
}
fn vmx_opcode_run(b: &[u8]) -> bool {
    b.first()
        .and_then(|&o| crate::vmx::io_instruction_len(o))
        .is_some()
}
fn vmx_reason_run(b: &[u8]) -> bool {
    matches!(
        classify_exit_le(b),
        Some(ExitClass::ExternalInterrupt)
            | Some(ExitClass::Hlt)
            | Some(ExitClass::IoInstruction)
            | Some(ExitClass::EptViolation)
    )
}

fn allocator_run(b: &[u8]) -> bool {
    // The allocator oracle asserts its own bookkeeping invariants on every
    // step; a panic (caught by the harness's no_panic wrapper) is the signal
    // that a double-free was accepted, the free count desynced, or an
    // out-of-range/already-free frame mutated state. "Accepted" here means
    // "completed without corrupting invariants".
    frame_fuzz_run(b)
}

fn decode_io_exit_le(b: &[u8]) -> Option<crate::vmx::IoExit> {
    if b.len() < 8 {
        return None;
    }
    let mut q = [0u8; 8];
    q.copy_from_slice(&b[..8]);
    crate::vmx::decode_io_exit(u64::from_le_bytes(q))
}
fn decode_ept_le(b: &[u8]) -> Option<crate::ept::EptViolation> {
    if b.len() < 8 {
        return None;
    }
    let mut q = [0u8; 8];
    q.copy_from_slice(&b[..8]);
    Some(crate::ept::decode_ept_violation(u64::from_le_bytes(q)))
}
fn classify_exit_le(b: &[u8]) -> Option<ExitClass> {
    if b.len() < 2 {
        return None;
    }
    Some(crate::vmx::classify_exit(u16::from_le_bytes([b[0], b[1]])))
}

fn base_byte(rng: &mut Rng, out: &mut Vec<Vec<u8>>) {
    // Boundary lengths, zeroed and filled, so every short-buffer branch and
    // every one-past-header offset is committed to disk as a seed.
    for &len in &[0usize, 1, 2, 3, 4, 5, 13, 14, 15, 19, 20, 21, 27, 28, 29] {
        out.push(vec![0u8; len]);
        out.push(vec![0xFF; len]);
        let r = (0..len).map(|_| rng.byte()).collect::<Vec<_>>();
        out.push(r);
        let r2 = vec![0xFF; len]
            .into_iter()
            .map(|_| rng.byte())
            .collect::<Vec<_>>();
        out.push(r2);
    }
    // A few longer hostile buffers (up to 1 KiB).
    for _ in 0..8 {
        let len = 256 + rng.pick(769);
        out.push((0..len).map(|_| rng.byte()).collect());
    }
}

fn base_vmx_io(rng: &mut Rng, out: &mut Vec<Vec<u8>>) {
    // Reserved size encoding (2) must refuse; all four handled size/direction/
    // string combinations; hostile ports.
    for &q in &[
        0u64,
        2,
        0x3F8u64 << 16,
        (0x3F8u64 << 16) | 1,
        (0x3F8u64 << 16) | (1 << 3),
        (0x3F8u64 << 16) | (1 << 4),
        u64::MAX,
        0xFFFF_FFFF,
    ] {
        out.push(q.to_le_bytes().to_vec());
    }
    for _ in 0..8 {
        let q = rng.next() & 0xFFFF_FFFF;
        out.push(q.to_le_bytes().to_vec());
    }
}

fn base_vmx_ept(rng: &mut Rng, out: &mut Vec<Vec<u8>>) {
    for &q in &[0u64, u64::MAX, 0x7, 0xFFF, 0x1000, 0xFFFFFFFFFFFFF000] {
        out.push(q.to_le_bytes().to_vec());
    }
    for _ in 0..8 {
        out.push(rng.next().to_le_bytes().to_vec());
    }
}

fn base_vmx_opcode(_rng: &mut Rng, out: &mut Vec<Vec<u8>>) {
    for op in 0u16..=255 {
        out.push(vec![op as u8]);
    }
}

fn base_vmx_reason(rng: &mut Rng, out: &mut Vec<Vec<u8>>) {
    for &r in &[1u16, 12, 30, 48, 49, 0, 0xFFFF] {
        out.push(r.to_le_bytes().to_vec());
    }
    for _ in 0..16 {
        out.push((rng.next() as u16).to_le_bytes().to_vec());
    }
}

fn structured_network(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    // Valid ethernet magic + garbage tail so the parser commits past the
    // 14-byte header, like the hardening_fuzz structured wing.
    let mut buf = seed.to_vec();
    if buf.len() < 14 {
        buf.resize(14, 0);
    }
    let ethertype = [0x08u8, 0x00, 0x08, 0x06, 0x86, 0xDD][rng.pick(6)];
    buf[12] = ethertype;
    buf[13] = match ethertype {
        0x08 => 0x00,
        0x06 => 0x06,
        _ => 0xDD,
    };
    if buf[6..12].iter().all(|&b| b == 0) {
        buf[6] = 0x02;
    }
    buf.extend((0..rng.pick(513)).map(|_| rng.byte()));
    buf
}

fn structured_tls(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    // TLS record header + hostile length so parse_record and the framing
    // branches commit; ServerHello-style bodies for the hello parser.
    let mut buf = seed.to_vec();
    if buf.len() < 5 {
        buf.resize(5, 0);
    }
    buf[0] = [0x14, 0x15, 0x16, 0x17, 0x01][rng.pick(5)];
    buf[1] = 0x03;
    buf[2] = 0x03;
    let hdr_len = [0u16, 1, 5, 0xFFFF, buf.len() as u16][rng.pick(5)];
    buf[3..5].copy_from_slice(&hdr_len.to_be_bytes());
    buf.extend((0..rng.pick(600)).map(|_| rng.byte()));
    buf
}

fn structured_vmx(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    // Keep a u64-shaped input but overwrite the size/direction/string bits
    // and the port field so decode_io_exit's structured branches are hit.
    let mut buf = seed.to_vec();
    if buf.len() < 8 {
        buf.resize(8, 0);
    }
    let q = u64::from_le_bytes(buf[..8].try_into().unwrap());
    let size = [0u64, 1, 2, 3][rng.pick(4)];
    let dir = (rng.pick(2) as u64) << 3;
    let string = (rng.pick(2) as u64) << 4;
    let port = (rng.pick(0x10000) as u64) << 16;
    let nq = (q & !0xFF) | size | dir | string | port;
    buf[..8].copy_from_slice(&nq.to_le_bytes());
    buf
}

fn structured_identity(_rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    seed.to_vec()
}

/// Base seeds for the allocator target: hand-crafted op streams that hit the
/// boundary cases (alloc-to-exhaustion, contiguous runs of every small size,
/// interleaved free/double-free, and a pure double-free storm) plus a few
/// random ones. The op encoding is documented on `frame::fuzz_run`.
fn base_allocator(rng: &mut Rng, out: &mut Vec<Vec<u8>>) {
    out.push(vec![]);
    // Exhaust then free-all: 200 allocs (op 0) then 200 frees (op 2).
    out.push((0..200).map(|_| 0u8).collect());
    out.push((0..200).map(|_| 2u8).collect());
    // Interleaved single alloc/free.
    out.push(
        (0..120)
            .map(|i| if i % 2 == 0 { 0u8 } else { 2u8 })
            .collect(),
    );
    // Contiguous runs of each small size with trailing frees.
    for n in 1u8..=8 {
        let mut s = vec![1u8, n]; // alloc_contiguous(1 + n&7) => alloc_contiguous(1+n)
        s.push(2); // free the base (a single tracked frame)
        out.push(s);
    }
    // Double-free storms (op 3) interleaved with allocs.
    out.push(
        (0..60)
            .map(|i| if i % 3 == 0 { 3u8 } else { 0u8 })
            .collect(),
    );
    // A long random stream.
    let len = 256 + rng.pick(769);
    out.push((0..len).map(|_| rng.byte()).collect());
}

fn structured_allocator(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    // Keep the op stream shape but flip a few bits so the allocator sees
    // different alloc/free/size decisions (including boundary sizes 1..=8).
    let mut buf = seed.to_vec();
    for _ in 0..=rng.pick(6) {
        if buf.is_empty() {
            buf.push(rng.byte());
            continue;
        }
        let i = rng.pick(buf.len());
        buf[i] ^= 1u8 << rng.pick(8);
    }
    buf
}

fn targets() -> Vec<Target> {
    vec![
        Target {
            name: "ethernet",
            run: ethernet_run,
            base: base_byte,
            structured: structured_network,
        },
        Target {
            name: "arp",
            run: arp_run,
            base: base_byte,
            structured: structured_network,
        },
        Target {
            name: "ipv4",
            run: ipv4_run,
            base: base_byte,
            structured: structured_network,
        },
        Target {
            name: "udp",
            run: udp_run,
            base: base_byte,
            structured: structured_network,
        },
        Target {
            name: "tcp",
            run: tcp_run,
            base: base_byte,
            structured: structured_network,
        },
        Target {
            name: "tls_record",
            run: tls_record_run,
            base: base_byte,
            structured: structured_tls,
        },
        Target {
            name: "tls_server_hello",
            run: tls_hello_run,
            base: base_byte,
            structured: structured_tls,
        },
        Target {
            name: "vmx_io",
            run: vmx_io_run,
            base: base_vmx_io,
            structured: structured_vmx,
        },
        Target {
            name: "vmx_ept",
            run: vmx_ept_run,
            base: base_vmx_ept,
            structured: structured_vmx,
        },
        Target {
            name: "vmx_opcode",
            run: vmx_opcode_run,
            base: base_vmx_opcode,
            structured: structured_identity,
        },
        Target {
            name: "vmx_reason",
            run: vmx_reason_run,
            base: base_vmx_reason,
            structured: structured_identity,
        },
        Target {
            name: "allocator",
            run: allocator_run,
            base: base_allocator,
            structured: structured_allocator,
        },
    ]
}

fn corpus_root() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    Path::new(&manifest).join("fuzz-corpus")
}

/// FNV-1a 64-bit content hash -> hex filename (dedup / naming only).
fn content_hash(bytes: &[u8]) -> String {
    let mut h = 0xcbf29ce484222325u64;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

fn load_seeds(dir: &Path) -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("bin") {
                if let Ok(b) = fs::read(&p) {
                    seeds.push(b);
                }
            }
        }
    }
    seeds
}

fn grow_write(dir: &Path, input: &[u8], existing: &Mutex<HashSet<String>>) {
    // Only writes when AEGIS_FUZZ_GROW=1; bounded and deduped. The set is
    // capped so candidates stop being recorded past the budget (a
    // contains-check that must stay O(1), not O(candidates²)).
    if std::env::var("AEGIS_FUZZ_GROW").as_deref() != Ok("1") {
        return;
    }
    let h = content_hash(input);
    let mut seen = existing.lock().unwrap();
    if seen.len() > CORPUS_CAP || !seen.insert(h.clone()) {
        return;
    }
    fs::create_dir_all(dir).ok();
    let _ = fs::write(dir.join(format!("{h}.bin")), input);
}

/// Maximum total corpus entries a single grow run appends (bounded growth,
/// so CI commits stay reviewable instead of dumping megabytes per run).
const CORPUS_CAP: usize = 2048;

/// The corpus-driven fuzz pass. One sequential test (corpus writes are not
/// thread-safe to interleave) that:
/// 1. ensures the base seeds exist (deterministic, on grow),
/// 2. loads every committed seed per target,
/// 3. mutates seeds — random, boundary, and structured — asserting total
///    no-panic, and
/// 4. grows the corpus (only with AEGIS_FUZZ_GROW=1) with inputs whose
///    verdict differs from their seed, boundary lengths, or edge decoder
///    encodings.
///
/// Budget: AEGIS_FUZZ_ITERS (default 50_000; nightly raises it).
#[test]
#[cfg_attr(miri, ignore)] // interpreted corpus pass; the fixed vectors still run under Miri
fn corpus_driven_fuzz_is_total_and_grows() {
    let root = corpus_root();
    fs::create_dir_all(&root).ok();
    let iters: usize = std::env::var("AEGIS_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);
    // Debug builds run the push CI gate; keep it a bounded few minutes by
    // scaling the default budget down (release / nightly keep the full budget).
    let iters = if cfg!(debug_assertions) {
        iters.min(12_500)
    } else {
        iters
    };
    let grow = std::env::var("AEGIS_FUZZ_GROW").as_deref() == Ok("1");
    let seen: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    let mut total = 0usize;

    for t in targets() {
        let dir = root.join(t.name);
        fs::create_dir_all(&dir).ok();
        let mut seeds = load_seeds(&dir);
        let committed = seeds.len();
        if grow {
            // Deterministic base seeds, generated fresh and written once.
            let mut rng = Rng::new(SEED ^ (t.name.len() as u64 * 0x9E37_79B9));
            let mut base = Vec::new();
            (t.base)(&mut rng, &mut base);
            for b in base {
                grow_write(&dir, &b, &seen);
                if !seeds.contains(&b) {
                    seeds.push(b);
                }
            }
        }
        let mut rng = Rng::new(SEED ^ ((t.name.len() as u64 * 0x9E37_79B9) ^ 0xA3));
        let per = iters.div_ceil(seeds.len().max(1));
        let mut accepted = 0usize;
        for _ in 0..per {
            for seed in &seeds {
                // Random mutation.
                let mut buf = seed.clone();
                match rng.pick(4) {
                    0 => {
                        // Bit flips.
                        for _ in 0..=rng.pick(8) {
                            if buf.is_empty() {
                                break;
                            }
                            let i = rng.pick(buf.len());
                            buf[i] ^= 1u8 << rng.pick(8);
                        }
                    }
                    1 => {
                        // Byte overwrite.
                        if !buf.is_empty() {
                            let i = rng.pick(buf.len());
                            buf[i] = rng.byte();
                        }
                    }
                    2 => {
                        // Truncate or extend.
                        if rng.pick(2) == 0 && !buf.is_empty() {
                            buf.truncate(rng.pick(buf.len() + 1));
                        } else {
                            buf.extend((0..rng.pick(257)).map(|_| rng.byte()));
                        }
                    }
                    _ => {
                        // Structured mutation.
                        buf = (t.structured)(&mut rng, seed);
                    }
                }
                total += 1;
                let seed_ok = (t.run)(seed);
                let got = no_panic(|| (t.run)(&buf));
                assert!(
                    got.is_some(),
                    "{} panicked on a corpus mutation of {} bytes (seed {:?})",
                    t.name,
                    buf.len(),
                    seed
                );
                if got.unwrap() {
                    accepted += 1;
                }
                // Keep: verdict differs from the seed, a boundary length, or
                // an edge decoder encoding (the structured mutations encode
                // these deliberately).
                let boundary =
                    buf.len() <= 30 || buf.len() == 255 || buf.len() == 256 || buf.len() == 2048;
                if grow && (got.unwrap() != seed_ok || boundary || matches!(rng.pick(64), 0)) {
                    grow_write(&dir, &buf, &seen);
                }
            }
        }
        eprintln!(
            "corpus {}: committed={committed} seeds, {} inputs run, {} accepted",
            t.name,
            per * seeds.len(),
            accepted
        );
    }
    // The sweep must have run a real number of inputs (proves it committed).
    assert!(
        total >= iters,
        "corpus pass ran only {total} inputs (budget {iters})"
    );
}

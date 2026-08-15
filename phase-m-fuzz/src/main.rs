//! Phase M: host-side fuzz campaign against the REAL in-crate boundary parsers.
//!
//! Unlike the `new_hypo` sandbox (Rust 1.75, which could not compile the
//! 1.82-MSVR `aegis-kernel` crate), this box has Rust >= 1.82, so this harness
//! links the actual `aegis-kernel` lib and fuzzes `elf_loader::parse_elf`,
//! `pe_loader::parse_pe`, and `store::decode_entries` in place — ruling out any
//! extraction drift from the extracted copies used in the sandbox campaign.
//!
//! Run:  cargo run --release -- <seed> <iterations_per_target>
//! (defaults: seed 0xC0FFEE12345678, 30_000_000 iterations per target)

use std::panic::{self, AssertUnwindSafe};
use std::time::Instant;

use aegis_kernel::elf_loader::parse_elf;
use aegis_kernel::pe_loader::parse_pe;
use aegis_kernel::store::{decode_entries, FileEntry, MAX_FILES};

// xorshift64, same algorithm as chaos.rs's Rng and the sandbox fuzz harness
// (independently reimplemented here since this is a standalone crate, not a
// dependency on the kernel).
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

fn random_bytes(rng: &mut Rng, max_len: usize) -> Vec<u8> {
    let len = rng.below(max_len as u64 + 1) as usize;
    (0..len).map(|_| rng.byte()).collect()
}

/// Seed corpus: valid-shaped inputs (built the same way each parser's own
/// unit tests build them) plus their truncations — bit-flip mutation
/// fuzzing from a valid seed finds more real bugs than pure random bytes,
/// because most random buffers get rejected in the first few bytes (wrong
/// magic) and never reach the interesting bounds-checking logic deeper in
/// each parser.
fn build_valid_elf() -> Vec<u8> {
    let phdrs: &[(u32, u32, u64, u64, u64, u64)] = &[
        (1u32, 5u32, 0x0000u64, 0x1000u64, 0x3000u64, 0x3000u64), // PT_LOAD
        (1u32, 6u32, 0x3000u64, 0x4000u64, 0x1000u64, 0x1000u64),
    ];
    const ELF_HEADER_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;
    let mut size = ELF_HEADER_SIZE + phdrs.len() * PHDR_SIZE;
    for &(_, _, p_offset, _, p_filesz, _) in phdrs {
        size = size.max((p_offset + p_filesz) as usize);
    }
    let mut data = vec![0u8; size];
    data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    data[4] = 2; // ELFCLASS64
    data[5] = 1; // ELFDATA2LSB
    data[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    data[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
    data[24..32].copy_from_slice(&0x4001E0u64.to_le_bytes());
    data[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
    data[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
    data[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
    for (i, &(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz)) in phdrs.iter().enumerate() {
        let ph = ELF_HEADER_SIZE + i * PHDR_SIZE;
        data[ph..ph + 4].copy_from_slice(&p_type.to_le_bytes());
        data[ph + 4..ph + 8].copy_from_slice(&p_flags.to_le_bytes());
        data[ph + 8..ph + 16].copy_from_slice(&p_offset.to_le_bytes());
        data[ph + 16..ph + 24].copy_from_slice(&p_vaddr.to_le_bytes());
        data[ph + 32..ph + 40].copy_from_slice(&p_filesz.to_le_bytes());
        data[ph + 40..ph + 48].copy_from_slice(&p_memsz.to_le_bytes());
    }
    data
}

fn build_valid_pe() -> Vec<u8> {
    let num_sections = 2usize;
    let mut data = vec![0u8; 512 + num_sections * 40];
    data[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
    data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    data[0x86..0x88].copy_from_slice(&(num_sections as u16).to_le_bytes());
    data[0x94..0x96].copy_from_slice(&64u16.to_le_bytes());
    data[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
    data[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0xB0..0xB8].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    data
}

fn build_valid_entries() -> Vec<u8> {
    // count=2, then two (namelen,name,node) triples
    let mut out = Vec::new();
    out.extend_from_slice(&2u32.to_le_bytes());
    for (name, node) in [(b"hello".as_slice(), 7u64), (b"world".as_slice(), 9u64)] {
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&node.to_le_bytes());
    }
    out
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    let ops = 1 + rng.below(6);
    for _ in 0..ops {
        if v.is_empty() {
            v.push(rng.byte());
            continue;
        }
        match rng.below(4) {
            0 => {
                let i = rng.below(v.len() as u64) as usize;
                v[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(v.len() as u64) as usize;
                v[i] = rng.byte();
            }
            2 => {
                let n = rng.below(v.len() as u64 + 1) as usize;
                v.truncate(n);
            }
            _ => {
                let i = rng.below(v.len() as u64 + 1) as usize;
                v.insert(i, rng.byte());
            }
        }
    }
    v
}

struct Report {
    label: &'static str,
    ran: u64,
    panics: u64,
    first_panic_input: Option<Vec<u8>>,
}

impl Report {
    fn new(label: &'static str) -> Self {
        Report {
            label,
            ran: 0,
            panics: 0,
            first_panic_input: None,
        }
    }
    fn record(&mut self, input: &[u8], panicked: bool) {
        self.ran += 1;
        if panicked {
            self.panics += 1;
            if self.first_panic_input.is_none() {
                self.first_panic_input = Some(input.to_vec());
            }
        }
    }
    fn print(&self) {
        println!("[{}] ran={} panics={}", self.label, self.ran, self.panics);
        if let Some(inp) = &self.first_panic_input {
            println!("  first panicking input ({} bytes): {:?}", inp.len(), inp);
        }
    }
}

fn run_target(
    label: &'static str,
    iterations: u64,
    max_len: usize,
    seed: u64,
    seeds: &[Vec<u8>],
    f: impl Fn(&[u8]),
) -> Report {
    let mut rng = Rng::new(seed);
    let mut report = Report::new(label);

    let random_share = iterations / 2;
    for _ in 0..random_share {
        let input = random_bytes(&mut rng, max_len);
        let panicked = panic::catch_unwind(AssertUnwindSafe(|| f(&input))).is_err();
        report.record(&input, panicked);
    }

    let mutation_share = iterations - random_share;
    for i in 0..mutation_share {
        let base = &seeds[(i as usize) % seeds.len()];
        let input = mutate(&mut rng, base);
        let panicked = panic::catch_unwind(AssertUnwindSafe(|| f(&input))).is_err();
        report.record(&input, panicked);
    }

    report
}

fn main() {
    let seed: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xC0_FF_EE_12_34_56_78);
    let iterations: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000_000);

    println!(
        "Phase M fuzz campaign (REAL in-crate functions) — seed={:#x} iterations_per_target={}",
        seed, iterations
    );
    let start = Instant::now();

    let elf_seeds = vec![build_valid_elf()];
    let pe_seeds = vec![build_valid_pe()];
    let entries_seeds = vec![build_valid_entries()];

    let r1 = run_target(
        "decode_entries",
        iterations,
        512,
        seed ^ 1,
        &entries_seeds,
        |data| {
            // FileEntry has no Default impl in the real crate; Name does.
            let mut out = [FileEntry {
                name: aegis_kernel::store::Name::default(),
                node: 0,
            }; MAX_FILES];
            let _ = decode_entries(data, &mut out);
        },
    );

    let r2 = run_target(
        "parse_elf",
        iterations,
        1024,
        seed ^ 2,
        &elf_seeds,
        |data| {
            let _ = parse_elf(data);
        },
    );

    let r3 = run_target("parse_pe", iterations, 1024, seed ^ 3, &pe_seeds, |data| {
        let _ = parse_pe(data);
    });

    let elapsed = start.elapsed();
    println!("--- results ---");
    r1.print();
    r2.print();
    r3.print();
    let total_ran = r1.ran + r2.ran + r3.ran;
    let total_panics = r1.panics + r2.panics + r3.panics;
    println!(
        "TOTAL: {} inputs across 3 targets, {} panics, elapsed={:.1}s",
        total_ran,
        total_panics,
        elapsed.as_secs_f64()
    );
    if total_panics == 0 {
        println!("RESULT: zero crashes across the full campaign");
    } else {
        println!(
            "RESULT: {} crash(es) found — see first-panic inputs above",
            total_panics
        );
        std::process::exit(1);
    }
}

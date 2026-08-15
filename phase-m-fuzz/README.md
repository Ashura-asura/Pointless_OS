# Phase M — boundary-parser fuzzing

Host-side fuzz campaign over the three kernel boundary parsers, run as part of
Phase M (fuzzing + security-audit closure). Two harnesses are kept, because the
two toolchains involved genuinely differ:

- **This repo builds on Rust 1.97.1**, so the authoritative harness fuzzes the
  **real in-crate functions** directly.
- The `new_hypo` sandbox ran Rust 1.75, which **cannot compile** the kernel's
  1.82-MSVR crate, so it fuzzed **verbatim extracted copies** of the same three
  parsers.

Both agree — **180,000,000 total inputs, 2 independent seeds, 0 panics** — which
rules out extraction drift.

## Targets

The three boundary parsers (parse-and-never-panic, no panic, no unwind leak):

| Parser | Function | Source |
|--------|----------|--------|
| Object-store entries | `store::decode_entries` | `aegis-kernel/src/store.rs` |
| Linux ELF | `elf_loader::parse_elf` | `aegis-kernel/src/elf_loader.rs` |
| Windows PE | `pe_loader::parse_pe` | `aegis-kernel/src/pe_loader.rs` |

Both harnesses run random-byte and mutation-from-valid-seed phases under
`catch_unwind`, with `panic = "unwind"` in the release profile so a panic is
caught and counted rather than aborting.

## Two harnesses

```
phase-m-fuzz/
├── README.md          this file
├── Cargo.toml         real-crate harness (links aegis-kernel)
├── src/main.rs        real-crate fuzz driver
├── fuzz-run.log       EVIDENCE: real-crate run (180M / 2 seeds / 0 panics)
└── extracted/         provenance baseline: the sandbox's extracted-copy harness
    ├── Cargo.toml     crate "phase-m-fuzz-extracted" (Rust 1.75-compatible)
    ├── main.rs        verbatim sandbox fuzz driver  (was fuzz_main.rs)
    ├── elf_loader.rs  verbatim extracted parser     (was elf_loader_extracted.rs)
    ├── pe_loader.rs   verbatim extracted parser     (was pe_loader_extracted.rs)
    ├── store_decode.rs verbatim extracted parser
    └── fuzz-run-extracted.log  EVIDENCE: extracted-copy run (same 180M / 0 panics)
```

### Real-crate harness (`phase-m-fuzz/`)

The authoritative campaign. Links `aegis-kernel` as a path dependency and fuzzes
the actual `parse_elf` / `parse_pe` / `decode_entries` in place.

```sh
cargo run --release -- <seed> <iterations_per_target>
```

### Extracted-copy harness (`phase-m-fuzz/extracted/`)

A self-contained, Rust 1.75-compatible crate that preserves the sandbox's
standalone campaign as a **provenance baseline**. The four source files are the
verbatim sandbox originals, byte-identical to what `new_hypo` ran (renamed only:
`fuzz_main.rs` → `main.rs`, `*_extracted.rs` → the parser names). Fidelity was
verified by diffing them against the real in-crate functions — identical except
the documented `.is_none_or(f)` → `opt_is_none_or(x,f)` mechanical change, plus a
benign added `impl Default for FileEntry` in the extracted `store_decode.rs` that
the real crate lacks (the harness constructs via `Name::default()` instead).

```sh
cargo run --release -- <seed> <iterations_per_target>
```

## Evidence

Raw `cargo test`-style output is committed verbatim:

- `phase-m-fuzz/fuzz-run.log` — real-crate run.
- `phase-m-fuzz/extracted/fuzz-run-extracted.log` — extracted-copy run.

Both show `ran=<n> panics=0` per target per seed and the `TOTAL` line.

## Honest ceilings

- **Not coverage-guided** — random + mutation only (no cargo-fuzz/nightly). A
  floor, not a ceiling, on what is there to find.
- **Network parsers (ARP/Ethernet/IPv4/UDP/TCP/TLS) are NOT fuzzed** — they
  depend on kernel-crate types that do not extract cleanly; `hardening.rs`'s 21
  deterministic tests are their only coverage.
- The harness runs under host `std`; the functions are `no_std`-clean and the
  kernel's `x86_64-unknown-none` release build compiles clean, but the fuzz
  itself is a std process.

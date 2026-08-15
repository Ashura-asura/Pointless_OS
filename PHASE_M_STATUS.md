# Phase M — fuzzing + security-audit closure, with real numbers (and now the real crate)

Phase M lands two things: (1) a real host-side fuzz campaign over the boundary
parsers, and (2) a security-audit reconciliation. The original campaign was
run in a sandbox (`new_hypo`, Rust 1.75) that **could not compile the real
`aegis-kernel` crate** (MSRV 1.82), so it fuzzed verbatim *extracted copies*.
This repo build has Rust ≥ 1.82, so the campaign is now also run against the
**real in-crate functions**. Both agree. The deliverable is complete.

## The MSRV blocker, confirmed concretely (not just asserted)

Sandbox tried the real crate first. `aegis-kernel/Cargo.toml` pins
`rust-version = "1.82"`; apt's newest there was `rustc 1.75.0`. Ran with
`--ignore-rust-version`:
```
error[E0658]: const operands for inline assembly are unstable   (cpu.rs)
error[E0599]: no method named `is_none_or` found for enum `Option`
              (page_tables.rs, fleet.rs, elf_loader.rs, pe_loader.rs, ...)
```
`is_none_or` stabilized in Rust 1.82 — the crate genuinely uses post-1.82
stdlib. 118 errors total. Real blocker on that toolchain, not a formality.
**This repo build is on Rust 1.97.1, so the blocker does not apply here** — the
real crate compiles and is fuzzed directly.

## What was fuzzed, and against what

Three boundary parsers: `store::decode_entries`, `elf_loader::parse_elf`,
`pe_loader::parse_pe`. Two independent campaigns:

1. **Extracted copies (sandbox provenance, reproducible standalone on Rust
   1.75+)** — `phase-m-fuzz/extracted/`, a self-contained crate over the three
   parsers copied byte-for-byte from the real source with exactly one
   mechanical change: `.is_none_or(f)` → a local `opt_is_none_or(x, f)` free
   function with identical match-arm semantics (`None => true, Some(x) => f(x)`).
   Extraction validated by running all **23** of the parsers' own original
   `#[cfg(test)]` unit tests unmodified against the extracted copies:
   ```
   test result: ok. 23 passed; 0 failed; 0 ignored
   ```
   (Re-verified in this repo: identical.)
2. **Real in-crate functions** — `phase-m-fuzz/` links `aegis-kernel` as a path
   dependency and calls the actual `store::decode_entries`,
   `elf_loader::parse_elf`, `pe_loader::parse_pe` in place. This is the piece
   the sandbox could not do. To enable it, `decode_entries` was widened from
   `pub(crate)` to `pub` (a pure parser, same rationale as `elf_loader`/
   `pe_loader` being already `pub`); 495 kernel tests still pass and the
   `x86_64-unknown-none` release build is clean.

## Results (random-byte + mutation phases, 2 independent seeds)

Mutation phase bit-flips/truncates/overwrites/inserts starting from a valid
seed of each format — random bytes alone mostly bounce off the first
magic-number check and never reach the interesting bounds logic deeper in the
parser.

```
seed=0xC0FFEE12345678, 30,000,000 inputs/target, REAL in-crate functions:
  [decode_entries] ran=30000000 panics=0
  [parse_elf]       ran=30000000 panics=0
  [parse_pe]         ran=30000000 panics=0
  (90,000,000 total, 0 panics)

seed=0x3ade68b1 (independent), 30,000,000 inputs/target, REAL in-crate functions:
  [decode_entries] ran=30000000 panics=0
  [parse_elf]       ran=30000000 panics=0
  [parse_pe]         ran=30000000 panics=0
  (90,000,000 total, 0 panics)
```

**180,000,000 total inputs across 2 independent seeds against the real
in-crate functions, 0 panics.** The extracted-copy campaign reproduces the
identical numbers (`phase-m-fuzz/extracted/fuzz-run-extracted.log`), so there
is no extraction drift — the real code and the copies agree. Raw output in
`phase-m-fuzz/fuzz-run.log`.

(Sandbox note, kept for honesty: its first "two different seeds" comparison was
actually the same seed twice — `"0x..."` hex strings don't parse with plain
`str::parse::<u64>()`, so the second CLI arg silently fell back to the default.
Fixed by passing decimal. Reproduced here with genuinely different decimal
seeds; both hit 0 panics.)

## What this is NOT (unchanged, honest ceilings)

- **Not coverage-guided** (no `cargo-fuzz`/libFuzzer — needs nightly + the real
  toolchain). Random + mutation harness, not corpus-minimizing coverage
  feedback. Real signal, lower ceiling than a proper `cargo-fuzz` campaign.
- **Doesn't cover the network parsers** the master doc also names (ARP,
  Ethernet, IPv4, UDP, TCP, TLS). Those pull in more kernel-specific types
  (`netif`, the packet structs) that don't extract cleanly and aren't pure
  functions. `hardening.rs`'s existing 21 deterministic tests are their only
  coverage. Named explicitly as NOT done in `SECURITY_AUDIT.md`.
- **The harness runs under the host's std target**, not inside `no_std` kernel
  context. The real functions are `no_std`-clean (the crate's `x86_64-unknown-none`
  release build compiles and 495 tests pass), and these are pure parsing
  functions with no target-specific codegen, but the fuzz itself executes in a
  std process. That is the honest boundary.

## Files

- `phase-m-fuzz/` — the real-crate harness (`Cargo.toml`, `src/main.rs`,
  `fuzz-run.log` evidence). `cargo run --release -- <seed> <iterations>`.
- `phase-m-fuzz/README.md` — explains the two harnesses and how they relate.
- `phase-m-fuzz/extracted/` — the sandbox's standalone extracted-copy harness,
  consolidated to a single set of source files at the crate root (crate
  `phase-m-fuzz-extracted`; the redundant `src/` duplicate copies were removed).
  The four sources (`main.rs`, `elf_loader.rs`, `pe_loader.rs`,
  `store_decode.rs`) are the sandbox's verbatim originals — byte-identical to
  what `new_hypo` ran, renamed only (`fuzz_main.rs` → `main.rs`,
  `*_extracted.rs` → the parser names). `cargo run --release -- <seed> <iterations>`.
- `SECURITY_AUDIT.md` — fuzzing row and non-certification #4 updated with the
  real numbers; ceiling row added for `AegisCeiling.tla`.
- `aegis-kernel/src/store.rs` — `decode_entries` widened `pub(crate)` → `pub`.

## To fully close the remaining Phase M gaps

1. Extend to the network parsers (ARP/Ethernet/IPv4/UDP/TCP/TLS) — real
   remaining work, not attempted.
2. Consider `cargo-fuzz` for coverage-guided fuzzing once nightly is available
   — the 0-panics result is real but coverage-blind, so it's a floor, not a
   ceiling, on what's there to find.
3. A real full pass reconciling every row in `SECURITY_AUDIT.md` against
   `HONEST_STATUS.md`'s current state (Phases J/K/L added live-boot evidence
   that several "NOT certified" rows may now be partially stale) — only the
   fuzzing/ceiling rows were reconciled here.

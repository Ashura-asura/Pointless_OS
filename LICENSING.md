# Licensing — Pointless OS / Aegis

This document is the single consolidated answer to "what is licensed how in
this repository". It distinguishes the project's **original code** (MIT OR
Apache-2.0) from **third-party components that are shipped in the repository**
(GPL-2.0 guest binaries, public-domain algorithms) and **components used only
at build/runtime time** (never committed). The licensing-gated part — the
GPL-2.0 guest payloads — is called out explicitly at the end with the
compliance obligations it imposes.

## 1. Original code — MIT OR Apache-2.0

All original Pointless OS / Aegis source is dual-licensed under the
**MIT License** and the **Apache License, Version 2.0** (SPDX:
`MIT OR Apache-2.0`), the same scheme the Rust project uses. See `LICENSE`.

Covered by this dual license:

- `aegis/` — the model SDK workspace (all 17 crates; the workspace root and
  `conformance`/`sdk-example` also declare `license = "MIT OR Apache-2.0"` in
  their `Cargo.toml`).
- `aegis-kernel/` — the bare-metal kernel (no third-party cargo
  dependencies at all; the two public-domain snippets below are separately
  attributed).
- `uefi-boot/` — the UEFI loader.
- `design/`, `aegis/spec/`, `*.md` — design and specification documents.
- `phase-m-fuzz/` — the host-side fuzz harness.

## 2. Third-party components shipped in this repository

These files are in the tree and travel with any distribution of the repo.
They are **not** covered by the MIT OR Apache-2.0 dual license.

| Component | Location | License | Origin |
|---|---|---|---|
| Linux kernel image | `guest/out/bzImage` (6.12.103) | **GPL-2.0-only** (with the standard syscall exception for UAPI) | Built from a mainline 6.12.x source tree; exact config: `guest/out/kernel.config` |
| BusyBox + applet initramfs | `guest/out/initramfs.cpio.gz`, `guest/initramfs/` | **GPL-2.0-only** | Built from upstream BusyBox via `guest/build-guest.sh` |
| IBM VGA 8x16 glyphs | `aegis-kernel/src/font.rs` | public domain | "IBM VGA font via dhepper/font8x16" (attributed in the file header) |
| days→civil calendar algorithm | `aegis-kernel/src/vdev.rs` (RTC/CMOS date decode) | public domain | Howard Hinnant's `days_from_civil`/`civil_from_days` (attributed at the site) |

## 3. Components used at build/runtime time, never committed

| Component | License | Where it is used |
|---|---|---|
| edk2 / OVMF firmware | BSD-2-Clause-Patent | The UEFI firmware the image boots under in QEMU (not in the repo) |
| QEMU | GPL-2.0-only | The dev/verification harness (`-machine q35`) |
| Rust toolchain + `cargo` registry crates (`uefi`, `log`, `subtle`, …) | per-crate (mostly MIT OR Apache-2.0) | Resolved by `Cargo.lock`/`Cargo.toml`; not vendored |
| `python` build helpers (`build_image.py`, `add_startup.py`) | MIT OR Apache-2.0 (original) | Image assembly for the committed boot images |

## 4. The licensing gate: GPL-2.0 guest payloads

The repository ships two **GPL-2.0-only binaries** (the Linux bzImage and the
BusyBox initramfs) inside the committed `guest/out/` directory. This has real
consequences for anyone redistributing the repository, whether on GitHub, as
a tarball, or as a built OS image:

1. **The GPL applies to the payloads, not to your use of them.** Using the
   binaries to boot a research VM is subject to GPL-2.0 section 1 (the
   license grants you the right to copy/redistribute under its terms), and
   the research use here is plainly within the license's purposes.
2. **Distribution obligations attach.** If you redistribute the binaries
   (or an image containing them), GPL-2.0 section 3 requires that the
   complete corresponding source be made available and that the license text
   accompany the binaries. This repository already satisfies the source
   side:
   - exact kernel build configuration: `guest/out/kernel.config`
   - reproducible guest build recipe: `guest/build-guest.sh`
   - boot orchestration: `guest/boot-standalone.sh`
   The upstream sources themselves are fetched by those scripts at build
   time; you must keep the scripts (or provide the fetched trees) with any
   redistribution.
3. **The GPL payloads are separable from the MIT OR Apache-2.0 original
   code.** Nothing in the kernel, loader, or model crates is derived from the
   Linux kernel or BusyBox source; the two worlds communicate only through
   published ABI/ABI-adjacent contracts (boot protocol, syscall ABI, cpio
   layout). So the repo's original code stays MIT OR Apache-2.0 regardless of
   the guest payloads, and the two can be redistributed independently.

### Future flexibility (decision points)

- **Keeping the repo MIT/Apache-only:** the guest binaries exist so the live
  demos are reproducible. They can be removed from the committed tree and
  built on demand (`guest/build-guest.sh` downloads the kernel + BusyBox
  sources and produces `bzImage` + `initramfs.cpio.gz`). Nothing in the
  original code depends on the binaries being in the repo; only the committed
  evidence (serial logs) would remain.
- **Publishing the SDK crates:** the model crates are already `MIT OR
  Apache-2.0`; publishing them (`cargo publish`) would need `publish = false`
  removed and crate-level metadata finalized. The guest payloads are not part
  of any crate.
- **Vendoring third-party crates** for offline builds: any vendored registry
  crate must carry its own license text and copyright notices with it; the
  dual license of this repo does not extend to them.

## 5. Audit log of this document

- **Phase X (2026-08-19):** created this document and `LICENSE`; added
  `license = "MIT OR Apache-2.0"` metadata to the `aegis-kernel` and
  `uefi-boot` packages. Verified the full inventory: no other third-party
  files are committed to the tree (the `Debug Files/` directory is
  gitignored; `uefi-boot/server.crt`/`.key` are runtime-generated and
  gitignored).
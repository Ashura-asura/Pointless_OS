# Track 2 — Guest Application Battery: Gap Inventory

Status: **AUTHORIZED, in progress.** This document is the verifiable evidence for
"what the Linux guest can do under QEMU right now" and the named gaps that stand
between the current guest and the `AEGIS_USEFUL_PROMPT.md` §3 battery DoD.

All outcomes below are verbatim guest responses captured in
`guest/out/battery-standalone-serial.log` and `guest/out/battery-standalone-serial2.log`.

## Method
- Booted the existing standalone guest (`guest/out/bzImage`, Linux 6.12.103 +
  BusyBox 1.37.0) under QEMU: `qemu-system-x86_64 -machine pc -cpu max -m 512
  -display none -serial tcp::1234,server,nowait -kernel guest/out/bzImage
  -append 'console=ttyS0'`. SeaBIOS (default, no OVMF) direct `-kernel` boot works.
- The embedded initramfs runs `/init` → `exec /bin/sh </dev/ttyS0 >/dev/ttyS0 2>&1`
  (the "Phase U DoD point" in the init script).
- A Python harness (`drive.py` / `drive2.py`, run from the host) connected to the
  TCP serial, waited for the shell prompt, and issued each probe. Output delimited
  by `__BEGIN__/__END__` markers (and, for the second pass, by the `~ # ` prompt).

## Results

| Battery item (§3) | State | Verbatim evidence |
|---|---|---|
| Guest kernel + init boot | PASS | `Linux (none) 6.12.103 ... x86_64 GNU/Linux`; `/init` reaches `Aegis guest: initramfs up` |
| Shell (`/bin/sh`) | PASS | `shell: BusyBox v1.37.0`; `SHELL=/bin/sh` |
| Job control (bg `&` / `jobs`) | PARTIAL | `sleep 1 & jobs` → `[1]+ Running`; **but** `/bin/sh: can't access tty; job control turned off` (no fg/bg/Ctrl-Z) |
| `/proc` mounted | FAIL | `ls: /proc: No such file or directory`; `head: /proc/meminfo: No such file or directory` |
| `/dev` completeness | FAIL | `ls /dev` → only `console`, `ttyS0` (no `/dev/null`, `/dev/zero`, `/dev/random`, …) → side effect `can't open '/dev/null'` |
| `python3` | FAIL | `/bin/sh: python3: not found` |
| `git` | FAIL | `/bin/sh: git: not found` |
| `vim` | FAIL | `/bin/sh: vim: not found` |
| `nano` | FAIL | `/bin/sh: nano: not found` |
| `gcc` | FAIL | `/bin/sh: gcc: not found` |
| `make` | FAIL | `/bin/sh: make: not found` |
| Networking (`ip`/`ifconfig`) | FAIL | `ls /sys/class/net` empty; `ifconfig: /proc/net/dev: No such file or directory`; `ifconfig: socket: Function not implemented` |

## Per-item gap → contract test

- **Job control (§3.1)**: missing a *controlling tty* on the serial console.
  `/init` does `exec /bin/sh </dev/ttyS0` with no `setsid`/`ioctl(TIOCSCTTY)`.
  Contract test: `fg`/`bg` and `Ctrl-Z` work (today: fails — "job control turned off").
- **`/proc`**: initramfs `/init` never mounts `procfs`. Missing syscall surface:
  `/proc`. Blocks `ps`/`top`/`free` and the §3.1 `ps`/`top`/`df` intent.
  Contract test: `ls /proc/self` succeeds.
- **`/dev`**: initramfs only creates `console` + `ttyS0`; no `mdev -s`/`devtmpfs`
  population. Contract test: `test -c /dev/null && echo ok` succeeds.
- **`python3`**: applet/binary absent from rootfs. Contract test: `python3 -c 'print(1)'` exits 0.
- **`git`**: absent. Contract test: `git clone <url-over-e1000e>` writes a repo.
- **`vim`/`nano`**: absent. Contract test: `vim --version` / `nano --version` succeed.
- **`gcc`/`make`**: absent. Contract test: compile + link a trivial C program.
- **Networking**: `guest/build-guest.sh:78` sets `CONFIG_NET=n`. No `lo`/`eth0`,
  no `/proc/net`, `socket()` → `Function not implemented`. The §3 e1000e clone path
  is impossible until `CONFIG_NET=y` + an e1000e NIC is present and driven.
  Contract test: `ip link` lists `lo` + `eth0`.

## Why the §3 DoD is not yet met on this machine (hardware/environment gates)

1. **Guest enrichment** (add `python3`/`git`/`vim`/`nano`/`gcc`/`make`, mount
   `/proc` + `/dev`, set `CONFIG_NET=y`) requires re-running `build-guest.sh`,
   i.e. a Linux build environment (kernel + BusyBox toolchain). Not available on
   this Windows/VBS host.
2. **End-to-end DoD** ("`git`/`python3` do real ops, clone over e1000e, script
   file I/O") also needs `vm.rs` to *host* the guest, which is hardware-gated by
   Windows VBS/HVCI (VT-x is unavailable to the Aegis hypervisor here). So the
   full e1000e path cannot be demonstrated on this box.

The verifiable artifact on this machine is therefore this gap inventory plus the
captured serial logs — not a passing contract test.

## Prepared improvements (code ready, run-gated on this host)

The following changes are committed and reviewable on the Windows/VBS dev box,
but their *effect* can only be observed when the guest is rebuilt and booted
under QEMU on a Linux host (the same environment gate as §"Why the §3 DoD is
not yet met"). They advance the battery toward its DoD without claiming a
passing live run here:

- **`guest/build-guest.sh`**: `CONFIG_NET` + `CONFIG_INET` + `CONFIG_PCI` +
  `CONFIG_E1000E` are now enabled, so the §3 e1000e clone path is at least
  kernel-possible. A documented KNOWN GATE notes that `python3`/`git`/`vim`/
  `nano`/`gcc`/`make` are *not* BusyBox applets and require a rootfs
  enrichment step (static binaries or Buildroot) before the contract tests
  for those items can pass.
- **`guest/initramfs/init`**: `mdev -s` populates `/dev` (closes the sparse-
  `/dev` gap); the interactive shell now starts under `setsid` so the kernel
  assigns `/dev/ttyS0` as its controlling terminal, turning job control
  (fg/bg/Ctrl-Z) ON (the prior "job control turned off" PARTIAL).
- **`guest/battery-init.sh`**: added `mdev -s` so the non-interactive battery
  path also sees a full `/dev`.
- **`guest/battery-contract.py`** (new): an automated, CI-ready harness that
  boots QEMU, drives every §3 battery item over the serial console, and exits
  non-zero on any FAIL. Run on a capable host with:

  ```
  python3 guest/battery-contract.py
  QEMU=/usr/bin/qemu-system-x86_64 python3 guest/battery-contract.py
  ```

  It is the automated form of the manual probes below and is the artifact
  that should be wired into CI once the environment gate lifts.

## What IS proven
- The guest kernel + initramfs boots under QEMU and presents a working BusyBox
  `/bin/sh` on the serial console (the Phase U DoD point). Background-process
  start + `jobs` works. This is the baseline every battery item builds on.

## Next actions (when the environment allows)
1. Fix `/init`: mount `proc`/`sys`, run `mdev -s` (or enable `devtmpfs`), and
   `setsid` + `TIOCSCTTY` the shell for real job control.
2. Rebuild the guest with `python3`/`git`/`vim`/`nano`/`gcc`/`make` and
   `CONFIG_NET=y` (+ e1000e).
3. Host via `vm.rs` on a VT-x (no-VBS) machine and run the contract tests above.
4. Wire each contract test into the CI battery so the gaps are regression-gated.

## Evidence artifacts (in repo)
- `guest/out/battery-standalone-serial.log` — first probe pass (echo-on transcript).
- `guest/out/battery-standalone-serial2.log` — clean networking/`/dev`/mounts pass.
- `guest/battery-init.sh` — alternative init-based battery (kept for reuse).
- `guest/battery-commands.txt` — probe command set.
- `guest/enrich-initramfs.sh` — closes the battery-binary KNOWN GATE (adds
  python3/git/vim/nano/gcc/make + libs into the initramfs).

## Native Linux (Kali) runbook — both environment blockers gone

Booting the dual-boot Kali (bare-metal Linux) removes **both** gates at once:
no CRLF/line-ending issue (native LF; `.gitattributes` now also forces
`*.sh`/`*.py` to LF on every checkout), and VT-x is free for `vm.rs` hosting
(Windows VBS/Core-Isolation does not exist here — just keep KVM unloaded so
Aegis's hypervisor can take VMX). This is the path that actually *runs* Track
2, not just prepares it.

Prerequisites (one time):
```
sudo apt-get update
sudo apt-get install -y build-essential ncurses-dev flex bison \
  libssl-dev bc curl qemu-system-x86 python3 git vim nano
# (build-essential provides gcc/make; the rest give the battery binaries + QEMU)
```

Steps:
1. **Build the base guest** (downloads cached after first run; ~5–8 min):
   ```
   bash guest/build-guest.sh "$PWD/guest"
   ```
2. **Close the KNOWN GATE** — add the real battery binaries into the
   initramfs (BusyBox alone does not have them):
   ```
   bash guest/enrich-initramfs.sh "$PWD/guest/initramfs"
   ```
3. **Re-bake the image with the enriched initramfs** (do NOT re-run
   `build-guest.sh` — its `make install` would overwrite the enriched
   `/bin`). Rebuild only the kernel embed + cpio:
   ```
   cd "$HOME/aegis-guest-build/linux-6.12.103"
   make -j"$(nproc)" bzImage
   cp arch/x86/boot/bzImage "$PWD/guest/out/bzImage"
   (cd "$PWD/guest/initramfs" && find . | cpio -o -H newc | gzip > "$PWD/guest/out/initramfs.cpio.gz")
   ```
4. **Run the battery** under QEMU (KVM or TCG both work for the userspace
   battery) and let the contract harness capture evidence:
   ```
   qemu-system-x86_64 -machine pc -cpu max -m 512 -display none \
     -serial tcp::1234,server,nowait \
     -kernel guest/out/bzImage -initrd guest/out/initramfs.cpio.gz \
     -append 'console=ttyS0' &
   python3 guest/battery-contract.py
   ```
   The harness prints `ok`/`FAIL` per item and exits non-zero on any FAIL.
   Capture its output + the QEMU serial to `guest/out/` as evidence.
5. **(Optional, strict §3 DoD)** host the guest under Aegis's own `vm.rs`
   instead of QEMU: unload KVM first so VMX is free, then run the
   `aegis-kernel` VM path against `guest/out/bzImage`. This exercises the
   guest's e1000e driver against Aegis's virtual e1000e (the "clone over the
   existing e1000e path" wording in `AEGIS_USEFUL_PROMPT.md` §3).

What flips from "run-gated" to "done" here: the `git`/`python3` DoD
(non-trivial ops inside the guest) becomes actually demonstrable, with serial
logs committed as evidence per Ground Rule 7.

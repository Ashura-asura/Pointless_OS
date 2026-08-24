# Kali Session Handover — Track 2 live battery run

*Self-contained for a fresh clone / fresh agent. Everything below assumes you
started from `git clone https://github.com/Ashura-asura/Pointless_OS.git`
on a native Linux host (the dual-boot Kali), NOT a copy of the Windows
working tree. All prior work is already on `main` and pushed.*

## TL;DR

The only remaining piece of the post-Track-1 master prompt is the **live
Track 2 guest-app battery run** (`AEGIS_USEFUL_PROMPT.md` §3: shell →
python3 → git → vim/nano → gcc/make inside the Linux guest). It was
environment-gated on Windows (no VT-x for `vm.rs`, no Linux build env). The
fix is to build + run it on native Linux (Kali), where VT-x is free and the
build env exists. This doc is the runbook + handover so the work completes
even if the originating session did not survive the reboot.

## Repo state on `main` (already pushed, do not redo)

| Commit | What |
|---|---|
| `272abcf` | Track 1.5 — §9 generalizes to a write/control task (supervisor monitor+restart) |
| `451f8b7` | Genode research pass — per-VM `DevicePolicy` allow-list on `DeviceSet` |
| `238b32a` | Post-Track-2 roadmap (phases A–E) |
| `9e34e1a` | Track 2 prepared: `battery-contract.py` CI harness + `build-guest.sh` `CONFIG_NET/E1000E` + `init`/`battery-init.sh` `/dev`+job-control fixes |
| `c9526fd` | Roadmap correction: Track 3 stays deferred until Track 2 DoD |
| `c1afe19` | §9 closure audit (§9.1–§9.4 closed; §9.5 reduced, named limits) |
| `d99a314` | Kali-ready tooling: `.gitattributes` (LF for `*.sh/*.py`), `guest/enrich-initramfs.sh` (battery binaries), runbook in `TRACK2_GUEST_BATTERY.md` |
| `122ec01` | Portability note: Kali is build host only, push to GitHub, Windows pulls |

No kernel-crate code is unfinished; the Rust suite is green at 818 on the last
run. The work left is purely the **guest-side battery execution + committed
evidence**.

## Environment decision (why Kali)

- Native Linux removes both gates: no CRLF/line-ending issue (`.gitattributes`
  already forces LF), and VT-x is free for `vm.rs` hosting (Windows VBS/Core
  Isolation does not exist here).
- 100 GB Kali disk is ample (kernel build peaks ~5–15 GB).
- **Work in Kali's native ext4, not the mounted Windows partition** — a kernel
  build uses symlinks heavily and is slow/flaky on NTFS.
- Push results to GitHub; Windows just `git pull`s. Nothing Kali-specific is
  baked into the project.

## Prerequisites (one time, in Kali)

```bash
sudo apt-get update
sudo apt-get install -y build-essential ncurses-dev flex bison \
  libssl-dev bc curl qemu-system-x86 python3 git vim nano
# build-essential provides gcc/make; the rest give the battery binaries + QEMU
```

## Execution (copy-paste)

```bash
# 1. clone (fresh session) — or: cd into the clone you already have
git clone https://github.com/Ashura-asura/Pointless_OS.git ~/pointless
cd ~/pointless

# 2. build the base guest (downloads cached after first run; ~5–8 min on 8 cores)
bash guest/build-guest.sh "$PWD/guest"

# 3. close the battery-binary KNOWN GATE: add python3/git/vim/nano/gcc/make
#    + their shared libs + dynamic linker into the BusyBox initramfs.
#    (Verified earlier: the copied python3 actually runs.)
bash guest/enrich-initramfs.sh "$PWD/guest/initramfs"

# 4. re-bake the image. DO NOT re-run build-guest.sh here — its `make install`
#    would overwrite the enriched /bin. Rebuild only the kernel embed + cpio.
cd "$HOME/aegis-guest-build/linux-6.12.103"
make -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "$PWD/guest/out/bzImage"
(cd "$PWD/guest/initramfs" && find . | cpio -o -H newc | gzip > "$PWD/guest/out/initramfs.cpio.gz")

# 5. run the battery under QEMU and capture evidence
qemu-system-x86_64 -machine pc -cpu max -m 512 -display none \
  -serial tcp::1234,server,nowait \
  -kernel guest/out/bzImage -initrd guest/out/initramfs.cpio.gz \
  -append 'console=ttyS0' &
python3 guest/battery-contract.py | tee guest/out/battery-contract-kali.log
# expect: every item prints "ok"; harness exits 0. FAIL items mean the enrich
# step missed a binary — re-check guest/enrich-initramfs.sh output.
```

### Optional: strict §3 DoD (host under Aegis's own `vm.rs`)

The QEMU run above validates the guest userspace battery. For the strictest
reading of `AEGIS_USEFUL_PROMPT.md` §3 ("clone over the existing e1000e
path"), host the guest under Aegis's `vm.rs` instead of QEMU: unload KVM so
VMX is free (`sudo rmmod kvm_intel kvm`), then run the `aegis-kernel` VM path
against `guest/out/bzImage`. This exercises the guest's e1000e driver against
Aegis's virtual e1000e.

## Commit & push the evidence

```bash
git add guest/out/bzImage guest/out/initramfs.cpio.gz guest/out/kernel.config \
        guest/out/battery-contract-kali.log
git commit -m "track2: live battery run on Kali (python3/git/vim/nano/gcc/make verified)"
git push
```

Then (back on Windows, or anywhere) `git pull` retrieves the artifacts. The
Kali clone in `~/pointless` can be deleted — it is not required to persist.

## If this session died and you are a fresh agent

1. Read `Docs/TRACK2_GUEST_BATTERY.md` (the runbook) and this file.
2. Confirm you are on native Linux with the apt prerequisites installed.
3. Run Execution steps 1–5 above.
4. On success, commit + push per "Commit & push the evidence".
5. Update `Docs/TRACK2_GUEST_BATTERY.md` "Evidence artifacts" with the new
   `battery-contract-kali.log`, and mark the battery items PASS (they were
   PARTIAL/FAIL before the enrich step).
6. Optionally update `POST_TRACK2_ROADMAP.md` Phase A to "done" once the
   evidence is committed.

## Honest limitations / notes

- The battery-binary gap (python3/git/vim/nano/gcc/make are not BusyBox
  applets) is closed by `guest/enrich-initramfs.sh`, which copies each binary
  + its `.so` deps + the dynamic linker into the initramfs. **Re-running
  `build-guest.sh` after enriching would wipe them** — always re-bake via
  step 4, never re-run the full script.
- The `vm.rs` hosting path (strict DoD) needs VMX free; unload KVM first.
- Nothing here touches the Rust kernel crate; the 818-test suite is unaffected.
- Per the master prompt's sequencing, Track 3 (Windows guest, broader
  device-model breadth, fuller distro) stays deferred until this Track 2 DoD
  is met (see `POST_TRACK2_ROADMAP.md` Phase B).

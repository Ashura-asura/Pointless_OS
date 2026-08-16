# SESSION HANDOFF — READ THIS FIRST, THEN DELETE IT

> **Instruction to the next session:** after reading this file, delete it
> (`git rm SESSION_HANDOFF.md`), commit the deletion, and continue. It exists
> only to reorient you; it should not live in the repo.

## Repo / remote
- `C:\Users\bisha\Desktop\Pointless_OS`, branch `main`, remote `origin` =
  https://github.com/Ashura-asura/Pointless_OS.git
- HEAD at handoff: `6197b1a`. Reorient with: `git log --oneline -6` +
  `git status`.

## Ground rules (established across phases — follow them)
- Keep `Cargo.lock` clean (no dependency changes unless truly needed).
- Count tests yourself; never restate a number you didn't verify.
- Label honest limits in `HONEST_STATUS.md` (closed/reduced/inherent) and add a
  commit-log row for every commit.
- Evidence logs go in `uefi-boot/` and are **force-added** (`git add -f`,
  `*.log` is gitignored) — matches the committed `serial-phase-*.log`/
  `serial-qemu-*.log` convention. Never commit `.vmdk`/`.vmx`/`qemu-*.ps1`.
- Current image: `uefi-boot/aegis-boot-now.img` (untracked, gitignored).
- Only commit when the user asks.

## Current state (all verified, committed, pushed)
- **Full-demo boot regression closed** (`570de98`): QEMU `#BP` at `RIP=0xB102`
  (page-fault stub now has the pop/iretq epilogue mirroring the timer stub) +
  VMware `#GP` at `RIP=0x700000000034` (Linux exit path now
  `switch_away_from` after `kill_current`). QEMU 4 clean boots + VMware 1 clean
  boot, 0 exceptions.
- **Fail-closed netstack** (`69a01d8`): all five `sys_net_*` gates return an
  error instead of reaching `nic_mut().expect("netif not initialized")` panic
  when no NIC is present; fleet `open_link`/poll loops guarded; `is_online()`.
- **`ERR_NET_OFFLINE` (`-2`)** (`0b4098c`, `6197b1a`): distinct from the
  generic `-1` cap-denial; the advisor detects it on its first `net_connect`
  poll and skips instantly (`[advisor] no NIC present - network demo
  skipped`). No-NIC live boot: advisor bails at log line ~460 (was ~11630).
- **Tests**: 496 kernel (`cargo test --features chaos-demo`) + 128 model
  (`cargo test` in `aegis/`) + 22 uefi-boot (`13 elf_contract + 9
  fleet_cfg_contract`) = **646, 0 failures**. fmt/clippy clean.

## Build & verify commands (Windows git-bash)
- Kernel: `cargo build --release --features kernel --target x86_64-unknown-none`
  in `aegis-kernel/`, then
  `cp target/x86_64-unknown-none/release/aegis-kernel ../uefi-boot/aegis-kernel.bin`
- Loader: `cargo build --release --features uefi --target x86_64-unknown-uefi`
  in `uefi-boot/`
- Image: `python build_image.py aegis-boot-now.img` then
  `python add_startup.py aegis-boot-now.img` in `uefi-boot/`
- QEMU visible demo: `powershell -NoProfile -ExecutionPolicy Bypass -File
  qemu-live-demo.ps1` (writes `serial-live-demo.log`; QEMU default e1000+SLIRP).
- QEMU no-NIC test: `qemu-nonic-test.ps1` (`-net none`, writes
  `serial-nonic-test.log`).
- Kill QEMU: `taskkill //F //IM qemu-system-x86_64.exe` (double-slash for
  git-bash).
- VMware: `"C:\Program Files\VMware\VMware Workstation\vmrun.exe" -T ws start
  aegis-boot-now.vmx nogui` (serial → `serial-vmware-now.log`). VMX has
  ethernet0 enabled (e1000/NAT) — required, else the ring-3 net demos used to
  panic (now fail closed).

## Display behavior (expected, not a bug)
- **QEMU**: Bochs-VBE GPU present → 800x600 framebuffer desktop (windows,
  status bar, clock).
- **VMware**: VM-SVGA is NOT Bochs-VBE → kernel logs `GPU: no Bochs-VBE
  display device - text backend only` and shows the **80x25 text-mode
  compositor** (the `aegis:~$` interactive shell with transparent dots + status
  bar). 0 exceptions; keyboard live. This is the expected VMware output.

## Open threads / next steps
1. **VMware SVGA driver** — add a VMware SVGA (PCI id 0x90000002) framebuffer
   driver so VMware shows the GPU desktop instead of the text fallback.
2. **Live wire demo** — run QEMU on the socket netdev +
   `uefi-boot/e1000_host_listener.py` (serves ARP + TCP 8080 HTTP + TLS 8443)
   plus a 443 echo for the advisor, so the HTTP/TLS/advisor exchanges complete
   on screen instead of timing out. Needs a `-netdev socket,connect=127.0.0.1:PORT
   -device e1000,mac=52:54:00:12:34:56` launcher.
3. User's own next phase — consult the Phase plan in `HONEST_STATUS.md`.
# Open Problems — Pointless OS / Aegis Boot

*Last updated: 2026-08-12. Session state at commit `bf78794` (PCI live enumeration follows).*

## Current Status
All critical issues have been resolved. The kernel boots and runs in both QEMU and VMware Workstation 26 with 0 exceptions. The IPC system (endpoints, call/serve/reply, capabilities) is functional at the model level. The boot demo is now **visible on the VM display** — a VGA text console mirrors the COM1 log white-on-black (verified via screendump glyph decoding).

### Honest Limits
- The kernel is a **single-threaded in-process model** — all contract tests are deterministic model logic, not real hardware isolation.
- QEMU/VMware verification proves the boot flow and IPC logic work under virtualization; it does **not** prove correctness on physical hardware.
- The IPC system has **no contract tests** (it requires real/virtual hardware for ring-3 transitions). Its proof is the live QEMU/VMware boot.
- TLA+ model-checking is finite-instance (2 tasks, 3 slots) — evidence, not inductive proof.
- No seL4-class formal proof exists for `aegis-kernel`. The design follows seL4-lineage architecture but does not inherit seL4's verification.
- AI behavior is monitored, not verified. The adaptive ceiling is property-tested, not formally proven.
- Full Windows/Linux compatibility is explicitly unsolved by translation alone (design doc).

### Resolved
- ✅ **VMware triple-fault crash** — Root cause identified: idle loop ran on shared `KERNEL_STACK`, its saved `rsp` got clobbered by other tasks. Fixed by allocating a dedicated idle stack (`cpu::IDLE_STACK_TOP`) and using `switch_to_idle_stack(entry)`.
- ✅ **schedule_next wrap-around bug** — When `cur=3` and `spawned=4`, `c+1 >= spawned` mapped to `usize::MAX` → `return Some(usize::MAX)` immediately, never checking tasks 0–2. Fixed to wrap to 0 and only return idle after checking all `spawned` tasks.
- ✅ **GPT/FAT16 layout** — All partition type GUIDs, bounds, BPB geometry, and backup GPT header corrected per spec. `verify()` in `build_image.py` now independently validates all fields.
- ✅ **VMware VM config** — `guestOS` changed from invalid `"uefi"` to `"other-64"` (kept `firmware = "efi"`).
- ✅ **STARTUP.NSH** — Added `add_startup.py` to patch `FS0:\EFI\BOOT\BOOTX64.EFI` into FAT16 ESP root so EFI shell auto-boots kernel.
- ✅ **CI workflows** — `.github/workflows/ci.yml` (kernel+UEFI builds, clippy) and `.github/workflows/test.yml` (fmt, clippy, test for `aegis` workspace + `aegis-kernel`). 242 tests pass.
- ✅ **Blank/garbled VM display** — the GTK window showed no text or wrong glyphs. Root causes (all fixed in `aegis-kernel/src/vga.rs`): SR4 chain4 bit made QEMU scatter text writes by `addr&3`; SR2=0x0F let the odd/even parity rule stamp plane 2 (the font area) with screen characters (SR2=0x03 keeps chars on plane 0 / attrs on plane 1); a 0x3C0 readback during the flip-flop data phase corrupted `ar[0]` (green background); cursor + light-gray attr cleaned up. Verified: plane-2 glyph probe returns the embedded font, DAC readback matches the palette, screendump decodes to the exact Aegis log lines, pixels = black `000000` bg + white `ffffff` fg.
- ✅ **NX bit enforcement** — every non-code mapping (kernel stacks/BSS, VGA framebuffer, LAPIC MMIO, ring-3 stacks) is now NX; the executable window is the kernel image's R+X PT_LOAD parsed from the ELF at runtime; per-user PML4s clone the low tables (USER bits never leak into shared kernel tables); IA32_EFER.NXE set explicitly. Ring-3 page faults now KILL the faulting task and resume the scheduler instead of halting the whole kernel. Verified: boot banner prints the parsed text window, `nx-test` fetching from 0xB8000 faults with the NX instruction-fetch bit, isolation-test + nx-test + IPC demo all complete in one boot, 0 exceptions.

### Verified
- ✅ **QEMU**: `echo reply: ping from client`, 0 exceptions, 11k+ lines of output
- ✅ **QEMU display**: white-on-black boot log visible (VGA text console, screendump-verified glyph-for-glyph)
- ✅ **QEMU**: per-task memory isolation — `iso-test` task's kernel-only read #PFs, task killed, kernel keeps running
- ✅ **QEMU**: NX enforcement — only kernel text executable; `nx-test` instruction fetch from 0xB8000 #PFs (NX bit set in error code), task killed, kernel keeps running (0 exceptions, 13k ticks)
- ✅ **QEMU**: live PCI enumeration (q35) — 6 devices found on bus 0 via legacy 0xCF8/0xCFC ports: host bridge 8086:29C0, stdvga 1234:1111 (2 MMIO BARs), e1000e 8086:10D3, ICH9 ISA bridge, AHCI SATA 8086:2922 (5 BARs: 4 MMIO + 2 IO), SMBus; VID/DID/class/prog-if/rev/BARs decode correctly in the boot log
- ✅ **VMware**: idle stack at `0x34000`, full IPC flow (`ipc_serve`→`ipc_call`→`ipc_serve`→`echo reply`), 0 exceptions, runs past tick 4200

## What Was Built
### Microkernel IPC System
- **`aegis-kernel/src/ipc.rs`** — Endpoints, `ipc_call`, `ipc_serve`, `ipc_reply`, `ipc_endpoint_create`, `ipc_cap_grant`
- **`aegis-kernel/src/cap.rs`** — `Cap` enum + `CapTable` type
- **`aegis-kernel/src/syscall.rs`** — Syscall numbers 5–9 for IPC
- **`aegis-kernel/src/tasks.rs`** — `TaskState`, `Caps`, `state`, `blocked_ep`, `schedule_next`, `block_current`/`unblock_task`, `grant_cap`, `set_task_cap`, `switch_away_from`, `context_frame`, `timer_preempt`, `init_idle_frame`

### Ring-3 Demo
- Echo server/client demo in `main.rs` using IPC endpoints

### VGA Text Console
- `aegis-kernel/src/vga.rs` — `vga_enter_text_mode` (Bochs VBE disable, CRTC/GC/AC programming, 16-color DAC palette, cursor off), `vga_upload_font` (8x16 font into plane 2 via map A), `vga_fmt_line`/`vga_write_bytes` (screen mirror)
- `aegis-kernel/src/font.rs` — canonical 8x16 font, 0x00..=0x7F
- `sprintln!` mirrors every line to COM1 + screen; the ring-3 `Write` syscall mirrors too

## Useful Commands
- **Rebuild image**: `python build_image.py` (from `uefi-boot/`) — must print `VERIFY OK`
- **Build kernel**: `cargo build --release --features kernel --target x86_64-unknown-none` (from `aegis-kernel/`)
- **vmrun**: `C:\Program Files\VMware\VMware Workstation\vmrun.exe`
- **Evidence**: `uefi-boot/serial.log`, `uefi-boot/vmware.log`

## Notes
- The kernel `[[bin]]` has `required-features = ["kernel"]` — a plain `cargo build --target x86_64-unknown-none` silently skips the bin and links a stale binary. Always use `--features kernel`.
- The vmdk is a monolithicFlat descriptor pointing at `aegis-boot.img` — regenerating the img is enough; no vmdk conversion needed.
- Runtime junk (vmware*.log, serial.log, *.lck, *.vmem, *.vmss, *.bak, *.png) is gitignored.

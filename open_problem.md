# Open Problems — Pointless OS / Aegis Boot

*Last updated: 2026-08-11. Session state at commit `0b8d002` (pushed to origin/main).*

## Current Status
All critical issues have been resolved. The kernel boots and runs in both QEMU and VMware Workstation 26 with 0 exceptions. The IPC system (endpoints, call/serve/reply, capabilities) is functional at the model level.

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
- ✅ **CI workflows** — `.github/workflows/ci.yml` (kernel+UEFI builds, clippy) and `.github/workflows/test.yml` (fmt, clippy, test for `aegis` workspace + `aegis-kernel`). 238 tests pass.

### Verified
- ✅ **QEMU**: `echo reply: ping from client`, 0 exceptions, 11k+ lines of output
- ✅ **VMware**: idle stack at `0x34000`, full IPC flow (`ipc_serve`→`ipc_call`→`ipc_serve`→`echo reply`), 0 exceptions, runs past tick 4200

## What Was Built
### Microkernel IPC System
- **`aegis-kernel/src/ipc.rs`** — Endpoints, `ipc_call`, `ipc_serve`, `ipc_reply`, `ipc_endpoint_create`, `ipc_cap_grant`
- **`aegis-kernel/src/cap.rs`** — `Cap` enum + `CapTable` type
- **`aegis-kernel/src/syscall.rs`** — Syscall numbers 5–9 for IPC
- **`aegis-kernel/src/tasks.rs`** — `TaskState`, `Caps`, `state`, `blocked_ep`, `schedule_next`, `block_current`/`unblock_task`, `grant_cap`, `set_task_cap`, `switch_away_from`, `context_frame`, `timer_preempt`, `init_idle_frame`

### Ring-3 Demo
- Echo server/client demo in `main.rs` using IPC endpoints

## Useful Commands
- **Rebuild image**: `python build_image.py` (from `uefi-boot/`) — must print `VERIFY OK`
- **Build kernel**: `cargo build --release --features kernel --target x86_64-unknown-none` (from `aegis-kernel/`)
- **vmrun**: `C:\Program Files\VMware\VMware Workstation\vmrun.exe`
- **Evidence**: `uefi-boot/serial.log`, `uefi-boot/vmware.log`

## Notes
- The kernel `[[bin]]` has `required-features = ["kernel"]` — a plain `cargo build --target x86_64-unknown-none` silently skips the bin and links a stale binary. Always use `--features kernel`.
- The vmdk is a monolithicFlat descriptor pointing at `aegis-boot.img` — regenerating the img is enough; no vmdk conversion needed.
- Runtime junk (vmware*.log, serial.log, *.lck, *.vmem, *.vmss, *.bak, *.png) is gitignored.

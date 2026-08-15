//! Phase J: the real ring-3 execution vehicle `linux_compat.rs` names as
//! its own missing piece ("no real ring-3 trap, no lightweight-VM
//! execution vehicle"). This module closes exactly that gap, and nothing
//! more — one real, unmodified, standard-toolchain-compiled minimal Linux
//! ELF binary, executing to completion in ring 3, its syscalls genuinely
//! intercepted and routed through the existing `linux_abi`/`linux_compat`
//! translation and capability gate. Smallest binary that proves the path,
//! per the roadmap's own scoping guidance — not a general ELF/libc/loader
//! story.
//!
//! # What's real here
//! - `LINUX_HELLO_ELF` is a genuine, standard-toolchain-compiled static
//!   x86-64 ELF executable (single `PT_LOAD` segment, R+E), loaded through
//!   this kernel's own `elf_loader::parse_elf` — the exact same parser
//!   that loads the kernel itself, not a special-cased reader for this one
//!   file. On this build host it is produced by the LLVM toolchain shipped
//!   with the pinned Rust toolchains (`llc` + `ld.lld`, see
//!   `build-linux-hello.bat` / `linux-hello.ll` / `link-hello.ld`); the
//!   committed `.elf` is the byte-identical single-PT_LOAD R+E binary. On
//!   a host with GNU binutils, an equivalent `as --64` + `ld` path yields
//!   the same layout.
//! - Its syscalls use `int 0x80` with the real x86-64 Linux syscall
//!   numbers (`linux_abi::SYS_WRITE`=1, `SYS_EXIT`=60) and the real Linux
//!   argument-register convention (rdi, rsi, rdx, r10, r8, r9) — a
//!   deliberate, disclosed scoping choice per the roadmap: reuse this
//!   kernel's existing `int 0x80`-style gate as the entry *mechanism*
//!   rather than build the `SYSCALL`/`SYSRET` MSR path from scratch. The
//!   syscall *numbers* and *argument registers* are the unmodified real
//!   ABI; only the trap instruction differs from a real Linux kernel's
//!   primary (`syscall`) entry point.
//!
//! # What's still honestly out of scope
//! A general Linux binary (libc, dynamic linking, `mmap`-backed heap, a
//! writable data segment) is not this phase's job — see the module doc on
//! `linux_compat.rs` and the master roadmap's own Phase J scoping.

use crate::linux_abi::{AegisOperation, SyscallArgs};
use crate::linux_compat::{LinuxCompatLayer, Personality};

/// A real, standard-toolchain-compiled static Linux x86-64 ELF binary:
/// `write(1, "...", 49)` then `exit(0)`, via `int 0x80`. Built from
/// `linux-hello.ll` (LLVM IR with the exact `mov`/`lea`/`int $0x80`
/// sequence) + `ld.lld` on this host, not hand-encoded bytes; the
/// single `PT_LOAD` segment is R+X and holds both the code and the message.
static LINUX_HELLO_ELF: &[u8] = include_bytes!("../linux-hello.elf");

/// Fixed load address for the single loaded segment. Chosen well clear of
/// the kernel's own identity-mapped low memory and every ring-3 task's
/// stack region (both live under `create_user_pml4`'s 1 GB stack window);
/// a canonical, unused high user-space-style address is the standard
/// convention for "this is user code, not kernel/stack memory" on x86-64.
const LINUX_CODE_VADDR: u64 = 0x0000_7000_0000_0000;

/// This demo spawns exactly one Linux-personality task; tracked so the
/// syscall trap can cheaply check "is the current task the Linux one"
/// without a general per-task personality table this phase doesn't need
/// yet (see module doc: smallest binary that proves the path).
static mut LINUX_TASK_IDX: usize = usize::MAX;
static mut LINUX_COMPAT_ID: u32 = 0;
static mut LINUX_COMPAT: Option<LinuxCompatLayer> = None;

/// Index of the spawned Linux task, if any (`usize::MAX` = none spawned).
pub fn linux_task_idx() -> usize {
    unsafe { core::ptr::read(core::ptr::addr_of!(LINUX_TASK_IDX)) }
}

/// Parse, map, and spawn the embedded Linux ELF as a ring-3 task.
///
/// `task_stack_base`/`cpl0_stack_base` follow the exact same contract as
/// `tasks::spawn_user` — two 16 KiB regions the kernel owns for the task's
/// lifetime, distinct from every other task's stacks.
///
/// # Safety
/// Same as `tasks::spawn_user`, plus: must be called at most once (this
/// phase tracks a single Linux task; a second call would silently
/// overwrite the tracked index of the first).
pub unsafe fn spawn_linux_hello(
    task_stack_base: u64,
    cpl0_stack_base: u64,
) -> Result<usize, &'static str> {
    let program = crate::elf_loader::parse_elf(LINUX_HELLO_ELF)?;
    if program.segment_count != 1 {
        return Err("expected exactly one PT_LOAD segment (R+E, no data segment)");
    }
    let seg = program.segments[0];
    const PF_W: u32 = 2;
    if seg.flags & PF_W != 0 {
        return Err("writable segment not supported by this minimal loader");
    }
    if seg.memsz > 4096 {
        return Err("segment larger than one page not supported by this minimal loader");
    }

    let phys = crate::frame::alloc_global().ok_or("out of physical frames")?;
    // Zero the whole page first: correctly implements memsz > filesz
    // zero-fill semantics (not needed for this exact binary, where
    // filesz == memsz, but this loader is written to the real ELF
    // contract, not special-cased to one file's exact sizes) and avoids
    // leaking whatever stale content the frame previously held into a
    // new task's executable page.
    core::ptr::write_bytes(phys as *mut u8, 0, 4096);
    let src = LINUX_HELLO_ELF
        .get(seg.offset as usize..(seg.offset + seg.filesz) as usize)
        .ok_or("segment file range out of bounds")?;
    core::ptr::copy_nonoverlapping(src.as_ptr(), phys as *mut u8, src.len());

    // Entry point is inside the loaded segment; this loader only supports
    // a single page, so the whole segment (and thus the entry point) sits
    // at a fixed offset from LINUX_CODE_VADDR.
    let entry_offset = program
        .entry
        .checked_sub(seg.vaddr)
        .ok_or("entry before segment start")?;
    if entry_offset >= 4096 {
        return Err("entry point outside the mapped page");
    }
    let entry_addr = LINUX_CODE_VADDR + entry_offset;
    // SAFETY (of this transmute): `entry_addr` will be mapped executable
    // in the task's own address space by `map_user_code_page` below
    // before the task is ever scheduled; the task-switch path only ever
    // uses this value as a raw RIP, the same way it uses every other
    // ring-3 task's Rust-function entry pointer — see `TaskFrame::fresh_user`.
    let entry: extern "sysv64" fn() -> ! = core::mem::transmute(entry_addr);

    let idx = crate::tasks::spawn_user("linux-hello", entry, task_stack_base, cpl0_stack_base)
        .ok_or("task table full")?;
    let pml4 = crate::tasks::context_pml4(idx);
    if !crate::page_tables::map_user_code_page(pml4, LINUX_CODE_VADDR, phys) {
        return Err("failed to map loaded segment as executable in the task's address space");
    }

    // Permissive-but-scoped: file + process capabilities only (matches
    // this demo's actual needs — write + exit), no network/memory/exec.
    // Mirrors the existing kernel-mode compat demo's file-only scope in
    // main.rs, just now gating a task that genuinely executes rather than
    // a hand-called dispatch from kernel code.
    let mut scope = crate::agent::CapabilityScope::restrictive();
    scope.allowed_syscalls[crate::linux_compat::CAP_FILE as usize] = true;
    scope.allowed_syscalls[crate::linux_compat::CAP_PROCESS as usize] = true;

    let mut layer = LinuxCompatLayer::new();
    let compat_id = layer.register(Personality::LinuxCompat, scope)?;

    core::ptr::write(core::ptr::addr_of_mut!(LINUX_COMPAT), Some(layer));
    core::ptr::write(core::ptr::addr_of_mut!(LINUX_COMPAT_ID), compat_id);
    core::ptr::write(core::ptr::addr_of_mut!(LINUX_TASK_IDX), idx);
    Ok(idx)
}

/// Real Linux syscall convention: arg1=rdi, arg2=rsi, arg3=rdx, arg4=r10,
/// arg5=r8, arg6=r9 — distinct from this kernel's own native convention
/// (arg1=rsi, arg2=rcx, arg3=rdx, arg4=r8), and from Linux syscall
/// *numbers* colliding with native ones at the same value (native 2 =
/// Read, Linux 2 = Open) — this is why Linux-personality dispatch must be
/// a genuinely separate path from `syscall::dispatch`, not a shared one
/// with different argument parsing bolted on.
///
/// Frame offsets match `syscall_trap_rust`'s own documented layout
/// exactly (r10=2, r9=3, r8=4, rdi=5, rsi=6, rdx=7, rax=10) — every
/// register this needs is already saved by the existing stub; no
/// assembly changes were required for this phase.
///
/// # Safety
/// `frame` must point at the live syscall regs block pushed by
/// `syscall_stub` on the current kernel stack — identical contract to
/// `syscall_trap_rust`.
pub unsafe fn dispatch_linux_syscall(frame: *mut u64) -> i64 {
    let num = *frame.add(10); // rax
    let args = SyscallArgs {
        arg1: *frame.add(5), // rdi
        arg2: *frame.add(6), // rsi
        arg3: *frame.add(7), // rdx
        arg4: *frame.add(2), // r10
        arg5: *frame.add(4), // r8
        arg6: *frame.add(3), // r9
    };

    let compat = match (*core::ptr::addr_of_mut!(LINUX_COMPAT)).as_mut() {
        Some(c) => c,
        None => return -1,
    };
    let op = match compat.dispatch(
        core::ptr::read(core::ptr::addr_of!(LINUX_COMPAT_ID)),
        num,
        args,
    ) {
        Ok(op) => op,
        Err(_) => return -1,
    };

    // Execute exactly the operations this minimal binary needs (write,
    // exit). A general syscall executor is out of this phase's scope —
    // `translate`+`translate_and_check` already proved every other
    // operation and denial path at the model level (linux_compat.rs's own
    // test suite); this phase's job was proving one real binary's real
    // syscalls reach that gate, not building an executor for all of them.
    match op {
        AegisOperation::Write { fd: 1, count } => {
            let buf = core::slice::from_raw_parts(args.arg2 as *const u8, count as usize);
            let mut w = crate::serial::SerialWriter;
            w.write_bytes(buf);
            crate::vga::vga_write_bytes(buf);
            count as i64
        }
        AegisOperation::Exit { code } => {
            let id = core::ptr::read(core::ptr::addr_of!(LINUX_COMPAT_ID));
            let denials = compat.denials(id).unwrap_or(0);
            crate::sprintln!(
                "Aegis: [linux-hello] real Linux binary called exit({}) via int 0x80 — syscall denials so far: {}",
                code,
                denials
            );
            crate::tasks::kill_current();
            // The task is now Zombie: returning to the syscall stub would
            // iretq the dead Linux task back into ring-3 (VMware observed a
            // #GP at its resumed RIP after exit(0)). Switch away to the next
            // context instead — the same primitive the blocking IPC path
            // uses; the zombie frame is never scheduled again, so this call
            // chain is abandoned for good.
            crate::tasks::switch_away_from(crate::tasks::current_idx());
            0
        }
        _ => -1, // translated and allowed, but this demo doesn't execute it
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_elf_parses_as_one_re_segment() {
        let program = crate::elf_loader::parse_elf(LINUX_HELLO_ELF).unwrap();
        assert_eq!(program.segment_count, 1);
        let seg = program.segments[0];
        const PF_R: u32 = 4;
        const PF_X: u32 = 1;
        assert_eq!(seg.flags & (PF_R | PF_X), PF_R | PF_X);
        assert_eq!(
            seg.flags & 2,
            0,
            "must not be writable — this loader only maps R+E"
        );
        assert!(seg.memsz <= 4096);
        assert!(program.entry >= seg.vaddr && program.entry < seg.vaddr + seg.memsz);
    }

    #[test]
    fn embedded_elf_is_a_real_binary_not_a_stub() {
        // Sanity check this is genuinely the compiled artifact, not an
        // accidentally-empty or truncated file.
        assert!(LINUX_HELLO_ELF.len() > 64); // bigger than just an ELF header
        assert_eq!(&LINUX_HELLO_ELF[0..4], &[0x7F, b'E', b'L', b'F']);
    }
}

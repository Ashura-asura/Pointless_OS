//! Phase K + Phase U-6: VT-x (VMX) bring-up and the hypervisor run loop —
//! the foundation of the design doc's "VM-based full-fidelity path"
//! (§7 Phase 9).
//!
//! Honest scope, stated up front per this repo's own Ground Rule 6: this
//! machine has no VT-x (`VirtualizationFirmwareEnabled=False`), so everything
//! here is written against the SDM and verified by contract tests on the
//! pure decode/encoding logic; the hardware-dependent half (trampolines,
//! VMCS writes, `vmlaunch`/`vmresume`) has never run on a real CPU. The
//! bring-up demo gets a real CPU into VMX root operation, launches a
//! minimal real-mode guest (`cpuid; hlt; jmp $-2`), and proves a full
//! VM-entry -> guest-executes -> VM-exit -> host-handles round trip. The
//! run loop (Phase U-6) adds what sits ON TOP: a resumable VM
//! (`vmlaunch` then repeated `vmresume`), nested paging (EPT),
//! external-interrupt/HLT/I/O VM-exit dispatch, and in-guest device
//! emulation via `Vm::handle_io` — the exact machinery a real Linux guest
//! image needs once it boots under Aegis's hypervisor on VT-x hardware.
//!
//! I could not compile, run, or verify the hardware half in the sandbox
//! that wrote it (no VMX/SVM CPU flag present, confirmed via CPUID — see
//! the conversation this shipped in). VMCS field encodings below are the
//! standard Intel SDM Vol. 3C Appendix B values used consistently across
//! the reference literature (KVM's `vmcs.h`, the "Hypervisor From Scratch"
//! / "SimpleVisor" tutorial lineage); the parts most likely to need
//! adjustment on real silicon are the **guest segment state in
//! `setup_guest_state` / `setup_guest_state_from_boot`** — if `vmlaunch`
//! fails with VM-instruction-error 7 ("invalid guest state") or exits
//! immediately with reason 33 (VM-entry failure due to invalid guest
//! state), start there and check against SDM §26.3.1 — and the
//! **trampoline's register dance**, where an error means `vmlaunch` or
//! `vmresume` failed synchronously with CF/ZF set and `VM_INSTRUCTION_ERROR`
//! readable.
//!
//! Wired into `main.rs` (Phase K, feature-gated): building with
//! `--features kernel,vmx-demo` runs the guarded call (`vmx_supported()` then
//! `bringup_demo()` + `run_loop_demo()`) at the END of boot, after every
//! other demo has spawned and the desktop is shown, before interrupts turn
//! on and the idle loop owns the machine. On a CPU without VT-x it prints
//! `no VT-x on this CPU — skipping VMX bring-up demo` and falls through to
//! the normal boot. Normal builds (no `vmx-demo` feature) compile zero VMX
//! code into the kernel image (the module itself stays compiled for its
//! contract tests).

use core::arch::{asm, global_asm};

use crate::ept::eptp;
use crate::virtio::BlockStore;
#[cfg(feature = "vmx-demo")]
use crate::virtio::GuestMem;
use crate::vm::{BootState, Vm};

// ---------------------------------------------------------------------
// MSR numbers (SDM Vol. 4)
// ---------------------------------------------------------------------
const IA32_FEATURE_CONTROL: u32 = 0x3A;
const IA32_VMX_BASIC: u32 = 0x480;
const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const IA32_VMX_EXIT_CTLS: u32 = 0x483;
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;
// Secondary proc-based controls only exist with the TRUE MSRs (or the
// legacy 0x482/0x483 if bit 55 of IA32_VMX_BASIC says so — the
// `adjust_controls` helper picks the right one).
const IA32_VMX_PROCBASED2_CTLS: u32 = 0x48A;
const IA32_VMX_TRUE_PROCBASED2_CTLS: u32 = 0x49A;

// ---------------------------------------------------------------------
// VMCS field encodings (SDM Vol. 3C, Appendix B) — the ones this minimal
// bring-up actually touches.
// ---------------------------------------------------------------------
mod field {
    // 16-bit guest-state
    pub const GUEST_ES_SELECTOR: u64 = 0x0800;
    pub const GUEST_CS_SELECTOR: u64 = 0x0802;
    pub const GUEST_SS_SELECTOR: u64 = 0x0804;
    pub const GUEST_DS_SELECTOR: u64 = 0x0806;
    pub const GUEST_FS_SELECTOR: u64 = 0x0808;
    pub const GUEST_GS_SELECTOR: u64 = 0x080A;
    pub const GUEST_LDTR_SELECTOR: u64 = 0x080C;
    pub const GUEST_TR_SELECTOR: u64 = 0x080E;
    // 16-bit host-state
    pub const HOST_CS_SELECTOR: u64 = 0x0C02;
    pub const HOST_SS_SELECTOR: u64 = 0x0C04;
    pub const HOST_TR_SELECTOR: u64 = 0x0C0C;
    // 64-bit control
    pub const VMCS_LINK_POINTER: u64 = 0x2800;
    pub const TSC_OFFSET: u64 = 0x2020;
    pub const EPTP: u64 = 0x201A;
    // 32-bit control
    pub const PIN_BASED_VM_EXEC_CONTROL: u64 = 0x4000;
    pub const CPU_BASED_VM_EXEC_CONTROL: u64 = 0x4002;
    pub const EXCEPTION_BITMAP: u64 = 0x4004;
    pub const SECONDARY_VM_EXEC_CONTROL: u64 = 0x401E;
    pub const VM_EXIT_CONTROLS: u64 = 0x400C;
    pub const VM_ENTRY_CONTROLS: u64 = 0x4012;
    // 32-bit read-only (VM-exit info)
    pub const VM_INSTRUCTION_ERROR: u64 = 0x4400;
    pub const VM_EXIT_REASON: u64 = 0x4402;
    pub const EXIT_QUALIFICATION: u64 = 0x6400;
    // 32-bit guest-state
    pub const GUEST_ES_LIMIT: u64 = 0x4800;
    pub const GUEST_CS_LIMIT: u64 = 0x4802;
    pub const GUEST_SS_LIMIT: u64 = 0x4804;
    pub const GUEST_DS_LIMIT: u64 = 0x4806;
    pub const GUEST_FS_LIMIT: u64 = 0x4808;
    pub const GUEST_GS_LIMIT: u64 = 0x480A;
    pub const GUEST_LDTR_LIMIT: u64 = 0x480C;
    pub const GUEST_TR_LIMIT: u64 = 0x480E;
    pub const GUEST_GDTR_LIMIT: u64 = 0x4810;
    pub const GUEST_IDTR_LIMIT: u64 = 0x4812;
    pub const GUEST_ES_AR_BYTES: u64 = 0x4814;
    pub const GUEST_CS_AR_BYTES: u64 = 0x4816;
    pub const GUEST_SS_AR_BYTES: u64 = 0x4818;
    pub const GUEST_DS_AR_BYTES: u64 = 0x481A;
    pub const GUEST_FS_AR_BYTES: u64 = 0x481C;
    pub const GUEST_GS_AR_BYTES: u64 = 0x481E;
    pub const GUEST_LDTR_AR_BYTES: u64 = 0x4820;
    pub const GUEST_TR_AR_BYTES: u64 = 0x4822;
    pub const GUEST_INTERRUPTIBILITY_INFO: u64 = 0x4824;
    pub const GUEST_ACTIVITY_STATE: u64 = 0x4826;
    // natural-width control
    pub const CR0_GUEST_HOST_MASK: u64 = 0x6000;
    pub const CR4_GUEST_HOST_MASK: u64 = 0x6002;
    // natural-width guest-state
    pub const GUEST_CR0: u64 = 0x6800;
    pub const GUEST_CR3: u64 = 0x6802;
    pub const GUEST_CR4: u64 = 0x6804;
    pub const GUEST_ES_BASE: u64 = 0x6806;
    pub const GUEST_CS_BASE: u64 = 0x6808;
    pub const GUEST_SS_BASE: u64 = 0x680A;
    pub const GUEST_DS_BASE: u64 = 0x680C;
    pub const GUEST_FS_BASE: u64 = 0x680E;
    pub const GUEST_GS_BASE: u64 = 0x6810;
    pub const GUEST_LDTR_BASE: u64 = 0x6812;
    pub const GUEST_TR_BASE: u64 = 0x6814;
    pub const GUEST_GDTR_BASE: u64 = 0x6816;
    pub const GUEST_IDTR_BASE: u64 = 0x6818;
    pub const GUEST_DR7: u64 = 0x681A;
    pub const GUEST_RSP: u64 = 0x681C;
    pub const GUEST_RIP: u64 = 0x681E;
    pub const GUEST_RFLAGS: u64 = 0x6820;
    // natural-width host-state
    pub const HOST_CR0: u64 = 0x6C00;
    pub const HOST_CR3: u64 = 0x6C02;
    pub const HOST_CR4: u64 = 0x6C04;
    pub const HOST_GDTR_BASE: u64 = 0x6C0C;
    pub const HOST_IDTR_BASE: u64 = 0x6C0E;
    pub const HOST_RIP: u64 = 0x6C16;
}

/// Real-mode-guest access-rights byte constants (SDM §26.3.1.2 / the
/// standard "unrestricted-off real-mode" values used across the VMX
/// tutorial lineage). Least-verified part of this file — see module docs.
mod ar {
    pub const CODE: u32 = 0x9B; // present, S=1, type=0xB (exec/read/accessed), DPL=0
    pub const DATA: u32 = 0x93; // present, S=1, type=0x3 (read/write/accessed), DPL=0
    pub const LDTR_UNUSABLE: u32 = 0x1_0000; // bit 16 = unusable
    pub const TR_BUSY_32: u32 = 0x8B; // present, type=0xB (32-bit TSS busy)
}

/// Primary processor-based VM-execution control bits this run loop needs
/// (SDM §24.6.2). Bit 31 turns on the secondary controls, which gate EPT
/// and unrestricted guest.
mod proc_primary {
    /// External interrupts cause VM-exits (so the PIC can be serviced and
    /// new vectors injected).
    pub const EXT_INT_EXITING: u32 = 1 << 0;
    /// IN/OUT cause VM-exits (so `Vm::handle_io` emulates the 16550/PIC/PIT).
    pub const IO_EXITING: u32 = 1 << 3;
    /// HLT causes a VM-exit (so a guest that "halts" returns to the host
    /// instead of stopping the machine).
    pub const HLT_EXITING: u32 = 1 << 7;
    /// Secondary controls (EPT, unrestricted guest, TSC offsetting) exist.
    pub const SECONDARY_CONTROLS: u32 = 1 << 31;
}

/// Secondary processor-based VM-execution control bits (SDM §24.6.2).
mod proc_secondary {
    /// Nested paging: the guest's CR3 is ignored and the EPT root from the
    /// EPTP field translates every guest-physical address.
    pub const EPT_ENABLE: u32 = 1 << 1;
    /// Guest may run in real/unreal mode without CR0.PE (lets a 32-bit
    /// Linux kernel boot under EPT without VMX root- or ring-0 paging).
    pub const UNRESTRICTED_GUEST: u32 = 1 << 3;
    /// Time-stamp-counter offsetting (per-VM TSC skew; needed once the
    /// guest measures time — the guest must never see the host's TSC).
    pub const TSC_OFFSETTING: u32 = 1 << 17;
}

/// Basic VM-exit reason codes the run loop dispatches (SDM §29.2.1,
/// Table 29-1).
mod exit_reason {
    pub const EXTERNAL_INTERRUPT: u16 = 1;
    pub const HLT: u16 = 12;
    pub const CR_ACCESS: u16 = 28;
    pub const IO_INSTRUCTION: u16 = 30;
    pub const INVALID_GUEST_STATE: u16 = 33;
    pub const MSR_LOADING: u16 = 34;
    pub const EPT_VIOLATION: u16 = 48;
    pub const EPT_MISCONFIGURATION: u16 = 49;
}

/// The subset of VM-exit reasons the run loop handles, classified so the
/// dispatch is contract-testable without a VMX CPU. Everything outside
/// the handled set is `Unhandled` and fails the run (never silently
/// swallowed or re-entered).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExitClass {
    ExternalInterrupt,
    Hlt,
    IoInstruction,
    EptViolation,
    Unhandled { reason: u16 },
}

fn classify_exit(reason: u16) -> ExitClass {
    match reason {
        exit_reason::EXTERNAL_INTERRUPT => ExitClass::ExternalInterrupt,
        exit_reason::HLT => ExitClass::Hlt,
        exit_reason::IO_INSTRUCTION => ExitClass::IoInstruction,
        exit_reason::EPT_VIOLATION => ExitClass::EptViolation,
        r => ExitClass::Unhandled { reason: r },
    }
}

// ---------------------------------------------------------------------
// Low-level MSR / instruction helpers
// ---------------------------------------------------------------------

unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    ((hi as u64) << 32) | lo as u64
}

unsafe fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi, options(nomem, nostack, preserves_flags));
}

unsafe fn read_cr0() -> u64 {
    let v: u64;
    asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags));
    v
}
unsafe fn read_cr3() -> u64 {
    let v: u64;
    asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags));
    v
}
unsafe fn read_cr4() -> u64 {
    let v: u64;
    asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags));
    v
}
unsafe fn write_cr4(v: u64) {
    asm!("mov cr4, {}", in(reg) v, options(nomem, nostack, preserves_flags));
}

/// `vmxon`/`vmclear`/`vmptrld` all take the *physical address* of a region
/// via a memory operand; `vmwrite`/`vmread` take field/value in registers.
unsafe fn vmxon(phys_addr: u64) -> bool {
    let ok: u8;
    asm!(
        "vmxon [{0}]",
        "setna {1}",   // CF=1 or ZF=1 => failure (setna = set if CF|ZF)
        in(reg) &phys_addr,
        lateout(reg_byte) ok,
        options(nostack)
    );
    ok == 0
}

unsafe fn vmclear(phys_addr: u64) -> bool {
    let ok: u8;
    asm!(
        "vmclear [{0}]",
        "setna {1}",
        in(reg) &phys_addr,
        lateout(reg_byte) ok,
        options(nostack)
    );
    ok == 0
}

unsafe fn vmptrld(phys_addr: u64) -> bool {
    let ok: u8;
    asm!(
        "vmptrld [{0}]",
        "setna {1}",
        in(reg) &phys_addr,
        lateout(reg_byte) ok,
        options(nostack)
    );
    ok == 0
}

unsafe fn vmwrite(field: u64, value: u64) -> bool {
    let ok: u8;
    asm!(
        "vmwrite {0}, {1}",
        "setna {2}",
        in(reg) field,
        in(reg) value,
        lateout(reg_byte) ok,
        options(nostack)
    );
    ok == 0
}

unsafe fn vmread(field: u64) -> u64 {
    let value: u64;
    asm!(
        "vmread {1}, {0}",
        in(reg) field,
        lateout(reg) value,
        options(nostack)
    );
    value
}

/// SDM's standard "adjust controls" algorithm: bits that must be 1 (per the
/// allowed-0 half of the capability MSR) are forced on; bits not permitted
/// to be 1 (per the allowed-1 half) are forced off. Uses the TRUE_* MSR if
/// IA32_VMX_BASIC bit 55 says it's available (true on every VMX CPU in
/// practice since Nehalem, but check honestly rather than assume).
///
/// Pure part, factored out so the algorithm is contract-testable without a
/// VMX CPU (the MSR reads are the only hardware-dependent half).
fn adjust_cap_bits(cap: u64, desired: u32) -> u32 {
    let allowed0 = cap as u32;
    let allowed1 = (cap >> 32) as u32;
    (desired | allowed0) & allowed1
}

unsafe fn adjust_controls(true_msr: u32, legacy_msr: u32, desired: u32) -> u32 {
    let basic = rdmsr(IA32_VMX_BASIC);
    let use_true = (basic >> 55) & 1 == 1;
    let cap = rdmsr(if use_true { true_msr } else { legacy_msr });
    adjust_cap_bits(cap, desired)
}

// ---------------------------------------------------------------------
// Feature detection + enabling VMX operation
// ---------------------------------------------------------------------

/// CPUID.1:ECX.VMX[bit 5]. Cheap, safe to call anywhere (no state change).
pub fn vmx_supported() -> bool {
    let ecx: u32;
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("eax") 1u32 => _,
            lateout("ecx") ecx,
            lateout("edx") _,
            options(nostack)
        );
    }
    (ecx >> 5) & 1 == 1
}

/// Sets CR4.VMXE and locks IA32_FEATURE_CONTROL with the VMXON-outside-SMX
/// bit set, if the MSR isn't already locked with that bit off (in which
/// case VMX was disabled by firmware and nothing here can override that —
/// name it plainly rather than silently no-op).
///
/// # Safety
/// Must run before any `vmxon` call, on the CPU that will use VMX.
pub unsafe fn enable_vmx_operation() -> Result<(), &'static str> {
    if !vmx_supported() {
        return Err("CPUID.1:ECX.VMX not set — no VT-x on this CPU");
    }

    let fc = rdmsr(IA32_FEATURE_CONTROL);
    const LOCK_BIT: u64 = 1 << 0;
    const VMXON_OUTSIDE_SMX: u64 = 1 << 2;
    if fc & LOCK_BIT != 0 {
        // Already locked by firmware — we can only proceed if it already
        // permits VMXON outside SMX. We cannot change a locked MSR.
        if fc & VMXON_OUTSIDE_SMX == 0 {
            return Err("IA32_FEATURE_CONTROL locked with VMX disabled by firmware/BIOS");
        }
    } else {
        wrmsr(IA32_FEATURE_CONTROL, fc | LOCK_BIT | VMXON_OUTSIDE_SMX);
    }

    // CR0/CR4 fixed-bit MSRs (IA32_VMX_CR0_FIXED0/1, CR4_FIXED0/1) further
    // constrain which bits may/must be set before VMXON; the common case
    // (paging + protection already on, which this kernel always has) is
    // covered by the kernel's existing CR0/CR4 state. Set CR4.VMXE:
    let cr4 = read_cr4();
    write_cr4(cr4 | (1 << 13)); // CR4.VMXE

    Ok(())
}

// ---------------------------------------------------------------------
// Region allocation (VMXON region + one VMCS) — identity-mapped physical
// frames per this kernel's existing convention (see mem.rs docs).
// ---------------------------------------------------------------------

unsafe fn alloc_vmx_region() -> Result<u64, &'static str> {
    let phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for VMX region")?;
    // Zero it, then stamp the VMCS revision identifier (low 31 bits of
    // IA32_VMX_BASIC) into the first dword — required for both the VMXON
    // region and every VMCS region (SDM §24.2, §31.5).
    let ptr = phys as *mut u8;
    core::ptr::write_bytes(ptr, 0, 4096);
    let revision = (rdmsr(IA32_VMX_BASIC) & 0x7FFF_FFFF) as u32;
    core::ptr::write_volatile(phys as *mut u32, revision);
    Ok(phys)
}

// ---------------------------------------------------------------------
// Guest payload: 5 real-mode bytes — `cpuid; hlt; jmp $-2`. Placed at the
// base of its own frame; guest CS selector/base set so selector*16==base,
// matching real hardware's real-mode convention (see module docs re:
// §26.3.1 if this turns out to be checked more loosely than assumed).
// ---------------------------------------------------------------------

/// The 5-byte real-mode guest program: `cpuid` (0F A2), `hlt` (F4),
/// `jmp $-2` (EB FE — a self-loop so any exit lands while the guest is
/// genuinely executing, and a stray re-entry has nowhere to wander).
const GUEST_CODE: [u8; 5] = [0x0F, 0xA2, 0xF4, 0xEB, 0xFE];

/// Real-address-mode CS selector for a given code-page physical base:
/// `selector = base >> 4` (so `selector*16 == base`, the real-mode
/// convention SDM §26.3.1 checks on entry).
fn real_mode_selector(base: u64) -> u16 {
    ((base >> 4) & 0xFFFF) as u16
}

unsafe fn alloc_guest_code() -> Result<u64, &'static str> {
    let phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for guest code page")?;
    core::ptr::write_bytes(phys as *mut u8, 0xF4, 4096); // fill with HLT as a safety net
    core::ptr::copy_nonoverlapping(GUEST_CODE.as_ptr(), phys as *mut u8, GUEST_CODE.len());
    Ok(phys)
}

// ---------------------------------------------------------------------
// Host/guest register capture used by the exit trampoline below. Rust
// mangles `static`s, so we give the linker an explicit, stable name via
// `#[no_mangle]` (referenced from the asm above and `vmx_report_exit`).
// ---------------------------------------------------------------------

#[no_mangle]
static mut VMX_EXIT_REGS_SYM: [u64; 15] = [0; 15];

// ---------------------------------------------------------------------
// Entry/exit trampoline. VMX does NOT save/restore general-purpose
// registers across VM-entry/VM-exit (only RIP/RSP/RFLAGS/CR*, via the VMCS
// guest-state fields we write explicitly) — so a hand-written asm stub has
// to load the guest's GPRs from `VMX_EXIT_REGS_SYM` before `vmlaunch`/
// `vmresume`, and capture whatever the CPU left in them (the guest's live
// values at the instant of exit) immediately on the other side, before any
// Rust code (which would clobber them) runs. This is the standard pattern
// used by every minimal VMX bring-up in the reference literature.
//
// Both trampolines are entered with a normal `call` from Rust, so `[rsp]`
// holds the caller's return address. They write the *caller's* RSP into
// the VMCS HOST_RSP field before entering: at VM-exit the CPU reloads RSP
// from that field, so `vmx_exit_landing` can `ret` straight back to the
// caller of `vmx_do_launch`/`vmx_do_resume` with the exit already handled.
// RAX is the return convention: 0 = reached via a real VM-exit (guest GPRs
// saved in `VMX_EXIT_REGS_SYM`), 1 = `vmlaunch`/`vmresume` failed
// synchronously (CF/ZF set; read VM_INSTRUCTION_ERROR). R11 is used as the
// base pointer, so it is stashed/restored around the load sequence (it
// must be loaded LAST of all registers, since it is the base).
//
// `VMX_EXIT_REGS_SYM` layout (indices): 0=rax, 1=rbx, 2=rcx, 3=rdx, 4=rsi,
// 5=rdi, 6=rbp, 7=r8, 8=r9, 9=r10, 10=r11, 11=r12, 12=r13, 13=r14, 14=r15.
// The run loop seeds index 4 (rsi) with the guest's initial ESI (the zero
// page pointer for a Linux boot) and index 0 (rax) with I/O IN results.
// ---------------------------------------------------------------------

global_asm!(
    r#"
.section .text
.macro VMX_LOAD_GPRS
    mov rax, [r11 + 0*8]
    mov rbx, [r11 + 1*8]
    mov rcx, [r11 + 2*8]
    mov rdx, [r11 + 3*8]
    mov rsi, [r11 + 4*8]
    mov rdi, [r11 + 5*8]
    mov rbp, [r11 + 6*8]
    mov r8,  [r11 + 7*8]
    mov r9,  [r11 + 8*8]
    mov r10, [r11 + 9*8]
    mov r12, [r11 + 11*8]
    mov r13, [r11 + 12*8]
    mov r14, [r11 + 13*8]
    mov r15, [r11 + 14*8]
    mov r11, [r11 + 10*8]
.endm

.global vmx_do_launch
vmx_do_launch:
    # r11 is the base for the load sequence below; save the caller's value
    # so the guest's saved r11 (array slot 10) is not clobbered by the lea.
    mov [rip + VMX_EXIT_REGS_SYM + 10*8], r11
    # HOST_RSP = the caller's stack pointer: at VM-exit the CPU restores
    # RSP from this field, and the landing's `ret` pops the return address
    # of this very `call`, landing back in the run loop. (vmwrite clobbers
    # rax, which the loads below overwrite anyway.)
    mov rax, 0x6C14
    vmwrite rax, rsp
    lea r11, [rip + VMX_EXIT_REGS_SYM]
    VMX_LOAD_GPRS
    vmlaunch
    # only reached if vmlaunch failed synchronously (bad VMCS/controls,
    # not a real VM-exit) -- CF/ZF already reflect why; caller reads
    # VM_INSTRUCTION_ERROR via vmread(0x4400).
    mov rax, 1
    ret

.global vmx_do_resume
vmx_do_resume:
    mov [rip + VMX_EXIT_REGS_SYM + 10*8], r11
    mov rax, 0x6C14
    vmwrite rax, rsp
    lea r11, [rip + VMX_EXIT_REGS_SYM]
    VMX_LOAD_GPRS
    vmresume
    mov rax, 1
    ret

.global vmx_exit_landing
vmx_exit_landing:
    # Reached via hardware VM-exit (HOST_RIP), not a call/ret. RAX..R15
    # (all except RSP, which the CPU just reloaded from HOST_RSP) still
    # hold the guest's values at the moment of exit -- save them first,
    # before touching anything that would clobber them. Every store is
    # RIP-relative so no register is consumed as a base pointer and the
    # guest's full GPR set (including r11) survives untouched.
    mov [rip + VMX_EXIT_REGS_SYM + 0*8],  rax
    mov [rip + VMX_EXIT_REGS_SYM + 1*8],  rbx
    mov [rip + VMX_EXIT_REGS_SYM + 2*8],  rcx
    mov [rip + VMX_EXIT_REGS_SYM + 3*8],  rdx
    mov [rip + VMX_EXIT_REGS_SYM + 4*8],  rsi
    mov [rip + VMX_EXIT_REGS_SYM + 5*8],  rdi
    mov [rip + VMX_EXIT_REGS_SYM + 6*8],  rbp
    mov [rip + VMX_EXIT_REGS_SYM + 7*8],  r8
    mov [rip + VMX_EXIT_REGS_SYM + 8*8],  r9
    mov [rip + VMX_EXIT_REGS_SYM + 9*8],  r10
    mov [rip + VMX_EXIT_REGS_SYM + 10*8], r11
    mov [rip + VMX_EXIT_REGS_SYM + 11*8], r12
    mov [rip + VMX_EXIT_REGS_SYM + 12*8], r13
    mov [rip + VMX_EXIT_REGS_SYM + 13*8], r14
    mov [rip + VMX_EXIT_REGS_SYM + 14*8], r15
    # Handled exit: return to the caller of vmx_do_launch/vmx_do_resume
    # (RSP was restored from HOST_RSP = that call's entry RSP, so [rsp] is
    # its return address). rax = 0 marks the handled-exit path.
    mov rax, 0
    ret
"#
);

extern "C" {
    fn vmx_do_launch() -> u64;
    fn vmx_do_resume() -> u64;
    fn vmx_exit_landing();
}

/// Human-readable tag for the VM-exit reason codes the run loop handles
/// (SDM Table 29-1). Pure, so it is contract-testable without a VMX CPU.
fn exit_reason_tag(reason: u16) -> &'static str {
    match reason {
        exit_reason::EXTERNAL_INTERRUPT => "external interrupt",
        10 => "CPUID — guest code executed for real",
        exit_reason::HLT => "HLT",
        exit_reason::CR_ACCESS => "control-register access",
        exit_reason::IO_INSTRUCTION => "I/O instruction",
        exit_reason::INVALID_GUEST_STATE => "VM-entry failure due to invalid guest state",
        exit_reason::MSR_LOADING => "VM-entry failure due to MSR loading",
        exit_reason::EPT_VIOLATION => "EPT violation",
        exit_reason::EPT_MISCONFIGURATION => "EPT misconfiguration",
        0 => "exception or NMI",
        _ => "other",
    }
}

// ---------------------------------------------------------------------
// Phase U-6 run-loop demo (feature-gated): the resumable VM under EPT.
// ---------------------------------------------------------------------

/// The demo guest, assembled by hand for gpa 0x100000 in 32-bit protected
/// mode under EPT + unrestricted guest. Prints "A" and a newline through
/// the emulated 16550 (port 0x3F8, `out dx, al` = 0xEE), then halts; the
/// `jmp $-10` would restart the loop after resume, but the demo's exit
/// budget stops it first. Layout:
///   B0 41        mov al, 0x41          ; 'A'
///   BA F8 03     mov dx, 0x3F8         ; 16550 THR
///   EE           out dx, al            ; -> I/O VM-exit, emulated UART
///   B0 0A        mov al, 0x0A          ; newline
///   EE           out dx, al            ; -> I/O VM-exit
///   F4           hlt                   ; -> HLT VM-exit (activity HLT)
///   EB F6        jmp -10               ; loop (not reached within budget)
pub const RUN_LOOP_GUEST: [u8; 14] = [
    0xB0, 0x41, 0xBA, 0xF8, 0x03, 0xEE, 0xB0, 0x0A, 0xEE, 0xF4, 0xEB, 0xF6, 0x90, 0x90,
];

/// RAM-backed `BlockStore` for the demo's `Vm` (the real machine store is
/// the NVMe-backed object store; a demo guest has no disk and the trait
/// boundary needs *some* store object).
#[cfg(feature = "vmx-demo")]
struct RamDiskStore {
    data: [u8; 512],
}

#[cfg(feature = "vmx-demo")]
impl BlockStore for RamDiskStore {
    fn capacity_sectors(&self) -> u64 {
        (self.data.len() / 512) as u64
    }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> bool {
        let start = (lba as usize).saturating_mul(512);
        if start + out.len() > self.data.len() {
            return false;
        }
        out.copy_from_slice(&self.data[start..start + out.len()]);
        true
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> bool {
        let start = (lba as usize).saturating_mul(512);
        if start + data.len() > self.data.len() {
            return false;
        }
        self.data[start..start + data.len()].copy_from_slice(data);
        true
    }
}

/// The Phase U-6 end-to-end demo: a resumable 32-bit guest under EPT that
/// talks to the emulated 16550 and halts, with every exit handled by the
/// run loop. Prints each byte the guest writes to COM1 (drained from the
/// emulated UART's tx fifo) and counts the VM-exits, then returns `Ok` —
/// proof-of-concept for the machinery a real Linux guest image will use.
/// The exit budget (9 = 3 iterations of 2 I/O exits + 1 HLT exit) keeps
/// the demo bounded on real silicon too.
///
/// # Safety
/// Requires VMX root operation and the same preconditions as
/// `vmx_run_guest`; run only on a VT-x-capable CPU (guard with
/// `vmx_supported()`), once per boot.
#[cfg(feature = "vmx-demo")]
pub unsafe fn run_loop_demo() -> Result<(), &'static str> {
    const MAX_EXITS: u64 = 9;
    // Guest memory layout (matches the standard guest constants in vm.rs):
    // GDT at 0x2000 (with the TSS page at 0x2100 inside the same frame),
    // code at 0x100000. The grant must cover 0x2000..=0x101000.
    const GDT_GPA: u64 = 0x2000;
    const TSS_GPA: u64 = 0x2100;
    const CODE_GPA: u64 = 0x100000;

    enable_vmx_operation()?;

    let vmxon_region = alloc_vmx_region()?;
    if !vmxon(vmxon_region) {
        return Err("VMXON failed — check IA32_FEATURE_CONTROL and CR0/CR4 fixed-bit MSRs");
    }
    crate::sprintln!("Aegis: [vmx] VMXON ok, region at {:#x}", vmxon_region);

    let vmcs_region = alloc_vmx_region()?;
    if !vmclear(vmcs_region) {
        return Err("VMCLEAR failed on fresh VMCS region");
    }
    if !vmptrld(vmcs_region) {
        return Err("VMPTRLD failed — VMCS not made current");
    }
    crate::sprintln!("Aegis: [vmx] VMCS active at {:#x}", vmcs_region);

    // Guest pages: one for GDT+TSS (0x2000 frame), one for code (0x100000).
    let gdt_tss_phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for guest GDT/TSS page")?;
    let code_phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for guest code page")?;

    let mut store = RamDiskStore { data: [0; 512] };
    let devices = crate::vdev::DeviceSet::new(&mut store, 0);
    let grant = crate::ept::MemGrant::new(0, (CODE_GPA >> 12) + 1);
    let mut vm = Vm::new(0, grant, devices, 0, 100);

    // EPT: map the two guest pages to their host frames (the isolation
    // gate is the grant check inside `map`).
    vm.ept
        .map(
            &mut crate::ept::KernelAlloc,
            &grant,
            GDT_GPA,
            gdt_tss_phys,
            1,
            crate::ept::EPT_DEFAULT_FLAGS,
        )
        .map_err(|_| "EPT map failed for guest GDT/TSS page")?;
    vm.ept
        .map(
            &mut crate::ept::KernelAlloc,
            &grant,
            CODE_GPA,
            code_phys,
            1,
            crate::ept::EPT_DEFAULT_FLAGS,
        )
        .map_err(|_| "EPT map failed for guest code page")?;

    // Fill guest memory through the EPT: setup GDT (+ zeroed TSS page) and
    // the demo code blob.
    {
        let mut mem = crate::vm::EptMem::new(&mut vm.ept);
        crate::vm::GuestBoot::write_setup_gdt(&mut mem, GDT_GPA, TSS_GPA)
            .map_err(|_| "guest GDT write failed")?;
        mem.write(TSS_GPA, &[0u8; 4096])
            .then_some(())
            .ok_or("guest TSS page write failed")?;
        mem.write(CODE_GPA, &RUN_LOOP_GUEST)
            .then_some(())
            .ok_or("guest code write failed")?;
    }

    // Boot state mirroring GuestBoot::boot_state() at our hand-picked
    // addresses: flat 32-bit segments, GDT/TSS in the low page, stack at
    // the standard guest stack top.
    let boot = BootState {
        eip: CODE_GPA,
        esi: 0,
        rsp: 0x9F000,
        cs: 0x08,
        ds: 0x10,
        es: 0x10,
        fs: 0x10,
        gs: 0x10,
        ss: 0x10,
        gdt_base: GDT_GPA,
        gdt_limit: 31,
        tr: 0x18,
        tss_base: TSS_GPA,
        tss_limit: 0x67,
        cr0: 0x31,   // PE | ET | NE
        cr4: 0x2000, // VMXE mirror
        rflags: 0x2,
    };

    setup_host_state()?;
    crate::sprintln!("Aegis: [vmx] run-loop demo: guest prints via emulated 16550, then halts");

    let mut exits = 0u64;
    let mut ept_handler = |vm: &mut Vm<'_, RamDiskStore>, v: crate::ept::EptViolation| {
        crate::sprintln!(
            "Aegis: [vmx] EPT violation {:#x} (isolation enforced — refused)",
            v.guest_phys
        );
        let _ = vm;
        Ok::<bool, &'static str>(false)
    };
    let mut exit_hook = |vm: &mut Vm<'_, RamDiskStore>| {
        while let Some(b) = vm.devices.uart.take_tx() {
            crate::sprintln!("Aegis: [vmx] guest serial out: {:?}", b as char);
        }
        exits += 1;
        Ok::<bool, &'static str>(exits < MAX_EXITS)
    };

    let result = vmx_run_guest(&boot, &mut vm, MAX_EXITS, &mut ept_handler, &mut exit_hook);
    match result {
        Ok(()) => {
            crate::sprintln!(
                "Aegis: [vmx] run-loop demo: {} VM-exits handled, all emulated (budget hit)",
                exits
            );
            Ok(())
        }
        Err(e) => {
            crate::sprintln!(
                "Aegis: [vmx] run-loop demo stopped: {} (after {} VM-exits)",
                e,
                exits
            );
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------
// VMCS state setup
// ---------------------------------------------------------------------

unsafe fn setup_host_state() -> Result<(), &'static str> {
    let (cs, ss, tr): (u16, u16, u16);
    asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
    asm!("str {0:x}", out(reg) tr, options(nomem, nostack, preserves_flags));

    let gdtr_base: u64;
    {
        let mut gdtr: [u16; 5] = [0; 5]; // 2-byte limit + 8-byte base (padded)
        asm!("sgdt [{0}]", in(reg) gdtr.as_mut_ptr(), options(nostack));
        gdtr_base = (gdtr[1] as u64)
            | ((gdtr[2] as u64) << 16)
            | ((gdtr[3] as u64) << 32)
            | ((gdtr[4] as u64) << 48);
    }

    vmwrite(field::HOST_CS_SELECTOR, (cs & 0xFFF8) as u64);
    vmwrite(field::HOST_SS_SELECTOR, (ss & 0xFFF8) as u64);
    vmwrite(field::HOST_TR_SELECTOR, (tr & 0xFFF8) as u64);
    vmwrite(field::HOST_CR0, read_cr0());
    vmwrite(field::HOST_CR3, read_cr3());
    vmwrite(field::HOST_CR4, read_cr4());
    vmwrite(field::HOST_GDTR_BASE, gdtr_base);
    // IDTR base — reuse the kernel's live IDT (already installed by
    // cpu::init_idt before this would ever run); read it the same way.
    let mut idtr: [u16; 5] = [0; 5];
    asm!("sidt [{0}]", in(reg) idtr.as_mut_ptr(), options(nostack));
    let idtr_base = (idtr[1] as u64)
        | ((idtr[2] as u64) << 16)
        | ((idtr[3] as u64) << 32)
        | ((idtr[4] as u64) << 48);
    vmwrite(field::HOST_IDTR_BASE, idtr_base);

    // HOST_RSP is intentionally NOT written here: the entry trampolines
    // write it from the caller's stack on every vmlaunch/vmresume, so a
    // VM-exit always returns to the run loop's own frame.
    vmwrite(
        field::HOST_RIP,
        vmx_exit_landing as *const () as usize as u64,
    );
    Ok(())
}

unsafe fn setup_guest_state(guest_code_phys: u64) -> Result<(), &'static str> {
    // Real-address-mode guest: CR0.PE=0, CR0.PG=0. ET (bit4) and NE (bit5)
    // set as the conventional minimal-reserved-safe value used across the
    // tutorial lineage — cross-check against IA32_VMX_CR0_FIXED0/1 MSRs if
    // entry fails on real hardware with a CR0-related error.
    vmwrite(field::GUEST_CR0, 0x30);
    vmwrite(field::GUEST_CR3, 0);
    vmwrite(field::GUEST_CR4, 0x2000); // VMXE mirrored per SDM requirement for guest CR4 under VMX
    vmwrite(field::CR0_GUEST_HOST_MASK, 0);
    vmwrite(field::CR4_GUEST_HOST_MASK, 0);

    // CS: selector*16 == base, matching real hardware real-mode semantics.
    let sel = real_mode_selector(guest_code_phys);
    vmwrite(field::GUEST_CS_SELECTOR, sel as u64);
    vmwrite(field::GUEST_CS_BASE, guest_code_phys);
    vmwrite(field::GUEST_CS_LIMIT, 0xFFFF);
    vmwrite(field::GUEST_CS_AR_BYTES, ar::CODE as u64);

    // SS/DS/ES/FS/GS: base 0, limit 0xFFFF, data AR — unused by the 5-byte
    // guest payload but must be present and "valid" for VM-entry checks.
    for (sel_f, base_f, limit_f, ar_f) in [
        (
            field::GUEST_DS_SELECTOR,
            field::GUEST_DS_BASE,
            field::GUEST_DS_LIMIT,
            field::GUEST_DS_AR_BYTES,
        ),
        (
            field::GUEST_ES_SELECTOR,
            field::GUEST_ES_BASE,
            field::GUEST_ES_LIMIT,
            field::GUEST_ES_AR_BYTES,
        ),
        (
            field::GUEST_SS_SELECTOR,
            field::GUEST_SS_BASE,
            field::GUEST_SS_LIMIT,
            field::GUEST_SS_AR_BYTES,
        ),
        (
            field::GUEST_FS_SELECTOR,
            field::GUEST_FS_BASE,
            field::GUEST_FS_LIMIT,
            field::GUEST_FS_AR_BYTES,
        ),
        (
            field::GUEST_GS_SELECTOR,
            field::GUEST_GS_BASE,
            field::GUEST_GS_LIMIT,
            field::GUEST_GS_AR_BYTES,
        ),
    ] {
        vmwrite(sel_f, 0);
        vmwrite(base_f, 0);
        vmwrite(limit_f, 0xFFFF);
        vmwrite(ar_f, ar::DATA as u64);
    }

    vmwrite(field::GUEST_LDTR_SELECTOR, 0);
    vmwrite(field::GUEST_LDTR_BASE, 0);
    vmwrite(field::GUEST_LDTR_LIMIT, 0xFFFF);
    vmwrite(field::GUEST_LDTR_AR_BYTES, ar::LDTR_UNUSABLE as u64);

    vmwrite(field::GUEST_TR_SELECTOR, 0);
    vmwrite(field::GUEST_TR_BASE, 0);
    vmwrite(field::GUEST_TR_LIMIT, 0xFFFF);
    vmwrite(field::GUEST_TR_AR_BYTES, ar::TR_BUSY_32 as u64);

    vmwrite(field::GUEST_GDTR_BASE, 0);
    vmwrite(field::GUEST_GDTR_LIMIT, 0xFFFF);
    vmwrite(field::GUEST_IDTR_BASE, 0);
    vmwrite(field::GUEST_IDTR_LIMIT, 0xFFFF);

    vmwrite(field::GUEST_DR7, 0x400);
    vmwrite(field::GUEST_RSP, 0);
    vmwrite(field::GUEST_RIP, 0); // offset 0 within the CS segment we just set
    vmwrite(field::GUEST_RFLAGS, 0x2); // reserved bit 1 must be set, rest clear

    vmwrite(field::GUEST_INTERRUPTIBILITY_INFO, 0);
    vmwrite(field::GUEST_ACTIVITY_STATE, 0); // active
    vmwrite(field::VMCS_LINK_POINTER, 0xFFFF_FFFF_FFFF_FFFF); // "not used"

    Ok(())
}

/// Load the VMCS guest-state fields from a `BootState` — the
/// protected-mode handoff a real Linux image needs (`GuestBoot::boot_state`
/// produces one; the run-loop demo builds its own). CS is `boot.cs` with a
/// flat 4 GiB limit and the G=1/D=1 present code AR byte 0xC09B; the data
/// segments are flat with 0xC093; TR points at the guest TSS (busy 32-bit,
/// 0x8B); GDTR at the guest's setup GDT. The AR bytes exactly match the
/// descriptors `GuestBoot::write_setup_gdt` installs, so the CPU's
/// VM-entry checks (SDM §26.3.1) and the guest's own segment state agree.
/// CR0/CR4 come from the boot state (guest-host masks are 0: nothing is
/// intercepted at the CR level), CR3 is 0 (EPT owns translation).
unsafe fn setup_guest_state_from_boot(boot: &BootState) -> Result<(), &'static str> {
    vmwrite(field::GUEST_CR0, boot.cr0);
    vmwrite(field::GUEST_CR3, 0);
    vmwrite(field::GUEST_CR4, boot.cr4);
    vmwrite(field::CR0_GUEST_HOST_MASK, 0);
    vmwrite(field::CR4_GUEST_HOST_MASK, 0);

    vmwrite(field::GUEST_CS_SELECTOR, boot.cs as u64);
    vmwrite(field::GUEST_CS_BASE, 0);
    vmwrite(field::GUEST_CS_LIMIT, 0xFFFFF);
    vmwrite(field::GUEST_CS_AR_BYTES, 0xC09B);

    // Flat 32-bit data segments for DS/ES/FS/GS/SS (unused by the demo
    // guest, mandatory valid for VM-entry checks — and the flat GDT layout
    // the Linux boot protocol sets up).
    for (sel, sel_f, base_f, limit_f, ar_f) in [
        (
            boot.ds,
            field::GUEST_DS_SELECTOR,
            field::GUEST_DS_BASE,
            field::GUEST_DS_LIMIT,
            field::GUEST_DS_AR_BYTES,
        ),
        (
            boot.es,
            field::GUEST_ES_SELECTOR,
            field::GUEST_ES_BASE,
            field::GUEST_ES_LIMIT,
            field::GUEST_ES_AR_BYTES,
        ),
        (
            boot.fs,
            field::GUEST_FS_SELECTOR,
            field::GUEST_FS_BASE,
            field::GUEST_FS_LIMIT,
            field::GUEST_FS_AR_BYTES,
        ),
        (
            boot.gs,
            field::GUEST_GS_SELECTOR,
            field::GUEST_GS_BASE,
            field::GUEST_GS_LIMIT,
            field::GUEST_GS_AR_BYTES,
        ),
        (
            boot.ss,
            field::GUEST_SS_SELECTOR,
            field::GUEST_SS_BASE,
            field::GUEST_SS_LIMIT,
            field::GUEST_SS_AR_BYTES,
        ),
    ] {
        vmwrite(sel_f, sel as u64);
        vmwrite(base_f, 0);
        vmwrite(limit_f, 0xFFFFF);
        vmwrite(ar_f, 0xC093);
    }

    vmwrite(field::GUEST_LDTR_SELECTOR, 0);
    vmwrite(field::GUEST_LDTR_BASE, 0);
    vmwrite(field::GUEST_LDTR_LIMIT, 0xFFFF);
    vmwrite(field::GUEST_LDTR_AR_BYTES, ar::LDTR_UNUSABLE as u64);

    vmwrite(field::GUEST_TR_SELECTOR, boot.tr as u64);
    vmwrite(field::GUEST_TR_BASE, boot.tss_base);
    vmwrite(field::GUEST_TR_LIMIT, boot.tss_limit as u64);
    vmwrite(field::GUEST_TR_AR_BYTES, ar::TR_BUSY_32 as u64);

    vmwrite(field::GUEST_GDTR_BASE, boot.gdt_base);
    vmwrite(field::GUEST_GDTR_LIMIT, boot.gdt_limit as u64);
    vmwrite(field::GUEST_IDTR_BASE, 0);
    vmwrite(field::GUEST_IDTR_LIMIT, 0xFFFF);

    vmwrite(field::GUEST_DR7, 0x400);
    vmwrite(field::GUEST_RSP, boot.rsp);
    vmwrite(field::GUEST_RIP, boot.eip);
    vmwrite(field::GUEST_RFLAGS, boot.rflags);

    vmwrite(field::GUEST_INTERRUPTIBILITY_INFO, 0);
    vmwrite(field::GUEST_ACTIVITY_STATE, 0);
    vmwrite(field::VMCS_LINK_POINTER, 0xFFFF_FFFF_FFFF_FFFF);

    Ok(())
}

/// Program the VM-execution controls. The primary controls always request
/// external-interrupt exiting (bit 0), I/O exiting (bit 3) and HLT exiting
/// (bit 7) plus the secondary-controls switch (bit 31); if the CPU's
/// capability MSRs cannot grant bit 31, there is no EPT and no
/// unrestricted-guest — refuse rather than degrade. With `use_ept` the
/// secondary controls additionally enable nested paging (EPT), unrestricted
/// guest and TSC offsetting, and the EPTP field is programmed from the
/// EPT root (its address encoding via `eptp`). The real-mode bring-up demo
/// passes `false` and runs without EPT (direct guest-physical access).
unsafe fn setup_controls(use_ept: bool, ept_root: u64) -> Result<(), &'static str> {
    let pin = adjust_controls(IA32_VMX_TRUE_PINBASED_CTLS, IA32_VMX_PINBASED_CTLS, 0);
    vmwrite(field::PIN_BASED_VM_EXEC_CONTROL, pin as u64);

    let primary_desired =
        proc_primary::EXT_INT_EXITING | proc_primary::IO_EXITING | proc_primary::HLT_EXITING;
    // The run loop is EPT-first: secondary controls must survive
    // adjustment or the whole approach fails honestly, not silently.
    let primary = adjust_controls(
        IA32_VMX_TRUE_PROCBASED_CTLS,
        IA32_VMX_PROCBASED_CTLS,
        primary_desired | proc_primary::SECONDARY_CONTROLS,
    );
    if primary & proc_primary::SECONDARY_CONTROLS == 0 {
        return Err("CPU lacks secondary proc-based controls (no EPT / unrestricted guest)");
    }
    vmwrite(field::CPU_BASED_VM_EXEC_CONTROL, primary as u64);

    if use_ept {
        let secondary_desired = proc_secondary::EPT_ENABLE
            | proc_secondary::UNRESTRICTED_GUEST
            | proc_secondary::TSC_OFFSETTING;
        let secondary = adjust_controls(
            IA32_VMX_TRUE_PROCBASED2_CTLS,
            IA32_VMX_PROCBASED2_CTLS,
            secondary_desired,
        );
        if secondary & proc_secondary::EPT_ENABLE == 0 {
            return Err("CPU lacks EPT (nested paging) — required for the run-loop demo");
        }
        vmwrite(field::SECONDARY_VM_EXEC_CONTROL, secondary as u64);
        vmwrite(field::EPTP, eptp(ept_root));
        vmwrite(field::TSC_OFFSET, 0);
    }

    // VM-exit controls: bit 9 (0x200) = host address-space size (64-bit
    // host) — required since this kernel runs in long mode.
    let exit_ctrls = adjust_controls(IA32_VMX_TRUE_EXIT_CTLS, IA32_VMX_EXIT_CTLS, 0x200);
    vmwrite(field::VM_EXIT_CONTROLS, exit_ctrls as u64);

    // VM-entry controls: 0 desired bits — IA-32e-mode-guest stays off
    // (this run loop's guests are 32-bit protected mode under EPT).
    let entry_ctrls = adjust_controls(IA32_VMX_TRUE_ENTRY_CTLS, IA32_VMX_ENTRY_CTLS, 0);
    vmwrite(field::VM_ENTRY_CONTROLS, entry_ctrls as u64);

    vmwrite(field::EXCEPTION_BITMAP, 0);
    Ok(())
}

// ---------------------------------------------------------------------
// VM-exit decode (pure — contract-tested without a VMX CPU)
// ---------------------------------------------------------------------

/// A decoded I/O VM-exit (SDM Table 27-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IoExit {
    port: u16,
    out: bool,
    size: u8,
    is_string: bool,
}

/// Decode the exit qualification of an I/O-instruction VM-exit: bits 2:0 =
/// operand size (0 = 1 byte, 1 = 2 bytes, 3 = 4 bytes), bit 3 = direction
/// (0 = OUT, 1 = IN), bit 4 = string instruction, bits 31:16 = port number.
/// Reserved size encodings (2) return `None` — refuse rather than guess.
fn decode_io_exit(qualification: u64) -> Option<IoExit> {
    let size = match qualification & 0x7 {
        0 => 1u8,
        1 => 2u8,
        3 => 4u8,
        _ => return None,
    };
    Some(IoExit {
        port: ((qualification >> 16) & 0xFFFF) as u16,
        out: (qualification >> 3) & 1 == 0,
        size,
        is_string: (qualification >> 4) & 1 == 1,
    })
}

/// Instruction length of an IN/OUT opcode, for advancing guest RIP past
/// the trapping instruction: E4/E5 (IN imm8) and E6/E7 (OUT imm8) are 2
/// bytes; EC/ED (IN DX) and EE/EF (OUT DX) are 1 byte. The run loop reads
/// the opcode at guest RIP (via the EPT) to pick the length; anything else
/// is refused.
fn io_instruction_len(opcode: u8) -> Option<u8> {
    match opcode {
        0xE4..=0xE7 => Some(2),
        0xEC..=0xEF => Some(1),
        _ => None,
    }
}

/// The EPT-violation exit qualification, decoded (SDM §28.2.3.2 / the
/// same layout `decode_ept_violation` in ept.rs consumes). The run loop
/// reuses `EptViolation` from the EPT module for both.
fn decode_ept_violation_qualification(qualification: u64) -> crate::ept::EptViolation {
    crate::ept::decode_ept_violation(qualification)
}

// ---------------------------------------------------------------------
// The run loop
// ---------------------------------------------------------------------

/// EPT-violation policy hook: `Ok(true)` maps the page and the run
/// continues, `Ok(false)` stops the run, `Err` fails it. The run loop
/// itself never maps — isolation policy lives in the caller.
type EptViolationHook<'a, S> =
    dyn for<'x> FnMut(&mut Vm<'x, S>, crate::ept::EptViolation) -> Result<bool, &'static str> + 'a;

/// Per-exit hook: runs after every handled VM-exit (device emulation side
/// effects, PIC updates, guest output draining). `Ok(false)` stops the run.
type ExitHook<'a, S> = dyn for<'x> FnMut(&mut Vm<'x, S>) -> Result<bool, &'static str> + 'a;

/// Run one VM through its full entry/exit cycle until the exit hook says stop,
/// an EPT handler refuses, an exit is unhandled, or the exit budget is
/// exhausted. First entry uses `vmlaunch`; every subsequent entry uses
/// `vmresume` (the VMCS stays current and loaded the whole time).
///
/// Dispatch per handled exit reason:
/// - external interrupt (1): EOI the local APIC, then the exit hook runs
///   (it may inject a new PIC vector before the next entry);
/// - HLT (12): set guest activity state to HLT and advance guest RIP by 1
///   (HLT does not advance RIP — the activity state makes the CPU halt at
///   the next entry);
/// - I/O instruction (30): decode the qualification, fetch the opcode at
///   guest RIP through the EPT, emulate via `Vm::handle_io`, write IN
///   results into the guest's saved RAX (with the upper bits of the target
///   register preserved for 1/2-byte accesses), advance guest RIP by the
///   instruction length;
/// - EPT violation (48): count it on the VM, hand the decoded violation
///   to the handler (which decides isolation policy); `Ok(false)` stops.
///
/// `Ok(())` means the run ended by the hook's request or the exit budget;
/// `Err` means something refused (unhandled exit, string I/O, decode
/// failure, EPT-handler refusal) or a synchronous `vmlaunch`/`vmresume`
/// failure (report `VM_INSTRUCTION_ERROR`).
///
/// # Safety
/// Requires VMX root operation on this CPU, a current VMCS configured by
/// `setup_host_state` + `setup_controls` + `setup_guest_state_from_boot`,
/// and interrupts in a state this kernel is prepared for (the run loop
/// services external-interrupt exits itself).
pub unsafe fn vmx_run_guest<S: BlockStore>(
    boot: &BootState,
    vm: &mut Vm<'_, S>,
    max_exits: u64,
    ept_handler: &mut EptViolationHook<'_, S>,
    exit_hook: &mut ExitHook<'_, S>,
) -> Result<(), &'static str> {
    setup_guest_state_from_boot(boot)?;
    setup_controls(true, vm.ept.root())?;

    // Seed the guest's initial registers: the trampoline loads every GPR
    // from VMX_EXIT_REGS_SYM (all zero initially, which is the boot
    // contract for every GPR except ESI/RSP/RIP), so only ESI differs:
    // a Linux boot hands the zero page pointer in ESI, and the demo guest
    // gets the same slot seeded from its boot state.
    VMX_EXIT_REGS_SYM[4] = boot.esi;

    let mut entered = false;
    let mut exits = 0u64;
    loop {
        if exits >= max_exits {
            return Err("exit budget exhausted");
        }
        let fail = if entered {
            vmx_do_resume()
        } else {
            vmx_do_launch()
        };
        entered = true;
        if fail != 0 {
            let err = vmread(field::VM_INSTRUCTION_ERROR);
            return Err(match err {
                7 => "vmentry failed synchronously: VM_INSTRUCTION_ERROR=7 (invalid guest state — see module docs re SDM §26.3.1)",
                _ => "vmentry failed synchronously: see VM_INSTRUCTION_ERROR in the log",
            });
        }
        exits += 1;

        let reason = (vmread(field::VM_EXIT_REASON) & 0xFFFF) as u16;
        match classify_exit(reason) {
            ExitClass::ExternalInterrupt => {
                crate::cpu::lapic_eoi();
                if !exit_hook(vm)? {
                    return Ok(());
                }
            }
            ExitClass::Hlt => {
                vmwrite(field::GUEST_ACTIVITY_STATE, 1);
                let rip = vmread(field::GUEST_RIP);
                vmwrite(field::GUEST_RIP, rip + 1);
                if !exit_hook(vm)? {
                    return Ok(());
                }
            }
            ExitClass::IoInstruction => {
                let io = decode_io_exit(vmread(field::EXIT_QUALIFICATION))
                    .ok_or("I/O VM-exit: reserved size encoding")?;
                if io.is_string {
                    return Err("I/O VM-exit: string I/O (INS/OUTS) not emulated");
                }
                let rip = vmread(field::GUEST_RIP);
                let opcode = vm
                    .read_guest_byte(rip)
                    .ok_or("I/O VM-exit: guest RIP unmapped in EPT")?;
                let len =
                    io_instruction_len(opcode).ok_or("I/O VM-exit: unknown opcode at guest RIP")?;
                let mut val: u64 = if io.out { VMX_EXIT_REGS_SYM[0] } else { 0 };
                let read = vm.handle_io(io.port, io.size, io.out, val as u32);
                if !io.out {
                    val = read as u64;
                    // Preserve the upper bits of the target register for
                    // 1/2-byte accesses (e.g. `in al, dx` writes AL only).
                    let mask = match io.size {
                        1 => 0xFF,
                        2 => 0xFFFF,
                        _ => u64::MAX,
                    };
                    let keep = VMX_EXIT_REGS_SYM[0] & !mask;
                    VMX_EXIT_REGS_SYM[0] = keep | (val & mask);
                }
                vmwrite(field::GUEST_RIP, rip + len as u64);
                if !exit_hook(vm)? {
                    return Ok(());
                }
            }
            ExitClass::EptViolation => {
                let qual = vmread(field::EXIT_QUALIFICATION);
                vm.ept_violations += 1;
                if !ept_handler(vm, decode_ept_violation_qualification(qual))? {
                    return Ok(());
                }
            }
            ExitClass::Unhandled { reason } => {
                return Err(match reason {
                    exit_reason::INVALID_GUEST_STATE => {
                        "VM-exit reason 33: VM-entry failed (invalid guest state — see module docs)"
                    }
                    exit_reason::MSR_LOADING => "VM-exit reason 34: VM-entry failed (MSR loading)",
                    _ => "unhandled VM-exit reason (not classified by the run loop)",
                });
            }
        }
    }
}

/// Full bring-up: enable VMX, VMXON, allocate + activate a VMCS, set up a
/// minimal real-mode guest running `cpuid; hlt; jmp $-2`, and launch it.
/// The first VM-exit lands in `vmx_exit_landing` — which now returns to
/// this function's caller (HOST_RSP is the caller's stack), so `Ok(())`
/// is reached with the guest's GPRs captured in `VMX_EXIT_REGS_SYM` and
/// the single round trip complete. On a *pre-entry* failure (feature
/// check, allocation, or `vmlaunch` itself failing synchronously) it
/// returns `Err` with what failed. This is the Phase K probe; the Phase
/// U-6 resumable loop is `vmx_run_guest` (and `run_loop_demo` wraps it).
///
/// # Safety
/// Must be called with interrupts in a state this kernel is prepared for
/// re-entering after VMX root operation is established, and only once per
/// CPU (this is a single-VMCS, single-attempt bring-up, not a scheduler).
pub unsafe fn bringup_demo() -> Result<(), &'static str> {
    enable_vmx_operation()?;

    let vmxon_region = alloc_vmx_region()?;
    if !vmxon(vmxon_region) {
        return Err("VMXON failed — check IA32_FEATURE_CONTROL and CR0/CR4 fixed-bit MSRs");
    }
    crate::sprintln!("Aegis: [vmx] VMXON ok, region at {:#x}", vmxon_region);

    let vmcs_region = alloc_vmx_region()?;
    if !vmclear(vmcs_region) {
        return Err("VMCLEAR failed on fresh VMCS region");
    }
    if !vmptrld(vmcs_region) {
        return Err("VMPTRLD failed — VMCS not made current");
    }
    crate::sprintln!("Aegis: [vmx] VMCS active at {:#x}", vmcs_region);

    let guest_code = alloc_guest_code()?;
    crate::sprintln!(
        "Aegis: [vmx] guest code page at {:#x} (cpuid; hlt; jmp $-2)",
        guest_code
    );

    setup_host_state()?;
    setup_guest_state(guest_code)?;
    setup_controls(false, 0)?;

    crate::sprintln!("Aegis: [vmx] VMCS configured, launching guest...");
    let fail = vmx_do_launch();
    if fail != 0 {
        let err = vmread(field::VM_INSTRUCTION_ERROR);
        crate::sprintln!(
            "Aegis: [vmx] VMLAUNCH failed synchronously, VM_INSTRUCTION_ERROR={}",
            err
        );
        return Err("vmlaunch failed synchronously — see VM_INSTRUCTION_ERROR in the log");
    }

    // A real VM-exit has now happened and been handled: the landing saved
    // the guest GPRs, returned via HOST_RSP, and this function resumed
    // with rax = 0. Report the round trip.
    let reason = (vmread(field::VM_EXIT_REASON) & 0xFFFF) as u16;
    crate::sprintln!(
        "Aegis: [vmx] VM-EXIT reason={} ({}) — full round trip, guest GPRs captured",
        reason,
        exit_reason_tag(reason)
    );
    crate::sprintln!(
        "Aegis: [vmx] guest RAX at exit = {:#x} (CPUID.EAX from real silicon)",
        VMX_EXIT_REGS_SYM[0]
    );
    Ok(())
}

// ---- Tests (pure protocol/encoding logic — no VMX CPU required) -----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_code_is_cpuid_hlt_self_loop() {
        // 0F A2 = CPUID; F4 = HLT; EB FE = JMP $-2 (self-loop).
        assert_eq!(GUEST_CODE, [0x0F, 0xA2, 0xF4, 0xEB, 0xFE]);
        // Decode by hand: cpuid sets EAX/EBX/ECX/EDX, so the first instruction
        // produces real CPUID output — that is the "guest executed for real"
        // proof the exit-reason 10 path relies on.
        assert_eq!(GUEST_CODE[0], 0x0F);
        assert_eq!(GUEST_CODE[1], 0xA2);
    }

    #[test]
    fn real_mode_selector_scales_base_by_16() {
        // selector*16 == base for page-aligned code bases.
        let base = 0x10000u64; // page-aligned
        assert_eq!(real_mode_selector(base) as u64, base >> 4);
        let base = 0x7C00u64;
        assert_eq!(real_mode_selector(base) as u64, base >> 4);
    }

    #[test]
    fn real_mode_selector_fits_16_bits() {
        // A base beyond 16:16 addressable range truncates (matches the VMCS
        // selector width) — the guest base itself is written independently,
        // so the selector only needs selector*16==base for the check.
        let base = 0x1_0000_0000u64;
        let sel = real_mode_selector(base);
        assert_eq!(sel as u64, (base >> 4) & 0xFFFF);
    }

    #[test]
    fn adjust_cap_bits_forces_mandatory_and_respects_reserved() {
        // cap layout: low 32 = bits that must be 1 (allowed-0), high 32 =
        // bits that may be 1 (allowed-1). On real silicon allowed0 bits are
        // always a subset of allowed1; keep them consistent here too.
        // allowed0 = bit 0 must be set; allowed1 = bits 0..1 may be set.
        let cap = (0x3u64 << 32) | 0x1u64;
        // A desired 0 still yields the mandatory bit 0.
        assert_eq!(adjust_cap_bits(cap, 0x0), 0x1);
        // A desired allowed bit (1) survives alongside the mandatory one.
        assert_eq!(adjust_cap_bits(cap, 0x2), 0x3);
        // A desired bit that is NOT allowed-1 (2) is cleared.
        assert_eq!(adjust_cap_bits(cap, 0x4), 0x1);
    }

    #[test]
    fn exit_reason_tags_expected_codes() {
        assert_eq!(exit_reason_tag(1), "external interrupt");
        assert_eq!(exit_reason_tag(10), "CPUID — guest code executed for real");
        assert_eq!(exit_reason_tag(12), "HLT");
        assert_eq!(exit_reason_tag(28), "control-register access");
        assert_eq!(exit_reason_tag(30), "I/O instruction");
        assert_eq!(
            exit_reason_tag(33),
            "VM-entry failure due to invalid guest state"
        );
        assert_eq!(exit_reason_tag(34), "VM-entry failure due to MSR loading");
        assert_eq!(exit_reason_tag(48), "EPT violation");
        assert_eq!(exit_reason_tag(49), "EPT misconfiguration");
        // Unknown codes are never panicked on.
        let _ = exit_reason_tag(99);
    }

    #[test]
    fn classify_exit_maps_the_handled_set() {
        assert_eq!(classify_exit(1), ExitClass::ExternalInterrupt);
        assert_eq!(classify_exit(12), ExitClass::Hlt);
        assert_eq!(classify_exit(30), ExitClass::IoInstruction);
        assert_eq!(classify_exit(48), ExitClass::EptViolation);
        // Everything outside the handled set is refused loudly, with the
        // real reason preserved for the error message.
        assert_eq!(classify_exit(28), ExitClass::Unhandled { reason: 28 });
        assert_eq!(classify_exit(0), ExitClass::Unhandled { reason: 0 });
        assert_eq!(classify_exit(99), ExitClass::Unhandled { reason: 99 });
    }

    #[test]
    fn decode_io_exit_byte_out_immediate_port() {
        // SDM Table 27-5: out dx, al -> size 0 (1 byte), direction 0 (OUT),
        // port 0x3F8 in bits 31:16.
        let qual = 0x3F8u64 << 16;
        assert_eq!(
            decode_io_exit(qual),
            Some(IoExit {
                port: 0x3F8,
                out: true,
                size: 1,
                is_string: false,
            })
        );
    }

    #[test]
    fn decode_io_exit_word_in_and_dword_out() {
        // 2-byte IN (direction bit 3 set) at port 0x60.
        let qual = (0x60u64 << 16) | (1 << 3) | 1;
        assert_eq!(
            decode_io_exit(qual),
            Some(IoExit {
                port: 0x60,
                out: false,
                size: 2,
                is_string: false,
            })
        );
        // 4-byte OUT at port 0xCF8.
        let qual = (0xCF8u64 << 16) | 3;
        assert_eq!(
            decode_io_exit(qual),
            Some(IoExit {
                port: 0xCF8,
                out: true,
                size: 4,
                is_string: false,
            })
        );
    }

    #[test]
    fn decode_io_exit_flags_string_and_refuses_reserved_sizes() {
        let qual = (0x3F8u64 << 16) | (1 << 4); // string bit 4
        assert!(decode_io_exit(qual).unwrap().is_string);
        // Size encoding 2 is reserved: refuse rather than guess.
        assert_eq!(decode_io_exit(2), None);
    }

    #[test]
    fn io_instruction_lengths_match_ops() {
        // E4/E5 (IN imm8), E6/E7 (OUT imm8): 2 bytes.
        for op in [0xE4u8, 0xE5, 0xE6, 0xE7] {
            assert_eq!(io_instruction_len(op), Some(2));
        }
        // EC/ED (IN DX), EE/EF (OUT DX): 1 byte.
        for op in [0xECu8, 0xED, 0xEE, 0xEF] {
            assert_eq!(io_instruction_len(op), Some(1));
        }
        // Anything else is refused (never guesses an advance).
        for op in [0x90u8, 0xF4, 0xCD, 0x00] {
            assert_eq!(io_instruction_len(op), None);
        }
    }

    #[test]
    fn run_loop_guest_decodes_as_serial_out_hlts() {
        // The demo blob: 'A' -> 0x3F8, '\n' -> 0x3F8, hlt, jmp -10.
        // Decode by hand so the blob's bytes are proven, not assumed.
        assert_eq!(RUN_LOOP_GUEST[0..2], [0xB0, 0x41]); // mov al, 0x41
        assert_eq!(RUN_LOOP_GUEST[2..5], [0xBA, 0xF8, 0x03]); // mov dx, 0x3F8
        assert_eq!(RUN_LOOP_GUEST[5], 0xEE); // out dx, al (1-byte, IO_EXITING)
        assert_eq!(RUN_LOOP_GUEST[6..8], [0xB0, 0x0A]); // mov al, 0x0A
        assert_eq!(RUN_LOOP_GUEST[8], 0xEE); // out dx, al
        assert_eq!(RUN_LOOP_GUEST[9], 0xF4); // hlt (HLT_EXITING)
        assert_eq!(RUN_LOOP_GUEST[10..12], [0xEB, 0xF6]); // jmp -10 -> offset 2
                                                          // Every I/O opcode in the blob is one the run loop advances by 1.
        assert_eq!(io_instruction_len(RUN_LOOP_GUEST[5]), Some(1));
        assert_eq!(io_instruction_len(RUN_LOOP_GUEST[8]), Some(1));
    }

    #[test]
    fn control_bits_are_the_sdm_values() {
        // Primary: external-interrupt exiting = bit 0, I/O = bit 3,
        // HLT = bit 7, secondary controls = bit 31.
        assert_eq!(proc_primary::EXT_INT_EXITING, 0x1);
        assert_eq!(proc_primary::IO_EXITING, 0x8);
        assert_eq!(proc_primary::HLT_EXITING, 0x80);
        assert_eq!(proc_primary::SECONDARY_CONTROLS, 0x8000_0000);
        // Secondary: EPT = bit 1, unrestricted guest = bit 3, TSC offset = 17.
        assert_eq!(proc_secondary::EPT_ENABLE, 0x2);
        assert_eq!(proc_secondary::UNRESTRICTED_GUEST, 0x8);
        assert_eq!(proc_secondary::TSC_OFFSETTING, 0x2_0000);
        // Exit reasons: the SDM Table 29-1 numbers, checked as a group so a
        // copy-paste mistake in any one of them fails loudly.
        assert_eq!(exit_reason::EXTERNAL_INTERRUPT, 1);
        assert_eq!(exit_reason::HLT, 12);
        assert_eq!(exit_reason::CR_ACCESS, 28);
        assert_eq!(exit_reason::IO_INSTRUCTION, 30);
        assert_eq!(exit_reason::INVALID_GUEST_STATE, 33);
        assert_eq!(exit_reason::MSR_LOADING, 34);
        assert_eq!(exit_reason::EPT_VIOLATION, 48);
        assert_eq!(exit_reason::EPT_MISCONFIGURATION, 49);
    }

    #[test]
    fn field_encodings_are_distinct_and_well_typed() {
        // Sanity: the VMCS fields we write have the expected encoding widths
        // (16-bit fields are 0x08xx, 32-bit are 0x40xx/0x48xx, natural-width
        // are 0x60xx/0x68xx/0x6Cxx). A wrong width class is a classic
        // vmwrite target that silently writes nothing on real hardware.
        assert_eq!(field::GUEST_CS_SELECTOR >> 8, 0x08);
        assert_eq!(field::GUEST_CS_LIMIT >> 8, 0x48);
        assert_eq!(field::GUEST_CS_AR_BYTES >> 8, 0x48);
        assert_eq!(field::PIN_BASED_VM_EXEC_CONTROL >> 8, 0x40);
        assert_eq!(field::SECONDARY_VM_EXEC_CONTROL >> 8, 0x40);
        assert_eq!(field::EPTP >> 8, 0x20);
        assert_eq!(field::TSC_OFFSET >> 8, 0x20);
        assert_eq!(field::GUEST_CR0 >> 8, 0x68);
        assert_eq!(field::HOST_CR0 >> 8, 0x6C);
        assert_eq!(field::GUEST_RIP >> 8, 0x68);
        assert_eq!(field::HOST_RIP >> 8, 0x6C);
        assert_eq!(field::EXIT_QUALIFICATION >> 8, 0x64);
    }
}

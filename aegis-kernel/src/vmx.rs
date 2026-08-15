//! Phase K: VT-x (VMX) bring-up — the hypervisor primitive the design doc's
//! "VM-based full-fidelity path" needs before any Windows-compatible guest
//! can be attempted (§7 Phase 9).
//!
//! Honest scope, stated up front per this repo's own Ground Rule 6: this
//! file gets a real CPU into VMX root operation, launches a minimal
//! real-mode guest (a five-byte blob: `cpuid; hlt; jmp $-2`), and proves a
//! full VM-entry -> guest-executes -> VM-exit -> host-handles round trip,
//! reporting the real exit reason and the guest's register state at the
//! moment of exit. That is the actual foundational primitive — it is NOT a
//! Windows boot, not EPT/nested-paging, not a resumable VM loop, and not a
//! multi-guest scheduler. Those are what get built ON TOP of this once this
//! primitive is confirmed working on real hardware.
//!
//! I could not compile, run, or verify any of this in the sandbox that
//! wrote it (no VMX/SVM CPU flag present, confirmed via `/proc/cpuinfo`
//! before starting — see the conversation this shipped in). VMCS field
//! encodings below are the standard Intel SDM Vol. 3C Appendix B values
//! used consistently across the reference literature (KVM's `vmcs.h`,
//! the "Hypervisor From Scratch" / "SimpleVisor" tutorial lineage); the
//! part I'm least certain of without a real CPU to test against is the
//! **guest real-mode segment state** in `setup_guest_state` — if
//! `vmlaunch` fails with VM-instruction-error 7 ("invalid guest state") or
//! `vmlaunch`'s success-but-immediate-exit reason is exit reason 33/0x21
//! (VM-entry failure due to invalid guest state), start there and check
//! against SDM §26.3.1 "Checks on Guest Segment Registers" — the
//! selector*16==base relationship for real-address-mode segments is the
//! most likely thing to need adjusting on real silicon vs. what's written
//! here.
//!
//! Everything downstream of a working `vmlaunch` (EPT, multiple vCPUs, an
//! actual NT-compatible guest image, VMEXIT handling for I/O/MSR/EPT
//! violations) is real future work this file does not attempt — this is
//! DoD option (b) made concrete: the design *and* a first real
//! implementation attempt of the ceiling primitive, not a working Windows VM.

use core::arch::{asm, global_asm};

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
    // 32-bit control
    pub const PIN_BASED_VM_EXEC_CONTROL: u64 = 0x4000;
    pub const CPU_BASED_VM_EXEC_CONTROL: u64 = 0x4002;
    pub const EXCEPTION_BITMAP: u64 = 0x4004;
    pub const VM_EXIT_CONTROLS: u64 = 0x400C;
    pub const VM_ENTRY_CONTROLS: u64 = 0x4012;
    // 32-bit read-only (VM-exit info)
    pub const VM_INSTRUCTION_ERROR: u64 = 0x4400;
    pub const VM_EXIT_REASON: u64 = 0x4402;
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
    pub const HOST_RSP: u64 = 0x6C14;
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
// to zero the guest's initial GPRs before `vmlaunch`, and capture whatever
// the CPU left in them (the guest's live values at the instant of exit)
// immediately on the other side, before any Rust code (which would
// clobber them) runs. This is the standard pattern used by every minimal
// VMX bring-up in the reference literature.
// ---------------------------------------------------------------------

global_asm!(
    r#"
.section .text
.global vmx_do_launch
vmx_do_launch:
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    xor rsi, rsi
    xor rdi, rdi
    xor rbp, rbp
    xor r8,  r8
    xor r9,  r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15
    vmlaunch
    # only reached if vmlaunch failed synchronously (bad VMCS/controls,
    # not a real VM-exit) -- CF/ZF already reflect why; caller checks
    # VM_INSTRUCTION_ERROR via vmread(0x4400).
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
    call vmx_report_exit
    ud2
"#
);

extern "C" {
    fn vmx_do_launch() -> u64;
    fn vmx_exit_landing();
}

/// Human-readable tag for the VM-exit reason codes this bring-up expects
/// (SDM §29.2.1). Pure, so it is contract-testable without a VMX CPU.
fn exit_reason_tag(reason: u16) -> &'static str {
    match reason {
        10 => "CPUID — guest code executed for real",
        12 => "HLT",
        33 => "VM-entry failure due to invalid guest state",
        28 => "EPT violation",
        0 => "exception or NMI",
        _ => "other",
    }
}

/// Called from `vmx_exit_landing` after guest GPRs are saved. Reports the
/// real VM-exit reason and returns nothing — this demo halts here rather
/// than resuming the guest; resumption (`vmresume` + advancing guest RIP
/// past the trapping instruction) is the natural next increment once a
/// single successful round trip is confirmed live.
#[no_mangle]
unsafe extern "C" fn vmx_report_exit() -> ! {
    let reason = (vmread(field::VM_EXIT_REASON) & 0xFFFF) as u16;
    let qual_err = vmread(field::VM_INSTRUCTION_ERROR);
    let guest_rax = VMX_EXIT_REGS_SYM[0];
    crate::sprintln!(
        "Aegis: [vmx] VM-EXIT reason={} (err field={})",
        reason,
        qual_err
    );
    crate::sprintln!("Aegis: [vmx] guest RAX at exit = {:#x}", guest_rax);
    crate::sprintln!(
        "Aegis: [vmx] reason {} = {}",
        reason,
        exit_reason_tag(reason)
    );
    crate::sprintln!("Aegis: [vmx] bring-up demo stops here (single round trip, no vmresume yet)");
    loop {
        asm!("hlt", options(nomem, nostack));
    }
}

// ---------------------------------------------------------------------
// VMCS state setup
// ---------------------------------------------------------------------

unsafe fn setup_host_state(host_stack_top: u64) -> Result<(), &'static str> {
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

    vmwrite(field::HOST_RSP, host_stack_top);
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

unsafe fn setup_controls() -> Result<(), &'static str> {
    let pin = adjust_controls(IA32_VMX_TRUE_PINBASED_CTLS, IA32_VMX_PINBASED_CTLS, 0);
    vmwrite(field::PIN_BASED_VM_EXEC_CONTROL, pin as u64);

    // Primary proc-based controls: request HLT-exiting (bit 7, 0x80) so we
    // get a clean, expected exit after the guest's `hlt` even if the
    // preceding `cpuid` exit isn't reached for some reason on real
    // hardware — belt and suspenders for a first bring-up.
    let proc_desired = 0x80u32;
    let proc = adjust_controls(
        IA32_VMX_TRUE_PROCBASED_CTLS,
        IA32_VMX_PROCBASED_CTLS,
        proc_desired,
    );
    vmwrite(field::CPU_BASED_VM_EXEC_CONTROL, proc as u64);

    // VM-exit controls: bit 9 (0x200) = host address-space size (64-bit
    // host) — required since this kernel runs in long mode.
    let exit_ctrls = adjust_controls(IA32_VMX_TRUE_EXIT_CTLS, IA32_VMX_EXIT_CTLS, 0x200);
    vmwrite(field::VM_EXIT_CONTROLS, exit_ctrls as u64);

    // VM-entry controls: 0 desired bits — IA-32e-mode-guest stays off,
    // this is a real-mode guest.
    let entry_ctrls = adjust_controls(IA32_VMX_TRUE_ENTRY_CTLS, IA32_VMX_ENTRY_CTLS, 0);
    vmwrite(field::VM_ENTRY_CONTROLS, entry_ctrls as u64);

    vmwrite(field::EXCEPTION_BITMAP, 0);
    Ok(())
}

/// Full bring-up: enable VMX, VMXON, allocate + activate a VMCS, set up a
/// minimal real-mode guest running `cpuid; hlt; jmp $-2`, and launch it.
/// On success this function does not return in the traditional sense —
/// `vmx_report_exit` (reached via the real VM-exit path, not a normal
/// call/return) prints the result and halts. On a *pre-entry* failure
/// (feature check, allocation, or `vmlaunch` itself failing synchronously)
/// it returns `Err` with what failed.
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

    // Host stack for the exit trampoline: 2 frames, well clear of anything
    // else in use, RSP set to the top (stacks grow down).
    let host_stack_phys = crate::frame::alloc_contiguous_global(2)
        .ok_or("frame allocator: out of memory for VMX host stack")?;
    let host_stack_top = host_stack_phys + (2 * 4096) - 16; // 16-byte aligned top

    setup_host_state(host_stack_top)?;
    setup_guest_state(guest_code)?;
    setup_controls()?;

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

    // Unreachable on success: control transferred into the guest, and any
    // subsequent VM-exit lands in vmx_exit_landing -> vmx_report_exit,
    // which loops forever. Kept only so the function's return type is
    // honest about the synchronous-failure path above.
    Err("unreachable: vmlaunch returned without a fail code and without exiting via VM-exit")
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
        assert_eq!(exit_reason_tag(10), "CPUID — guest code executed for real");
        assert_eq!(exit_reason_tag(12), "HLT");
        assert_eq!(
            exit_reason_tag(33),
            "VM-entry failure due to invalid guest state"
        );
        // Unknown codes are never panicked on.
        let _ = exit_reason_tag(99);
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
        assert_eq!(field::GUEST_CR0 >> 8, 0x68);
        assert_eq!(field::HOST_CR0 >> 8, 0x6C);
        assert_eq!(field::GUEST_RIP >> 8, 0x68);
        assert_eq!(field::HOST_RIP >> 8, 0x6C);
    }
}

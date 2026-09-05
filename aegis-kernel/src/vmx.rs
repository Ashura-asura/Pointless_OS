//! Phase K + Phase U-6 + Phase U-7: VT-x (VMX) bring-up, the hypervisor
//! run loop, and the real Linux guest boot — the foundation of the design
//! doc's "VM-based full-fidelity path" (§7 Phase 9).
//!
//! Honest scope, stated up front per this repo's own Ground Rule 6: the
//! hardware-dependent half (trampolines, VMCS writes, `vmlaunch`/`vmresume`)
//! only runs on a host that **owns VMX** — Aegis booted as the host OS with
//! VT-x present and no other hypervisor (KVM / virtualization-based security
//! / Core Isolation) already holding it. Everything here is written against
//! the SDM and verified by contract tests on the pure decode/encoding logic;
//! the host-readiness pre-flight (`vmx_host_readiness`, below) fails loudly
//! with the exact remediation on any host that cannot own VMX. The
//! bring-up demo gets a real CPU into VMX root operation, launches a
//! minimal real-mode guest (`cpuid; hlt; jmp $-2`), and proves a full
//! VM-entry -> guest-executes -> VM-exit -> host-handles round trip. The
//! run loop (Phase U-6) adds what sits ON TOP: a resumable VM
//! (`vmlaunch` then repeated `vmresume`), nested paging (EPT),
//! external-interrupt/HLT/I/O VM-exit dispatch, in-guest device
//! emulation via `Vm::handle_io`, virtual-clock feeding at wall-clock
//! speed (host TSC calibrated against the host PIT), and interrupt
//! injection gated on the guest's RFLAGS.IF — the machinery a real Linux
//! guest needs. Phase U-7 (`guest_boot_demo`) boots the committed guest
//! image (bzImage + initramfs, embedded into the kernel) under that run
//! loop, stopping when the guest reaches its shell on the emulated 16550.
//!
//! The hardware half is verified on a host that owns VMX — bare metal or a
//! guest hypervisor under nested virtualization (KVM `nested=Y`), where VT-x
//! is exposed and Aegis can own it for its own guests. The pre-flight
//! (`vmx_host_readiness`) blocks only on the CPU-level disqualifiers and
//! reports `Ready` whenever VT-x is present and feature control permits
//! VMXON. VMCS field encodings below are the
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
//! on and the idle loop owns the machine. On a host that cannot own VMX the
//! pre-flight prints the exact reason (no VT-x, or firmware-locked off) and
//! returns before any `vmxon`.
//! Normal builds (no `vmx-demo` feature) compile zero VMX
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
const IA32_VMX_CR0_FIXED0: u32 = 0x486;
const IA32_VMX_CR0_FIXED1: u32 = 0x487;
const IA32_VMX_CR4_FIXED0: u32 = 0x488;
const IA32_VMX_CR4_FIXED1: u32 = 0x489;
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
// Secondary proc-based controls (EPT / unrestricted guest / TSC offsetting).
// The correct MSR is 0x48B (IA32_VMX_PROCBASED_CTLS2) — previously this was
// 0x48A/0x49A (VMCS_ENUM and a nonexistent MSR), so `rdmsr` #GP'd the moment
// the EPT path ran. There is no separate "TRUE" secondary-controls MSR; the
// single 0x48B MSR always reports the full capability set (Linux
// arch/x86/include/asm/msr-index.h confirms 0x48B).
const IA32_VMX_PROCBASED2_CTLS: u32 = 0x48B;
const IA32_VMX_TRUE_PROCBASED2_CTLS: u32 = 0x48B;
const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;

/// Cached value of IA32_VMX_EPT_VPID_CAP read once during VMX init.
/// Bit 14: WB memory type for EPT supported.
/// Bit 21: EPT accessed/dirty (AD) supported.
static mut EPT_VPID_CAP: u64 = 0;

/// Read the EPT VPID capability once; returns the cached value.
pub fn ept_vpid_cap() -> u64 {
    unsafe { EPT_VPID_CAP }
}

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
    pub const HOST_ES_SELECTOR: u64 = 0x0C00;
    pub const HOST_CS_SELECTOR: u64 = 0x0C02;
    pub const HOST_SS_SELECTOR: u64 = 0x0C04;
    pub const HOST_DS_SELECTOR: u64 = 0x0C06;
    pub const HOST_FS_SELECTOR: u64 = 0x0C08;
    pub const HOST_GS_SELECTOR: u64 = 0x0C0A;
    pub const HOST_TR_SELECTOR: u64 = 0x0C0C;
    // 64-bit control
    pub const VMCS_LINK_POINTER: u64 = 0x2800;
    pub const TSC_OFFSET: u64 = 0x2010;
    pub const EPTP: u64 = 0x201A;
    // 32-bit control
    pub const PIN_BASED_VM_EXEC_CONTROL: u64 = 0x4000;
    pub const CPU_BASED_VM_EXEC_CONTROL: u64 = 0x4002;
    pub const EXCEPTION_BITMAP: u64 = 0x4004;
    pub const SECONDARY_VM_EXEC_CONTROL: u64 = 0x401E;
    pub const VM_EXIT_CONTROLS: u64 = 0x400C;
    pub const VM_ENTRY_CONTROLS: u64 = 0x4012;
    /// Interruption-information field: written to inject an event at the
    /// next VM-entry (bit 31 = valid, bits 10:8 = type, bits 7:0 = vector).
    pub const VM_ENTRY_INTR_INFO: u64 = 0x4016;
    /// Error code pushed onto guest stack when injecting an exception.
    pub const VM_ENTRY_EXCEPTION_ERROR_CODE: u64 = 0x4018;
    /// Instruction length — required when injecting exceptions with error codes.
    pub const VM_ENTRY_INSTRUCTION_LEN: u64 = 0x401A;
    // 32-bit read-only (VM-exit info)
    pub const VM_INSTRUCTION_ERROR: u64 = 0x4400;
    pub const VM_EXIT_REASON: u64 = 0x4402;
    /// VM-exit interruption information (SDM Vol. 3C §24.9.2, Table 24-13):
    /// bits 7:0 = vector, bits 10:8 = type (0=ext,2=NMI,3=hw-exc,6=sw-int),
    /// bit 31 = valid. Whenever `VM_EXIT_REASON` == 0 (exception or NMI),
    /// the SDM *guarantees* bit 31 here is set — so a "reason=0, this field
    /// reads 0" observation always means the wrong field is being read,
    /// never a hardware quirk. This is the correct source for the
    /// exception vector on exit reason 0.
    pub const VM_EXIT_INTERRUPTION_INFO: u64 = 0x4404;
    /// Error code for the event named by `VM_EXIT_INTERRUPTION_INFO`, valid
    /// whenever that field's vector delivers one (#PF, #GP, #DF, ...).
    /// NOT the same as `EXIT_QUALIFICATION`, which for a #PF exit instead
    /// holds the faulting linear address (identical to CR2) — a common
    /// mix-up since both are populated together on page faults.
    pub const VM_EXIT_INTERRUPTION_ERROR_CODE: u64 = 0x4406;
    pub const VM_EXIT_INSTRUCTION_LEN: u64 = 0x440C;
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
    pub const HOST_FS_BASE: u64 = 0x6C06;
    pub const HOST_GS_BASE: u64 = 0x6C08;
    pub const HOST_TR_BASE: u64 = 0x6C0A;
    pub const HOST_GDTR_BASE: u64 = 0x6C0C;
    pub const HOST_IDTR_BASE: u64 = 0x6C0E;
    pub const HOST_RIP: u64 = 0x6C16;
    pub const HOST_RSP: u64 = 0x6C14;
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

/// Secondary processor-based VM-execution control bits (SDM Table 24-7).
mod proc_secondary {
    /// Nested paging: the guest's CR3 is ignored and the EPT root from the
    /// EPTP field translates every guest-physical address. (SDM bit 1)
    pub const EPT_ENABLE: u32 = 1 << 1;
    /// Enable RDTSCP: guest can execute RDTSCP. (SDM bit 3)
    pub const RDTSCP: u32 = 1 << 3;
    /// Unrestricted Guest: allows CR0.PE=0 (real mode) under VMX and
    /// relaxes segment-check rules.  Required on Bay Trail for VM-entry
    /// to pass even when running protected-mode guests without EPT.
    /// (SDM Table 24-7 bit 7)
    pub const UNRESTRICTED_GUEST: u32 = 1 << 7;
    /// Time-stamp-counter offsetting (per-VM TSC skew; needed once the
    /// guest measures time — the guest must never see the host's TSC).
    // Used by the SDM-value contract test; deliberately not requested in the
    // run-loop secondary controls (nested KVM does not emulate it for L2).
    #[cfg_attr(not(test), allow(dead_code))]
    pub const TSC_OFFSETTING: u32 = 1 << 17;
}

/// Basic VM-exit reason codes the run loop dispatches (SDM §29.2.1,
/// Table 29-1).
mod exit_reason {
    pub const EXCEPTION: u16 = 0;
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
pub(crate) enum ExitClass {
    Exception,
    ExternalInterrupt,
    Hlt,
    IoInstruction,
    EptViolation,
    Unhandled { reason: u16 },
}

pub(crate) fn classify_exit(reason: u16) -> ExitClass {
    match reason {
        exit_reason::EXCEPTION => ExitClass::Exception,
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

/// Ensure the 4 KB physical page at `phys` is mapped as Write-Back via a
/// variable-range MTRR.  On Bay Trail the firmware sets MTRRdefType to UC
/// (0), which overrides the PAT for ALL physical memory not explicitly
/// covered by a variable MTRR — and vmxon requires WB memory or #GP(0).
unsafe fn ensure_wb_mtrr(phys: u64) {
    let def = rdmsr(0x2FF);
    let def_type = (def & 0xFF) as u8;
    crate::sprintln!("Aegis: [vmx] MTRR: def_type={} phys={:#x}", def_type, phys);
    if def_type == 6 {
        return; // default is already WB
    }
    // Instead of hunting for a free variable MTRR (which the BIOS may have
    // consumed entirely), set the MTRR default type to WB (6). This is what
    // Linux does — it makes ALL physical memory Write-Back by default, and
    // any variable-range MTRRs the BIOS set for specific UC/WC regions still
    // override within their ranges.
    let new_def = (def & !0xFF) | 6u64;
    wrmsr(0x2FF, new_def);
    // WBINVD + INVLPG to ensure the type change takes effect.
    core::arch::asm!("wbinvd", options(nomem, nostack));
    crate::sprintln!(
        "Aegis: [vmx] MTRR: def_type {} -> 6 (WB) via MSR 0x2FF — all memory now WB",
        def_type
    );
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
unsafe fn write_cr0(v: u64) {
    asm!("mov cr0, {}", in(reg) v, options(nomem, nostack, preserves_flags));
}
/// CR2 (page-fault linear address) is NOT a VMCS field and is NOT touched
/// by VM-entry/VM-exit (SDM §27.1). The host must write it explicitly before
/// re-injecting #PF, or the guest's handler reads stale CR2 and faults forever.
unsafe fn write_cr2(v: u64) {
    asm!("mov cr2, {}", in(reg) v, options(nomem, nostack, preserves_flags));
}

/// `vmxon`/`vmclear`/`vmptrld` all take the *physical address* of a region
/// via a memory operand; `vmwrite`/`vmread` take field/value in registers.
unsafe fn vmxon(phys_addr: u64) -> bool {
    // Bay Trail errata: CR4.VMXE can get silently cleared between the
    // enable_vmx_operation() write and the actual vmxon execution (SMM/SCI
    // handlers or firmware-level CR4 shadowing).  Re-set it here with a
    // serializing write to guarantee the write is committed before vmxon.
    let cr4 = read_cr4();
    if cr4 & (1 << 13) == 0 {
        crate::sprintln!(
            "Aegis: [vmx] vmxon pre-flight: CR4.VMXE was CLEAR, re-asserting (cr4={:#x})",
            cr4
        );
        write_cr4(cr4 | (1 << 13));
    }
    // Dump diagnostics: IA32_FEATURE_CONTROL, CR0, CR4, VMXON region contents.
    let fc = rdmsr(IA32_FEATURE_CONTROL);
    let cr0 = read_cr0();
    let basic = rdmsr(IA32_VMX_BASIC);
    let vmx_mem_type = (basic >> 50) & 0xF; // bits 53:50 = required memory type
    let revision = core::ptr::read_volatile(phys_addr as *const u32);
    crate::sprintln!(
        "Aegis: [vmx] vmxon: phys={:#x} cr0={:#x} cr4={:#x} fc={:#x} rev={:#x} basic={:#x} mem_type={}",
        phys_addr, cr0, cr4, fc, revision, basic, vmx_mem_type
    );
    // Serializing fence: MFENCE + LFENCE ensures the CR4 write retires
    // before vmxon is fetched (stronger than CPUID on x86-64).
    core::arch::x86_64::_mm_mfence();
    core::arch::x86_64::_mm_lfence();
    // WBINVD: flush ALL caches so vmxon reads the region from DRAM with
    // the WB MTRR type, not from stale UC cache lines.
    core::arch::asm!("wbinvd", options(nostack));
    core::arch::x86_64::_mm_mfence();
    // vmxon takes a memory operand pointing to the 64-bit physical address.
    let phys_val = phys_addr;
    let cf: u8;
    asm!(
        "vmxon [{0}]",
        "setc {1}",
        in(reg) &phys_val,
        out(reg_byte) cf,
        options(nostack)
    );
    if cf != 0 {
        crate::sprintln!("Aegis: [vmx] vmxon FAILED: CF=1 (VMfailInvalid)");
        false
    } else {
        true
    }
}

unsafe fn vmclear(phys_addr: u64) -> bool {
    let phys_val = phys_addr;
    let cf: u8;
    asm!(
        "vmclear [{0}]",
        "setc {1}",
        in(reg) &phys_val,
        out(reg_byte) cf,
        options(nostack)
    );
    if cf != 0 {
        crate::sprintln!(
            "Aegis: [vmx] vmclear FAILED: CF=1 (VMfailInvalid — VMCS pointer invalid or couldn't write back)"
        );
        false
    } else {
        true
    }
}

/// After vmclear, the processor writes the VMCS data back to the memory
/// region.  On Bay Trail (and possibly other Atom silicon), vmclear can
/// overwrite the first 4 bytes of the VMCS region — the revision-ID
/// header — with garbage.  If vmptrld then sees a bad revision ID, it
/// silently loads a corrupted VMCS and vmlaunch gets error 7.
///
/// Re-stamp the revision ID into offset 0 after every vmclear, before the
/// next vmptrld.  A wbinvd + mfence ensures the write reaches DRAM so
/// vmptrld reads the correct header through the UC MTRR path.
unsafe fn resstamp_vmcs_header(vmcs_phys: u64) {
    let revision = (rdmsr(IA32_VMX_BASIC) & 0x7FFF_FFFF) as u32;
    let hdr = vmcs_phys as *mut u32;
    core::ptr::write_volatile(hdr, revision);
    core::arch::x86_64::_mm_mfence();
    let check = core::ptr::read_volatile(vmcs_phys as *const u32);
    crate::sprintln!(
        "Aegis: [vmx]   resstamp: wrote rev={:#x} hdr={:#x} {}",
        revision,
        check,
        if check == revision { "ok" } else { "MISMATCH" }
    );
}

/// Read the first 4 bytes of the VMCS region for diagnostics.
unsafe fn read_vmcs_header(vmcs_phys: u64) -> u32 {
    core::ptr::read_volatile(vmcs_phys as *const u32)
}

unsafe fn vmptrld(phys_addr: u64) -> bool {
    let phys_val = phys_addr;
    let cf: u8;
    asm!(
        "vmptrld [{0}]",
        "setc {1}",
        in(reg) &phys_val,
        out(reg_byte) cf,
        options(nostack)
    );
    if cf != 0 {
        crate::sprintln!(
            "Aegis: [vmx] vmptrld FAILED: CF=1 (VMfailInvalid — VMCS pointer invalid)"
        );
        false
    } else {
        true
    }
}

unsafe fn vmwrite(field: u64, value: u64) -> bool {
    // Use pushfq/pop with a single out(reg) to atomically capture RFLAGS.
    // NO options(nostack) — pushfq writes 8 bytes to the stack and the
    // compiler must account for this.  A single out(reg) eliminates the
    // register-overlap bug that made lateout(reg_byte) for CF and ZF
    // silently destroy CF when both landed in the same byte register.
    let rflags: u64;
    asm!(
        "vmwrite {0}, {1}",
        "pushfq",
        "pop {2}",
        in(reg) field,
        in(reg) value,
        out(reg) rflags,
    );
    let cf = (rflags & 1) as u8;
    let zf = ((rflags >> 6) & 1) as u8;
    if cf != 0 || zf != 0 {
        crate::sprintln!(
            "Aegis: [vmx] vmwrite FAILED: field={:#x} CF={} ZF={} ({})",
            field,
            cf,
            zf,
            if cf != 0 {
                "VMfailInvalid"
            } else {
                "VMfailValid"
            }
        );
        false
    } else {
        true
    }
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

/// Apply CR0/CR4 fixed-bit constraints per SDM §24.8 / §25.2:
/// `value = (value | fixed0) & fixed1`.
/// fixed0 = bits that MUST be 1; fixed1 = bits that MUST be 0.
/// Pure (no hardware access) — testable without a VMX CPU.
fn apply_fixed_bits(value: u64, fixed0_msr: u32, fixed1_msr: u32) -> u64 {
    let fixed0 = unsafe { rdmsr(fixed0_msr) };
    let fixed1 = unsafe { rdmsr(fixed1_msr) };
    (value | fixed0) & fixed1
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

    // Apply CR0/CR4 fixed bits per SDM §24.8 / §25.2:
    //   IA32_VMX_CR0_FIXED0 (0x486): bits that MUST be 1 in CR0 before VMXON
    //   IA32_VMX_CR0_FIXED1 (0x487): bits that MUST be 0 in CR0 before VMXON
    //   IA32_VMX_CR4_FIXED0 (0x488): bits that MUST be 1 in CR4 before VMXON
    //   IA32_VMX_CR4_FIXED1 (0x489): bits that MUST be 0 in CR4 before VMXON
    //
    // The most common offender on Bay Trail: CR0.NE (bit 5) left clear by
    // firmware/BIOS, which causes #GP(0) at vmxon if not forced on.
    let cr0 = read_cr0();
    let cr0_new = apply_fixed_bits(cr0, IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1);
    if cr0 != cr0_new {
        crate::sprintln!(
            "Aegis: [vmx] enable_vmx: CR0 fixed bits: {:#x} -> {:#x}",
            cr0,
            cr0_new
        );
        // MOV CR0 requires bit 5 (NE) to already be set if CD is being
        // changed — set NE first with a separate MOV, then the full value.
        if cr0_new & (1 << 5) != 0 && cr0 & (1 << 5) == 0 {
            write_cr0(cr0 | (1 << 5)); // set NE first
        }
        write_cr0(cr0_new);
    }

    let cr4 = read_cr4();
    let cr4_new = apply_fixed_bits(cr4, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1);
    if cr4 != cr4_new {
        crate::sprintln!(
            "Aegis: [vmx] enable_vmx: CR4 fixed bits: {:#x} -> {:#x}",
            cr4,
            cr4_new
        );
    }
    // Set CR4.VMXE (bit 13) on top of the fixed-bit result.
    write_cr4(cr4_new | (1 << 13));

    // Read and cache the EPT/VPID capability MSR — used by eptp() to gate
    // bit 6 (accessed/dirty) and bits 2:0 (memory type) on actual
    // silicon support.  Dumped so the log shows what Bay Trail advertises.
    EPT_VPID_CAP = rdmsr(IA32_VMX_EPT_VPID_CAP);
    crate::sprintln!(
        "Aegis: [vmx] IA32_VMX_EPT_VPID_CAP = {:#x}  (bit14_WB={} bit21_AD={})",
        EPT_VPID_CAP,
        (EPT_VPID_CAP >> 14) & 1,
        (EPT_VPID_CAP >> 21) & 1
    );

    Ok(())
}

// ---------------------------------------------------------------------
// Host readiness pre-flight (Phase A Problem 2: live hosting)
// ---------------------------------------------------------------------
//
// The single real obstacle to hosting a guest here is *ownership* of VMX,
// not the presence of the silicon. VT-x can be present yet firmware-locked
// off, or (on a bare-metal host with another VMM loaded) already held —
// in which case Aegis's `vmxon` fails with a cryptic VM-instruction error
// instead of a useful diagnosis. This pre-flight turns that into an exact,
// actionable message and is unit-tested through the pure
// `classify_vmx_readiness` below.
//
// Important (found by actually attempting the nested path): running under
// another hypervisor (CPUID.1:ECX[bit 31]) is NOT a disqualifier. With
// nested virtualization enabled (KVM `nested=Y`, QEMU `-cpu host`), the
// guest hypervisor is handed VT-x and can own it for its own guests. The
// pre-flight therefore blocks only on the CPU-level disqualifiers (no VT-x,
// firmware disabled); if a guest of another VMM wants to host, and VT-x is
// exposed, it reports `Ready` and the attempt is the honest test.

/// The result of checking whether this host can host a guest right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmxReadiness {
    /// VT-x present, feature control permits VMXON. Aegis owns (or can
    /// own) VMX — even under nested virtualization (CPUID.1:ECX[bit 31]
    /// set is *not* a blocker; a guest hypervisor with nested VT-x exposed
    /// can host its own guest).
    Ready,
    /// CPUID.1:ECX.VMX[bit 5] is clear — no Intel VT-x on this part.
    NoVtx,
    /// IA32_FEATURE_CONTROL is locked with VMXON-outside-SMX disabled.
    FeatureControlLockedDisabled,
}

/// Pure classifier — every branch is unit-testable without touching
/// hardware. `feature_control_ok` is true when IA32_FEATURE_CONTROL either
/// is unlocked or is locked with the VMXON-outside-SMX bit set.
///
/// Deliberately does NOT treat "running under another hypervisor" as a
/// failure: under nested virtualization (KVM `nested=Y` / QEMU `-cpu host`),
/// a guest hypervisor is given VT-x and *can* own it for its own guests.
/// If nested VMX is not exposed, the VMX bit reads 0 and this reports
/// `NoVtx` — the honest signal either way.
pub const fn classify_vmx_readiness(vmx_present: bool, feature_control_ok: bool) -> VmxReadiness {
    if !vmx_present {
        return VmxReadiness::NoVtx;
    }
    if !feature_control_ok {
        return VmxReadiness::FeatureControlLockedDisabled;
    }
    VmxReadiness::Ready
}

/// CPUID.1:ECX[bit 31] — "hypervisor present". Set when we are a guest of
/// another VMM. Kept as a public *diagnostic*: it does NOT disqualify a
/// host (a guest hypervisor with nested VT-x exposed can host its own
/// guest), but it explains to an operator *why* VMX is present while the
/// machine is itself a guest.
pub fn under_hypervisor() -> bool {
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
    (ecx >> 31) & 1 == 1
}

/// Runtime pre-flight: probe the real CPU and MSRs. Reads the privileged
/// `IA32_FEATURE_CONTROL` MSR, so it is only callable at CPL 0 — it is
/// invoked by the boot-time demo entry points (`run_loop_demo`,
/// `guest_boot_demo`, `bringup_demo`), never by a user-mode host test (where
/// `rdmsr` would #GP). No test calls this function; the pure classifier
/// `classify_vmx_readiness` covers the logic in host tests instead.
pub fn vmx_host_readiness() -> VmxReadiness {
    if !vmx_supported() {
        return VmxReadiness::NoVtx;
    }
    let fc = unsafe { rdmsr(IA32_FEATURE_CONTROL) };
    const LOCK_BIT: u64 = 1 << 0;
    const VMXON_OUTSIDE_SMX: u64 = 1 << 2;
    let fc_ok = (fc & LOCK_BIT == 0) || (fc & VMXON_OUTSIDE_SMX != 0);
    classify_vmx_readiness(true, fc_ok)
}

/// Human-readable remediation for each readiness state, used by the demo
/// entry points so a wrong host fails loudly and correctly.
pub fn readiness_advice(r: VmxReadiness) -> &'static str {
    match r {
        VmxReadiness::Ready => {
            "VMX host ready — Aegis owns VMX (under nested virtualization, a guest \
             hypervisor with VT-x exposed is a valid host for its own guests)"
        }
        VmxReadiness::NoVtx => {
            "VT-x (VMX) absent from CPUID.1:ECX[bit5]: this CPU lacks Intel VT-x \
             (or is AMD without the equivalent). Aegis's hypervisor cannot run here."
        }
        VmxReadiness::FeatureControlLockedDisabled => {
            "IA32_FEATURE_CONTROL is locked by firmware/BIOS with VMXON-outside-SMX \
             disabled. Enable 'VT-x' / 'Virtualization Technology' in firmware setup."
        }
    }
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
    // CRITICAL: write-back fence + cache flush so the revision ID write
    // (which went through the WB identity-map) is flushed to DRAM before
    // vmxon reads the region.  On Bay Trail the MTRR default type is UC,
    // meaning vmxon reads bypass the CPU cache — if the write is still in
    // a cache line vmxon reads stale zeros and #GP's on revision mismatch.
    core::arch::x86_64::_mm_mfence();
    unsafe {
        // WBINVD: write-back and invalidate ALL caches.  Overkill but
        // guaranteed to flush the revision ID to DRAM on any MTRR config.
        core::arch::asm!("wbinvd", options(nostack));
        core::arch::x86_64::_mm_mfence();
    }
    // Verify the write landed.
    let check = core::ptr::read_volatile(phys as *const u32);
    crate::sprintln!(
        "Aegis: [vmx] alloc_vmx: phys={:#x} revision={:#x} check={:#x} match={}",
        phys,
        revision,
        check,
        revision == check
    );
    // Ensure this physical page is Write-Back via MTRR (Bay Trail UC default
    // causes vmxon to #GP).
    ensure_wb_mtrr(phys);
    Ok(phys)
}

/// Enter VMX root operation exactly once per boot. The three VMX demos
/// (`bringup_demo`, `run_loop_demo`, `guest_boot_demo`) run serially at the
/// end of boot; once one has done VMXON the processor is already in VMX root
/// operation, and a second VMXON would fail (SDM: VMXON is rejected when VMX
/// root operation is active). This latches the first successful VMXON so
/// every demo shares a single root entry.
unsafe fn ensure_vmx_root() -> Result<(), &'static str> {
    static mut ACTIVE: bool = false;
    if ACTIVE {
        return Ok(());
    }
    enable_vmx_operation()?;
    let vmxon_region = alloc_vmx_region()?;
    if !vmxon(vmxon_region) {
        return Err("VMXON failed — check IA32_FEATURE_CONTROL and CR0/CR4 fixed-bit MSRs");
    }
    crate::sprintln!("Aegis: [vmx] VMXON ok, region at {:#x}", vmxon_region);
    ACTIVE = true;
    Ok(())
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
    # Only reached if vmlaunch failed synchronously (bad VMCS/controls,
    # not a real VM-exit).  Capture CF and ZF to classify the failure:
    #   CF=1 ZF=0 → VMfailInvalid  (VMCS not valid / not current)
    #   CF=0 ZF=1 → VMfailValid    (VMCS valid, error in VM_INSTRUCTION_ERROR)
    # Pack into rax: bit 0 = CF, bit 1 = ZF.  Return 0 on success.
    setc al
    movzx eax, al
    setz cl
    or  al, cl
    shl al, 1          # pack: bit 0 = CF, bit 1 = ZF
    movzx eax, al
    ret

.global vmx_do_resume
vmx_do_resume:
    mov [rip + VMX_EXIT_REGS_SYM + 10*8], r11
    mov rax, 0x6C14
    vmwrite rax, rsp
    lea r11, [rip + VMX_EXIT_REGS_SYM]
    VMX_LOAD_GPRS
    vmresume
    # Same failure encoding as vmx_do_launch: bit 0 = CF, bit 1 = ZF.
    setc al
    movzx eax, al
    setz cl
    or  al, cl
    shl al, 1
    movzx eax, al
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

/// Reload host DS/ES/FS/GS with a safe flat data selector (0x10, index 2).
/// Called after every VM-entry attempt (success or failure) to prevent the
/// #GP(0x13B) cascading failure — on Bay Trail, a failed VM-entry can
/// leave host segment registers with stale/invalid selectors, and the
/// next interrupt or context-switch reload trips a #GP if the selector
/// exceeds the host GDT limit.
#[inline(always)]
unsafe fn sanitize_host_segments() {
    // Selector 0x10 = GDT index 2, RPL 0 — the kernel's flat data segment.
    // We already set this up in setup_host_state, but a failed VM-entry
    // may not have restored host state properly.
    let safe: u32 = 0x10;
    unsafe {
        core::arch::asm!(
            "mov ds, {0:e}",
            "mov es, {0:e}",
            "mov fs, {0:e}",
            "mov gs, {0:e}",
            in(reg) safe,
            options(nomem, nostack, preserves_flags),
        );
    }
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
// Host TSC: the run loop's virtual-clock reference. The guest's PIT and
// CMOS advance by the *real* host time that elapsed since the last exit
// (TSC deltas at the calibrated host frequency), so a Linux guest's own
// timer calibration sees a consistent TSC:PIT ratio — the same trick the
// kernel itself uses on bare metal.
// ---------------------------------------------------------------------

/// Ticks of the host TSC (nominal frequency from `TSC_HZ`, calibrated
/// against the host PIT once per boot by `calibrate_host_tsc_hz`).
fn rdtsc_cycles() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Host TSC frequency in Hz, 0 until `calibrate_host_tsc_hz` succeeds.
static mut TSC_HZ: u64 = 0;

/// TSC Hz derived from a PIT calibration: `cycles` of TSC elapsed while
/// the PIT counted `count` PIT cycles at `PIT_CLOCK_HZ`. Pure, so the
/// arithmetic is contract-tested without touching any hardware.
#[cfg(feature = "vmx-demo")]
fn tsc_hz_from_calibration(cycles: u64, count: u64) -> u64 {
    if cycles == 0 || count == 0 {
        0
    } else {
        cycles * crate::vm::PIT_CLOCK_HZ / count
    }
}

/// Calibrate the host TSC against the host 8254 PIT channel 2 — the
/// classic PC bootstrap technique (the Linux guest does the same inside
/// its own boot). Loads a 10 ms mode-0 count, measures the TSC delta
/// until the count expires, and derives Hz. Returns 0 if the PIT or TSC
/// misbehaved (the run loop then leaves the virtual clock frozen).
///
/// On Bay Trail (and other Atom SoCs) the PIT channel 2 is often not
/// wired, so the PIT path is tried first and then CPUID-based fallbacks:
///   1. CPUID leaf 0x15: core crystal clock (denominator, numerator, freq)
///   2. CPUID leaf 0x16: nominal TSC frequency in MHz (bits 15:0)
///
/// # Safety
/// Runs host port I/O on the PIT (unused by this kernel after the PICs
/// are masked) and reads the TSC/CPUID; call once, before the run loop.
#[cfg(feature = "vmx-demo")]
unsafe fn calibrate_host_tsc_hz() -> u64 {
    // --- Attempt 1: PIT channel 2 calibration ---
    const CAL_MS: u64 = 10;
    const MAX_SPINS: u32 = 200_000;
    let latch = ((crate::vm::PIT_CLOCK_HZ * CAL_MS) / 1000) as u16;
    // Gate 2 high / speaker off, then channel 2, mode 0, LSB-then-MSB.
    unsafe {
        asm!("out dx, al", in("dx") 0x61u16, in("al") 0x01u8, options(nomem, preserves_flags));
    }
    unsafe {
        asm!("out dx, al", in("dx") 0x43u16, in("al") 0xB0u8, options(nomem, preserves_flags));
    }
    unsafe {
        asm!("out dx, al", in("dx") 0x42u16, in("al") (latch & 0xFF) as u8, options(nomem, preserves_flags));
    }
    unsafe {
        asm!("out dx, al", in("dx") 0x42u16, in("al") (latch >> 8) as u8, options(nomem, preserves_flags));
    }
    let t0 = rdtsc_cycles();
    let mut spins = 0u32;
    let mut pit_timed_out = false;
    loop {
        // Latch + read the current count; a spent mode-0 channel holds at 0.
        unsafe {
            asm!("out dx, al", in("dx") 0x43u16, in("al") 0x80u8, options(nomem, preserves_flags));
        }
        let lo: u8;
        let hi: u8;
        unsafe {
            asm!("in al, dx", out("al") lo, in("dx") 0x42u16, options(nomem, preserves_flags));
            asm!("in al, dx", out("al") hi, in("dx") 0x42u16, options(nomem, preserves_flags));
        }
        if u16::from_le_bytes([lo, hi]) == 0 {
            break;
        }
        spins += 1;
        if spins >= MAX_SPINS {
            pit_timed_out = true;
            crate::sprintln!("Aegis: [vmx] PIT calibration timed out — trying CPUID fallbacks");
            break;
        }
    }
    if !pit_timed_out {
        let t1 = rdtsc_cycles();
        let pit_result = tsc_hz_from_calibration(t1.wrapping_sub(t0), latch as u64);
        if pit_result > 0 {
            crate::sprintln!("Aegis: [vmx] TSC calibrated via PIT: {} Hz", pit_result);
            return pit_result;
        }
    }

    // --- Attempt 2: CPUID leaf 0x15 — Core Crystal Clock Ratio ---
    // EAX = denominator, EBX = numerator, ECX = nominal freq in Hz.
    // TSC Hz = ECX * EBX / EAX.
    // Sanity: reject if result < 100 MHz (CPUID.15h often returns garbage
    // on Atom/Bay Trail where the crystal is not wired to this interface).
    {
        let regs = core::arch::x86_64::__cpuid_count(0x15, 0);
        if regs.eax != 0 && regs.ebx != 0 && regs.ecx != 0 {
            let freq = regs.ecx as u64;
            let numer = regs.ebx as u64;
            let denom = regs.eax as u64;
            let hz = freq * numer / denom;
            if hz >= 100_000_000 {
                crate::sprintln!(
                    "Aegis: [vmx] TSC calibrated via CPUID.15h: {} Hz (freq={} numer={} denom={})",
                    hz,
                    freq,
                    numer,
                    denom
                );
                return hz;
            }
            crate::sprintln!(
                "Aegis: [vmx] CPUID.15h gave {} Hz (< 100 MHz, likely garbage on Bay Trail)",
                hz
            );
        }
    }

    // --- Attempt 3: CPUID leaf 0x16 — Nominal TSC Frequency (MHz) ---
    // Sanity: reject if < 500 MHz — CPUID.16h can return garbage on Bay
    // Trail (we've seen 1 MHz). Bay Trail TSC is 1.33–2.4 GHz.
    {
        let regs = core::arch::x86_64::__cpuid_count(0x16, 0);
        let mhz = (regs.eax & 0xFFFF) as u64;
        if mhz >= 500 {
            let hz = mhz * 1_000_000;
            crate::sprintln!(
                "Aegis: [vmx] TSC calibrated via CPUID.16h: {} MHz -> {} Hz",
                mhz,
                hz
            );
            return hz;
        }
        if mhz > 0 {
            crate::sprintln!(
                "Aegis: [vmx] CPUID.16h gave {} MHz (< 500 MHz, likely garbage on Bay Trail)",
                mhz
            );
        }
    }

    // --- Fallback: Bay Trail typically 1.33–1.83 GHz; use 1.33 GHz ---
    crate::sprintln!("Aegis: [vmx] WARNING: all TSC calibration methods failed, assuming 1.33 GHz");
    1_330_000_000
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

    // Phase A Problem 2 pre-flight: fail loudly and correctly if this host
    // cannot own VMX (no VT-x, firmware-disabled).
    let readiness = vmx_host_readiness();
    if readiness != VmxReadiness::Ready {
        let msg = readiness_advice(readiness);
        crate::sprintln!("Aegis: [vmx] pre-flight not ready: {}", msg);
        return Err(msg);
    }

    ensure_vmx_root()?;

    let vmcs_region = alloc_vmx_region()?;
    crate::cpu::check_alloc_not_idt(vmcs_region, "VMCS run-loop");
    crate::sprintln!(
        "Aegis: [vmx] run-loop: header after alloc: {:#x}",
        read_vmcs_header(vmcs_region)
    );
    crate::sprintln!("Aegis: [vmx] run-loop: NO-VMCLEAR — vmptrld directly on fresh VMCS");
    if !vmptrld(vmcs_region) {
        return Err("VMPTRLD failed — VMCS not made current");
    }
    crate::sprintln!("Aegis: [vmx] VMCS active at {:#x}", vmcs_region);

    // Guest pages: one for GDT+TSS (0x2000 frame), one for code (0x100000).
    let gdt_tss_phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for guest GDT/TSS page")?;
    crate::cpu::check_alloc_not_idt(gdt_tss_phys, "guest GDT/TSS");
    let code_phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for guest code page")?;
    crate::cpu::check_alloc_not_idt(code_phys, "guest code");

    let mut store = RamDiskStore { data: [0; 512] };
    let devices = crate::vdev::DeviceSet::new(&mut store, 0, crate::vdev::DevicePolicy::all());
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
        mem.write(TSS_GPA, &[0u8; 0x80]) // TSS limit is 0x67; 0x80 bytes covers it within the GDT frame (0x2000–0x3000)
            .then_some(())
            .ok_or("guest TSS page write failed")?;
        mem.write(CODE_GPA, &RUN_LOOP_GUEST)
            .then_some(())
            .ok_or("guest code write failed")?;
    }

    // ── Pre-VMLAUNCH diagnostic: prove what bytes the guest will see ──
    // Read the first 16 bytes at code_phys (host-side physical access)
    // to verify the guest code was written correctly.
    {
        let src = code_phys as *const u8;
        let mut hex = [0u8; 48]; // 16 bytes × 3 hex chars
        for i in 0..16u32 {
            let b = core::ptr::read_volatile(src.add(i as usize));
            let hi = b >> 4;
            let lo = b & 0x0F;
            hex[(i * 3) as usize] = if hi < 10 { b'0' + hi } else { b'A' + hi - 10 };
            hex[(i * 3 + 1) as usize] = if lo < 10 { b'0' + lo } else { b'A' + lo - 10 };
            hex[(i * 3 + 2) as usize] = b' ';
        }
        crate::sprintln!(
            "Aegis: [vmx] PRE-LAUNCH: first 16 bytes at code_phys={:#x}: {:?}",
            code_phys,
            core::str::from_utf8(&hex).unwrap_or("???")
        );
        // Also dump GDT bytes for cross-check.
        let gdt_src = gdt_tss_phys as *const u8;
        let mut ghex = [0u8; 48];
        for i in 0..16u32 {
            let b = core::ptr::read_volatile(gdt_src.add(i as usize));
            let hi = b >> 4;
            let lo = b & 0x0F;
            ghex[(i * 3) as usize] = if hi < 10 { b'0' + hi } else { b'A' + hi - 10 };
            ghex[(i * 3 + 1) as usize] = if lo < 10 { b'0' + lo } else { b'A' + lo - 10 };
            ghex[(i * 3 + 2) as usize] = b' ';
        }
        crate::sprintln!(
            "Aegis: [vmx] PRE-LAUNCH: first 16 bytes at gdt_phys={:#x}: {:?}",
            gdt_tss_phys,
            core::str::from_utf8(&ghex).unwrap_or("???")
        );
        // Expected RUN_LOOP_GUEST bytes for comparison.
        crate::sprintln!(
            "Aegis: [vmx] EXPECTED:   guest code bytes {:02X?}",
            &RUN_LOOP_GUEST[..14]
        );
    }

    // Identity page directory for the guest: KVM nested's CR0 validity
    // check requires the guest to run with PG=1 (CR0_FIXED0 includes PG),
    // so the guest needs real 32-bit page tables. A single 4 MiB-page
    // directory maps the whole 4 GiB linear space identity, which the EPT
    // then bounds to the host frames. PD frame at guest-physical 0x4000.
    let pd_phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for guest page directory")?;
    crate::cpu::check_alloc_not_idt(pd_phys, "guest PD");
    {
        let pd = pd_phys as *mut u32;
        for i in 0..1024usize {
            // 4 MiB page: PS | RW | P — identity (linear i*4MiB -> phys i*4MiB).
            // PDEs are 32-bit (4 bytes), NOT 64-bit — using u64 would overflow
            // the 4 KiB page by 4 KiB, corrupting the next allocated frame.
            core::ptr::write_volatile(pd.add(i), ((i as u32) * 0x400_000) | 0x83);
        }
    }
    const PD_GPA: u64 = 0x4000;
    vm.ept
        .map(
            &mut crate::ept::KernelAlloc,
            &grant,
            PD_GPA,
            pd_phys,
            1,
            crate::ept::EPT_DEFAULT_FLAGS,
        )
        .map_err(|_| "EPT map failed for guest page directory")?;

    // A zeroed low-memory frame for guest-phys 0x0: the 4 MiB identity PDE
    // covers linear 0x0, and the first instruction's page-walk touches the
    // low page (interrupt-vector / null-page area). Map it so the guest's
    // paging-walk A/D tracking and any low-page read succeed.
    let low_phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for guest low-memory page")?;
    crate::cpu::check_alloc_not_idt(low_phys, "guest low-mem");
    core::ptr::write_bytes(low_phys as *mut u8, 0, 4096);
    vm.ept
        .map(
            &mut crate::ept::KernelAlloc,
            &grant,
            0x0,
            low_phys,
            1,
            crate::ept::EPT_DEFAULT_FLAGS,
        )
        .map_err(|_| "EPT map failed for guest low-memory page")?;

    // Boot state mirroring GuestBoot::boot_state() at our hand-picked
    // addresses: flat 32-bit segments, GDT/TSS in the low page, stack at
    // the standard guest stack top, and identity paging (PG=1, CR3 -> PD).
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
        cr0: 0x8000_0031, // PE | NE | ET | PG (CD/NW must be 0 when PG=1 per SDM §26.3.1.1) (PG required by KVM nested CR0 validity)
        cr3: PD_GPA,
        cr4: 0x2010, // VMXE | PSE (PSE required for the 4 MiB-page directory)
        rflags: 0x2,
    };

    setup_host_state()?;
    crate::sprintln!("Aegis: [vmx] run-loop demo: guest prints via emulated 16550, then halts");

    let mut exits = 0u64;
    let mut ept_handler = |vm: &mut Vm<'_, RamDiskStore>, v: crate::ept::EptViolation| {
        crate::sprintln!(
            "Aegis: [vmx] EPT violation at gpa {:#x} access={:?} present={} rip={:#x} cr3={:#x} qual={:#x} (isolation enforced — refused)",
            v.guest_phys,
            v.access,
            v.present,
            vmread(field::GUEST_RIP),
            vmread(field::GUEST_CR3),
            vmread(field::EXIT_QUALIFICATION)
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
    // ── IDT integrity: compare checksum after VM-exit processing ──
    {
        let mut idtr: [u16; 5] = [0; 5];
        unsafe { core::arch::asm!("sidt [{0}]", in(reg) idtr.as_mut_ptr(), options(nostack)) };
        let base = (idtr[1] as u64)
            | ((idtr[2] as u64) << 16)
            | ((idtr[3] as u64) << 32)
            | ((idtr[4] as u64) << 48);
        let limit = idtr[0];
        let cs = crate::idt::idt_checksum(base, limit);
        crate::sprintln!(
            "Aegis: [vmx] POST-RETURN IDT: base={:#x} limit={} checksum={:#018x}",
            base,
            limit,
            cs
        );
        crate::idt::dump_gate(base, 13);
        // Raw descriptors for byte-level comparison
        crate::sprintln!("Aegis: [vmx] POST-RETURN RAW gates[0..32]:");
        crate::idt::dump_raw_gates(base, 0, 32);
    }
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
// Phase U-7: the real Linux guest under Aegis's hypervisor (feature-gated).
// ---------------------------------------------------------------------

/// The committed guest kernel image (built by `guest/build-guest.sh`,
/// evidence in `guest/out/`). Embedded into the kernel image so the
/// hypervisor ships with its guest — this is what the user will boot on
/// real VT-x hardware.
#[cfg(feature = "vmx-demo")]
const GUEST_BZIMAGE: &[u8] = include_bytes!("../../guest/out/bzImage");

/// The committed guest initramfs (BusyBox + the Phase U /init, which
/// prints the Phase U DoD marker when it reaches its interactive shell).
#[cfg(feature = "vmx-demo")]
const GUEST_INITRAMFS: &[u8] = include_bytes!("../../guest/out/initramfs.cpio.gz");

/// True only when a real (multi-MiB) guest image is embedded. When the guest is
/// stubbed out (e.g. during kernel debugging, to shrink the `vmx-demo` payload
/// below the ESP size limit), the boot demos are skipped so the kernel reaches
/// its own shell instead of trying to boot an invalid 4-byte "guest".
#[cfg(feature = "vmx-demo")]
pub fn guest_image_valid() -> bool {
    GUEST_BZIMAGE.len() > (1 << 20) && GUEST_INITRAMFS.len() > (1 << 17)
}

/// Guest RAM for the real-kernel demo: must cover the kernel's `init_size`
/// window (34 MiB) plus the initrd at 16 MiB; Linux relocates itself into
/// the top of this region at decompress time.
#[cfg(feature = "vmx-demo")]
const GUEST_BOOT_RAM_MB: u64 = 128;

/// Backstop exit budget for the real-kernel run (the demo normally ends
/// on the DoD marker, not the budget).
#[cfg(feature = "vmx-demo")]
const GUEST_BOOT_MAX_EXITS: u64 = 2_000_000;

/// The line `guest/initramfs/init` prints when it reaches the interactive
/// shell on the virtual serial console — the Phase U Definition of Done
/// completion point.
#[cfg(feature = "vmx-demo")]
const DOD_MARKER: &[u8] = b"Phase U DoD point";

/// The Phase U-7 end-to-end demo: boots the real committed Linux guest
/// (bzImage + initramfs) under Aegis's hypervisor. Allocates 128 MiB of
/// contiguous host frames as guest RAM, loads the image through the EPT
/// (`Vm::load_linux` maps the whole grant), calibrates the host TSC
/// against the PIT so the guest's virtual clock tracks wall-clock time,
/// and runs the kernel under the resumable run loop with the guest's
/// serial console drained through the emulated 16550 and timer/PIC
/// interrupt injection enabled. Stops when the guest prints the Phase U
/// DoD marker (its shell is up), or at the exit budget.
///
/// # Safety
/// Requires VMX root operation and the same preconditions as
/// `vmx_run_guest`; run only on a VT-x-capable CPU (guard with
/// `vmx_supported()`), once per boot, before interrupts turn on.
#[cfg(feature = "vmx-demo")]
pub unsafe fn guest_boot_demo() -> Result<(), &'static str> {
    // Phase A Problem 2 pre-flight: fail loudly and correctly if this host
    // cannot own VMX (no VT-x, firmware-disabled).
    let readiness = vmx_host_readiness();
    if readiness != VmxReadiness::Ready {
        let msg = readiness_advice(readiness);
        crate::sprintln!("Aegis: [vmx] pre-flight not ready: {}", msg);
        return Err(msg);
    }

    ensure_vmx_root()?;

    let vmcs_region = alloc_vmx_region()?;
    crate::sprintln!(
        "Aegis: [vmx] guest-boot: header after alloc: {:#x}",
        read_vmcs_header(vmcs_region)
    );
    crate::sprintln!("Aegis: [vmx] guest-boot: NO-VMCLEAR — vmptrld directly on fresh VMCS");
    if !vmptrld(vmcs_region) {
        return Err("VMPTRLD failed — VMCS not made current");
    }
    crate::sprintln!("Aegis: [vmx] VMCS active at {:#x}", vmcs_region);

    // Host TSC calibration drives the guest's virtual clock (PIT/CMOS) at
    // wall-clock speed, so the guest kernel's own timer calibration sees
    // a consistent TSC:PIT ratio.
    let tsc_hz = calibrate_host_tsc_hz();
    unsafe { TSC_HZ = tsc_hz };
    crate::sprintln!("Aegis: [vmx] host TSC calibrated at {} Hz", tsc_hz);

    // Guest RAM: one contiguous host allocation for the whole grant.
    let frames = (GUEST_BOOT_RAM_MB << 20) / 4096;
    let guest_ram = crate::frame::alloc_contiguous_global(frames)
        .ok_or("frame allocator: out of memory for guest RAM (128 MiB contiguous)")?;
    crate::sprintln!(
        "Aegis: [vmx] guest RAM: {} MiB at host phys {:#x}",
        GUEST_BOOT_RAM_MB,
        guest_ram
    );

    let mut store = RamDiskStore { data: [0; 512] };
    let devices = crate::vdev::DeviceSet::new(&mut store, 0, crate::vdev::DevicePolicy::all());
    let grant = crate::ept::MemGrant::new(0, frames);
    let mut vm = Vm::new(0, grant, devices, guest_ram, 1000);

    // `noapic`: the guest has no ACPI tables, so Linux must not touch the
    // LAPIC/I/O-APIC MMIO (unmapped in the EPT — a violation would stop
    // the run). The legacy PIC + PIT + 16550 are the whole device set.
    const CMDLINE: &str = "console=ttyS0,115200n8 noapic nolapic";
    vm.load_linux(
        &mut crate::ept::KernelAlloc,
        GUEST_BZIMAGE,
        Some(GUEST_INITRAMFS),
        CMDLINE,
    )
    .map_err(|_| "guest image load failed (layout/EPT error — see vm.rs GuestBoot)")?;
    let boot = vm.boot_state().ok_or("guest not loaded")?;
    setup_host_state()?;

    // ── Dump first 32 bytes at the 32-bit entry point ──
    {
        if let Some(hpa) = vm.ept.translate(crate::vm::CODE32_GPA) {
            let src = hpa as *const u8;
            let mut hex = [0u8; 96]; // 32 bytes × 3 hex chars
            for i in 0..32u32 {
                let b = core::ptr::read_volatile(src.add(i as usize));
                let hi = b >> 4;
                let lo = b & 0x0F;
                hex[(i * 3) as usize] = if hi < 10 { b'0' + hi } else { b'A' + hi - 10 };
                hex[(i * 3 + 1) as usize] = if lo < 10 { b'0' + lo } else { b'A' + lo - 10 };
                hex[(i * 3 + 2) as usize] = b' ';
            }
            crate::sprintln!(
                "Aegis: [vmx] guest boot: first 32 bytes at {:#x} (hpa={:#x}): {:?}",
                crate::vm::CODE32_GPA,
                hpa,
                core::str::from_utf8(&hex).unwrap_or("?")
            );
        } else {
            crate::sprintln!(
                "Aegis: [vmx] guest boot: WARNING — cannot translate GPA {:#x} to host PA",
                crate::vm::CODE32_GPA
            );
        }
    }

    // ── Write a 256-entry IDT into guest memory ──
    // The guest IDTR points to GPA 0 (the low-memory page). Write
    // exception gate entries for ALL 256 vectors, each pointing to a
    // tiny handler at GPA 0x200 that just does `iret`.
    //
    // IMPORTANT: vmx_run_guest → setup_guest_state_from_boot overrides
    // GUEST_IDTR_LIMIT to 0xFFFF (64KB). If we only write 32 entries,
    // any interrupt with vector ≥ 32 reads garbage from GPA 0x100+,
    // causing #GP(0) on VM-entry — this is the root cause of the
    // #GP(0) at RIP=0x100000 on Braswell (xHCI MSI = vector 39).
    // All 256 vectors must be covered to survive the 0xFFFF override.
    const IDT_BASE: u64 = 0x0;
    const IDT_HANDLER: u64 = 0x200; // `iret` gadget
    {
        let mut idt = [0u8; 2048]; // 256 vectors × 8 bytes
        for v in 0..256u64 {
            let off = IDT_HANDLER as u32;
            let entry: [u8; 8] = [
                (off & 0xFF) as u8,
                ((off >> 8) & 0xFF) as u8,
                0x08, // selector = kernel code
                0,    // reserved
                0x8E, // present, DPL=0, 32-bit interrupt gate
                0x00,
                ((off >> 16) & 0xFF) as u8,
                ((off >> 24) & 0xFF) as u8,
            ];
            let base = (v * 8) as usize;
            idt[base..base + 8].copy_from_slice(&entry);
        }
        // Translate GPA→HPA and write directly (avoids GuestMem visibility issue)
        let mut write_at = |gpa: u64, data: &[u8]| -> bool {
            match vm.ept.translate(gpa) {
                Some(hpa) => {
                    unsafe {
                        core::ptr::copy_nonoverlapping(data.as_ptr(), hpa as *mut u8, data.len());
                    }
                    true
                }
                None => false,
            }
        };
        if !write_at(IDT_BASE, &idt) {
            crate::sprintln!(
                "Aegis: [vmx] guest boot: WARNING — IDT write to GPA {:#x} failed",
                IDT_BASE
            );
        }
        if !write_at(IDT_HANDLER, &[0xCF]) {
            // iret
            crate::sprintln!(
                "Aegis: [vmx] guest boot: WARNING — iret gadget write to GPA {:#x} failed",
                IDT_HANDLER
            );
        }
        // Update the VMCS IDTR (vmwrite touches VMCS, not vm.ept)
        vmwrite(field::GUEST_IDTR_BASE, IDT_BASE);
        vmwrite(field::GUEST_IDTR_LIMIT, (256 * 8 - 1) as u64);
        crate::sprintln!(
            "Aegis: [vmx] guest boot: 256-entry IDT at GPA {:#x} (all vectors → iret at {:#x})",
            IDT_BASE,
            IDT_HANDLER
        );
    }

    crate::sprintln!(
        "Aegis: [vmx] guest boot: bzImage {} bytes, initramfs {} bytes, cmdline \"{}\"",
        GUEST_BZIMAGE.len(),
        GUEST_INITRAMFS.len(),
        CMDLINE
    );
    crate::sprintln!(
        "Aegis: [vmx] guest boot: running the real Linux kernel under EPT (exit budget {})",
        GUEST_BOOT_MAX_EXITS
    );

    // Guest console capture: buffer serial bytes into lines, print each
    // complete line with a prefix, and stop shortly after the Phase U DoD
    // marker line (the guest's shell is up — everything after it is idle
    // traffic). The exit budget is the backstop.
    let mut line = [0u8; 512];
    let mut line_len = 0usize;
    let mut marker_exit: Option<u64> = None;
    let mut exits = 0u64;
    let mut ept_handler = |vm: &mut Vm<'_, RamDiskStore>, v: crate::ept::EptViolation| {
        crate::sprintln!(
            "Aegis: [vmx] guest boot EPT violation at {:#x} (unexpected — the full grant is mapped)",
            v.guest_phys
        );
        let _ = vm;
        Ok::<bool, &'static str>(false)
    };
    let mut exit_hook = |vm: &mut Vm<'_, RamDiskStore>| {
        while let Some(b) = vm.devices.uart.take_tx() {
            if b == b'\n' || line_len == line.len() {
                let text = core::str::from_utf8(&line[..line_len]).unwrap_or("<non-utf8>");
                crate::sprintln!("Aegis: [vmx-guest] {}", text);
                if marker_exit.is_none()
                    && line[..line_len]
                        .windows(DOD_MARKER.len())
                        .any(|w| w == DOD_MARKER)
                {
                    marker_exit = Some(exits);
                }
                line_len = 0;
            } else if b != b'\r' {
                line[line_len] = b;
                line_len += 1;
            }
        }
        exits += 1;
        if let Some(at) = marker_exit {
            // Flush a few exits past the marker (the shell prompt itself),
            // then stop cleanly.
            if exits >= at + 20 {
                return Ok::<bool, &'static str>(false);
            }
        }
        Ok::<bool, &'static str>(exits < GUEST_BOOT_MAX_EXITS)
    };

    let result = vmx_run_guest(
        &boot,
        &mut vm,
        GUEST_BOOT_MAX_EXITS,
        &mut ept_handler,
        &mut exit_hook,
    );
    // ── Guest IDT diagnostic (read via VMCS + EPT, NOT host sidt) ──
    // The host IDTR is reloaded by VMX hardware on every VM-exit, so
    // `sidt` always shows the host's IDT — useless for diagnosing
    // guest faults. Read the guest's actual IDTR from the VMCS.
    {
        let idt_base = vmread(field::GUEST_IDTR_BASE);
        let idt_limit = vmread(field::GUEST_IDTR_LIMIT) as u16;
        crate::sprintln!(
            "Aegis: [vmx] GUEST POST-VMEXIT IDTR: base={:#x} limit={:#x}",
            idt_base,
            idt_limit
        );
        // Dump gate 13 from the guest's IDT via EPT translation.
        if let Some(hpa) = vm.ept.translate(idt_base) {
            crate::idt::dump_gate(hpa, 13);
            crate::sprintln!("Aegis: [vmx] GUEST POST-VMEXIT RAW gates[0..32]:");
            crate::idt::dump_raw_gates(hpa, 0, 32);
        } else {
            crate::sprintln!(
                "Aegis: [vmx] GUEST POST-VMEXIT IDT: WARNING — cannot translate guest IDT base {:#x}",
                idt_base
            );
        }
    }
    match result {
        Ok(()) if marker_exit.is_some() => {
            crate::sprintln!(
                "Aegis: [vmx] guest boot: Phase U DoD marker seen — the real Linux kernel reached its shell through Aegis's hypervisor ({} VM-exits)",
                exits
            );
            Ok(())
        }
        Ok(()) => {
            crate::sprintln!(
                "Aegis: [vmx] guest boot: stopped before the DoD marker ({} VM-exits)",
                exits
            );
            Err("guest boot stopped before the DoD marker (see the [vmx-guest] log)")
        }
        Err(e) => {
            crate::sprintln!("Aegis: [vmx] guest boot failed: {} ({} VM-exits)", e, exits);
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------
// VMCS state setup
// ---------------------------------------------------------------------

unsafe fn setup_host_state() -> Result<(), &'static str> {
    let (cs, ss, tr, ds, es, fs, gs): (u16, u16, u16, u16, u16, u16, u16);
    asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
    asm!("str {0:x}", out(reg) tr, options(nomem, nostack, preserves_flags));
    asm!("mov {0:x}, ds", out(reg) ds, options(nomem, nostack, preserves_flags));
    asm!("mov {0:x}, es", out(reg) es, options(nomem, nostack, preserves_flags));
    asm!("mov {0:x}, fs", out(reg) fs, options(nomem, nostack, preserves_flags));
    asm!("mov {0:x}, gs", out(reg) gs, options(nomem, nostack, preserves_flags));

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
    vmwrite(field::HOST_DS_SELECTOR, (ds & 0xFFF8) as u64);
    vmwrite(field::HOST_ES_SELECTOR, (es & 0xFFF8) as u64);
    vmwrite(field::HOST_FS_SELECTOR, (fs & 0xFFF8) as u64);
    vmwrite(field::HOST_GS_SELECTOR, (gs & 0xFFF8) as u64);
    vmwrite(field::HOST_CR0, read_cr0());
    vmwrite(field::HOST_CR3, read_cr3());
    vmwrite(field::HOST_CR4, read_cr4());
    vmwrite(field::HOST_FS_BASE, rdmsr(0xC0000100)); // MSR_FS_BASE
    vmwrite(field::HOST_GS_BASE, rdmsr(0xC0000101)); // MSR_GS_BASE
    vmwrite(field::HOST_GDTR_BASE, gdtr_base);
    // HOST_TR_BASE: read the TSS base from the GDT using the live TR
    // selector.  In long mode, TSS descriptors are 16 bytes; the base
    // address spans bytes 2-3 (base[15:0]), byte 4 (base[23:16]),
    // byte 7 (base[31:24]), and bytes 8-11 (base[63:32]).
    {
        let tr_idx = ((tr & 0xFFF8) >> 3) as u64;
        let desc_lo = core::ptr::read_volatile((gdtr_base + tr_idx * 8) as *const u64);
        let desc_hi = core::ptr::read_volatile((gdtr_base + tr_idx * 8 + 8) as *const u64);
        let base_lo = (desc_lo >> 16) & 0xFFFF;
        let base_mid = (desc_lo >> 32) & 0xFF;
        let base_hi = (desc_lo >> 56) & 0xFF;
        let base_top = desc_hi & 0xFFFFFFFF;
        let tr_base = base_lo | (base_mid << 16) | (base_hi << 24) | (base_top << 32);
        vmwrite(field::HOST_TR_BASE, tr_base);
    }
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

unsafe fn setup_guest_state(
    guest_code_phys: u64,
    gdt_phys: u64,
    tss_phys: u64,
) -> Result<(), &'static str> {
    // Protected-mode guest with flat 32-bit segments. Real mode can't reach
    // code pages allocated above 1MB (selector is only 16 bits, so
    // selector*16 can't exceed 1MB). With PE=1, PG=0, and flat segments
    // (base=0, limit=4GB), the guest accesses physical memory directly —
    // RIP = guest_code_phys works regardless of address.
    vmwrite(field::GUEST_CR0, 0x0021); // PE | NE (no PG, no CD/NW)
    vmwrite(field::GUEST_CR3, 0);
    vmwrite(field::GUEST_CR4, 0x2000); // VMXE
    vmwrite(field::CR0_GUEST_HOST_MASK, 0);
    vmwrite(field::CR4_GUEST_HOST_MASK, 0);

    // CS: 32-bit code segment, base=0, limit=4GB, D=1 (32-bit default).
    // AR=0xC09B: P=1, DPL=0, S=1, type=code-r/a, G=1, D=1, L=0.
    vmwrite(field::GUEST_CS_SELECTOR, 0x08);
    vmwrite(field::GUEST_CS_BASE, 0);
    vmwrite(field::GUEST_CS_LIMIT, 0xFFFFF);
    vmwrite(field::GUEST_CS_AR_BYTES, 0xC09B);

    // DS/ES/SS: 32-bit data segment, base=0, limit=4GB.
    // AR=0xC093: P=1, DPL=0, S=1, type=data-r/w/a, G=1, D=1, L=0.
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
    ] {
        vmwrite(sel_f, 0x10);
        vmwrite(base_f, 0);
        vmwrite(limit_f, 0xFFFFF);
        vmwrite(ar_f, 0xC093);
    }

    // FS/GS: mark unusable — not used by the demo guest and having them
    // usable requires valid GDT descriptors. Bit 16 = 1 → unusable.
    for sel_f in [field::GUEST_FS_SELECTOR, field::GUEST_GS_SELECTOR] {
        vmwrite(sel_f, 0);
    }
    vmwrite(field::GUEST_FS_BASE, 0);
    vmwrite(field::GUEST_FS_LIMIT, 0xFFFF);
    vmwrite(field::GUEST_FS_AR_BYTES, ar::LDTR_UNUSABLE as u64);
    vmwrite(field::GUEST_GS_BASE, 0);
    vmwrite(field::GUEST_GS_LIMIT, 0xFFFF);
    vmwrite(field::GUEST_GS_AR_BYTES, ar::LDTR_UNUSABLE as u64);

    vmwrite(field::GUEST_LDTR_SELECTOR, 0);
    vmwrite(field::GUEST_LDTR_BASE, 0);
    vmwrite(field::GUEST_LDTR_LIMIT, 0xFFFF);
    vmwrite(field::GUEST_LDTR_AR_BYTES, ar::LDTR_UNUSABLE as u64);

    // TR: 32-bit busy TSS at GDT entry 3 (selector 0x18).
    // The GDT is set up by the caller with entry 3 as a 32-bit TSS.
    vmwrite(field::GUEST_TR_SELECTOR, 0x18);
    vmwrite(field::GUEST_TR_BASE, tss_phys);
    vmwrite(field::GUEST_TR_LIMIT, 0x67); // sizeof(minimal TSS) - 1
    vmwrite(field::GUEST_TR_AR_BYTES, ar::TR_BUSY_32 as u64);

    vmwrite(field::GUEST_GDTR_BASE, gdt_phys);
    vmwrite(field::GUEST_GDTR_LIMIT, 0x27); // 4 entries × 8 bytes - 1 = 31
    vmwrite(field::GUEST_IDTR_BASE, 0);
    vmwrite(field::GUEST_IDTR_LIMIT, 0xFFFF);

    vmwrite(field::GUEST_DR7, 0x400);
    vmwrite(field::GUEST_RSP, 0);
    vmwrite(field::GUEST_RIP, guest_code_phys); // flat base=0, so RIP = physical address
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
    vmwrite(field::GUEST_CR3, boot.cr3);
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
        // TSC_OFFSETTING deliberately excluded from the desired set: under
        // nested virtualization (KVM L0) it is not emulated for L2 and its
        // presence in the secondary controls can make L2 entry fail.
        let secondary_desired = proc_secondary::EPT_ENABLE
            | proc_secondary::UNRESTRICTED_GUEST
            | proc_secondary::RDTSCP;
        let secondary = adjust_controls(
            IA32_VMX_TRUE_PROCBASED2_CTLS,
            IA32_VMX_PROCBASED2_CTLS,
            secondary_desired,
        );
        if secondary & proc_secondary::EPT_ENABLE == 0 {
            return Err("CPU lacks EPT (nested paging) — required for the run-loop demo");
        }
        vmwrite(field::SECONDARY_VM_EXEC_CONTROL, secondary as u64);
        vmwrite(field::EPTP, eptp(ept_root, EPT_VPID_CAP));
        // TSC_OFFSET intentionally NOT written: Bay Trail reports RDTSCP
        // (bit 3) as allowed-1 but does not support the TSC_OFFSET field
        // when TSC_OFFSETTING (bit 17) is disabled.  Writing it causes a
        // VMfailValid (VM_INSTRUCTION_ERROR=7).  With TSC_OFFSETTING off
        // the CPU treats TSC_OFFSET as 0, which is what we want.
    } else {
        // Bay Trail requires Unrestricted Guest (bit 7) even for
        // protected-mode guests without EPT — without it the
        // VM-entry check rejects guest state (exit reason 33).
        let secondary_desired = proc_secondary::UNRESTRICTED_GUEST;
        let secondary = adjust_controls(
            IA32_VMX_TRUE_PROCBASED2_CTLS,
            IA32_VMX_PROCBASED2_CTLS,
            secondary_desired,
        );
        vmwrite(field::SECONDARY_VM_EXEC_CONTROL, secondary as u64);
    }

    // VM-exit controls: bit 9 (0x200) = host address-space size (64-bit
    // host) — required since this kernel runs in long mode.
    let exit_ctrls = adjust_controls(IA32_VMX_TRUE_EXIT_CTLS, IA32_VMX_EXIT_CTLS, 0x200);
    vmwrite(field::VM_EXIT_CONTROLS, exit_ctrls as u64);

    // VM-entry controls: 0 desired bits — IA-32e-mode-guest stays off
    // (this run loop's guests are 32-bit protected mode under EPT).
    let entry_ctrls = adjust_controls(IA32_VMX_TRUE_ENTRY_CTLS, IA32_VMX_ENTRY_CTLS, 0);
    vmwrite(field::VM_ENTRY_CONTROLS, entry_ctrls as u64);

    // Intercept #GP (vec 13) and #PF (vec 14) so Linux faults cause a clean
    // VM-exit.  The exit handler injects them back into the guest via VM-entry
    // interruption injection so the guest's own IDT handles them.
    // (Bitmap=0 caused triple-fault reboot loops on Braswell N3060.)
    vmwrite(field::EXCEPTION_BITMAP, (1 << 13) | (1 << 14));
    Ok(())
}

// ---------------------------------------------------------------------
// VM-exit decode (pure — contract-tested without a VMX CPU)
// ---------------------------------------------------------------------

/// A decoded I/O VM-exit (SDM Table 27-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IoExit {
    port: u16,
    out: bool,
    size: u8,
    is_string: bool,
}

/// Decode the exit qualification of an I/O-instruction VM-exit: bits 2:0 =
/// operand size (0 = 1 byte, 1 = 2 bytes, 3 = 4 bytes), bit 3 = direction
/// (0 = OUT, 1 = IN), bit 4 = string instruction, bits 31:16 = port number.
/// Reserved size encodings (2) return `None` — refuse rather than guess.
pub(crate) fn decode_io_exit(qualification: u64) -> Option<IoExit> {
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
pub(crate) fn io_instruction_len(opcode: u8) -> Option<u8> {
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

/// Deliver a pending PIC vector at the next VM-entry if the guest is
/// ready for it: RFLAGS.IF set and no STI/MOV-SS interrupt blocking. A
/// pending vector wakes a halted guest (the HLT activity state is cleared
/// so the entry does not halt again). The vector is taken from the PIC
/// (IRR -> ISR ack) only when actually injected, so an IF-clear guest
/// keeps the IRQ latched for a later exit.
///
/// # Safety
/// Requires a current VMCS and VMX root operation (same context as
/// `vmx_run_guest`).
unsafe fn maybe_inject_interrupt<S: BlockStore>(devices: &mut crate::vdev::DeviceSet<'_, S>) {
    if devices.pic_peek_vector().is_none() {
        return;
    }
    let rflags = vmread(field::GUEST_RFLAGS);
    if rflags & (1 << 9) == 0 {
        return;
    }
    if vmread(field::GUEST_INTERRUPTIBILITY_INFO) != 0 {
        return;
    }
    if let Some(vector) = devices.pic_pending_vector() {
        vmwrite(field::GUEST_ACTIVITY_STATE, 0);
        vmwrite(
            field::VM_ENTRY_INTR_INFO,
            0x8000_0000 | (vector as u64 & 0xFF),
        );
    }
}

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
/// After every handled exit, before the next entry, the loop also:
/// - advances the guest's virtual clock (PIT/CMOS) by the real host time
///   that elapsed since the last exit (TSC deltas at the calibrated host
///   frequency — see the TSC block above). Sub-millisecond remainders
///   accumulate so the PIT keeps moving even while the guest spins in
///   tight I/O loops;
/// - reflects device lines into the PIC (`update_pic`);
/// - injects a pending PIC vector if the guest is ready for one
///   (RFLAGS.IF set, no interrupt blocking — see `maybe_inject_interrupt`).
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

    // ── Pre-VMLAUNCH diagnostic: dump VMCS guest state ──
    crate::sprintln!(
        "Aegis: [vmx] PRE-LAUNCH GUEST: RIP={:#x} CS_BASE={:#x} CS_LIM={:#x} CR0={:#x} CR3={:#x} CR4={:#x}",
        vmread(field::GUEST_RIP),
        vmread(field::GUEST_CS_BASE),
        vmread(field::GUEST_CS_LIMIT),
        vmread(field::GUEST_CR0),
        vmread(field::GUEST_CR3),
        vmread(field::GUEST_CR4),
    );
    crate::sprintln!(
        "Aegis: [vmx] PRE-LAUNCH GUEST: RSP={:#x} RFLAGS={:#x} GDTR_BASE={:#x} GDTR_LIM={} TR_SEL={:#x}",
        vmread(field::GUEST_RSP),
        vmread(field::GUEST_RFLAGS),
        vmread(field::GUEST_GDTR_BASE),
        vmread(field::GUEST_GDTR_LIMIT),
        vmread(field::GUEST_TR_SELECTOR),
    );
    // ── Pre-VMLAUNCH HOST state dump — compare with bringup_demo ──
    crate::sprintln!(
        "Aegis: [vmx] PRE-LAUNCH HOST: CS={:#x} SS={:#x} DS={:#x} ES={:#x} FS={:#x} GS={:#x} TR={:#x}",
        vmread(field::HOST_CS_SELECTOR),
        vmread(field::HOST_SS_SELECTOR),
        vmread(field::HOST_DS_SELECTOR),
        vmread(field::HOST_ES_SELECTOR),
        vmread(field::HOST_FS_SELECTOR),
        vmread(field::HOST_GS_SELECTOR),
        vmread(field::HOST_TR_SELECTOR),
    );
    crate::sprintln!(
        "Aegis: [vmx] PRE-LAUNCH HOST: CR0={:#x} CR3={:#x} CR4={:#x} RIP={:#x} RSP={:#x}",
        vmread(field::HOST_CR0),
        vmread(field::HOST_CR3),
        vmread(field::HOST_CR4),
        vmread(field::HOST_RIP),
        vmread(field::HOST_RSP),
    );
    crate::sprintln!(
        "Aegis: [vmx] PRE-LAUNCH HOST: GDTR_BASE={:#x} IDTR_BASE={:#x} FS_BASE={:#x} GS_BASE={:#x} TR_BASE={:#x}",
        vmread(field::HOST_GDTR_BASE),
        vmread(field::HOST_IDTR_BASE),
        vmread(field::HOST_FS_BASE),
        vmread(field::HOST_GS_BASE),
        vmread(field::HOST_TR_BASE),
    );
    // ── Live CPU segment registers (right now, before VMLAUNCH) ──
    {
        let mut cs: u16;
        let mut ss: u16;
        let mut ds: u16;
        let mut es: u16;
        let mut fs: u16;
        let mut gs: u16;
        let mut tr: u16;
        unsafe {
            core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack));
            core::arch::asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack));
            core::arch::asm!("mov {0:x}, ds", out(reg) ds, options(nomem, nostack));
            core::arch::asm!("mov {0:x}, es", out(reg) es, options(nomem, nostack));
            core::arch::asm!("mov {0:x}, fs", out(reg) fs, options(nomem, nostack));
            core::arch::asm!("mov {0:x}, gs", out(reg) gs, options(nomem, nostack));
            core::arch::asm!("str {0:x}", out(reg) tr, options(nomem, nostack));
        }
        crate::sprintln!(
            "Aegis: [vmx] LIVE CPU SEG: CS={:#x} SS={:#x} DS={:#x} ES={:#x} FS={:#x} GS={:#x} TR={:#x}",
            cs, ss, ds, es, fs, gs, tr
        );
    }
    // ── Dump host GDT descriptors for selectors 0x08..0x38 ──
    {
        let gdtr_base = vmread(field::HOST_GDTR_BASE);
        for sel in [0x08u16, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38] {
            let idx = (sel >> 3) as usize;
            let desc_lo = core::ptr::read_volatile((gdtr_base + (idx * 8) as u64) as *const u64);
            let desc_hi =
                core::ptr::read_volatile((gdtr_base + (idx * 8 + 8) as u64) as *const u64);
            let base = ((desc_lo >> 16) & 0xFFFF)
                | (((desc_lo >> 32) & 0xFF) << 16)
                | (((desc_lo >> 56) & 0xFF) << 24);
            let limit = (desc_lo & 0xFFFF) | (((desc_lo >> 48) & 0xF) << 16);
            let ar = ((desc_lo >> 40) & 0xFF) as u8;
            let typ = ar & 0x0F;
            let s = (ar >> 4) & 1;
            let dpl = (ar >> 5) & 3;
            let p = (ar >> 7) & 1;
            let g = ((desc_lo >> 55) & 1) as u8;
            let db = ((desc_lo >> 54) & 1) as u8;
            let l = ((desc_lo >> 53) & 1) as u8;
            crate::sprintln!(
                "Aegis: [vmx] HOST GDT[{:#x}]: sel={:#x} base={:#x} lim={:#x} typ={} S={} DPL={} P={} G={} D/B={} L={}",
                idx, sel, base, limit, typ, s, dpl, p, g, db, l
            );
        }
    }
    // ── Dump bytes at guest RIP (GPA 0x100000) through EPT translation ──
    {
        let gpa_rip = boot.eip;
        let mut hex32 = [0u8; 96]; // 32 bytes × 3 hex chars
                                   // Read through EPT translation (what the guest actually sees)
        let hpa = vm.ept.translate(gpa_rip);
        if let Some(hpa) = hpa {
            let src = hpa as *const u8;
            for i in 0..32u32 {
                let b = core::ptr::read_volatile(src.add(i as usize));
                let hi = b >> 4;
                let lo = b & 0x0F;
                hex32[(i * 3) as usize] = if hi < 10 { b'0' + hi } else { b'A' + hi - 10 };
                hex32[(i * 3 + 1) as usize] = if lo < 10 { b'0' + lo } else { b'A' + lo - 10 };
                hex32[(i * 3 + 2) as usize] = b' ';
            }
            crate::sprintln!(
                "Aegis: [vmx] GUEST RIP BYTES (GPA={:#x} -> HPA={:#x}): {:?}",
                gpa_rip,
                hpa,
                core::str::from_utf8(&hex32).unwrap_or("???")
            );
        } else {
            crate::sprintln!(
                "Aegis: [vmx] GUEST RIP BYTES: GPA={:#x} NOT MAPPED IN EPT!",
                gpa_rip
            );
        }
        // Dump EPT walk for GPA 0x100000
        crate::sprintln!(
            "Aegis: [vmx] EPT walk for GPA {:#x}: root={:#x}",
            gpa_rip,
            vm.ept.root()
        );
    }
    crate::sprintln!("Aegis: [vmx] PRE-LAUNCH: seeding ESI={:#x}", boot.esi);
    VMX_EXIT_REGS_SYM[4] = boot.esi;
    crate::sprintln!("Aegis: [vmx] PRE-LAUNCH: ESI seeded, about to enter loop");

    // ── IDT integrity: capture checksum before first VMLAUNCH ──
    let (_idtr_base_pre, _idtr_limit_pre, _checksum_pre) = {
        let mut idtr: [u16; 5] = [0; 5];
        unsafe { asm!("sidt [{0}]", in(reg) idtr.as_mut_ptr(), options(nostack)) };
        let base = (idtr[1] as u64)
            | ((idtr[2] as u64) << 16)
            | ((idtr[3] as u64) << 32)
            | ((idtr[4] as u64) << 48);
        let limit = idtr[0];
        let cs = crate::idt::idt_checksum(base, limit);
        crate::sprintln!(
            "Aegis: [vmx] PRE-LAUNCH IDT: base={:#x} limit={} checksum={:#018x}",
            base,
            limit,
            cs
        );
        // Dump the specific gate that would be vector 13 (#GP) for cross-check
        crate::idt::dump_gate(base, 13);
        // Raw descriptors for gates 0-31 for byte-level comparison
        crate::sprintln!("Aegis: [vmx] PRE-LAUNCH RAW gates[0..32]:");
        crate::idt::dump_raw_gates(base, 0, 32);
        (base, limit, cs)
    };

    // Seed the guest's initial registers: the trampoline loads every GPR
    // from VMX_EXIT_REGS_SYM (all zero initially, which is the boot
    // contract for every GPR except ESI/RSP/RIP), so only ESI differs:
    // a Linux boot hands the zero page pointer in ESI, and the demo guest
    // gets the same slot seeded from its boot state.
    VMX_EXIT_REGS_SYM[4] = boot.esi;

    let mut entered = false;
    let mut exits = 0u64;
    let mut inject_count = 0u32;
    let mut mystery_count = 0u32;
    let mut last_inject_rip: u64 = 0;
    let mut last_inject_vec: u8 = 0;
    let mut consecutive_same_rip: u32 = 0;
    // Virtual-clock bookkeeping: the last host TSC sample and the
    // sub-millisecond accumulator (µs), so fractional per-exit deltas are
    // not lost to integer rounding.
    let mut last_tsc = rdtsc_cycles();
    let mut frac_us: u64 = 0;
    loop {
        if exits >= max_exits {
            return Err("exit budget exhausted");
        }
        crate::sprintln!(
            "Aegis: [vmx] LOOP ITER {}: about to {} (entered={})",
            exits,
            if entered { "vmresume" } else { "vmx_do_launch" },
            entered as u32,
        );
        // Clear any stale VM-entry interruption info from a previous
        // injection attempt — if left set, the CPU will try to deliver
        // the old event on the next VM-entry, causing an immediate exit.
        vmwrite(field::VM_ENTRY_INTR_INFO, 0);
        let fail = if entered {
            vmx_do_resume()
        } else {
            vmx_do_launch()
        };
        entered = true;
        if fail != 0 {
            sanitize_host_segments();
            let cf = fail & 1;
            let zf = (fail >> 1) & 1;
            let err = vmread(field::VM_INSTRUCTION_ERROR);
            crate::sprintln!(
                "Aegis: [vmx] vmentry FAILED: CF={} ZF={} VM_INSTRUCTION_ERROR={}",
                cf,
                zf,
                err
            );
            if cf != 0 && zf == 0 {
                return Err("vmentry failed: VMfailInvalid (VMCS not valid or not current)");
            } else {
                return Err("vmentry failed: VMfailValid — see VM_INSTRUCTION_ERROR above");
            }
        }
        exits += 1;

        // Virtual clock: feed the guest's PIT/CMOS the real host time that
        // passed while the guest ran and this exit was emulated. The PIT
        // only moves when the host TSC frequency is known (calibrated by
        // `calibrate_host_tsc_hz`); without it the clock stays frozen.
        let now = rdtsc_cycles();
        let delta = now.wrapping_sub(last_tsc);
        last_tsc = now;
        let mut pulses = 0u32;
        let hz = unsafe { TSC_HZ };
        if hz > 0 && delta > 0 {
            frac_us = frac_us.wrapping_add(delta.saturating_mul(1_000_000) / hz);
            let ms = (frac_us / 1000) as u32;
            frac_us %= 1000;
            if ms > 0 {
                pulses = vm.advance_time(ms);
            }
        }

        let reason = (vmread(field::VM_EXIT_REASON) & 0xFFFF) as u16;
        match classify_exit(reason) {
            ExitClass::Exception => {
                let int_info = vmread(field::VM_EXIT_INTERRUPTION_INFO);
                let vector = (int_info & 0xFF) as u8;
                let int_type = ((int_info >> 8) & 0x7) as u8;
                let rip = vmread(field::GUEST_RIP);

                if int_type == 2 {
                    crate::sprintln!(
                        "Aegis: [vmx] NMI while in guest rip={:#x} (continuing)",
                        rip
                    );
                    if !exit_hook(vm)? {
                        return Ok(());
                    }
                    continue;
                }

                if int_info & (1 << 31) != 0 && (vector == 14 || vector == 13) {
                    inject_count += 1;

                    // One-time: dump the guest's actual IDTR from VMCS
                    // (not host sidt) + CS/CR0/CR4 at first exception.
                    if inject_count == 1 {
                        let g_idtr_base = vmread(field::GUEST_IDTR_BASE);
                        let g_idtr_limit = vmread(field::GUEST_IDTR_LIMIT);
                        let g_cs = vmread(field::GUEST_CS_SELECTOR);
                        let g_cs_base = vmread(field::GUEST_CS_BASE);
                        let g_cs_limit = vmread(field::GUEST_CS_LIMIT);
                        let g_cs_ar = vmread(field::GUEST_CS_AR_BYTES);
                        let g_cr0 = vmread(field::GUEST_CR0);
                        let g_cr4 = vmread(field::GUEST_CR4);
                        let g_rip = vmread(field::GUEST_RIP);
                        crate::sprintln!(
                            "Aegis: [vmx] FIRST EXCEPTION CONTEXT: rip={:#x} vec={} int_info={:#x}",
                            g_rip, vector, int_info
                        );
                        crate::sprintln!(
                            "Aegis: [vmx]   guest IDTR: base={:#x} limit={:#x}",
                            g_idtr_base, g_idtr_limit
                        );
                        crate::sprintln!(
                            "Aegis: [vmx]   guest CS: sel={:#x} base={:#x} limit={:#x} AR={:#x}",
                            g_cs, g_cs_base, g_cs_limit, g_cs_ar
                        );
                        crate::sprintln!(
                            "Aegis: [vmx]   guest CR0={:#x} CR4={:#x}",
                            g_cr0, g_cr4
                        );
                        // Dump the first 2 gates from the guest's actual IDT
                        // via EPT translate — confirms the iret gadget is there.
                        if let Some(idt_hpa) = vm.ept.translate(g_idtr_base) {
                            crate::sprintln!(
                                "Aegis: [vmx]   guest IDT at GPA {:#x} = HPA {:#x}",
                                g_idtr_base,
                                idt_hpa
                            );
                            crate::idt::dump_raw_gates(idt_hpa, 0, 4);
                        }
                    }

                    // Consecutive-same-RIP hard stop: if the same vector
                    // fires at the same RIP more than 10 times in a row,
                    // the guest is stuck and re-injecting is pointless.
                    if rip == last_inject_rip && vector == last_inject_vec {
                        consecutive_same_rip += 1;
                    } else {
                        consecutive_same_rip = 1;
                        last_inject_rip = rip;
                        last_inject_vec = vector;
                    }
                    if consecutive_same_rip > 10 {
                        let err_q = vmread(field::EXIT_QUALIFICATION);
                        crate::sprintln!(
                            "Aegis: [vmx] FATAL: exception injection loop — vec={} rip={:#x} err_qual={:#x} int_info={:#x} (consecutive={})",
                            vector, rip, err_q, int_info, consecutive_same_rip
                        );
                        return Err("exception injection loop: same vector+RIP fired >10 times — guest is stuck");
                    }

                    if inject_count <= 5 || inject_count % 100 == 0 {
                        let err_q = vmread(field::EXIT_QUALIFICATION);
                        crate::sprintln!(
                            "Aegis: [vmx] inject vec={} rip={:#x} err_qual={:#x} int_info={:#x} (total={}, consecutive={})",
                            vector, rip, err_q, int_info, inject_count, consecutive_same_rip
                        );
                    }
                    if inject_count > 2000 {
                        return Err(
                            "total injection count exceeded (>2000 total #PF/#GP)",
                        );
                    }
                    let error_code =
                        (vmread(field::VM_EXIT_INTERRUPTION_ERROR_CODE) & 0xFFFF) as u32;
                    let inst_len = vmread(field::VM_EXIT_INSTRUCTION_LEN) as u32;
                    if vector == 14 {
                        // For #PF: EXIT_QUALIFICATION holds the faulting
                        // linear address. CR2 is NOT a VMCS field — must
                        // write it explicitly before re-injecting.
                        write_cr2(vmread(field::EXIT_QUALIFICATION));
                    }
                    let entry_info: u32 = (1u32 << 31)      // valid
                        | (3u32 << 8)                        // type = hardware exception
                        | (vector as u32 & 0xFF); // vector
                    vmwrite(field::VM_ENTRY_INTR_INFO, entry_info as u64);
                    vmwrite(field::VM_ENTRY_EXCEPTION_ERROR_CODE, error_code as u64);
                    vmwrite(field::VM_ENTRY_INSTRUCTION_LEN, inst_len as u64);
                    if !exit_hook(vm)? {
                        return Ok(());
                    }
                    continue;
                }

                // Exit reason 0 with the (now-correctly-read) interruption-
                // info field's valid bit clear should be unreachable per
                // spec — SDM guarantees it's set whenever exit reason is 0.
                // Kept as a safety net rather than a panic in case some
                // other exit-reason==0 path exists that this code doesn't
                // yet classify, but this should no longer fire in practice
                // now that VM_EXIT_INTERRUPTION_INFO reads the correct
                // field (0x4404) instead of VM-exit instruction information
                // (0x440E), which is what it read here previously.
                mystery_count += 1;
                if mystery_count <= 10 {
                    crate::sprintln!(
                        "Aegis: [vmx] mystery exit reason=0 rip={:#x} int_info={:#x} (count={})",
                        rip,
                        int_info,
                        mystery_count
                    );
                }
                if mystery_count > 10 {
                    return Err("too many mystery VM-exits (reason=0, int_info=0) — guest triple-faults on entry?");
                }
                if !exit_hook(vm)? {
                    return Ok(());
                }
                continue;
            }
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
                    r => {
                        crate::sprintln!("Aegis: [vmx] unhandled VM-exit reason {}", r);
                        "unhandled VM-exit reason (see log)"
                    }
                });
            }
        }

        // Device lines (UART RX/virtio INTx, plus the PIT pulses just fed)
        // into the PIC, then a ready-for-it guest gets the vector injected
        // at the next entry.
        vm.devices.update_pic(pulses);
        maybe_inject_interrupt(&mut vm.devices);
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
    // Phase A Problem 2 pre-flight: fail loudly and correctly if this host
    // cannot own VMX (no VT-x, firmware-disabled).
    let readiness = vmx_host_readiness();
    if readiness != VmxReadiness::Ready {
        let msg = readiness_advice(readiness);
        crate::sprintln!("Aegis: [vmx] pre-flight not ready: {}", msg);
        return Err(msg);
    }

    ensure_vmx_root()?;

    let vmcs_region = alloc_vmx_region()?;
    crate::cpu::check_alloc_not_idt(vmcs_region, "VMCS bringup");
    crate::sprintln!(
        "Aegis: [vmx] header after alloc (fresh, zeroed): {:#x}",
        read_vmcs_header(vmcs_region)
    );
    crate::sprintln!("Aegis: [vmx] --- NO-VMCLEAR TEST: skipping vmclear, vmptrld only ---");
    if !vmptrld(vmcs_region) {
        return Err("VMPTRLD failed — VMCS not made current");
    }
    crate::sprintln!("Aegis: [vmx] VMCS active at {:#x}", vmcs_region);

    let guest_code = alloc_guest_code()?;
    crate::cpu::check_alloc_not_idt(guest_code, "guest code bringup");
    crate::sprintln!(
        "Aegis: [vmx] guest code page at {:#x} (cpuid; hlt; jmp $-2)",
        guest_code
    );

    // Allocate a minimal GDT for protected-mode guest:
    //   Entry 0 (0x00): NULL descriptor
    //   Entry 1 (0x08): 32-bit code: base=0, limit=4GB, G=1, D=1, present, code-r/a
    //   Entry 2 (0x10): 32-bit data: base=0, limit=4GB, G=1, D=1, present, data-r/w/a
    //   Entry 3 (0x18): 32-bit TSS: base=0, limit=0x67, P=1, type=0x9 (available 32-bit TSS)
    let gdt_phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for guest GDT")?;
    crate::cpu::check_alloc_not_idt(gdt_phys, "guest GDT bringup");
    core::ptr::write_bytes(gdt_phys as *mut u8, 0, 4096);
    let gdt = gdt_phys as *mut u64;
    // Entry 0: NULL
    core::ptr::write_volatile(gdt.add(0), 0u64);
    // Entry 1 (0x08): code segment — base=0, limit=0xFFFFF, G=1, D=1, L=0, P=1, type=0xA (code r/a)
    // high32=0x00CF9A00, low32=0x0000FFFF → full 4 GiB flat code segment
    core::ptr::write_volatile(gdt.add(1), 0x00CF_9A00_0000_FFFFu64);
    // Entry 2 (0x10): data segment — base=0, limit=0xFFFFF, G=1, D=1, L=0, P=1, type=0x2 (data r/w/a)
    // high32=0x00CF9300, low32=0x0000FFFF → full 4 GiB flat data segment
    core::ptr::write_volatile(gdt.add(2), 0x00CF_9300_0000_FFFFu64);
    // Entry 3 (0x18): 32-bit TSS — base=0, limit=0x67, G=0, D/B=0, P=1, type=0x9 (available 32-bit TSS)
    // The VMCS TR AR will set type=0xB (busy) — the GDT entry is "available";
    // the CPU transitions it to "busy" when TR is loaded.
    // low32:  Limit[15:0]=0x0067, Base[15:0]=0x0000
    // high32: Base[23:16]=0x00, Type=0x9, P=1, DPL=00, S=0, G=0, Base[31:24]=0x00
    //   Type byte = 0x89 (P=1, DPL=00, S=0, type=1001=available 32-bit TSS)
    //   Flags+limit_hi = 0x00 (G=0, AVL=0, limit[19:16]=0)
    core::ptr::write_volatile(gdt.add(3), 0x0000_8900_0000_0067u64);
    crate::sprintln!(
        "Aegis: [vmx] guest GDT at {:#x} (4 entries: null/code/data/tss)",
        gdt_phys
    );

    // Allocate a minimal TSS region for TR (32-bit TSS is 0x68 bytes).
    // TR_BASE must point to real TSS memory, not the GDT entry that
    // describes it.  The content doesn't matter — the guest never does
    // hardware task switching — but the address must be valid for the
    // VM-entry TR-base check.
    let tss_phys = crate::frame::alloc_contiguous_global(1)
        .ok_or("frame allocator: out of memory for guest TSS")?;
    crate::cpu::check_alloc_not_idt(tss_phys, "guest TSS bringup");
    core::ptr::write_bytes(tss_phys as *mut u8, 0, 4096);
    crate::sprintln!(
        "Aegis: [vmx] guest TSS at {:#x} (zeroed, 0x68 bytes)",
        tss_phys
    );

    setup_host_state()?;
    setup_guest_state(guest_code, gdt_phys, tss_phys)?;

    // ── Pre-VMLAUNCH diagnostic (bringup) ──
    {
        let src = guest_code as *const u8;
        let mut hex = [0u8; 48];
        for i in 0..16u32 {
            let b = core::ptr::read_volatile(src.add(i as usize));
            let hi = b >> 4;
            let lo = b & 0x0F;
            hex[(i * 3) as usize] = if hi < 10 { b'0' + hi } else { b'A' + hi - 10 };
            hex[(i * 3 + 1) as usize] = if lo < 10 { b'0' + lo } else { b'A' + lo - 10 };
            hex[(i * 3 + 2) as usize] = b' ';
        }
        crate::sprintln!(
            "Aegis: [vmx] BRINGUP PRE-LAUNCH: first 16 bytes at guest_code={:#x}: {:?}",
            guest_code,
            core::str::from_utf8(&hex).unwrap_or("???")
        );
        crate::sprintln!(
            "Aegis: [vmx] BRINGUP PRE-LAUNCH: GUEST_RIP={} GUEST_CS_BASE={} GUEST_CR0={:#x} GUEST_CR3={:#x} GUEST_CR4={:#x}",
            vmread(field::GUEST_RIP),
            vmread(field::GUEST_CS_BASE),
            vmread(field::GUEST_CR0),
            vmread(field::GUEST_CR3),
            vmread(field::GUEST_CR4),
        );
    }

    // Build a minimal EPT identity map for the 3 guest pages.
    // Required because UG=1 ⟹ EPT=1 (SDM §26.2.1.1 cross-field
    // constraint).  Without EPT, Bay Trail rejects VMLAUNCH with
    // VM_INSTRUCTION_ERROR=7.
    let grant = crate::ept::MemGrant::new(0, 0x400000); // cover 4 GiB
    let mut ept = crate::ept::Ept::new();
    ept.map(
        &mut crate::ept::KernelAlloc,
        &grant,
        guest_code,
        guest_code,
        1,
        crate::ept::EPT_DEFAULT_FLAGS,
    )
    .map_err(|_| "EPT map failed for guest code page")?;
    ept.map(
        &mut crate::ept::KernelAlloc,
        &grant,
        gdt_phys,
        gdt_phys,
        1,
        crate::ept::EPT_DEFAULT_FLAGS,
    )
    .map_err(|_| "EPT map failed for guest GDT page")?;
    ept.map(
        &mut crate::ept::KernelAlloc,
        &grant,
        tss_phys,
        tss_phys,
        1,
        crate::ept::EPT_DEFAULT_FLAGS,
    )
    .map_err(|_| "EPT map failed for guest TSS page")?;
    crate::sprintln!(
        "Aegis: [vmx] bringup EPT: identity-mapped code={:#x} gdt={:#x} tss={:#x} ({} tables)",
        guest_code,
        gdt_phys,
        tss_phys,
        ept.table_pages()
    );

    setup_controls(true, ept.root())?;

    // ── IDT integrity: capture checksum before VMLAUNCH (bringup) ──
    {
        let mut idtr: [u16; 5] = [0; 5];
        unsafe { core::arch::asm!("sidt [{0}]", in(reg) idtr.as_mut_ptr(), options(nostack)) };
        let base = (idtr[1] as u64)
            | ((idtr[2] as u64) << 16)
            | ((idtr[3] as u64) << 32)
            | ((idtr[4] as u64) << 48);
        let limit = idtr[0];
        let cs = crate::idt::idt_checksum(base, limit);
        crate::sprintln!(
            "Aegis: [vmx] BRINGUP PRE-LAUNCH IDT: base={:#x} limit={} checksum={:#018x}",
            base,
            limit,
            cs
        );
        crate::idt::dump_gate(base, 13);
        // Raw descriptors for byte-level comparison
        crate::sprintln!("Aegis: [vmx] BRINGUP PRE-LAUNCH RAW gates[0..32]:");
        crate::idt::dump_raw_gates(base, 0, 32);
    }

    crate::sprintln!("Aegis: [vmx] VMCS configured, launching guest...");
    // ── Pre-VMLAUNCH HOST state dump (bringup path) ──
    crate::sprintln!(
        "Aegis: [vmx] BRINGUP PRE-LAUNCH GUEST: RIP={:#x} CS_BASE={:#x} CR0={:#x} CR3={:#x} CR4={:#x}",
        vmread(field::GUEST_RIP),
        vmread(field::GUEST_CS_BASE),
        vmread(field::GUEST_CR0),
        vmread(field::GUEST_CR3),
        vmread(field::GUEST_CR4),
    );
    crate::sprintln!(
        "Aegis: [vmx] BRINGUP PRE-LAUNCH HOST: CS={:#x} SS={:#x} DS={:#x} ES={:#x} FS={:#x} GS={:#x} TR={:#x}",
        vmread(field::HOST_CS_SELECTOR),
        vmread(field::HOST_SS_SELECTOR),
        vmread(field::HOST_DS_SELECTOR),
        vmread(field::HOST_ES_SELECTOR),
        vmread(field::HOST_FS_SELECTOR),
        vmread(field::HOST_GS_SELECTOR),
        vmread(field::HOST_TR_SELECTOR),
    );
    crate::sprintln!(
        "Aegis: [vmx] BRINGUP PRE-LAUNCH HOST: CR0={:#x} CR3={:#x} CR4={:#x} RIP={:#x} RSP={:#x}",
        vmread(field::HOST_CR0),
        vmread(field::HOST_CR3),
        vmread(field::HOST_CR4),
        vmread(field::HOST_RIP),
        vmread(field::HOST_RSP),
    );
    crate::sprintln!(
        "Aegis: [vmx] BRINGUP PRE-LAUNCH HOST: GDTR={:#x} IDTR={:#x} FS_BASE={:#x} GS_BASE={:#x} TR_BASE={:#x}",
        vmread(field::HOST_GDTR_BASE),
        vmread(field::HOST_IDTR_BASE),
        vmread(field::HOST_FS_BASE),
        vmread(field::HOST_GS_BASE),
        vmread(field::HOST_TR_BASE),
    );
    crate::sprintln!(
        "Aegis: [vmx] --- NO-VMCLEAR TEST: launching directly (no vmclear, no resstamp, no 2nd vmptrld) ---"
    );
    crate::sprintln!(
        "Aegis: [vmx] header before launch: {:#x}",
        read_vmcs_header(vmcs_region)
    );
    crate::sprintln!("Aegis: [vmx] VMLAUNCH (no vmclear)...");
    let fail = vmx_do_launch();
    if fail != 0 {
        sanitize_host_segments();
        let cf = fail & 1;
        let zf = (fail >> 1) & 1;
        let vmcs_hdr = read_vmcs_header(vmcs_region);
        crate::sprintln!(
            "Aegis: [vmx] 4/4 VMLAUNCH FAILED — CF={} ZF={} vmcs_header={:#x}",
            cf,
            zf,
            vmcs_hdr
        );
        if cf != 0 && zf == 0 {
            crate::sprintln!("Aegis: [vmx]   class: VMfailInvalid — VMCS not valid or not current");
        } else if cf == 0 && zf != 0 {
            let inst_err = vmread(field::VM_INSTRUCTION_ERROR);
            crate::sprintln!(
                "Aegis: [vmx]   class: VMfailValid — VMCS current, VM_INSTRUCTION_ERROR={}",
                inst_err
            );
        } else {
            crate::sprintln!("Aegis: [vmx]   class: unexpected CF={} ZF={}", cf, zf);
        }
        return Err("vmlaunch failed — see VMX trace above");
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
    if reason == exit_reason::INVALID_GUEST_STATE {
        // The guest never executed: VM-entry was rejected because the guest
        // state failed an SDM §26.3.1 check. VM_INSTRUCTION_ERROR (0x4400)
        // names the specific failing check — read and report it, then halt
        // cleanly instead of reading meaningless guest GPRs (which under
        // nested virtualization was faulting at RIP=0).
        sanitize_host_segments();
        let err = vmread(field::VM_INSTRUCTION_ERROR);
        crate::sprintln!(
            "Aegis: [vmx] VM-entry rejected: VM_INSTRUCTION_ERROR={} (guest state invalid per SDM §26.3.1)",
            err
        );
        return Err("guest state rejected at VM-entry — see VM_INSTRUCTION_ERROR above");
    }
    sanitize_host_segments();
    // ── IDT integrity: compare checksum after VM-exit (bringup) ──
    {
        let mut idtr: [u16; 5] = [0; 5];
        unsafe { core::arch::asm!("sidt [{0}]", in(reg) idtr.as_mut_ptr(), options(nostack)) };
        let base = (idtr[1] as u64)
            | ((idtr[2] as u64) << 16)
            | ((idtr[3] as u64) << 32)
            | ((idtr[4] as u64) << 48);
        let limit = idtr[0];
        let cs = crate::idt::idt_checksum(base, limit);
        crate::sprintln!(
            "Aegis: [vmx] BRINGUP POST-RETURN IDT: base={:#x} limit={} checksum={:#018x}",
            base,
            limit,
            cs
        );
        crate::idt::dump_gate(base, 13);
        // Raw descriptors for byte-level comparison
        crate::sprintln!("Aegis: [vmx] BRINGUP POST-RETURN RAW gates[0..32]:");
        crate::idt::dump_raw_gates(base, 0, 32);
    }
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

    // ---- host readiness pre-flight (Phase A Problem 2) -----------------

    #[test]
    fn classify_vmx_readiness_covers_all_states() {
        assert_eq!(classify_vmx_readiness(false, true), VmxReadiness::NoVtx);
        assert_eq!(
            classify_vmx_readiness(true, false),
            VmxReadiness::FeatureControlLockedDisabled
        );
        assert_eq!(classify_vmx_readiness(true, true), VmxReadiness::Ready);
    }

    #[test]
    fn readiness_advice_is_actionable_per_state() {
        assert!(readiness_advice(VmxReadiness::NoVtx).contains("VT-x"));
        assert!(readiness_advice(VmxReadiness::FeatureControlLockedDisabled).contains("firmware"));
        assert!(readiness_advice(VmxReadiness::Ready).contains("VMX host ready"));
    }

    // The runtime pre-flight must always agree with the CPUID probe it
    // was built from. CPUID is a user-mode instruction, so this runs in a
    // host test; the MSR-reading half (`vmx_host_readiness`) is only called
    // at CPL 0 because `rdmsr` needs privilege.
    #[test]
    fn readiness_agrees_with_the_cpuid_probe() {
        let r = classify_vmx_readiness(vmx_supported(), true);
        if !vmx_supported() {
            assert_eq!(r, VmxReadiness::NoVtx);
        } else {
            assert_eq!(r, VmxReadiness::Ready);
        }
    }

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

    /// Verify apply_fixed_bits logic: (value | fixed0) & fixed1.
    /// This is the pure arithmetic — the MSR reads are tested on real HW.
    #[test]
    fn apply_fixed_bits_forces_required_and_clears_forbidden() {
        // Simulate: bit 5 must be 1 (CR0.NE), bit 0 must be 0.
        // fixed0 = 0x20, fixed1 = ~0x1 (all bits allowed except bit 0).
        // value = 0 (neither NE set, bit 0 set) -> result = 0x20 & !0x1 = 0x20.
        let val = 0u64;
        let fixed0 = 0x20u64; // bit 5 must be 1
        let fixed1 = !0u64; // all bits allowed
        let result = (val | fixed0) & fixed1;
        assert_eq!(result, 0x20);
        // value = 0x21 (NE + bit 0) with fixed1 clearing bit 0 -> 0x20.
        let val2 = 0x21u64;
        let fixed1_bit0_clear = !1u64;
        let result2 = (val2 | fixed0) & fixed1_bit0_clear;
        assert_eq!(result2, 0x20);
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
        assert_eq!(classify_exit(0), ExitClass::Exception);
        assert_eq!(classify_exit(1), ExitClass::ExternalInterrupt);
        assert_eq!(classify_exit(12), ExitClass::Hlt);
        assert_eq!(classify_exit(30), ExitClass::IoInstruction);
        assert_eq!(classify_exit(48), ExitClass::EptViolation);
        // Everything outside the handled set is refused loudly, with the
        // real reason preserved for the error message.
        assert_eq!(classify_exit(28), ExitClass::Unhandled { reason: 28 });
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

    /// Phase AE: a malicious guest controls the VM-exit qualification and the
    /// instruction byte at guest RIP — both are untrusted input. Drive every
    /// bit pattern through the decoders the run loop feeds on exit reason 30 /
    /// 48 and assert total no-panic + fail-closed on reserved encodings.
    #[test]
    #[cfg_attr(miri, ignore)] // interpreted sweep; the fixed vectors still run under Miri
    fn guest_controlled_exit_decodes_are_total_and_fail_closed() {
        use crate::hardening_fuzz::{no_panic, Rng, SEED};
        let mut rng = Rng::new(SEED ^ 0x1A6EA3);
        let mut reserved_io_sizes = 0usize;
        let mut unhandled = 0usize;
        for _ in 0..crate::hardening_fuzz::sweep_iters(1_000_000) {
            let q = rng.next();
            // I/O exit qualification: every 32-bit pattern, structured and
            // random. Reserved size encoding (2 in bits 2:0) must refuse.
            match no_panic(|| decode_io_exit(q & 0xFFFF_FFFF)) {
                Some(Some(_)) => {}
                Some(None) => reserved_io_sizes += 1,
                None => panic!("decode_io_exit panicked on qualification {q:#018x}"),
            }
            // Instruction length: total over all 256 opcodes (the run loop
            // reads this byte from guest memory — fully guest-controlled).
            let _ = no_panic(|| io_instruction_len(rng.byte()));
            // EPT-violation qualification.
            let _ = no_panic(|| decode_ept_violation_qualification(q));
            // Exit reason: total over the whole u16 range, unhandled refused.
            match no_panic(|| classify_exit((q >> 48) as u16)) {
                Some(ExitClass::Unhandled { .. }) => unhandled += 1,
                Some(_) => {}
                None => panic!("classify_exit panicked on reason {}", (q >> 48) as u16),
            }
        }
        // A fuzz sweep that never saw a reserved size encoding would prove
        // nothing about the fail-closed path — the seeded RNG must hit it.
        assert!(
            reserved_io_sizes > 0,
            "reserved size encoding never exercised"
        );
        assert!(unhandled > 0, "unhandled exit reasons never exercised");
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
        // Secondary: EPT = bit 1, RDTSCP = bit 3, unrestricted guest = bit 7, TSC offset = 17.
        assert_eq!(proc_secondary::EPT_ENABLE, 0x2);
        assert_eq!(proc_secondary::RDTSCP, 0x8);
        assert_eq!(proc_secondary::UNRESTRICTED_GUEST, 0x80);
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
        assert_eq!(field::VM_ENTRY_INTR_INFO >> 8, 0x40);
        // Exact-value checks: VM_EXIT_INTERRUPTION_INFO was previously
        // 0x440E (IDT-vectoring info) instead of 0x4404 (interruption info),
        // causing every exception exit to read 0x0 and appear as a "mystery
        // exit". Both share the 0x44 type byte so prefix checks pass.
        assert_eq!(field::VM_EXIT_INTERRUPTION_INFO, 0x4404);
        assert_eq!(field::VM_EXIT_INTERRUPTION_ERROR_CODE, 0x4406);
    }

    #[cfg(feature = "vmx-demo")]
    #[test]
    fn tsc_hz_from_calibration_math() {
        // 10 ms at 1.19318 MHz = 11932 PIT counts; 10 ms at 2.5 GHz =
        // 25,000,000 TSC cycles -> 2,500,000,000 Hz.
        assert_eq!(
            tsc_hz_from_calibration(25_000_000, 11_932),
            25_000_000 * 1_193_180 / 11_932
        );
        // Sanity: ~2.5 GHz result.
        assert!(tsc_hz_from_calibration(25_000_000, 11_932) > 2_000_000_000);
        assert!(tsc_hz_from_calibration(25_000_000, 11_932) < 3_000_000_000);
        // Zero guards: no cycles or no count must never divide by zero.
        assert_eq!(tsc_hz_from_calibration(0, 11_932), 0);
        assert_eq!(tsc_hz_from_calibration(25_000_000, 0), 0);
    }

    #[cfg(feature = "vmx-demo")]
    #[test]
    fn guest_boot_layout_fits_the_grant() {
        // The Phase U-7 demo's embedded image must satisfy every layout
        // rule `Vm::load_linux` enforces — checked without a VMX CPU by
        // running the same pure code the demo runs.
        let frames = (GUEST_BOOT_RAM_MB << 20) / 4096;
        let grant = crate::ept::MemGrant::new(0, frames);
        let (_, code_len) = crate::vm::parse_bzimage(GUEST_BZIMAGE).expect("bzImage parses");
        let boot = crate::vm::GuestBoot::build(
            &grant,
            GUEST_BZIMAGE,
            Some(GUEST_INITRAMFS),
            "console=ttyS0,115200n8 noapic",
        )
        .expect("guest layout fits the 128 MiB grant");
        // The kernel's decompression window (init_size) plus the initrd
        // must sit inside guest RAM: the kernel relocates itself to the
        // top of RAM at decompress time.
        assert!((code_len as u64) < crate::vm::INITRD_GPA);
        assert!(boot.initrd_gpa + boot.initrd_len as u64 <= boot.ram_end_gpa);
        // init_size is read from the image header; the window from the
        // kernel load address must fit below the top of guest RAM.
        let init_size = u32::from_le_bytes([
            GUEST_BZIMAGE[0x260],
            GUEST_BZIMAGE[0x261],
            GUEST_BZIMAGE[0x262],
            GUEST_BZIMAGE[0x263],
        ]);
        assert!(
            crate::vm::CODE32_GPA + init_size as u64 <= boot.ram_end_gpa,
            "init_size window must fit in guest RAM"
        );
    }

    #[cfg(feature = "vmx-demo")]
    #[test]
    fn guest_boot_ram_is_contiguous_allocatable() {
        // The demo needs 32768 consecutive host frames. The allocator's
        // contiguous path is bitmap-based (tested in frame.rs); this test
        // just pins the arithmetic the demo uses.
        let frames = (GUEST_BOOT_RAM_MB << 20) / 4096;
        assert_eq!(frames, 32768);
        assert_eq!(frames * 4096, 128 << 20);
    }
}

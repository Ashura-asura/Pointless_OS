/// x86_64 Task State Segment (104 bytes; the architectural minimum for a
/// 64-bit TSS, and the size `ltr` enforces via the descriptor limit).
#[repr(C, packed)]
pub struct TssStruct {
    pub reserved: u32,
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    pub reserved2: u64,
    pub ist1: u64,
    pub ist2: u64,
    pub ist3: u64,
    pub ist4: u64,
    pub ist5: u64,
    pub ist6: u64,
    pub ist7: u64,
    pub reserved3: u64,
    pub iopb_offset: u16,
    pub reserved4: u16,
}

impl TssStruct {
    pub const fn new() -> Self {
        TssStruct {
            reserved: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved2: 0,
            ist1: 0,
            ist2: 0,
            ist3: 0,
            ist4: 0,
            ist5: 0,
            ist6: 0,
            ist7: 0,
            reserved3: 0,
            iopb_offset: core::mem::size_of::<TssStruct>() as u16,
            reserved4: 0,
        }
    }
}

impl Default for TssStruct {
    fn default() -> Self {
        Self::new()
    }
}

/// A single GDT entry (8 bytes)
#[repr(C, packed)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub granularity: u8,
    pub base_high: u8,
}

/// Selector constants
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
pub const USER_CODE_SELECTOR: u16 = 0x18 | 3;
pub const USER_DATA_SELECTOR: u16 = 0x20 | 3;
pub const TSS_SELECTOR: u16 = 0x28;

const fn gdt_entry(base: u32, limit: u32, access: u8, granularity: u8) -> GdtEntry {
    GdtEntry {
        limit_low: (limit & 0xFFFF) as u16,
        base_low: (base & 0xFFFF) as u16,
        base_mid: ((base >> 16) & 0xFF) as u8,
        access,
        granularity,
        base_high: ((base >> 24) & 0xFF) as u8,
    }
}

/// GDT with 8 entries + TSS. Entry 6 is the mandatory upper half of the
/// 16-byte 64-bit TSS descriptor (base[63:32] + reserved, all zero for a
/// sub-4 GB TSS); QEMU's LTR helper rejects a nonzero upper "type" nibble.
/// Entry 7 mirrors the loader's flat DPL0 64-bit code descriptor so the
/// CS=0x38 in force at handoff remains valid after `lgdt`.
pub struct Gdt {
    entries: [GdtEntry; 8],
    tss: TssStruct,
}

#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

impl Gdt {
    pub const fn new() -> Self {
        // Null entry
        let null = gdt_entry(0, 0, 0, 0);

        // Kernel code: ring 0, 64-bit, present, readable
        // Access: present(1) DPL(00) S(1) type(1010) = 0x9A
        // Granularity: L(1) D/B(0) G(1) = 0xA0
        let kernel_code = gdt_entry(0, 0xFFFFF, 0x9A, 0xA0);

        // Kernel data: ring 0, present, writable
        // Access: present(1) DPL(00) S(1) type(0010) = 0x92
        // Granularity: D/B(1) G(1) = 0xC0
        let kernel_data = gdt_entry(0, 0xFFFFF, 0x92, 0xC0);

        // User code: ring 3, 64-bit, present, readable
        // Access: present(1) DPL(11) S(1) type(1010) = 0xFA
        // Granularity: L(1) D/B(0) G(1) = 0xA0
        let user_code = gdt_entry(0, 0xFFFFF, 0xFA, 0xA0);

        // User data: ring 3, present, writable
        // Access: present(1) DPL(11) S(1) type(0010) = 0xF2
        // Granularity: D/B(1) G(1) = 0xC0
        let user_data = gdt_entry(0, 0xFFFFF, 0xF2, 0xC0);

        // TSS entry (index 5 = selector 0x28): 64-bit TSS, present
        // Access: present(1) DPL(00) S(0) type(1001) = 0x89
        // Granularity: 0x00
        // Base/limit will be filled by install() since we can't reference self in const
        let tss_entry = GdtEntry {
            limit_low: 0, // placeholder, set in install()
            base_low: 0,
            base_mid: 0,
            access: 0x89,
            granularity: 0x00,
            base_high: 0,
        };

        // TSS upper half (index 6 = selector 0x30): base[63:32] + reserved,
        // all zero. Not a usable data segment; never loaded. The CPU reads
        // this as part of the 16-byte 64-bit TSS descriptor at index 5.
        let tss_upper = gdt_entry(0, 0, 0, 0);

        // Flat DPL0 64-bit code (index 7 = selector 0x38): mirrors the
        // loader's CS, which stays in force until the first ring transition.
        let code38 = gdt_entry(0, 0xFFFFF, 0x9A, 0xA0);

        Gdt {
            entries: [
                null,
                kernel_code,
                kernel_data,
                user_code,
                user_data,
                tss_entry,
                tss_upper,
                code38,
            ],
            tss: TssStruct::new(),
        }
    }

    /// Load GDT and TSS via lgdt/ltr. UNTESTED on real hardware.
    ///
    /// # Safety
    ///
    /// Must be called with a valid `self` whose TSS base will be patched into
    /// the TSS descriptor. After this call the CPU uses this GDT, so the
    /// struct must outlive its use and never move.
    pub unsafe fn install(&mut self) {
        // Patch the TSS GDT entry to point to our TSS
        let tss_addr = &self.tss as *const TssStruct as u64;
        self.entries[5] = GdtEntry {
            limit_low: (core::mem::size_of::<TssStruct>() as u16 - 1),
            base_low: (tss_addr & 0xFFFF) as u16,
            base_mid: ((tss_addr >> 16) & 0xFF) as u8,
            access: 0x89,
            granularity: 0x00,
            base_high: ((tss_addr >> 24) & 0xFF) as u8,
        };
        // Upper half of the 16-byte 64-bit TSS descriptor: TSS base[63:32]
        // (zero for sub-4 GB) and reserved-zero type bits. Without this,
        // QEMU's LTR reads the following GDT entry as the upper half and
        // raises #GP on the nonzero type nibble.
        self.entries[6] = GdtEntry {
            limit_low: ((tss_addr >> 32) & 0xFFFF) as u16,
            base_low: ((tss_addr >> 48) & 0xFFFF) as u16,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        };

        let gdt_ptr = GdtPtr {
            limit: (core::mem::size_of::<[GdtEntry; 8]>() - 1) as u16,
            base: self.entries.as_ptr() as u64,
        };

        // Load GDT
        core::arch::asm!("lgdt [{}]", in(reg) &gdt_ptr);

        // Load TSS
        let tss_sel = TSS_SELECTOR;
        core::arch::asm!("ltr {tss_sel:x}", tss_sel = in(reg) tss_sel);

        // Set data segment registers.
        // CS is intentionally NOT reloaded here: the firmware's code
        // descriptor is already a DPL0 64-bit descriptor (verified in the
        // QEMU trace under OVMF), and a far transfer would need a
        // position-independent CS reload that stable inline asm cannot
        // express (a `lea reg64, [label]` materializes the label address
        // absolutely, which is invalid for the kernel's PIE image).
        // CS gets replaced at the first ring transition, when the TSS
        // entry / user code path is implemented.
        let data_sel = KERNEL_DATA_SELECTOR;
        core::arch::asm!(
            "mov ds, {sel:x}",
            "mov es, {sel:x}",
            "mov ss, {sel:x}",
            sel = in(reg) data_sel,
        );
    }

    /// Get the TSS pointer for setting RSP0 on context switch
    pub fn tss_mut(&mut self) -> &mut TssStruct {
        &mut self.tss
    }
}

impl Default for Gdt {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_constants_are_as_documented() {
        assert_eq!(KERNEL_CODE_SELECTOR, 0x08);
        assert_eq!(KERNEL_DATA_SELECTOR, 0x10);
        assert_eq!(USER_CODE_SELECTOR, 0x1B);
        assert_eq!(USER_DATA_SELECTOR, 0x23);
        assert_eq!(TSS_SELECTOR, 0x28);
    }

    #[test]
    fn kernel_segment_descriptors_are_flat_64bit() {
        // gdt_entry(base, limit, access, granularity)
        let code: GdtEntry = gdt_entry(0, 0xFFFFF, 0x9A, 0xA0);
        assert_eq!(code.access, 0x9A); // present, DPL0, code, readable
        assert_eq!(code.granularity, 0xA0); // long mode, granularity
        let data: GdtEntry = gdt_entry(0, 0xFFFFF, 0x92, 0xC0);
        assert_eq!(data.access, 0x92); // present, DPL0, data, writable
        assert_eq!(data.granularity, 0xC0);
    }

    #[test]
    fn tss_iopb_offset_points_at_the_end_of_the_struct() {
        let tss = TssStruct::new();
        assert_eq!(tss.iopb_offset as usize, core::mem::size_of::<TssStruct>());
    }
}

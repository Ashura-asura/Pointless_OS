/// x86_64 Task State Segment (104 bytes)
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
        }
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

/// GDT with 6 entries + TSS
pub struct Gdt {
    entries: [GdtEntry; 6],
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
            limit_low: 0,   // placeholder, set in install()
            base_low: 0,
            base_mid: 0,
            access: 0x89,
            granularity: 0x00,
            base_high: 0,
        };

        Gdt {
            entries: [null, kernel_code, kernel_data, user_code, user_data, tss_entry],
            tss: TssStruct::new(),
        }
    }

    /// Load GDT and TSS via lgdt/ltr. UNTESTED on real hardware.
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

        let gdt_ptr = GdtPtr {
            limit: (core::mem::size_of::<[GdtEntry; 6]>() - 1) as u16,
            base: self.entries.as_ptr() as u64,
        };

        // Load GDT
        core::arch::asm!("lgdt [{}]", in(reg) &gdt_ptr);

        // Reload CS via far return
        let code_sel = KERNEL_CODE_SELECTOR as u64;
        core::arch::asm!(
            "push {code_sel}",
            "lea {tmp}, [2f]",
            "push {tmp}",
            "retfq",
            "2:",
            code_sel = in(reg) code_sel,
            tmp = out(reg) _,
        );

        // Load TSS
        let tss_sel = TSS_SELECTOR;
        core::arch::asm!("ltr {tss_sel:x}", tss_sel = in(reg) tss_sel);

        // Set data segment registers
        let data_sel = KERNEL_DATA_SELECTOR;
        core::arch::asm!(
            "mov ds, {data_sel:x}",
            "mov es, {data_sel:x}",
            "mov ss, {data_sel:x}",
            data_sel = in(reg) data_sel,
        );
    }

    /// Get the TSS pointer for setting RSP0 on context switch
    pub fn tss_mut(&mut self) -> &mut TssStruct {
        &mut self.tss
    }
}

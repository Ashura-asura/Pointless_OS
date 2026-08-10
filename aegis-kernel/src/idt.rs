/// A single IDT entry (16 bytes)
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct IdtEntry {
    pub offset_low: u16,
    pub selector: u16,
    pub ist: u8,
    pub type_attr: u8,
    pub offset_mid: u16,
    pub offset_high: u32,
    pub reserved: u32,
}

impl IdtEntry {
    pub const fn new() -> Self {
        IdtEntry {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }
}

#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

pub struct Idt {
    entries: [IdtEntry; 256],
}

const fn idt_entry(handler_addr: u64, selector: u16, ist: u8, type_attr: u8) -> IdtEntry {
    IdtEntry {
        offset_low: (handler_addr & 0xFFFF) as u16,
        selector,
        ist,
        type_attr,
        offset_mid: ((handler_addr >> 16) & 0xFFFF) as u16,
        offset_high: ((handler_addr >> 32) as u32),
        reserved: 0,
    }
}

impl Idt {
    pub const fn new() -> Self {
        Idt {
            entries: [IdtEntry::new(); 256],
        }
    }

    /// Set a handler for a given vector.
    /// handler_addr is the address of the handler function.
    /// dpl is the privilege level required to call this interrupt (0 = kernel only).
    pub fn set_handler(&mut self, vector: usize, handler_addr: u64, selector: u16, dpl: u8) {
        // Type attr: present(1) DPL(dpl) storage_seg(0) gate_type(1110) = present | (dpl << 5) | 0x0E
        let type_attr = 0x80 | ((dpl & 3) << 5) | 0x0E;
        self.entries[vector] = idt_entry(handler_addr, selector, 0, type_attr);
    }

    /// Load IDT via lidt. UNTESTED on real hardware.
    pub unsafe fn install(&self) {
        let idt_ptr = IdtPtr {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: self.entries.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{}]", in(reg) &idt_ptr);
    }
}

// Exception handler stubs for vectors 0-31
// Each just halts — real interrupt handling is Phase 2+ scope.

macro_rules! exception_handler_stub {
    ($name:ident) => {
        #[no_mangle]
        pub extern "sysv64" fn $name() -> ! {
            loop {
                unsafe { core::arch::asm!("hlt") }
            }
        }
    };
}

exception_handler_stub!(handler_divide_error);
exception_handler_stub!(handler_debug);
exception_handler_stub!(handler_nmi);
exception_handler_stub!(handler_breakpoint);
exception_handler_stub!(handler_overflow);
exception_handler_stub!(handler_bound_range);
exception_handler_stub!(handler_invalid_opcode);
exception_handler_stub!(handler_device_not_available);
exception_handler_stub!(handler_double_fault);
exception_handler_stub!(handler_coprocessor_segment);
exception_handler_stub!(handler_invalid_tss);
exception_handler_stub!(handler_segment_not_present);
exception_handler_stub!(handler_stack_fault);
exception_handler_stub!(handler_general_protection);
exception_handler_stub!(handler_page_fault);
exception_handler_stub!(handler_x87_fpu);
exception_handler_stub!(handler_alignment_check);
exception_handler_stub!(handler_machine_check);
exception_handler_stub!(handler_simd_exception);

/// Install all exception handler stubs into the IDT.
pub fn install_exception_handlers(idt: &mut Idt) {
    let selector: u16 = 0x08; // kernel code selector

    idt.set_handler(0, handler_divide_error as *const () as u64, selector, 0);
    idt.set_handler(1, handler_debug as *const () as u64, selector, 0);
    idt.set_handler(2, handler_nmi as *const () as u64, selector, 0);
    idt.set_handler(3, handler_breakpoint as *const () as u64, selector, 3);
    idt.set_handler(4, handler_overflow as *const () as u64, selector, 3);
    idt.set_handler(5, handler_bound_range as *const () as u64, selector, 0);
    idt.set_handler(6, handler_invalid_opcode as *const () as u64, selector, 0);
    idt.set_handler(7, handler_device_not_available as *const () as u64, selector, 0);
    idt.set_handler(8, handler_double_fault as *const () as u64, selector, 0);
    idt.set_handler(9, handler_coprocessor_segment as *const () as u64, selector, 0);
    idt.set_handler(10, handler_invalid_tss as *const () as u64, selector, 0);
    idt.set_handler(11, handler_segment_not_present as *const () as u64, selector, 0);
    idt.set_handler(12, handler_stack_fault as *const () as u64, selector, 0);
    idt.set_handler(13, handler_general_protection as *const () as u64, selector, 0);
    idt.set_handler(14, handler_page_fault as *const () as u64, selector, 0);
    idt.set_handler(15, handler_x87_fpu as *const () as u64, selector, 0);
    idt.set_handler(16, handler_alignment_check as *const () as u64, selector, 0);
    idt.set_handler(17, handler_machine_check as *const () as u64, selector, 0);
    idt.set_handler(18, handler_simd_exception as *const () as u64, selector, 0);
}

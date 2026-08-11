use core::arch::naked_asm;

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

impl Default for IdtEntry {
    fn default() -> Self {
        Self::new()
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

    /// Set a DPL-0 interrupt-gate handler for a hardware IRQ (type attr 0x8E:
    /// interrupts are cleared while the handler runs by the CPU).
    pub fn set_irq_handler(&mut self, vector: usize, handler_addr: u64) {
        let type_attr = 0x80 | 0x0E; // present(1) DPL(00) storage_seg(0) gate_type(1110)
        self.entries[vector] =
            idt_entry(handler_addr, crate::gdt::KERNEL_CODE_SELECTOR, 0, type_attr);
    }

    /// Load IDT via lidt. UNTESTED on real hardware.
    ///
    /// # Safety
    ///
    /// All handlers referenced by the entries must be valid, present code.
    /// This struct must remain alive and unmoved while the IDT is loaded.
    pub unsafe fn install(&self) {
        let idt_ptr = IdtPtr {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: self.entries.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{}]", in(reg) &idt_ptr);
    }
}

impl Default for Idt {
    fn default() -> Self {
        Self::new()
    }
}

// Exception handler stubs for vectors 0-31. Each is a naked x86-64 stub
// that saves the general-purpose registers, records the error-code slot,
// and hands the frame to `cpu::exception_trap_rust`, which prints the
// fault (vector, error code, RIP, RSP, CR2) over serial and halts.
//
// Stack discipline (SysV ABI, interrupt entry): the CPU sets RSP to
// (old & ~15) - 8 then pushes 3 or 4 words (RIP/CS/RFLAGS and, for
// vectors with error codes, the error word). Entry RSP is therefore
// 16-aligned for the 18 non-error vectors and 8 modulo 16 for the
// 7 error-code vectors. The stubs always push the error slot + 9
// registers (80 bytes), so non-error vectors are already aligned for the
// `call`; error-code vectors get an extra `sub rsp, 8`. Because the trap
// side never returns, the 8 bytes are never popped.
//
// The frame seen by `exception_trap_rust` (base = RSP after the pushes):
//   [0]  error-code slot (architectural error code, or 0)
//   [1..10]  rax rbx rcx rdx rsi rdi r8 r9 r10 r11
//   [10]  architectural error code  (error-code vectors only)
//   [10 or 11]  interrupted RIP
//   [11 or 12]  interrupted CS
//   [12 or 13]  RFLAGS
//   [13 or 14]  interrupted RSP
//   [14 or 15]  SS

/// Vectors that push an architectural error code on entry.
pub const ERR_CODE_VECTORS: [u8; 7] = [8, 10, 11, 12, 13, 14, 17];

macro_rules! exception_handler_stub {
    ($name:ident, $vector:literal, $err:literal) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub extern "sysv64" fn $name() -> ! {
            naked_asm!(
                "push 0",
                "push rax", "push rbx", "push rcx", "push rdx",
                "push rsi", "push rdi", "push r8", "push r9",
                "push r10", "push r11",
                "sub rsp, 8",
                "mov rdi, {vector}",
                "mov esi, {has_err}",
                "mov rdx, rsp",
                "call {trap}",
                vector = const $vector,
                has_err = const $err,
                trap = sym crate::cpu::exception_trap_rust,
            )
        }
    };
}

// Vector 14 (page fault) with a resume tail: when a RING-3 task faults
// (isolation/NX demo), `exception_trap_rust` kills the task and returns;
// the tail then switches the scheduler to the next context (same primitive
// the timer stub uses — the saved dead task's frame is never resumed). If
// a KERNEL fault occurs, `exception_trap_rust` never returns (it halts).
macro_rules! exception_handler_stub_page_fault {
    () => {
        #[unsafe(naked)]
        #[no_mangle]
        pub extern "sysv64" fn handler_page_fault() -> ! {
            naked_asm!(
                "push 0",
                "push rax", "push rbx", "push rcx", "push rdx",
                "push rsi", "push rdi", "push r8", "push r9",
                "push r10", "push r11",
                "sub rsp, 8",
                "mov rdi, 14",
                "mov esi, 1",
                "mov rdx, rsp",
                "call {trap}",
                "call {preempt}",
                trap = sym crate::cpu::exception_trap_rust,
                preempt = sym crate::tasks::timer_preempt,
            )
        }
    };
}

exception_handler_stub!(handler_divide_error, 0, 0);
exception_handler_stub!(handler_debug, 1, 0);
exception_handler_stub!(handler_nmi, 2, 0);
exception_handler_stub!(handler_breakpoint, 3, 0);
exception_handler_stub!(handler_overflow, 4, 0);
exception_handler_stub!(handler_bound_range, 5, 0);
exception_handler_stub!(handler_invalid_opcode, 6, 0);
exception_handler_stub!(handler_device_not_available, 7, 0);
exception_handler_stub!(handler_double_fault, 8, 1);
exception_handler_stub!(handler_coprocessor_segment, 9, 0);
exception_handler_stub!(handler_invalid_tss, 10, 1);
exception_handler_stub!(handler_segment_not_present, 11, 1);
exception_handler_stub!(handler_stack_fault, 12, 1);
exception_handler_stub!(handler_general_protection, 13, 1);
exception_handler_stub_page_fault!(); // vector 14
exception_handler_stub!(handler_x87_fpu, 15, 0);
exception_handler_stub!(handler_alignment_check, 16, 0);
exception_handler_stub!(handler_machine_check, 17, 1);
exception_handler_stub!(handler_simd_exception, 18, 0);

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
    idt.set_handler(
        7,
        handler_device_not_available as *const () as u64,
        selector,
        0,
    );
    idt.set_handler(8, handler_double_fault as *const () as u64, selector, 0);
    idt.set_handler(
        9,
        handler_coprocessor_segment as *const () as u64,
        selector,
        0,
    );
    idt.set_handler(10, handler_invalid_tss as *const () as u64, selector, 0);
    idt.set_handler(
        11,
        handler_segment_not_present as *const () as u64,
        selector,
        0,
    );
    idt.set_handler(12, handler_stack_fault as *const () as u64, selector, 0);
    idt.set_handler(
        13,
        handler_general_protection as *const () as u64,
        selector,
        0,
    );
    idt.set_handler(14, handler_page_fault as *const () as u64, selector, 0);
    idt.set_handler(15, handler_x87_fpu as *const () as u64, selector, 0);
    idt.set_handler(16, handler_alignment_check as *const () as u64, selector, 0);
    idt.set_handler(17, handler_machine_check as *const () as u64, selector, 0);
    idt.set_handler(18, handler_simd_exception as *const () as u64, selector, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a packed IDT entry as plain integers (avoids unaligned
    /// field access on the packed struct).
    fn decode(e: &IdtEntry) -> (u16, u16, u8, u8, u16, u32) {
        let b: [u8; 16] =
            unsafe { core::ptr::read_unaligned(e as *const IdtEntry as *const [u8; 16]) };
        (
            u16::from_le_bytes([b[0], b[1]]),               // offset_low
            u16::from_le_bytes([b[2], b[3]]),               // selector
            b[4],                                           // ist
            b[5],                                           // type_attr
            u16::from_le_bytes([b[6], b[7]]),               // offset_mid
            u32::from_le_bytes([b[8], b[9], b[10], b[11]]), // offset_high
        )
    }

    #[test]
    fn set_handler_encodes_dpl0_trap_gate() {
        let mut idt = Idt::new();
        idt.set_handler(14, 0x1234_5678_9ABC_DEF0, 0x08, 0);
        let (low, sel, ist, attr, mid, high) = decode(&idt.entries[14]);
        assert_eq!(low, 0xDEF0);
        assert_eq!(mid, 0x9ABC);
        assert_eq!(high, 0x1234_5678);
        assert_eq!(sel, 0x08);
        assert_eq!(ist, 0);
        assert_eq!(attr, 0x80 | 0x0E); // present, DPL0, trap gate
        assert_eq!(decode(&idt.entries[13]).2, 0); // untouched neighbours
    }

    #[test]
    fn set_irq_handler_encodes_interrupt_gate() {
        let mut idt = Idt::new();
        idt.set_irq_handler(0x30, 0xCAFE);
        let (low, sel, _ist, attr, _mid, _high) = decode(&idt.entries[0x30]);
        assert_eq!(low, 0xCAFE);
        assert_eq!(attr, 0x8E); // present, DPL0, interrupt gate
        assert_eq!(sel, crate::gdt::KERNEL_CODE_SELECTOR);
    }

    #[test]
    fn err_code_vectors_are_exactly_the_architectural_set() {
        assert_eq!(ERR_CODE_VECTORS, [8, 10, 11, 12, 13, 14, 17]);
    }

    #[test]
    fn decode_handlers_are_distinct() {
        let handled: [usize; 19] = [
            handler_divide_error as *const () as usize,
            handler_debug as *const () as usize,
            handler_nmi as *const () as usize,
            handler_breakpoint as *const () as usize,
            handler_overflow as *const () as usize,
            handler_bound_range as *const () as usize,
            handler_invalid_opcode as *const () as usize,
            handler_device_not_available as *const () as usize,
            handler_double_fault as *const () as usize,
            handler_coprocessor_segment as *const () as usize,
            handler_invalid_tss as *const () as usize,
            handler_segment_not_present as *const () as usize,
            handler_stack_fault as *const () as usize,
            handler_general_protection as *const () as usize,
            handler_page_fault as *const () as usize,
            handler_x87_fpu as *const () as usize,
            handler_alignment_check as *const () as usize,
            handler_machine_check as *const () as usize,
            handler_simd_exception as *const () as usize,
        ];
        let mut distinct = handled;
        distinct.sort_unstable();
        for pair in distinct.windows(2) {
            assert_ne!(
                pair[0], pair[1],
                "two exception vectors share a handler stub"
            );
        }
    }
}

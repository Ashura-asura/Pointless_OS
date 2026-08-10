//! x86_64 4-level page table setup for identity mapping.

use core::arch::asm;

/// Page table entry flags
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const PAGE_SIZE: u64 = 1 << 7; // 2MB huge page

#[repr(C, align(4096))]
struct PageTable {
    entries: [u64; 512],
}

impl PageTable {
    const fn new() -> Self {
        PageTable { entries: [0; 512] }
    }
}

/// Static page tables (must be in a known location for CR3)
static mut PML4: PageTable = PageTable::new();
static mut PDPT: PageTable = PageTable::new();
static mut PD: PageTable = PageTable::new();

/// Set up identity mapping: PML4[0] -> PDPT -> PD with 2MB huge pages.
/// Maps the first 1GB of physical memory (512 x 2MB pages).
pub unsafe fn setup_identity_mapping() {
    // Clear tables
    PML4.entries = [0; 512];
    PDPT.entries = [0; 512];
    PD.entries = [0; 512];

    // PML4[0] -> PDPT (present + writable)
    PML4.entries[0] = (&raw const PDPT as u64) | PRESENT | WRITABLE;

    // PDPT[0] -> PD (present + writable)
    PDPT.entries[0] = (&raw const PD as u64) | PRESENT | WRITABLE;

    // PD entries: 512 x 2MB huge pages = 1GB identity mapped
    for i in 0..512u64 {
        PD.entries[i as usize] = (i * 0x200000) | PRESENT | WRITABLE | PAGE_SIZE;
    }

    // Write CR3
    let cr3 = &raw const PML4 as u64;
    asm!("mov cr3, {cr3}", cr3 = in(reg) cr3);

    // Invalidate TLB
    asm!(
        "mov rax, cr3",
        "mov cr3, rax",
        out("rax") _
    );
}

/// Read current CR3 value
pub fn read_cr3() -> u64 {
    let val: u64;
    unsafe {
        asm!("mov {val}, cr3", val = out(reg) val);
    }
    val
}

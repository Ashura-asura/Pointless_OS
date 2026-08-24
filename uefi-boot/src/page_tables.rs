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
static mut PD1: PageTable = PageTable::new();
static mut PD2: PageTable = PageTable::new();
static mut PD3: PageTable = PageTable::new();
// PDs for the 4-7 GiB range, used to map a GOP framebuffer that sits above
// the first 4 GiB (the loader's base identity map covers only GB0-3).
static mut PD4: PageTable = PageTable::new();
static mut PD5: PageTable = PageTable::new();
static mut PD6: PageTable = PageTable::new();
static mut PD7: PageTable = PageTable::new();

/// Map a 1 GiB window [gb, gb+1) through pd_table with 2MB huge pages.
unsafe fn map_1gb(pdpt: *mut PageTable, pd: *mut PageTable, gb: u64) {
    (*pdpt).entries[gb as usize] = (pd as u64) | PRESENT | WRITABLE;
    for i in 0..512u64 {
        (*pd).entries[i as usize] = ((gb << 30) | (i * 0x200000)) | PRESENT | WRITABLE | PAGE_SIZE;
    }
}

/// Set up identity mapping: PML4[0] -> PDPT -> PD with 2MB huge pages.
/// Maps the first 4GB of physical memory (4 x 512 x 2MB pages) plus the
/// LAPIC MMIO window at FEE00000.
pub unsafe fn setup_identity_mapping() {
    // Clear tables
    PML4.entries = [0; 512];
    PDPT.entries = [0; 512];
    PD.entries = [0; 512];
    PD1.entries = [0; 512];
    PD2.entries = [0; 512];
    PD3.entries = [0; 512];

    // PML4[0] -> PDPT (present + writable)
    PML4.entries[0] = (&raw const PDPT as u64) | PRESENT | WRITABLE;

    // PDPT[g] -> PDg: identity map gigabytes 0..4 (LAPIC at FEE00000 falls
    // inside GB3, PD index 0xEE00000 >> 21 = 119, and is covered by it)
    map_1gb(&raw mut PDPT, &raw mut PD, 0);
    map_1gb(&raw mut PDPT, &raw mut PD1, 1);
    map_1gb(&raw mut PDPT, &raw mut PD2, 2);
    map_1gb(&raw mut PDPT, &raw mut PD3, 3);

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

/// Map one 1 GiB window `[gb, gb+1)` into the identity map with 2 MB pages,
/// so a device memory range above 4 GiB (e.g. the GOP framebuffer) is
/// accessible. Only GB4-GB7 have static PD tables here.
///
/// # Safety
/// Call once, before the kernel handoff, while the loader's page tables are
/// current (a `mov cr3` reload makes it visible).
pub unsafe fn map_gb(gb: u64) {
    let pd: *mut PageTable = match gb {
        4 => &raw mut PD4,
        5 => &raw mut PD5,
        6 => &raw mut PD6,
        7 => &raw mut PD7,
        _ => return, // only 4-7 GiB statics exist
    };
    let pd_ref = pd.as_mut().unwrap();
    pd_ref.entries = [0; 512];
    let pdpt = (&raw mut PDPT).as_mut().unwrap();
    pdpt.entries[gb as usize] = pd as u64 | PRESENT | WRITABLE;
    for i in 0..512u64 {
        pd_ref.entries[i as usize] = ((gb << 30) | (i * 0x200000)) | PRESENT | WRITABLE | PAGE_SIZE;
    }
    // Reload CR3 so the new PDPT entry is used.
    asm!("mov rax, cr3", "mov cr3, rax", out("rax") _);
}

/// Read current CR3 value
pub fn read_cr3() -> u64 {
    let val: u64;
    unsafe {
        asm!("mov {val}, cr3", val = out(reg) val);
    }
    val
}

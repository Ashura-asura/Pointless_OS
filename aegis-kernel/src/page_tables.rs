use core::arch::asm;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE_PAGE: u64 = 1 << 7;

#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; 512],
}

impl PageTable {
    pub const fn new() -> Self {
        PageTable { entries: [0; 512] }
    }

    pub fn clear(&mut self) {
        self.entries = [0; 512];
    }
}

// Static kernel page tables — identity-mapped, shared by all processes
static mut KERNEL_PML4: PageTable = PageTable::new();
static mut KERNEL_PDPT: PageTable = PageTable::new();

// Per-process scratch area for creating new user page tables
static mut SCRATCH_PDPT: PageTable = PageTable::new();
static mut SCRATCH_PD: PageTable = PageTable::new();

/// Set up identity-mapped kernel page tables (first 1GB, same as Phase 1).
/// Maps first 4 GB using 1GB huge pages via PDPT entries.
pub unsafe fn init_kernel_tables() {
    let pml4 = &mut *(&raw mut KERNEL_PML4);
    let pdpt = &mut *(&raw mut KERNEL_PDPT);

    pml4.clear();
    pdpt.clear();

    // Map first 4 entries as 1GB each = 4GB identity
    for i in 0..4 {
        pdpt.entries[i] = (i as u64 * 0x4000_0000) | PRESENT | WRITABLE | HUGE_PAGE;
    }

    // Link PDPT into PML4
    pml4.entries[0] = core::ptr::addr_of!(KERNEL_PDPT) as u64 | PRESENT | WRITABLE;
}

/// Create new user page tables.
/// Upper half (entries 256-511) points to kernel's PDPT (kernel space shared).
/// Lower half (entries 0-255) are zeroed (user space unique).
/// Returns the physical address of the new PML4.
pub unsafe fn create_user_tables() -> u64 {
    static mut USER_PML4: PageTable = PageTable::new();
    let user_pml4 = &mut *(&raw mut USER_PML4);
    let kernel_pml4 = &*(&raw const KERNEL_PML4);

    user_pml4.clear();

    // Copy kernel's upper-half entries
    for i in 256..512 {
        user_pml4.entries[i] = kernel_pml4.entries[i];
    }

    // Lower half is zeroed (already cleared)
    core::ptr::addr_of!(USER_PML4) as u64
}

/// Map one 2MB page in the given PML4.
pub unsafe fn map_page(pml4_phys: u64, vaddr: u64, paddr: u64, flags: u64) {
    let pml4 = &mut *(pml4_phys as *mut PageTable);

    let pml4_index = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_index = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_index = ((vaddr >> 21) & 0x1FF) as usize;

    // Get or create PDPT
    if pml4.entries[pml4_index] & PRESENT == 0 {
        let scratch = &mut *(&raw mut SCRATCH_PDPT);
        scratch.clear();
        pml4.entries[pml4_index] =
            core::ptr::addr_of!(SCRATCH_PDPT) as u64 | PRESENT | WRITABLE | USER;
    }
    let pdpt = &mut *((pml4.entries[pml4_index] & !0xFFF) as *mut PageTable);

    // Get or create PD
    if pdpt.entries[pdpt_index] & PRESENT == 0 {
        let scratch = &mut *(&raw mut SCRATCH_PD);
        scratch.clear();
        pdpt.entries[pdpt_index] =
            core::ptr::addr_of!(SCRATCH_PD) as u64 | PRESENT | WRITABLE | USER;
    }
    let pd = &mut *((pdpt.entries[pdpt_index] & !0xFFF) as *mut PageTable);

    // Map the 2MB page
    pd.entries[pd_index] = (paddr & !0x1FFFFF) | PRESENT | WRITABLE | USER | HUGE_PAGE | flags;
}

/// Switch to a different address space by writing CR3.
pub unsafe fn switch_to(pml4_phys: u64) {
    asm!("mov cr3, {}", in(reg) pml4_phys);
}

/// Get the physical address of the kernel PML4
pub fn kernel_pml4_phys() -> u64 {
    core::ptr::addr_of!(KERNEL_PML4) as u64
}

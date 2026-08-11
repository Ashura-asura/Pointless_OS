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
        let p = self.entries.as_mut_ptr();
        for i in 0..512 {
            unsafe { core::ptr::write_volatile(p.add(i), 0u64) };
        }
    }
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

// Static kernel page tables — identity-mapped, shared by all processes
static mut KERNEL_PML4: PageTable = PageTable::new();
static mut KERNEL_PDPT: PageTable = PageTable::new();

// Scratch area for the 0xC0000000-0xFFFFFFFF window (splits the huge page so
// the local APIC page can be mapped with ordinary 4 KB pages: QEMU TCG cannot
// perform MMIO writes through a 1 GB huge page and triple-faults).
static mut SCRATCH_PD: PageTable = PageTable::new();
static mut SCRATCH_PT: PageTable = PageTable::new();

// Per-process scratch area for creating new user page tables
static mut SCRATCH_PDPT: PageTable = PageTable::new();

const LAPIC_PHYS: u64 = 0xFEE0_0000;

/// Set up identity-mapped kernel page tables (first 1GB, same as Phase 1).
/// Maps first 4 GB using 1GB huge pages via PDPT entries, except the local
/// APIC page (0xFEE00000) which is mapped through a 4 KB page table so MMIO
/// writes reach the device.
///
/// # Safety
///
/// Must be called exactly once at boot, before any address-space switch. The
/// static page tables are mutated in place; concurrent access is undefined.
pub unsafe fn init_kernel_tables() {
    let pml4 = (&raw mut KERNEL_PML4).as_mut().unwrap();
    let pdpt = (&raw mut KERNEL_PDPT).as_mut().unwrap();
    let pd = (&raw mut SCRATCH_PD).as_mut().unwrap();
    let pt = (&raw mut SCRATCH_PT).as_mut().unwrap();

    pml4.clear();
    pdpt.clear();
    pd.clear();
    pt.clear();

    // Map first 3 entries as 1GB each = 3GB identity. The first 1 GB gets
    // the USER flag so ring-3 code (the demo user task + its stacks, and
    // the whole kernel image below 1 MB) is executable/readable at CPL3.
    // HONEST LIMIT: with a 1 GB huge page the whole window becomes
    // user-accessible — this demo enforces privilege TRANSITIONS, not
    // memory isolation (per-process page tables with ring-3-only regions
    // are a separate phase).
    for i in 0..3 {
        let mut flags = PRESENT | WRITABLE | HUGE_PAGE;
        if i == 0 {
            flags |= USER;
        }
        pdpt.entries[i] = (i as u64 * 0x4000_0000) | flags;
    }

    // 4th entry (0xC0000000-0xFFFFFFFF): PD of 2MB pages, with the LAPIC
    // page broken out into a 4KB page table.
    pdpt.entries[3] = core::ptr::addr_of!(SCRATCH_PD) as u64 | PRESENT | WRITABLE;
    for i in 0..512u64 {
        pd.entries[i as usize] = (0xC000_0000 + i * 0x20_0000) | PRESENT | WRITABLE | HUGE_PAGE;
    }
    let lapic_pd_index = ((LAPIC_PHYS >> 21) & 0x1FF) as usize;
    pd.entries[lapic_pd_index] = core::ptr::addr_of!(SCRATCH_PT) as u64 | PRESENT | WRITABLE;
    let lapic_window = LAPIC_PHYS & !0x1F_FFFF;
    for i in 0..512u64 {
        pt.entries[i as usize] = (lapic_window + i * 0x1000) | PRESENT | WRITABLE;
    }

    // Link PDPT into PML4. The first 1 GB is reachable by ring-3, so the
    // PML4 entry itself must carry USER too — user-mode access requires the
    // U/S bit at EVERY paging level, not just the leaf.
    pml4.entries[0] = core::ptr::addr_of!(KERNEL_PDPT) as u64 | PRESENT | WRITABLE | USER;
}

/// Create new user page tables.
/// Upper half (entries 256-511) points to kernel's PDPT (kernel space shared).
/// Lower half (entries 0-255) are zeroed (user space unique).
/// Returns the physical address of the new PML4.
///
/// # Safety
///
/// The returned address references a single static scratch PML4; callers must
/// copy it into per-process memory before creating another table.
pub unsafe fn create_user_tables() -> u64 {
    static mut USER_PML4: PageTable = PageTable::new();
    let user_pml4 = (&raw mut USER_PML4).as_mut().unwrap();
    let kernel_pml4 = (&raw const KERNEL_PML4).as_ref().unwrap();

    user_pml4.clear();

    // Copy kernel's upper-half entries
    for i in 256..512 {
        user_pml4.entries[i] = kernel_pml4.entries[i];
    }

    // Lower half is zeroed (already cleared)
    core::ptr::addr_of!(USER_PML4) as u64
}

/// Map one 2MB page in the given PML4.
///
/// # Safety
///
/// `pml4_phys` must be a valid physical address of a present PML4 page table.
/// Scratch page-table pages are reused; only one mapping walk may be in flight.
pub unsafe fn map_page(pml4_phys: u64, vaddr: u64, paddr: u64, flags: u64) {
    let pml4 = &mut *(pml4_phys as *mut PageTable);

    let pml4_index = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_index = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_index = ((vaddr >> 21) & 0x1FF) as usize;

    // Get or create PDPT
    if pml4.entries[pml4_index] & PRESENT == 0 {
        let scratch = (&raw mut SCRATCH_PDPT).as_mut().unwrap();
        scratch.clear();
        pml4.entries[pml4_index] =
            core::ptr::addr_of!(SCRATCH_PDPT) as u64 | PRESENT | WRITABLE | USER;
    }
    let pdpt = &mut *((pml4.entries[pml4_index] & !0xFFF) as *mut PageTable);

    // Get or create PD
    if pdpt.entries[pdpt_index] & PRESENT == 0 {
        let scratch = (&raw mut SCRATCH_PD).as_mut().unwrap();
        scratch.clear();
        pdpt.entries[pdpt_index] =
            core::ptr::addr_of!(SCRATCH_PD) as u64 | PRESENT | WRITABLE | USER;
    }
    let pd = &mut *((pdpt.entries[pdpt_index] & !0xFFF) as *mut PageTable);

    // Map the 2MB page
    pd.entries[pd_index] = (paddr & !0x1FFFFF) | PRESENT | WRITABLE | USER | HUGE_PAGE | flags;
}

/// Switch to a different address space by writing CR3.
///
/// # Safety
///
/// `pml4_phys` must be the physical address of a valid, fully populated PML4.
/// Switching to a partially-built table will fault on the next access.
pub unsafe fn switch_to(pml4_phys: u64) {
    asm!("mov cr3, {}", in(reg) pml4_phys);
}

/// Get the physical address of the kernel PML4
pub fn kernel_pml4_phys() -> u64 {
    core::ptr::addr_of!(KERNEL_PML4) as u64
}

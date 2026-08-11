use core::arch::asm;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE_PAGE: u64 = 1 << 7;
#[allow(dead_code)]
const NX: u64 = 1 << 63;

#[repr(C, align(4096))]
#[derive(Copy, Clone)]
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

const LAPIC_PHYS: u64 = 0xFEE0_0000;

/// End of everything ring-3 code needs in the low identity map: the kernel
/// image (text+rodata+data+bss, ends just above 0x35000 today) and every
/// task stack/CPL0 stack carved by the frame allocator. The corresponding
/// 2 MB PD entry is marked USER so ring-3 tasks can fetch their own code
/// and use their stacks; everything else in the lower half stays kernel-only
/// and ring-3 access to it faults (see `task_isolation_test`).
const USER_LOW_END: u64 = 0x200_000;

/// Set up identity-mapped kernel page tables (first 1GB, same as Phase 1).
/// Maps first 4 GB using 1GB huge pages via PDPT entries, except the local
/// APIC page (0xFEE00000) which is mapped through a 4 KB page table so MMIO
/// writes reach the device.
///
/// **Memory isolation**: The kernel PML4 has NO USER flags. Ring-3 tasks
/// cannot access kernel memory through this page table. Per-user-task PML4s
/// (created by `create_user_pml4`) share the same identity mapping and mark
/// only the regions a task needs to run (its code in the low 2 MB, plus its
/// stack) as USER-accessible.
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

    // Map first 3 entries as 1GB each = 3GB identity.
    // NO USER flag on any entry — kernel-only access through this PML4.
    for i in 0..3 {
        let flags = PRESENT | WRITABLE | HUGE_PAGE;
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

    // Link PDPT into PML4. NO USER flag — ring-3 cannot access any memory
    // through the kernel PML4. Per-user PML4s share the upper-half entries.
    pml4.entries[0] = core::ptr::addr_of!(KERNEL_PDPT) as u64 | PRESENT | WRITABLE;
}

/// Create a per-user-task PML4 with memory isolation.
///
/// The new PML4 copies the kernel PML4 entirely (kernel code accessible from
/// ring-0 during interrupts), then breaks the 1GB huge page containing the
/// task's stack into 2MB entries and sets the USER flag on:
///   - the 2MB region(s) covering the kernel image (the ring-3 task's own
///     code runs from there — a teaching-kernel compromise: coarse 2MB
///     granularity makes the low 2MB readable by ring-3), and
///   - the 2MB region containing the task's stack.
///
/// Every other 2MB entry stays kernel-only, so ring-3 access to the rest
/// of the identity map (e.g. 16 MiB, where `task_isolation_test` reads)
/// faults.
///
/// Returns the physical address of the new PML4, or 0 on allocation failure.
///
/// # Safety
///
/// `stack_phys` must be a valid physical address of a 16 KiB stack region.
pub unsafe fn create_user_pml4(stack_phys: u64) -> u64 {
    use crate::frame::alloc_global;

    let pml4_frame = match alloc_global() {
        Some(f) => f,
        None => return 0,
    };
    let user_pml4 = &mut *(pml4_frame as *mut PageTable);

    // Copy the entire kernel PML4 entries (identity-mapped lower half).
    // This provides kernel code/stack access at ring-0 for interrupts.
    *user_pml4 = *((&raw const KERNEL_PML4).as_ref().unwrap());

    // The stack is in the first 1GB, which is mapped as a 1GB huge page
    // by KERNEL_PDPT. We must allocate a NEW PDPT for the user PML4
    // (to avoid corrupting the shared KERNEL_PDPT), then break the 1GB
    // page into 2MB entries with the USER flag on just the stack region.
    let pml4_idx = ((stack_phys >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((stack_phys >> 30) & 0x1FF) as usize;
    let pd_idx = ((stack_phys >> 21) & 0x1FF) as usize;

    // Read the original 1GB entry from the kernel's shared PDPT
    let kernel_pdpt_phys = user_pml4.entries[pml4_idx] & !0xFFF;
    let kernel_pdpt = &*(kernel_pdpt_phys as *const PageTable);
    let original_1gb_entry = kernel_pdpt.entries[pdpt_idx];

    // Allocate a new PDPT for the user PML4
    let user_pdpt_frame = match alloc_global() {
        Some(f) => f,
        None => return 0,
    };
    let user_pdpt = &mut *(user_pdpt_frame as *mut PageTable);

    // Copy ALL entries from the kernel PDPT to the user PDPT
    for i in 0..512 {
        user_pdpt.entries[i] = kernel_pdpt.entries[i];
    }

    // Point the user PML4 at the new PDPT. USER is required on every level
    // a ring-3 page walk crosses: the PML4 entry and the PDPT entry below,
    // otherwise the walk faults before reaching the leaf.
    user_pml4.entries[pml4_idx] = user_pdpt_frame | PRESENT | WRITABLE | USER;

    if original_1gb_entry & HUGE_PAGE != 0 {
        // 1GB huge page -> break into 512 x 2MB entries in a new PD
        let base_1gb = original_1gb_entry & !0x1F_FFFF;
        let new_pd_frame = match alloc_global() {
            Some(f) => f,
            None => return 0,
        };
        let new_pd = &mut *(new_pd_frame as *mut PageTable);
        for i in 0..512u64 {
            new_pd.entries[i as usize] =
                (base_1gb + i * 0x20_0000) | PRESENT | WRITABLE | HUGE_PAGE;
        }
        // USER on the 2MB region(s) the task needs to run: its own code
        // (the kernel image in the low identity map) and its stack.
        let low_end_pd = (USER_LOW_END >> 21) as usize;
        for i in 0..low_end_pd {
            new_pd.entries[i] |= USER;
        }
        new_pd.entries[pd_idx] |= USER;
        // Point the user PDPT at the new PD (USER: ring-3 walks this level)
        user_pdpt.entries[pdpt_idx] = new_pd_frame | PRESENT | WRITABLE | USER;
    } else {
        // Already a PD pointer -- just add USER to the stack's 2MB entry
        let pd_phys = original_1gb_entry & !0xFFF;
        let pd = &mut *(pd_phys as *mut PageTable);
        pd.entries[pd_idx] |= USER;
    }

    pml4_frame
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

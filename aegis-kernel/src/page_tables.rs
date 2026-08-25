//! Kernel page tables: identity-mapped first 4 GB with NX (non-executable)
//! enforcement on every data page.
//!
//! Layout (kernel PML4):
//! - Entries 0-2: identity-mapped via PDs of 2 MB huge pages (NOT 1 GB
//!   PDPT-level huge pages — GB2 carries the GOP framebuffer on real
//!   hardware, and 1 GB huge pages are documented elsewhere in this file
//!   as unable to take MMIO writes reliably; see PD1/PD2 below). Entry 0's
//!   PD is further broken into 4 KB pages for the 2 MB regions containing
//!   the executable window (the kernel image's R+X PT_LOAD, parsed from
//!   the ELF at runtime), so the window can be the ONLY executable pages
//!   in the low map. The first 2 MB region is always split in ordinary
//!   builds (kernel image + VGA text framebuffer live there); a kernel image
//!   whose text links above 2 MB (large embedded payload, e.g. a guest OS
//!   image) gets its window region split the same way.
//! - Entry 3: the 0xC0000000-0xFFFFFFFF scratch window (2 MB pages), with
//!   the local APIC page broken out into 4 KB pages (QEMU TCG cannot do
//!   MMIO writes through huge pages).
//! - The NX bit (bit 63) is set on every non-code mapping: kernel stacks,
//!   BSS, the VGA framebuffer, LAPIC MMIO, allocator frames. Kernel data is
//!   never executable; ring-3 data pages (user stacks, video memory) are
//!   also NX, so a user task fetching an instruction from 0xB8000 #PFs
//!   (verified live by `task_nx_test`).
//!
//! Honest limits: 4 KB granularity only for the 2 MB regions that contain
//! the executable window; the rest of the low map uses 2 MB/1 GB huge pages.
//! Verified under QEMU/TCG, not on physical hardware.

use core::arch::asm;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE_PAGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;

/// IA32_EFER MSR. NXE (bit 11) must be set or the hardware ignores the NX
/// page-table bit.
const IA32_EFER: u32 = 0xC000_0080;
const EFER_NXE: u64 = 1 << 11;

/// ELF program-header flag: executable segment.
const PF_X: u32 = 1;

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

// Static kernel page tables — identity-mapped, shared by all processes.
static mut KERNEL_PML4: PageTable = PageTable::new();
static mut KERNEL_PDPT: PageTable = PageTable::new();

// First 1 GB broken into 2 MB pages (so data can be marked NX).
static mut KERNEL_PD0: PageTable = PageTable::new();
// 4 KB tables for the 2 MB regions that contain part of the executable
// window (so code and data can be separated there). The window is a single
// contiguous R+X PT_LOAD of the kernel image, so it can straddle at most two
// 2 MB regions.
static mut KERNEL_PT_WIN: [PageTable; 2] = [PageTable::new(); 2];

// Scratch area for the 0xC0000000-0xFFFFFFFF window (splits the huge page so
// the local APIC page can be mapped with ordinary 4 KB pages: QEMU TCG cannot
// perform MMIO writes through a 1 GB huge page and triple-faults).
static mut SCRATCH_PD: PageTable = PageTable::new();
static mut SCRATCH_PT: PageTable = PageTable::new();

// GB1/GB2 (0x40000000-0xBFFFFFFF), broken from a single 1 GB huge PDPT entry
// into a PD of 2 MB huge pages — same reason as SCRATCH_PD/SCRATCH_PT above.
// The GOP framebuffer (0x90000000 on the TP201S, confirmed 2 MB-aligned)
// lives in GB2; `create_user_pml4` below already assumes a GB1/2 PDPT entry
// might be a 1 GB huge page and knows how to split one on demand for a user
// stack, which is direct evidence this project has already hit the "1 GB
// huge page can't take MMIO" class of bug once (see SCRATCH_PD) — it was
// just never applied to the kernel's own mapping of the framebuffer region.
// 2 MB is the granularity the *loader's* identity map already uses for this
// same address range (uefi-boot/src/page_tables.rs::map_1gb) before the
// kernel's CR3 switch, so this matches a mapping already exercised earlier
// in the same boot.
static mut PD1: PageTable = PageTable::new();
static mut PD2: PageTable = PageTable::new();

// 64-bit device BAR window: QEMU's q35 machine assigns the NVMe controller's
// BAR0 above 4 GiB (0xC000000000 = 768 GiB). PML4[1] -> DEV_HI_PDPT (slot 256
// = GB 768) -> DEV_HI_PD (2 MB pages, NX) -> DEV_HI_PT (first 2 MB split into
// 4 KB NX pages so TCG can take MMIO through them, same pattern as the LAPIC).
static mut DEV_HI_PDPT: PageTable = PageTable::new();
static mut DEV_HI_PD: PageTable = PageTable::new();
static mut DEV_HI_PT: PageTable = PageTable::new();

pub const DEVICE_BAR_WINDOW: u64 = 0xC000000000;

const LAPIC_PHYS: u64 = 0xFEE0_0000;

/// Page index (4 KB) of a virtual address.
pub fn pt_index(addr: u64) -> usize {
    ((addr >> 12) & 0x1FF) as usize
}

/// 2 MB page index of a virtual address.
pub fn pd_index(addr: u64) -> usize {
    ((addr >> 21) & 0x1FF) as usize
}

/// 1 GB page index of a virtual address.
pub fn pdpt_index(addr: u64) -> usize {
    ((addr >> 30) & 0x1FF) as usize
}

/// First and last 4 KB page index *containing* the half-open window
/// `[start, end)`.
pub fn exec_page_range(text_start: u64, text_end: u64) -> (usize, usize) {
    let first = (text_start >> 12) as usize;
    let last = ((text_end + 0xFFF) >> 12) as usize;
    (first, last)
}

/// Does the half-open 2 MB region `[region_start, region_end)` contain any
/// part of the executable window `[ts, te)`?
pub fn region_contains_window(ts: u64, te: u64, region_start: u64, region_end: u64) -> bool {
    ts < region_end && te > region_start
}

/// Is 4 KB page `page` inside the executable window? `page` is the address's
/// global 4 KB page index (`addr >> 12`), not a 2 MB-region-local index —
/// the window is a range of global pages, so a region-local index only
/// matches for the first 2 MB (where the two coincide).
pub fn is_exec_page(page: usize, text_start: u64, text_end: u64) -> bool {
    let (first, last) = exec_page_range(text_start, text_end);
    page >= first && page < last
}

/// Wait, is the page at virtual address `addr` inside the window?
/// Is the 4 KB page containing virtual address `addr` inside the window?
pub fn addr_is_exec(addr: u64, text_start: u64, text_end: u64) -> bool {
    is_exec_page((addr >> 12) as usize, text_start, text_end)
}

/// Parse the executable (R+X) PT_LOAD window of an ELF64 image from raw
/// bytes. Pure and unit-testable; `kernel_text_window` feeds it the kernel
/// image at identity address 0.
pub fn text_window_from_elf(data: &[u8]) -> Result<(u64, u64), &'static str> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err("bad ELF magic");
    }
    let is64 = data[4] == 2;
    let le = data[5] == 1;
    if !is64 || !le {
        return Err("not ELF64 little-endian");
    }
    let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(data[56..58].try_into().unwrap());
    if e_phentsize < 56 || e_phnum == 0 {
        return Err("bad program header table");
    }
    let mut window: Option<(u64, u64)> = None;
    for i in 0..e_phnum {
        let stride = e_phentsize as u64;
        let off = e_phoff
            .checked_add(
                (i as u64)
                    .checked_mul(stride)
                    .ok_or("program header offset overflow")?,
            )
            .ok_or("program header offset overflow")?;
        let off = usize::try_from(off).map_err(|_| "program header offset overflow")?;
        if off.checked_add(56).is_none_or(|end| end > data.len()) {
            return Err("program header out of bounds");
        }
        let p_type = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let p_flags = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(data[off + 32..off + 40].try_into().unwrap());
        if p_type != 1 {
            continue; // PT_LOAD only
        }
        if p_flags & PF_X == 0 {
            continue;
        }
        let start = p_vaddr;
        let end = p_vaddr + p_filesz;
        let w = window.get_or_insert((start, end));
        w.0 = w.0.min(start);
        w.1 = w.1.max(end);
    }
    window.ok_or("no executable PT_LOAD")
}

/// Executable window of the running kernel image (ELF at identity address
/// 0). `None` if the image's program headers cannot be parsed — a build
/// problem, not a runtime one.
pub fn kernel_text_window() -> Option<(u64, u64)> {
    // Address 0 is the identity-mapped kernel image (ELF header + program
    // header table). Copy the headers into a stack buffer with volatile
    // reads (no raw-null slice), then run the pure parser on it.
    let mut buf = [0u8; 1024];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = unsafe { core::ptr::read_volatile((i as u64) as *const u8) };
    }
    text_window_from_elf(&buf).ok()
}

/// Ensure IA32_EFER.NXE is set so the NX page-table bit is honored.
///
/// # Safety
///
/// Must be called at boot in ring 0 while the EFER MSR is writable.
pub unsafe fn enable_nxe() {
    let lo: u32;
    let hi: u32;
    asm!("rdmsr", in("ecx") IA32_EFER, out("eax") lo, out("edx") hi, options(nostack));
    let efer = ((hi as u64) << 32) | lo as u64;
    let efer = efer | EFER_NXE;
    asm!(
        "wrmsr",
        in("ecx") IA32_EFER,
        in("eax") efer as u32,
        in("edx") (efer >> 32) as u32,
        options(nostack)
    );
}

/// Set up identity-mapped kernel page tables (first 4 GB) with NX on every
/// data mapping. The only executable pages are those overlapping the kernel
/// image's R+X PT_LOAD window (parsed from the ELF at address 0).
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
    enable_nxe();

    let pml4 = (&raw mut KERNEL_PML4).as_mut().unwrap();
    let pdpt = (&raw mut KERNEL_PDPT).as_mut().unwrap();
    let pd0 = (&raw mut KERNEL_PD0).as_mut().unwrap();
    let pd = (&raw mut SCRATCH_PD).as_mut().unwrap();
    let pt = (&raw mut SCRATCH_PT).as_mut().unwrap();

    pml4.clear();
    pdpt.clear();
    pd0.clear();
    for pt_win in (&raw mut KERNEL_PT_WIN).as_mut().unwrap().iter_mut() {
        pt_win.clear();
    }
    pd.clear();
    pt.clear();
    (&raw mut DEV_HI_PDPT).as_mut().unwrap().clear();
    (&raw mut DEV_HI_PD).as_mut().unwrap().clear();
    (&raw mut DEV_HI_PT).as_mut().unwrap().clear();

    // Executable window of the kernel image. Everything outside it is NX.
    let window = kernel_text_window();

    // First 1 GB: PD of 2 MB pages. Every 2 MB region is NX by default.
    pdpt.entries[0] = core::ptr::addr_of!(KERNEL_PD0) as u64 | PRESENT | WRITABLE;
    for i in 0..512u64 {
        pd0.entries[i as usize] = (i * 0x20_0000) | PRESENT | WRITABLE | HUGE_PAGE | NX;
    }
    // 2 MB regions that contain part of the executable window are split into
    // 4 KB pages so the window can be the ONLY executable pages in the low
    // map. The first 2 MB is split whenever the ELF parses (it is where the
    // kernel image and the VGA text framebuffer live in ordinary builds); a
    // kernel image whose text links above 2 MB — e.g. one carrying a large
    // embedded payload — gets its window region split the same way, so the
    // text stays executable after the CR3 switch.
    let mut win_tables = 0usize;
    for i in 0..512u64 {
        let region_start = i * 0x20_0000;
        let region_end = region_start + 0x20_0000;
        let hit = match window {
            Some((ts, te)) => region_contains_window(ts, te, region_start, region_end),
            None => i == 0,
        };
        if !hit {
            continue;
        }
        let pt = match core::ptr::addr_of_mut!(KERNEL_PT_WIN[win_tables]).as_mut() {
            Some(pt) => pt,
            None => core::panic!("exec window spans more than two 2 MB regions"),
        };
        win_tables += 1;
        pt.clear();
        for k in 0..512u64 {
            let addr = region_start + k * 0x1000;
            let flags = PRESENT | WRITABLE | NX;
            pt.entries[k as usize] = match window {
                Some((ts, te)) if addr_is_exec(addr, ts, te) => addr | (flags & !NX),
                _ => addr | flags,
            };
        }
        pd0.entries[i as usize] =
            core::ptr::addr_of!(KERNEL_PT_WIN[win_tables - 1]) as u64 | PRESENT | WRITABLE;
    }

    // GBs 1-2: PD of 2 MB huge pages, NX (no executable content lives
    // there). NOT a single 1 GB PDPT-level huge page: the GOP framebuffer
    // (GB2 on the TP201S) needs MMIO writes to actually land, and this
    // project already has a documented case (SCRATCH_PD/SCRATCH_PT, GB3's
    // LAPIC page) of a 1 GB huge page silently breaking MMIO. `create_user_pml4`
    // below already special-cases "this GB1/2 PDPT entry might be a 1 GB huge
    // page" for a different reason (per-task USER stack mapping) — that
    // branch stays correct either way since it starts from `gb_entry`, not
    // a hardcoded assumption.
    let pd1 = (&raw mut PD1).as_mut().unwrap();
    let pd2 = (&raw mut PD2).as_mut().unwrap();
    pd1.clear();
    pd2.clear();
    for i in 0..512u64 {
        pd1.entries[i as usize] =
            (0x4000_0000 + i * 0x20_0000) | PRESENT | WRITABLE | HUGE_PAGE | NX;
        pd2.entries[i as usize] =
            (0x8000_0000 + i * 0x20_0000) | PRESENT | WRITABLE | HUGE_PAGE | NX;
    }
    pdpt.entries[1] = core::ptr::addr_of!(PD1) as u64 | PRESENT | WRITABLE;
    pdpt.entries[2] = core::ptr::addr_of!(PD2) as u64 | PRESENT | WRITABLE;

    // 4th GB (0xC0000000-0xFFFFFFFF): PD of 2 MB pages, NX, with the LAPIC
    // page broken out into a 4 KB page table (also NX — MMIO, never code).
    pdpt.entries[3] = core::ptr::addr_of!(SCRATCH_PD) as u64 | PRESENT | WRITABLE;
    for i in 0..512u64 {
        pd.entries[i as usize] =
            (0xC000_0000 + i * 0x20_0000) | PRESENT | WRITABLE | HUGE_PAGE | NX;
    }
    let lapic_pd_index = ((LAPIC_PHYS >> 21) & 0x1FF) as usize;
    pd.entries[lapic_pd_index] = core::ptr::addr_of!(SCRATCH_PT) as u64 | PRESENT | WRITABLE;
    let lapic_window = LAPIC_PHYS & !0x1F_FFFF;
    for i in 0..512u64 {
        pt.entries[i as usize] = (lapic_window + i * 0x1000) | PRESENT | WRITABLE | NX;
    }

    // Link PDPT into PML4. NO USER flag — ring-3 cannot access any memory
    // through the kernel PML4. Per-user PML4s share the upper-half entries.
    pml4.entries[0] = core::ptr::addr_of!(KERNEL_PDPT) as u64 | PRESENT | WRITABLE;

    // 64-bit device BAR window at 0xC000000000 (PML4[1] -> PDPT[256] -> PD[0]).
    // 2 MB NX pages by default; the first 2 MB is split into DEV_HI_PT 4 KB
    // pages so TCG can take MMIO (same reason as the LAPIC breakout).
    let dev_pdpt = (&raw mut DEV_HI_PDPT).as_mut().unwrap();
    let dev_pd = (&raw mut DEV_HI_PD).as_mut().unwrap();
    let dev_pt = (&raw mut DEV_HI_PT).as_mut().unwrap();
    let dev_pdpt_idx = ((DEVICE_BAR_WINDOW >> 30) & 0x1FF) as usize; // 256
    dev_pdpt.entries[dev_pdpt_idx] = core::ptr::addr_of!(DEV_HI_PD) as u64 | PRESENT | WRITABLE;
    for i in 0..512u64 {
        dev_pd.entries[i as usize] =
            (DEVICE_BAR_WINDOW + i * 0x20_0000) | PRESENT | WRITABLE | HUGE_PAGE | NX;
    }
    dev_pd.entries[0] = core::ptr::addr_of!(DEV_HI_PT) as u64 | PRESENT | WRITABLE;
    for i in 0..512u64 {
        dev_pt.entries[i as usize] = (DEVICE_BAR_WINDOW + i * 0x1000) | PRESENT | WRITABLE | NX;
    }
    pml4.entries[1] = core::ptr::addr_of!(DEV_HI_PDPT) as u64 | PRESENT | WRITABLE;

    // DIAG for the NVMe open problem: dump the four page-walk qwords the CPU
    // will read when translating 0xC000000000.
    crate::sprintln!(
        "Aegis: DIAG walk CR3=0x{:X} pml4[1]=0x{:X} pdpt[256]=0x{:X} pd[0]=0x{:X} pt[0]=0x{:X}",
        core::ptr::addr_of!(KERNEL_PML4) as u64,
        pml4.entries[1],
        dev_pdpt.entries[dev_pdpt_idx],
        dev_pd.entries[0],
        dev_pt.entries[0]
    );
}

/// Create a per-user-task PML4 with memory isolation.
///
/// The new PML4 copies the kernel PML4 (kernel code accessible from ring-0
/// during interrupts), then clones the kernel's tables so USER flags can be
/// added without mutating the shared kernel tables:
///   - every 4 KB-split 2 MB region of the stack's GB (the low 2 MB kernel
///     image window, plus any exec-window region above 2 MB) becomes a
///     per-user 4 KB clone with every leaf USER — the ring-3 task's own code
///     runs from the kernel image in the identity map, a teaching-kernel
///     compromise — but NX is preserved, so only text pages are executable,
///     and
///   - the 2 MB region containing the task's stack is marked USER (and stays
///     NX: a ring-3 stack is data, never executable).
///
/// Every other entry stays kernel-only, so ring-3 access to the rest of the
/// identity map (e.g. 16 MiB, where `task_isolation_test` reads) faults.
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
    *user_pml4 = *((&raw const KERNEL_PML4).as_ref().unwrap());

    let pml4_idx = pdpt_index(stack_phys); // == pml4 index of the stack's 1 GB
    let pdpt_idx = pdpt_index(stack_phys);
    let pd_idx = pd_index(stack_phys);

    // Read the stack's 1 GB entry from the kernel's shared PDPT.
    let kernel_pdpt_phys = user_pml4.entries[pml4_idx] & !0xFFF;
    let kernel_pdpt = &*(kernel_pdpt_phys as *const PageTable);
    let gb_entry = kernel_pdpt.entries[pdpt_idx];

    // Fresh per-user PDPT: full copy of the kernel's, then the stack's 1 GB
    // entry is replaced with USER-accessible clones below.
    let user_pdpt_frame = match alloc_global() {
        Some(f) => f,
        None => return 0,
    };
    let user_pdpt = &mut *(user_pdpt_frame as *mut PageTable);
    for i in 0..512 {
        user_pdpt.entries[i] = kernel_pdpt.entries[i];
    }
    // USER is required on every level a ring-3 page walk crosses.
    user_pml4.entries[pml4_idx] = user_pdpt_frame | PRESENT | WRITABLE | USER;

    if gb_entry & HUGE_PAGE != 0 {
        // 1 GB huge page -> break into 512 x 2 MB NX entries in a fresh PD;
        // only the stack's 2 MB region becomes USER.
        let base_1gb = gb_entry & !0x1F_FFFF;
        let new_pd_frame = match alloc_global() {
            Some(f) => f,
            None => return 0,
        };
        let new_pd = &mut *(new_pd_frame as *mut PageTable);
        for i in 0..512u64 {
            new_pd.entries[i as usize] =
                (base_1gb + i * 0x20_0000) | PRESENT | WRITABLE | HUGE_PAGE | NX;
        }
        new_pd.entries[pd_idx] |= USER;
        user_pdpt.entries[pdpt_idx] = new_pd_frame | PRESENT | WRITABLE | USER;
    } else {
        // The stack's 1 GB is already a PD pointer (like GB 0 after NX).
        // Clone the kernel PD into a fresh one so USER flags never leak
        // into the shared kernel tables.
        let kernel_pd = &*((gb_entry & !0xFFF) as *const PageTable);
        let new_pd_frame = match alloc_global() {
            Some(f) => f,
            None => return 0,
        };
        let new_pd = &mut *(new_pd_frame as *mut PageTable);
        for i in 0..512 {
            new_pd.entries[i] = kernel_pd.entries[i];
        }
        if pdpt_idx == 0 {
            // GB 0's 4 KB-split 2 MB regions — the low 2 MB kernel image
            // window, plus any exec-window region above 2 MB when the kernel
            // text links high (large embedded payload) — are cloned per-user
            // with every leaf marked USER: ring-3 task code runs from the
            // kernel image, a teaching-kernel compromise. NX is preserved,
            // so only text pages are executable.
            for pd_i in 0..512 {
                let e = new_pd.entries[pd_i];
                if e & PRESENT == 0 || e & HUGE_PAGE != 0 {
                    continue;
                }
                let kernel_pt_phys = e & !0xFFF;
                let kernel_pt = &*(kernel_pt_phys as *const PageTable);
                let new_pt_frame = match alloc_global() {
                    Some(f) => f,
                    None => return 0,
                };
                let new_pt = &mut *(new_pt_frame as *mut PageTable);
                for i in 0..512 {
                    new_pt.entries[i] = kernel_pt.entries[i] | USER;
                }
                new_pd.entries[pd_i] = new_pt_frame | PRESENT | WRITABLE | USER;
            }
        }
        new_pd.entries[pd_idx] |= USER;
        user_pdpt.entries[pdpt_idx] = new_pd_frame | PRESENT | WRITABLE | USER;
    }

    pml4_frame
}

/// Map one 4 KB executable page into a per-user address space at `vaddr`
/// with USER access, backing it with physical frame `phys`. The page is
/// executable (no NX) and not writable, so it is the kernel-side analog of
/// an ELF R+E text page.
///
/// `vaddr` must sit in an otherwise-empty PML4 slot above the kernel's own
/// tables (the Phase J Linux code page uses PML4 index 224). The PDPT/PD/PT
/// chain is built fresh inside the user's own tables so no USER flag leaks
/// into the shared kernel tables.
///
/// Returns false if any frame allocation fails. A present-but-zeroed upper
/// entry can remain if a later frame alloc fails (the fresh chain is always
/// zero-filled, so the leftover PDPT/PD/PT is uniformly empty and harmless);
/// the leaf page is never installed on failure.
///
/// # Safety
///
/// `pml4_phys` must be the physical address of a per-user PML4 (as returned
/// by `create_user_pml4`), `vaddr` must be page-aligned, and `phys` must be
/// a free frame owned by the kernel.
pub unsafe fn map_user_code_page(pml4_phys: u64, vaddr: u64, phys: u64) -> bool {
    use crate::frame::alloc_global;

    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    let pml4 = &mut *(pml4_phys as *mut PageTable);

    // PML4 -> PDPT (fresh unless already present).
    let pdpt_phys = if pml4.entries[pml4_idx] & PRESENT != 0 {
        pml4.entries[pml4_idx] & !0xFFF
    } else {
        let f = match alloc_global() {
            Some(f) => f,
            None => return false,
        };
        core::ptr::write_bytes(f as *mut u8, 0, 4096);
        pml4.entries[pml4_idx] = f | PRESENT | WRITABLE | USER;
        f
    };

    let pdpt = &mut *(pdpt_phys as *mut PageTable);

    // PDPT -> PD (fresh unless already present).
    let pd_phys = if pdpt.entries[pdpt_idx] & PRESENT != 0 {
        pdpt.entries[pdpt_idx] & !0xFFF
    } else {
        let f = match alloc_global() {
            Some(f) => f,
            None => return false,
        };
        core::ptr::write_bytes(f as *mut u8, 0, 4096);
        pdpt.entries[pdpt_idx] = f | PRESENT | WRITABLE | USER;
        f
    };

    let pd = &mut *(pd_phys as *mut PageTable);

    // PD -> PT (fresh unless already present).
    let pt_phys = if pd.entries[pd_idx] & PRESENT != 0 {
        pd.entries[pd_idx] & !0xFFF
    } else {
        let f = match alloc_global() {
            Some(f) => f,
            None => return false,
        };
        core::ptr::write_bytes(f as *mut u8, 0, 4096);
        pd.entries[pd_idx] = f | PRESENT | WRITABLE | USER;
        f
    };

    let pt = &mut *(pt_phys as *mut PageTable);

    // Leaf: present, USER, executable (no NX), NOT writable — an R+E page.
    pt.entries[pt_idx] = phys | PRESENT | USER;
    true
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ELF64 little-endian image with the given program
    /// headers: (p_type, p_flags, p_vaddr, p_filesz).
    fn elf_with(phdrs: &[(u32, u32, u64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; 64 + phdrs.len() * 56];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // ELF64
        b[5] = 1; // little-endian
        b[32..40].copy_from_slice(&(64u64).to_le_bytes()); // e_phoff
        b[54..56].copy_from_slice(&(56u16).to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes()); // e_phnum
        for (i, &(p_type, p_flags, p_vaddr, p_filesz)) in phdrs.iter().enumerate() {
            let off = 64 + i * 56;
            b[off..off + 4].copy_from_slice(&p_type.to_le_bytes());
            b[off + 4..off + 8].copy_from_slice(&p_flags.to_le_bytes());
            b[off + 16..off + 24].copy_from_slice(&p_vaddr.to_le_bytes());
            b[off + 32..off + 40].copy_from_slice(&p_filesz.to_le_bytes());
        }
        b
    }

    #[test]
    fn text_window_from_elf_takes_rx_segment_only() {
        let elf = elf_with(&[
            (1, 4, 0x0, 0x2000),     // PT_LOAD R only
            (1, 5, 0x3000, 0x5000),  // PT_LOAD R+X -> text
            (1, 6, 0x9000, 0x10000), // PT_LOAD R+W data
        ]);
        assert_eq!(text_window_from_elf(&elf), Ok((0x3000, 0x8000)));
    }

    #[test]
    fn text_window_from_elf_merges_multiple_rx_segments() {
        let elf = elf_with(&[(1, 5, 0x1000, 0x800), (1, 5, 0x2000, 0x100)]);
        assert_eq!(text_window_from_elf(&elf), Ok((0x1000, 0x2100)));
    }

    #[test]
    fn text_window_rejects_garbage() {
        assert!(text_window_from_elf(b"not an elf at all").is_err());
        assert!(text_window_from_elf(&[0u8; 64]).is_err());
    }

    #[test]
    fn text_window_rejects_overflowing_phoff() {
        // e_phoff chosen so that e_phoff + i*e_phentsize wraps around usize
        // back into range for some i, if computed with unchecked arithmetic.
        // Must be rejected outright, not silently wrap into a bogus offset
        // that then gets treated as a real (and possibly exec+RW) segment.
        let mut b = vec![0u8; 128];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[32..40].copy_from_slice(&(u64::MAX - 10).to_le_bytes()); // e_phoff
        b[54..56].copy_from_slice(&(56u16).to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&(4u16).to_le_bytes()); // e_phnum
        assert!(text_window_from_elf(&b).is_err());
    }

    #[test]
    fn text_window_without_exec_segment_fails() {
        let elf = elf_with(&[(1, 4, 0x0, 0x1000), (1, 6, 0x2000, 0x1000)]);
        assert!(text_window_from_elf(&elf).is_err());
    }

    #[test]
    fn exec_page_range_rounds_window_to_page_boundaries() {
        // 0x32F0..0x8AA4 spans 4 KB pages 3..8 (0x3000..0x9000).
        assert_eq!(exec_page_range(0x32F0, 0x8AA4), (3, 9));
        // Exact page boundary: page 4 is inside, page 4+1 starts after end.
        assert_eq!(exec_page_range(0x4000, 0x5000), (4, 5));
    }

    #[test]
    fn is_exec_page_matches_window() {
        let (ts, te) = (0x4000u64, 0x9000u64);
        assert!(is_exec_page(4, ts, te));
        assert!(!is_exec_page(3, ts, te));
        assert!(!is_exec_page(9, ts, te));
        assert!(addr_is_exec(0x57F0, ts, te));
        assert!(!addr_is_exec(0xB8000, ts, te));
    }

    #[test]
    fn index_helpers_are_spec_correct() {
        assert_eq!(pt_index(0xB8000), (0xB8000 >> 12) & 0x1FF);
        assert_eq!(pd_index(0x1000000), (0x1000000 >> 21) & 0x1FF);
        assert_eq!(pdpt_index(0x40000000), 1);
        assert_eq!(pdpt_index(0xFEE00000), pdpt_index(0xFEE0_0000));
        assert_eq!(pt_index(0), 0);
        // 0xC000000000 = 768 GiB: PML4 index 1 (bits 47:39), PDPT slot 256
        // (bits 38:30), PD slot 0, PT slot 0.
        assert_eq!((0xC000000000u64 >> 39) & 0x1FF, 1);
        assert_eq!(pdpt_index(0xC000000000), 256);
        assert_eq!(pd_index(0xC000000000), 0);
        assert_eq!(pt_index(0xC000000000), 0);
    }

    #[test]
    fn region_contains_window_matches_2mb_regions() {
        let (ts, te) = (0xAF_3EB0u64, 0xB2_0724u64); // text window above 2 MB
                                                     // Inside the window's own 2 MB region (0xA00000-0xC00000).
        assert!(region_contains_window(ts, te, 0xA00000, 0xC00000));
        // Region entirely below the window.
        assert!(!region_contains_window(ts, te, 0, 0x200000));
        assert!(!region_contains_window(ts, te, 0x800000, 0xA00000));
        // Region entirely above the window.
        assert!(!region_contains_window(ts, te, 0xC00000, 0xE00000));
        // Window ending exactly at a region start: not inside that region.
        assert!(!region_contains_window(
            0x100000, 0x200000, 0x200000, 0x400000
        ));
        // Window straddling a region boundary: both regions hit.
        assert!(region_contains_window(0x1FF000, 0x201000, 0, 0x200000));
        assert!(region_contains_window(
            0x1FF000, 0x201000, 0x200000, 0x400000
        ));
    }

    #[test]
    fn elfs_with_out_of_bounds_phdrs_fail() {
        let mut elf = elf_with(&[(1, 5, 0x4000, 0x1000)]);
        // Corrupt e_phoff to point past the buffer.
        elf[32..40].copy_from_slice(&0xFFFFusize.to_le_bytes());
        assert!(text_window_from_elf(&elf).is_err());
    }

    #[test]
    fn map_user_code_page_builds_executable_user_leaf() {
        // Host-test environment: there is no real physical memory, so back
        // the "frames" with heap memory and use their addresses as if they
        // were physical — exactly the pattern the other page-table tests use.
        // The buffer is padded and rounded up to 0x1000 so each 4 KiB
        // "frame" satisfies PageTable's 4096-byte alignment.
        let mut backing = vec![0u8; 4096 * 8];
        let base = (backing.as_mut_ptr() as u64 + 0xFFF) & !0xFFF;
        let pml4 = base;
        let pdpt = base + 0x1000;
        let pd = base + 0x2000;
        let pt = base + 0x3000;
        // Pre-wire a minimal chain so map_user_code_page only installs the
        // leaf (it also handles building the chain, but a pre-wired chain
        // isolates the leaf-bit assertions below).
        let vaddr = 0x0000_7000_0000_0000u64; // Phase J Linux code VADDR
        unsafe {
            let pm = &mut *(pml4 as *mut crate::page_tables::PageTable);
            pm.entries[((vaddr >> 39) & 0x1FF) as usize] = pdpt | PRESENT | WRITABLE | USER;
            let pdpt_ref = &mut *(pdpt as *mut crate::page_tables::PageTable);
            pdpt_ref.entries[((vaddr >> 30) & 0x1FF) as usize] = pd | PRESENT | WRITABLE | USER;
            let pd_ref = &mut *(pd as *mut crate::page_tables::PageTable);
            pd_ref.entries[((vaddr >> 21) & 0x1FF) as usize] = pt | PRESENT | WRITABLE | USER;

            let phys = base + 0x9000;
            assert!(map_user_code_page(pml4, vaddr, phys));
        }
        unsafe {
            let pt_ref = &*(pt as *const crate::page_tables::PageTable);
            let leaf = pt_ref.entries[((vaddr >> 12) & 0x1FF) as usize];
            assert_ne!(leaf & PRESENT, 0, "leaf must be present");
            assert_ne!(leaf & USER, 0, "leaf must be USER-accessible");
            assert_eq!(leaf & NX, 0, "leaf must be executable (no NX)");
            assert_eq!(leaf & WRITABLE, 0, "leaf must be read+execute only");
            assert_eq!(
                leaf & !0xFFF,
                base + 0x9000,
                "leaf must point at the backing frame"
            );
        }
    }
}

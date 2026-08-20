//! Phase U: Extended Page Tables (EPT) — second-level address translation
//! for a VMX guest under Aegis's hypervisor.
//!
//! What this is: the pure-logic EPT layer. A 4-level EPT (PML4E -> PDPTE ->
//! PDE -> PTE, 4 KiB pages) maps guest-physical frames to host-physical
//! frames, and the mapping is gated by a *memory grant* — a VM's RAM is a
//! capability like every other kernel resource, not a special case. A guest
//! physical range that is not inside the VM's grant is refused at map time,
//! before any hardware sees it.
//!
//! Honest scope, stated up front per Ground Rule 6: everything in this file
//! is CPU-independent, contract-testable logic (page-table arithmetic, the
//! grant gate, the EPTP encoding, EPT-violation qualification decoding). It
//! is NOT live-verified against real silicon — wiring the root into a VMCS
//! and observing real hardware walks it is the hardware-gated half of
//! Phase U (this machine has no VT-x: `HypervisorPresent` is set, the VMX
//! feature bit is absent). Known simplifications, deliberate for the first
//! real increment: 4 KiB leaf pages only (no 2 MiB `PS` large pages —
//! listed as a later refinement, not this phase's job); identity-style
//! mapping (guest RAM is a contiguous physical grant, host frames are
//! mapped 1:1 within it — the same contiguous-frame convention the rest of
//! this kernel already uses); no superpages, no EPT poisoning, no
//! page-modification logging (the EPT PML bits stay 0; the dirty/accessed
//! tracking use cases are explicitly not this phase's job).

use core::ptr;

/// 4 KiB page size, matching the frame allocator.
pub const PAGE_SIZE: u64 = 4096;
/// Level-4 index width: 512 entries per table.
const ENTRIES: u64 = 512;
/// Host-physical address bits inside an EPT entry (SDM §28.3.3.1).
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------
// EPT entry flags (SDM §28.2.1, §28.3.3.1)
// ---------------------------------------------------------------------

/// Read access allowed.
pub const EPT_R: u64 = 1 << 0;
/// Write access allowed.
pub const EPT_W: u64 = 1 << 1;
/// Execute access allowed.
pub const EPT_X: u64 = 1 << 2;
/// Large page (2 MiB / 1 GiB) — unused by this phase's 4 KiB-only builder,
/// kept as the named constant so the later large-page refinement has the
/// encoding already documented.
pub const EPT_PS: u64 = 1 << 7;
/// EPT memory type mask (bits 5:3): write-back (6) is the value used for
/// all RAM mappings here.
pub const EPT_MT_WB: u64 = 6 << 3;
/// Ignore PAT (bit 6): the guest's PAT is irrelevant to RAM we map as WB.
pub const EPT_IPAT: u64 = 1 << 6;

/// Leaf-entry flags used by `Ept::map` when the caller passes `EPT_DEFAULT_FLAGS`.
pub const EPT_DEFAULT_FLAGS: u64 = EPT_R | EPT_W | EPT_X | EPT_MT_WB | EPT_IPAT;
/// Upper-level (table) entries are always present with full access; they
/// aggregate permissions for the walk (SDM §28.3.3.2).
const TABLE_FLAGS: u64 = EPT_R | EPT_W | EPT_X;

// ---------------------------------------------------------------------
// Page allocation
// ---------------------------------------------------------------------

/// Frame-page source for EPT table pages. Implemented by kernel frames
/// (`alloc_global`/`free_global`) in production and by a test-local arena in
/// the contract tests — the EPT builder never knows which.
pub trait PageAlloc {
    /// Allocate one zeroed 4 KiB page, returning its host-physical address.
    fn alloc_page(&mut self) -> Option<u64>;
    /// Return a page that came from `alloc_page`.
    fn free_page(&mut self, phys: u64) -> bool;
}

/// The kernel's production allocator: wraps the existing frame allocator
/// (`frame::alloc_global`/`free_global`) and zeroes each page before handing
/// it out — EPT tables must start empty.
pub struct KernelAlloc;

impl PageAlloc for KernelAlloc {
    fn alloc_page(&mut self) -> Option<u64> {
        let phys = unsafe { crate::frame::alloc_global() }?;
        unsafe { ptr::write_bytes(phys as *mut u8, 0, PAGE_SIZE as usize) };
        Some(phys)
    }

    fn free_page(&mut self, phys: u64) -> bool {
        unsafe { crate::frame::free_global(phys) }
    }
}

// ---------------------------------------------------------------------
// The memory grant (the capability)
// ---------------------------------------------------------------------

/// A VM's guest-memory grant: a contiguous range of guest-physical frames
/// the VM's owner was given authority over. This is what the EPT builder
/// checks every mapping against — the capability gate is a map-time refusal,
/// not a runtime hope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemGrant {
    /// First guest-physical address of the grant (page-aligned).
    pub start_gpa: u64,
    /// Number of contiguous 4 KiB frames granted.
    pub frames: u64,
}

impl MemGrant {
    pub const fn new(start_gpa: u64, frames: u64) -> MemGrant {
        MemGrant { start_gpa, frames }
    }

    /// Guest-physical size of the grant in bytes.
    pub fn bytes(&self) -> u64 {
        self.frames * PAGE_SIZE
    }

    /// Does the grant fully cover guest-physical `[gpa, gpa + count*4K)`?
    pub fn contains(&self, gpa: u64, count: u64) -> bool {
        let size = match count.checked_mul(PAGE_SIZE) {
            Some(s) => s,
            None => return false,
        };
        let end = match gpa.checked_add(size) {
            Some(e) => e,
            None => return false,
        };
        let grant_end = self.start_gpa + self.bytes();
        gpa >= self.start_gpa && end <= grant_end && end > gpa
    }

    /// The first guest-physical address past the grant.
    pub fn end_gpa(&self) -> u64 {
        self.start_gpa + self.bytes()
    }
}

// ---------------------------------------------------------------------
// The EPT itself
// ---------------------------------------------------------------------

/// Errors the EPT builder can refuse with — every one is a checked,
/// contract-tested path; none panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EptError {
    /// The allocator ran out of table pages.
    OutOfPages,
    /// A guest or host address was not 4 KiB aligned.
    Misaligned,
    /// The requested guest range overflowed 64-bit arithmetic.
    Overflow,
    /// The guest range is not fully inside the VM's memory grant.
    OutsideGrant,
    /// At least one guest page in the range is already mapped.
    AlreadyMapped,
}

/// A 4-level EPT for one VM. Holds the host-physical root address (the value
/// the EPTP field of the VMCS is built from) and a table-page count so
/// teardown is checkable.
pub struct Ept {
    /// Host-physical address of the PML4 root page.
    root: u64,
    /// Number of EPT table pages currently allocated (stats + teardown check).
    tables: u64,
}

impl Ept {
    /// A brand-new EPT with no root page yet. `map` allocates the root on
    /// first use, so a VM with zero mapped memory allocates zero EPT pages.
    pub const fn new() -> Ept {
        Ept { root: 0, tables: 0 }
    }
}

impl Default for Ept {
    fn default() -> Self {
        Self::new()
    }
}

impl Ept {
    /// Is any memory mapped at all?
    pub fn is_empty(&self) -> bool {
        self.root == 0
    }

    /// Host-physical address of the PML4 root (0 if nothing mapped yet).
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Number of EPT table pages currently allocated.
    pub fn table_pages(&self) -> u64 {
        self.tables
    }

    /// Map `count` contiguous guest pages at `guest_base` to contiguous host
    /// pages at `host_base`. The whole range must be inside `grant` — that
    /// is the capability gate, enforced at map time and proven by tests.
    pub fn map(
        &mut self,
        alloc: &mut impl PageAlloc,
        grant: &MemGrant,
        guest_base: u64,
        host_base: u64,
        count: u64,
        flags: u64,
    ) -> Result<(), EptError> {
        // Overflow is the more fundamental failure: refuse it before
        // alignment, so an astronomically unaligned request reports
        // Overflow (the size itself cannot even be represented).
        let size = match count.checked_mul(PAGE_SIZE) {
            Some(s) => s,
            None => return Err(EptError::Overflow),
        };
        if guest_base.checked_add(size).is_none() {
            return Err(EptError::Overflow);
        }
        if guest_base % PAGE_SIZE != 0 || host_base % PAGE_SIZE != 0 {
            return Err(EptError::Misaligned);
        }
        if count == 0 {
            return Ok(());
        }
        if !grant.contains(guest_base, count) {
            return Err(EptError::OutsideGrant);
        }
        // Refuse to overlap an existing mapping: every page must be free.
        for i in 0..count {
            if self.translate(guest_base + i * PAGE_SIZE).is_some() {
                return Err(EptError::AlreadyMapped);
            }
        }
        if self.root == 0 {
            self.root = alloc.alloc_page().ok_or(EptError::OutOfPages)?;
            self.tables = 1;
        }
        for i in 0..count {
            self.walk_and_set(
                alloc,
                guest_base + i * PAGE_SIZE,
                host_base + i * PAGE_SIZE,
                flags,
            )?;
        }
        Ok(())
    }

    /// Translate a guest-physical address through this EPT to its
    /// host-physical address, or `None` if unmapped. Mirrors the hardware
    /// walk the CPU performs with this EPT active.
    pub fn translate(&self, gpa: u64) -> Option<u64> {
        if self.root == 0 {
            return None;
        }
        unsafe {
            let pml4 = self.root as *const u64;
            let pml4e = read_entry(pml4, idx(gpa, 39));
            if pml4e & EPT_R == 0 {
                return None;
            }
            let pdpt = pml4e & ADDR_MASK;
            let pdpte = read_entry(pdpt as *const u64, idx(gpa, 30));
            if pdpte & EPT_R == 0 {
                return None;
            }
            let pd = pdpte & ADDR_MASK;
            let pde = read_entry(pd as *const u64, idx(gpa, 21));
            if pde & EPT_R == 0 {
                return None;
            }
            let pt = pde & ADDR_MASK;
            let pte = read_entry(pt as *const u64, idx(gpa, 12));
            if pte & EPT_R == 0 {
                return None;
            }
            Some(pte & ADDR_MASK)
        }
    }

    /// Walk down to the leaf entry for `gpa`, allocating intermediate tables
    /// as needed, and write the leaf mapping. `gpa`/`hpa` are page-aligned.
    fn walk_and_set(
        &mut self,
        alloc: &mut impl PageAlloc,
        gpa: u64,
        hpa: u64,
        flags: u64,
    ) -> Result<(), EptError> {
        unsafe {
            let pml4 = self.root as *mut u64;
            let pml4i = idx(gpa, 39);
            let pdpt = self.descend(alloc, pml4, pml4i)?;
            let pdpti = idx(gpa, 30);
            let pd = self.descend(alloc, pdpt, pdpti)?;
            let pdi = idx(gpa, 21);
            let pt = self.descend(alloc, pd, pdi)?;
            let pti = idx(gpa, 12);
            write_entry(pt, pti, (hpa & ADDR_MASK) | flags);
            Ok(())
        }
    }

    /// Read the entry at `table[i]`; if it is not present, allocate a fresh
    /// zeroed table page, link it, and return its address.
    ///
    /// # Safety
    /// `table` must be a live EPT table page. Only called from `walk_and_set`.
    unsafe fn descend(
        &mut self,
        alloc: &mut impl PageAlloc,
        table: *mut u64,
        i: u64,
    ) -> Result<*mut u64, EptError> {
        let entry = read_entry(table, i);
        if entry & EPT_R != 0 {
            return Ok((entry & ADDR_MASK) as *mut u64);
        }
        let page = alloc.alloc_page().ok_or(EptError::OutOfPages)?;
        write_entry(table, i, (page & ADDR_MASK) | TABLE_FLAGS);
        self.tables += 1;
        Ok(page as *mut u64)
    }

    /// Tear the whole EPT down: every table page (PT, PD, PDPT, PML4 root)
    /// returns to the allocator. The mapped *guest* frames are the VM's
    /// grant and are freed separately by VM teardown — this only frees the
    /// translation structures.
    pub fn unmap_all(&mut self, alloc: &mut impl PageAlloc) {
        if self.root == 0 {
            return;
        }
        unsafe {
            let pml4 = self.root as *mut u64;
            for pml4i in 0..ENTRIES {
                let pdpt = read_entry(pml4, pml4i) & ADDR_MASK;
                if pdpt == 0 {
                    continue;
                }
                for pdpti in 0..ENTRIES {
                    let pd = read_entry(pdpt as *const u64, pdpti) & ADDR_MASK;
                    if pd == 0 {
                        continue;
                    }
                    for pdi in 0..ENTRIES {
                        let pt = read_entry(pd as *const u64, pdi) & ADDR_MASK;
                        if pt == 0 {
                            continue;
                        }
                        alloc.free_page(pt);
                        self.tables -= 1;
                    }
                    alloc.free_page(pd);
                    self.tables -= 1;
                }
                alloc.free_page(pdpt);
                self.tables -= 1;
            }
            alloc.free_page(self.root);
            self.tables -= 1;
        }
        self.root = 0;
        debug_assert_eq!(self.tables, 0);
    }
}

/// Entry index for a given bit range of the guest-physical address.
fn idx(gpa: u64, shift: u32) -> u64 {
    (gpa >> shift) & (ENTRIES - 1)
}

/// # Safety
/// `table` must point at a live EPT table page.
unsafe fn read_entry(table: *const u64, i: u64) -> u64 {
    ptr::read_volatile(table.add(i as usize))
}

/// # Safety
/// `table` must point at a live EPT table page.
unsafe fn write_entry(table: *mut u64, i: u64, val: u64) {
    ptr::write_volatile(table.add(i as usize), val);
}

// ---------------------------------------------------------------------
// VMCS-facing encodings (pure, contract-tested)
// ---------------------------------------------------------------------

/// Build the EPTP value for a VMCS from the EPT root's host-physical
/// address (SDM §24.6.11): memory type WB (6) in bits 2:0, EPT enabled
/// (bit 6), page-walk length 4 minus one (3) in bits 11:7, root in bits 51:12.
pub fn eptp(root: u64) -> u64 {
    (root & ADDR_MASK) | (6) | (1 << 6) | (3 << 7)
}

/// A decoded EPT-violation VM-exit (exit reason 28) qualification
/// (SDM §28.2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EptViolation {
    /// The guest-physical address of the faulting access (page-aligned).
    pub guest_phys: u64,
    /// The access that faulted.
    pub access: EptAccess,
    /// The EPT entry for the page was present (the fault is a permission
    /// fault rather than a not-present fault).
    pub present: bool,
}

/// What kind of access faulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EptAccess {
    Read,
    Write,
    Execute,
}

/// Decode the qualification for an EPT-violation exit. Pure: no CPU state
/// touched, so the decode is contract-testable without a VMX CPU.
///
/// SDM layout: bit 0 = read, bit 1 = write, bit 2 = execute access faulted;
/// bit 3 = reserved-bit violation (EPT misconfiguration — caller should
/// treat as a host error); bit 4 = page present (usable); bits 51:32 =
/// guest-physical address.
pub fn decode_ept_violation(qualification: u64) -> EptViolation {
    let write = qualification & 0x2 != 0;
    let exec = qualification & 0x4 != 0;
    let access = if write {
        EptAccess::Write
    } else if exec {
        EptAccess::Execute
    } else {
        EptAccess::Read
    };
    EptViolation {
        guest_phys: (qualification >> 32) & ADDR_MASK,
        access,
        present: qualification & 0x10 != 0,
    }
}

// ---------------------------------------------------------------------
// Tests (pure protocol/encoding logic — no VMX CPU required)
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A heap page that is *really* 4 KiB aligned: `Box<[u64; 512]>` is only
    /// 8-byte aligned, so rounding its address up to a page boundary would
    /// push the fake "physical" page past the end of the allocation.
    #[repr(align(4096))]
    struct Page(#[allow(dead_code)] [u64; 512]);

    /// Test arena: hands out zeroed 4 KiB pages as fake "host physical"
    /// addresses, tracking them so `free_page` really releases them and the
    /// teardown count assertions are meaningful. A `budget` cap simulates
    /// memory pressure (the `OutOfPages` path).
    ///
    /// Each page is a raw allocation (`Box::into_raw`) reclaimed with
    /// `Box::from_raw` on free, so the fake "phys" addresses remain valid
    /// raw memory for the EPT's volatile reads/writes without an active
    /// reference tag (Miri-clean under Stacked Borrows).
    struct TestAlloc {
        pages: Vec<(u64, *mut Page)>,
        budget: Option<usize>,
    }

    impl TestAlloc {
        fn new() -> TestAlloc {
            TestAlloc {
                pages: Vec::new(),
                budget: None,
            }
        }

        fn with_budget(budget: usize) -> TestAlloc {
            TestAlloc {
                pages: Vec::new(),
                budget: Some(budget),
            }
        }

        fn outstanding(&self) -> usize {
            self.pages.len()
        }
    }

    impl Drop for TestAlloc {
        fn drop(&mut self) {
            // Reclaim any pages a test mapped but never unmapped (they were
            // raw-allocated via `Box::into_raw`), so Miri sees no leak.
            for (_, page) in self.pages.drain(..) {
                unsafe {
                    drop(Box::from_raw(page));
                }
            }
        }
    }

    impl PageAlloc for TestAlloc {
        fn alloc_page(&mut self) -> Option<u64> {
            if let Some(b) = self.budget {
                if self.pages.len() >= b {
                    return None;
                }
            }
            let page = Box::into_raw(Box::new(Page([0; ENTRIES as usize])));
            let phys = page as *const Page as u64;
            self.pages.push((phys, page));
            Some(phys)
        }

        fn free_page(&mut self, phys: u64) -> bool {
            match self.pages.iter().position(|(p, _)| *p == phys) {
                Some(i) => {
                    let (_, page) = self.pages.remove(i);
                    unsafe {
                        drop(Box::from_raw(page));
                    }
                    true
                }
                None => false,
            }
        }
    }

    /// 4 MiB grant at 0x1_0000_0000, plus a second grant for tests that
    /// build mappings at higher PML4 indices.
    fn grant() -> MemGrant {
        MemGrant::new(0x1_0000_0000, 1024)
    }

    fn grant_high() -> MemGrant {
        MemGrant::new(0x20_0000_0000, 1024)
    }

    fn host_frame(i: u64) -> u64 {
        (0x10_0000 + i) * PAGE_SIZE
    }

    #[test]
    fn empty_ept_has_no_root_and_translates_nothing() {
        let ept = Ept::new();
        assert!(ept.is_empty());
        assert_eq!(ept.root(), 0);
        assert_eq!(ept.translate(0x1_0000_0000), None);
    }

    #[test]
    fn map_round_trips_contiguous_pages() {
        let mut alloc = TestAlloc::new();
        let mut ept = Ept::new();
        ept.map(
            &mut alloc,
            &grant(),
            0x1_0000_0000,
            host_frame(0),
            8,
            EPT_DEFAULT_FLAGS,
        )
        .unwrap();
        assert_eq!(ept.root() & 0xFFF, 0);
        for i in 0..8u64 {
            assert_eq!(
                ept.translate(0x1_0000_0000 + i * PAGE_SIZE),
                Some(host_frame(i))
            );
        }
        assert_eq!(ept.translate(0x1_0000_8000), None); // first unmapped page past the range
                                                        // 1 PML4 + 1 PDPT + 1 PD + 1 PT for a 32 KiB mapping.
        assert_eq!(ept.table_pages(), 4);
        assert!(!ept.is_empty());
    }

    #[test]
    fn map_crosses_all_four_levels() {
        let mut alloc = TestAlloc::new();
        let mut ept = Ept::new();
        // 0x20_0000_0000 needs PML4 index 2; the 4 KiB leaf is at the bottom
        // of a fresh PDPT/PD/PT chain.
        ept.map(
            &mut alloc,
            &grant_high(),
            0x20_0000_0000,
            host_frame(9),
            1,
            EPT_DEFAULT_FLAGS,
        )
        .unwrap();
        assert_eq!(ept.translate(0x20_0000_0000), Some(host_frame(9)));
        assert_eq!(ept.table_pages(), 4);
        // A second leaf 2 MiB away shares the PML4/PDPT/PD (a PD table
        // spans a whole 1 GiB); only a fresh PT is needed.
        ept.map(
            &mut alloc,
            &grant_high(),
            0x20_0020_0000,
            host_frame(10),
            1,
            EPT_DEFAULT_FLAGS,
        )
        .unwrap();
        assert_eq!(ept.translate(0x20_0020_0000), Some(host_frame(10)));
        assert_eq!(ept.table_pages(), 5);
    }

    #[test]
    fn grant_gate_refuses_outside_memory() {
        let mut alloc = TestAlloc::new();
        let mut ept = Ept::new();
        // Entirely outside the grant.
        assert_eq!(
            ept.map(
                &mut alloc,
                &grant(),
                0x1_0000_0000 + 1024 * PAGE_SIZE,
                host_frame(0),
                1,
                EPT_DEFAULT_FLAGS
            ),
            Err(EptError::OutsideGrant)
        );
        // Partially overlapping the grant edge.
        assert_eq!(
            ept.map(
                &mut alloc,
                &grant(),
                0x1_0000_0000 + 1023 * PAGE_SIZE,
                host_frame(0),
                2,
                EPT_DEFAULT_FLAGS
            ),
            Err(EptError::OutsideGrant)
        );
        // Below the grant start.
        assert_eq!(
            ept.map(
                &mut alloc,
                &grant(),
                0xFFFF_0000,
                host_frame(0),
                1,
                EPT_DEFAULT_FLAGS
            ),
            Err(EptError::OutsideGrant)
        );
        assert!(ept.is_empty(), "refused maps must not allocate anything");
    }

    #[test]
    fn overlapping_mappings_are_refused() {
        let mut alloc = TestAlloc::new();
        let mut ept = Ept::new();
        ept.map(
            &mut alloc,
            &grant(),
            0x1_0000_0000,
            host_frame(0),
            4,
            EPT_DEFAULT_FLAGS,
        )
        .unwrap();
        // Exact overlap.
        assert_eq!(
            ept.map(
                &mut alloc,
                &grant(),
                0x1_0000_0000,
                host_frame(9),
                1,
                EPT_DEFAULT_FLAGS
            ),
            Err(EptError::AlreadyMapped)
        );
        // Interior overlap (second page of an existing 4-page run).
        assert_eq!(
            ept.map(
                &mut alloc,
                &grant(),
                0x1_0000_1000,
                host_frame(9),
                2,
                EPT_DEFAULT_FLAGS
            ),
            Err(EptError::AlreadyMapped)
        );
        // The original mapping is untouched by the refusals.
        for i in 0..4u64 {
            assert_eq!(
                ept.translate(0x1_0000_0000 + i * PAGE_SIZE),
                Some(host_frame(i))
            );
        }
    }

    #[test]
    fn misaligned_and_overflowing_maps_are_refused() {
        let mut alloc = TestAlloc::new();
        let mut ept = Ept::new();
        assert_eq!(
            ept.map(
                &mut alloc,
                &grant(),
                0x1_0000_0001,
                host_frame(0),
                1,
                EPT_DEFAULT_FLAGS
            ),
            Err(EptError::Misaligned)
        );
        assert_eq!(
            ept.map(
                &mut alloc,
                &grant(),
                0x1_0000_0000,
                host_frame(0) + 1,
                1,
                EPT_DEFAULT_FLAGS
            ),
            Err(EptError::Misaligned)
        );
        assert_eq!(
            ept.map(
                &mut alloc,
                &grant(),
                u64::MAX - 8,
                host_frame(0),
                2,
                EPT_DEFAULT_FLAGS
            ),
            Err(EptError::Overflow)
        );
        assert!(ept.is_empty());
    }

    #[test]
    fn zero_length_map_is_a_noop() {
        let mut alloc = TestAlloc::new();
        let mut ept = Ept::new();
        ept.map(
            &mut alloc,
            &grant(),
            0x1_0000_0000,
            host_frame(0),
            0,
            EPT_DEFAULT_FLAGS,
        )
        .unwrap();
        assert!(ept.is_empty());
    }

    #[test]
    fn unmap_returns_every_table_page() {
        let mut alloc = TestAlloc::new();
        let mut ept = Ept::new();
        ept.map(
            &mut alloc,
            &grant(),
            0x1_0000_0000,
            host_frame(0),
            8,
            EPT_DEFAULT_FLAGS,
        )
        .unwrap();
        ept.map(
            &mut alloc,
            &grant_high(),
            0x20_0000_0000,
            host_frame(9),
            1,
            EPT_DEFAULT_FLAGS,
        )
        .unwrap();
        let before = ept.table_pages();
        assert!(before > 0);
        ept.unmap_all(&mut alloc);
        assert!(ept.is_empty());
        assert_eq!(ept.table_pages(), 0);
        assert_eq!(alloc.outstanding(), 0, "all EPT pages must be freed");
        // A torn-down EPT can be reused for a fresh mapping.
        ept.map(
            &mut alloc,
            &grant(),
            0x1_0000_0000,
            host_frame(0),
            1,
            EPT_DEFAULT_FLAGS,
        )
        .unwrap();
        assert_eq!(ept.translate(0x1_0000_0000), Some(host_frame(0)));
    }

    #[test]
    fn double_unmap_is_safe() {
        let mut alloc = TestAlloc::new();
        let mut ept = Ept::new();
        ept.map(
            &mut alloc,
            &grant(),
            0x1_0000_0000,
            host_frame(0),
            1,
            EPT_DEFAULT_FLAGS,
        )
        .unwrap();
        ept.unmap_all(&mut alloc);
        ept.unmap_all(&mut alloc);
        assert_eq!(alloc.outstanding(), 0);
    }

    #[test]
    fn out_of_pages_is_reported_not_panicked() {
        // An arena with zero pages left: the first map cannot even build the
        // PML4 root.
        let mut alloc = TestAlloc::with_budget(0);
        let mut ept = Ept::new();
        assert_eq!(
            ept.map(
                &mut alloc,
                &grant(),
                0x1_0000_0000,
                host_frame(0),
                1,
                EPT_DEFAULT_FLAGS
            ),
            Err(EptError::OutOfPages)
        );
        assert!(ept.is_empty());
    }

    #[test]
    fn eptp_encodes_wb_walk_length_4_and_root() {
        let root = 0x1234_5678_9000u64;
        let ep = eptp(root);
        assert_eq!(ep & 0x7, 6, "memory type WB");
        assert_eq!((ep >> 6) & 1, 1, "EPT enabled");
        assert_eq!((ep >> 7) & 0x1F, 3, "page-walk length 4 minus one");
        assert_eq!(ep & 0x000F_FFFF_FFFF_F000, root);
        // The fields live in disjoint bit ranges: no aliasing.
        assert_eq!(ep, root | 6 | (1 << 6) | (3 << 7));
    }

    #[test]
    fn decode_ept_violation_qualifications() {
        // Write fault on a present page at GPA 0x8000_0000 (bits 51:32).
        let qual = (0x8000_0000u64 << 32) | 0x2 | 0x10;
        let v = decode_ept_violation(qual);
        assert_eq!(v.guest_phys, 0x8000_0000);
        assert_eq!(v.access, EptAccess::Write);
        assert!(v.present);

        // Execute fault on a not-present page (the classic NX-style denial).
        let qual = (0x1000_0000u64 << 32) | 0x4;
        let v = decode_ept_violation(qual);
        assert_eq!(v.guest_phys, 0x1000_0000);
        assert_eq!(v.access, EptAccess::Execute);
        assert!(!v.present);

        // Read fault, low bits beyond the page are ignored by the decode.
        let qual = (0x2000_0000u64 << 32) | 0x1 | 0x10 | 0x8;
        let v = decode_ept_violation(qual);
        assert_eq!(v.guest_phys, 0x2000_0000);
        assert_eq!(v.access, EptAccess::Read);
        assert!(v.present);

        // A write sets access=Write even if read is also set (real CPUs set
        // both for some faults; write is the stricter category).
        let qual = 0x3;
        let v = decode_ept_violation(qual);
        assert_eq!(v.access, EptAccess::Write);
    }

    #[test]
    fn grant_contains_checks_bounds_and_overflow() {
        let g = MemGrant::new(0x1000, 4);
        assert!(g.contains(0x1000, 1));
        assert!(g.contains(0x3000, 1));
        assert!(g.contains(0x1000, 4));
        assert!(!g.contains(0x1000, 5));
        assert!(!g.contains(0x5000, 1));
        assert!(!g.contains(0, 1));
        assert!(!g.contains(0x1000, 0)); // empty range is not "covered"
        let huge = MemGrant::new(0, u64::MAX / PAGE_SIZE);
        assert!(!huge.contains(0, u64::MAX)); // overflow -> false, no panic
    }
}

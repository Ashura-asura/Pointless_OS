//! Centralized validation of caller-supplied pointers (hostile-audit Phase 1,
//! §4: one gate, not a per-syscall habit).
//!
//! A ring-3 syscall argument pointer must name a range fully contained in the
//! CALLER's USER-accessible, PRESENT mappings. The kernel walks the owning
//! task's page tables and refuses any range that touches a kernel-only page,
//! an unmapped page, or — for writes — a non-writable page. No syscall path
//! dereferences a user pointer before this gate has approved the whole range.
//!
//! Kernel-context callers (raw `pml4_phys == 0` — kernel-resident tasks and
//! the test harness) are trusted: their pointers ARE kernel pointers, so the
//! walk is a no-op pass (sanity: non-null). Untrusted ring-3 always runs on a
//! per-user PML4 (`tasks::spawn_user` sets it), so the strict walk applies
//! exactly where it must.
//!
//! Deferred copies (e.g. `ipc_reply` writing into the *caller's* reply buffer
//! while running as the server) pass the OWNING task's PML4 explicitly — a
//! pointer is always validated against the address space it will actually be
//! read from or written to.

/// Page-table entry bits (x86-64).
const PTE_PRESENT: u64 = 1;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_PAGE_SIZE: u64 = 1 << 7;

/// Is `va` present, USER-accessible, and (if `writable`) writable in the
/// address space rooted at `pml4_phys`? Handles 4 KiB, 2 MiB, and 1 GiB
/// pages. `pml4_phys` must be non-zero and a valid physical address of a
/// populated PML4.
///
/// # Safety
/// `pml4_phys` must name a real, identity-mapped page table owned by the
/// kernel (the kernel runs identity-mapped, so physical == virtual here).
/// The table hierarchy is immutable while a task is not running (a blocked
/// caller's mappings cannot change), so the walk is stable.
fn user_page(pml4_phys: u64, va: u64, writable: bool) -> bool {
    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx = ((va >> 21) & 0x1FF) as usize;
    let pt_idx = ((va >> 12) & 0x1FF) as usize;
    unsafe {
        let pml4 = *(pml4_phys as *const u64).add(pml4_idx);
        if pml4 & PTE_PRESENT == 0 {
            return false;
        }
        let pdpt = *((pml4 & !0xFFF) as *const u64).add(pdpt_idx);
        if pdpt & PTE_PRESENT == 0 {
            return false;
        }
        if pdpt & PTE_PAGE_SIZE != 0 {
            // 1 GiB page: the PDPT entry is the leaf.
            return pdpt & PTE_USER != 0 && (!writable || pdpt & PTE_WRITABLE != 0);
        }
        let pd = *((pdpt & !0xFFF) as *const u64).add(pd_idx);
        if pd & PTE_PRESENT == 0 {
            return false;
        }
        if pd & PTE_PAGE_SIZE != 0 {
            // 2 MiB page: the PD entry is the leaf.
            return pd & PTE_USER != 0 && (!writable || pd & PTE_WRITABLE != 0);
        }
        let pt = *((pd & !0xFFF) as *const u64).add(pt_idx);
        pt & PTE_PRESENT != 0
            && pt & PTE_USER != 0
            && (!writable || pt & PTE_WRITABLE != 0)
    }
}

/// Validate the range `[va, va+len)` against the address space rooted at
/// `pml4_phys`. Returns true when:
///   - `len == 0` (nothing to touch), or
///   - the address space is the kernel's own (`pml4_phys == 0`): the caller
///     is kernel-context and trusted (sanity: non-null only), or
///   - every page the range crosses is present, USER, and (if `writable`)
///     writable.
/// An overflowing range or any non-conforming page is refused.
pub fn validate_range(pml4_phys: u64, va: u64, len: usize, writable: bool) -> bool {
    if len == 0 {
        return true;
    }
    if pml4_phys == 0 {
        return va != 0;
    }
    let Some(end) = va.checked_add(len as u64) else {
        return false;
    };
    let mut page = va & !0xFFF;
    while page < end {
        if !user_page(pml4_phys, page, writable) {
            return false;
        }
        match page.checked_add(0x1000) {
            Some(p) => page = p,
            None => return false, // the range runs past the top of the address space
        }
    }
    true
}

/// The raw per-user PML4 of the current task, or 0 when the current context
/// runs on the kernel page tables (kernel-resident task, idle, or the test
/// harness).
pub fn current_user_pml4() -> u64 {
    crate::tasks::current_user_pml4_phys()
}

/// Copy `dst.len()` bytes from the caller's buffer at `va` (validated in the
/// address space rooted at `pml4_phys`) into kernel memory `dst`. Returns
/// false on any invalid range; nothing is copied on failure.
///
/// # Safety
/// `pml4_phys` must be valid per `user_page`. On success `[va, va+len)` is
/// guaranteed to be present and user-readable.
pub unsafe fn copy_from_user(pml4_phys: u64, dst: &mut [u8], va: u64) -> bool {
    if !validate_range(pml4_phys, va, dst.len(), false) {
        return false;
    }
    core::ptr::copy_nonoverlapping(va as *const u8, dst.as_mut_ptr(), dst.len());
    true
}

/// Copy `src.len()` bytes from kernel memory `src` into the caller's buffer
/// at `va` (validated in the address space rooted at `pml4_phys`). Returns
/// false on any invalid range (including a non-writable page); nothing is
/// copied on failure.
///
/// # Safety
/// `pml4_phys` must be valid per `user_page`. On success `[va, va+len)` is
/// guaranteed to be present, user-writable, and writable.
pub unsafe fn copy_to_user(pml4_phys: u64, va: u64, src: &[u8]) -> bool {
    if !validate_range(pml4_phys, va, src.len(), true) {
        return false;
    }
    core::ptr::copy_nonoverlapping(src.as_ptr(), va as *mut u8, src.len());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // A synthetic page-table hierarchy, all statics (page-aligned like real
    // tables — the walker masks the low 12 bits of every table address):
    // PML4[0] -> PDPT[0] -> PD[0] -> PT, with a 2 MiB huge page at PD[1] and
    // a read-only user page at PT[1]. Tests the walk and the gate without
    // needing the global frame allocator (which only exists after boot-time
    // `init_global`).
    #[repr(align(4096))]
    struct Table([u64; 512]);
    #[repr(align(4096))]
    struct Bytes([u8; 8]);
    static mut T_PML4: Table = Table([0; 512]);
    static mut T_PDPT: Table = Table([0; 512]);
    static mut T_PD: Table = Table([0; 512]);
    static mut T_PT: Table = Table([0; 512]);
    static mut T_BUF: Bytes = Bytes([0; 8]);

    /// Wire the synthetic hierarchy and return the root's address. The mapped
    /// pages use FIXED virtual addresses in the first 2 MiB region
    /// (VA 0x100000 = PT index 256), backed by the statics through the
    /// identity map:
    ///   VA 0x100000  -> T_BUF  (user, writable)
    ///   VA 0x101000  -> T_BUF  (user, read-only)
    ///   VA 0x102000  -> unmapped
    ///   VA 0x40201000 -> mid-page of the 2 MiB user huge page at PD index 1
    fn wired_root() -> u64 {
        unsafe {
            T_PML4.0[0] = core::ptr::addr_of!(T_PDPT) as u64 | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            T_PDPT.0[0] = core::ptr::addr_of!(T_PD) as u64 | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            // PD[0] -> PT; PD[1] = a 2 MiB huge USER page (VA 0x0020_0000).
            T_PD.0[0] = core::ptr::addr_of!(T_PT) as u64 | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            T_PD.0[1] = 0x0020_0000 | PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_PAGE_SIZE;
            // PT[0x100] maps VA 0x100000 -> T_BUF, writable and user-accessible.
            T_PT.0[0x100] = core::ptr::addr_of!(T_BUF) as u64 | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            // PT[0x101] maps VA 0x101000 -> T_BUF too, but read-only (no
            // WRITABLE): reads pass, writes must be refused.
            T_PT.0[0x101] = core::ptr::addr_of!(T_BUF) as u64 | PTE_PRESENT | PTE_USER;
            // PT[0x102] (VA 0x102000) is unmapped.
            core::ptr::addr_of!(T_PML4) as u64
        }
    }

    #[test]
    fn user_ptr_gate_accepts_only_user_present_writable_ranges() {
        let _g = crate::kernel_state_guard();
        let root = wired_root();
        // A user, present, writable page accepts reads and writes.
        assert!(validate_range(root, 0x100000, 8, false));
        assert!(validate_range(root, 0x100000, 8, true));
        // Crossing into an unmapped PT entry is refused.
        assert!(!validate_range(root, 0x101000, 0x1000 + 1, false), "crosses into an unmapped page");
        assert!(!validate_range(root, 0x102000, 4, false));
        // The 2 MiB huge page is user-accessible mid-page.
        assert!(validate_range(root, 0x0020_1000, 0x1000, true), "2 MiB USER huge page");
        // The read-only user page: reads pass, writes are refused.
        assert!(validate_range(root, 0x101000, 4, false));
        assert!(
            !validate_range(root, 0x101000, 4, true),
            "a non-writable user page must refuse writes"
        );
        // Empty ranges always pass.
        assert!(validate_range(root, 0, 0, true));
        // Overflowing ranges are refused, never wrapped.
        assert!(!validate_range(root, u64::MAX - 3, 4, false));
    }

    #[test]
    fn copy_helpers_land_bytes_only_through_approved_ranges() {
        let _g = crate::kernel_state_guard();
        unsafe {
            // A SECOND, dedicated hierarchy wired at the REAL address of
            // T_BUF: the copy helpers move bytes through the identity map, so
            // the mapped VA must be where the static actually lives. Reading
            // or writing any other VA in this root is refused (unmapped).
            #[repr(align(4096))]
            struct CTable([u64; 512]);
            static mut C_PML4: CTable = CTable([0; 512]);
            static mut C_PDPT: CTable = CTable([0; 512]);
            static mut C_PD: CTable = CTable([0; 512]);
            static mut C_PT: CTable = CTable([0; 512]);
            let buf_addr = core::ptr::addr_of!(T_BUF) as u64;
            let (pm, pp, pd, pt) = (
                ((buf_addr >> 39) & 0x1FF) as usize,
                ((buf_addr >> 30) & 0x1FF) as usize,
                ((buf_addr >> 21) & 0x1FF) as usize,
                ((buf_addr >> 12) & 0x1FF) as usize,
            );
            C_PML4.0[pm] = core::ptr::addr_of!(C_PDPT) as u64 | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            C_PDPT.0[pp] = core::ptr::addr_of!(C_PD) as u64 | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            C_PD.0[pd] = core::ptr::addr_of!(C_PT) as u64 | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            C_PT.0[pt] = buf_addr | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            let copy_root = core::ptr::addr_of!(C_PML4) as u64;

            // copy_from_user reads the mapped user page into kernel memory.
            let mut dst = [0u8; 8];
            core::ptr::write(core::ptr::addr_of_mut!(T_BUF.0), [1, 2, 3, 4, 5, 6, 7, 8]);
            assert!(copy_from_user(copy_root, &mut dst, buf_addr));
            assert_eq!(dst, [1, 2, 3, 4, 5, 6, 7, 8]);
            // copy_to_user writes a kernel buffer into the mapped user page.
            assert!(copy_to_user(copy_root, buf_addr, &[9, 9, 9]));
            let buf_bytes = core::ptr::read(core::ptr::addr_of!(T_BUF.0));
            assert_eq!(&buf_bytes[..3], &[9, 9, 9]);
            // Any OTHER VA in this root is unmapped: refused, no crash, and —
            // critically — nothing lands anywhere.
            let before = core::ptr::read(core::ptr::addr_of!(T_BUF.0));
            assert!(!copy_to_user(copy_root, 0x100000, &[0xEE, 0xEE]));
            assert!(!copy_from_user(copy_root, &mut dst, 0x102000));
            assert_eq!(
                core::ptr::read(core::ptr::addr_of!(T_BUF.0)),
                before,
                "no partial write on refusal"
            );
        }
    }

    #[test]
    fn kernel_context_callers_bypass_the_walk() {
        let _g = crate::kernel_state_guard();
        // pml4_phys == 0 means kernel-context: trusted, non-null pointers pass.
        assert!(validate_range(0, 0x1000, 4, false));
        assert!(validate_range(0, 0x1000, 4, true));
        // A null pointer is still refused.
        assert!(!validate_range(0, 0, 4, false));
    }
}
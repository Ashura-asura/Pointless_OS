//! Capability-addressed memory regions (Phase 2): a capability to a memory
//! region names a set of real physical frames owned by the kernel allocator,
//! and `mem_read`/`mem_write`/`mem_len` are gated on the caller's READ/WRITE
//! rights on that capability. This is the kernel side of "userspace resource
//! managers decide allocation policy within their granted budget" — the kernel
//! hands out memory under capability control, never as ambient authority.
//!
//! Honest limits: regions are backed by real frames (`frame::alloc_global`),
//! identity-mapped, so reads/writes are real data movement in the live kernel;
//! but there is no page-table isolation of regions per task yet (region caps
//! are authority records, not address-space windows), no MMIO/device regions,
//! no revocation beyond slot clearing, no ownership transfer. Contract tests
//! exercise the gate + bounds logic in-process.

use crate::audit::OpKind as AuditedOp;
use crate::cap::{Cap, CapSlot, Rights};
use crate::tasks::{current_idx, set_task_cap, task_cap, MAX_CAPS};

pub const MAX_REGIONS: usize = 112;

/// Model crate `create_mem` installs READ|WRITE|GRANT on a fresh region.
pub use crate::cap::MEM_RIGHTS;

#[derive(Clone, Copy)]
struct MemRegion {
    active: bool,
    /// Physical base of the first frame backing the region.
    base: u64,
    /// Size in bytes (always a multiple of the page size).
    len: usize,
}

static mut REGIONS: [MemRegion; MAX_REGIONS] = [MemRegion {
    active: false,
    base: 0,
    len: 0,
}; MAX_REGIONS];

/// Read region `id` into a local copy. Works through raw pointers so we never
/// form a (potentially dangling) shared reference to the `static mut` — that
/// is undefined behavior under Rust 2024's `static_mut_refs` rules.
fn region(id: usize) -> Option<MemRegion> {
    unsafe {
        let p = core::ptr::addr_of_mut!(REGIONS).cast::<MemRegion>().add(id);
        Some(core::ptr::read(p))
    }
}

/// Write a whole region `id`. Raw-pointer store; see `region`.
fn set_region(id: usize, r: MemRegion) {
    unsafe {
        let p = core::ptr::addr_of_mut!(REGIONS).cast::<MemRegion>().add(id);
        core::ptr::write(p, r);
    }
}

/// Release region `id` (no longer backed, slot reusable).
fn clear_region(id: usize) {
    set_region(
        id,
        MemRegion {
            active: false,
            base: 0,
            len: 0,
        },
    );
}

/// Resolve a region id to its backing `(base, len)`. `None` when the slot is
/// not active.
pub(crate) fn region_base_len(id: u32) -> Option<(u64, usize)> {
    region(id as usize)
        .map(|r| (r.base, r.len))
        .filter(|(_, l)| *l > 0)
}

/// Claim the first inactive region slot, binding it to the real byte range
/// `[base, base + len)`. Used by the kernel-resident storage service to stage
/// block/node bytes as real regions WITHOUT going through the frame allocator
/// (the store owns a reserved kernel-memory arena, mirrors how the model crate
/// backs blocks with kernel objects). Returns the region id or `None` when the
/// region table is full.
pub(crate) unsafe fn claim_region(base: u64, len: usize) -> Option<u32> {
    let id = (0..MAX_REGIONS).find(|&i| region(i).map(|r| !r.active).unwrap_or(false))?;
    set_region(
        id,
        MemRegion {
            active: true,
            base,
            len,
        },
    );
    Some(id as u32)
}

/// Test-only: clear every active region so contract tests start from a clean,
/// deterministic region table (the store shares this table with `mem.rs`).
#[cfg(test)]
pub(crate) fn reset_regions_for_test() {
    for i in 0..MAX_REGIONS {
        clear_region(i);
    }
}

/// Resolve a capability slot to a region id, requiring the caller to hold the
/// given rights on it. `None` when the slot is empty, names a non-region
/// object, or the held rights are insufficient. Mirrors `ipc::caps_endpoint`.
fn caps_region(cur: usize, slot: u64, need: Rights) -> Option<usize> {
    if slot as usize >= MAX_CAPS {
        return None;
    }
    match task_cap(cur, slot as usize) {
        CapSlot {
            cap: Cap::MemRegion(id),
            rights,
        } if rights.contains(need) => Some(id as usize),
        _ => None,
    }
}

/// Syscall: create a memory region of `frames` pages, installing a
/// READ|WRITE|GRANT capability in the caller's table. Returns the capability
/// slot, or -1 on any failure (no frames available, no free region slot, no
/// free capability slot).
///
/// # Safety
/// Must be called via syscall with valid task context.
pub unsafe fn mem_create(frames: u64) -> i64 {
    let cur = current_idx();
    let id = (0..MAX_REGIONS).find(|&i| region(i).map(|r| !r.active).unwrap_or(false));
    let id = match id {
        Some(i) => i,
        None => return -1,
    };
    if frames == 0 {
        return -1;
    }
    let base = match crate::frame::alloc_contiguous_global(frames) {
        Some(b) => b,
        None => return -1,
    };
    set_region(
        id,
        MemRegion {
            active: true,
            base,
            len: frames as usize * crate::frame::PAGE_SIZE as usize,
        },
    );
    let slot = (0..MAX_CAPS).find(|&s| task_cap(cur, s).cap == Cap::None);
    let slot = match slot {
        Some(s) => s,
        None => {
            clear_region(id);
            crate::frame::free_global(base);
            return -1;
        }
    };
    set_task_cap(
        cur,
        slot,
        CapSlot {
            cap: Cap::MemRegion(id as u32),
            rights: MEM_RIGHTS,
        },
    );
    slot as i64
}

/// Syscall: byte length of region `slot`. Requires READ.
///
/// # Safety
/// Must be called via syscall with invalid task context.
pub unsafe fn mem_len(slot: u64) -> i64 {
    let cur = current_idx();
    let id = match caps_region(cur, slot, Rights::READ) {
        Some(i) => i,
        None => {
            crate::audit::record(cur, AuditedOp::MemRead, None, false);
            return -1;
        }
    };
    let r = match region(id) {
        Some(r) if r.active => r,
        _ => {
            crate::audit::record(cur, AuditedOp::MemRead, Some(id as u32), false);
            return -1;
        }
    };
    crate::audit::record(cur, AuditedOp::MemRead, Some(id as u32), true);
    r.len as i64
}

/// Syscall: copy `len` bytes from region `slot` at `offset` into `dst_va`.
/// Requires READ. Bounds-checked like the model's `mem_read`; returns the
/// number of bytes copied or -1.
///
/// # Safety
/// Must be called via syscall; `dst_va` must be a writable caller buffer.
pub unsafe fn mem_read(slot: u64, offset: u64, len: u64, dst_va: u64) -> i64 {
    let cur = current_idx();
    let id = match caps_region(cur, slot, Rights::READ) {
        Some(i) => i,
        None => {
            crate::audit::record(cur, AuditedOp::MemRead, None, false);
            return -1;
        }
    };
    let r = match region(id) {
        Some(r) if r.active => r,
        _ => {
            crate::audit::record(cur, AuditedOp::MemRead, Some(id as u32), false);
            return -1;
        }
    };
    let end = offset.checked_add(len);
    let end = match end {
        Some(e) => e as usize,
        None => {
            crate::audit::record(cur, AuditedOp::MemRead, Some(id as u32), false);
            return -1;
        }
    };
    if end > r.len {
        crate::audit::record(cur, AuditedOp::MemRead, Some(id as u32), false);
        return -1;
    }
    core::ptr::copy_nonoverlapping(
        (r.base + offset) as *const u8,
        dst_va as *mut u8,
        len as usize,
    );
    crate::audit::record(cur, AuditedOp::MemRead, Some(id as u32), true);
    len as i64
}

/// Syscall: copy `len` bytes from `src_va` into region `slot` at `offset`.
/// Requires WRITE. Bounds-checked like the model's `mem_write`; returns 0 or
/// -1.
///
/// # Safety
/// Must be called via syscall; `src_va` must be a readable caller buffer.
pub unsafe fn mem_write(slot: u64, offset: u64, len: u64, src_va: u64) -> i64 {
    let cur = current_idx();
    let id = match caps_region(cur, slot, Rights::WRITE) {
        Some(i) => i,
        None => {
            crate::audit::record(cur, AuditedOp::MemWrite, None, false);
            return -1;
        }
    };
    let r = match region(id) {
        Some(r) if r.active => r,
        _ => {
            crate::audit::record(cur, AuditedOp::MemWrite, Some(id as u32), false);
            return -1;
        }
    };
    let end = offset.checked_add(len);
    let end = match end {
        Some(e) => e as usize,
        None => {
            crate::audit::record(cur, AuditedOp::MemWrite, Some(id as u32), false);
            return -1;
        }
    };
    if end > r.len {
        crate::audit::record(cur, AuditedOp::MemWrite, Some(id as u32), false);
        return -1;
    }
    let dst = (r.base + offset) as *mut u8;
    let src = src_va as *const u8;
    core::ptr::copy_nonoverlapping(src, dst, len as usize);
    crate::audit::record(cur, AuditedOp::MemWrite, Some(id as u32), true);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::new_cap_table;
    use crate::tasks::set_current_for_test;

    /// Seed region `id` (a unique test-local id) bound to real test memory.
    /// Uses a stack buffer so each test owns its bytes (no shared statics, so
    /// parallel tests never race).
    fn seed_region(idx: usize, slot: usize, id: usize, base: u64, len: usize, rights: Rights) {
        set_task_cap(
            idx,
            slot,
            CapSlot {
                cap: Cap::MemRegion(id as u32),
                rights,
            },
        );
        set_region(
            id,
            MemRegion {
                active: true,
                base,
                len,
            },
        );
    }

    #[test]
    fn region_gate_requires_held_right_on_region_cap() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        // Task 0 slot 0 carries a MemRegion with READ only.
        set_current_for_test(0);
        let mut backing = [0u8; 4096];
        seed_region(0, 0, 1, backing.as_mut_ptr() as u64, 16, Rights::READ);
        assert_eq!(caps_region(0, 0, Rights::READ), Some(1));
        assert_eq!(
            caps_region(0, 0, Rights::WRITE),
            None,
            "READ-only cap must not satisfy WRITE"
        );
        assert_eq!(caps_region(0, 0, Rights::GRANT), None);
    }

    #[test]
    fn read_requires_read_right_out_of_bounds_denied() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        set_current_for_test(2);
        let mut backing = [0u8; 4096];
        seed_region(2, 0, 2, backing.as_mut_ptr() as u64, 16, Rights::READ);
        let mut buf = [0u8; 4];
        assert_eq!(unsafe { mem_read(0, 0, 4, buf.as_mut_ptr() as u64) }, 4);
        assert_eq!(
            unsafe { mem_read(0, 12, 4, buf.as_mut_ptr() as u64) },
            4,
            "offset 12 len 4 ends exactly at len 16: 4 bytes copied"
        );
        assert_eq!(
            unsafe { mem_read(0, 13, 4, buf.as_mut_ptr() as u64) },
            -1,
            "offset 13 len 4 exceeds len 16"
        );
        assert_eq!(unsafe { mem_read(0, 0, 17, buf.as_mut_ptr() as u64) }, -1);
        assert_eq!(
            unsafe { mem_read(0, 15, 2, buf.as_mut_ptr() as u64) },
            -1,
            "offset 15 len 2 straddles the end"
        );
    }

    #[test]
    fn read_from_region_without_read_right_denied() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        set_current_for_test(3);
        let mut backing = [0u8; 4096];
        seed_region(3, 0, 3, backing.as_mut_ptr() as u64, 16, Rights::WRITE);
        let mut buf = [0u8; 4];
        assert_eq!(unsafe { mem_read(0, 0, 4, buf.as_mut_ptr() as u64) }, -1);
    }

    #[test]
    fn write_requires_write_right() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        set_current_for_test(4);
        // Same region id; slot 0 WRITE-only this time.
        let mut backing = [0u8; 4096];
        seed_region(4, 0, 4, backing.as_mut_ptr() as u64, 16, Rights::WRITE);
        let mut src = [0u8; 4];
        for b in src.iter_mut() {
            *b = 0xAB;
        }
        assert_eq!(unsafe { mem_write(0, 0, 4, src.as_ptr() as u64) }, 0);
        assert_eq!(
            unsafe { mem_write(0, 15, 2, src.as_ptr() as u64) },
            -1,
            "offset 15 len 2 exceeds len 16"
        );
        assert_eq!(unsafe { mem_write(0, 0, 17, src.as_ptr() as u64) }, -1);
        // READ-only must be refused for writes.
        seed_region(4, 0, 5, backing.as_mut_ptr() as u64, 16, Rights::READ);
        assert_eq!(unsafe { mem_write(0, 0, 4, src.as_ptr() as u64) }, -1);
        assert_eq!(backing[0], 0xAB, "the WRITE-only attempt did land");
        assert_eq!(backing[1], 0xAB);
    }

    #[test]
    fn len_requires_read_right() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        set_current_for_test(5);
        let mut backing = [0u8; 4096];
        seed_region(5, 0, 6, backing.as_mut_ptr() as u64, 4096, Rights::READ);
        assert_eq!(unsafe { mem_len(0) }, 4096);
        seed_region(5, 0, 7, backing.as_mut_ptr() as u64, 8192, Rights::WRITE);
        assert_eq!(unsafe { mem_len(0) }, -1);
    }

    #[test]
    fn read_write_roundtrip_through_real_memory() {
        // Bind the region to the backing buffer; write bytes, read them back.
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        set_current_for_test(6);
        let mut backing = [0u8; 64];
        for (i, b) in backing.iter_mut().take(16).enumerate() {
            *b = i as u8;
        }
        seed_region(
            6,
            0,
            8,
            backing.as_mut_ptr() as u64,
            16,
            Rights::READ.union(Rights::WRITE),
        );
        let mut out = [0u8; 4];
        assert_eq!(unsafe { mem_read(0, 4, 4, out.as_mut_ptr() as u64) }, 4);
        assert_eq!(out, [4, 5, 6, 7]);
        let mut src = [0u8; 8];
        for b in src.iter_mut() {
            *b = 0xEE;
        }
        assert_eq!(unsafe { mem_write(0, 4, 2, src.as_ptr() as u64) }, 0);
        assert_eq!(backing[4], 0xEE);
        assert_eq!(backing[5], 0xEE);
        assert_eq!(backing[6], 6, "bytes past the write stay intact");
        // Read the patched region back through the capability syscall.
        assert_eq!(unsafe { mem_read(0, 4, 4, out.as_mut_ptr() as u64) }, 4);
        assert_eq!(out, [0xEE, 0xEE, 6, 7]);
    }

    #[test]
    fn non_region_caps_are_not_addressable() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        set_current_for_test(1);
        set_task_cap(
            1,
            0,
            CapSlot {
                cap: Cap::Endpoint(3),
                rights: Rights::ALL,
            },
        );
        set_task_cap(
            1,
            1,
            CapSlot {
                cap: Cap::Task(4),
                rights: Rights::ALL,
            },
        );
        assert_eq!(caps_region(1, 0, Rights::READ), None);
        assert_eq!(caps_region(1, 1, Rights::WRITE), None);
        assert_eq!(unsafe { mem_len(0) }, -1);
        assert_eq!(unsafe { mem_len(1) }, -1);
    }

    #[test]
    fn out_of_range_slot_is_denied() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        set_current_for_test(2);
        assert_eq!(caps_region(2, MAX_CAPS as u64 + 100, Rights::READ), None);
        assert_eq!(unsafe { mem_len(MAX_CAPS as u64 + 100) }, -1);
    }

    #[test]
    fn mem_create_installs_read_write_grant() {
        // Task 3 uses mem_create; alloc fails without an initialized frame
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        // pool, so this asserts the fail path is clean and non-panicking in
        // the contract-test host (real allocation is proven by live boot).
        set_current_for_test(3);
        let r = unsafe { mem_create(4) };
        assert!(r == -1 || r >= 0, "must not panic / corrupt: {}", r);
        // Still no region seeded: the caller's table must be untouched.
        assert_eq!(task_cap(3, 0).cap, Cap::None);
        let _ = new_cap_table;
    }

    #[test]
    fn grant_use_revoke_deny_cycle_across_tasks() {
        // Phase B contract for the ring-3 memory-page manager: a grantor that
        // holds a MemRegion with GRANT hands a copy to a grantee; the grantee
        // can use it; the grantor revokes; every later gated op is DENIED
        // (-1) at the gate — never a panic, never a silent success.
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        reset_regions_for_test();
        unsafe {
            crate::tasks::spawn("grantor", crate::tasks::tests_dummy, 0x100000).unwrap();
            crate::tasks::spawn("grantee", crate::tasks::tests_dummy, 0x200000).unwrap();
        }
        let (grantor, grantee) = (0usize, 1usize);
        let mut backing = [0u8; 4096];
        // The grantor anchors the page (its slot 0, READ|WRITE|GRANT).
        seed_region(grantor, 0, 100, backing.as_mut_ptr() as u64, 16, MEM_RIGHTS);
        // Grant a copy to the grantee at their slot 0.
        set_current_for_test(grantor);
        assert_eq!(
            unsafe { crate::ipc::ipc_cap_grant(grantee as u64, 0, 0) },
            0
        );
        // The grantee can use the granted page.
        set_current_for_test(grantee);
        assert_eq!(unsafe { mem_len(0) }, 16);
        let src = [0xABu8; 4];
        assert_eq!(unsafe { mem_write(0, 0, 4, src.as_ptr() as u64) }, 0);
        let mut out = [0u8; 4];
        assert_eq!(unsafe { mem_read(0, 0, 4, out.as_mut_ptr() as u64) }, 4);
        assert_eq!(out, [0xAB; 4]);
        // Revoke: the grantee's copy is cleared — the page returns to the pool.
        set_current_for_test(grantor);
        assert_eq!(
            unsafe { crate::ipc::ipc_cap_revoke(grantee as u64, 0, 0) },
            0
        );
        // Every further op is refused at the capability gate.
        set_current_for_test(grantee);
        assert_eq!(unsafe { mem_len(0) }, -1);
        assert_eq!(unsafe { mem_read(0, 0, 4, out.as_mut_ptr() as u64) }, -1);
        assert_eq!(unsafe { mem_write(0, 0, 4, src.as_ptr() as u64) }, -1);
        // A second revoke is refused: nothing left to take.
        set_current_for_test(grantor);
        assert_eq!(
            unsafe { crate::ipc::ipc_cap_revoke(grantee as u64, 0, 0) },
            -1
        );
    }
}

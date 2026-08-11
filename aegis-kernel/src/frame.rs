//! Physical frame allocator, fed by the boot-info memory map.
//!
//! A single bitmap covers the whole 4 GiB address space (1 MiB frames,
//! 128 KiB of BSS). Every frame starts "used"; `init` clears the bits for
//! CONVENTIONAL ranges from the boot-info handoff, then re-sets the
//! reserved regions. Allocation hands out the lowest free frame; freeing
//! returns it to the pool.
//!
//! Honest limits: the bitmap only covers the first 4 GiB (frames above
//! are never handed out); only UEFI CONVENTIONAL memory is considered
//! usable (bootloader/firmware regions are not reclaimed yet); and the
//! kernel-image reservation comes from the loader-computed `image_end`
//! in the handoff, capped at [0x0, max(image_end, 0x11000)) so the
//! boot-info page itself is always protected.

use crate::boot_info::{BootInfo, TYPE_CONVENTIONAL};

pub const PAGE_SIZE: u64 = 4096;
/// Frames in the address space we cover (4 GiB / 4 KiB).
pub const MAX_FRAMES: u64 = 1 << 20;
pub const FRAME_WORDS: usize = (MAX_FRAMES / 64) as usize;

/// The boot-info handoff page (0x10000..0x11000) must never be handed out
/// even if the map marks it conventional.
const BOOT_INFO_RESERVE_END: u64 = 0x1_1000;

/// Bitmap allocator over a borrowed word slice (works both on the kernel's
/// static `BITMAP` and on a test-local buffer).
pub struct FrameAllocator<'a> {
    bitmap: &'a mut [u64],
    total: u64,
    free: u64,
}

impl<'a> FrameAllocator<'a> {
    /// Wrap a bitmap that starts fully-used (all bits set).
    pub const fn empty(bitmap: &'a mut [u64]) -> Self {
        Self {
            bitmap,
            total: 0,
            free: 0,
        }
    }

    /// Mark conventional ranges usable, then restore the reserved regions
    /// (kernel image per the handoff's `image_end`, plus the boot-info
    /// page itself).
    pub fn init(&mut self, info: &BootInfo) {
        for e in info.entries.iter() {
            if e.ty != TYPE_CONVENTIONAL {
                continue;
            }
            let start = e.base / PAGE_SIZE;
            let end = (e.base / PAGE_SIZE).saturating_add(e.pages).min(MAX_FRAMES);
            if end > start {
                clear_bits(self.bitmap, start, end);
            }
        }
        let kernel_end = info.image_end.max(BOOT_INFO_RESERVE_END);
        set_bits(self.bitmap, 0, kernel_end / PAGE_SIZE);
        self.total = self
            .bitmap
            .iter()
            .fold(0u64, |acc, w| acc + w.count_zeros() as u64);
        self.free = self.total;
    }

    /// Claim the lowest free frame, returning its physical address.
    pub fn alloc(&mut self) -> Option<u64> {
        if self.free == 0 {
            return None;
        }
        for (wi, word) in self.bitmap.iter().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros() as u64;
                self.bitmap[wi] |= 1u64 << bit;
                self.free -= 1;
                return Some(((wi as u64 * 64) + bit) * PAGE_SIZE);
            }
        }
        None
    }

    /// Claim `n` consecutive free frames, returning the physical address of
    /// the first. Fails if no run of `n` exists.
    pub fn alloc_contiguous(&mut self, n: u64) -> Option<u64> {
        if n == 0 || self.free < n {
            return None;
        }
        let mut run: u64 = 0;
        let mut run_start: u64 = 0;
        for (wi, word) in self.bitmap.iter().enumerate() {
            for bit in 0..64u32 {
                let frame = wi as u64 * 64 + bit as u64;
                if frame >= MAX_FRAMES {
                    return None;
                }
                if word >> bit & 1 == 0 {
                    if run == 0 {
                        run_start = frame;
                    }
                    run += 1;
                    if run == n {
                        set_bits(self.bitmap, run_start, frame + 1);
                        self.free -= n;
                        return Some(run_start * PAGE_SIZE);
                    }
                } else {
                    run = 0;
                }
            }
        }
        None
    }

    /// Return a frame to the pool. `false` if it was never allocated or is
    /// outside the covered address space.
    pub fn free(&mut self, phys: u64) -> bool {
        let frame = phys / PAGE_SIZE;
        if frame >= MAX_FRAMES {
            return false;
        }
        let wi = (frame / 64) as usize;
        let bit = (frame % 64) as u32;
        if wi >= self.bitmap.len() || self.bitmap[wi] >> bit & 1 == 0 {
            return false;
        }
        self.bitmap[wi] &= !(1u64 << bit);
        self.free += 1;
        true
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.total, self.free)
    }

    /// Is `phys` a frame the allocator considers usable right now?
    pub fn is_free(&self, phys: u64) -> bool {
        let frame = phys / PAGE_SIZE;
        if frame >= MAX_FRAMES {
            return false;
        }
        let wi = (frame / 64) as usize;
        let bit = (frame % 64) as u32;
        wi < self.bitmap.len() && self.bitmap[wi] >> bit & 1 == 0
    }
}

/// Clear bits [start, end) (frame indices) in a fully-used bitmap.
/// Returns the number of bits that were set before clearing.
fn clear_bits(bitmap: &mut [u64], start: u64, end: u64) -> u64 {
    let mut changed = 0u64;
    let mut f = start;
    while f < end {
        let wi = (f / 64) as usize;
        if wi >= bitmap.len() {
            break;
        }
        let bit = (f % 64) as u32;
        let room = 64 - bit as u64;
        let span = (end - f).min(room) as u32;
        let mask = bit_mask(bit, span);
        changed += (bitmap[wi] & mask).count_ones() as u64;
        bitmap[wi] &= !mask;
        f += span as u64;
    }
    changed
}

/// Set bits [start, end) (frame indices) in the bitmap.
fn set_bits(bitmap: &mut [u64], start: u64, end: u64) {
    let mut f = start;
    while f < end {
        let wi = (f / 64) as usize;
        if wi >= bitmap.len() {
            break;
        }
        let bit = (f % 64) as u32;
        let room = 64 - bit as u64;
        let span = (end - f).min(room) as u32;
        bitmap[wi] |= bit_mask(bit, span);
        f += span as u64;
    }
}

/// Bits [bit, bit+span) set, handled so a full 64-bit span never shifts
/// past the word size.
fn bit_mask(bit: u32, span: u32) -> u64 {
    let low = if span == 64 {
        u64::MAX
    } else {
        (1u64 << span) - 1
    };
    low << bit
}

/// Kernel-global state. All access happens through raw pointers (see the
/// wrapper functions below); the kernel is single-threaded so each call
/// re-derives a temporary `FrameAllocator` over the same static bitmap —
/// never two live references to it.
static mut BITMAP: [u64; FRAME_WORDS] = [u64::MAX; FRAME_WORDS];
static mut TOTAL: u64 = 0;
static mut FREE: u64 = 0;

fn global_slice() -> &'static mut [u64] {
    unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(BITMAP) as *mut u64, FRAME_WORDS)
    }
}

/// Wire the global allocator up to a boot-info map.
///
/// # Safety
/// Single-threaded kernel; must run before any other allocation.
pub unsafe fn init_global(info: &BootInfo) {
    let mut a = FrameAllocator::empty(global_slice());
    a.init(info);
    let (total, free) = a.stats();
    core::ptr::write(core::ptr::addr_of_mut!(TOTAL), total);
    core::ptr::write(core::ptr::addr_of_mut!(FREE), free);
}

/// Allocate a frame from the global pool.
///
/// # Safety
/// Single-threaded kernel; must run after `init_global`.
pub unsafe fn alloc_global() -> Option<u64> {
    let mut a = FrameAllocator::empty(global_slice());
    a.free = core::ptr::read(core::ptr::addr_of_mut!(FREE));
    let f = a.alloc();
    core::ptr::write(core::ptr::addr_of_mut!(FREE), a.free);
    f
}

/// Free a frame back to the global pool.
///
/// # Safety
/// `phys` must have come from `alloc_global` and not been freed already.
pub unsafe fn free_global(phys: u64) -> bool {
    let mut a = FrameAllocator::empty(global_slice());
    a.free = core::ptr::read(core::ptr::addr_of_mut!(FREE));
    let ok = a.free(phys);
    core::ptr::write(core::ptr::addr_of_mut!(FREE), a.free);
    ok
}

/// Allocate `n` consecutive frames from the global pool.
///
/// # Safety
/// Single-threaded kernel; must run after `init_global`.
pub unsafe fn alloc_contiguous_global(n: u64) -> Option<u64> {
    let mut a = FrameAllocator::empty(global_slice());
    a.free = core::ptr::read(core::ptr::addr_of_mut!(FREE));
    let f = a.alloc_contiguous(n);
    core::ptr::write(core::ptr::addr_of_mut!(FREE), a.free);
    f
}

/// (total usable frames, currently free frames).
///
/// # Safety
/// Single-threaded kernel; must run after `init_global`.
pub unsafe fn stats_global() -> (u64, u64) {
    (
        core::ptr::read(core::ptr::addr_of_mut!(TOTAL)),
        core::ptr::read(core::ptr::addr_of_mut!(FREE)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_info::{self, MapEntry};

    /// Default kernel image end assumed by the sample maps.
    const TEST_IMAGE_END: u64 = 0x1_1000;

    struct TestAlloc {
        alloc: FrameAllocator<'static>,
    }

    fn make(map_entries: &[MapEntry]) -> TestAlloc {
        make_with_image_end(map_entries, TEST_IMAGE_END)
    }

    fn make_with_image_end(map_entries: &[MapEntry], image_end: u64) -> TestAlloc {
        let bitmap: &'static mut [u64] = Box::leak(Box::new([u64::MAX; 64]));
        let mut alloc = FrameAllocator::empty(bitmap);
        let raw = boot_info::build_image(map_entries, image_end);
        let info = boot_info::parse(&raw).expect("test map must parse");
        alloc.init(&info);
        TestAlloc { alloc }
    }

    /// Small conventional region at 0x1_0000 (just above the kernel
    /// reservation), plus one at 0x1_0000_0.
    fn sample_map() -> Vec<MapEntry> {
        vec![
            // 640 KiB conventional at the bottom (covers kernel image).
            MapEntry {
                ty: TYPE_CONVENTIONAL,
                base: 0x0,
                pages: 160,
            },
            // 1 MiB conventional at 1 MiB.
            MapEntry {
                ty: TYPE_CONVENTIONAL,
                base: 0x10_0000,
                pages: 256,
            },
            // An MMIO region that must never become usable.
            MapEntry {
                ty: 11,
                base: 0xFEE0_0000,
                pages: 8,
            },
        ]
    }

    #[test]
    fn init_counts_conventional_frames_and_reserves() {
        let t = make(&sample_map());
        let free = t.alloc.stats().1;
        // 160 + 256 usable; the kernel reservation covers the first 17
        // frames (0x0..0x11000), all inside the 160-frame region.
        assert_eq!(free, 160 + 256 - 17);
    }

    #[test]
    fn alloc_returns_lowest_free_frame() {
        let mut t = make(&sample_map());
        let f = t.alloc.alloc().unwrap();
        // First free frame sits just above the kernel reservation.
        assert_eq!(f, 17 * PAGE_SIZE); // 0x11000
        assert_eq!(t.alloc.stats().1, 160 + 256 - 17 - 1);
    }

    #[test]
    fn alloc_never_returns_reserved_or_mmio() {
        let mut t = make(&sample_map());
        for _ in 0..(160 + 256 - 17) {
            let f = t.alloc.alloc().expect("should have frames left");
            assert!(f >= TEST_IMAGE_END, "allocated inside kernel: {:#x}", f);
            assert!(f < 0xFEE0_0000, "allocated MMIO: {:#x}", f);
        }
        assert_eq!(t.alloc.alloc(), None, "pool must be exhausted");
    }

    #[test]
    fn image_end_expands_reservation() {
        // A kernel image growing to 0x3_0000 must push the first free
        // frame above it (0x3_0000 = 48 frames).
        let t = make_with_image_end(&sample_map(), 0x3_0000);
        assert_eq!(t.alloc.stats().1, 160 + 256 - 48);
        let mut t = t;
        assert_eq!(t.alloc.alloc(), Some(48 * PAGE_SIZE));
    }

    #[test]
    fn free_makes_frame_available_again() {
        let mut t = make(&sample_map());
        let f0 = t.alloc.alloc().unwrap();
        let _f1 = t.alloc.alloc().unwrap();
        assert!(t.alloc.free(f0));
        // The lowest hole is now f0 again.
        let f2 = t.alloc.alloc().unwrap();
        assert_eq!(f2, f0);
    }

    #[test]
    fn free_untracked_or_out_of_range_rejected() {
        let mut t = make(&sample_map());
        assert!(!t.alloc.free(0x10_0000)); // never allocated (still free)
        assert!(!t.alloc.free(0x1_4000_0000)); // beyond covered space
        assert!(!t.alloc.free(u64::MAX));
    }

    #[test]
    fn is_free_tracks_allocation() {
        let mut t = make(&sample_map());
        let probe = 17 * PAGE_SIZE;
        assert!(t.alloc.is_free(probe));
        let f = t.alloc.alloc().unwrap();
        assert_eq!(f, probe);
        assert!(!t.alloc.is_free(probe));
        assert!(t.alloc.free(probe));
        assert!(t.alloc.is_free(probe));
    }

    #[test]
    fn entries_beyond_4gib_are_clamped_out() {
        let map = vec![
            MapEntry {
                ty: TYPE_CONVENTIONAL,
                base: 0x0,
                pages: 160,
            },
            MapEntry {
                ty: TYPE_CONVENTIONAL,
                base: 0x1_0000_0000,
                pages: 1000,
            },
        ];
        let t = make(&map);
        assert_eq!(t.alloc.stats().1, 160 - 17);
    }

    #[test]
    fn alloc_contiguous_returns_consecutive_run() {
        let mut t = make(&sample_map());
        // Free pool: frames 17..176 (low region) then 256+ (1 MiB region).
        let base = t.alloc.alloc_contiguous(8).unwrap();
        assert_eq!(base, 17 * PAGE_SIZE);
        // Second call wraps to the next 8-frame hole.
        let base2 = t.alloc.alloc_contiguous(8).unwrap();
        assert_eq!(base2, 25 * PAGE_SIZE);
        assert_eq!(t.alloc.stats().1, 160 + 256 - 17 - 16);
    }

    #[test]
    fn alloc_contiguous_spans_word_boundary() {
        // Region that makes the run cross a 64-frame word boundary:
        // frames 60..70 must stay 10-consecutive even though 64 is a
        // word edge. Build a map with conventional frames 60..70 only.
        let map = vec![MapEntry {
            ty: TYPE_CONVENTIONAL,
            base: 60 * PAGE_SIZE,
            pages: 10,
        }];
        let mut t = make_with_image_end(&map, 0x1000);
        let base = t.alloc.alloc_contiguous(10).unwrap();
        assert_eq!(base, 60 * PAGE_SIZE);
    }

    #[test]
    fn alloc_contiguous_fails_when_fragmented() {
        // Two free frames separated by a used one must not merge.
        let map = vec![MapEntry {
            ty: TYPE_CONVENTIONAL,
            base: 17 * PAGE_SIZE,
            pages: 3,
        }];
        let mut t = make_with_image_end(&map, 0x1000);
        let _mid = t.alloc.alloc().unwrap(); // takes frame 17
        let base = t.alloc.alloc_contiguous(2).unwrap();
        // Only frames 18..19 remain contiguous; the run at 17 is gone.
        assert_eq!(base, 18 * PAGE_SIZE);
        let base2 = t.alloc.alloc_contiguous(2);
        assert_eq!(base2, None);
    }

    #[test]
    fn alloc_contiguous_zero_rejected() {
        let mut t = make(&sample_map());
        assert_eq!(t.alloc.alloc_contiguous(0), None);
    }

    #[test]
    fn non_conventional_entries_are_ignored() {
        let map = vec![MapEntry {
            ty: 1,
            base: 0x1000,
            pages: 64,
        }];
        let mut t = make(&map);
        assert_eq!(t.alloc.stats(), (0, 0));
        assert_eq!(t.alloc.alloc(), None);
    }
}

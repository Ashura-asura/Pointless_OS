//! Physical frame allocator, fed by the boot-info memory map.
//!
//! A single bitmap covers the first 2 GiB of the address space (512 Ki
//! frames, 64 KiB of BSS). Every frame starts "used"; `init` clears the
//! bits for CONVENTIONAL ranges from the boot-info handoff, then re-sets
//! the reserved regions. Allocation hands out the lowest free frame;
//! freeing returns it to the pool.
//!
//! Honest limits: the bitmap only covers the first 2 GiB (frames above
//! are never handed out); only UEFI CONVENTIONAL memory is considered
//! usable (bootloader/firmware regions are not reclaimed yet); and the
//! kernel-image + boot-info-handoff reservation comes from the
//! loader-computed `image_end` in the handoff, capped at
//! [0x0, max(image_end + handoff pages, 0x11000)) so the handoff pages
//! (which live just above the image) are always protected.
//!
//! Hardening properties (Phase AG):
//! - **Double-free**: `free` rejects a frame that is already free (or was
//!   never allocated / is out of range) and leaves the free count untouched;
//!   a second free of a live frame can never reclaim or corrupt it.
//! - **Allocation-size sanity**: every hand-out checks the request against
//!   *actually available* memory *before* committing the bitmap — `alloc`
//!   only runs when `free > 0`, and `alloc_contiguous` refuses `n == 0`,
//!   `n > total`, and `n > free`. No frame is ever marked used without the
//!   corresponding `free` decrement, so the bookkeeping can never desync.
//! - **Use-after-free (no_std, no MMU)**: *accepted risk, by decision* — a
//!   bitmap allocator with no page tables cannot revoke a stale physical
//!   address; scrubbing a freed frame is unsafe because the address may be
//!   device/MMIO memory, not RAM. The blast radius is instead bounded by the
//!   capability model + the user-pointer gate (`mem.rs`/`user_ptr.rs`), which
//!   require a live, rights-checked region capability for every access and
//!   re-validate the buffer on each use. This is documented in the threat
//!   model (Phase AH), not silently omitted.

use crate::boot_info::{BootInfo, TYPE_CONVENTIONAL};

pub const PAGE_SIZE: u64 = 4096;
/// Frames in the address space we cover (2 GiB / 4 KiB).
pub const MAX_FRAMES: u64 = 1 << 19;
pub const FRAME_WORDS: usize = (MAX_FRAMES / 64) as usize;

/// The boot-info handoff is written by the loader on the first page(s)
/// strictly above the kernel image (`image_end`); those pages must never be
/// handed out even though the map may mark them conventional.
pub const BOOT_INFO_RESERVE_END: u64 = 0x1_1000;

/// Bitmap allocator over borrowed word slices (works both on the kernel's
/// static `BITMAP`/`ALLOCED` and on test-local buffers).
///
/// Two bitmaps, distinct roles:
/// - `bitmap`: *availability* — `1` means unavailable (reserved by the
///   firmware/kernel image, or handed out by an allocation), `0` means free.
/// - `alloced`: *ownership* — `1` means handed out by `alloc`/`alloc_contiguous`,
///   `0` means never allocated (free, or reserved firmware/kernel memory).
///
/// Splitting the two is what makes `free` safe: it only accepts a frame that
/// is both unavailable AND owned. Freeing a reserved/kernelspace frame
/// (unavailable but not owned) is rejected, so it can never later be handed
/// back out; an already-free frame is rejected (double-free detection); an
/// out-of-range frame is rejected at the bounds check. Without the `alloced`
/// bitmap, `free` could not tell a freshly-allocated frame from a frame the
/// loader simply marked reserved.
pub struct FrameAllocator<'a> {
    bitmap: &'a mut [u64],
    alloced: &'a mut [u64],
}

impl<'a> FrameAllocator<'a> {
    /// Wrap a fully-used availability bitmap and a zeroed ownership bitmap.
    pub const fn empty(bitmap: &'a mut [u64], alloced: &'a mut [u64]) -> Self {
        Self { bitmap, alloced }
    }

    /// Mark conventional ranges usable, then restore the reserved regions
    /// (kernel image per the handoff's `image_end`, the boot-info handoff
    /// pages at `image_end`, plus the legacy handoff page).
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
        paint_diag(120, [0xFF, 0xFF, 0x00]); // F4: after entries loop
        let handoff_end = info
            .image_end
            .saturating_add(crate::boot_info::HANDOFF_PAGES * PAGE_SIZE);
        let kernel_end = handoff_end.max(BOOT_INFO_RESERVE_END);
        paint_diag(160, [0xFF, 0x00, 0xFF]); // F5: before set_bits
        set_bits(self.bitmap, 0, kernel_end / PAGE_SIZE);
        paint_diag(200, [0x00, 0xFF, 0xFF]); // F6: after set_bits
    }

    /// Total usable (conventional) frames: free bits plus allocated bits —
    /// reserved/kernelspace frames are marked unavailable *and* not owned, so
    /// they are excluded. Derived from the bitmaps, never stored, so re-deriving
    /// an `FrameAllocator` over the same buffers is always consistent (no
    /// out-of-band counter to desync).
    pub fn total_frames(&self) -> u64 {
        self.free_count()
            + self
                .alloced
                .iter()
                .fold(0u64, |a, w| a + w.count_ones() as u64)
    }

    /// Currently free frames: every `0` bit in the availability bitmap.
    pub fn free_count(&self) -> u64 {
        self.bitmap
            .iter()
            .fold(0u64, |a, w| a + w.count_zeros() as u64)
    }

    /// Claim the lowest free frame, returning its physical address.
    pub fn alloc(&mut self) -> Option<u64> {
        for (wi, word) in self.bitmap.iter().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros() as u64;
                self.bitmap[wi] |= 1u64 << bit;
                self.alloced[wi] |= 1u64 << bit;
                return Some(((wi as u64 * 64) + bit) * PAGE_SIZE);
            }
        }
        None
    }

    /// Claim `n` consecutive free frames, returning the physical address of
    /// the first. Fails if no run of `n` exists.
    pub fn alloc_contiguous(&mut self, n: u64) -> Option<u64> {
        // Size sanity: refuse a run larger than the entire usable pool
        // (can never fit) or larger than what is currently free (not enough
        // memory to commit) *before* touching the bitmap. Availability is
        // derived from the bitmaps, so this is always consistent.
        if n == 0 || n > self.total_frames() || self.free_count() < n {
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
                        set_bits(self.alloced, run_start, frame + 1);
                        return Some(run_start * PAGE_SIZE);
                    }
                } else {
                    run = 0;
                }
            }
        }
        None
    }

    /// Return a frame to the pool. `false` if it was never allocated (already
    /// free, a reserved/kernelspace frame, or outside the covered address
    /// space) — so a reserved frame can never be freed-then-realloc'd out from
    /// under the kernel, and a double-free is always rejected.
    pub fn free(&mut self, phys: u64) -> bool {
        let frame = phys / PAGE_SIZE;
        if frame >= MAX_FRAMES {
            return false;
        }
        let wi = (frame / 64) as usize;
        let bit = (frame % 64) as u32;
        if wi >= self.bitmap.len() || wi >= self.alloced.len() {
            return false;
        }
        let avail = self.bitmap[wi] >> bit & 1; // 1 = unavailable (reserved/allocated)
        let owned = self.alloced[wi] >> bit & 1; // 1 = allocated by us
                                                 // Only a frame we actually allocated (unavailable AND owned) may be
                                                 // freed. A reserved frame is unavailable but not owned -> rejected; an
                                                 // already-free frame is available -> rejected; out-of-range above.
        if avail == 0 || owned == 0 {
            return false;
        }
        self.bitmap[wi] &= !(1u64 << bit);
        self.alloced[wi] &= !(1u64 << bit);
        true
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.total_frames(), self.free_count())
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

/// Host-testable adversarial allocator oracle (Phase AG fuzz target).
///
/// Drives an `FrameAllocator` over a small, fully-deterministic pool from a
/// byte stream of operations and *asserts the allocator's invariants on every
/// step* — so a single bookkeeping slip (double-free accepted, free-count
/// desync, an alloc handing back an already-used frame, an out-of-range free
/// mutating state) turns into a panic the fuzzing harness catches. This is the
/// "host-testable extraction" discipline from Phase AD applied to the allocator
/// specifically: no `unsafe`, no globals, pure bitmap logic over a borrowed
/// slice, so it runs equally under `cargo test`, the nightly corpus fuzzer,
/// and Miri.
///
/// Op encoding (low 2 bits of each byte):
/// - `0`: alloc one frame (track it).
/// - `1`: alloc `1 + next_byte & 7` contiguous frames (track the base).
/// - `2`: free the most recently tracked frame.
/// - `3`: adversarial frees — a genuine free of the most recent tracked frame
///   followed by a *double-free* of it (must be rejected), an out-of-range
///   free (must be rejected), and a free of a reserved/used frame (rejected).
#[cfg(test)]
pub fn fuzz_run(ops: &[u8]) -> bool {
    use crate::boot_info::{self, MapEntry, TYPE_CONVENTIONAL};

    const POOL_FRAMES: u64 = 128;
    let entries = [MapEntry {
        ty: TYPE_CONVENTIONAL,
        base: 0,
        pages: POOL_FRAMES,
    }];
    let raw = boot_info::build_image(&entries, 0x1000);
    let info = boot_info::parse(&raw).expect("fixture boot info must parse");
    let mut bitmap = [u64::MAX; 2]; // 128 frames, two 64-bit words.
    let mut alloced = [0u64; 2];
    let mut a = FrameAllocator::empty(&mut bitmap, &mut alloced);
    a.init(&info);
    let (_total, mut free) = a.stats();
    let mut alloced: Vec<u64> = Vec::new();
    let mut i = 0;
    while i < ops.len() {
        let op = ops[i] & 0x3;
        i += 1;
        match op {
            0 => match a.alloc() {
                Some(f) => {
                    assert!(!a.is_free(f), "alloc returned a frame still marked free");
                    assert_eq!(a.stats().1, free - 1, "alloc did not decrement free");
                    free -= 1;
                    alloced.push(f);
                }
                None => {
                    assert_eq!(free, 0, "alloc returned None while free > 0");
                }
            },
            1 => {
                let n = if i < ops.len() {
                    let v = ops[i] & 0x7;
                    i += 1;
                    1 + v as u64
                } else {
                    1
                };
                if n == 0 {
                    continue;
                }
                // None is legitimate on fragmentation / insufficient free;
                // only the success path asserts bookkeeping.
                if let Some(base) = a.alloc_contiguous(n) {
                    assert!(!a.is_free(base), "contiguous base still marked free");
                    assert_eq!(
                        a.stats().1,
                        free - n,
                        "contiguous did not decrement free by n"
                    );
                    free -= n;
                    alloced.push(base);
                }
            }
            2 => {
                if let Some(f) = alloced.pop() {
                    assert!(a.free(f), "free of a tracked allocated frame failed");
                    assert!(a.is_free(f), "freed frame not marked free");
                    assert_eq!(a.stats().1, free + 1, "free did not increment free");
                    free += 1;
                }
            }
            _ => {
                // Double-free: genuinely free the most recent tracked frame,
                // then attempt to free it again — must be refused, no count
                // change.
                if let Some(f) = alloced.pop() {
                    assert!(a.free(f), "free of allocated frame failed");
                    assert!(a.is_free(f), "freed frame not marked free");
                    free += 1;
                    assert_eq!(a.stats().1, free);
                    assert!(!a.free(f), "double-free of the same frame was accepted");
                    assert_eq!(a.stats().1, free, "double-free changed the free count");
                }
                // Out-of-range free (beyond the covered address space).
                let wild = (POOL_FRAMES + 1 + (ops.len() as u64)) * PAGE_SIZE;
                assert!(!a.free(wild), "out-of-range free was accepted");
                assert_eq!(a.stats().1, free, "out-of-range free changed free count");
                // Free of a reserved (never-allocated, used) frame rejected.
                assert!(!a.free(0), "free of a reserved frame was accepted");
                assert_eq!(a.stats().1, free);
            }
        }
    }
    // Final invariant: our tracked free count matches the allocator's.
    assert_eq!(
        a.stats().1,
        free,
        "allocator free count desynced from tracked bookkeeping"
    );
    true
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
/// re-derives a temporary `FrameAllocator` over the same static bitmaps —
/// never two live references to them. `total`/`free` are derived from the
/// bitmaps on demand, so no separate counter must be kept in sync.
static mut BITMAP: [u64; FRAME_WORDS] = [u64::MAX; FRAME_WORDS];
static mut ALLOCED: [u64; FRAME_WORDS] = [0u64; FRAME_WORDS];

fn global_slice() -> (&'static mut [u64], &'static mut [u64]) {
    paint_diag(240, [0xFF, 0xFF, 0xFF]); // G1: at very start of global_slice
    unsafe {
        let bm = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(BITMAP) as *mut u64,
            FRAME_WORDS,
        );
        paint_diag(280, [0xFF, 0x80, 0x00]); // G2: after BITMAP slice
        let al = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(ALLOCED) as *mut u64,
            FRAME_WORDS,
        );
        (bm, al)
    }
}

/// Wire the global allocator up to a boot-info map.
///
/// # Safety
/// Single-threaded kernel; must run before any other allocation.
/// Paint a 40x40 block at the right edge via the stashed GOP handoff (the
/// same mechanism as `main::paint`, which is known to work on the TP201S).
/// This bypasses `diag_fill`, which silently no-ops if the DIAG framebuffer
/// hasn't been registered — so a visible block proves this line executed.
fn paint_diag(x: usize, rgb: [u8; 3]) {
    let handoff = unsafe { crate::boot_info::boot_handoff() };
    if handoff == 0 {
        return;
    }
    if let Some(h) = unsafe { crate::boot_info::gop_at(handoff) } {
        let fb = h.framebuffer_base as *mut u8;
        let stride = h.stride_px as usize;
        let bpp = (h.bpp / 8) as usize;
        let y = 300usize;
        for dy in 0..40usize {
            for dx in 0..40usize {
                let off = ((y + dy) * stride + (x + dx)) * bpp;
                unsafe {
                    core::ptr::write_volatile(fb.add(off), rgb[0]);
                    core::ptr::write_volatile(fb.add(off + 1), rgb[1]);
                    core::ptr::write_volatile(fb.add(off + 2), rgb[2]);
                }
            }
        }
    }
}

pub unsafe fn init_global(info: &BootInfo) {
    paint_diag(320, [0xFF, 0xFF, 0xFF]); // F0: init_global entry, before global_slice() is even called
    let (bm, al) = global_slice();
    paint_diag(0, [0xFF, 0x00, 0x00]); // F1: after global_slice
    let mut a = FrameAllocator::empty(bm, al);
    paint_diag(40, [0x00, 0xFF, 0x00]); // F2: after empty
    a.init(info);
    paint_diag(80, [0x00, 0x00, 0xFF]); // F3: after init
}

/// Allocate a frame from the global pool.
///
/// # Safety
/// Single-threaded kernel; must run after `init_global`.
pub unsafe fn alloc_global() -> Option<u64> {
    let (bm, al) = global_slice();
    let mut a = FrameAllocator::empty(bm, al);
    a.alloc()
}

/// Free a frame back to the global pool.
///
/// # Safety
/// `phys` must have come from `alloc_global` and not been freed already.
pub unsafe fn free_global(phys: u64) -> bool {
    let (bm, al) = global_slice();
    let mut a = FrameAllocator::empty(bm, al);
    a.free(phys)
}

/// Allocate `n` consecutive frames from the global pool.
///
/// # Safety
/// Single-threaded kernel; must run after `init_global`.
pub unsafe fn alloc_contiguous_global(n: u64) -> Option<u64> {
    let (bm, al) = global_slice();
    let mut a = FrameAllocator::empty(bm, al);
    a.alloc_contiguous(n)
}

/// (total usable frames, currently free frames).
///
/// # Safety
/// Single-threaded kernel; must run after `init_global`.
pub unsafe fn stats_global() -> (u64, u64) {
    let (bm, al) = global_slice();
    let a = FrameAllocator::empty(bm, al);
    a.stats()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_info::{self, MapEntry};

    /// Default kernel image end assumed by the sample maps.
    const TEST_IMAGE_END: u64 = 0x1_1000;

    /// Frames reserved by `init` for a given image end: the kernel image,
    /// the boot-info handoff pages just above it, and the legacy handoff
    /// page. Mirrors the production formula.
    fn reserved_frames(image_end: u64) -> u64 {
        (image_end + boot_info::HANDOFF_PAGES * PAGE_SIZE).max(BOOT_INFO_RESERVE_END) / PAGE_SIZE
    }

    /// Test harness owns the backing buffers and lends a borrowed
    /// `FrameAllocator` per call. Because `free`/`total` are derived from the
    /// bitmaps (not stored), re-deriving an allocator over the same buffers is
    /// always consistent — and no `Box::leak` is needed, so this is Miri-clean.
    struct TestAlloc {
        bitmap: Vec<u64>,
        alloced: Vec<u64>,
    }

    impl TestAlloc {
        fn fa(&mut self) -> FrameAllocator<'_> {
            FrameAllocator::empty(&mut self.bitmap, &mut self.alloced)
        }
    }

    fn make(map_entries: &[MapEntry]) -> TestAlloc {
        make_with_image_end(map_entries, TEST_IMAGE_END)
    }

    fn make_with_image_end(map_entries: &[MapEntry], image_end: u64) -> TestAlloc {
        let mut t = TestAlloc {
            bitmap: vec![u64::MAX; 64],
            alloced: vec![0u64; 64],
        };
        let raw = boot_info::build_image(map_entries, image_end);
        let info = boot_info::parse(&raw).expect("test map must parse");
        t.fa().init(&info);
        t
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
        let mut t = make(&sample_map());
        let free = t.fa().stats().1;
        // 160 + 256 usable; the reservation covers the kernel image
        // (0x0..image_end) plus the handoff pages above it — 19 frames.
        assert_eq!(free, 160 + 256 - reserved_frames(TEST_IMAGE_END));
    }

    #[test]
    fn alloc_returns_lowest_free_frame() {
        let mut t = make(&sample_map());
        let f = t.fa().alloc().unwrap();
        // First free frame sits just above the kernel + handoff reservation.
        assert_eq!(f, reserved_frames(TEST_IMAGE_END) * PAGE_SIZE);
        assert_eq!(
            t.fa().stats().1,
            160 + 256 - reserved_frames(TEST_IMAGE_END) - 1
        );
    }

    #[test]
    fn alloc_never_returns_reserved_or_mmio() {
        let mut t = make(&sample_map());
        for _ in 0..(160 + 256 - reserved_frames(TEST_IMAGE_END)) {
            let f = t.fa().alloc().expect("should have frames left");
            assert!(f >= TEST_IMAGE_END, "allocated inside kernel: {:#x}", f);
            assert!(f < 0xFEE0_0000, "allocated MMIO: {:#x}", f);
        }
        assert_eq!(t.fa().alloc(), None, "pool must be exhausted");
    }

    #[test]
    fn image_end_expands_reservation() {
        // A kernel image growing to 0x3_0000 must push the first free
        // frame above it, plus the handoff pages (0x3_0000 = 48 frames).
        let mut t = make_with_image_end(&sample_map(), 0x3_0000);
        assert_eq!(t.fa().stats().1, 160 + 256 - reserved_frames(0x3_0000));
        assert_eq!(t.fa().alloc(), Some(reserved_frames(0x3_0000) * PAGE_SIZE));
    }

    #[test]
    fn free_makes_frame_available_again() {
        let mut t = make(&sample_map());
        let f0 = t.fa().alloc().unwrap();
        let _f1 = t.fa().alloc().unwrap();
        assert!(t.fa().free(f0));
        // The lowest hole is now f0 again.
        let f2 = t.fa().alloc().unwrap();
        assert_eq!(f2, f0);
    }

    #[test]
    fn free_untracked_or_out_of_range_rejected() {
        let mut t = make(&sample_map());
        assert!(!t.fa().free(0x10_0000)); // never allocated (still free)
        assert!(!t.fa().free(0x1_4000_0000)); // beyond covered space
        assert!(!t.fa().free(u64::MAX));
    }

    #[test]
    fn is_free_tracks_allocation() {
        let mut t = make(&sample_map());
        let probe = reserved_frames(TEST_IMAGE_END) * PAGE_SIZE;
        assert!(t.fa().is_free(probe));
        let f = t.fa().alloc().unwrap();
        assert_eq!(f, probe);
        assert!(!t.fa().is_free(probe));
        assert!(t.fa().free(probe));
        assert!(t.fa().is_free(probe));
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
        let mut t = make(&map);
        assert_eq!(t.fa().stats().1, 160 - reserved_frames(TEST_IMAGE_END));
    }

    #[test]
    fn alloc_contiguous_returns_consecutive_run() {
        let mut t = make(&sample_map());
        // Free pool: reserved_frames..176 (low region) then 256+ (1 MiB region).
        let base = t.fa().alloc_contiguous(8).unwrap();
        assert_eq!(base, reserved_frames(TEST_IMAGE_END) * PAGE_SIZE);
        // Second call wraps to the next 8-frame hole.
        let base2 = t.fa().alloc_contiguous(8).unwrap();
        assert_eq!(base2, (reserved_frames(TEST_IMAGE_END) + 8) * PAGE_SIZE);
        assert_eq!(
            t.fa().stats().1,
            160 + 256 - reserved_frames(TEST_IMAGE_END) - 16
        );
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
        let base = t.fa().alloc_contiguous(10).unwrap();
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
        let _mid = t.fa().alloc().unwrap(); // takes frame 17
        let base = t.fa().alloc_contiguous(2).unwrap();
        // Only frames 18..19 remain contiguous; the run at 17 is gone.
        assert_eq!(base, 18 * PAGE_SIZE);
        let base2 = t.fa().alloc_contiguous(2);
        assert_eq!(base2, None);
    }

    #[test]
    fn alloc_contiguous_zero_rejected() {
        let mut t = make(&sample_map());
        assert_eq!(t.fa().alloc_contiguous(0), None);
    }

    #[test]
    fn non_conventional_entries_are_ignored() {
        let map = vec![MapEntry {
            ty: 1,
            base: 0x1000,
            pages: 64,
        }];
        let mut t = make(&map);
        assert_eq!(t.fa().stats(), (0, 0));
        assert_eq!(t.fa().alloc(), None);
    }

    #[test]
    fn double_free_is_rejected_and_leaves_count_unchanged() {
        let mut t = make(&sample_map());
        let f = t.fa().alloc().unwrap();
        assert!(t.fa().free(f));
        // Second free of the same frame: rejected, count untouched.
        let (_total, free_before) = t.fa().stats();
        assert!(!t.fa().free(f), "double-free must be refused");
        assert_eq!(
            t.fa().stats().1,
            free_before,
            "double-free mutated the free count"
        );
        // A wild out-of-range free is also refused without side effects.
        assert!(!t.fa().free(0x1_4000_0000));
        assert_eq!(t.fa().stats().1, free_before);
    }

    #[test]
    fn exhaustion_then_full_free_restores_pool_without_leak() {
        let mut t = make(&sample_map());
        let (total, free0) = t.fa().stats();
        assert_eq!(total, free0, "fresh pool is fully free");
        let mut handed = Vec::new();
        while let Some(f) = t.fa().alloc() {
            handed.push(f);
        }
        assert_eq!(t.fa().stats().1, 0, "exhaustion reaches exactly zero free");
        // Every allocation is unique (no aliasing even under exhaustion).
        handed.sort_unstable();
        handed.dedup();
        assert_eq!(handed.len() as u64, total, "no frame handed out twice");
        // Free everything; the pool returns to fully-free.
        for f in handed {
            assert!(t.fa().free(f));
        }
        assert_eq!(t.fa().stats().1, total, "full free restores the whole pool");
    }

    #[test]
    fn alloc_contiguous_refuses_oversized_run() {
        let mut t = make(&sample_map());
        let (total, _free) = t.fa().stats();
        // A run larger than the entire usable pool is refused up front
        // (size sanity vs actually-available memory), regardless of how the
        // free space is laid out.
        assert_eq!(t.fa().alloc_contiguous(total + 1), None);
        assert_eq!(t.fa().alloc_contiguous(u64::MAX), None);
        // A small run that fits the first free region is handed out at the
        // lowest free frame.
        let first = t.fa().alloc().unwrap();
        // After one single-frame alloc, the lowest 5-frame run starts one
        // frame higher.
        assert_eq!(t.fa().alloc_contiguous(5).unwrap(), first + PAGE_SIZE);
    }

    /// Phase AG allocator fuzz — the deterministic, Miri-runnable battery.
    /// The nightly corpus fuzzer (`fuzz_corpus`) drives `fuzz_run` with
    /// mutated/random bytes; this fixed battery is the host-testable core
    /// that also runs under `cargo miri test frame::`.
    #[test]
    fn fuzz_run_adversarial_sequences_hold_invariants() {
        let seqs: &[&[u8]] = &[
            &[],
            &[0, 0, 0, 0, 0, 2, 2, 2, 2, 2],
            &[1, 1, 1, 2, 1, 3, 1, 4, 1, 5, 2, 2, 2, 2, 2],
            &[0, 0, 2, 0, 2, 3, 0, 0, 0, 2, 2, 2, 3],
            &[0u8; 300], // exhaust then the trailing ops hit the None branch
            &[1, 8, 1, 8, 1, 8, 2, 2, 2, 3, 1, 8, 2, 3],
            &[2, 2, 3, 0, 0, 1, 1, 2, 3, 1, 2, 2, 3, 0, 0, 0, 2, 2, 2],
        ];
        for s in seqs {
            assert!(
                fuzz_run(s),
                "allocator fuzz sequence panicked or desynced: {:?}",
                s
            );
        }
    }
}

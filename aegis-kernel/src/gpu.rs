//! Bochs/QEMU "stdvga" VBE (dispi) linear-framebuffer driver — Phase H.
//!
//! Scope is deliberately narrow: framebuffer/display *output* only (set a
//! linear pixel mode, write raw pixels into it). No 2D/3D acceleration, no
//! compute — that is a separate, much larger undertaking, the same blocker
//! that keeps local AI inference out of reach (see the roadmap's Phase H
//! section).
//!
//! Device model: this targets the "Bochs VBE extensions" register
//! interface (the `dispi` interface) that QEMU's `std`/`stdvga`/`bochs-
//! display`/`virtio-vga` devices all implement, and that `vga.rs` already
//! pokes at (see its VBE-disable code) to get the legacy VGA text path
//! back. That interface lives at IO ports 0x1CE (index) / 0x1CF (data),
//! **not** behind the PCI BAR's MMIO window — the BAR only supplies the
//! linear framebuffer (LFB) memory itself. This mirrors the existing
//! project convention (`e1000`/`nvme` map BAR0 as MMIO *registers*; this
//! driver maps BAR0 as raw pixel *memory* and drives mode-setting over
//! ports instead).
//!
//! Honest limits: verified live under QEMU/TCG, matching every other
//! driver in this tree; UNTESTED on real hardware. VMware's SVGA-II is a
//! different register interface entirely and is deliberately rejected by
//! the dispi ID probe in `probe()` rather than silently mishandled — see
//! `pci.rs`'s `find_display` doc comment, which already calls this out.

#[cfg(not(test))]
use crate::pci::PciDeviceList;

// ---- Bochs VBE "dispi" interface: IO port index/data pair ----
// Gated to `cfg(not(test))` with the port I/O below: these are read/written
// only by `dispi_*` / `set_mode` / `probe`, which don't exist in the test
// build (they would fault on the host). `VBE_DISPI_ID0`/`ID5` stay
// ungated — `is_bochs_dispi_id` is pure and host-tested.
#[cfg(not(test))]
const VBE_DISPI_IOPORT_INDEX: u16 = 0x01CE;
#[cfg(not(test))]
const VBE_DISPI_IOPORT_DATA: u16 = 0x01CF;

#[cfg(not(test))]
const VBE_DISPI_INDEX_ID: u16 = 0x0;
#[cfg(not(test))]
const VBE_DISPI_INDEX_XRES: u16 = 0x1;
#[cfg(not(test))]
const VBE_DISPI_INDEX_YRES: u16 = 0x2;
#[cfg(not(test))]
const VBE_DISPI_INDEX_BPP: u16 = 0x3;
#[cfg(not(test))]
const VBE_DISPI_INDEX_ENABLE: u16 = 0x4;
#[cfg(not(test))]
const VBE_DISPI_INDEX_BANK: u16 = 0x5;
#[cfg(not(test))]
const VBE_DISPI_INDEX_VIRT_WIDTH: u16 = 0x6;
#[cfg(not(test))]
const VBE_DISPI_INDEX_VIRT_HEIGHT: u16 = 0x7;
#[cfg(not(test))]
const VBE_DISPI_INDEX_X_OFFSET: u16 = 0x8;
#[cfg(not(test))]
const VBE_DISPI_INDEX_Y_OFFSET: u16 = 0x9;

#[cfg(not(test))]
const VBE_DISPI_DISABLED: u16 = 0x00;
#[cfg(not(test))]
const VBE_DISPI_ENABLED: u16 = 0x01;
#[cfg(not(test))]
const VBE_DISPI_LFB_ENABLED: u16 = 0x40;
#[cfg(not(test))]
const VBE_DISPI_NOCLEARMEM: u16 = 0x80;

/// The device's ID register reads back one of these six values
/// (`VBE_DISPI_ID0`..`VBE_DISPI_ID5`) when it really speaks this
/// interface. A display-class PCI device that answers something else
/// (VMware's SVGA-II, an unemulated passthrough GPU, ...) is not this
/// device — `probe()` rejects it rather than guessing.
const VBE_DISPI_ID0: u16 = 0xB0C0;
const VBE_DISPI_ID5: u16 = 0xB0C5;

/// Bits per pixel this driver requests. 32bpp keeps the pixel format
/// (BGRX8888, see `gpu_compositor`) simple and matches what OVMF's own GOP
/// framebuffer already uses on this same device, so it's known-supported.
#[cfg(not(test))]
const BPP: u16 = 32;

/// True if `id` is one of the six documented Bochs dispi IDs. Pure and
/// host-testable on purpose — see the `port`/`dispi_*` doc comments below
/// for why the port I/O around it isn't.
pub fn is_bochs_dispi_id(id: u16) -> bool {
    (VBE_DISPI_ID0..=VBE_DISPI_ID5).contains(&id)
}

/// A successfully-installed pixel mode: everything `gpu_compositor` needs
/// to compute a byte offset for a given pixel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    pub bpp: u16,
    /// Bytes per scanline row (`width * bpp/8`). This driver never asks
    /// for a virtual width wider than the visible width, so there is no
    /// extra row padding to account for.
    pub pitch: usize,
}

/// Compute the `Mode` for `width`x`height`@`bpp`, or `None` if it does not
/// fit in an LFB window of `lfb_len` bytes, or the inputs are degenerate.
/// Pure geometry, no hardware — host-testable, and reused by `set_mode` so
/// the exact same rejection logic is exercised by both the real path and
/// the unit tests below.
pub fn mode_geometry(width: u32, height: u32, bpp: u16, lfb_len: usize) -> Option<Mode> {
    if width == 0 || height == 0 || bpp == 0 || bpp % 8 != 0 {
        return None;
    }
    let bytes_per_pixel = (bpp / 8) as usize;
    let pitch = (width as usize).checked_mul(bytes_per_pixel)?;
    let needed = pitch.checked_mul(height as usize)?;
    if needed > lfb_len {
        return None;
    }
    Some(Mode {
        width,
        height,
        bpp,
        pitch,
    })
}

// ---- real port I/O (Bochs dispi index/data pair) ----
// Gated to `cfg(not(test))`: `out`/`in` are privileged instructions that
// fault in the host `cargo test` process (no I/O port access outside
// ring 0) — the same reason `vga.rs`'s hardware-touching functions
// (`vga_enter_text_mode`, `vga_upload_font`, the VBE-disable code, ...)
// carry no unit tests either. They're proven live, under QEMU, not on the
// host; see `BochsGpu::probe`/`set_mode` below for the same treatment.
#[cfg(not(test))]
mod port {
    pub fn out16(port: u16, val: u16) {
        unsafe {
            core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, preserves_flags));
        }
    }

    pub fn in16(port: u16) -> u16 {
        let v: u16;
        unsafe {
            core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, preserves_flags));
        }
        v
    }
}

#[cfg(not(test))]
fn dispi_write(index: u16, value: u16) {
    port::out16(VBE_DISPI_IOPORT_INDEX, index);
    port::out16(VBE_DISPI_IOPORT_DATA, value);
}

#[cfg(not(test))]
fn dispi_read(index: u16) -> u16 {
    port::out16(VBE_DISPI_IOPORT_INDEX, index);
    port::in16(VBE_DISPI_IOPORT_DATA)
}

/// A mapped Bochs-VBE-compatible display device: its linear framebuffer
/// (from BAR0) plus the dispi mode-setting state machine.
pub struct BochsGpu {
    lfb: *mut u8,
    pub bar_addr: u64,
    // Read only by `set_mode` (`mode_geometry`'s fit check), which is
    // `cfg(not(test))`; the test build only writes it via `test_with_mode`,
    // so gate the "never read" lint off for the test compile.
    #[cfg_attr(test, allow(dead_code))]
    lfb_len: usize,
    mode: Option<Mode>,
}

impl BochsGpu {
    /// Find a Bochs-VBE-compatible display device on the bus and map its
    /// linear framebuffer BAR. Returns `None` — not an error, see
    /// `pci.rs`'s `find_display` doc comment — for: no display-class
    /// device present, a display device whose BAR0 isn't identity-mapped
    /// below 4 GiB (same guard `e1000::probe`/`nvme::probe` use for their
    /// BARs), or a display device that doesn't answer the dispi ID probe.
    ///
    /// Assumes a 16 MiB BAR0, the size QEMU's `std`/`stdvga`/`bochs-
    /// display` devices actually expose for their LFB; every mode this
    /// driver sets is well under that, and `mode_geometry` re-checks the
    /// fit against the assumed `lfb_len` regardless.
    #[cfg(not(test))]
    pub fn probe(pci: &PciDeviceList) -> Option<BochsGpu> {
        const ASSUMED_LFB_LEN: usize = 16 * 1024 * 1024;

        let dev = pci.find_display()?;
        let addr = dev.bar_address(0);
        if addr == 0 || addr >= 0x1_0000_0000 {
            crate::sprintln!("Aegis: gpu: BAR {:#x} not identity-mapped - skipped", addr);
            return None;
        }
        unsafe {
            crate::pci::enable_bus_mastering(dev.address);
        }

        let id = dispi_read(VBE_DISPI_INDEX_ID);
        if !is_bochs_dispi_id(id) {
            crate::sprintln!(
                "Aegis: gpu: display device id={:#06x} does not speak Bochs VBE - skipped",
                id
            );
            return None;
        }

        crate::sprintln!(
            "Aegis: gpu: Bochs VBE display found, id={:#06x} lfb={:#x}",
            id,
            addr
        );

        Some(BochsGpu {
            lfb: addr as *mut u8,
            bar_addr: addr,
            lfb_len: ASSUMED_LFB_LEN,
            mode: None,
        })
    }

    /// Set a linear-framebuffer graphics mode via the dispi interface.
    /// Returns `false` (no mode installed / previous mode left in place)
    /// if the geometry doesn't fit the mapped LFB, or if the device
    /// doesn't latch back the exact geometry that was requested.
    #[cfg(not(test))]
    pub fn set_mode(&mut self, width: u32, height: u32) -> bool {
        let mode = match mode_geometry(width, height, BPP, self.lfb_len) {
            Some(m) => m,
            None => {
                crate::sprintln!(
                    "Aegis: gpu: mode {}x{}x{} does not fit LFB ({:#x} bytes) - rejected",
                    width,
                    height,
                    BPP,
                    self.lfb_len
                );
                return false;
            }
        };

        // Bochs requires ENABLE=0 while XRES/YRES/BPP are reprogrammed.
        dispi_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
        dispi_write(VBE_DISPI_INDEX_XRES, width as u16);
        dispi_write(VBE_DISPI_INDEX_YRES, height as u16);
        dispi_write(VBE_DISPI_INDEX_BPP, BPP);
        dispi_write(VBE_DISPI_INDEX_BANK, 0);
        dispi_write(VBE_DISPI_INDEX_VIRT_WIDTH, width as u16);
        dispi_write(VBE_DISPI_INDEX_VIRT_HEIGHT, height as u16);
        dispi_write(VBE_DISPI_INDEX_X_OFFSET, 0);
        dispi_write(VBE_DISPI_INDEX_Y_OFFSET, 0);
        dispi_write(
            VBE_DISPI_INDEX_ENABLE,
            VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM,
        );

        // Readback: confirm the device actually latched what was asked —
        // the same discipline `vga.rs`'s register-readback proof already
        // uses for its own mode-setting.
        let got_x = dispi_read(VBE_DISPI_INDEX_XRES);
        let got_y = dispi_read(VBE_DISPI_INDEX_YRES);
        let got_bpp = dispi_read(VBE_DISPI_INDEX_BPP);
        if got_x as u32 != width || got_y as u32 != height || got_bpp != BPP {
            crate::sprintln!(
                "Aegis: gpu: mode set rejected by device: asked {}x{}x{}, device reports {}x{}x{}",
                width,
                height,
                BPP,
                got_x,
                got_y,
                got_bpp
            );
            dispi_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
            return false;
        }

        // NOCLEARMEM above skips the device's own clear, so stamp the LFB
        // ourselves — otherwise stale VRAM content from a previous mode
        // (or from firmware's own GOP framebuffer) shows through on the
        // very first frame.
        unsafe {
            core::ptr::write_bytes(self.lfb, 0, mode.pitch * mode.height as usize);
        }

        crate::sprintln!("Aegis: gpu: mode set {}x{}x{}", width, height, BPP);
        self.mode = Some(mode);
        true
    }

    /// The currently-installed mode, if any.
    pub fn mode(&self) -> Option<Mode> {
        self.mode
    }

    /// Raw pixel access for `gpu_compositor::blit_cells`. `None` if no
    /// mode has been set (`probe` succeeded but `set_mode` was never
    /// called, or it failed) — `blit_cells` treats that as a no-op, by
    /// design, so the VGA text backend never depends on this driver.
    pub fn framebuffer_mut(&mut self) -> Option<(&mut [u8], Mode)> {
        let mode = self.mode?;
        let len = mode.pitch * mode.height as usize;
        // Safety: `len` was computed by `mode_geometry` against `lfb_len`
        // on the real path (bounded by the mapped BAR), or supplied
        // directly by the test caller on the test path (`test_with_mode`,
        // bounded by the buffer it was given) — either way `self.lfb`
        // actually has at least `len` bytes behind it.
        let fb = unsafe { core::slice::from_raw_parts_mut(self.lfb, len) };
        Some((fb, mode))
    }

    /// Test-only constructor: build a `BochsGpu` directly over a
    /// host-owned buffer, bypassing PCI probing and the real dispi port
    /// I/O entirely (which requires ring 0 and would fault under `cargo
    /// test` — see the `port`/`dispi_*` doc comments above). Exists so
    /// `gpu_compositor::blit_cells` — the part of this driver with real
    /// pixel logic worth testing — can be exercised on the host without
    /// QEMU. `buf` must be at least `mode`'s `pitch * height` bytes when
    /// `mode` is `Some`.
    #[cfg(test)]
    pub fn test_with_mode(buf: &mut [u8], mode: Option<Mode>) -> BochsGpu {
        BochsGpu {
            lfb: buf.as_mut_ptr(),
            bar_addr: 0,
            lfb_len: buf.len(),
            mode,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispi_id_range_accepts_only_documented_ids() {
        assert!(is_bochs_dispi_id(VBE_DISPI_ID0));
        assert!(is_bochs_dispi_id(VBE_DISPI_ID5));
        assert!(is_bochs_dispi_id(0xB0C3));
        assert!(!is_bochs_dispi_id(0xB0C6));
        assert!(!is_bochs_dispi_id(0x0000));
        assert!(!is_bochs_dispi_id(0xFFFF)); // e.g. a VMware SVGA-II misread
    }

    #[test]
    fn mode_geometry_computes_pitch_for_32bpp() {
        let m = mode_geometry(640, 480, 32, 640 * 480 * 4).unwrap();
        assert_eq!(m.pitch, 640 * 4);
        assert_eq!(m.width, 640);
        assert_eq!(m.height, 480);
        assert_eq!(m.bpp, 32);
    }

    #[test]
    fn mode_geometry_rejects_mode_too_big_for_lfb() {
        // 16 MiB LFB; this mode needs roughly 24.5 MiB.
        assert!(mode_geometry(4096, 1560, 32, 16 * 1024 * 1024).is_none());
    }

    #[test]
    fn mode_geometry_rejects_degenerate_inputs() {
        assert!(mode_geometry(0, 480, 32, 1 << 30).is_none());
        assert!(mode_geometry(640, 0, 32, 1 << 30).is_none());
        assert!(mode_geometry(640, 480, 0, 1 << 30).is_none());
        assert!(mode_geometry(640, 480, 15, 1 << 30).is_none()); // not byte-aligned
    }

    #[test]
    fn mode_geometry_accepts_exact_fit_rejects_one_byte_over() {
        let lfb_len = 640 * 480 * 4;
        assert!(mode_geometry(640, 480, 32, lfb_len).is_some());
        assert!(mode_geometry(640, 480, 32, lfb_len - 1).is_none());
    }

    #[test]
    fn framebuffer_mut_none_without_a_mode() {
        let mut buf = [0u8; 64];
        let mut gpu = BochsGpu::test_with_mode(&mut buf, None);
        assert!(gpu.framebuffer_mut().is_none());
    }

    #[test]
    fn framebuffer_mut_returns_slice_sized_to_mode() {
        let mode = Mode {
            width: 4,
            height: 2,
            bpp: 32,
            pitch: 16,
        };
        let mut buf = [0u8; 32];
        let mut gpu = BochsGpu::test_with_mode(&mut buf, Some(mode));
        let (fb, m) = gpu.framebuffer_mut().unwrap();
        assert_eq!(fb.len(), 32);
        assert_eq!(m, mode);
    }
}

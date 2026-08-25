//! UEFI Graphics Output Protocol (GOP) query for the kernel's display
//! driver (Phase T).
//!
//! Real hardware has no Bochs VBE dispi interface, so the only display
//! path a physical machine offers is the GOP framebuffer UEFI set up
//! before handing over. The loader queries GOP here, *before*
//! `ExitBootServices` (firmware services are dead afterwards), and writes
//! a fixed 40-byte `GopHandoff` block at handoff offset 5199 (see
//! `aegis-kernel/src/boot_info.rs`, `GOP_OFFSET` + `parse_gop`), exactly
//! mirroring how the fleet block is passed. If there is no GOP, or its
//! framebuffer is not directly CPU-writable (Bitmask/BltOnly formats),
//! the loader writes `present = 0` and the kernel falls back to its
//! Bochs-VBE PCI probe (QEMU) or the text backend alone.

use uefi::boot::{
    locate_handle_buffer, open_protocol, OpenProtocolAttributes, OpenProtocolParams, SearchType,
};
use uefi::proto::console::gop::{GraphicsOutput, ModeInfo, PixelFormat};
use uefi::Identify;

/// Offset of the GOP block inside the handoff page: directly after the
/// 55-byte fleet block (5144 + 55). Must match
/// `aegis-kernel/src/boot_info.rs` `GOP_OFFSET`.
pub const GOP_OFFSET: usize = 24 + 20 * 256 + 55; // 5199

/// Fixed serialized size of the GOP handoff block (40 bytes).
pub const GOP_BLOCK_SIZE: usize = 40;

/// Mirrors `aegis_kernel::boot_info::GopHandoff` byte-for-byte.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GopHandoff {
    /// 1 = block valid, 0 = absent/unusable.
    pub present: u32,
    /// GOP `PixelFormat` flattened: 0 = Rgb (RGBX8888), 1 = Bgr
    /// (BGRX8888). Bitmask/BltOnly are never reported (not CPU-writable).
    pub pixel_format: u32,
    pub width: u32,
    pub height: u32,
    /// Pixels per scan line (GOP `stride` — often wider than `width`).
    pub stride_px: u32,
    /// Bits per pixel (32 for both Rgb/Bgr formats).
    pub bpp: u32,
    pub framebuffer_base: u64,
    pub framebuffer_size: u64,
}

/// Serialize the GOP handoff into the exact bytes the kernel expects.
/// Stack-only: this runs after `ExitBootServices`, where the UEFI
/// allocator is dead — never allocate here.
pub fn to_handoff_bytes(h: &GopHandoff) -> [u8; GOP_BLOCK_SIZE] {
    let mut b = [0u8; GOP_BLOCK_SIZE];
    b[0..4].copy_from_slice(&h.present.to_le_bytes());
    b[4..8].copy_from_slice(&h.pixel_format.to_le_bytes());
    b[8..12].copy_from_slice(&h.width.to_le_bytes());
    b[12..16].copy_from_slice(&h.height.to_le_bytes());
    b[16..20].copy_from_slice(&h.stride_px.to_le_bytes());
    b[20..24].copy_from_slice(&h.bpp.to_le_bytes());
    b[24..32].copy_from_slice(&h.framebuffer_base.to_le_bytes());
    b[32..40].copy_from_slice(&h.framebuffer_size.to_le_bytes());
    b
}

/// Query the GOP framebuffer + current mode. Returns `None` when there is
/// no GOP, or the only one's framebuffer is not directly CPU-writable
/// (Bitmask/BltOnly pixel formats), or a field is degenerate — the kernel
/// then falls back to its Bochs-VBE probe. Must be called before
/// `ExitBootServices` (locate/open are boot services).
///
/// When the firmware's current mode is usable, the loader tries to switch
/// to a preferred 800x600 32bpp mode first (a `GraphicsOutput::set_mode`
/// call, i.e. real firmware mode-setting): the kernel demo scripts click
/// at 800x600 display coordinates, and 800x600 is in every firmware's mode
/// list (QEMU stdvga + real GPUs). If the switch fails the current mode is
/// handed over unchanged and the kernel centers its 640x400 desktop in it.
pub fn query() -> Option<GopHandoff> {
    uefi::println!("GOP: locate");
    let handles = locate_handle_buffer(SearchType::ByProtocol(&GraphicsOutput::GUID)).ok()?;
    let handle = *handles.first()?;
    uefi::println!("GOP: open");
    // Open with NO agent handle (BY_HANDLE_PROTOCOL): `open_protocol_exclusive`
    // passes the loader's image handle as the agent, and that OpenProtocol
    // call faults on the TP201S firmware (reboot). A raw BY_HANDLE_PROTOCOL
    // open asks only for the interface, which this firmware handles.
    let mut gop = unsafe {
        open_protocol::<GraphicsOutput>(
            OpenProtocolParams {
                handle,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;

    // Use the firmware's CURRENT mode as-is. We deliberately do NOT call
    // `set_mode` to switch to 800x600x32: on real hardware (the TP201S) the
    // UEFI SetMode boot service faulted here and the loader crashed before
    // the kernel ever started (the screen froze at "no FLEET.CFG"). The
    // kernel centers its desktop in whatever mode the firmware already has,
    // so the switch is not required for the boot path.
    uefi::println!("GOP: mode");
    let info = gop.current_mode_info();
    if !usable_mode(&info) {
        return None;
    }
    let (width, height) = info.resolution();
    let (width, height) = (width as u32, height as u32);
    let stride_px = info.stride() as u32;
    let (pixel_format, bpp) = match info.pixel_format() {
        PixelFormat::Bgr => (1u32, 32u32), // BGRX8888 (same as Bochs VBE)
        PixelFormat::Rgb => (0u32, 32u32), // RGBX8888 (common on real hw)
        _ => return None,                  // Bitmask/BltOnly: not CPU-writable
    };

    uefi::println!("GOP: fb");
    let mut fb = gop.frame_buffer();
    let framebuffer_base = fb.as_mut_ptr() as u64;
    let framebuffer_size = fb.size() as u64;
    if framebuffer_base == 0 || framebuffer_size == 0 {
        return None;
    }

    Some(GopHandoff {
        present: 1,
        pixel_format,
        width,
        height,
        stride_px,
        bpp,
        framebuffer_base,
        framebuffer_size,
    })
}

/// A mode is usable when the framebuffer is directly CPU-writable
/// (Rgb/Bgr 32bpp, non-degenerate geometry).
fn usable_mode(info: &ModeInfo) -> bool {
    let (width, height) = info.resolution();
    if width == 0 || height == 0 {
        return false;
    }
    if info.stride() < width {
        return false;
    }
    matches!(info.pixel_format(), PixelFormat::Bgr | PixelFormat::Rgb)
}

//! PS/2 mouse driver (Phase N): IRQ12 (slave 8259A IRQ4) delivers standard
//! 3-byte PS/2 mouse packets from the keyboard controller's auxiliary
//! port. The driver is a pure, total packet state machine
//! (`MouseState::feed_byte`) that never panics on any byte sequence: a byte
//! that cannot start a packet (bit 3 clear) is discarded for resync, and
//! completed packets decode into `input::MouseEvent`s pushed into a
//! bounded, allocation-free ring buffer (`input::InputBuffer`) that the
//! idle loop's input task drains and hands to `desktop::handle_mouse`.
//!
//! Interrupt routing: the kernel uses only the LAPIC (legacy PIC fully
//! masked at boot). The mouse interrupt is re-enabled through the same
//! virtual-wire path as the keyboard: IRQ12 is unmasked on the slave
//! (vector base 0x28 + 4 = 0x2C), the IRQ2 cascade is unmasked on the
//! master, LVT0 is set to ExtINT so the software-enabled LAPIC passes the
//! PIC's INTR through, and the slave's EOI is followed by the master's EOI
//! (the slave supplied the vector, delivered through the cascade).
//!
//! Honest limits: standard PS/2 3-byte packets only (no IntelliMouse
//! 4-byte wheel packets — the `scroll` field stays 0); the cursor is
//! clamped to the boot-time 800x600 framebuffer (`FB_W`/`FB_H`), which
//! matches the 800x600 mode set at boot; the port I/O paths are exercised
//! live under QEMU, while the translation is pure and unit-tested.

use core::arch::naked_asm;

use crate::input::{InputBuffer, InputEvent, MouseEvent};

/// Vector used for the PS/2 mouse IRQ12 (slave base 0x28 + 4, above the
/// 0-31 exception range and the keyboard's 0x21).
pub const MOUSE_VECTOR: u8 = 0x2C;

/// Boot-time framebuffer dimensions the cursor is clamped to. Honest
/// limit: this matches the 800x600 mode `gpu::BochsGpu::set_mode` installs
/// at boot; a future mode change must update these too.
pub const FB_W: i16 = 800;
pub const FB_H: i16 = 600;

/// PS/2 controller I/O ports (the same controller ports `ps2.rs` uses; the
/// mouse shares them, multiplexed by the 0xD4 "write to auxiliary device"
/// command).
const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
const PS2_CMD: u16 = 0x64;

/// Ring buffer holding decoded mouse events. Single producer (IRQ context)
/// / single consumer (idle loop); the consumer disables interrupts around
/// the pop so the pair never tears.
static mut MOUSE_BUF: Option<InputBuffer> = None;

/// Cursor + button state and the in-flight packet accumulator, shared by
/// the IRQ handler and, locally, by the tests.
static mut MOUSE_STATE: MouseState = MouseState::new();

/// PS/2 mouse decode state: the live cursor position, the button latches,
/// and the 3-byte packet accumulator.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MouseState {
    pub x: i16,
    pub y: i16,
    pub left: bool,
    pub right: bool,
    pub middle: bool,
    buf: [u8; 3],
    count: usize,
}

impl Default for MouseState {
    fn default() -> Self {
        Self::new()
    }
}

impl MouseState {
    /// Start centered on the boot-time framebuffer, all buttons up.
    pub const fn new() -> Self {
        Self {
            x: FB_W / 2,
            y: FB_H / 2,
            left: false,
            right: false,
            middle: false,
            buf: [0u8; 3],
            count: 0,
        }
    }

    /// Test constructor: start at an explicit pixel with no buttons held.
    #[cfg(test)]
    pub fn at(x: i16, y: i16) -> Self {
        Self {
            x,
            y,
            left: false,
            right: false,
            middle: false,
            buf: [0u8; 3],
            count: 0,
        }
    }

    /// Feed one PS/2 byte from the auxiliary port. Total: never panics on
    /// any byte sequence.
    ///
    /// Byte 0 of a packet carries the flags (bit 7 = Y overflow, bit 6 = X
    /// overflow, bit 5 = Y sign, bit 4 = X sign, bit 3 = always 1, bit 2 =
    /// middle, bit 1 = right, bit 0 = left); bytes 1 and 2 are the signed
    /// X/Y deltas. Resync rule: while looking for byte 0 (`count == 0`), a
    /// byte without bit 3 set is not a plausible packet start and is
    /// discarded (returns `None`, state unchanged). On the third byte the
    /// packet is decoded, the cursor and buttons update, and a
    /// `MouseEvent` is pushed into `out`; `Some(ev)` is returned on
    /// success, `None` if the ring buffer was full (the event is dropped,
    /// the ring stays coherent).
    pub fn feed_byte(&mut self, out: &mut InputBuffer, byte: u8) -> Option<MouseEvent> {
        if self.count == 0 && byte & 0x08 == 0 {
            return None; // out of sync: not a plausible packet start
        }
        self.buf[self.count] = byte;
        self.count += 1;
        if self.count < 3 {
            return None; // mid-packet: no event yet
        }
        self.count = 0; // full packet consumed

        let b0 = self.buf[0];
        let mut dx = self.buf[1] as i16;
        let mut dy = self.buf[2] as i16;
        if b0 & 0x10 != 0 {
            dx -= 256; // X sign bit
        }
        if b0 & 0x20 != 0 {
            dy -= 256; // Y sign bit
        }
        if b0 & 0xC0 != 0 {
            // Overflow bits: the true delta exceeded the signed 9-bit
            // range; clamp it rather than trust the truncated sample.
            dx = dx.clamp(-255, 255);
            dy = dy.clamp(-255, 255);
        }
        self.x = (self.x + dx).clamp(0, FB_W - 1);
        self.y = (self.y + dy).clamp(0, FB_H - 1);
        self.left = b0 & 0x01 != 0;
        self.right = b0 & 0x02 != 0;
        self.middle = b0 & 0x04 != 0;

        let ev = MouseEvent {
            x: self.x,
            y: self.y,
            left_button: self.left,
            right_button: self.right,
            scroll: 0,
        };
        if out.push(InputEvent::Mouse(ev)).is_ok() {
            Some(ev)
        } else {
            None // buffer full: drop the event, ring stays coherent
        }
    }
}

unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, preserves_flags));
    v
}

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, preserves_flags));
}

/// Enable IRQ12 on the PS/2 controller: enable the auxiliary port (0xA8),
/// flush any pending byte, set bit 1 (IRQ12) of the controller command
/// byte while clearing bit 5 (port-2 clock not disabled) and keeping
/// everything else (especially bit 6, scancode translation), then send
/// 0xF4 (enable data reporting) to the auxiliary device through the 0xD4
/// "write to port 2" command and drain the 0xFA ACK plus any strays.
unsafe fn init_controller() {
    outb(PS2_CMD, 0xA8); // enable auxiliary device (port 2)
    if inb(PS2_STATUS) & 0x01 != 0 {
        let _ = inb(PS2_DATA); // flush any pending byte
    }
    outb(PS2_CMD, 0x20); // read controller command byte
    if inb(PS2_STATUS) & 0x01 != 0 {
        let mut cmd = inb(PS2_DATA);
        crate::sprintln!("Aegis: [mouse] controller command byte = 0x{:02X}", cmd);
        cmd |= 0x02; // IRQ12 enable (bit 1)
        cmd &= !0x20; // port 2 clock not disabled (bit 5)
        outb(PS2_CMD, 0x60); // write controller command byte
        outb(PS2_DATA, cmd);
    }
    outb(PS2_CMD, 0xD4); // write to the auxiliary device (port 2)
    outb(PS2_DATA, 0xF4); // enable data reporting
    crate::sprintln!("Aegis: [mouse] data reporting enabled");
    // Drain the 0xFA ACK and any strays (bounded loop).
    for _ in 0..4 {
        if inb(PS2_STATUS) & 0x01 != 0 {
            let _ = inb(PS2_DATA);
        }
    }
}

/// Bring up the mouse. Must be called after `cpu::init_idt` (the 0x2C gate
/// must be live) and after `cpu::init_legacy_pic_irq12` (the slave IRQ12
/// and the master IRQ2 cascade must be unmasked).
///
/// # Safety
///
/// Single-threaded boot-time call; the static ring buffer must not be
/// touched concurrently.
pub unsafe fn init() {
    init_controller();
    core::ptr::addr_of_mut!(MOUSE_BUF).write(Some(InputBuffer::new()));
    crate::sprintln!(
        "Aegis: PS/2 mouse ready (IRQ12 -> vector 0x{:02X}, 3-byte packets)",
        MOUSE_VECTOR
    );
}

/// Pop the next decoded mouse event (if any). Disables interrupts around
/// the pop so the IRQ-producer/consumer pair cannot tear.
pub fn pop_event() -> Option<InputEvent> {
    unsafe {
        core::arch::asm!("cli", options(nomem));
        let ev = core::ptr::addr_of_mut!(MOUSE_BUF)
            .as_mut()
            .and_then(|o| o.as_mut())
            .and_then(|b| b.pop());
        core::arch::asm!("sti", options(nomem));
        ev
    }
}

/// Current cursor position (single-threaded kernel; read outside the IRQ
/// window by the compositor's re-blit path).
pub fn cursor_pos() -> (i16, i16) {
    unsafe { (MOUSE_STATE.x, MOUSE_STATE.y) }
}

/// Inject one raw PS/2-wire-format mouse packet byte from a non-PS/2 input
/// source (the USB HID boot-mouse poller in `usbhcd.rs`). Feeds the same
/// `MouseState`/`MOUSE_BUF` pair IRQ12 uses, byte by byte, so a full 3-byte
/// synthetic packet resyncs and decodes exactly like a real one. USB HID
/// boot-mouse reports (buttons byte, signed dx, signed dy) share the same
/// two's-complement-delta wire shape as PS/2 packets, so the byte values
/// need no translation beyond setting the flags byte's "always 1" bit 3.
///
/// # Safety
///
/// Same caveat as `ps2::inject_scancode`: not synchronized against the real
/// mouse IRQ beyond interrupt-disable around the access; on hardware with
/// no PS/2 controller (`PS2=N`) the real IRQ12 never fires, so there is no
/// actual race in practice.
pub unsafe fn inject_byte(byte: u8) {
    let buf = core::ptr::addr_of_mut!(MOUSE_BUF)
        .as_mut()
        .and_then(|o| o.as_mut());
    if let Some(b) = buf {
        let st = core::ptr::addr_of_mut!(MOUSE_STATE).as_mut().unwrap();
        let _ = st.feed_byte(b, byte);
    }
    // Reflect USB-HID-injected input on the diagnostic latch (the tablet has
    // no PS/2 controller, so the real IRQ12 ISR never fires to set it).
    crate::cpu::mark_mouse_fired();
}

/// Rust side of the mouse IRQ: read one PS/2 byte (if the controller has
/// one), feed the packet state machine, then EOI the slave 8259A (which
/// supplied the vector) and the master (the cascade it came through).
#[no_mangle]
pub extern "sysv64" fn mouse_trap_rust() {
    unsafe {
        let status = inb(PS2_STATUS);
        if status & 0x01 != 0 {
            let byte = inb(PS2_DATA);
            let buf = core::ptr::addr_of_mut!(MOUSE_BUF)
                .as_mut()
                .and_then(|o| o.as_mut());
            if let Some(b) = buf {
                let st = core::ptr::addr_of_mut!(MOUSE_STATE).as_mut().unwrap();
                let _ = st.feed_byte(b, byte);
            }
        }
        // EOI the slave (it supplied this vector via the IRQ2 cascade),
        // then the master (which forwarded it).
        outb(0xA0, 0x20);
        outb(0x20, 0x20);
    }
}

/// Interrupt gate stub for the mouse: save registers, run the Rust side,
/// restore, and return. Mirrors the keyboard stub's stack discipline.
#[unsafe(naked)]
#[no_mangle]
pub extern "sysv64" fn mouse_stub() -> ! {
    naked_asm!(
        "cli",
        "push rax", "push rcx", "push rdx", "push rsi", "push rdi",
        "push r8", "push r9", "push r10", "push r11",
        "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
        "sub rsp, 8",
        "call {trap}",
        "add rsp, 8",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
        "iretq",
        trap = sym mouse_trap_rust,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_updates_position_and_buttons() {
        let mut st = MouseState::at(100, 100);
        let mut buf = InputBuffer::new();
        // byte 0 = 0x09: bit 3 (always 1) + left button; dx=+5, dy=+3.
        st.feed_byte(&mut buf, 0x09);
        st.feed_byte(&mut buf, 5);
        let ev = st.feed_byte(&mut buf, 3).unwrap();
        assert_eq!((st.x, st.y), (105, 103));
        assert!(st.left);
        assert!(!st.right);
        assert!(!st.middle);
        assert_eq!(
            ev,
            MouseEvent {
                x: 105,
                y: 103,
                left_button: true,
                right_button: false,
                scroll: 0,
            }
        );
    }

    #[test]
    fn negative_deltas_from_sign_bits() {
        let mut st = MouseState::at(300, 300);
        let mut buf = InputBuffer::new();
        // byte 0 = 0x38: bit 3 + X sign + Y sign; deltas 5 and 3 decode as
        // 5 - 256 = -251 and 3 - 256 = -253.
        st.feed_byte(&mut buf, 0x38);
        st.feed_byte(&mut buf, 5);
        st.feed_byte(&mut buf, 3);
        assert_eq!((st.x, st.y), (300 - 251, 300 - 253));
        assert_eq!((st.x, st.y), (49, 47));
        assert!(!st.left);
    }

    #[test]
    fn position_clamps_at_edges() {
        let mut buf = InputBuffer::new();
        // At the bottom-right edge, positive deltas clamp in place.
        let mut st = MouseState::at(799, 599);
        st.feed_byte(&mut buf, 0x08); // bit 3 only, no buttons
        st.feed_byte(&mut buf, 10);
        st.feed_byte(&mut buf, 10);
        assert_eq!((st.x, st.y), (799, 599));
        // At the origin, sign-bit deltas (dx = 10 - 256 = -246, dy = -246)
        // clamp in place too.
        let mut st = MouseState::at(0, 0);
        st.feed_byte(&mut buf, 0x38); // bit 3 + X sign + Y sign
        st.feed_byte(&mut buf, 10);
        st.feed_byte(&mut buf, 10);
        assert_eq!((st.x, st.y), (0, 0));
    }

    #[test]
    fn out_of_sync_first_byte_is_discarded() {
        let mut st = MouseState::at(100, 100);
        let mut buf = InputBuffer::new();
        // A lone byte without bit 3 is not a plausible packet start.
        assert!(st.feed_byte(&mut buf, 0x00).is_none());
        assert_eq!(st.count, 0);
        assert!(buf.is_empty());
        // A valid packet then decodes normally.
        st.feed_byte(&mut buf, 0x09);
        st.feed_byte(&mut buf, 5);
        st.feed_byte(&mut buf, 3);
        assert_eq!((st.x, st.y), (105, 103));
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn resync_after_partial_packet() {
        let mut st = MouseState::at(100, 100);
        let mut buf = InputBuffer::new();
        // Partial packet: byte 0 and byte 1 arrive before the stream is
        // cut. The next byte completes the stale packet as garbage
        // (mid-packet bytes are raw deltas, accepted blindly), which
        // returns the machine to the byte-0 boundary — the resync point.
        st.feed_byte(&mut buf, 0x09);
        st.feed_byte(&mut buf, 5);
        st.feed_byte(&mut buf, 0x00); // garbage completes the stale packet
        assert_eq!(buf.len(), 1); // stale packet event pushed
        assert_eq!(st.count, 0); // back at the byte-0 boundary
                                 // Still out of sync: a byte-0 without bit 3 is discarded.
        st.feed_byte(&mut buf, 0x01);
        assert_eq!(buf.len(), 1); // discarded, count stays 0
                                  // A full valid packet now decodes correctly (5 + 5 in x, 0 + 3 in y).
        st.feed_byte(&mut buf, 0x09);
        st.feed_byte(&mut buf, 5);
        st.feed_byte(&mut buf, 3);
        assert_eq!((st.x, st.y), (110, 103));
        assert_eq!(buf.len(), 2);
        // FIFO: the stale packet event first, then the valid packet's.
        assert!(matches!(
            buf.pop(),
            Some(InputEvent::Mouse(m)) if m.x == 105 && m.y == 100
        ));
        assert!(matches!(
            buf.pop(),
            Some(InputEvent::Mouse(m)) if m.x == 110 && m.y == 103
        ));
    }

    #[test]
    fn button_state_tracks_packet() {
        let mut st = MouseState::at(100, 100);
        let mut buf = InputBuffer::new();
        // byte 0 = 0x0F: bit 3 + middle + right + left.
        st.feed_byte(&mut buf, 0x0F);
        st.feed_byte(&mut buf, 0);
        st.feed_byte(&mut buf, 0);
        assert!(st.left && st.right && st.middle);
        // byte 0 = 0x08: bit 3 only — all buttons release.
        st.feed_byte(&mut buf, 0x08);
        st.feed_byte(&mut buf, 0);
        st.feed_byte(&mut buf, 0);
        assert!(!st.left && !st.right && !st.middle);
    }

    #[test]
    fn overflow_bits_clamp_delta() {
        let mut st = MouseState::at(256, 256);
        let mut buf = InputBuffer::new();
        // byte 0 = 0xF8: bit 3 + X/Y sign + X/Y overflow; raw deltas 0 with
        // both sign bits decode to −256. The overflow clamp must reduce each
        // to −255, so the position lands exactly on (1, 1); without the
        // clamp it would land on (0, 0), which the position clamp alone
        // would otherwise hide at any start < 256.
        st.feed_byte(&mut buf, 0xF8);
        st.feed_byte(&mut buf, 0x00);
        st.feed_byte(&mut buf, 0x00);
        assert_eq!((st.x, st.y), (1, 1));
    }

    #[test]
    fn buffer_full_drops_event_without_corruption() {
        let mut st = MouseState::at(100, 100);
        let mut buf = InputBuffer::new();
        for _ in 0..64 {
            assert!(st.feed_byte(&mut buf, 0x09).is_none()); // byte 0
            st.feed_byte(&mut buf, 0); // byte 1
            assert!(st.feed_byte(&mut buf, 0).is_some()); // byte 2 -> event
        }
        assert!(buf.is_full());
        // The 65th packet is dropped (buffer full), the ring stays coherent.
        st.feed_byte(&mut buf, 0x09);
        st.feed_byte(&mut buf, 0);
        assert!(st.feed_byte(&mut buf, 0).is_none()); // dropped
        assert_eq!(buf.len(), 64);
        for _ in 0..64 {
            assert!(buf.pop().is_some());
        }
        assert!(buf.is_empty());
        assert!(buf.pop().is_none());
    }
}

//! PS/2 keyboard driver (roadmap §10 item 4: the shell's one real input
//! path). IRQ1 delivers a scancode from the keyboard controller; the driver
//! translates scancode-set-1 bytes (printable keys, Enter, Escape, Tab,
//! Backspace, Space, arrows) into `input::KeyEvent`s and pushes them into a
//! bounded, allocation-free ring buffer (`input::InputBuffer`), which the
//! idle loop drains and feeds to the window manager.
//!
//! Interrupt routing: the kernel uses only the LAPIC (legacy PIC fully
//! masked at boot). The keyboard interrupt is re-enabled through the
//! classic virtual-wire path: the master 8259A is remapped so IRQ1 presents
//! vector 0x21, LVT0 is set to ExtINT so the software-enabled LAPIC passes
//! the PIC's INTR through, and IRQ1 is unmasked on the master (everything
//! else stays masked — the LAPIC timer remains the only tick source). EOI
//! goes to the master PIC, which supplied the vector.
//!
//! Honest limits: scancode set 1 only (the default on QEMU/VMware); left
//! Shift and left Ctrl are tracked, right Ctrl/Alt are not; punctuation
//! keys have no `Key` variant in the `input` model, so they are dropped.
//! The translation is pure and unit-tested; the port I/O paths are
//! exercised live under QEMU/VMware.

use core::arch::naked_asm;

use crate::input::{InputBuffer, InputEvent, Key, KeyEvent, KeyModifiers};

/// Vector used for the PS/2 keyboard IRQ1 (above the 0-31 exception range,
/// below the LAPIC timer's 0x30).
pub const KEYBOARD_VECTOR: u8 = 0x21;

/// PS/2 controller I/O ports.
const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
const PS2_CMD: u16 = 0x64;

/// Ring buffer holding translated input events. Single producer (IRQ
/// context) / single consumer (idle loop); the consumer disables interrupts
/// around the pop so the pair never tears.
static mut KEY_BUF: Option<InputBuffer> = None;

/// Scancode-state machine (E0 prefix, shift, ctrl) shared by the IRQ
/// handler and, locally, by the tests.
static mut PS2_STATE: Ps2State = Ps2State::new();

/// Scancode-set-1 translation state.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ps2State {
    /// A 0xE0 prefix (extended scancode) is pending for the next byte.
    pub extended: bool,
    pub shift: bool,
    pub ctrl: bool,
}

impl Ps2State {
    pub const fn new() -> Self {
        Self {
            extended: false,
            shift: false,
            ctrl: false,
        }
    }

    /// Feed one scancode byte. Pushes a `Key` event (make or break) into
    /// `buf` and returns it, or `None` when the byte was part of a
    /// modifier/E0 sequence, was not a key the `input` model knows, or the
    /// buffer was full (event dropped — the ring stays coherent).
    pub fn feed(&mut self, buf: &mut InputBuffer, sc: u8) -> Option<KeyEvent> {
        if sc == 0xE0 {
            self.extended = true;
            return None;
        }
        let press = sc & 0x80 == 0;
        let code = sc & 0x7F;
        if !self.extended {
            match code {
                0x2A | 0x36 => {
                    self.shift = press;
                    return None;
                }
                0x1D => {
                    self.ctrl = press;
                    return None;
                }
                0x38 => return None, // left alt: no `Key` variant, ignored
                _ => {}
            }
        }
        let ext = self.extended;
        self.extended = false;
        let key = match translate(ext, code) {
            Some(k) => k,
            None => return None,
        };
        let ev = KeyEvent {
            key,
            pressed: press,
            modifiers: KeyModifiers {
                shift: self.shift,
                ctrl: self.ctrl,
                alt: false,
            },
        };
        if buf.push(InputEvent::Key(ev)).is_ok() {
            Some(ev)
        } else {
            None // buffer full: drop the event, ring stays coherent
        }
    }
}

/// Scancode-set-1 (make code) -> `Key`. `extended` marks the 0xE0-prefixed
/// set (arrows, keypad Enter).
fn translate(extended: bool, code: u8) -> Option<Key> {
    if extended {
        return match code {
            0x48 => Some(Key::ArrowUp),
            0x50 => Some(Key::ArrowDown),
            0x4B => Some(Key::ArrowLeft),
            0x4D => Some(Key::ArrowRight),
            0x1C => Some(Key::Enter),
            _ => None,
        };
    }
    match code {
        0x01 => Some(Key::Escape),
        0x02 => Some(Key::One),
        0x03 => Some(Key::Two),
        0x04 => Some(Key::Three),
        0x05 => Some(Key::Four),
        0x06 => Some(Key::Five),
        0x07 => Some(Key::Six),
        0x08 => Some(Key::Seven),
        0x09 => Some(Key::Eight),
        0x0A => Some(Key::Nine),
        0x0B => Some(Key::Zero),
        0x0E => Some(Key::Backspace),
        0x0F => Some(Key::Tab),
        0x1C => Some(Key::Enter),
        0x39 => Some(Key::Space),
        0x10 => Some(Key::Q),
        0x11 => Some(Key::W),
        0x12 => Some(Key::E),
        0x13 => Some(Key::R),
        0x14 => Some(Key::T),
        0x15 => Some(Key::Y),
        0x16 => Some(Key::U),
        0x17 => Some(Key::I),
        0x18 => Some(Key::O),
        0x19 => Some(Key::P),
        0x1E => Some(Key::A),
        0x1F => Some(Key::S),
        0x20 => Some(Key::D),
        0x21 => Some(Key::F),
        0x22 => Some(Key::G),
        0x23 => Some(Key::H),
        0x24 => Some(Key::J),
        0x25 => Some(Key::K),
        0x26 => Some(Key::L),
        0x2C => Some(Key::Z),
        0x2D => Some(Key::X),
        0x2E => Some(Key::C),
        0x2F => Some(Key::V),
        0x30 => Some(Key::B),
        0x31 => Some(Key::N),
        0x32 => Some(Key::M),
        _ => None,
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

/// Enable IRQ1 on the PS/2 controller: disable both ports, flush the output
/// buffer, set bit 0 (port 1 IRQ) of the controller command byte while
/// clearing bit 4 (port 1 clock disable) and keeping bit 6 (translation)
/// set so the controller converts scancode set 2 to set 1, then re-enable
/// port 1. The firmware already used the keyboard, so this is
/// belt-and-braces; it makes the IRQ source authoritative regardless of the
/// firmware's state.
unsafe fn init_controller() {
    outb(PS2_CMD, 0xAD); // disable port 1 device
    outb(PS2_CMD, 0xA7); // disable port 2 device
    if inb(PS2_STATUS) & 0x01 != 0 {
        let _ = inb(PS2_DATA); // flush any pending byte
    }
    outb(PS2_CMD, 0x20); // read controller command byte
    if inb(PS2_STATUS) & 0x01 != 0 {
        let mut cmd = inb(PS2_DATA);
        crate::sprintln!("Aegis: [kbd] controller command byte = 0x{:02X}", cmd);
        cmd |= 0x01; // IRQ1 enable
        cmd &= !0x10; // port 1 clock not disabled (bit 4)
        cmd |= 0x40; // translation on: controller converts set 2 -> set 1
        outb(PS2_CMD, 0x60);
        outb(PS2_DATA, cmd);
        crate::sprintln!("Aegis: [kbd] controller command byte set to 0x{:02X}", cmd);
    } else {
        crate::sprintln!("Aegis: [kbd] WARNING: no command-byte response from controller");
    }
    outb(PS2_CMD, 0xAE); // enable port 1 device
}

/// Bring up the keyboard. Must be called after `cpu::init_idt` (the IRQ1
/// gate must be live) and after `cpu::init_lapic_timer` (so the LAPIC is
/// software-enabled and LVT0 can be configured to ExtINT).
///
/// # Safety
///
/// Single-threaded boot-time call; the static ring buffer must not be
/// touched concurrently.
pub unsafe fn init() {
    init_controller();
    core::ptr::addr_of_mut!(KEY_BUF).write(Some(InputBuffer::new()));
    crate::sprintln!(
        "Aegis: PS/2 keyboard ready (IRQ1 -> vector 0x{:02X}, scancode set 1)",
        KEYBOARD_VECTOR
    );
}

/// Pop the next input event (if any). Disables interrupts around the pop so
/// the IRQ-producer/consumer pair cannot tear.
pub fn pop_event() -> Option<InputEvent> {
    unsafe {
        core::arch::asm!("cli", options(nomem));
        let ev = core::ptr::addr_of_mut!(KEY_BUF)
            .as_mut()
            .and_then(|o| o.as_mut())
            .and_then(|b| b.pop());
        core::arch::asm!("sti", options(nomem));
        ev
    }
}

/// Rust side of the keyboard IRQ: read one scancode (if the controller has
/// one), translate it into the ring buffer, then EOI the master PIC.
#[no_mangle]
pub extern "sysv64" fn keyboard_trap_rust() {
    unsafe {
        let status = inb(PS2_STATUS);
        crate::sprintln!("Aegis: [kbd] IRQ1 fired, status=0x{:02X}", status);
        if status & 0x01 != 0 {
            let sc = inb(PS2_DATA);
            crate::sprintln!("Aegis: [kbd] scancode 0x{:02X}", sc);
            let buf = core::ptr::addr_of_mut!(KEY_BUF)
                .as_mut()
                .and_then(|o| o.as_mut());
            if let Some(b) = buf {
                let st = core::ptr::addr_of_mut!(PS2_STATE).as_mut().unwrap();
                let _ = st.feed(b, sc);
            }
        }
        // EOI to the master 8259A (it supplied the vector via LVT0 ExtINT).
        outb(0x20, 0x20);
    }
}

/// Interrupt gate stub for the keyboard: save registers, run the Rust side,
/// restore, and return. Mirrors the timer stub's stack discipline.
#[unsafe(naked)]
#[no_mangle]
pub extern "sysv64" fn keyboard_stub() -> ! {
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
        trap = sym keyboard_trap_rust,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(key: Key, pressed: bool, shift: bool, ctrl: bool) -> InputEvent {
        InputEvent::Key(KeyEvent {
            key,
            pressed,
            modifiers: KeyModifiers {
                shift,
                ctrl,
                alt: false,
            },
        })
    }

    #[test]
    fn letter_scancode_produces_press_event() {
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        let out = st.feed(&mut buf, 0x1E).unwrap(); // 'a' make
        assert_eq!(
            out,
            KeyEvent {
                key: Key::A,
                pressed: true,
                modifiers: KeyModifiers::default(),
            }
        );
        assert_eq!(buf.pop(), Some(ev(Key::A, true, false, false)));
        assert!(buf.is_empty());
    }

    #[test]
    fn sequence_preserves_order_and_release() {
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        st.feed(&mut buf, 0x1E); // 'a' down
        st.feed(&mut buf, 0x9E); // 'a' up (break)
        st.feed(&mut buf, 0x0F); // Tab down
        st.feed(&mut buf, 0x8F); // Tab up (break)
        assert_eq!(buf.pop(), Some(ev(Key::A, true, false, false)));
        assert_eq!(buf.pop(), Some(ev(Key::A, false, false, false)));
        assert_eq!(buf.pop(), Some(ev(Key::Tab, true, false, false)));
        assert_eq!(buf.pop(), Some(ev(Key::Tab, false, false, false)));
        assert!(buf.is_empty());
    }

    #[test]
    fn extended_arrows_map_to_arrow_keys() {
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        for (sc, key) in [
            (0x48, Key::ArrowUp),
            (0x50, Key::ArrowDown),
            (0x4B, Key::ArrowLeft),
            (0x4D, Key::ArrowRight),
        ] {
            st.feed(&mut buf, 0xE0);
            st.feed(&mut buf, sc);
            assert_eq!(buf.pop(), Some(ev(key, true, false, false)));
        }
        // An extended release must not leak state into the next key.
        st.feed(&mut buf, 0xE0);
        st.feed(&mut buf, 0x48 | 0x80);
        assert_eq!(buf.pop(), Some(ev(Key::ArrowUp, false, false, false)));
        st.feed(&mut buf, 0x1E);
        assert_eq!(buf.pop(), Some(ev(Key::A, true, false, false)));
    }

    #[test]
    fn shift_tracks_modifier_state() {
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        st.feed(&mut buf, 0x2A); // left shift down
        st.feed(&mut buf, 0x1E);
        assert_eq!(buf.pop(), Some(ev(Key::A, true, true, false)));
        st.feed(&mut buf, 0xAA); // left shift up
        st.feed(&mut buf, 0x1E);
        assert_eq!(buf.pop(), Some(ev(Key::A, true, false, false)));
    }

    #[test]
    fn ctrl_tracks_modifier_state() {
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        st.feed(&mut buf, 0x1D); // left ctrl down
        st.feed(&mut buf, 0x0F); // Tab
        assert_eq!(buf.pop(), Some(ev(Key::Tab, true, false, true)));
        st.feed(&mut buf, 0x9D); // left ctrl up
        st.feed(&mut buf, 0x0F);
        assert_eq!(buf.pop(), Some(ev(Key::Tab, true, false, false)));
    }

    #[test]
    fn unmapped_and_e0_prefixed_scancodes_drop_cleanly() {
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        assert!(st.feed(&mut buf, 0x0C).is_none()); // '-': no Key variant
        assert!(st.feed(&mut buf, 0xE0).is_none()); // E0 prefix alone
        assert!(st.feed(&mut buf, 0x5B).is_none()); // extended, unmapped
        // The stray E0 prefix must not corrupt the next plain key.
        st.feed(&mut buf, 0x1E);
        assert_eq!(buf.pop(), Some(ev(Key::A, true, false, false)));
        assert!(buf.is_empty());
    }

    #[test]
    fn buffer_full_drops_event_without_corruption() {
        let mut st = Ps2State::new();
        let mut buf = InputBuffer::new();
        for _ in 0..64 {
            assert!(st.feed(&mut buf, 0x1E).is_some());
        }
        assert!(buf.is_full());
        assert!(st.feed(&mut buf, 0x0F).is_none()); // dropped
        assert_eq!(buf.len(), 64);
        for _ in 0..64 {
            assert_eq!(buf.pop(), Some(ev(Key::A, true, false, false)));
        }
        assert!(buf.is_empty());
        assert!(buf.pop().is_none());
    }
}
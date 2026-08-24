//! Minimal COM1 (serial) logger for the kernel.
//!
//! Same protocol as the bootloader's logger (115200 8N1, polled writes,
//! no IRQ, no FIFO tuning): the bootloader prints loader diagnostics to
//! COM1, and the kernel continues on the same port so the whole boot chain
//! lands in one serial log (QEMU `-serial file:` / VMware `serial.log`).
//!
//! Honest limits: polled transmit only, no receive, no flow control — a
//! boot diagnostic sink, not a driver.

use core::fmt::Write;

/// COM1 base port (only touched on the live kernel; unit tests never do
/// port I/O).
#[cfg(not(test))]
const COM1: u16 = 0x3F8;

/// SerialWriter — a `core::fmt::Write` sink that emits to COM1.
pub struct SerialWriter;

impl SerialWriter {
    pub fn init() {
        #[cfg(not(test))]
        {
            unsafe {
                // Disable interrupts, enable DLAB.
                core::arch::asm!("out dx, al", in("dx") COM1, in("al") 0x00u8, options(nomem, preserves_flags));
                core::arch::asm!("out dx, al", in("dx") COM1 + 1, in("al") 0x00u8, options(nomem, preserves_flags));
                // Baud divisor for 115200: 1 (1.8432 MHz / 16 / 1).
                core::arch::asm!("out dx, al", in("dx") COM1 + 3, in("al") 0x80u8, options(nomem, preserves_flags));
                core::arch::asm!("out dx, al", in("dx") COM1, in("al") 0x01u8, options(nomem, preserves_flags));
                core::arch::asm!("out dx, al", in("dx") COM1 + 1, in("al") 0x00u8, options(nomem, preserves_flags));
                // 8N1, DLAB off.
                core::arch::asm!("out dx, al", in("dx") COM1 + 3, in("al") 0x03u8, options(nomem, preserves_flags));
                // Enable FIFO, clear, 14-byte threshold.
                core::arch::asm!("out dx, al", in("dx") COM1 + 2, in("al") 0xC7u8, options(nomem, preserves_flags));
                // DTR/RTS.
                core::arch::asm!("out dx, al", in("dx") COM1 + 4, in("al") 0x0Bu8, options(nomem, preserves_flags));
            }
        }
    }

    /// Write raw bytes (no length prefix, no trailing newline). Used by
    /// the syscall `Write` path to emit user buffers verbatim.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.putc(b);
        }
    }

    fn putc(&mut self, c: u8) {
        #[cfg(not(test))]
        unsafe {
            // Wait for the transmit-holding-register-empty bit (bit 5 of LSR).
            loop {
                let mut status: u8 = 0;
                core::arch::asm!("in al, dx", out("al") status, in("dx") COM1 + 5, options(nomem, preserves_flags));
                if status & 0x20 != 0 {
                    break;
                }
            }
            core::arch::asm!("out dx, al", in("dx") COM1, in("al") c, options(nomem, preserves_flags));
        }
        #[cfg(test)]
        {
            let _ = c;
        }
    }
}

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            self.putc(b);
        }
        Ok(())
    }
}

/// Print a formatted line to COM1 (appends CRLF) and mirror it to the VGA
/// text console and the GOP framebuffer console, so the demo is visible on
/// the VM display and (on real hardware, where COM1 is unwired) on the
/// physical screen.
#[macro_export]
macro_rules! sprintln {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut w = $crate::serial::SerialWriter;
        let _ = w.write_fmt(format_args!($($arg)*));
        let _ = w.write_str("\r\n");
        $crate::vga::vga_fmt_line(format_args!($($arg)*));
        $crate::gop_console::mirror(format_args!($($arg)*));
    }};
}

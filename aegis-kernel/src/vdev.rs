//! Phase U: virtual devices for the hypervisor's guest — the classic
//! minimal-PC device set, all port-I/O based (no MMIO device emulation
//! needed for the Phase U DoD):
//!
//! - i8259A PIC (master 0x20-0x21, slave 0xA0-0xA1) — IRQ delivery
//! - 16550 UART (0x3F8-0x3FF, IRQ 4) — the guest's serial console
//! - 8254 PIT (0x40-0x43, channel 0 -> IRQ 0) — the guest's tick
//! - MC146818 CMOS RTC (0x70-0x71) — the guest's wall clock
//! - PCI config space (0xCF8/0xCFC) hosting a fake host bridge (needed for
//!   Linux's config-type-1 probe to succeed at all) and the virtio-blk
//!   device (which lives in `virtio.rs`; its I/O BAR is dynamic)
//!
//! The guest kernel is built and booted with `console=ttyS0,115200 noapic
//! nolapic` so it uses exactly this set and nothing else — no LAPIC, no
//! IO-APIC, no HPET, no ACPI. That is the honest minimum Aegis's hypervisor
//! must emulate for a real Linux guest to reach a shell.
//!
//! Everything here is pure emulation state and pure I/O logic — CPU-
//! independent and fully contract-testable. Wiring it to real VM-exit
//! events (guest port I/O arriving as exit reason 30) is the hardware-gated
//! half, in `vm.rs`. Known simplifications, deliberately scoped to "boot a
//! real Linux guest to a shell": no UART FIFO depth emulation (single-byte
//! buffer, FIFO-mode control bits stored only), no PIT sub-cycle OUT
//! waveforms (mode 2/3 both fire one IRQ0 per programmed count; BCD counts
//! stored but not decoded), no RTC alarm/NMI, no CMOS write-through, two
//! PCI slots beyond the host bridge (virtio-blk at slot 6, UHCI at slot 5),
//! no MSI-X/IO-APIC (guest is `noapic`),
//! no ACPI tables, unhandled port reads return 0xFF like a floating bus
//! rather than faulting (real-hardware behavior).
//!
//! Phase Z adds two guest-visible peripherals to the same set: a UHCI USB
//! host controller with a low-speed HID keyboard (16-bit registers at
//! 0xCC00, INTx#A -> PIC IRQ 10) and a Sound Blaster 16 DSP (0x220-0x237,
//! classic reset handshake + command surface). Both are pure register/state
//! models with a memory-agnostic data path (`UsbMem`), exercised live by the
//! hypervisor's run loop (`DeviceSet::usb_process`) and drained by host
//! hooks (key reports / playback requests). Honest simplifications: UHCI has
//! no bandwidth/reclamation scheduling, one low-speed device on port 1 only,
//! a bounded 64-TD-per-walk cap, and the SB16's 8237 DMA is not emulated —
//! a playback request carries the block length and sample rate only, leaving
//! the actual sample data path to the host audio hook.

use crate::virtio::BlockStore;

// ---------------------------------------------------------------------
// i8259A PIC
// ---------------------------------------------------------------------

/// i8259A dual-PIC emulation (master + slave, slave cascaded on master IRQ 2).
/// The guest programs its own ICW sequence (including the vector bases), so
/// the vectors returned here are exactly what the guest configured. The
/// per-PIC state is public: the run loop and the contract tests inspect it
/// directly (the same way `DeviceSet` exposes its devices).
pub struct Pic8259 {
    /// Master PIC state.
    pub master: PicState,
    /// Slave PIC state.
    pub slave: PicState,
}

/// One PIC's internal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PicState {
    /// Interrupt mask register (OCW1).
    pub imr: u8,
    /// Interrupt request register (raised lines).
    pub irr: u8,
    /// In-service register (acked, awaiting EOI).
    pub isr: u8,
    /// Vector base programmed by the guest (ICW2, high 5 bits).
    pub base: u8,
    /// ICW sequence state: which ICW comes next.
    pub icw_step: u8,
    /// ICW4 was programmed (bit 0 of ICW1).
    pub icw4: bool,
    /// Cascade mode (ICW1 bit 1 clear = cascaded).
    pub cascade: bool,
    /// OCW3 read selection: true = ISR, false = IRR.
    pub read_isr: bool,
    /// Automatic EOI (ICW4 bit 1).
    pub auto_eoi: bool,
}

impl Default for PicState {
    fn default() -> Self {
        Self::new()
    }
}

impl PicState {
    pub const fn new() -> PicState {
        PicState {
            imr: 0xFF,
            irr: 0,
            isr: 0,
            base: 0,
            icw_step: 0,
            icw4: false,
            cascade: false,
            read_isr: false,
            auto_eoi: false,
        }
    }

    /// Highest-priority (lowest-numbered) unmasked, pending, not-in-service
    /// IRQ, if any. Real 8259 semantics: while an IRQ is in service, only
    /// *higher*-priority lines may preempt it — everything at or below the
    /// lowest in-service line is held until the EOI (the lowest set ISR bit
    /// is the highest-priority in-service line).
    fn pending(&self) -> Option<u8> {
        let mut masked = self.irr & !self.imr;
        if self.isr != 0 {
            let lowest_isr = self.isr.trailing_zeros() as u8;
            masked &= (1u8 << lowest_isr) - 1;
        }
        if masked == 0 {
            None
        } else {
            Some(masked.trailing_zeros() as u8)
        }
    }
}

impl Default for Pic8259 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pic8259 {
    pub const fn new() -> Pic8259 {
        Pic8259 {
            master: PicState::new(),
            slave: PicState::new(),
        }
    }

    /// Raise an IRQ line (edge latched into IRR).
    pub fn raise(&mut self, irq: u8) {
        if irq < 8 {
            self.master.irr |= 1 << irq;
        } else if irq < 16 {
            // Cascade: the slave's output drives master IRQ 2.
            self.slave.irr |= 1 << (irq - 8);
            self.master.irr |= 1 << 2;
        }
    }

    /// Drop a level-triggered line (no-op for our edge/latch model, kept for
    /// API symmetry with device polling).
    pub fn lower(&mut self, _irq: u8) {}

    /// The next vector to inject, if any, and the IRQ it corresponds to.
    /// Matches INTA semantics: the acked IRQ moves IRR -> ISR.
    pub fn take_pending(&mut self) -> Option<(u8, u8)> {
        if let Some(irq) = self.master.pending() {
            if irq == 2 {
                // Cascade: the slave's own pending IRQ supplies the vector.
                if let Some(sirq) = self.slave.pending() {
                    self.slave.irr &= !(1 << sirq);
                    self.slave.isr |= 1 << sirq;
                    self.master.irr &= !(1 << 2);
                    self.master.isr |= 1 << 2;
                    return Some((self.slave.base + sirq, 8 + sirq));
                }
            }
            self.master.irr &= !(1 << irq);
            self.master.isr |= 1 << irq;
            return Some((self.master.base + irq, irq));
        }
        None
    }

    /// The next vector/IRQ to inject, if any — same INTA-style priority
    /// resolution as `take_pending` but without consuming (no IRR -> ISR
    /// move). The run loop peeks first to gate injection on the guest's
    /// interrupt state (RFLAGS.IF, STI/MOV-SS blocking) so an IRQ the
    /// guest is not ready for stays latched in the IRR for a later exit.
    pub fn peek_pending(&self) -> Option<(u8, u8)> {
        if let Some(irq) = self.master.pending() {
            if irq == 2 {
                if let Some(sirq) = self.slave.pending() {
                    return Some((self.slave.base + sirq, 8 + sirq));
                }
            }
            return Some((self.master.base + irq, irq));
        }
        None
    }

    /// Guest EOI (OCW2, non-specific or specific).
    fn eoi(&mut self, which: WhichPic, level: Option<u8>) {
        let pic = match which {
            WhichPic::Master => &mut self.master,
            WhichPic::Slave => &mut self.slave,
        };
        if let Some(l) = level {
            pic.isr &= !(1 << l);
            if which == WhichPic::Slave {
                // The cascade line on the master is in service only as long
                // as the slave has work; a slave EOI frees master IRQ 2.
                self.master.isr &= !(1 << 2);
            }
        } else {
            // Non-specific EOI: clear the highest-priority in-service bit.
            if pic.isr != 0 {
                let l = pic.isr.trailing_zeros() as u8;
                pic.isr &= !(1 << l);
                if which == WhichPic::Slave {
                    self.master.isr &= !(1 << 2);
                }
            }
        }
    }

    /// Port I/O. `port` is the absolute port; the guest only ever uses the
    /// two standard pairings.
    pub fn inb(&mut self, port: u16) -> u8 {
        match port {
            0x20 => {
                if self.master.read_isr {
                    self.master.isr
                } else {
                    self.master.irr
                }
            }
            0x21 => self.master.imr,
            0xA0 => {
                if self.slave.read_isr {
                    self.slave.isr
                } else {
                    self.slave.irr
                }
            }
            0xA1 => self.slave.imr,
            _ => 0xFF,
        }
    }

    pub fn outb(&mut self, port: u16, val: u8) {
        let (which, is_master) = match port {
            0x20 => (WhichPic::Master, true),
            0x21 => (WhichPic::Master, true),
            0xA0 => (WhichPic::Slave, false),
            0xA1 => (WhichPic::Slave, false),
            _ => return,
        };
        let pic = if is_master {
            &mut self.master
        } else {
            &mut self.slave
        };
        if port == 0x21 || port == 0xA1 {
            if pic.icw_step == 0 {
                // No ICW sequence in progress: OCW1 = IMR write.
                pic.imr = val;
            } else if pic.icw_step == 1 {
                // ICW2: vector base.
                pic.base = val & 0xF8;
                pic.icw_step = if pic.cascade { 2 } else { 3 };
            } else if pic.icw_step == 2 {
                // ICW3: cascade wiring (slave id / master slave-bit mask).
                pic.icw_step = 3;
            } else if pic.icw_step == 3 {
                // ICW4.
                pic.auto_eoi = val & 0x2 != 0;
                pic.icw_step = 0;
            }
            return;
        }
        // Command port (0x20 / 0xA0).
        if val & 0x10 != 0 {
            // ICW1.
            pic.icw4 = val & 0x1 != 0;
            pic.cascade = val & 0x2 == 0;
            pic.icw_step = 1;
            // ICW1 resets the read selection.
            pic.read_isr = false;
            return;
        }
        if val & 0x08 == 0 {
            // OCW2: EOI / rotate commands.
            let eoi = val & 0x20 != 0;
            let specific = val & 0x40 != 0;
            if eoi {
                let level = if specific { Some(val & 0x7) } else { None };
                self.eoi(which, level);
            }
            // Rotate/priority-set commands are accepted and ignored (no
            // priority rotation in this emulation — honest limit).
            return;
        }
        if val & 0x08 != 0 && val & 0x04 == 0 {
            // OCW3.
            if val & 0x2 != 0 {
                // OCW3 read command: D0 (RIS) selects ISR (1) / IRR (0).
                // Canonical values: 0x0B = read ISR, 0x0A = read IRR.
                pic.read_isr = val & 0x1 != 0;
            }
            if val & 0x40 != 0 {
                // Special mask mode: stored, not emulated (honest limit).
            }
            if val & 0x20 != 0 {
                // Poll command: report current pending as a status byte.
                // The guest sets this on the command port then reads it.
                // Linux uses the poll path on some boards; keep the flag so
                // the read returns the same byte (handled in inb below via
                // read_isr=false path — approximation, documented).
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WhichPic {
    Master,
    Slave,
}

// ---------------------------------------------------------------------
// 16550 UART
// ---------------------------------------------------------------------

/// 16550 UART emulation at 0x3F8-0x3FF, IRQ 4. Single-byte RX/TX buffers
/// (no FIFO depth emulation — control bits stored, depth not modeled).
pub struct Uart16550 {
    /// Divisor-latch access bit (LCR bit 7).
    dlab: bool,
    /// Interrupt enable register.
    ier: u8,
    /// FIFO control register.
    fcr: u8,
    /// Line control register.
    lcr: u8,
    /// Modem control register.
    mcr: u8,
    /// Line status register (reflects live state; computed on read).
    msr: u8,
    /// Scratch register.
    scr: u8,
    /// Baud divisor (DLL/DLM); stored for guest calibration reads, not used
    /// for timing (honest limit — output is immediate).
    divisor: u16,
    /// One byte of received data pending guest read, if any.
    rx: Option<u8>,
    /// One byte of transmitted data pending host pickup, if any.
    tx: Option<u8>,
}

impl Default for Uart16550 {
    fn default() -> Self {
        Self::new()
    }
}

impl Uart16550 {
    pub const fn new() -> Uart16550 {
        Uart16550 {
            dlab: false,
            ier: 0,
            fcr: 0,
            lcr: 0x03,
            mcr: 0,
            msr: 0x30,
            scr: 0,
            divisor: 1,
            rx: None,
            tx: None,
        }
    }

    /// IRQ 4 is asserted while a condition the guest enabled in IER holds.
    pub fn irq_line(&self) -> bool {
        (self.ier & 0x01 != 0 && self.rx.is_some()) || (self.ier & 0x02 != 0 && self.tx.is_none())
    }

    /// Feed a byte from the host (serial RX) into the guest's RBR.
    pub fn rx(&mut self, byte: u8) {
        self.rx = Some(byte);
    }

    /// Pick up a byte the guest wrote to THR, for the host to emit.
    pub fn take_tx(&mut self) -> Option<u8> {
        let b = self.tx.take();
        if b.is_some() {
            // THR emptied: a THRE interrupt condition becomes true again.
        }
        b
    }

    fn lsr(&self) -> u8 {
        let mut lsr = 0x60; // THRE + TEMT always true (no FIFO depth modeled)
        if self.rx.is_some() {
            lsr |= 0x01; // RX data ready
        }
        if self.rx.is_none() {
            lsr |= 0x20; // (already in 0x60)
        }
        lsr
    }

    fn iir(&self) -> u8 {
        let fifo = if self.fcr & 0x01 != 0 { 0xC0 } else { 0 };
        let pending = if self.ier & 0x01 != 0 && self.rx.is_some() {
            0x04 // RX data available
        } else if self.ier & 0x02 != 0 && self.tx.is_none() {
            0x02 // THR empty
        } else {
            0x01 // no interrupt pending
        };
        fifo | pending
    }

    pub fn inb(&mut self, port: u16) -> u8 {
        match port {
            0x3F8 if self.dlab => self.divisor as u8,        // DLL
            0x3F8 => self.rx.take().unwrap_or(0xFF),         // RBR
            0x3F9 if self.dlab => (self.divisor >> 8) as u8, // DLM
            0x3F9 => self.ier,
            0x3FA => self.iir(),
            0x3FB => self.lcr,
            0x3FC => self.mcr,
            0x3FD => self.lsr(),
            0x3FE => self.msr,
            0x3FF => self.scr,
            _ => 0xFF,
        }
    }

    pub fn outb(&mut self, port: u16, val: u8) {
        match port {
            0x3F8 if self.dlab => {
                self.divisor = (self.divisor & 0xFF00) | val as u16;
            }
            0x3F8 => {
                self.tx = Some(val);
            }
            0x3F9 if self.dlab => {
                self.divisor = (self.divisor & 0x00FF) | ((val as u16) << 8);
            }
            0x3F9 => self.ier = val & 0x0F,
            0x3FA => self.fcr = val,
            0x3FB => {
                self.lcr = val;
                self.dlab = val & 0x80 != 0;
            }
            0x3FC => self.mcr = val,
            0x3FD => {}
            0x3FE => self.msr = val,
            0x3FF => self.scr = val,
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------
// 8254 PIT
// ---------------------------------------------------------------------

/// 8254 PIT emulation. Only channel 0 (the system tick -> IRQ 0) is modeled
/// in any depth; channels 1/2 exist as selectable targets but never fire.
pub struct Pit8254 {
    /// Channel 0 state.
    pub ch0: PitChannel,
    /// Channels 1/2 (stored-only).
    ch1: PitChannel,
    ch2: PitChannel,
}

/// One PIT channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PitChannel {
    /// Access mode: 0 = latch, 1 = LSB, 2 = MSB, 3 = LSB-then-MSB.
    pub access: u8,
    /// Operating mode 0-5.
    pub mode: u8,
    /// BCD count flag (stored; binary-only counting — honest limit).
    pub bcd: bool,
    /// Count value the guest loaded (after both bytes in LSB-then-MSB).
    pub count: u16,
    /// Count remaining before the next IRQ (counts down per `advance`).
    pub remaining: u16,
    /// Bytes of a half-written count (LSB-then-MSB staging).
    partial: u8,
    /// Whether the LSB of a two-byte count is already staged.
    have_lsb: bool,
    /// Latched count for the guest's calibration reads.
    latch: u16,
    /// Read-side LSB/MSB toggle for two-byte reads, kept separate from the
    /// write-staging `have_lsb` flag (writes and reads must not interfere).
    read_high: bool,
}

impl Default for PitChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl PitChannel {
    pub const fn new() -> PitChannel {
        PitChannel {
            access: 3,
            mode: 3,
            bcd: false,
            count: 0,
            remaining: 0,
            partial: 0,
            have_lsb: false,
            latch: 0,
            read_high: false,
        }
    }

    /// Fire `n` PIT cycles into the channel. Returns the number of IRQ0
    /// pulses produced (mode 2/3: one per full count; mode 0: one when the
    /// count expires). Other modes never fire.
    pub fn advance(&mut self, n: u32) -> u32 {
        if self.count == 0 || n == 0 {
            return 0;
        }
        let mut pulses = 0u32;
        match self.mode {
            0 => {
                // One-shot: count down once; pulse on expiry, then stop
                // (a spent channel stays silent until a new count is loaded).
                if self.remaining == 0 {
                    return 0;
                }
                let steps = n as u16;
                if self.remaining <= steps {
                    self.remaining = 0;
                    pulses = 1;
                } else {
                    self.remaining -= steps;
                }
            }
            2 | 3 => {
                // Rate generator / square wave: reload and fire each period.
                for _ in 0..n {
                    self.remaining = self.remaining.saturating_sub(1);
                    if self.remaining == 0 {
                        self.remaining = self.count;
                        pulses += 1;
                    }
                }
            }
            _ => {}
        }
        pulses
    }
}

impl Default for Pit8254 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pit8254 {
    pub const fn new() -> Pit8254 {
        Pit8254 {
            ch0: PitChannel::new(),
            ch1: PitChannel::new(),
            ch2: PitChannel::new(),
        }
    }

    /// Advance all modeled channels by `n` PIT cycles; IRQ0 pulses on ch0.
    pub fn advance(&mut self, n: u32) -> u32 {
        self.ch0.advance(n) + self.ch1.advance(n) + self.ch2.advance(n)
    }

    /// Channel 2 OUT line (bit 7 of port 0x61): high once a mode-0 count
    /// has expired. The classic guest TSC-calibration path (the Linux
    /// kernel's `pit_calibrate_tsc`) runs channel 2 in mode 0 and reads
    /// the count to expiry, so this lets that calibration converge.
    pub fn ch2_out2(&self) -> bool {
        self.ch2.count != 0 && self.ch2.remaining == 0
    }

    fn channel(&mut self, sel: u8) -> &mut PitChannel {
        match sel {
            0 => &mut self.ch0,
            1 => &mut self.ch1,
            _ => &mut self.ch2,
        }
    }

    pub fn inb(&mut self, port: u16) -> u8 {
        match port {
            0x40 => Self::read_count(&mut self.ch0),
            0x41 => Self::read_count(&mut self.ch1),
            0x42 => Self::read_count(&mut self.ch2),
            0x43 => 0xFF, // command port is write-only
            _ => 0xFF,
        }
    }

    pub fn outb(&mut self, port: u16, val: u8) {
        match port {
            0x40 => Self::write_count(&mut self.ch0, val),
            0x41 => Self::write_count(&mut self.ch1, val),
            0x42 => Self::write_count(&mut self.ch2, val),
            0x43 => {
                let sel = (val >> 6) & 0x3;
                let access = (val >> 4) & 0x3;
                let mode = (val >> 1) & 0x7;
                let bcd = val & 0x1 != 0;
                if sel == 3 {
                    // Read-back command: latch all (approximation: latch the
                    // channels' current counts; the guest only uses this for
                    // calibration reads of ch0).
                    self.ch0.latch = self.ch0.remaining;
                    self.ch0.read_high = false;
                    self.ch1.latch = self.ch1.remaining;
                    self.ch1.read_high = false;
                    self.ch2.latch = self.ch2.remaining;
                    self.ch2.read_high = false;
                    return;
                }
                let ch = self.channel(sel);
                if access == 0 {
                    // Latch current count for reading; the first read after
                    // the latch returns the LSB.
                    ch.latch = ch.remaining;
                    ch.read_high = false;
                    return;
                }
                ch.access = access;
                ch.mode = mode;
                ch.bcd = bcd;
                ch.have_lsb = false;
            }
            _ => {}
        }
    }

    fn write_count(ch: &mut PitChannel, val: u8) {
        match ch.access {
            1 => {
                // LSB only.
                ch.count = val as u16;
                ch.remaining = ch.count;
            }
            2 => {
                // MSB only.
                ch.count = (val as u16) << 8;
                ch.remaining = ch.count;
            }
            _ => {
                // LSB then MSB.
                if !ch.have_lsb {
                    ch.partial = val;
                    ch.have_lsb = true;
                } else {
                    ch.count = ((val as u16) << 8) | ch.partial as u16;
                    ch.remaining = ch.count;
                    ch.have_lsb = false;
                }
            }
        }
    }

    fn read_count(ch: &mut PitChannel) -> u8 {
        let count = if ch.access == 0 {
            ch.latch
        } else {
            ch.remaining
        };
        match ch.access {
            1 => count as u8,
            2 => (count >> 8) as u8,
            _ => {
                // LSB then MSB: alternate which half the guest gets; the
                // guest normally latches first so the LSB read is stable.
                let b = if ch.read_high {
                    (count >> 8) as u8
                } else {
                    count as u8
                };
                ch.read_high = !ch.read_high;
                b
            }
        }
    }
}

// ---------------------------------------------------------------------
// MC146818 CMOS RTC
// ---------------------------------------------------------------------

/// Minimal CMOS RTC: the guest can read a plausible clock and status
/// registers. Time is a fixed epoch plus elapsed VM ticks (the host wall
/// clock is a hardware-gated refinement — see module docs).
pub struct CmosRtc {
    /// The register index the guest selected (0x70 write).
    index: u8,
    /// Seconds since the Unix epoch the clock starts from.
    epoch_seconds: u64,
    /// VM ticks (host timer ticks) elapsed since construction.
    elapsed: u64,
}

/// Convert a binary number to the hex-style BCD the RTC uses.
fn bin2bcd(v: u64) -> u8 {
    let lo = (v % 10) as u8;
    let hi = ((v / 10) % 10) as u8;
    (hi << 4) | lo
}

impl CmosRtc {
    pub const fn new(epoch_seconds: u64) -> CmosRtc {
        CmosRtc {
            index: 0,
            epoch_seconds,
            elapsed: 0,
        }
    }

    /// Advance VM time by `n` host ticks (one tick = one second, a coarse
    /// but honest mapping for the first increment; see module docs).
    pub fn advance_seconds(&mut self, n: u64) {
        self.elapsed += n;
    }

    fn read_reg(&self, reg: u8) -> u8 {
        // Fixed status values a real MC146818 power-on would present.
        match reg {
            0x0A => 0x26, // status A: 32.768 kHz crystal, 1024 Hz int freq
            0x0B => 0x02, // status B: 24-hour mode, no IRQ enables
            0x0C => 0x00, // status C: no interrupt flags
            0x0D => 0x80, // status D: CMOS RAM valid
            0x32 => 0x20, // century (2000s)
            _ => {
                // Time fields, BCD-encoded from the running clock.
                let t = self.epoch_seconds + self.elapsed;
                let days = t / 86400;
                let secs = t % 86400;
                let (hour, min, sec) = (secs / 3600, (secs % 3600) / 60, secs % 60);
                // Days since 1970-01-01; the civil-date math is approximate
                // around month boundaries but self-consistent (honest limit).
                let (y, m, d) = civil_from_days(days as i64);
                match reg {
                    0x00 => bin2bcd(sec),
                    0x02 => bin2bcd(min),
                    0x04 => bin2bcd(hour),
                    0x06 => bin2bcd(((days as i64 + 4) % 7 + 1) as u64), // day of week
                    0x07 => bin2bcd(d as u64),
                    0x08 => bin2bcd(m as u64),
                    0x09 => bin2bcd((y % 100) as u64),
                    0x32 => bin2bcd((y / 100) as u64),
                    _ => 0xFF, // unimplemented registers read back 0xFF
                }
            }
        }
    }

    pub fn inb(&mut self, port: u16) -> u8 {
        match port {
            0x70 => self.index,
            0x71 => self.read_reg(self.index & 0x3F),
            _ => 0xFF,
        }
    }

    pub fn outb(&mut self, port: u16, val: u8) {
        match port {
            0x70 => self.index = val,
            0x71 => {
                // Data writes: status registers are accepted (stored where
                // meaningful), time registers are ignored — the clock is
                // emulation-owned. Honest limit, documented.
            }
            _ => {}
        }
    }
}

/// Howard Hinnant's days->civil algorithm (public domain), used so the RTC
/// calendar math is correct rather than hand-rolled.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------
// PCI config space (0xCF8 / 0xCFC)
// ---------------------------------------------------------------------

/// The PCI devices this hypervisor fabricates: a fake host bridge (needed so
/// Linux's config-type-1 presence probe succeeds at all) and the virtio-blk
/// device (its register-level emulation lives in `virtio.rs`; the config
/// space here only carries identity, BAR, and IRQ line).
pub struct PciConfigBus {
    /// Shadow of the 0xCF8 CONFIG_ADDRESS register.
    address: u32,
    /// 256-byte config space shadow per device slot (0 = host bridge,
    /// 6 = virtio-blk).
    slots: [PciSlot; MAX_SLOTS],
    /// True while the guest is probing BAR sizes (all-ones write).
    probing_bar: [bool; MAX_SLOTS],
}

/// One fabricated PCI device slot.
#[derive(Clone, Copy)]
pub struct PciSlot {
    /// 256-byte config space shadow.
    pub config: [u8; 256],
}

pub const MAX_SLOTS: usize = 32;
/// Slot the virtio-blk device lives in.
pub const VIRTIO_SLOT: usize = 6;
/// IRQ line assigned to the virtio-blk device (INTx#A -> PIC IRQ 11).
pub const VIRTIO_IRQ: u8 = 11;

fn put_u16(config: &mut [u8; 256], off: usize, v: u16) {
    config[off] = v as u8;
    config[off + 1] = (v >> 8) as u8;
}

fn put_u32(config: &mut [u8; 256], off: usize, v: u32) {
    config[off] = v as u8;
    config[off + 1] = (v >> 8) as u8;
    config[off + 2] = (v >> 16) as u8;
    config[off + 3] = (v >> 24) as u8;
}

impl Default for PciConfigBus {
    fn default() -> Self {
        Self::new()
    }
}

impl PciConfigBus {
    pub const fn new() -> PciConfigBus {
        PciConfigBus {
            address: 0,
            slots: [PciSlot {
                config: [0xFF; 256],
            }; MAX_SLOTS],
            probing_bar: [false; MAX_SLOTS],
        }
    }

    /// Fabricate the host bridge (slot 0) and the virtio-blk device
    /// (slot 6) with the given 64-bit capacity in sectors.
    pub fn init(&mut self, capacity_sectors: u64) {
        let bridge = &mut self.slots[0].config;
        put_u16(bridge, 0x00, 0x8086); // vendor (Intel — matches the i440fx role)
        put_u16(bridge, 0x02, 0x1237); // device
        put_u16(bridge, 0x04, 0x0007); // command: I/O + memory + bus-master
        put_u16(bridge, 0x06, 0x0000); // status
        put_u32(bridge, 0x08, 0x06000000); // class: host bridge
        put_u16(bridge, 0x0E, 0x0000); // header type 0
        put_u16(bridge, 0x2C, 0x8086); // subsystem vendor
        put_u16(bridge, 0x2E, 0x0000); // subsystem id

        let blk = &mut self.slots[VIRTIO_SLOT].config;
        put_u16(blk, 0x00, 0x1AF4); // vendor: Red Hat / virtio
        put_u16(blk, 0x02, 0x1001); // device: virtio-blk (legacy)
        put_u16(blk, 0x04, 0x0007); // command: I/O + memory + bus-master
        put_u16(blk, 0x06, 0x0000); // status
        put_u32(blk, 0x08, 0x01800000); // class: mass-storage controller, block
        put_u16(blk, 0x0E, 0x0000); // header type 0
        put_u32(blk, 0x10, 0x0000_0001); // BAR0: I/O space, size 0x100, base 0
        put_u16(blk, 0x2C, 0x1AF4); // subsystem vendor
        put_u16(blk, 0x2E, 0x0001); // subsystem id: virtio-blk
        put_u8(blk, 0x3C, VIRTIO_IRQ); // interrupt line: PIC IRQ 11
        put_u8(blk, 0x3D, 0x01); // interrupt pin: INTx#A
        put_u16(blk, 0x3E, 0x0000); // min_gnt/max_lat
                                    // Device-specific config starts at the virtio config offset (0x18 of
                                    // the I/O region) — handled by virtio.rs, not here. The capacity is
                                    // stored for reference by the run loop.
        let _ = capacity_sectors;

        let uhci = &mut self.slots[UHCI_SLOT].config;
        put_u16(uhci, 0x00, 0x8086); // vendor: Intel (matches the UHCI role)
        put_u16(uhci, 0x02, 0x7020); // device: UHCI (USB 1.1 host controller)
        put_u16(uhci, 0x04, 0x0007); // command: I/O + memory + bus-master
        put_u16(uhci, 0x06, 0x0000); // status
        put_u32(uhci, 0x08, 0x0C030000); // class: serial bus controller, USB (UHCI)
        put_u16(uhci, 0x0E, 0x0000); // header type 0
        put_u32(uhci, 0x10, (UHCI_BASE as u32) | 0x1); // BAR0: I/O space, fixed base
        put_u16(uhci, 0x2C, 0x8086); // subsystem vendor
        put_u16(uhci, 0x2E, 0x7020); // subsystem id
        put_u8(uhci, 0x3C, UHCI_IRQ); // interrupt line: PIC IRQ 10
        put_u8(uhci, 0x3D, 0x01); // interrupt pin: INTx#A
        put_u16(uhci, 0x3E, 0x0000); // min_gnt/max_lat
    }

    /// The base port of the virtio-blk I/O BAR, once the guest programs it.
    pub fn virtio_bar(&self) -> u16 {
        let raw = u32_from(&self.slots[VIRTIO_SLOT].config, 0x10);
        if raw & 1 == 0 {
            return 0;
        }
        (raw & 0xFFFC) as u16
    }

    /// The base port of the fabricated UHCI I/O BAR (fixed at [`UHCI_BASE`]).
    pub fn uhci_bar(&self) -> u16 {
        let raw = u32_from(&self.slots[UHCI_SLOT].config, 0x10);
        if raw & 1 == 0 {
            return 0;
        }
        (raw & 0xFFFC) as u16
    }

    /// 32-bit write to the 0xCF8 CONFIG_ADDRESS register.
    pub fn write_address(&mut self, val: u32) {
        self.address = val;
    }

    /// 32-bit read from 0xCFC (CONFIG_DATA).
    pub fn read_data(&self) -> u32 {
        let addr = self.address;
        if addr & 0x8000_0000 == 0 {
            return 0xFFFF_FFFF;
        }
        let bus = (addr >> 16) & 0xFF;
        let dev = (addr >> 11) & 0x1F;
        let func = (addr >> 8) & 0x7;
        let reg = (addr >> 2) & 0x3F;
        if bus != 0 || func != 0 || (dev as usize) >= MAX_SLOTS {
            return 0xFFFF_FFFF;
        }
        let slot = &self.slots[dev as usize];
        let base = (reg as usize) * 4;
        // A BAR under an in-flight all-ones probe reports its size.
        if reg == 4 && self.probing_bar[dev as usize] {
            return 0x0000_00FD; // I/O BAR, 0x100 bytes
        }
        u32_from(&slot.config, base)
    }

    /// 32-bit write to 0xCFC (CONFIG_DATA).
    pub fn write_data(&mut self, val: u32) {
        let addr = self.address;
        if addr & 0x8000_0000 == 0 {
            return;
        }
        let bus = (addr >> 16) & 0xFF;
        let dev = (addr >> 11) & 0x1F;
        let func = (addr >> 8) & 0x7;
        let reg = (addr >> 2) & 0x3F;
        if bus != 0 || func != 0 || (dev as usize) >= MAX_SLOTS {
            return;
        }
        let slot = &mut self.slots[dev as usize];
        let base = (reg as usize) * 4;
        if reg == 4 {
            // BAR sizing probe: an all-ones write arms the size readback.
            self.probing_bar[dev as usize] = val == 0xFFFF_FFFF;
        }
        put_u32(&mut slot.config, base, val);
    }
}

fn u32_from(config: &[u8; 256], off: usize) -> u32 {
    (config[off] as u32)
        | ((config[off + 1] as u32) << 8)
        | ((config[off + 2] as u32) << 16)
        | ((config[off + 3] as u32) << 24)
}

/// Byte-write helper for config initialization.
fn put_u8(config: &mut [u8; 256], off: usize, v: u8) {
    config[off] = v;
}

// ---------------------------------------------------------------------
// UHCI USB host controller (Phase Z)
// ---------------------------------------------------------------------

/// UHCI I/O base (standard PCI-assigned base; also the fixed BAR this
/// hypervisor's fabricated UHCI PCI slot reports).
pub const UHCI_BASE: u16 = 0xCC00;
/// UHCI interrupt line (INTx#A -> PIC IRQ 10; IRQ 11 is the virtio-blk).
pub const UHCI_IRQ: u8 = 10;
/// PCI slot the fabricated UHCI device lives in.
pub const UHCI_SLOT: usize = 5;

/// Guest-memory interface the UHCI frame-list walk reads/writes through.
/// The live run loop will back it with EPT-mapped guest memory; the contract
/// tests and the boot demo back it with a fixed byte arena. Same discipline
/// as `acpi::PhysRead` / `vm::GuestMem` — the emulation is memory-agnostic.
pub trait UsbMem {
    fn read(&self, addr: u32, out: &mut [u8]) -> bool;
    fn write(&mut self, addr: u32, data: &[u8]) -> bool;

    fn read_u32(&self, addr: u32) -> Option<u32> {
        let mut b = [0u8; 4];
        if self.read(addr, &mut b) {
            Some(u32::from_le_bytes(b))
        } else {
            None
        }
    }

    fn write_u32(&mut self, addr: u32, v: u32) -> bool {
        self.write(addr, &v.to_le_bytes())
    }
}

/// A plain in-memory byte arena implementing [`UsbMem`] — the test and demo
/// backing store.
pub struct ByteArena<'a> {
    pub buf: &'a mut [u8],
}

impl UsbMem for ByteArena<'_> {
    fn read(&self, addr: u32, out: &mut [u8]) -> bool {
        let a = addr as usize;
        if a + out.len() <= self.buf.len() {
            out.copy_from_slice(&self.buf[a..a + out.len()]);
            true
        } else {
            false
        }
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> bool {
        let a = addr as usize;
        if a + data.len() <= self.buf.len() {
            self.buf[a..a + data.len()].copy_from_slice(data);
            true
        } else {
            false
        }
    }
}

/// A control transfer the HID keyboard has in flight (set by a SETUP TD,
/// consumed by the next data or status TD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UsbPending {
    None,
    GetDescriptor {
        desc_type: u8,
        index: u8,
        requested_len: u16,
        off: u16,
    },
    SetAddress(u8),
    SetConfig(u8),
    SetIdle(u8),
    SetProtocol(u8),
}

/// UHCI host-controller model with one low-speed HID keyboard attached to
/// port 1. Registers are 16-bit at `UHCI_BASE`; the frame-list TD engine
/// (the actual data path) is exercised by the run loop via
/// [`UhciUsb::process_frame_list`]. Port-I/O emulation and the TD walk are
/// pure and contract-tested; no MMIO, no interrupt controller of its own
/// (INTx#A -> PIC IRQ 10 through `DeviceSet::update_pic`).
pub struct UhciUsb {
    cmd: u16,
    sts: u16,
    intr: u16,
    frnum: u16,
    frbase: u32,
    sofmod: u8,
    portsc: [u16; 2],
    /// Assigned USB device address (0 = unaddressed, awaiting SET_ADDRESS).
    device_address: u8,
    configured: bool,
    idle: u8,
    protocol: u8,
    pending: UsbPending,
    /// Bounded ring of queued 8-byte keyboard reports (interrupt-IN drains).
    keys: [[u8; 8]; 16],
    key_count: usize,
    key_next: usize,
    /// Total TDs completed since reset (the run loop's progress counter).
    pub tds_processed: u64,
    /// Control requests the device does not understand (honest counter).
    pub unknown_requests: u32,
}

const UHCI_MAX_TDS_PER_WALK: usize = 64;
const UHCI_KEY_RING: usize = 16;

/// Standard 18-byte USB device descriptor for the HID keyboard.
const USB_DEVICE_DESC: [u8; 18] = [
    0x12, 0x01, // bLength, bDescriptorType (Device)
    0x10, 0x01, // bcdUSB 1.10
    0x00, 0x00, 0x00, // class/subclass/protocol (each interface defines)
    0x08, // bMaxPacketSize0
    0x34, 0x12, // idVendor 0x1234 (Aegis)
    0x01, 0x00, // idProduct 0x0001 (HID keyboard)
    0x00, 0x01, // bcdDevice 1.00
    0x00, 0x00, 0x00, // iManufacturer/Product/Serial
    0x01, // bNumConfigurations
];

/// 34-byte config descriptor: config + HID keyboard interface + interrupt IN
/// endpoint.
const USB_CONFIG_DESC: [u8; 34] = [
    0x09, 0x02, 0x22, 0x00, 0x01, 0x01, 0x00, 0xA0, 0x32, // config
    0x09, 0x04, 0x00, 0x00, 0x01, 0x03, 0x01, 0x01, 0x00, // interface (HID boot keyboard)
    0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x3F, 0x00, // HID 1.11, 1 report desc (63)
    0x07, 0x05, 0x81, 0x03, 0x08, 0x00, 0x0A, // EP1 IN, interrupt, 8 bytes, 10 ms
];

/// Standard boot-keyboard report descriptor (63 bytes).
const USB_REPORT_DESC: [u8; 63] = [
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01,
    0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06,
    0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xC0,
];

/// English LANGID string descriptor.
const USB_STRING_LANGID: [u8; 4] = [0x04, 0x03, 0x09, 0x04];

impl Default for UhciUsb {
    fn default() -> Self {
        Self::new()
    }
}

impl UhciUsb {
    pub const fn new() -> UhciUsb {
        UhciUsb {
            cmd: 0,
            // Bit 5 (HC Halted) set at reset, like a real UHCI after reset.
            sts: 0x0020,
            intr: 0,
            frnum: 0,
            frbase: 0,
            sofmod: 0x40,
            // Port 1: current connect status + low-speed device attached.
            portsc: [0x0011, 0x0000],
            device_address: 0,
            configured: false,
            idle: 0,
            protocol: 1,
            pending: UsbPending::None,
            keys: [[0u8; 8]; UHCI_KEY_RING],
            key_count: 0,
            key_next: 0,
            tds_processed: 0,
            unknown_requests: 0,
        }
    }

    /// 16-bit register read over the UHCI I/O range.
    pub fn inw(&self, port: u16) -> u16 {
        match port - UHCI_BASE {
            0x00 => self.cmd,
            0x02 => self.sts,
            0x04 => self.intr,
            0x06 => self.frnum & 0x7FF,
            0x08 => (self.frbase & 0xFFFF) as u16,
            0x0A => (self.frbase >> 16) as u16,
            0x0C => self.sofmod as u16,
            0x10 => self.portsc[0],
            0x12 => self.portsc[1],
            _ => 0xFFFF,
        }
    }

    /// 16-bit register write over the UHCI I/O range.
    pub fn outw(&mut self, port: u16, val: u16) {
        match port - UHCI_BASE {
            0x00 => {
                // USBCMD: RUN/STOP (bit 0); GRESET (bit 1) and FGR (bit 3)
                // reset the whole controller.
                if val & 0x000A != 0 {
                    *self = UhciUsb::new();
                    return;
                }
                self.cmd = val & 0x003F;
            }
            0x02 => {
                // USBSTS: RW1C for the status bits (0x3E); bit 0 (USBINT)
                // is cleared by writing 1 too.
                self.sts &= !(val & 0x003F);
            }
            0x04 => self.intr = val & 0x000F,
            0x06 => self.frnum = val & 0x07FF,
            0x08 => {
                let lo = val as u32;
                self.frbase = (self.frbase & 0xFFFF_0000) | lo;
                self.frbase &= 0xFFFF_F000; // page aligned
            }
            0x0A => {
                self.frbase = (self.frbase & 0x0000_FFFF) | ((val as u32) << 16);
            }
            0x0C => self.sofmod = (val & 0x7F) as u8,
            0x10 => self.write_portsc(0, val),
            0x12 => self.write_portsc(1, val),
            _ => {}
        }
    }

    /// PORTSC write semantics: RW1C change bits clear when written 1; the
    /// PR (port reset) bit arms a reset that completes when the driver
    /// clears it; CCS/LSDA are read-only.
    fn write_portsc(&mut self, port: usize, val: u16) {
        let mut cur = self.portsc[port];
        cur &= !(val & 0x4002); // CSC (bit 1) / OCC (bit 14) RW1C
        if val & (1 << 13) != 0 {
            cur |= 1 << 13; // PR: reset armed
            cur &= !0x0004; // PE cleared during reset
        } else {
            // PR cleared: complete the reset. Port 1 has the keyboard, so it
            // comes back connected + low-speed + enabled.
            cur &= !(1 << 13);
            if port == 0 {
                cur |= 0x0011 | 0x0004; // CCS | LSDA | PE
            }
        }
        self.portsc[port] = cur;
    }

    /// UHCI IRQ line: an interrupt-on-complete TD finished and IOC is enabled.
    pub fn irq_line(&self) -> bool {
        self.sts & 0x0001 != 0 && self.intr & 0x0001 != 0
    }

    /// The USB device address the guest has assigned (0 = unaddressed).
    pub fn device_address(&self) -> u8 {
        self.device_address
    }

    /// Whether the guest has completed SET_CONFIGURATION on the keyboard.
    pub fn configured(&self) -> bool {
        self.configured
    }

    /// Queue a keyboard report (8 bytes: modifier, reserved, 6 scancodes).
    /// Bounded: drops when the ring is full.
    pub fn enqueue_key(&mut self, report: [u8; 8]) {
        if self.key_count < UHCI_KEY_RING {
            let idx = (self.key_next + self.key_count) % UHCI_KEY_RING;
            self.keys[idx] = report;
            self.key_count += 1;
        }
    }

    fn pop_key(&mut self) -> Option<[u8; 8]> {
        if self.key_count == 0 {
            return None;
        }
        let r = self.keys[self.key_next];
        self.key_next = (self.key_next + 1) % UHCI_KEY_RING;
        self.key_count -= 1;
        Some(r)
    }

    /// Walk the current frame's TD list, executing each active TD against the
    /// HID keyboard model and writing the completion back to guest memory.
    /// Bounded (max [`UHCI_MAX_TDS_PER_WALK`] TDs, frame-list entry and every
    /// link validated) — never loops forever on a corrupt chain. Returns the
    /// number of TDs completed.
    pub fn process_frame_list(&mut self, mem: &mut impl UsbMem) -> usize {
        // Not running (RUN/STOP clear) or no frame list programmed: nothing.
        if self.cmd & 0x0001 == 0 || self.frbase == 0 {
            return 0;
        }
        let frame_idx = (self.frnum as usize) & 0x3FF;
        let Some(entry) = mem.read_u32(self.frbase + (frame_idx as u32) * 4) else {
            return 0;
        };
        if entry & 0x0000_0001 != 0 {
            return 0; // terminated frame-list entry
        }
        let mut td_addr = entry & 0xFFFF_FFF0;
        let mut processed = 0usize;
        loop {
            if processed >= UHCI_MAX_TDS_PER_WALK {
                break;
            }
            if td_addr & 0x0000_0001 != 0 {
                break; // link pointer terminate bit
            }
            let td = td_addr & 0xFFFF_FFF0;
            let Some(link) = mem.read_u32(td) else {
                break;
            };
            let Some(ctrl) = mem.read_u32(td + 4) else {
                break;
            };
            if ctrl & 0x0000_0001 == 0 {
                // Inactive TD: breadth-first walk continues to the link.
                if link & 0x0000_0001 != 0 {
                    break;
                }
                td_addr = link & 0xFFFF_FFF0;
                continue;
            }
            let Some(token) = mem.read_u32(td + 8) else {
                break;
            };
            let Some(buffer) = mem.read_u32(td + 12) else {
                break;
            };
            let pid = (token & 0xFF) as u8;
            let addr = ((token >> 8) & 0xFF) as u8;
            let endpoint = ((token >> 16) & 0x07) as u8;
            let mut maxlen = ((token >> 20) & 0x3FF) as usize;
            if maxlen == 0 {
                maxlen = 0x800; // UHCI: MaxLen 0 means 0x800
            }
            let buf = buffer & 0xFFFF_FFF0;
            let ioc = ctrl & 0x0000_0002 != 0;
            let done = self.execute_td(mem, pid, addr, endpoint, maxlen, buf);
            // Write the completion back: clear Active, set the status field
            // and the Actual-Length (bits 30:21) the HCD reads.
            let mut ctrl = ctrl & !0x0000_0001;
            ctrl = ctrl & !(0xFF << 16) | ((done.status as u32) << 16);
            ctrl = ctrl & !(0x3FF << 21) | ((done.actual_len as u32 & 0x3FF) << 21);
            let _ = mem.write_u32(td + 4, ctrl);
            if done.nak {
                // NAK also sets the NAK bit when the HCD armed NAK counting.
                let _ = mem.write_u32(td + 4, ctrl | 0x0000_0040);
            }
            if ioc {
                self.sts |= 0x0001; // USBINT
            }
            processed += 1;
            if link & 0x0000_0001 != 0 {
                break;
            }
            td_addr = link & 0xFFFF_FFF0;
        }
        self.tds_processed += processed as u64;
        if processed > 0 {
            self.frnum = (self.frnum + 1) & 0x7FF;
        }
        processed
    }

    /// Execute one TD against the device model, returning the completion
    /// status to write back. Never touches host memory beyond what the TD's
    /// buffer pointer grants through `mem`.
    fn execute_td(
        &mut self,
        mem: &mut impl UsbMem,
        pid: u8,
        addr: u8,
        endpoint: u8,
        maxlen: usize,
        buffer: u32,
    ) -> TdResult {
        let n = maxlen.min(64);
        match pid {
            // SETUP
            0x2D => {
                let mut setup = [0u8; 8];
                if mem.read(buffer, &mut setup) {
                    self.handle_setup(&setup);
                }
                TdResult {
                    status: 0,
                    actual_len: 8,
                    nak: false,
                }
            }
            // IN
            0x69 => {
                if endpoint == 1 {
                    // Interrupt IN: report when configured, else NAK.
                    if !self.configured {
                        return TdResult::nak();
                    }
                    match self.pop_key() {
                        Some(r) => {
                            let _ = mem.write(buffer, &r[..n.min(8)]);
                            TdResult {
                                status: 0,
                                actual_len: 8,
                                nak: false,
                            }
                        }
                        None => TdResult::nak(),
                    }
                } else {
                    // Endpoint 0: descriptor data stage / status stage.
                    match self.pending {
                        UsbPending::GetDescriptor {
                            desc_type,
                            index,
                            requested_len,
                            off,
                        } => {
                            let desc = self.descriptor(desc_type, index);
                            match desc {
                                Some(d) => {
                                    let off_us = off as usize;
                                    let remaining = d.len().saturating_sub(off_us);
                                    let want = (requested_len as usize).saturating_sub(off_us);
                                    let take = remaining.min(want).min(n);
                                    if take > 0 {
                                        let _ = mem.write(buffer, &d[off_us..off_us + take]);
                                    }
                                    let new_off = off_us + take;
                                    let done = new_off >= d.len() || take == 0;
                                    self.pending = if done {
                                        UsbPending::None
                                    } else {
                                        UsbPending::GetDescriptor {
                                            desc_type,
                                            index,
                                            requested_len,
                                            off: new_off as u16,
                                        }
                                    };
                                    TdResult {
                                        status: 0,
                                        actual_len: take as u16,
                                        nak: false,
                                    }
                                }
                                None => {
                                    self.unknown_requests += 1;
                                    self.pending = UsbPending::None;
                                    TdResult::stall()
                                }
                            }
                        }
                        UsbPending::SetAddress(a) => {
                            self.device_address = a;
                            self.pending = UsbPending::None;
                            TdResult::zero()
                        }
                        UsbPending::SetConfig(c) => {
                            self.configured = c == 1;
                            self.pending = UsbPending::None;
                            TdResult::zero()
                        }
                        UsbPending::SetIdle(v) => {
                            self.idle = v;
                            self.pending = UsbPending::None;
                            TdResult::zero()
                        }
                        UsbPending::SetProtocol(p) => {
                            self.protocol = p;
                            self.pending = UsbPending::None;
                            TdResult::zero()
                        }
                        UsbPending::None => TdResult::zero(),
                    }
                }
            }
            // OUT
            0xE1 => {
                if addr != 0 && !self.configured && endpoint == 1 {
                    return TdResult::nak();
                }
                if let UsbPending::SetConfig(_)
                | UsbPending::SetIdle(_)
                | UsbPending::SetProtocol(_) = self.pending
                {
                    // Status-stage OUT after a control setup with no data stage.
                    self.pending = UsbPending::None;
                }
                // Data we accept and discard (e.g. a SET_REPORT LED output).
                let mut sink = [0u8; 64];
                let take = n.min(64);
                let _ = mem.read(buffer, &mut sink[..take]);
                self.pending = UsbPending::None;
                TdResult {
                    status: 0,
                    actual_len: take as u16,
                    nak: false,
                }
            }
            _ => {
                self.unknown_requests += 1;
                TdResult::stall()
            }
        }
    }

    fn descriptor(&self, desc_type: u8, index: u8) -> Option<&'static [u8]> {
        if index != 0 {
            return None;
        }
        match desc_type {
            1 => Some(&USB_DEVICE_DESC),
            2 => Some(&USB_CONFIG_DESC),
            3 => Some(&USB_STRING_LANGID),
            0x22 => Some(&USB_REPORT_DESC),
            _ => None,
        }
    }

    fn handle_setup(&mut self, s: &[u8; 8]) {
        let bm = s[0];
        let req = s[1];
        let wvalue = u16::from_le_bytes([s[2], s[3]]);
        let wlength = u16::from_le_bytes([s[6], s[7]]);
        match (bm, req) {
            (0x80, 0x06) => {
                // GET_DESCRIPTOR: wValue high byte = type, low = index.
                let desc_type = (wvalue >> 8) as u8;
                let index = (wvalue & 0xFF) as u8;
                self.pending = UsbPending::GetDescriptor {
                    desc_type,
                    index,
                    requested_len: wlength,
                    off: 0,
                };
            }
            (0x00, 0x05) => {
                self.pending = UsbPending::SetAddress((wvalue & 0x7F) as u8);
            }
            (0x00, 0x09) => {
                self.pending = UsbPending::SetConfig((wvalue & 0xFF) as u8);
            }
            (0x21, 0x0A) => {
                self.pending = UsbPending::SetIdle((wvalue >> 8) as u8);
            }
            (0x21, 0x0B) => {
                self.pending = UsbPending::SetProtocol((wvalue & 0xFF) as u8);
            }
            _ => {
                self.unknown_requests += 1;
            }
        }
    }
}

/// Completion written back to a TD: the 8-bit status field (UHCI: 0x00 =
/// success, 0x04 = STALL, 0x05 = NAK), the actual transfer length, and the
/// NAK flag (sets the NAK bit when the HCD armed NAK counting).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TdResult {
    status: u8,
    actual_len: u16,
    nak: bool,
}

impl TdResult {
    fn zero() -> TdResult {
        TdResult {
            status: 0,
            actual_len: 0,
            nak: false,
        }
    }

    fn nak() -> TdResult {
        TdResult {
            status: 0x05,
            actual_len: 0,
            nak: true,
        }
    }

    fn stall() -> TdResult {
        TdResult {
            status: 0x04,
            actual_len: 0,
            nak: false,
        }
    }
}

// ---------------------------------------------------------------------
// Sound Blaster 16 DSP (Phase Z)
// ---------------------------------------------------------------------

/// SB16 DSP I/O base (the classic 0x220).
pub const SB16_BASE: u16 = 0x220;
/// Maximum pending playback requests the DSP keeps before the host hook
/// drains them.
pub const SB16_MAX_PLAYBACKS: usize = 8;

/// One completed DSP playback request awaiting the host audio hook: the block
/// length the guest programmed and the sample rate in effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaybackReq {
    pub length: u16,
    pub sample_rate: u32,
    pub auto_init: bool,
}

/// The next DSP command byte that needs a parameter byte written to 0x22C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DspPending {
    None,
    BlockLen1,
    BlockLen2Lo,
    BlockLen2Hi,
    SampleRateLo,
    SampleRateHi,
    TimeConstant,
}

/// Sound Blaster 16 DSP register-level model: the reset handshake, the
/// 0x22A read data path (status bit at 0x22E), the 0x22C write data path,
/// the classic command surface (version query, speaker, sample rate, single-
/// cycle / auto-init 8-bit output), and a bounded playback-request queue the
/// host audio hook drains. Honest simplification, documented in the module
/// docs: the 8237 DMA controller is NOT emulated — a playback request carries
/// the block length (and sample rate) only; the run loop/host hook is
/// responsible for the actual sample data path.
pub struct Sb16Dsp {
    read_buf: [u8; 8],
    read_len: usize,
    read_pos: usize,
    write_ready: bool,
    reset_done: bool,
    speaker_on: bool,
    sample_rate: u32,
    time_constant: u8,
    auto_init: bool,
    pending: DspPending,
    /// Staged low byte of a two-byte playback length (0x14/0x90/0x91).
    len_lo: u8,
    /// Staged low byte of a two-byte sample rate (0x41).
    rate_lo: u8,
    playbacks: [PlaybackReq; SB16_MAX_PLAYBACKS],
    playback_count: usize,
    pub unknown_cmds: u32,
    pub input_requests: u32,
}

const SB16_VERSION_HI: u8 = 0x04;
const SB16_VERSION_LO: u8 = 0x05;

impl Default for Sb16Dsp {
    fn default() -> Self {
        Self::new()
    }
}

impl Sb16Dsp {
    pub const fn new() -> Sb16Dsp {
        Sb16Dsp {
            read_buf: [0u8; 8],
            read_len: 0,
            read_pos: 0,
            write_ready: true,
            reset_done: false,
            speaker_on: true,
            sample_rate: 11025,
            time_constant: 0,
            auto_init: false,
            pending: DspPending::None,
            len_lo: 0,
            rate_lo: 0,
            playbacks: [PlaybackReq {
                length: 0,
                sample_rate: 0,
                auto_init: false,
            }; SB16_MAX_PLAYBACKS],
            playback_count: 0,
            unknown_cmds: 0,
            input_requests: 0,
        }
    }

    fn push_read(&mut self, byte: u8) {
        if self.read_len < self.read_buf.len() {
            let idx = (self.read_pos + self.read_len) % self.read_buf.len();
            self.read_buf[idx] = byte;
            self.read_len += 1;
        }
    }

    /// 8-bit port read over 0x220..0x237.
    pub fn inb(&mut self, port: u16) -> u8 {
        match port - SB16_BASE {
            0x06 => 0, // reset port reads return 0
            0x0A => {
                // DSP read data.
                if self.read_len == 0 {
                    0
                } else {
                    let b = self.read_buf[self.read_pos];
                    self.read_pos = (self.read_pos + 1) % self.read_buf.len();
                    self.read_len -= 1;
                    b
                }
            }
            0x0E => {
                // DSP read status: bit 7 = data ready to read.
                if self.read_len > 0 {
                    0x80
                } else {
                    0
                }
            }
            0x0C => {
                // DSP write status: bit 7 = ready to write.
                if self.write_ready {
                    0x80
                } else {
                    0
                }
            }
            _ => 0xFF,
        }
    }

    /// 8-bit port write over 0x220..0x237.
    pub fn outb(&mut self, port: u16, val: u8) {
        match port - SB16_BASE {
            0x06 => {
                // DSP reset: a 1 pulse arms the 0xAA handshake; the 0 clears.
                if val != 0 {
                    // Reset latches until a 0 write completes the handshake.
                    self.write_ready = true;
                } else {
                    self.reset_done = true;
                    self.read_len = 0;
                    self.read_pos = 0;
                    self.push_read(0xAA);
                }
            }
            0x0C => {
                // DSP write data.
                self.write_ready = false;
                match self.pending {
                    DspPending::BlockLen1 => {
                        let len = val as u16;
                        self.enqueue_playback(len);
                        self.pending = DspPending::None;
                        self.write_ready = true;
                    }
                    DspPending::BlockLen2Lo => {
                        self.pending = DspPending::BlockLen2Hi;
                        self.len_lo = val;
                        self.write_ready = true;
                    }
                    DspPending::BlockLen2Hi => {
                        let len = ((val as u16) << 8) | self.len_lo as u16;
                        self.pending = DspPending::None;
                        self.enqueue_playback(len);
                        self.write_ready = true;
                    }
                    DspPending::SampleRateLo => {
                        self.rate_lo = val;
                        self.pending = DspPending::SampleRateHi;
                        self.write_ready = true;
                    }
                    DspPending::SampleRateHi => {
                        let rate = ((val as u32) << 8) | self.rate_lo as u32;
                        self.sample_rate = rate;
                        self.pending = DspPending::None;
                        self.write_ready = true;
                    }
                    DspPending::TimeConstant => {
                        self.time_constant = val;
                        // 256 - (1_000_000 / rate); store, rate derived later.
                        self.pending = DspPending::None;
                        self.write_ready = true;
                    }
                    DspPending::None => self.command(val),
                }
            }
            _ => {}
        }
    }

    fn command(&mut self, cmd: u8) {
        match cmd {
            0xE1 => {
                // Get version.
                self.push_read(SB16_VERSION_HI);
                self.push_read(SB16_VERSION_LO);
            }
            0xD1 => self.speaker_on = true,
            0xD3 => self.speaker_on = false,
            0x40 => self.pending = DspPending::TimeConstant,
            0x41 => self.pending = DspPending::SampleRateLo,
            0x10 => self.pending = DspPending::BlockLen1,
            0x14 => self.pending = DspPending::BlockLen2Lo,
            0x90 => {
                // DAC 8-bit single-cycle (2-byte length).
                self.auto_init = false;
                self.pending = DspPending::BlockLen2Lo;
            }
            0x91 => {
                // DAC 8-bit auto-init (2-byte length).
                self.auto_init = true;
                self.pending = DspPending::BlockLen2Lo;
            }
            0xD0 => { /* pause: no streaming state to pause yet */ }
            0xD4 => { /* resume */ }
            0xC0 | 0xC8 => self.input_requests += 1,
            _ => self.unknown_cmds += 1,
        }
        self.write_ready = true;
    }

    fn enqueue_playback(&mut self, length: u16) {
        if self.playback_count < SB16_MAX_PLAYBACKS {
            self.playbacks[self.playback_count] = PlaybackReq {
                length,
                sample_rate: self.sample_rate,
                auto_init: self.auto_init,
            };
            self.playback_count += 1;
        }
        self.auto_init = false;
    }

    /// Number of playback requests awaiting the host audio hook.
    pub fn pending_playbacks(&self) -> usize {
        self.playback_count
    }

    /// Pop the oldest playback request for the host audio hook.
    pub fn pop_playback(&mut self) -> Option<PlaybackReq> {
        if self.playback_count == 0 {
            return None;
        }
        let r = self.playbacks[0];
        self.playbacks.copy_within(1..self.playback_count, 0);
        self.playback_count -= 1;
        Some(r)
    }

    pub fn reset_done(&self) -> bool {
        self.reset_done
    }

    pub fn speaker_on(&self) -> bool {
        self.speaker_on
    }

    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    pub fn time_constant(&self) -> u8 {
        self.time_constant
    }

    pub fn version(&self) -> (u8, u8) {
        (SB16_VERSION_HI, SB16_VERSION_LO)
    }
}

// ---------------------------------------------------------------------
// The combined device set
// ---------------------------------------------------------------------

/// Everything the guest can touch in its I/O space. The run loop dispatches
/// VM-exit port I/O here; `update_pic` is called after every I/O op to
/// reflect device lines into the PIC. Generic over the virtio-blk block
/// store so the same emulation serves the kernel's object-store-backed disk
/// and the contract tests' memory disk.
pub struct DeviceSet<'a, S: BlockStore> {
    pub pic: Pic8259,
    pub uart: Uart16550,
    pub pit: Pit8254,
    pub rtc: CmosRtc,
    pub pci: PciConfigBus,
    /// The virtio-blk device (legacy PCI, I/O BAR, INTx#A -> IRQ 11).
    pub virtio: crate::virtio::VirtioBlk<'a, S>,
    /// The UHCI USB host controller with the HID keyboard (I/O BAR
    /// 0xCC00, INTx#A -> IRQ 10). The run loop drives the frame-list walk
    /// through [`DeviceSet::usb_process`].
    pub usb: UhciUsb,
    /// The Sound Blaster 16 DSP (0x220-0x237). Playback requests are
    /// drained by the host audio hook.
    pub audio: Sb16Dsp,
    /// Port 0x61 refresh-flag state (bit 5 toggles on every read).
    pit61_refresh: bool,
}

impl<'a, S: BlockStore> DeviceSet<'a, S> {
    pub fn new(store: &'a mut S, rtc_epoch_seconds: u64) -> DeviceSet<'a, S> {
        let capacity = store.capacity_sectors();
        let mut ds = DeviceSet {
            pic: Pic8259::new(),
            uart: Uart16550::new(),
            pit: Pit8254::new(),
            rtc: CmosRtc::new(rtc_epoch_seconds),
            pci: PciConfigBus::new(),
            virtio: crate::virtio::VirtioBlk::new(store),
            usb: UhciUsb::new(),
            audio: Sb16Dsp::new(),
            pit61_refresh: false,
        };
        ds.pci.init(capacity);
        ds
    }

    /// 8-bit port read. Unhandled ports read 0xFF (floating-bus behavior).
    pub fn inb(&mut self, port: u16) -> u8 {
        match port {
            0x20 | 0x21 | 0xA0 | 0xA1 => self.pic.inb(port),
            0x3F8..=0x3FF => self.uart.inb(port),
            0x40..=0x43 => self.pit.inb(port),
            0x61 => {
                // PIT2 status port: OUT2 on bit 7, refresh flag toggling
                // on bit 5 (the guest kernel's timer calibration reads
                // this during boot).
                self.pit61_refresh = !self.pit61_refresh;
                let out2 = if self.pit.ch2_out2() { 0x80 } else { 0 };
                let refresh = if self.pit61_refresh { 0x20 } else { 0 };
                out2 | refresh | 0x10
            }
            0x70 | 0x71 => self.rtc.inb(port),
            0x220..=0x237 => self.audio.inb(port),
            _ => {
                let bar = self.pci.virtio_bar();
                if bar != 0 && (port as u32) >= bar as u32 && (port as u32) < bar as u32 + 0x100 {
                    self.virtio.legacy_inb(port - bar)
                } else {
                    0xFF
                }
            }
        }
    }

    /// 8-bit port write. Unhandled ports are ignored (floating-bus).
    pub fn outb(&mut self, port: u16, val: u8) {
        match port {
            0x20 | 0x21 | 0xA0 | 0xA1 => self.pic.outb(port, val),
            0x3F8..=0x3FF => self.uart.outb(port, val),
            0x40..=0x43 => self.pit.outb(port, val),
            0x70 | 0x71 => self.rtc.outb(port, val),
            0x220..=0x237 => self.audio.outb(port, val),
            _ => {
                let bar = self.pci.virtio_bar();
                if bar != 0 && (port as u32) >= bar as u32 && (port as u32) < bar as u32 + 0x100 {
                    self.virtio.legacy_outb(port - bar, val);
                }
            }
        }
    }

    /// 16-bit port read: the UHCI registers (0xCC00-0xCC1F) and the virtio
    /// I/O BAR (QUEUE_NUM / QUEUE_NUM_MAX); everything else in this device
    /// set is byte- or dword-oriented, so 16-bit accesses to other ranges
    /// return the floating-bus value.
    pub fn inw(&mut self, port: u16) -> u16 {
        if (UHCI_BASE..UHCI_BASE + 0x20).contains(&port) {
            return self.usb.inw(port);
        }
        let bar = self.pci.virtio_bar();
        if bar != 0 && (port as u32) >= bar as u32 && (port as u32) < bar as u32 + 0x100 {
            self.virtio.legacy_inw(port - bar)
        } else {
            0xFFFF
        }
    }

    /// 16-bit port write: the UHCI registers and the virtio I/O BAR
    /// (QUEUE_NUM / QUEUE_SEL / QUEUE_NOTIFY); other ranges are ignored
    /// (floating-bus).
    pub fn outw(&mut self, port: u16, val: u16) {
        if (UHCI_BASE..UHCI_BASE + 0x20).contains(&port) {
            self.usb.outw(port, val);
            return;
        }
        let bar = self.pci.virtio_bar();
        if bar != 0 && (port as u32) >= bar as u32 && (port as u32) < bar as u32 + 0x100 {
            self.virtio.legacy_outw(port - bar, val);
        }
    }

    /// 32-bit port read: PCI config space and the virtio I/O BAR.
    pub fn inl(&mut self, port: u16) -> u32 {
        match port {
            0xCF8 => self.pci.address,
            0xCFC => self.pci.read_data(),
            _ => {
                let bar = self.pci.virtio_bar();
                if bar != 0 && (port as u32) >= bar as u32 && (port as u32) < bar as u32 + 0x100 {
                    self.virtio.legacy_inl(port - bar)
                } else {
                    0xFFFF_FFFF
                }
            }
        }
    }

    /// 32-bit port write: PCI config space and the virtio I/O BAR.
    pub fn outl(&mut self, port: u16, val: u32) {
        match port {
            0xCF8 => self.pci.write_address(val),
            0xCFC => self.pci.write_data(val),
            _ => {
                let bar = self.pci.virtio_bar();
                if bar != 0 && (port as u32) >= bar as u32 && (port as u32) < bar as u32 + 0x100 {
                    self.virtio.legacy_outl(port - bar, val);
                }
            }
        }
    }

    /// The next vector to inject into the guest, if any (with the PIC
    /// ack semantics applied). The run loop calls this before each entry.
    pub fn pic_pending_vector(&mut self) -> Option<u8> {
        self.pic.take_pending().map(|(v, _)| v)
    }

    /// Non-consuming look at the PIC's next injectable vector. The run
    /// loop peeks first so an IRQ the guest is not ready for (IF clear,
    /// interrupt blocking active) stays latched in the IRR until a later
    /// exit, instead of being lost by the ack.
    pub fn pic_peek_vector(&self) -> Option<u8> {
        self.pic.peek_pending().map(|(v, _)| v)
    }

    /// Recompute PIC IRR from device lines and PIT pulses. Called by the
    /// run loop after any device activity.
    pub fn update_pic(&mut self, pit_pulses: u32) {
        for _ in 0..pit_pulses {
            self.pic.raise(0); // PIT channel 0 -> IRQ 0
        }
        if self.uart.irq_line() {
            self.pic.raise(4);
        }
        if self.virtio.irq_line() {
            self.pic.raise(VIRTIO_IRQ);
        }
        if self.usb.irq_line() {
            self.pic.raise(UHCI_IRQ);
        }
    }

    /// Drive the UHCI frame-list walk (the run loop calls this on the guest's
    /// behalf each time the UHCI is running); reflects resulting IRQ lines
    /// into the PIC. Returns the number of TDs completed.
    pub fn usb_process(&mut self, mem: &mut impl UsbMem) -> usize {
        let done = self.usb.process_frame_list(mem);
        self.update_pic(0);
        done
    }

    /// Feed a byte from the host serial port into the guest UART.
    pub fn host_rx(&mut self, byte: u8) {
        self.uart.rx(byte);
    }

    /// A byte the guest console emitted, for the host serial port.
    pub fn take_guest_tx(&mut self) -> Option<u8> {
        self.uart.take_tx()
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test block store: a plain byte vector served at 512-byte sectors.
    struct MemStore {
        bytes: Vec<u8>,
        capacity: u64,
    }

    impl MemStore {
        fn new(sectors: u64) -> MemStore {
            MemStore {
                bytes: vec![0u8; (sectors * 512) as usize],
                capacity: sectors,
            }
        }
    }

    impl BlockStore for MemStore {
        fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> bool {
            let start = (lba * 512) as usize;
            let end = start + 512;
            if end > self.bytes.len() {
                return false;
            }
            out[..512].copy_from_slice(&self.bytes[start..end]);
            true
        }
        fn write_sector(&mut self, lba: u64, data: &[u8]) -> bool {
            let start = (lba * 512) as usize;
            let end = start + 512;
            if end > self.bytes.len() {
                return false;
            }
            self.bytes[start..end].copy_from_slice(&data[..512]);
            true
        }
        fn capacity_sectors(&self) -> u64 {
            self.capacity
        }
    }

    /// Phase AE: every guest-facing device model is untrusted-input surface —
    /// a malicious guest drives arbitrary port/register sequences against the
    /// whole fabricated device set (PIC, UART, PIT, RTC, PCI config, virtio
    /// BAR, UHCI, SB16) through the single guest port surface `DeviceSet`
    /// exposes. Sweep hostile (port, value) pairs (real ports + random,
    /// structured ICW/OCW/mode words + random bytes, byte and dword widths)
    /// and assert total no-panic. The stateful sequence matters: a hostile
    /// ICW command can leave the PIC mid-ICW, so the sweep interleaves reads
    /// and writes on one live device rather than a fresh one per input.
    #[test]
    #[cfg_attr(miri, ignore)] // interpreted sweep; the fixed vectors still run under Miri
    fn guest_device_io_never_panics_on_hostile_port_sequences() {
        use crate::hardening_fuzz::{no_panic, Rng, SEED};
        let mut rng = Rng::new(SEED ^ 0xDE4A5);
        let mut store = MemStore::new(4);
        let mut ds = DeviceSet::new(&mut store, 0);
        let real_ports: [u16; 24] = [
            0x20, 0x21, 0xA0, 0xA1, 0x3F8, 0x3F9, 0x3FA, 0x3FB, 0x3FC, 0x3FD, 0x3FE, 0x3FF, 0x40,
            0x43, 0x61, 0x70, 0x71, 0xCF8, 0xCFC, 0x220, 0x237, 0xC000, 0xCC00, 0xCC1F,
        ];
        let command_words: [u8; 12] = [
            0x11, 0x01, 0x08, 0x0A, 0x20, 0x60, 0x68, 0x0C, 0x36, 0x54, 0x77, 0xB6,
        ];
        for _ in 0..crate::hardening_fuzz::sweep_iters(500_000) {
            let port = if rng.pick(2) == 0 {
                real_ports[rng.pick(real_ports.len())]
            } else {
                rng.next() as u16
            };
            let val = if rng.pick(4) == 0 {
                command_words[rng.pick(command_words.len())]
            } else {
                rng.byte()
            };
            // Interleave reads and writes, byte and dword widths, on the
            // live device state.
            if rng.pick(2) == 0 {
                let _ = no_panic(|| ds.inb(port));
                let _ = no_panic(|| ds.outb(port, val));
            }
            let _ = no_panic(|| ds.inb(port));
            let _ = no_panic(|| ds.outb(port, val));
            let _ = no_panic(|| ds.inw(port));
            let _ = no_panic(|| ds.outw(port, rng.next() as u16));
            let _ = no_panic(|| ds.inl(port));
            let _ = no_panic(|| ds.outl(port, rng.next() as u32));
            // A PIT command word can flip a channel into any mode/read-back
            // state; keep the UART DLAB and divisor bits moving so the whole
            // register space stays reachable.
            if rng.pick(4) == 0 {
                let _ = no_panic(|| ds.outb(0x3FB, val));
            }
        }
        // Sanity: the device set is still coherent after the hostile sweep.
        let _ = ds.inb(0x20);
        let _ = ds.inb(0x3F8);
        let _ = ds.inb(0x40);
        let _ = ds.inb(0x71);
        let _ = ds.inl(0xCFC);
    }

    #[test]
    fn pic_icw_sequence_programs_vector_bases() {
        let mut pic = Pic8259::new();
        // ICW1: cascade mode, ICW4 needed, to the master command port.
        pic.outb(0x20, 0x11);
        // ICW2: base 0x20.
        pic.outb(0x21, 0x20);
        // ICW3: slave on master IRQ 2.
        pic.outb(0x21, 0x04);
        // ICW4: 8086 mode.
        pic.outb(0x21, 0x01);
        // Same for the slave, base 0x28, slave id 2.
        pic.outb(0xA0, 0x11);
        pic.outb(0xA1, 0x28);
        pic.outb(0xA1, 0x02);
        pic.outb(0xA1, 0x01);

        assert_eq!(pic.master.base, 0x20);
        assert_eq!(pic.slave.base, 0x28);

        // Now OCW1 writes the IMR, not more ICWs.
        pic.outb(0x21, 0x00);
        assert_eq!(pic.master.imr, 0x00);
        assert_eq!(pic.master.icw_step, 0);
    }

    #[test]
    fn pic_delivers_priority_ordered_vectors() {
        let mut pic = Pic8259::new();
        pic.outb(0x20, 0x11);
        pic.outb(0x21, 0x20);
        pic.outb(0x21, 0x04);
        pic.outb(0x21, 0x01);
        pic.outb(0x21, 0x00); // unmask all

        // Raise IRQ 4 and 0; 0 must win (highest priority), and while IRQ 0
        // is in service IRQ 4 is held (no preemption below priority 0).
        pic.raise(4);
        pic.raise(0);
        assert_eq!(pic.take_pending(), Some((0x20, 0)));
        assert_eq!(
            pic.take_pending(),
            None,
            "IRQ 4 is held while IRQ 0 is in service"
        );
        pic.outb(0x20, 0x20); // non-specific EOI
        assert_eq!(pic.take_pending(), Some((0x24, 4)));
        assert_eq!(pic.take_pending(), None);
    }

    #[test]
    fn pic_masked_irq_is_not_delivered() {
        let mut pic = Pic8259::new();
        pic.outb(0x20, 0x11);
        pic.outb(0x21, 0x20);
        pic.outb(0x21, 0x04);
        pic.outb(0x21, 0x01);
        pic.outb(0x21, 0x10); // mask IRQ 4 only
        pic.raise(4);
        pic.raise(1);
        assert_eq!(pic.take_pending(), Some((0x21, 1)));
        assert_eq!(pic.take_pending(), None);
    }

    #[test]
    fn pic_slave_cascade_uses_slave_vector() {
        let mut pic = Pic8259::new();
        pic.outb(0x20, 0x11);
        pic.outb(0x21, 0x20);
        pic.outb(0x21, 0x04);
        pic.outb(0x21, 0x01);
        pic.outb(0xA0, 0x11);
        pic.outb(0xA1, 0x28);
        pic.outb(0xA1, 0x02);
        pic.outb(0xA1, 0x01);
        pic.outb(0x21, 0x00);
        pic.outb(0xA1, 0x00);

        pic.raise(9); // slave IRQ 1 -> vector 0x28 + 1
        assert_eq!(pic.take_pending(), Some((0x29, 9)));
        // The cascade holds master IRQ 2 in service; a slave EOI releases it.
        pic.outb(0xA0, 0x20); // slave non-specific EOI
        assert_eq!(pic.master.isr & (1 << 2), 0);
        assert_eq!(pic.master.irr & (1 << 2), 0);
    }

    #[test]
    fn pic_eoi_clears_in_service_and_allows_retrigger() {
        let mut pic = Pic8259::new();
        pic.outb(0x20, 0x11);
        pic.outb(0x21, 0x20);
        pic.outb(0x21, 0x04);
        pic.outb(0x21, 0x01);
        pic.outb(0x21, 0x00);

        pic.raise(0);
        assert_eq!(pic.take_pending(), Some((0x20, 0)));
        // In service: nothing new can be delivered until EOI.
        pic.raise(1);
        assert_eq!(pic.take_pending(), None);
        pic.outb(0x20, 0x20); // non-specific EOI (clears IRQ 0, highest)
        assert_eq!(pic.take_pending(), Some((0x21, 1)));
    }

    #[test]
    fn pic_ocw3_selects_isr_readback() {
        let mut pic = Pic8259::new();
        pic.outb(0x20, 0x11);
        pic.outb(0x21, 0x20);
        pic.outb(0x21, 0x04);
        pic.outb(0x21, 0x01);
        pic.outb(0x21, 0x00);
        pic.raise(3);
        pic.take_pending();
        // OCW3: read ISR.
        pic.outb(0x20, 0x0B);
        assert_eq!(pic.inb(0x20), 1 << 3);
        // OCW3: read IRR.
        pic.outb(0x20, 0x0A);
        assert_eq!(pic.inb(0x20), 0);
    }

    #[test]
    fn uart_console_round_trip() {
        let mut uart = Uart16550::new();
        // Guest (Linux 8250) init: disable IRQs, set DLAB, divisor 1, 8N1.
        uart.outb(0x3F9, 0x00);
        uart.outb(0x3FB, 0x80);
        uart.outb(0x3F8, 0x01);
        uart.outb(0x3F9, 0x00);
        uart.outb(0x3FB, 0x03);
        // Console write path: poll LSR for THRE, write THR.
        assert_eq!(uart.inb(0x3FD) & 0x20, 0x20);
        uart.outb(0x3F8, b'A');
        assert_eq!(uart.take_tx(), Some(b'A'));
        assert_eq!(uart.take_tx(), None);
        // Host feeds a byte; IRQ 4 asserts once IER enables RX.
        assert!(!uart.irq_line());
        uart.outb(0x3F9, 0x01); // enable RX interrupt
        uart.rx(b'k');
        assert!(uart.irq_line());
        assert_eq!(uart.inb(0x3FA), 0x04); // IIR: RX data available
        assert_eq!(uart.inb(0x3FD) & 0x01, 0x01); // LSR: data ready
        assert_eq!(uart.inb(0x3F8), b'k');
        assert!(!uart.irq_line());
    }

    #[test]
    fn uart_dlab_switches_register_bank() {
        let mut uart = Uart16550::new();
        uart.outb(0x3FB, 0x80);
        uart.outb(0x3F8, 0x0C); // DLL
        uart.outb(0x3F9, 0x00); // DLM
        assert_eq!(uart.inb(0x3F8), 0x0C); // DLL readback
        uart.outb(0x3FB, 0x03);
        assert_eq!(uart.inb(0x3F8), 0xFF); // RBR now (empty -> 0xFF)
    }

    #[test]
    fn pit_mode_3_fires_one_pulse_per_count() {
        let mut pit = Pit8254::new();
        // Command: ch0, LSB-then-MSB, mode 3.
        pit.outb(0x43, 0x36);
        pit.outb(0x40, 0x9C); // LSB of 0x2E9C
        pit.outb(0x40, 0x2E); // MSB
        assert_eq!(pit.ch0.count, 0x2E9C);
        assert_eq!(pit.advance(0x2E9C - 1), 0);
        assert_eq!(pit.advance(1), 1);
        // Reloaded: a full period again before the next pulse.
        assert_eq!(pit.advance(0x2E9C - 1), 0);
        assert_eq!(pit.advance(1), 1);
    }

    #[test]
    fn pit_latch_reads_current_count() {
        let mut pit = Pit8254::new();
        pit.outb(0x43, 0x36);
        pit.outb(0x40, 0x00);
        pit.outb(0x40, 0x10); // count 0x1000
        pit.advance(0x123); // 0x1000 - 0x123 = 0xEDD remaining
        pit.outb(0x43, 0x00); // latch ch0
        pit.outb(0x40, 0x00); // clear staging state
        assert_eq!(pit.inb(0x40), 0xDD); // latched LSB
        assert_eq!(pit.inb(0x40), 0x0E); // latched MSB
    }

    #[test]
    fn pit_mode_0_fires_once() {
        let mut pit = Pit8254::new();
        pit.outb(0x43, 0x30); // ch0, LSB-then-MSB, mode 0
        pit.outb(0x40, 0x05);
        pit.outb(0x40, 0x00);
        assert_eq!(pit.advance(4), 0);
        assert_eq!(pit.advance(1), 1);
        assert_eq!(pit.advance(100), 0); // one-shot: no reload
    }

    #[test]
    fn rtc_reports_plausible_calendar() {
        let mut rtc = CmosRtc::new(1_600_000_000); // 2020-09-13 12:26:40 UTC
        rtc.outb(0x70, 0x00);
        assert_eq!(rtc.inb(0x71), 0x40); // 40 seconds (BCD)
        rtc.outb(0x70, 0x02);
        assert_eq!(rtc.inb(0x71), 0x26); // 26 minutes
        rtc.outb(0x70, 0x04);
        assert_eq!(rtc.inb(0x71), 0x12); // 12 hours
        rtc.outb(0x70, 0x32);
        assert_eq!(rtc.inb(0x71), 0x20); // century
        rtc.outb(0x70, 0x0A);
        assert_eq!(rtc.inb(0x71), 0x26); // status A
    }

    #[test]
    fn rtc_advances_time() {
        let mut rtc = CmosRtc::new(0);
        rtc.advance_seconds(65);
        rtc.outb(0x70, 0x00);
        assert_eq!(rtc.inb(0x71), 0x05);
        rtc.outb(0x70, 0x02);
        assert_eq!(rtc.inb(0x71), 0x01);
    }

    #[test]
    fn pci_type1_probe_sees_host_bridge() {
        let mut pci = PciConfigBus::new();
        pci.init(0x1000);
        // Linux's config-type-1 presence probe: read bus 0 dev 0 reg 0.
        pci.write_address(0x8000_0000);
        assert_eq!(pci.read_data() & 0xFFFF, 0x8086);
    }

    #[test]
    fn pci_unknown_slots_read_all_ones() {
        let mut pci = PciConfigBus::new();
        pci.init(0x1000);
        pci.write_address(0x8000_1000); // bus 0, dev 2
        assert_eq!(pci.read_data(), 0xFFFF_FFFF);
        pci.write_address(0x8000_F800); // bus 0, dev 31
        assert_eq!(pci.read_data(), 0xFFFF_FFFF);
        pci.write_address(0x0000_0000); // enable bit clear
        assert_eq!(pci.read_data(), 0xFFFF_FFFF);
    }

    #[test]
    fn pci_bar_probe_reports_size_then_base() {
        let mut pci = PciConfigBus::new();
        pci.init(0x1000);
        // Probe BAR0 (reg 4 of slot 6): all-ones write -> size readback.
        pci.write_address(0x8000_0000 | (6 << 11) | (4 << 2));
        pci.write_data(0xFFFF_FFFF);
        assert_eq!(pci.read_data(), 0xFD); // I/O BAR, 0x100 bytes
                                           // Program the real base (0xC000).
        pci.write_data(0xC001);
        assert_eq!(pci.read_data(), 0xC001);
        assert_eq!(pci.virtio_bar(), 0xC000);
    }

    #[test]
    fn device_set_unhandled_ports_float() {
        let mut store = MemStore::new(4);
        let mut ds = DeviceSet::new(&mut store, 0);
        assert_eq!(ds.inl(0x4000), 0xFFFF_FFFF);
        ds.outb(0x61, 0xFF); // speaker control writes are ignored
        ds.outl(0x4000, 0xDEAD_BEEF);
    }

    #[test]
    fn device_set_pit2_status_port_and_peek() {
        let mut store = MemStore::new(4);
        let mut ds = DeviceSet::new(&mut store, 0);
        // Port 0x61: refresh flag (bit 5) toggles on every read; bit 7
        // (OUT2) is low while channel 2 has not expired; the other bits
        // read as the floating-bus-ish default.
        let a = ds.inb(0x61);
        let b = ds.inb(0x61);
        assert_ne!(a & 0x20, b & 0x20, "refresh flag must toggle");
        assert_eq!(a & 0x80, 0, "OUT2 low before any channel-2 count");
        // Channel 2 in mode 0, count 4, then expire it.
        ds.outb(0x43, 0xB0);
        ds.outb(0x42, 0x04);
        ds.outb(0x42, 0x00);
        assert!(!ds.pit.ch2_out2());
        ds.pit.advance(3);
        assert!(!ds.pit.ch2_out2());
        ds.pit.advance(1);
        assert!(ds.pit.ch2_out2(), "mode-0 expiry raises OUT2");
        assert_ne!(ds.inb(0x61) & 0x80, 0, "OUT2 reflected on port 0x61");
        // peek_pending must not consume: the same vector is peekable
        // repeatedly until taken. Bring the PIC up with IRQs unmasked
        // (ICW sequence + OCW1, as the guest kernel does).
        ds.outb(0x20, 0x11);
        ds.outb(0x21, 0x20);
        ds.outb(0x21, 0x04);
        ds.outb(0x21, 0x01);
        ds.outb(0x21, 0x00);
        ds.host_rx(b'x');
        ds.outb(0x3F9, 0x01); // enable UART RX interrupt
        ds.update_pic(0);
        assert_eq!(ds.pic_peek_vector(), Some(0x24));
        assert_eq!(ds.pic_peek_vector(), Some(0x24), "peek must not consume");
        assert_eq!(ds.pic_pending_vector(), Some(0x24));
        assert_eq!(ds.pic_peek_vector(), None, "taken vector is gone");
    }

    #[test]
    fn device_set_routes_pic_uart_pit_rtc() {
        let mut store = MemStore::new(4);
        let mut ds = DeviceSet::new(&mut store, 0);
        ds.outb(0x20, 0x11);
        ds.outb(0x21, 0x20);
        ds.outb(0x21, 0x04);
        ds.outb(0x21, 0x01);
        ds.outb(0x21, 0x00);
        ds.outb(0x3F9, 0x01); // enable the UART RX interrupt (IER)
        ds.host_rx(b'x');
        ds.update_pic(0);
        assert_eq!(ds.pic_pending_vector(), Some(0x24)); // IRQ 4 -> base+4
        ds.pic.outb(0x20, 0x20); // EOI
                                 // PIT pulses raise IRQ 0.
        ds.outb(0x43, 0x36);
        ds.outb(0x40, 0x01);
        ds.outb(0x40, 0x00);
        ds.update_pic(1);
        assert_eq!(ds.pic_pending_vector(), Some(0x20));
    }

    #[test]
    fn fmt_traits_do_not_panic() {
        let _ = format!("{:?}", PitChannel::new());
        let _ = format!("{:?}", PicState::new());
    }

    // -----------------------------------------------------------------
    // Phase Z helpers: build UHCI TDs / frame lists in a ByteArena.
    // -----------------------------------------------------------------

    fn put_td(mem: &mut impl UsbMem, addr: u32, link: u32, ctrl: u32, token: u32, buffer: u32) {
        let _ = mem.write_u32(addr, link);
        let _ = mem.write_u32(addr + 4, ctrl);
        let _ = mem.write_u32(addr + 8, token);
        let _ = mem.write_u32(addr + 12, buffer);
    }

    fn u32_from_bytes(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    // -----------------------------------------------------------------
    // Phase Z: UHCI registers
    // -----------------------------------------------------------------

    #[test]
    fn uhci_register_map_defaults() {
        let uhci = UhciUsb::new();
        assert_eq!(uhci.inw(UHCI_BASE), 0); // USBCMD
        assert_eq!(uhci.inw(UHCI_BASE + 0x02), 0x0020); // USBSTS: HC Halted
        assert_eq!(uhci.inw(UHCI_BASE + 0x04), 0); // USBINTR
        assert_eq!(uhci.inw(UHCI_BASE + 0x06), 0); // FRNUM
        assert_eq!(uhci.inw(UHCI_BASE + 0x08), 0); // FRBASE (lo)
        assert_eq!(uhci.inw(UHCI_BASE + 0x0A), 0); // FRBASE (hi)
        assert_eq!(uhci.inw(UHCI_BASE + 0x0C), 0x40); // SOFMOD
        assert_eq!(uhci.inw(UHCI_BASE + 0x10), 0x0011); // PORTSC1: CCS + LSDA
        assert_eq!(uhci.inw(UHCI_BASE + 0x12), 0x0000); // PORTSC2: empty
        assert_eq!(uhci.inw(UHCI_BASE + 0x20), 0xFFFF); // out of range floats
    }

    #[test]
    fn uhci_global_reset_restores_defaults() {
        let mut uhci = UhciUsb::new();
        uhci.outw(UHCI_BASE, 1); // RUN
        uhci.outw(UHCI_BASE + 0x08, 0x1000);
        uhci.outw(UHCI_BASE + 0x04, 0x000F);
        uhci.outw(UHCI_BASE, 0x0002); // GRESET
        assert_eq!(uhci.inw(UHCI_BASE), 0);
        assert_eq!(uhci.inw(UHCI_BASE + 0x02), 0x0020);
        assert_eq!(uhci.inw(UHCI_BASE + 0x04), 0);
        assert_eq!(uhci.inw(UHCI_BASE + 0x08), 0);
        assert_eq!(uhci.tds_processed, 0);
    }

    #[test]
    fn uhci_portsc_reset_completes_on_pr_clear() {
        let mut uhci = UhciUsb::new();
        // Arm a port-1 reset.
        uhci.outw(UHCI_BASE + 0x10, 0x2000);
        assert_eq!(uhci.inw(UHCI_BASE + 0x10) & 0x2000, 0x2000, "PR set");
        assert_eq!(uhci.inw(UHCI_BASE + 0x10) & 0x0004, 0, "PE cleared");
        // Clear PR: the keyboard comes back connected + low-speed + enabled.
        uhci.outw(UHCI_BASE + 0x10, 0x0000);
        let ps = uhci.inw(UHCI_BASE + 0x10);
        assert_eq!(ps & 0x2000, 0, "PR cleared");
        assert_eq!(ps & 0x0011, 0x0011, "CCS + LSDA");
        assert_eq!(ps & 0x0004, 0x0004, "PE re-enabled");
    }

    #[test]
    fn uhci_frnum_wraps_at_2048() {
        let mut uhci = UhciUsb::new();
        uhci.outw(UHCI_BASE + 0x06, 0x07FF);
        assert_eq!(uhci.inw(UHCI_BASE + 0x06), 0x07FF);
        uhci.outw(UHCI_BASE + 0x06, 0x0800); // above the 11-bit range
        assert_eq!(uhci.inw(UHCI_BASE + 0x06), 0x0000);
    }

    #[test]
    fn uhci_irq_line_requires_intr_enable() {
        let mut uhci = UhciUsb::new();
        // USBINT pending but the IOC interrupt disabled: no line.
        uhci.sts |= 0x0001;
        assert!(!uhci.irq_line());
        // Enable the IOC interrupt: the line asserts.
        uhci.intr |= 0x0001;
        assert!(uhci.irq_line());
    }

    // -----------------------------------------------------------------
    // Phase Z: UHCI key ring
    // -----------------------------------------------------------------

    #[test]
    fn uhci_key_ring_round_trip() {
        let mut uhci = UhciUsb::new();
        assert_eq!(uhci.key_count, 0);
        uhci.enqueue_key([0x02, 0, 0x04, 0, 0, 0, 0, 0]);
        uhci.enqueue_key([0x00, 0, 0x05, 0, 0, 0, 0, 0]);
        assert_eq!(uhci.key_count, 2);
        assert_eq!(uhci.pop_key(), Some([0x02, 0, 0x04, 0, 0, 0, 0, 0]));
        assert_eq!(uhci.pop_key(), Some([0x00, 0, 0x05, 0, 0, 0, 0, 0]));
        assert_eq!(uhci.pop_key(), None);
    }

    #[test]
    fn uhci_key_ring_is_bounded() {
        let mut uhci = UhciUsb::new();
        for i in 0..UHCI_KEY_RING + 8 {
            uhci.enqueue_key([0, 0, i as u8, 0, 0, 0, 0, 0]);
        }
        assert_eq!(uhci.key_count, UHCI_KEY_RING);
    }

    // -----------------------------------------------------------------
    // Phase Z: UHCI TD engine
    // -----------------------------------------------------------------

    #[test]
    fn uhci_no_run_or_no_frame_list_returns_zero() {
        let mut arena = vec![0u8; 0x4000];
        let mut mem = ByteArena {
            buf: arena.as_mut_slice(),
        };
        let mut uhci = UhciUsb::new();
        // Not running.
        assert_eq!(uhci.process_frame_list(&mut mem), 0);
        // Running but no frame list.
        uhci.outw(UHCI_BASE, 1);
        assert_eq!(uhci.process_frame_list(&mut mem), 0);
        assert_eq!(uhci.tds_processed, 0);
    }

    #[test]
    fn uhci_terminated_frame_entry_returns_zero() {
        let mut arena = vec![0u8; 0x4000];
        let mut mem = ByteArena {
            buf: arena.as_mut_slice(),
        };
        let mut uhci = UhciUsb::new();
        uhci.outw(UHCI_BASE, 1);
        uhci.outw(UHCI_BASE + 0x08, 0x1000);
        let _ = mem.write_u32(0x1000, 0x0000_0001); // terminate bit set
        assert_eq!(uhci.process_frame_list(&mut mem), 0);
    }

    #[test]
    fn uhci_inactive_td_is_skipped() {
        let mut arena = vec![0u8; 0x4000];
        let mut mem = ByteArena {
            buf: arena.as_mut_slice(),
        };
        let mut uhci = UhciUsb::new();
        uhci.outw(UHCI_BASE, 1);
        uhci.outw(UHCI_BASE + 0x08, 0x1000);
        let _ = mem.write_u32(0x1000, 0x2000);
        // TD1 inactive (active bit clear), links to TD2.
        put_td(&mut mem, 0x2000, 0x2010, 0x00, 0x69, 0x0);
        // TD2 active: IN endpoint 0 with nothing pending -> zero length.
        put_td(&mut mem, 0x2010, 0x1, 0x09, 0x69, 0x0);
        assert_eq!(uhci.process_frame_list(&mut mem), 1);
        assert_eq!(uhci.tds_processed, 1);
        // TD1's active bit is untouched; TD2's is cleared.
        assert_eq!(u32_from_bytes(mem.buf, 0x2004) & 0x1, 0x0);
        assert_eq!(u32_from_bytes(mem.buf, 0x2014) & 0x1, 0x0);
    }

    #[test]
    fn uhci_enumeration_full_flow() {
        let mut arena = vec![0u8; 0x4000];
        let mut uhci = UhciUsb::new();
        uhci.outw(UHCI_BASE, 1); // RUN
        uhci.outw(UHCI_BASE + 0x08, 0x1000); // FRBASE
        uhci.outw(UHCI_BASE + 0x04, 0x0001); // IOC interrupt enable
        uhci.enqueue_key([0x00, 0x00, 0x04, 0, 0, 0, 0, 0]); // scancode 4 = 'a'
        {
            let mut mem = ByteArena {
                buf: arena.as_mut_slice(),
            };
            let _ = mem.write_u32(0x1000, 0x2000);
            // SETUP: Set Address 1.
            let _ = mem.write(0x3000, &[0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
            put_td(&mut mem, 0x2000, 0x2010, 0x09, 0x2D | (8 << 21), 0x3000);
            // IN status stage (acknowledge the address).
            put_td(&mut mem, 0x2010, 0x2020, 0x09, 0x69 | (1 << 8), 0x0);
            // SETUP: GET_DESCRIPTOR device (type 1, length 18).
            let _ = mem.write(0x3010, &[0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00]);
            put_td(
                &mut mem,
                0x2020,
                0x2030,
                0x09,
                0x2D | (1 << 8) | (8 << 21),
                0x3010,
            );
            // IN: device descriptor data stage.
            put_td(
                &mut mem,
                0x2030,
                0x2040,
                0x09,
                0x69 | (1 << 8) | (18 << 21),
                0x3020,
            );
            // SETUP: SET_CONFIGURATION 1.
            let _ = mem.write(0x3050, &[0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
            put_td(
                &mut mem,
                0x2040,
                0x2050,
                0x09,
                0x2D | (1 << 8) | (8 << 21),
                0x3050,
            );
            // IN status stage.
            put_td(&mut mem, 0x2050, 0x2060, 0x09, 0x69 | (1 << 8), 0x0);
            // Interrupt IN: report (IOC set).
            put_td(
                &mut mem,
                0x2060,
                0x1,
                0x0B,
                0x69 | (1 << 8) | (1 << 16) | (8 << 21),
                0x3040,
            );
            assert_eq!(uhci.process_frame_list(&mut mem), 7);
            assert_eq!(uhci.tds_processed, 7);
            // The device descriptor landed at 0x3020.
            let mut desc = [0u8; 18];
            mem.read(0x3020, &mut desc);
            assert_eq!(&desc[..2], &[0x12, 0x01]);
            assert_eq!(u16::from_le_bytes([desc[8], desc[9]]), 0x1234);
            // The key report landed at 0x3040.
            let mut report = [0u8; 8];
            mem.read(0x3040, &mut report);
            assert_eq!(report, [0x00, 0x00, 0x04, 0, 0, 0, 0, 0]);
            // TD2's completion: Active cleared, status 0.
            assert_eq!(u32_from_bytes(mem.buf, 0x2014) & 0x1, 0x0);
            assert_eq!((u32_from_bytes(mem.buf, 0x2014) >> 16) & 0xFF, 0x00);
        }
        // Model state after the walk.
        assert_eq!(uhci.device_address, 1);
        assert!(uhci.configured);
        assert!(uhci.irq_line(), "IOC TD completed -> USBINT + intr enabled");
        assert_eq!(uhci.inw(UHCI_BASE + 0x06), 1, "frame advanced");
    }

    #[test]
    fn uhci_interrupt_in_naks_when_idle() {
        let mut arena = vec![0u8; 0x4000];
        let mut mem = ByteArena {
            buf: arena.as_mut_slice(),
        };
        let mut uhci = UhciUsb::new();
        uhci.outw(UHCI_BASE, 1);
        uhci.outw(UHCI_BASE + 0x08, 0x1000);
        // Configure the device first (no keys queued).
        uhci.configured = true;
        let _ = mem.write_u32(0x1000, 0x2000);
        put_td(
            &mut mem,
            0x2000,
            0x1,
            0x09,
            0x69 | (1 << 8) | (1 << 16) | (8 << 21),
            0x3040,
        );
        assert_eq!(uhci.process_frame_list(&mut mem), 1);
        // NAK status (0x05) in bits 23:16, and the NAK bit (0x40) set.
        let ctrl = u32_from_bytes(mem.buf, 0x2004);
        assert_eq!((ctrl >> 16) & 0xFF, 0x05);
        assert_ne!(ctrl & 0x40, 0);
        assert_eq!(uhci.tds_processed, 1);
    }

    #[test]
    fn uhci_unknown_request_stalls() {
        let mut arena = vec![0u8; 0x4000];
        let mut mem = ByteArena {
            buf: arena.as_mut_slice(),
        };
        let mut uhci = UhciUsb::new();
        uhci.outw(UHCI_BASE, 1);
        uhci.outw(UHCI_BASE + 0x08, 0x1000);
        let _ = mem.write_u32(0x1000, 0x2000);
        // SETUP: GET_DESCRIPTOR for an unknown descriptor type (0x77).
        let _ = mem.write(0x3000, &[0x80, 0x06, 0x00, 0x77, 0x00, 0x00, 0x12, 0x00]);
        put_td(&mut mem, 0x2000, 0x2010, 0x09, 0x2D | (8 << 21), 0x3000);
        // The IN data stage has no descriptor to serve: STALL.
        put_td(&mut mem, 0x2010, 0x1, 0x09, 0x69 | (18 << 21), 0x3020);
        assert_eq!(uhci.process_frame_list(&mut mem), 2);
        assert!(uhci.unknown_requests > 0);
        let ctrl = u32_from_bytes(mem.buf, 0x2014);
        assert_eq!((ctrl >> 16) & 0xFF, 0x04, "STALL status");
    }

    #[test]
    fn uhci_td_walk_is_bounded() {
        let mut arena = vec![0u8; 0x4000];
        let mut mem = ByteArena {
            buf: arena.as_mut_slice(),
        };
        let mut uhci = UhciUsb::new();
        uhci.outw(UHCI_BASE, 1);
        uhci.outw(UHCI_BASE + 0x08, 0x1000);
        let _ = mem.write_u32(0x1000, 0x2000);
        // A chain of 70 active TDs: the walk must stop at 64.
        let mut addr = 0x2000u32;
        for i in 0..70u32 {
            let link = if i == 69 { 0x1 } else { (addr + 0x10) & !1u32 };
            put_td(&mut mem, addr, link, 0x09, 0x69, 0x0);
            addr += 0x10;
        }
        assert_eq!(uhci.process_frame_list(&mut mem), 64);
        assert_eq!(uhci.tds_processed, 64);
    }

    // -----------------------------------------------------------------
    // Phase Z: SB16 DSP
    // -----------------------------------------------------------------

    #[test]
    fn sb16_reset_handshake() {
        let mut dsp = Sb16Dsp::new();
        assert!(!dsp.reset_done());
        dsp.outb(SB16_BASE + 0x06, 0x01); // reset pulse high
        assert_eq!(dsp.inb(SB16_BASE + 0x06), 0);
        dsp.outb(SB16_BASE + 0x06, 0x00); // reset pulse low
        assert!(dsp.reset_done());
        // 0xAA appears on the read-data path; status shows data ready.
        assert_eq!(dsp.inb(SB16_BASE + 0x0E), 0x80);
        assert_eq!(dsp.inb(SB16_BASE + 0x0A), 0xAA);
        assert_eq!(dsp.inb(SB16_BASE + 0x0E), 0x00);
    }

    #[test]
    fn sb16_version_query() {
        let mut dsp = Sb16Dsp::new();
        dsp.outb(SB16_BASE + 0x0C, 0xE1);
        assert_eq!(dsp.inb(SB16_BASE + 0x0A), 0x04);
        assert_eq!(dsp.inb(SB16_BASE + 0x0A), 0x05);
        assert_eq!(dsp.version(), (0x04, 0x05));
    }

    #[test]
    fn sb16_speaker_toggle() {
        let mut dsp = Sb16Dsp::new();
        assert!(dsp.speaker_on());
        dsp.outb(SB16_BASE + 0x0C, 0xD3); // speaker off
        assert!(!dsp.speaker_on());
        dsp.outb(SB16_BASE + 0x0C, 0xD1); // speaker on
        assert!(dsp.speaker_on());
    }

    #[test]
    fn sb16_sample_rate_two_byte() {
        let mut dsp = Sb16Dsp::new();
        dsp.outb(SB16_BASE + 0x0C, 0x41);
        dsp.outb(SB16_BASE + 0x0C, 0x22); // lo byte
        dsp.outb(SB16_BASE + 0x0C, 0x56); // hi byte
        assert_eq!(dsp.sample_rate(), 0x5622);
    }

    #[test]
    fn sb16_time_constant() {
        let mut dsp = Sb16Dsp::new();
        dsp.outb(SB16_BASE + 0x0C, 0x40);
        dsp.outb(SB16_BASE + 0x0C, 0xE6); // 230 -> ~11 kHz
        assert_eq!(dsp.time_constant(), 0xE6);
    }

    #[test]
    fn sb16_single_cycle_playback() {
        let mut dsp = Sb16Dsp::new();
        dsp.outb(SB16_BASE + 0x0C, 0x10); // single-cycle, 1-byte length
        dsp.outb(SB16_BASE + 0x0C, 0xFF); // length 0xFF
        assert_eq!(dsp.pending_playbacks(), 1);
        let req = dsp.pop_playback().unwrap();
        assert_eq!(req.length, 0xFF);
        assert!(!req.auto_init);
    }

    #[test]
    fn sb16_two_byte_playback_length() {
        let mut dsp = Sb16Dsp::new();
        dsp.outb(SB16_BASE + 0x0C, 0x14); // two-byte length
        dsp.outb(SB16_BASE + 0x0C, 0x00); // lo
        dsp.outb(SB16_BASE + 0x0C, 0x10); // hi -> 0x1000
        assert_eq!(dsp.pending_playbacks(), 1);
        assert_eq!(dsp.pop_playback().unwrap().length, 0x1000);
    }

    #[test]
    fn sb16_auto_init_playback() {
        let mut dsp = Sb16Dsp::new();
        dsp.outb(SB16_BASE + 0x0C, 0x41);
        dsp.outb(SB16_BASE + 0x0C, 0x22);
        dsp.outb(SB16_BASE + 0x0C, 0x56); // 22050 Hz
        dsp.outb(SB16_BASE + 0x0C, 0x91); // auto-init DAC
        dsp.outb(SB16_BASE + 0x0C, 0x00);
        dsp.outb(SB16_BASE + 0x0C, 0x04); // length 0x0400
        let req = dsp.pop_playback().unwrap();
        assert_eq!(req.length, 0x0400);
        assert_eq!(req.sample_rate, 0x5622);
        assert!(req.auto_init);
        assert_eq!(dsp.pending_playbacks(), 0);
    }

    #[test]
    fn sb16_playback_fifo_is_bounded() {
        let mut dsp = Sb16Dsp::new();
        for _ in 0..SB16_MAX_PLAYBACKS + 4 {
            dsp.outb(SB16_BASE + 0x0C, 0x10);
            dsp.outb(SB16_BASE + 0x0C, 0x10);
        }
        assert_eq!(dsp.pending_playbacks(), SB16_MAX_PLAYBACKS);
    }

    #[test]
    fn sb16_unknown_and_input_commands_counted() {
        let mut dsp = Sb16Dsp::new();
        dsp.outb(SB16_BASE + 0x0C, 0xF7); // unknown
        dsp.outb(SB16_BASE + 0x0C, 0xE5); // unknown
        dsp.outb(SB16_BASE + 0x0C, 0xC0); // input DMA 8-bit
        assert_eq!(dsp.unknown_cmds, 2);
        assert_eq!(dsp.input_requests, 1);
    }

    // -----------------------------------------------------------------
    // Phase Z: DeviceSet wiring
    // -----------------------------------------------------------------

    #[test]
    fn pci_uhci_slot_is_fabricated() {
        let mut pci = PciConfigBus::new();
        pci.init(0x1000);
        pci.write_address(0x8000_0000 | ((UHCI_SLOT as u32) << 11));
        assert_eq!(pci.read_data() & 0xFFFF, 0x8086);
        pci.write_address(0x8000_0000 | ((UHCI_SLOT as u32) << 11) | (2 << 2));
        assert_eq!(pci.read_data() >> 16, 0x0C03);
        assert_eq!(pci.uhci_bar(), UHCI_BASE);
    }

    #[test]
    fn device_set_routes_usb_and_audio_ports() {
        let mut store = MemStore::new(4);
        let mut ds = DeviceSet::new(&mut store, 0);
        // UHCI register access through the 16-bit path.
        assert_eq!(ds.inw(UHCI_BASE + 0x02), 0x0020);
        ds.outw(UHCI_BASE, 1);
        assert_eq!(ds.inw(UHCI_BASE), 1);
        // SB16 register access through the 8-bit path.
        assert_eq!(ds.inb(SB16_BASE + 0x06), 0);
        ds.outb(SB16_BASE + 0x06, 0x01);
        ds.outb(SB16_BASE + 0x06, 0x00);
        assert_eq!(ds.inb(SB16_BASE + 0x0E), 0x80);
        assert_eq!(ds.inb(SB16_BASE + 0x0A), 0xAA);
        // Non-device ports still float.
        assert_eq!(ds.inw(0xCC80), 0xFFFF);
        assert_eq!(ds.inb(0x200), 0xFF);
    }

    #[test]
    fn device_set_update_pic_raises_uhci_irq() {
        let mut store = MemStore::new(4);
        let mut ds = DeviceSet::new(&mut store, 0);
        ds.outb(0x20, 0x11);
        ds.outb(0x21, 0x20);
        ds.outb(0x21, 0x04);
        ds.outb(0x21, 0x01);
        ds.outb(0x21, 0x00); // unmask all (master)
        ds.outb(0xA0, 0x11);
        ds.outb(0xA1, 0x28);
        ds.outb(0xA1, 0x02);
        ds.outb(0xA1, 0x01);
        ds.outb(0xA1, 0x00); // unmask all (slave — UHCI IRQ 10 lives here)
                             // Complete one IOC interrupt-IN TD so USBINT asserts.
        ds.usb.outw(UHCI_BASE, 1);
        ds.usb.outw(UHCI_BASE + 0x08, 0x1000);
        ds.usb.outw(UHCI_BASE + 0x04, 0x0001);
        ds.usb.configured = true;
        ds.usb.enqueue_key([0x00, 0x00, 0x04, 0, 0, 0, 0, 0]);
        let mut arena = vec![0u8; 0x4000];
        {
            let mut mem = ByteArena {
                buf: arena.as_mut_slice(),
            };
            let _ = mem.write_u32(0x1000, 0x2000);
            put_td(
                &mut mem,
                0x2000,
                0x1,
                0x0B, // Active + IOC
                0x69 | (1 << 8) | (1 << 16) | (8 << 21),
                0x3040,
            );
        }
        assert_eq!(
            ds.usb_process(&mut ByteArena {
                buf: arena.as_mut_slice(),
            }),
            1
        );
        assert!(ds.usb.irq_line());
        assert_eq!(ds.pic_peek_vector(), Some(0x20 + UHCI_IRQ));
        assert_eq!(ds.pic_pending_vector(), Some(0x20 + UHCI_IRQ));
    }
}

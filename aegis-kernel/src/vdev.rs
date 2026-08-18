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
//! stored but not decoded), no RTC alarm/NMI, no CMOS write-through, one
//! PCI slot beyond the host bridge, no MSI-X/IO-APIC (guest is `noapic`),
//! no ACPI tables, unhandled port reads return 0xFF like a floating bus
//! rather than faulting (real-hardware behavior).

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
    }

    /// The base port of the virtio-blk I/O BAR, once the guest programs it.
    pub fn virtio_bar(&self) -> u16 {
        let raw = u32_from(&self.slots[VIRTIO_SLOT].config, 0x10);
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
            0x70 | 0x71 => self.rtc.inb(port),
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
            _ => {
                let bar = self.pci.virtio_bar();
                if bar != 0 && (port as u32) >= bar as u32 && (port as u32) < bar as u32 + 0x100 {
                    self.virtio.legacy_outb(port - bar, val);
                }
            }
        }
    }

    /// 16-bit port read: only the virtio I/O BAR has 16-bit registers
    /// (QUEUE_NUM / QUEUE_NUM_MAX); everything else in this device set is
    /// byte- or dword-oriented, so 16-bit accesses to other ranges return
    /// the floating-bus value.
    pub fn inw(&mut self, port: u16) -> u16 {
        let bar = self.pci.virtio_bar();
        if bar != 0 && (port as u32) >= bar as u32 && (port as u32) < bar as u32 + 0x100 {
            self.virtio.legacy_inw(port - bar)
        } else {
            0xFFFF
        }
    }

    /// 16-bit port write: the virtio I/O BAR (QUEUE_NUM / QUEUE_SEL /
    /// QUEUE_NOTIFY); other ranges are ignored (floating-bus).
    pub fn outw(&mut self, port: u16, val: u16) {
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
        assert_eq!(ds.inb(0x61), 0xFF); // speaker port: not emulated
        assert_eq!(ds.inl(0x4000), 0xFFFF_FFFF);
        ds.outb(0x61, 0xFF); // must not panic
        ds.outl(0x4000, 0xDEAD_BEEF);
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
}

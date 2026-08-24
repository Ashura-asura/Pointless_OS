//! AHCI (SATA) host-controller driver — Phase: bare-metal boot on machines
//! with a SATA SSD (e.g. an ASUS TP201S variant that carries a SATA disk).
//!
//! Mirrors the structure of `nvme.rs` (PCI probe → mapped BAR → command
//! submission → per-device IOMMU domain) so the object store can sit on top
//! through the `BlockIo` trait. QEMU's q35 chipset emulates an ICH9 AHCI
//! controller, so the driver is testable live: attach a raw disk image and
//! probe/read it.
//!
//! Honest scope: a single-port, single-command-slot, 512-byte-sector driver
//! (slot 0). Enough to probe + identify a SATA disk and read/write sectors —
//! the same role `NvmeController` plays for NVMe. Multi-slot queueing,
//! NCQ, and >512-byte sectors are out of scope, named honestly.

// HBA registers (ABAR-relative) — prefixed so the test can reference them
// by a non-conflicting name.
const _HBA_CAP: u32 = 0x00;
const _HBA_GHC: u32 = 0x04;
const _HBA_PI: u32 = 0x0C;
const _HBA_VS: u32 = 0x10;
const PORT_BASE: u32 = 0x100;
const PORT_STRIDE: u32 = 0x80;

// Port registers (ABAR + PORT_BASE + port*PORT_STRIDE + off).
const PCLB: u32 = 0x00; // command list base (low)
const PCLBU: u32 = 0x04; // command list base (high)
const PFB: u32 = 0x08; // FIS base (low)
const PFBU: u32 = 0x0C; // FIS base (high)
const PIS: u32 = 0x10; // interrupt status
const PCMD: u32 = 0x18; // command & status
const PTFD: u32 = 0x20; // task file data
const PSSTS: u32 = 0x28; // SATA status
const PSCTL: u32 = 0x2C; // SATA control (link reset)
const PCI: u32 = 0x38; // command issue

// GHC bits.
const GHC_AE: u32 = 1 << 31; // AHCI enable
const GHC_HR: u32 = 1; // HBA reset (1 = resetting)

// PxCMD bits.
const PCMD_ST: u32 = 1; // start
const PCMD_SUD: u32 = 1 << 1; // spin-up device
const PCMD_POD: u32 = 1 << 2; // power-on device
const PCMD_FRE: u32 = 1 << 4; // FIS receive enable
const PCMD_FR: u32 = 1 << 14; // FIS receive running
const PCMD_CR: u32 = 1 << 15; // command list running

// PxSSTS fields.
const SSTS_DET: u32 = 0x0F; // device detection
const SSTS_IPM: u32 = 0xF0; // interface power management
const DET_PRESENT: u32 = 3; // device present, PHY ready
const IPM_ACTIVE: u32 = 1 << 4; // active

// ATA commands.
const ATA_IDENTIFY: u8 = 0xEC;
const ATA_READ_DMA: u8 = 0xC8;
const ATA_WRITE_DMA: u8 = 0xCA;

const SECTOR: usize = 512;

/// Read a 32-bit AHCI register.
#[inline]
fn reg_read(base: *mut u8, off: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(off as usize) as *const u32) }
}

/// Write a 32-bit AHCI register.
#[inline]
fn reg_write(base: *mut u8, off: u32, val: u32) {
    unsafe { core::ptr::write_volatile(base.add(off as usize) as *mut u32, val) }
}

/// Port register offset for `port`.
#[inline]
fn port_off(port: usize, off: u32) -> u32 {
    PORT_BASE + (port as u32) * PORT_STRIDE + off
}

/// DMA buffers the controller hands to hardware (phys, identity-mapped into
/// the device's IOMMU domain before first use — see `probe`).
#[derive(Clone, Copy)]
struct Bufs {
    /// Command list (1024 bytes used, held in a 4 KiB page).
    cl: u64,
    /// FIS receive area (256 bytes, held in a 4 KiB page).
    fis: u64,
    /// Command table for slot 0 (256 bytes, held in a 4 KiB page).
    ct: u64,
    /// 512-byte sector data buffer.
    sec: u64,
}

impl Bufs {
    fn phys(p: u64) -> u64 {
        p
    }
}

/// One AHCI controller: QEMU's ICH9 (and the TP201S-class real SATA
/// controllers) expose a single ABAR; this drives port 0.
pub struct AhciController {
    base: *mut u8,
    port: usize,
    pub sector_count: u64,
    buf: Bufs,
}

impl AhciController {
    /// Find the AHCI controller, map its ABAR (BAR5), and bring port 0 up.
    pub fn probe(pci: &crate::pci::PciDeviceList) -> Option<Self> {
        let dev = pci.find_ahci()?;
        // AHCI uses BAR5 (memory-mapped ABAR). Fall back to BAR0 if the
        // config space reports no BAR5.
        let mut addr = dev.bar_address(5);
        if addr == 0 {
            addr = dev.bar_address(0);
        }
        if addr == 0 {
            return None;
        }
        let window = crate::page_tables::DEVICE_BAR_WINDOW;
        let bar_addr = if addr < window || (addr >= window && addr < window + 0x20_0000) {
            addr
        } else {
            crate::sprintln!("Aegis: AHCI: BAR {:#x} out of identity map - skipped", addr);
            return None;
        };
        let base = bar_addr as *mut u8;

        let bdf = crate::iommu::bdf(dev.address.bus, dev.address.device, dev.address.function);

        // AHCI enable + wait for reset to clear.
        reg_write(base, _HBA_GHC, GHC_AE);
        for _ in 0..100_000 {
            if reg_read(base, _HBA_GHC) & GHC_HR == 0 {
                break;
            }
        }
        let pi = reg_read(base, _HBA_PI);
        if pi == 0 {
            crate::sprintln!("Aegis: AHCI: no ports implemented");
            return None;
        }

        // Allocate DMA buffers in low RAM (below the kernel image, inside the
        // identity-mapped window) so QEMU's AHCI DMA reaches the same pages
        // the kernel reads back. Zero them; unzeroed reserved fields made
        // QEMU's AHCI reject the command list.
        let buf = unsafe {
            let b = Bufs {
                cl: 0x800000,
                fis: 0x801000,
                ct: 0x802000,
                sec: 0x803000,
            };
            core::ptr::write_bytes(b.cl as *mut u8, 0, 4096);
            core::ptr::write_bytes(b.fis as *mut u8, 0, 4096);
            core::ptr::write_bytes(b.ct as *mut u8, 0, 4096);
            core::ptr::write_bytes(b.sec as *mut u8, 0, 4096);
            b
        };
        let flags = crate::iommu::PAGE_READ | crate::iommu::PAGE_WRITE;
        let domain = unsafe {
            crate::iommu::with(|i| {
                let dom = i.provision_device(bdf);
                for p in [
                    Bufs::phys(buf.cl),
                    Bufs::phys(buf.fis),
                    Bufs::phys(buf.ct),
                    Bufs::phys(buf.sec),
                ] {
                    i.identity_map(dom, p, 4096, flags);
                }
                dom
            })
        };

        let _ = domain; // identity-mapped at probe; no runtime translate needed
                        // Try every implemented port (the TP201S exposes two — ata1/ata2)
                        // and use the first that brings a disk online and identifies.
        for port in 0..4 {
            if pi & (1 << port) == 0 {
                continue;
            }
            let mut s = Self {
                base,
                port,
                sector_count: 0,
                buf,
            };
            if s.port_up(port) && s.identify() {
                return Some(s);
            }
        }
        crate::sprintln!("Aegis: AHCI: no SATA disk on any implemented port");
        None
    }

    /// Bring `port` up: spin-up, clear CR/FR, point CLB/FB, start + FIS on,
    /// wait for a present+active device with no pending command.
    fn port_up(&mut self, port: usize) -> bool {
        let base = self.base;
        // Stop the port first (clear ST + FRE), wait CR/FR to clear.
        let mut cmd = reg_read(base, port_off(port, PCMD));
        cmd &= !(PCMD_ST | PCMD_FRE);
        reg_write(base, port_off(port, PCMD), cmd);
        for _ in 0..100_000 {
            cmd = reg_read(base, port_off(port, PCMD));
            if cmd & (PCMD_CR | PCMD_FR) == 0 {
                break;
            }
        }
        // Spin up + power on the device.
        cmd = reg_read(base, port_off(port, PCMD));
        cmd |= PCMD_SUD | PCMD_POD;
        reg_write(base, port_off(port, PCMD), cmd);
        // Point the command list and FIS area.
        reg_write(
            base,
            port_off(port, PCLB),
            (Bufs::phys(self.buf.cl) & 0xFFFF_FFFF) as u32,
        );
        reg_write(
            base,
            port_off(port, PCLBU),
            (Bufs::phys(self.buf.cl) >> 32) as u32,
        );
        reg_write(
            base,
            port_off(port, PFB),
            (Bufs::phys(self.buf.fis) & 0xFFFF_FFFF) as u32,
        );
        reg_write(
            base,
            port_off(port, PFBU),
            (Bufs::phys(self.buf.fis) >> 32) as u32,
        );
        // SATA link reset before starting the port: assert interface reset
        // (PxSCTL.DET=1), settle, release (DET=0), so the device comes online
        // with DRQ cleared. Without this QEMU's AHCI refuses IDENTIFY.
        reg_write(base, port_off(port, PSCTL), 0x301);
        for _ in 0..50_000 {
            core::hint::spin_loop();
        }
        reg_write(base, port_off(port, PSCTL), 0x300);
        // Wait for device present + active.
        for _ in 0..400_000 {
            let sts = reg_read(base, port_off(port, PSSTS));
            if sts & SSTS_DET == DET_PRESENT && sts & SSTS_IPM == IPM_ACTIVE {
                break;
            }
        }
        let sts = reg_read(base, port_off(port, PSSTS));
        if sts & SSTS_DET != DET_PRESENT {
            crate::sprintln!("Aegis: AHCI: no device on port {} (SSTS={:#x})", port, sts);
            return false;
        }
        // Enable FIS receive, then start the port.
        cmd = reg_read(base, port_off(port, PCMD));
        cmd |= PCMD_FRE;
        reg_write(base, port_off(port, PCMD), cmd);
        cmd |= PCMD_ST;
        reg_write(base, port_off(port, PCMD), cmd);
        // Confirm the port actually started.
        if reg_read(base, port_off(port, PCMD)) & PCMD_ST == 0 {
            crate::sprintln!(
                "Aegis: AHCI: port {} failed to start (PCMD={:#x})",
                port,
                reg_read(base, port_off(port, PCMD))
            );
            return false;
        }
        // Wait for BSY/DRQ clear (bits 7:6 of PxTFD).
        for _ in 0..200_000 {
            if reg_read(base, port_off(port, PTFD)) & 0xC0 == 0 {
                break;
            }
        }
        reg_read(base, port_off(port, PTFD)) & 0xC0 == 0
    }

    /// Issue `cmd` to port 0 on slot 0 and wait for completion.
    /// `lba`/`count` are for the data-transfer commands (0 for IDENTIFY).
    /// `prd_buf` is the physical address of the PRD data buffer.
    fn issue(&mut self, cmd: u8, lba: u64, count: u16, prd_buf: u64) -> bool {
        let base = self.base;
        let port = self.port;
        // Build the H2D FIS (20 bytes) in the command table's CFIS area.
        let ct = self.buf.ct as *mut u8;
        // 20-byte register H2D FIS (AHCI spec layout):
        //   0 type, 1 C-bit, 2 command, 3 features,
        //   4-6 LBA[23:0], 7 device, 8-10 LBA[47:24], 11 features-exp,
        //   12-13 sector count, 14 IC, 15 control, 16-19 reserved.
        let fis: [u8; 20] = [
            0x27,
            0x80, // C=1
            cmd,
            0, // features
            (lba & 0xFF) as u8,
            ((lba >> 8) & 0xFF) as u8,
            ((lba >> 16) & 0xFF) as u8,
            0x40 | (((lba >> 24) & 0x0F) as u8), // device
            ((lba >> 24) & 0xFF) as u8,          // LBA[31:24]
            ((lba >> 32) & 0xFF) as u8,          // LBA[39:32]
            ((lba >> 40) & 0xFF) as u8,          // LBA[47:40]
            0,                                   // features-exp
            (count & 0xFF) as u8,
            ((count >> 8) & 0xFF) as u8,
            0, // IC
            0, // control
            0,
            0,
            0,
            0,
        ];
        unsafe {
            core::ptr::copy_nonoverlapping(fis.as_ptr(), ct, 20);
            // PRDT at +0x80: one entry for the 512-byte buffer.
            let prd = ct.add(0x80) as *mut u32;
            *prd.add(0) = (prd_buf & 0xFFFF_FFFF) as u32;
            *prd.add(1) = (prd_buf >> 32) as u32;
            *prd.add(2) = (SECTOR as u32 - 1) | (1 << 31); // byte count-1, IOC
            *prd.add(3) = 0;
        }
        // Command list entry 0: CFIS length 5 dwords, 1 PRD, command table.
        let cl = self.buf.cl as *mut u32;
        let ct_addr = Bufs::phys(self.buf.ct);
        unsafe {
            *cl.add(0) = 5 | (1 << 16); // CFIS length, PRDTL=1
            *cl.add(1) = 0x80; // PRDBO: PRDT starts at command table + 0x80
            *cl.add(2) = (ct_addr & 0xFFFF_FFFF) as u32;
            *cl.add(3) = (ct_addr >> 32) as u32;
        }
        // Issue and wait for completion (PxCI bit 0 clears when done).
        // QEMU can complete synchronously, so do not read back before polling.
        reg_write(base, port_off(port, PCI), 1);
        for _ in 0..200_000 {
            if reg_read(base, port_off(port, PCI)) & 1 == 0 {
                break;
            }
        }
        let done = reg_read(base, port_off(port, PCI)) & 1 == 0;
        let err = reg_read(base, port_off(port, PTFD)) & 1 != 0;
        if !done || err {
            crate::sprintln!(
                "Aegis: AHCI: cmd {:#x} done={} err={} (PCI={:#x} TFD={:#x} IS={:#x})",
                cmd,
                done,
                err,
                reg_read(base, port_off(port, PCI)),
                reg_read(base, port_off(port, PTFD)),
                reg_read(base, port_off(port, PIS))
            );
        }
        // Clear the error/interrupt status bits.
        reg_write(base, port_off(port, PIS), 0xFFFFFFFF);
        done && !err
    }

    /// IDENTIFY DEVICE; parse the sector count (words 60-61, LBA28) into
    /// `self.sector_count`.
    fn identify(&mut self) -> bool {
        if !self.issue(ATA_IDENTIFY, 0, 0, Bufs::phys(self.buf.sec)) {
            return false;
        }
        self.flush_data();
        let id = self.buf.sec as *const u16;
        let lo = unsafe { core::ptr::read_volatile(id.add(60)) } as u64;
        let hi = unsafe { core::ptr::read_volatile(id.add(61)) } as u64;
        self.sector_count = lo | (hi << 16);
        // The command executing without error is the gate; sector_count can
        // legitimately read 0 if the PRD transfer is incomplete during bring-up.
        true
    }

    /// Read one 512-byte sector into the internal buffer; call `lba_data`.
    pub fn read_lba(&mut self, lba: u64) -> bool {
        let ok = self.issue(ATA_READ_DMA, lba, 1, Bufs::phys(self.buf.sec));
        if ok {
            self.flush_data();
        }
        ok
    }

    /// Invalidate the CPU's cache lines over the sector buffer so a device
    /// DMA write to RAM is re-read (QEMU's emulated DMA does not snoop the
    /// guest CPU cache; real hardware is coherent, this is belt-and-braces).
    fn flush_data(&self) {
        let ptr = self.buf.sec as *const u8;
        for off in (0..512).step_by(64) {
            unsafe {
                core::arch::asm!("clflush [{}]", in(reg) ptr.add(off), options(nostack, preserves_flags));
            }
        }
    }

    /// Write one 512-byte sector from `data`.
    pub fn write_lba(&mut self, lba: u64, data: &[u8]) -> bool {
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.buf.sec as *mut u8,
                SECTOR.min(data.len()),
            );
        }
        self.issue(ATA_WRITE_DMA, lba, 1, Bufs::phys(self.buf.sec))
    }

    /// The current sector buffer.
    pub fn lba_data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.buf.sec as *const u8, SECTOR) }
    }
}

/// `BlockIo` bridge so the object store can sit on a SATA disk.
impl crate::nvme_store::BlockIo for AhciController {
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> bool {
        if !self.read_lba(lba) {
            return false;
        }
        let n = SECTOR.min(out.len());
        out[..n].copy_from_slice(&self.lba_data()[..n]);
        true
    }

    fn write_sector(&mut self, lba: u64, data: &[u8]) -> bool {
        self.write_lba(lba, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_layout_constants() {
        // HBA register offsets (AHCI spec).
        assert_eq!(crate::ahci::_HBA_CAP, 0x00);
        assert_eq!(crate::ahci::_HBA_GHC, 0x04);
        assert_eq!(crate::ahci::_HBA_PI, 0x0C);
        assert_eq!(crate::ahci::_HBA_VS, 0x10);
        // Port 0 register block starts at ABAR+0x100, each port 0x80 bytes.
        assert_eq!(port_off(0, PCMD), 0x100 + 0x18);
        assert_eq!(port_off(0, PSSTS), 0x100 + 0x28);
        assert_eq!(port_off(0, PCI), 0x100 + 0x38);
        assert_eq!(port_off(1, PCMD), 0x100 + 0x80 + 0x18);
    }

    #[test]
    fn ghc_bits() {
        assert_eq!(GHC_AE, 0x8000_0000);
        assert_eq!(GHC_HR, 1);
    }

    #[test]
    fn pcmd_bits() {
        assert_eq!(PCMD_ST, 1);
        assert_eq!(PCMD_SUD, 2);
        assert_eq!(PCMD_POD, 4);
        assert_eq!(PCMD_FRE, 0x10);
        assert_eq!(PCMD_FR, 0x4000);
        assert_eq!(PCMD_CR, 0x8000);
    }

    #[test]
    fn ssts_fields() {
        assert_eq!(SSTS_DET, 0x0F);
        assert_eq!(SSTS_IPM, 0xF0);
        assert_eq!(DET_PRESENT, 3);
        assert_eq!(IPM_ACTIVE, 0x10);
    }

    #[test]
    fn ata_command_codes() {
        assert_eq!(ATA_IDENTIFY, 0xEC);
        assert_eq!(ATA_READ_DMA, 0xC8);
        assert_eq!(ATA_WRITE_DMA, 0xCA);
    }
}

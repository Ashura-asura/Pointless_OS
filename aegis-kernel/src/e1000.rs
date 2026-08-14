//! Intel 82574L (e1000e) NIC driver — QEMU q35's default NIC (8086:10D3).
//!
//! Polled transmit and receive over legacy descriptor rings; no interrupts
//! and no MSI-X are used (the live demo is boot-time, so polling is honest).
//! The driver is verified under QEMU/TCG where the NIC is attached to a
//! `socket` netdev: frames the kernel transmits leave the guest and are
//! captured externally on the host, and frames the host writes back are
//! received through the RX ring. UNTESTED on real hardware.
//!
//! Registers are memory-mapped through BAR0 (identity-mapped below 4 GiB on
//! q35, so a plain volatile read/write works — the NVMe driver uses the same
//! trick for its 64-bit window).

// ---- register offsets (bytes) ----
pub const CTRL: u64 = 0x0000;
pub const STATUS: u64 = 0x0008;
pub const ICR: u64 = 0x00C0;
pub const IMC: u64 = 0x00D8;
pub const RCTL: u64 = 0x0100;
pub const RDBAL: u64 = 0x02800;
pub const RDBAH: u64 = 0x02804;
pub const RDLEN: u64 = 0x02808;
pub const RDH: u64 = 0x02810;
pub const RDT: u64 = 0x02818;
pub const RXDCTL: u64 = 0x02828;
pub const TDBAL: u64 = 0x03800;
pub const TDBAH: u64 = 0x03804;
pub const TDLEN: u64 = 0x03808;
pub const TDH: u64 = 0x03810;
pub const TDT: u64 = 0x03818;
pub const TXDCTL: u64 = 0x03828;
pub const TCTL: u64 = 0x00400;
pub const TIPG: u64 = 0x00410;
pub const RAL0: u64 = 0x05400;
pub const RAH0: u64 = 0x05404;

// ---- control/status bits ----
pub const CTRL_RST: u32 = 1 << 26;
pub const CTRL_SLU: u32 = 1 << 6;
pub const STATUS_LU: u32 = 1 << 1;
pub const TCTL_EN: u32 = 1 << 1;
pub const TCTL_PSP: u32 = 1 << 3;
pub const RCTL_EN: u32 = 1 << 1;
pub const RCTL_BAM: u32 = 1 << 3;
pub const RCTL_LPE: u32 = 1 << 15;
pub const RAH_AV: u32 = 1 << 31;

/// Legacy TX descriptor command bits.
pub const DESC_CMD_EOP: u8 = 0x01;
pub const DESC_CMD_IFCS: u8 = 0x02;
pub const DESC_CMD_RS: u8 = 0x08;
/// Legacy descriptor status bits (TX: DD; RX: DD|EOP).
pub const DESC_STATUS_DD: u8 = 0x01;
pub const DESC_STATUS_RX_EOP: u8 = 0x02;

pub const TX_RING_LEN: usize = 8;
/// RX ring size in descriptors. QEMU's `E1000_XDLEN_MASK` (= 0xFFFF80)
/// zeroes any RDLEN that is not a multiple of 128 bytes (8 descriptors),
/// so a ring of fewer than 8 legacy descriptors is silently disabled.
pub const RX_RING_LEN: usize = 8;
pub const DESC_BYTES: usize = 16;
pub const RX_BUF_BYTES: usize = 2048;

/// One legacy descriptor (16 bytes), as programmed in the descriptor ring.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LegacyDescriptor {
    pub addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

impl LegacyDescriptor {
    pub fn tx(addr: u64, length: u16, cmd: u8) -> Self {
        LegacyDescriptor {
            addr,
            length,
            cso: 0,
            cmd,
            status: 0,
            css: 0,
            special: 0,
        }
    }

    pub fn rx(addr: u64) -> Self {
        LegacyDescriptor {
            addr,
            length: 0,
            cso: 0,
            cmd: 0,
            status: 0,
            css: 0,
            special: 0,
        }
    }

    pub fn done(&self) -> bool {
        self.status & DESC_STATUS_DD != 0
    }
}

/// `(high, low)` u32 halves of a 64-bit physical address.
fn address_halves(addr: u64) -> (u32, u32) {
    ((addr >> 32) as u32, addr as u32)
}

/// Encode a 48-bit MAC from the RAL0/RAH0 register pair.
///
/// The registers hold the MAC as little-endian bytes: RAL0 = mac[0..3] (bytes
/// 0-3), RAH0 = mac[4] (byte 0), mac[5] (byte 1), with the AV bit in bit 31.
/// This matches both QEMU (`e1000x_reset_mac_addr` / `e1000x_rx_group_filter`
/// compare the registers as little-endian bytes) and the Intel 82574L layout.
pub fn mac_from_regs(ral: u32, rah: u32) -> [u8; 6] {
    [
        ral as u8,
        (ral >> 8) as u8,
        (ral >> 16) as u8,
        (ral >> 24) as u8,
        rah as u8,
        (rah >> 8) as u8,
    ]
}

/// Build the 42-byte ARP request frame for `sender` asking for `target`.
///
/// Ethernet II (14 B) + ARP request (28 B). The frame is what the external
/// capture on the host must show byte-for-byte.
pub fn build_arp_request(sender: [u8; 6], target: [u8; 4]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[0..6].copy_from_slice(&[0xFF; 6]); // broadcast dest
    f[6..12].copy_from_slice(&sender);
    f[12..14].copy_from_slice(&[0x08, 0x06]); // ARP
    f[14..16].copy_from_slice(&[0x00, 0x01]); // htype: Ethernet
    f[16..18].copy_from_slice(&[0x08, 0x00]); // ptype: IPv4
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&[0x00, 0x01]); // op: request
    f[22..28].copy_from_slice(&sender); // sender hw
    f[28..32].copy_from_slice(&[10, 0, 2, 15]); // sender proto (10.0.2.15)
                                                // target hw = 0
    f[38..42].copy_from_slice(&target); // target proto
    f
}

/// True if `frame` is an ARP reply (op 2) addressed to `our_mac`.
pub fn is_arp_reply_for(frame: &[u8], our_mac: [u8; 6]) -> bool {
    if frame.len() < 42 {
        return false;
    }
    if frame[0..6] != our_mac {
        return false;
    }
    if frame[12..14] != [0x08, 0x06] {
        return false;
    }
    frame[20..22] == [0x00, 0x02]
}

fn rd32(base: *mut u8, offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *mut u32) }
}

fn wr32(base: *mut u8, offset: u64, value: u32) {
    unsafe { core::ptr::write_volatile(base.add(offset as usize) as *mut u32, value) }
}

fn wr64(base: *mut u8, offset: u64, value: u64) {
    let (hi, lo) = address_halves(value);
    wr32(base, offset, lo);
    wr32(base, offset + 4, hi);
}

fn spin_until(mut iters: u32, cond: impl FnMut() -> bool) -> bool {
    let mut c = cond;
    while iters > 0 {
        if c() {
            return true;
        }
        iters -= 1;
        unsafe { core::arch::asm!("pause", options(nomem, nostack)) };
    }
    false
}

/// A DMA ring + its payload buffer, backed by one physical frame each
/// (identity-mapped, so the physical address is also the VA the CPU reads).
struct DmaFrame {
    phys: u64,
    len: usize,
}

impl DmaFrame {
    /// Allocate `len` bytes of physical, contiguous DMA memory and
    /// identity-map it into `domain` (Phase G) before returning it —
    /// nothing is ever handed back to a caller as a DMA target without
    /// first being a real, mapped entry in that device's IOMMU domain.
    fn alloc(len: usize, domain: u32) -> Option<DmaFrame> {
        let frames = len.div_ceil(4096) as u64;
        let phys = unsafe { crate::frame::alloc_contiguous_global(frames) }?;
        let bytes = unsafe { core::slice::from_raw_parts_mut(phys as *mut u8, len) };
        bytes.fill(0);
        let flags = crate::iommu::PAGE_READ | crate::iommu::PAGE_WRITE;
        let mapped =
            unsafe { crate::iommu::with(|i| i.identity_map(domain, phys, frames * 4096, flags)) };
        if !mapped {
            crate::sprintln!("Aegis: e1000: IOMMU identity-map failed for DMA frame");
            return None;
        }
        Some(DmaFrame { phys, len })
    }

    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.phys as *mut u8, self.len) }
    }
}

pub struct E1000 {
    base: *mut u8,
    pub bar_addr: u64,
    pub mac: [u8; 6],
    /// Phase G: this device's IOMMU requester id. Every DMA address handed
    /// to hardware is translated through `dma_addr` first, gated on this
    /// bdf's domain.
    bdf: u32,
    tx: DmaFrame,
    tx_buf: DmaFrame,
    rx: DmaFrame,
    rx_buf: DmaFrame,
    pub tx_head: u16,
    pub rx_next: u16,
}

impl E1000 {
    /// Find the NIC on the PCI bus, map BAR0, reset, read the MAC and
    /// program the legacy TX + RX rings.
    pub fn probe(pci: &crate::pci::PciDeviceList) -> Option<E1000> {
        let dev = pci.find_network()?;
        let addr = dev.bar_address(0);
        if addr == 0 || addr >= 0x1_0000_0000 {
            crate::sprintln!("Aegis: e1000: BAR {:x} not identity-mapped - skipped", addr);
            return None;
        }
        unsafe {
            crate::pci::enable_bus_mastering(dev.address);
        }
        let base = addr as *mut u8;

        // Phase G: own IOMMU domain, all four DMA rings/buffers identity-
        // mapped into it before any address reaches hardware. Same pattern
        // as `nvme::NvmeController::probe`.
        let bdf = crate::iommu::bdf(dev.address.bus, dev.address.device, dev.address.function);
        let domain = unsafe { crate::iommu::with(|i| i.provision_device(bdf)) };
        let tx = DmaFrame::alloc(TX_RING_LEN * DESC_BYTES, domain)?;
        let tx_buf = DmaFrame::alloc(2048, domain)?;
        let rx = DmaFrame::alloc(RX_RING_LEN * DESC_BYTES, domain)?;
        let rx_buf = DmaFrame::alloc(RX_RING_LEN * RX_BUF_BYTES, domain)?;
        Some(E1000 {
            base,
            bar_addr: addr,
            mac: [0; 6],
            bdf,
            tx,
            tx_buf,
            rx,
            rx_buf,
            tx_head: 0,
            rx_next: 0,
        })
    }

    /// This device's IOMMU requester id, exposed for the boot-demo denial
    /// test in `main.rs`.
    pub fn iommu_bdf(&self) -> u32 {
        self.bdf
    }

    /// Translate a physical DMA address through this device's IOMMU domain
    /// before it is written into any descriptor or BAR register. A no-op
    /// pass-through for the real rings/buffers allocated in `probe` (they
    /// were identity-mapped there); a hard denial — logged, address 0
    /// returned — for anything else.
    fn dma_addr(&self, phys: u64) -> u64 {
        let flags = crate::iommu::PAGE_READ | crate::iommu::PAGE_WRITE;
        match unsafe { crate::iommu::with(|i| i.translate(self.bdf, phys, flags)) } {
            Ok(p) => p,
            Err(reason) => {
                crate::sprintln!(
                    "Aegis: e1000: IOMMU denied DMA phys={:#x} ({:?})",
                    phys,
                    reason
                );
                0
            }
        }
    }

    /// Reset the device, bring the link up and read the MAC.
    pub fn reset(&mut self) -> bool {
        wr32(self.base, CTRL, CTRL_RST);
        // Wait for the reset bit to self-clear.
        if !spin_until(10_000, || rd32(self.base, CTRL) & CTRL_RST == 0) {
            return false;
        }
        // Force link up; QEMU e1000e reports LU once SLU is set.
        let mut ctrl = rd32(self.base, CTRL);
        ctrl |= CTRL_SLU;
        wr32(self.base, CTRL, ctrl);
        let ral = rd32(self.base, RAL0);
        let rah = rd32(self.base, RAH0);
        self.mac = mac_from_regs(ral, rah);
        self.tx_head = 0;
        self.rx_next = 0;
        true
    }

    /// Set the RX address filters and enable the receive unit.
    pub fn rx_enable(&mut self) {
        // RAL0 = mac[0..3] as LE bytes; RAH0 = mac[4], mac[5] as bytes 0-1,
        // with the address-valid bit in bit 31 (see `mac_from_regs`).
        let ral = u32::from_le_bytes([self.mac[0], self.mac[1], self.mac[2], self.mac[3]]);
        let rah = RAH_AV | (self.mac[4] as u32) | ((self.mac[5] as u32) << 8);
        wr32(self.base, RAL0, ral);
        wr32(self.base, RAH0, rah);

        wr64(self.base, RDBAL, self.dma_addr(self.rx.phys));
        wr32(self.base, RDLEN, (RX_RING_LEN * DESC_BYTES) as u32);
        wr32(self.base, RDH, 0);
        wr32(self.base, RDT, (RX_RING_LEN - 1) as u32);

        // Fill the ring with buffer descriptors. Addresses are translated
        // through the IOMMU *before* `self.rx` is mutably borrowed below —
        // `dma_addr` needs `&self` (whole struct), so it can't run while
        // `ring` holds an exclusive borrow of `self.rx`.
        {
            let rx_buf_phys = self.rx_buf.phys;
            let mut addrs = [0u64; RX_RING_LEN];
            for (i, a) in addrs.iter_mut().enumerate() {
                *a = self.dma_addr(rx_buf_phys + (i * RX_BUF_BYTES) as u64);
            }
            let ring = self.rx.as_mut();
            for (i, addr) in addrs.iter().enumerate() {
                let d = LegacyDescriptor::rx(*addr);
                write_desc(ring, i, &d);
            }
        }

        let rctl = RCTL_EN | RCTL_BAM | RCTL_LPE;
        wr32(self.base, RCTL, rctl);
        wr32(self.base, RXDCTL, 0x0100_0000); // enable + buffer threshold
    }

    /// Program and enable the transmit unit.
    pub fn tx_enable(&mut self) {
        wr64(self.base, TDBAL, self.dma_addr(self.tx.phys));
        wr32(self.base, TDLEN, (TX_RING_LEN * DESC_BYTES) as u32);
        wr32(self.base, TDH, 0);
        wr32(self.base, TDT, 0);
        wr32(self.base, TXDCTL, 0x0100_0000);
        wr32(self.base, TIPG, 0x0060_200A);
        wr32(self.base, TCTL, TCTL_EN | TCTL_PSP);
    }

    pub fn link_up(&self) -> bool {
        rd32(self.base, STATUS) & STATUS_LU != 0
    }

    /// Transmit one Ethernet frame. Polls the descriptor for completion.
    pub fn send(&mut self, frame: &[u8]) -> bool {
        if frame.is_empty() || frame.len() > 2048 {
            return false;
        }
        let slot = self.tx_head as usize % TX_RING_LEN;
        self.tx_buf.as_mut()[..frame.len()].copy_from_slice(frame);
        let tx_buf_addr = self.dma_addr(self.tx_buf.phys);
        let desc = LegacyDescriptor::tx(
            tx_buf_addr,
            frame.len() as u16,
            DESC_CMD_EOP | DESC_CMD_IFCS | DESC_CMD_RS,
        );
        write_desc(self.tx.as_mut(), slot, &desc);
        wr32(self.base, TDT, ((slot + 1) % TX_RING_LEN) as u32);
        // Poll for completion (descriptor DD) — polled driver, no interrupts.
        let ok = spin_until(200_000, || read_desc(self.tx.as_mut(), slot).done());
        self.tx_head = (self.tx_head + 1) % TX_RING_LEN as u16;
        ok
    }

    /// Receive a frame if one has landed in the RX ring. Returns the byte
    /// length written into `out`.
    pub fn receive(&mut self, out: &mut [u8]) -> Option<usize> {
        let slot = self.rx_next as usize % RX_RING_LEN;
        let d = read_desc(self.rx.as_mut(), slot);
        if !d.done() {
            return None;
        }
        let len = d.length as usize;
        let len = len.min(out.len());
        let buf_off = slot * RX_BUF_BYTES;
        let src = &self.rx_buf.as_mut()[buf_off..buf_off + len];
        out[..len].copy_from_slice(src);
        // Re-arm the descriptor and advance RDT. Translate before borrowing
        // `self.rx` mutably, same reasoning as in `rx_enable`.
        let rearm_addr = self.dma_addr(self.rx_buf.phys + (slot * RX_BUF_BYTES) as u64);
        write_desc(self.rx.as_mut(), slot, &LegacyDescriptor::rx(rearm_addr));
        wr32(self.base, RDT, slot as u32);
        self.rx_next = (self.rx_next + 1) % RX_RING_LEN as u16;
        Some(len)
    }
}

fn write_desc(ring: &mut [u8], index: usize, d: &LegacyDescriptor) {
    let off = index * DESC_BYTES;
    let (hi, lo) = address_halves(d.addr);
    ring[off..off + 4].copy_from_slice(&lo.to_le_bytes());
    ring[off + 4..off + 8].copy_from_slice(&hi.to_le_bytes());
    ring[off + 8..off + 10].copy_from_slice(&d.length.to_le_bytes());
    ring[off + 10] = d.cso;
    ring[off + 11] = d.cmd;
    ring[off + 12] = d.status;
    ring[off + 13] = d.css;
    ring[off + 14..off + 16].copy_from_slice(&d.special.to_le_bytes());
}

fn read_desc(ring: &[u8], index: usize) -> LegacyDescriptor {
    let off = index * DESC_BYTES;
    // The status and length fields are written by the device (DMA), so they
    // are read volatile — otherwise the compiler may hoist the poll into a
    // single read and never observe the hardware's writeback.
    let ptr = unsafe { ring.as_ptr().add(off) };
    let mut lo = [0u8; 4];
    let mut hi = [0u8; 4];
    lo.copy_from_slice(&ring[off..off + 4]);
    hi.copy_from_slice(&ring[off + 4..off + 8]);
    let addr = u64::from_le_bytes([lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]);
    let length = unsafe { core::ptr::read_volatile(ptr.add(8) as *const u16) };
    let status = unsafe { core::ptr::read_volatile(ptr.add(12)) };
    LegacyDescriptor {
        addr,
        length,
        cso: ring[off + 10],
        cmd: ring[off + 11],
        status,
        css: ring[off + 13],
        special: u16::from_le_bytes([ring[off + 14], ring[off + 15]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_request_layout() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let f = build_arp_request(mac, [10, 0, 2, 2]);
        assert_eq!(f.len(), 42);
        assert_eq!(&f[0..6], &[0xFF; 6]);
        assert_eq!(&f[6..12], &mac);
        assert_eq!(&f[12..14], &[0x08, 0x06]);
        assert_eq!(&f[14..16], &[0x00, 0x01]);
        assert_eq!(&f[16..18], &[0x08, 0x00]);
        assert_eq!(f[18], 6);
        assert_eq!(f[19], 4);
        assert_eq!(&f[20..22], &[0x00, 0x01]);
        assert_eq!(&f[28..32], &[10, 0, 2, 15]);
        assert_eq!(&f[38..42], &[10, 0, 2, 2]);
    }

    #[test]
    fn arp_reply_detection() {
        let our_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let mut reply = build_arp_request(our_mac, [10, 0, 2, 2]);
        // Turn the request into a reply from the gateway.
        reply[0..6].copy_from_slice(&our_mac);
        reply[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x02]);
        reply[20..22].copy_from_slice(&[0x00, 0x02]);
        reply[22..28].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x02]);
        reply[28..32].copy_from_slice(&[10, 0, 2, 2]);
        reply[32..38].copy_from_slice(&our_mac);
        reply[38..42].copy_from_slice(&[10, 0, 2, 15]);
        assert!(is_arp_reply_for(&reply, our_mac));
        assert!(!is_arp_reply_for(
            &build_arp_request(our_mac, [10, 0, 2, 2]),
            our_mac
        ));
    }

    #[test]
    fn mac_from_regs_roundtrip() {
        let ral = u32::from_le_bytes([0x52, 0x54, 0x00, 0x12]);
        // mac[4]=0x34 at byte 0, mac[5]=0x56 at byte 1, AV in bit 31.
        let rah = (0x56u32 << 8) | 0x34 | RAH_AV;
        assert_eq!(
            mac_from_regs(ral, rah),
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
        );
    }

    #[test]
    fn address_halves_split() {
        assert_eq!(
            address_halves(0x1234_5678_9ABC_DEF0),
            (0x1234_5678, 0x9ABC_DEF0)
        );
    }

    #[test]
    fn tx_descriptor_layout() {
        let mut ring = [0u8; TX_RING_LEN * DESC_BYTES];
        let d = LegacyDescriptor::tx(0xDEAD_BEEF, 42, DESC_CMD_EOP | DESC_CMD_IFCS);
        write_desc(&mut ring, 2, &d);
        let back = read_desc(&ring, 2);
        assert_eq!(back.addr, 0xDEAD_BEEF);
        assert_eq!(back.length, 42);
        assert_eq!(back.cmd, DESC_CMD_EOP | DESC_CMD_IFCS);
        assert!(!back.done());
    }

    #[test]
    fn rx_descriptor_done_uses_dd_bit() {
        let mut ring = [0u8; RX_RING_LEN * DESC_BYTES];
        let d = LegacyDescriptor::rx(0x1000);
        write_desc(&mut ring, 0, &d);
        let mut back = read_desc(&ring, 0);
        assert!(!back.done());
        back.status = DESC_STATUS_DD | DESC_STATUS_RX_EOP;
        write_desc(&mut ring, 0, &back);
        let b2 = read_desc(&ring, 0);
        assert!(b2.done());
        assert_eq!(b2.status & DESC_STATUS_RX_EOP, DESC_STATUS_RX_EOP);
    }

    #[test]
    fn send_rejects_oversized_frame() {
        let mut e = E1000 {
            base: core::ptr::null_mut(),
            bar_addr: 0,
            mac: [0; 6],
            bdf: 0,
            tx: DmaFrame {
                phys: 0x1000,
                len: TX_RING_LEN * DESC_BYTES,
            },
            tx_buf: DmaFrame {
                phys: 0x2000,
                len: 2048,
            },
            rx: DmaFrame {
                phys: 0x3000,
                len: RX_RING_LEN * DESC_BYTES,
            },
            rx_buf: DmaFrame {
                phys: 0x4000,
                len: RX_RING_LEN * RX_BUF_BYTES,
            },
            tx_head: 0,
            rx_next: 0,
        };
        assert!(!e.send(&[0u8; 4096]));
        assert!(!e.send(&[]));
    }
}

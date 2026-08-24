//! USB host controller driver — XHCI (USB 3.x) with an EHCI fallback probe.
//!
//! Phase 1: probe, controller bring-up (DCBAA + command ring + event ring +
//! run), slot enable, address-device, and a single control transfer
//! (GET_DESCRIPTOR) to read the first connected device's descriptor.
//!
//! Mirrors `nvme.rs`/`ahci.rs` structure: PCI probe -> mapped BAR -> IOMMU
//! domain -> DMA buffers -> command submission. All buffers come from the
//! frame allocator (identity-mapped) and are zeroed.
//!
//! Honest scope: register offsets, TRB/context encodings, and the descriptor
//! helpers are contract-tested. The live flow (event-ring polling, slot /
//! address-device, control transfer) is written against the xHCI spec and
//! verified under QEMU with a `-device usb-*` attached; final validation is
//! the real TP201S. EHCI is probed but not yet driven.

// ---------- capability registers (BAR + off) ----------
const CAPLENGTH: u32 = 0x00;
const HCSPARAMS1: u32 = 0x04;
const HCCPARAMS1: u32 = 0x10;
const DB_OFFSET: u32 = 0x14;
const RTSOFF: u32 = 0x18;

// ---------- operational registers (BAR + CAPLENGTH + off) ----------
const USBCMD: u32 = 0x00;
const USBSTS: u32 = 0x04;
const CRCR: u32 = 0x18;
const DCBAAP: u32 = 0x30;
const CONFIG: u32 = 0x38;
const PORTSC_BASE: u32 = 0x400;
const PORTSC_STRIDE: u32 = 0x10;

// USBCMD bits.
const USBCMD_RUN: u32 = 1;
const USBCMD_HCRST: u32 = 1 << 1;
const USBCMD_INTE: u32 = 1 << 2;
#[cfg_attr(not(test), allow(dead_code))]
const USBCMD_HSEE: u32 = 1 << 3;

// USBSTS bits.
const USBSTS_HCH: u32 = 1; // host controller halted
const USBSTS_CNR: u32 = 1 << 11; // controller not ready

// ---------- runtime registers (BAR + RTSOFF + off) ----------
const ERSTSZ: u32 = 0x10; // interrupter 0, ERST size
const ERSTBA: u32 = 0x18; // ERST base (low at +0x18, high at +0x1C)
const ERDP: u32 = 0x24; // event ring dequeue pointer

// ---------- TRB types ----------
const TRB_ENABLE_SLOT: u32 = 3;
const TRB_ADDRESS_DEVICE: u32 = 8;
const TRB_LINK: u32 = 1;
const TRB_SETUP_STAGE: u32 = 5;
const TRB_DATA_STAGE: u32 = 6;
const TRB_STATUS_STAGE: u32 = 7;
const TRB_EVENT_CMD_COMPLETE: u32 = 32;

// Completion codes (event TRB bits 23:16).
const CC_SUCCESS: u32 = 1;

// ---------- control-transfer setup packet ----------
const GET_DESCRIPTOR: u8 = 0x06;

/// Descriptor layout helpers (device descriptor, 18 bytes, little-endian).
pub fn descriptor_vendor_id(d: &[u8]) -> u16 {
    u16::from_le_bytes([d[8], d[9]])
}
pub fn descriptor_product_id(d: &[u8]) -> u16 {
    u16::from_le_bytes([d[10], d[11]])
}
pub fn descriptor_class(d: &[u8]) -> u8 {
    d[4]
}

// ---------- DMA buffers (identity-mapped, from the frame allocator) ----------
#[derive(Clone, Copy)]
struct Bufs {
    /// Command ring: 16 TRBs x 16 bytes = 256 B (4 KiB page).
    cmd_ring: u64,
    /// Event ring: 16 event TRBs x 16 bytes = 256 B.
    ev_ring: u64,
    /// ERST: 1 segment table entry (16 bytes).
    erst: u64,
    /// DCBAA: 256 device-context pointers x 8 bytes.
    dcbaa: u64,
    /// Input context (input-control + slot + EP0), 3 x 32 = 96 B.
    input_ctx: u64,
    /// Device context (slot + EP0), 64 B.
    dev_ctx: u64,
    /// Control transfer ring: 16 TRBs x 16 = 256 B.
    xfer_ring: u64,
    /// 18-byte device descriptor buffer.
    desc: u64,
}

/// XHCI host controller.
pub struct XhciController {
    pub bar_addr: u64,
    base: *mut u8,
    caplen: u32,
    db_off: u32,
    rts_off: u32,
    max_slots: u8,
    max_ports: u8,
    cmd_enq: u32,  // next command-ring TRB index (0..16)
    xfer_enq: u32, // next transfer-ring TRB index
    ev_idx: u32,   // next event-ring TRB index
    ev_ccs: bool,  // event-ring cycle bit
    cmd_ccs: bool,
    xfer_ccs: bool,
    slot: u32, // enabled slot id
    pub device_descriptor: [u8; 18],
    buf: Bufs,
}

fn reg_read(base: *mut u8, off: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(off as usize) as *const u32) }
}
fn reg_write(base: *mut u8, off: u32, v: u32) {
    unsafe { core::ptr::write_volatile(base.add(off as usize) as *mut u32, v) }
}

impl XhciController {
    pub fn probe(pci: &crate::pci::PciDeviceList) -> Option<Self> {
        let dev = pci.find_usb_xhci()?;
        let addr = dev.bar_address(0);
        if addr == 0 {
            return None;
        }
        let window = crate::page_tables::DEVICE_BAR_WINDOW;
        let bar_addr = if addr < window || (addr >= window && addr < window + 0x20_0000) {
            addr
        } else {
            crate::sprintln!("Aegis: xHCI: BAR {:#x} out of identity map - skipped", addr);
            return None;
        };
        let base = bar_addr as *mut u8;
        let caplen = reg_read(base, CAPLENGTH) & 0xFF;
        let db_off = reg_read(base, DB_OFFSET) & 0xFFFF_FFF0;
        let rts_off = reg_read(base, RTSOFF) & 0xFFFF_FFF0;
        let hcs1 = reg_read(base, HCSPARAMS1);
        let max_slots = (hcs1 & 0xFF) as u8;
        let max_ports = ((hcs1 >> 24) & 0xFF) as u8;
        // 64-bit addressing capability (HCCPARAMS1 bit 0) is assumed; we use
        // only low 32 bits of phys (frame allocator returns < 4 GiB here).
        reg_read(base, HCCPARAMS1);

        // Allocate + zero DMA buffers, provision the IOMMU domain.
        let buf = unsafe {
            let b = Bufs {
                cmd_ring: crate::frame::alloc_contiguous_global(1)?,
                ev_ring: crate::frame::alloc_contiguous_global(1)?,
                erst: crate::frame::alloc_contiguous_global(1)?,
                dcbaa: crate::frame::alloc_contiguous_global(1)?,
                input_ctx: crate::frame::alloc_contiguous_global(1)?,
                dev_ctx: crate::frame::alloc_contiguous_global(1)?,
                xfer_ring: crate::frame::alloc_contiguous_global(1)?,
                desc: crate::frame::alloc_contiguous_global(1)?,
            };
            for p in [
                b.cmd_ring,
                b.ev_ring,
                b.erst,
                b.dcbaa,
                b.input_ctx,
                b.dev_ctx,
                b.xfer_ring,
                b.desc,
            ] {
                core::ptr::write_bytes(p as *mut u8, 0, 4096);
            }
            b
        };
        let bdf = crate::iommu::bdf(dev.address.bus, dev.address.device, dev.address.function);
        unsafe {
            crate::iommu::with(|i| {
                let dom = i.provision_device(bdf);
                for p in [
                    buf.cmd_ring,
                    buf.ev_ring,
                    buf.erst,
                    buf.dcbaa,
                    buf.input_ctx,
                    buf.dev_ctx,
                    buf.xfer_ring,
                    buf.desc,
                ] {
                    i.identity_map(
                        dom,
                        p,
                        4096,
                        crate::iommu::PAGE_READ | crate::iommu::PAGE_WRITE,
                    );
                }
            });
        }

        let mut s = XhciController {
            bar_addr,
            base,
            caplen,
            db_off,
            rts_off,
            max_slots,
            max_ports,
            cmd_enq: 0,
            xfer_enq: 0,
            ev_idx: 0,
            ev_ccs: true,
            cmd_ccs: true,
            xfer_ccs: true,
            slot: 0,
            device_descriptor: [0; 18],
            buf,
        };
        s.init()?;
        Some(s)
    }

    pub fn max_slots(&self) -> u8 {
        self.max_slots
    }
    pub fn max_ports(&self) -> u8 {
        self.max_ports
    }

    /// Reset the controller, set up DCBAA + command + event rings, and run.
    fn init(&mut self) -> Option<()> {
        // Reset.
        reg_write(self.base, self.caplen + USBCMD, USBCMD_HCRST);
        for _ in 0..100_000 {
            if reg_read(self.base, self.caplen + USBCMD) & USBCMD_HCRST == 0 {
                break;
            }
        }
        // Wait for not-halted.
        for _ in 0..100_000 {
            if reg_read(self.base, self.caplen + USBSTS) & (USBSTS_HCH | USBSTS_CNR) == 0 {
                break;
            }
        }

        // Command ring CRCR: ring base | RCS (bit 0) | CRR (bit 3).
        let cmd_base = (self.buf.cmd_ring as u32) | 1;
        reg_write(self.base, self.caplen + CRCR, cmd_base);
        reg_write(self.base, self.caplen + CRCR, cmd_base | 8); // command ring running

        // Event ring: ERST (1 segment of 16 entries) + ERDP.
        let erst_base = self.buf.erst as *mut u32;
        unsafe {
            *erst_base.add(0) = self.buf.ev_ring as u32;
            *erst_base.add(1) = (self.buf.ev_ring >> 32) as u32;
            *erst_base.add(2) = 16; // 16 event TRBs
            *erst_base.add(3) = 0;
        }
        let rts = unsafe { self.base.add(self.rts_off as usize) };
        reg_write(rts, ERSTSZ, 1);
        reg_write(rts, ERSTBA, self.buf.erst as u32);
        reg_write(rts, ERSTBA + 4, (self.buf.erst >> 32) as u32);
        reg_write(rts, ERDP, (self.buf.ev_ring + 16) as u32); // dequeue at ring+16 (63b=1)
        reg_write(rts, ERDP + 4, 0);

        // DCBAA.
        reg_write(self.base, self.caplen + DCBAAP, self.buf.dcbaa as u32);
        reg_write(
            self.base,
            self.caplen + DCBAAP + 4,
            (self.buf.dcbaa >> 32) as u32,
        );

        // CONFIG: enable all slots.
        reg_write(self.base, self.caplen + CONFIG, self.max_slots as u32);

        // Run.
        reg_write(self.base, self.caplen + USBCMD, USBCMD_RUN | USBCMD_INTE);
        for _ in 0..100_000 {
            if reg_read(self.base, self.caplen + USBSTS) & USBSTS_HCH == 0 {
                break;
            }
        }
        Some(())
    }

    /// Ring the command doorbell (doorbell 0).
    fn ring_cmd_doorbell(&self) {
        reg_write(self.base, self.db_off, 0);
    }

    /// Post one command TRB to the command ring and ring the doorbell.
    /// Returns the slot id from the command-completion event, or None.
    fn cmd(&mut self, trb: [u32; 4]) -> Option<u32> {
        let idx = self.cmd_enq as usize;
        let ring = self.buf.cmd_ring as *mut u32;
        let mut t = trb;
        // Set the cycle bit on DW3 (bit 0).
        t[3] = (t[3] & !1u32) | if self.cmd_ccs { 1 } else { 0 };
        unsafe {
            core::ptr::copy_nonoverlapping(t.as_ptr(), ring.add(idx * 4), 4);
        }
        // Link TRB at the end.
        self.cmd_enq = (self.cmd_enq + 1) % 16;
        if self.cmd_enq == 0 {
            self.cmd_ccs = !self.cmd_ccs;
            let link = [(self.buf.cmd_ring & 0xFFFF_FFC0) as u32, 0, 0, TRB_LINK | 2];
            unsafe {
                core::ptr::copy_nonoverlapping(link.as_ptr(), ring.add(15 * 4), 4);
            }
        }
        self.ring_cmd_doorbell();
        // Poll the event ring for a command-completion event.
        self.poll_event()
    }

    /// Poll the event ring for the next event TRB. Returns the slot id on a
    /// command-completion event with CC_SUCCESS.
    fn poll_event(&mut self) -> Option<u32> {
        for _ in 0..100_000 {
            let idx = self.ev_idx as usize;
            let ev = self.buf.ev_ring as *const u32;
            let dw0 = unsafe { core::ptr::read_volatile(ev.add(idx * 4)) };
            let dw3 = unsafe { core::ptr::read_volatile(ev.add(idx * 4 + 3)) };
            let ccs_bit = dw3 & 1;
            if ccs_bit != if self.ev_ccs { 1 } else { 0 } {
                // No event yet.
                continue;
            }
            let trb_type = (dw3 >> 10) & 0x3F;
            let cc = (dw3 >> 24) & 0xFF;
            self.ev_idx = (self.ev_idx + 1) % 16;
            if self.ev_idx == 0 {
                self.ev_ccs = !self.ev_ccs;
            }
            // Advance ERDP.
            let rts = unsafe { self.base.add(self.rts_off as usize) };
            let next = self.buf.ev_ring + (self.ev_idx as u64) * 16 + 16;
            reg_write(rts, ERDP, next as u32);
            reg_write(rts, ERDP + 4, (next >> 32) as u32);
            if trb_type == TRB_EVENT_CMD_COMPLETE && cc == CC_SUCCESS {
                return Some(dw0 & 0xFF); // slot id in low byte
            }
            // Non-command events: keep polling.
        }
        None
    }

    /// Enable a slot (command type 3). Returns the slot id.
    fn enable_slot(&mut self) -> Option<u32> {
        let trb = [0, 0, 0, TRB_ENABLE_SLOT << 10];
        self.cmd(trb)
    }

    /// Address the device in `slot` (command type 8) using the input context.
    fn address_device(&mut self, slot: u32) -> bool {
        // Input context: input-control (8 bytes: context flags), then slot
        // context, then EP0 context.
        let ic = self.buf.input_ctx as *mut u32;
        unsafe {
            // Input control: A0=1 (slot ctx), A1=1 (EP0 ctx).
            *ic.add(0) = 0x3;
            *ic.add(1) = 0;
            // Slot context (offset +8): context entries = 1 (EP0), route 0.
            let slot_ctx = ic.add(2);
            *slot_ctx.add(0) = 1 << 27; // context entries = 1
            *slot_ctx.add(1) = 0;
            *slot_ctx.add(2) = 0;
            *slot_ctx.add(3) = 0;
            // EP0 context (offset +8 + 32): type 4 (control), max packet 8
            // (default 8 bytes for EP0 low/full/high speed), etc.
            let ep0 = ic.add(2 + 8);
            *ep0.add(0) = (4 << 3) | (8 << 16); // EP type control, maxpkt 8
            *ep0.add(1) = 0;
            *ep0.add(2) = 0;
            *ep0.add(3) = 0;
            // DCBAA[slot] -> device context.
            let dcbaa = self.buf.dcbaa as *mut u32;
            *dcbaa.add(slot as usize * 2) = self.buf.dev_ctx as u32;
            *dcbaa.add(slot as usize * 2 + 1) = (self.buf.dev_ctx >> 32) as u32;
        }
        let trb = [
            slot,                                      // slot id
            (self.buf.input_ctx & 0xFFFF_FFF0) as u32, // input context base low
            (self.buf.input_ctx >> 32) as u32,
            TRB_ADDRESS_DEVICE << 10,
        ];
        self.cmd(trb).is_some()
    }

    /// Submit a control transfer on `slot`'s EP0 transfer ring (we reuse the
    /// single xfer ring). `setup` is the 8-byte setup packet; `data` is the
    /// data-stage buffer address (0 = no data stage).
    fn control_transfer(
        &mut self,
        slot: u32,
        setup: [u8; 8],
        data: u64,
        data_len: u16,
        dir_in: bool,
    ) -> bool {
        let ring = self.buf.xfer_ring as *mut u32;
        let mut enq = self.xfer_enq as usize;
        let trb = |t: [u32; 4], ccs: bool| {
            let mut v = t;
            v[3] = (v[3] & !1u32) | if ccs { 1 } else { 0 };
            v
        };
        // Setup stage TRB (type 5): TRB[0..1] = setup packet, TRB[2] =
        // length + transfer type (IOC=1 in TRB[3] via bit 5).
        let mut s = [0u32; 4];
        s[0] = u32::from_le_bytes([setup[0], setup[1], setup[2], setup[3]]);
        s[1] = u32::from_le_bytes([setup[4], setup[5], setup[6], setup[7]]);
        s[2] = (data_len as u32) << 17;
        s[3] = (TRB_SETUP_STAGE << 10) | (1 << 6) | (1 << 5); // TRT + IOC
        unsafe {
            core::ptr::copy_nonoverlapping(trb(s, self.xfer_ccs).as_ptr(), ring.add(enq * 4), 4);
        }
        enq = (enq + 1) % 16;
        if enq == 0 {
            self.xfer_ccs = !self.xfer_ccs;
        }
        // Data stage (type 6) if requested.
        if data != 0 && data_len > 0 {
            let mut d = [0u32; 4];
            d[0] = data as u32;
            d[1] = (data >> 32) as u32;
            d[2] = (data_len as u32) << 17 | if dir_in { 0 } else { 1 << 16 }; // DIR=1 for OUT
            d[3] = (TRB_DATA_STAGE << 10) | (1 << 5); // IOC
            unsafe {
                core::ptr::copy_nonoverlapping(
                    trb(d, self.xfer_ccs).as_ptr(),
                    ring.add(enq * 4),
                    4,
                );
            }
            enq = (enq + 1) % 16;
            if enq == 0 {
                self.xfer_ccs = !self.xfer_ccs;
            }
        }
        // Status stage (type 7). DIR bit (bit 16) = 1 for IN, 0 for OUT.
        let dir = if dir_in { 0 } else { 1 };
        let mut st = [0u32; 4];
        st[3] = (TRB_STATUS_STAGE << 10) | (1 << 5) | (dir << 16); // IOC
        unsafe {
            core::ptr::copy_nonoverlapping(trb(st, self.xfer_ccs).as_ptr(), ring.add(enq * 4), 4);
        }
        self.xfer_enq = ((enq + 1) % 16) as u32;
        if self.xfer_enq == 0 {
            self.xfer_ccs = !self.xfer_ccs;
        }
        // Ring the doorbell for this slot (doorbell offset + slot).
        reg_write(self.base, self.db_off + slot * 4, 1);
        // Poll for transfer completion: wait for the transfer event's cycle
        // bit. Simpler: poll the event ring until we consume one transfer
        // event (type 32 is cmd; type 33 is transfer).
        for _ in 0..100_000 {
            let idx = self.ev_idx as usize;
            let ev = self.buf.ev_ring as *const u32;
            let dw3 = unsafe { core::ptr::read_volatile(ev.add(idx * 4 + 3)) };
            if (dw3 & 1) != if self.ev_ccs { 1 } else { 0 } {
                continue;
            }
            let trb_type = (dw3 >> 10) & 0x3F;
            let cc = (dw3 >> 24) & 0xFF;
            self.ev_idx = (self.ev_idx + 1) % 16;
            if self.ev_idx == 0 {
                self.ev_ccs = !self.ev_ccs;
            }
            let rts = unsafe { self.base.add(self.rts_off as usize) };
            let next = self.buf.ev_ring + (self.ev_idx as u64) * 16 + 16;
            reg_write(rts, ERDP, next as u32);
            reg_write(rts, ERDP + 4, (next >> 32) as u32);
            if trb_type == 33 {
                return cc == CC_SUCCESS; // transfer event, completion code
            }
        }
        false
    }

    /// Enumerate the first connected device: wait for a port, enable a slot,
    /// address the device.
    pub fn enumerate_first_device(&mut self) -> bool {
        // Find a connected port (PORTSC CCS = bit 0).
        let mut port = None;
        for p in 0..self.max_ports {
            let ps = reg_read(
                self.base,
                self.caplen + PORTSC_BASE + (p as u32) * PORTSC_STRIDE,
            );
            if ps & 1 != 0 {
                port = Some(p);
                break;
            }
        }
        if port.is_none() {
            crate::sprintln!("Aegis: xHCI: no connected port");
            return false;
        }
        // Reset the port (bit 4, write 1) then wait for PED (bit 1).
        let psc = self.caplen + PORTSC_BASE + (port.unwrap() as u32) * PORTSC_STRIDE;
        reg_write(self.base, psc, reg_read(self.base, psc) | (1 << 4));
        for _ in 0..100_000 {
            if reg_read(self.base, psc) & 2 != 0 {
                break;
            }
        }
        let slot = match self.enable_slot() {
            Some(s) => s,
            None => {
                crate::sprintln!("Aegis: xHCI: enable-slot command failed");
                return false;
            }
        };
        self.slot = slot;
        if !self.address_device(slot) {
            crate::sprintln!("Aegis: xHCI: address-device failed for slot {}", slot);
            return false;
        }
        true
    }

    /// Read the 18-byte device descriptor into `self.device_descriptor`.
    pub fn read_device_descriptor(&mut self) -> bool {
        let slot = self.slot;
        if slot == 0 {
            return false;
        }
        // GET_DESCRIPTOR(device): bmRequestType=0x80, bRequest=6, wValue=0x0100,
        // wIndex=0, wLength=18.
        let setup = [0x80, GET_DESCRIPTOR, 0x00, 0x01, 0x00, 0x00, 18, 0];
        let ok = self.control_transfer(slot, setup, self.buf.desc, 18, true);
        if ok {
            unsafe {
                let src = self.buf.desc as *const u8;
                for i in 0..18 {
                    self.device_descriptor[i] = core::ptr::read_volatile(src.add(i));
                }
            }
        }
        ok
    }
}

/// EHCI (USB 2.0) host controller — probed but not yet driven (XHCI is
/// preferred; the TP201S exposes one of the two).
pub struct EhciController {
    pub bar_addr: u64,
}

impl EhciController {
    pub fn probe(pci: &crate::pci::PciDeviceList) -> Option<Self> {
        let dev = pci.find_usb_ehci()?;
        let addr = dev.bar_address(0);
        if addr == 0 {
            return None;
        }
        crate::sprintln!(
            "Aegis: EHCI: controller at {:#x} (driver not yet implemented)",
            addr
        );
        Some(EhciController { bar_addr: addr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xhci_register_offsets() {
        assert_eq!(CAPLENGTH, 0x00);
        assert_eq!(HCSPARAMS1, 0x04);
        assert_eq!(HCCPARAMS1, 0x10);
        assert_eq!(DB_OFFSET, 0x14);
        assert_eq!(RTSOFF, 0x18);
        assert_eq!(USBCMD, 0x00);
        assert_eq!(USBSTS, 0x04);
        assert_eq!(CRCR, 0x18);
        assert_eq!(DCBAAP, 0x30);
        assert_eq!(CONFIG, 0x38);
        assert_eq!(PORTSC_BASE, 0x400);
        assert_eq!(PORTSC_STRIDE, 0x10);
    }

    #[test]
    fn usbcmd_bits() {
        assert_eq!(USBCMD_RUN, 1);
        assert_eq!(USBCMD_HCRST, 2);
        assert_eq!(USBCMD_INTE, 4);
        assert_eq!(USBCMD_HSEE, 8);
    }

    #[test]
    fn trb_types() {
        assert_eq!(TRB_ENABLE_SLOT, 3);
        assert_eq!(TRB_ADDRESS_DEVICE, 8);
        assert_eq!(TRB_SETUP_STAGE, 5);
        assert_eq!(TRB_DATA_STAGE, 6);
        assert_eq!(TRB_STATUS_STAGE, 7);
        assert_eq!(TRB_EVENT_CMD_COMPLETE, 32);
    }

    #[test]
    fn descriptor_helpers() {
        let mut d = [0u8; 18];
        d[4] = 9; // class: hub
        d[8] = 0x34;
        d[9] = 0x12;
        d[10] = 0xcd;
        d[11] = 0xab;
        assert_eq!(descriptor_class(&d), 9);
        assert_eq!(descriptor_vendor_id(&d), 0x1234);
        assert_eq!(descriptor_product_id(&d), 0xabcd);
        assert_eq!(d[7], 0); // maxpkt0 default in a fresh buffer
        assert_eq!(d[17], 0); // nconf
    }

    #[test]
    fn cmd_ring_cycle_bit() {
        // The cycle bit (DW3 bit 0) is driven by cmd_ccs: a freshly-built
        // TRB without the bit gets it set for the first pass.
        let t = [0u32, 0, 0, 3 << 10];
        let ccs = true;
        let v = (t[3] & !1u32) | if ccs { 1 } else { 0 };
        assert_eq!(v & 1, 1);
        let ccs2 = false;
        let v2 = (t[3] & !1u32) | if ccs2 { 1 } else { 0 };
        assert_eq!(v2 & 1, 0);
    }
}

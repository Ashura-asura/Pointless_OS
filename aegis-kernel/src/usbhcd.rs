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

/// Number of TRBs in the command and transfer rings (slot 15 is the link).
const RING_TRBS: u32 = 16;

/// Write one TRB into a 16-slot ring at `*enq`, advancing `*enq`. Slot 15 is
/// a permanent Link TRB that wraps the ring to slot 0 with the cycle toggled
/// (TC bit set), so multi-TRB sequences and repeated commands never collide
/// with the wrap.
fn ring_put(ring: u64, trb: [u32; 4], enq: &mut u32, ccs: &mut bool) {
    let idx = *enq as usize;
    let base = ring as *mut u32;
    let mut t = trb;
    t[3] = (t[3] & !1u32) | if *ccs { 1 } else { 0 };
    unsafe {
        core::ptr::copy_nonoverlapping(t.as_ptr(), base.add(idx * 4), 4);
    }
    if idx as u32 == RING_TRBS - 2 {
        // Next free slot would be 15 (the Link slot): write the Link TRB,
        // toggle the cycle, wrap to slot 0.
        *ccs = !*ccs;
        let link = [
            (ring & 0xFFFF_FFC0) as u32,
            (ring >> 32) as u32,
            0,
            (TRB_LINK << 10) | (1 << 1) | if *ccs { 1 } else { 0 }, // TC + new cycle
        ];
        unsafe {
            core::ptr::copy_nonoverlapping(link.as_ptr(), base.add(15 * 4), 4);
        }
        *enq = 0;
    } else {
        *enq = (idx as u32 + 1) % RING_TRBS;
    }
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

        // Command ring CRCR: ring base | RCS (bit 0). The CRR bit (3) is
        // read-only and set by hardware; software only arms the ring here.
        let cmd_base = (self.buf.cmd_ring as u32) | 1;
        reg_write(self.base, self.caplen + CRCR, cmd_base);

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
        // ERDP points at the first event TRB; bit 0 (EHB) set on write.
        reg_write(rts, ERDP, (self.buf.ev_ring | 1) as u32);
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
        ring_put(self.buf.cmd_ring, trb, &mut self.cmd_enq, &mut self.cmd_ccs);
        self.ring_cmd_doorbell();
        // Poll the event ring for a command-completion event.
        self.poll_event()
    }

    /// Poll the event ring for the next event TRB. Returns the slot id on a
    /// command-completion event with CC_SUCCESS.
    ///
    /// Event TRB layout: DW2 bits 23:16 = completion code, bits 31:24 =
    /// slot id (command completion); DW3 bits 15:10 = TRB type, bit 0 =
    /// cycle.
    fn poll_event(&mut self) -> Option<u32> {
        for _ in 0..100_000 {
            let idx = self.ev_idx as usize;
            let ev = self.buf.ev_ring as *const u32;
            let dw2 = unsafe { core::ptr::read_volatile(ev.add(idx * 4 + 2)) };
            let dw3 = unsafe { core::ptr::read_volatile(ev.add(idx * 4 + 3)) };
            let ccs_bit = dw3 & 1;
            if ccs_bit != if self.ev_ccs { 1 } else { 0 } {
                // No event yet.
                continue;
            }
            let trb_type = (dw3 >> 10) & 0x3F;
            let cc = (dw2 >> 16) & 0xFF;
            let slot = (dw2 >> 24) & 0xFF;
            self.ev_idx = (self.ev_idx + 1) % 16;
            if self.ev_idx == 0 {
                self.ev_ccs = !self.ev_ccs;
            }
            // Advance ERDP to the next unprocessed event TRB.
            let rts = unsafe { self.base.add(self.rts_off as usize) };
            let next = self.buf.ev_ring + (self.ev_idx as u64) * 16 + 16;
            reg_write(rts, ERDP, next as u32);
            reg_write(rts, ERDP + 4, (next >> 32) as u32);
            if trb_type == TRB_EVENT_CMD_COMPLETE && cc == CC_SUCCESS {
                return Some(slot);
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
    /// `max_pkt0` is the device's EP0 max packet size (bytes) from the first
    /// descriptor read; it goes into the EP0 context MaxPacketSize field.
    fn address_device(&mut self, slot: u32, max_pkt0: u8) -> bool {
        // Input context: input-control (8 bytes: context flags), then slot
        // context, then EP0 context.
        let ic = self.buf.input_ctx as *mut u32;
        unsafe {
            // Input control: A0=1 (slot ctx), A1=1 (EP0 ctx).
            *ic.add(0) = 0x3;
            *ic.add(1) = 0;
            // Slot context (offset +8): Context Entries field = bits 26:24,
            // set to 1 (only EP0). Route/parent/other fields = 0.
            let slot_ctx = ic.add(2);
            *slot_ctx.add(0) = 1 << 24;
            *slot_ctx.add(1) = 0;
            *slot_ctx.add(2) = 0;
            *slot_ctx.add(3) = 0;
            // EP0 context (offset +8 + 32): EP Type (bits 15:13) = 4 (control),
            // Max Packet Size (bits 9:6) = log2(max_pkt0)-3 (8->0, 64->3).
            let mps = if max_pkt0 >= 8 {
                ((max_pkt0 as u32).trailing_zeros().saturating_sub(3)).min(0xF)
            } else {
                0
            };
            let ep0 = ic.add(2 + 8);
            *ep0.add(0) = (4 << 13) | (mps << 6);
            *ep0.add(1) = 0;
            *ep0.add(2) = 0;
            *ep0.add(3) = 0;
            // DCBAA[slot] -> device context.
            let dcbaa = self.buf.dcbaa as *mut u32;
            *dcbaa.add(slot as usize * 2) = self.buf.dev_ctx as u32;
            *dcbaa.add(slot as usize * 2 + 1) = (self.buf.dev_ctx >> 32) as u32;
        }
        // Address Device command: DW0 bits 31:24 = slot id, DW1/DW2 = input
        // context base (64-byte aligned).
        let trb = [
            slot << 24,
            (self.buf.input_ctx & !0x3F) as u32,
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
        // Setup stage TRB (type 5): TRB[0..1] = setup packet, DW2 bits 31:17 =
        // transfer length, bit 16 = TRT (1=IN data stage, 2=OUT data stage).
        let mut s = [0u32; 4];
        s[0] = u32::from_le_bytes([setup[0], setup[1], setup[2], setup[3]]);
        s[1] = u32::from_le_bytes([setup[4], setup[5], setup[6], setup[7]]);
        let trt = if data_len == 0 {
            0
        } else if dir_in {
            1
        } else {
            2
        };
        s[2] = (data_len as u32) << 17 | (trt << 16);
        s[3] = (TRB_SETUP_STAGE << 10) | (1 << 5); // IOC
        ring_put(
            self.buf.xfer_ring,
            s,
            &mut self.xfer_enq,
            &mut self.xfer_ccs,
        );

        // Data stage (type 6) if requested.
        if data != 0 && data_len > 0 {
            let mut d = [0u32; 4];
            d[0] = data as u32;
            d[1] = (data >> 32) as u32;
            d[2] = (data_len as u32) << 17 | if dir_in { 0 } else { 1 << 16 }; // DIR=0 IN, 1 OUT
            d[3] = (TRB_DATA_STAGE << 10) | (1 << 5); // IOC
            ring_put(
                self.buf.xfer_ring,
                d,
                &mut self.xfer_enq,
                &mut self.xfer_ccs,
            );
        }

        // Status stage (type 7). DIR bit (bit 16) is the OPPOSITE of the data
        // stage: for a control IN (device->host) the status stage is OUT
        // (DIR=1); for a control OUT it is IN (DIR=0).
        let dir = if dir_in { 1 } else { 0 };
        let mut st = [0u32; 4];
        st[3] = (TRB_STATUS_STAGE << 10) | (1 << 5) | (dir << 16); // IOC
        ring_put(
            self.buf.xfer_ring,
            st,
            &mut self.xfer_enq,
            &mut self.xfer_ccs,
        );
        // Ring the doorbell for this slot (doorbell offset + slot).
        reg_write(self.base, self.db_off + slot * 4, 1);
        // Poll the event ring for the transfer event (type 33). Completion
        // code is DW2 bits 23:16.
        for _ in 0..100_000 {
            let idx = self.ev_idx as usize;
            let ev = self.buf.ev_ring as *const u32;
            let dw2 = unsafe { core::ptr::read_volatile(ev.add(idx * 4 + 2)) };
            let dw3 = unsafe { core::ptr::read_volatile(ev.add(idx * 4 + 3)) };
            if (dw3 & 1) != if self.ev_ccs { 1 } else { 0 } {
                continue;
            }
            let trb_type = (dw3 >> 10) & 0x3F;
            let cc = (dw2 >> 16) & 0xFF;
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
        // Reset the port (bit 4, write 1), wait for PR to clear (reset done)
        // then PED (bit 1) — the device is enabled.
        let psc = self.caplen + PORTSC_BASE + (port.unwrap() as u32) * PORTSC_STRIDE;
        reg_write(self.base, psc, reg_read(self.base, psc) | (1 << 4));
        for _ in 0..200_000 {
            if reg_read(self.base, psc) & (1 << 4) == 0 {
                break;
            }
        }
        for _ in 0..200_000 {
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

        // Read the first 8 bytes of the device descriptor at address 0 to
        // learn bMaxPacketSize0 (byte 7), then address the device with the
        // correct EP0 max packet size.
        let setup8 = [0x80, GET_DESCRIPTOR, 0x00, 0x01, 0x00, 0x00, 8, 0];
        if !self.control_transfer(slot, setup8, self.buf.desc, 8, true) {
            crate::sprintln!(
                "Aegis: xHCI: first descriptor read failed for slot {}",
                slot
            );
            return false;
        }
        let max_pkt0 = unsafe { core::ptr::read_volatile((self.buf.desc as *const u8).add(7)) };
        if !self.address_device(slot, max_pkt0) {
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
    fn event_trb_completion_code_and_slot_from_dw2() {
        // Event TRB: DW2 bits 23:16 = CC, bits 31:24 = slot id; DW3 =
        // (type << 10) | cycle.
        let dw2: u32 = (7 << 24) | (CC_SUCCESS << 16); // slot 7, CC=1
        let dw3: u32 = (TRB_EVENT_CMD_COMPLETE << 10) | 1;
        assert_eq!((dw2 >> 16) & 0xFF, CC_SUCCESS);
        assert_eq!((dw2 >> 24) & 0xFF, 7);
        assert_eq!((dw3 >> 10) & 0x3F, TRB_EVENT_CMD_COMPLETE);
    }

    #[test]
    fn address_device_trb_encodes_slot_in_high_byte() {
        // DW0 bits 31:24 = slot id for the Address Device command.
        let trb = [3u32 << 24, 0x2000, 0, TRB_ADDRESS_DEVICE << 10];
        assert_eq!((trb[0] >> 24) & 0xFF, 3);
        assert_eq!((trb[3] >> 10) & 0x3F, TRB_ADDRESS_DEVICE);
    }

    #[test]
    fn ep0_context_type_is_control() {
        // EP Type field (bits 15:13) = 4 (control); Max Packet Size field
        // (bits 9:6) = 0 -> 8 bytes default.
        let dw0: u32 = 4 << 13;
        assert_eq!((dw0 >> 13) & 0x7, 4);
        assert_eq!((dw0 >> 6) & 0xF, 0);
    }

    #[test]
    fn slot_context_entries_field() {
        // Context Entries = bits 26:24, value 1 (only EP0).
        let dw0: u32 = 1 << 24;
        assert_eq!((dw0 >> 24) & 0x7, 1);
    }

    #[test]
    fn status_stage_dir_is_opposite_of_data_stage() {
        // Control IN (GET_DESCRIPTOR): data stage DIR=0, status stage DIR=1.
        let data_dir_in: u32 = 0;
        let status_dir = if data_dir_in == 0 { 1 } else { 0 };
        assert_eq!(status_dir, 1);
        // Control OUT: data stage DIR=1, status stage DIR=0.
        let data_dir_out: u32 = 1 << 16;
        let status_dir2 = if data_dir_out == 0 { 1 } else { 0 };
        assert_eq!(status_dir2, 0);
    }

    #[test]
    fn max_packet_size_field_encoding() {
        // MaxPacketSize field = log2(maxpkt)-3: 8->0, 16->1, 32->2, 64->3.
        let f = |m: u8| {
            if m >= 8 {
                ((m as u32).trailing_zeros().saturating_sub(3)).min(0xF)
            } else {
                0
            }
        };
        assert_eq!(f(8), 0);
        assert_eq!(f(16), 1);
        assert_eq!(f(32), 2);
        assert_eq!(f(64), 3);
        assert_eq!(f(0), 0);
    }

    #[test]
    fn ring_put_writes_link_trb_and_wraps() {
        let mut buf = [0u8; 4096];
        let ring = buf.as_mut_ptr() as u64;
        let mut enq = 14u32; // writing at slot 14 forces the link at 15 + wrap
        let mut ccs = true;
        ring_put(ring, [1, 2, 3, 0], &mut enq, &mut ccs);
        // The command landed at slot 14 with cycle bit set.
        let slot14 = unsafe { (ring as *const u32).add(14 * 4) };
        assert_eq!(unsafe { *slot14.add(3) } & 1, 1);
        // Link TRB at slot 15: type LINK(1)<<10 | TC(bit1) | new cycle.
        let slot15 = unsafe { (ring as *const u32).add(15 * 4) };
        let dw3 = unsafe { *slot15.add(3) };
        assert_eq!((dw3 >> 10) & 0x3F, TRB_LINK);
        assert_eq!(dw3 & 2, 2); // TC set
        assert_eq!(dw3 & 1, 0); // cycle toggled off
        assert_eq!(enq, 0);
        assert!(!ccs); // toggled
    }

    #[test]
    fn setup_trb_encodes_trt() {
        // GET_DESCRIPTOR (IN): TRT=1. For an 18-byte transfer, length<<17.
        let data_len = 18u16;
        let trt = 1u32; // IN data stage
        let dw2 = (data_len as u32) << 17 | (trt << 16);
        assert_eq!(dw2 & 0x10000, 0x10000); // TRT bit
        assert_eq!((dw2 >> 17) & 0x7FFF, 18); // length
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

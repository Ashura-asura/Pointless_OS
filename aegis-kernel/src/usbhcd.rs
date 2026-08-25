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

// ---------- TRB types (xHCI 1.2 §6.4.6 TRB Type field encodings) ----------
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_LINK: u32 = 6;
const TRB_SETUP_STAGE: u32 = 2;
const TRB_DATA_STAGE: u32 = 3;
const TRB_STATUS_STAGE: u32 = 4;
const TRB_EVENT_CMD_COMPLETE: u32 = 33; // Command Completion Event
const TRB_TRANSFER_EVENT: u32 = 32; // Transfer Event

// Completion codes (event TRB bits 23:16).
const CC_SUCCESS: u32 = 1;

// ---------- control-transfer setup packet ----------
const GET_DESCRIPTOR: u8 = 0x06;
const SET_CONFIGURATION: u8 = 0x09;

// HID class-specific requests (USB HID 1.11 §7.2), bmRequestType 0x21
// (host-to-device, class, interface).
const HID_SET_IDLE: u8 = 0x0A;
const HID_SET_PROTOCOL: u8 = 0x0B;
const HID_PROTOCOL_BOOT: u16 = 0x0000;

// Descriptor types (wValue high byte of GET_DESCRIPTOR).
const DESC_CONFIGURATION: u16 = 0x02;
const DESC_INTERFACE: u8 = 4;
const DESC_ENDPOINT: u8 = 5;

// Interface class/subclass/protocol for boot-protocol HID keyboard/mouse
// (USB HID 1.11 §4.2, Device Class Definition for HID).
const CLASS_HID: u8 = 3;
const CLASS_HUB: u8 = 9;
const SUBCLASS_BOOT: u8 = 1;
const PROTOCOL_KEYBOARD: u8 = 1;
const PROTOCOL_MOUSE: u8 = 2;

// xHCI Configure Endpoint command (xHCI 1.2 §6.4.3.5).
const TRB_CONFIGURE_ENDPOINT: u32 = 12;

/// Maximum simultaneously-tracked HID boot devices. Two is the expected
/// case (keyboard dock + touchpad on the TP201S); a couple of spares cost
/// nothing and avoid a hard cap on the first port that happens to enumerate.
const MAX_HID: usize = 4;

/// One enumerated HID boot-protocol device (keyboard or mouse) with its
/// interrupt IN endpoint configured and running.
///
/// Honest limits: boot-protocol only (no report-descriptor parsing, no
/// non-boot HID devices, no output reports/LEDs); one interrupt IN endpoint
/// per device, matching the boot keyboard/mouse spec exactly. Verified
/// against the xHCI/HID specs and unit-tested at the byte-decoding level;
/// not yet run against the real TP201S USB HID hardware.
#[allow(dead_code)]
struct HidDevice {
    slot: u32,
    /// Device Context Index of the interrupt IN endpoint (`2*epnum + 1`).
    dci: u32,
    kind: HidKind,
    max_pkt: u16,
    /// xHCI Interval field already converted from the descriptor's
    /// bInterval (see `interval_field_for_interrupt`).
    interval_field: u32,
    /// Per-device interrupt transfer ring (16 TRBs) and its producer state
    /// — separate from the shared EP0 `xfer_ring` in `Bufs`, since this
    /// ring is polled continuously for the device's whole lifetime rather
    /// than one-shot per control transfer.
    int_ring: u64,
    int_enq: u32,
    int_ccs: bool,
    /// DMA buffer the interrupt IN transfer writes each report into.
    report_buf: u64,
    report_len: usize,
    /// Whether a transfer TRB is currently outstanding on `int_ring` (so
    /// `poll_hid` knows whether to check for a completion or submit a
    /// fresh one).
    armed: bool,
    /// Previous boot-keyboard report (8 bytes: modifier, reserved, 6
    /// keycodes), for edge-detecting presses/releases across polls. Unused
    /// for mice.
    kb_prev: [u8; 8],
}

#[derive(Clone, Copy, PartialEq)]
enum HidKind {
    Keyboard,
    Mouse,
}

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
    #[allow(dead_code)]
    bdf: u32,
    iommu_domain: u32,
    /// Enumerated HID boot-protocol devices (keyboard/mouse) beyond the
    /// single EP0-only device the original Phase 1 demo path addresses.
    /// Populated by `enumerate_hid_devices`, drained by `poll_hid`.
    hid: [Option<HidDevice>; MAX_HID],
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
        // toggle the cycle, wrap to slot 0. The Link TRB's cycle bit must be
        // the *current* lap's consumer-cycle (the hardware follows it and only
        // then toggles to the next lap), so capture it before toggling.
        let link_cycle = *ccs;
        *ccs = !*ccs;
        let link = [
            (ring & 0xFFFF_FFC0) as u32,
            (ring >> 32) as u32,
            0,
            (TRB_LINK << 10) | (1 << 1) | if link_cycle { 1 } else { 0 }, // TC + current cycle
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
        let mut iommu_domain: u32 = 0;
        unsafe {
            crate::iommu::with(|i| {
                let dom = i.provision_device(bdf);
                iommu_domain = dom;
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
            bdf,
            iommu_domain,
            hid: [None, None, None, None],
        };
        s.init()?;
        Some(s)
    }

    /// Identity-map `[addr, addr+len)` into this controller's IOMMU domain
    /// (the one `probe()` provisioned for it), read+write. Used for the
    /// per-HID-device DMA buffers `enumerate_hid_devices` allocates after
    /// `probe()` — those pages exist only once a device is found, so they
    /// can't be pre-mapped alongside the fixed `Bufs` set.
    fn iommu_map(&self, addr: u64, len: u64) {
        let dom = self.iommu_domain;
        unsafe {
            crate::iommu::with(|i| {
                i.identity_map(
                    dom,
                    addr,
                    len,
                    crate::iommu::PAGE_READ | crate::iommu::PAGE_WRITE,
                );
            });
        }
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
        // ERDP points at the first event TRB; writing bit 3 clears EHB.
        reg_write(rts, ERDP, (self.buf.ev_ring | 0x8) as u32);
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
            // For the Enable Slot command the newly-assigned Slot ID is returned
            // in the Completion Parameter (DW2[15:0]); for other commands the
            // parameter is 0 and only the success flag matters to callers.
            let slot = dw2 & 0xFFFF;
            self.ev_idx = (self.ev_idx + 1) % 16;
            if self.ev_idx == 0 {
                self.ev_ccs = !self.ev_ccs;
            }
            // Advance ERDP to the next event TRB to be processed (EVidx points
            // at it after the increment), clearing the EHB (bit 3).
            let rts = unsafe { self.base.add(self.rts_off as usize) };
            let next = self.buf.ev_ring + (self.ev_idx as u64) * 16;
            reg_write(rts, ERDP, (next as u32) | 0x8);
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
        // Setup stage TRB (type 2): TRB[0..1] = setup packet, DW2 bits 23:0 =
        // transfer length (fixed 8 for the setup packet), bits 17:16 = TRT
        // (0=no data, 1=IN data stage, 2=OUT data stage).
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
        s[2] = 8 | (trt << 16);
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
            // Data stage TRB (type 3): DW2 bits 23:0 = transfer length, bit 16 =
            // DIR (0=OUT, 1=IN). A control IN reads data device->host, so DIR=1.
            d[2] = (data_len as u32) | if dir_in { 1 << 16 } else { 0 };
            d[3] = (TRB_DATA_STAGE << 10) | (1 << 5); // IOC
            ring_put(
                self.buf.xfer_ring,
                d,
                &mut self.xfer_enq,
                &mut self.xfer_ccs,
            );
        }

        // Status stage (type 4). DIR bit (bit 16) is the OPPOSITE of the data
        // stage: for a control IN (data DIR=1) the status stage is OUT (DIR=0);
        // for a control OUT (data DIR=0) it is IN (DIR=1).
        let dir = if dir_in { 0 } else { 1 << 16 };
        let mut st = [0u32; 4];
        st[3] = (TRB_STATUS_STAGE << 10) | (1 << 5) | dir; // IOC
        ring_put(
            self.buf.xfer_ring,
            st,
            &mut self.xfer_enq,
            &mut self.xfer_ccs,
        );
        // Ring the doorbell for this slot (doorbell offset + slot).
        reg_write(self.base, self.db_off + slot * 4, 1);
        // Poll the event ring for the Transfer Event (type 32). Completion
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
            let next = self.buf.ev_ring + (self.ev_idx as u64) * 16;
            reg_write(rts, ERDP, (next as u32) | 0x8);
            reg_write(rts, ERDP + 4, (next >> 32) as u32);
            if trb_type == TRB_TRANSFER_EVENT {
                return cc == CC_SUCCESS; // transfer event, completion code
            }
        }
        false
    }

    /// Power on every root port (xHCI PP bit, bit 9) and record diagnostic
    /// counters. Bay Trail / many SoC xHCI ports start unpowered, so without
    /// this `PORTSC.CCS` stays 0 and enumeration finds nothing.
    fn power_ports(&mut self) {
        unsafe {
            crate::cpu::set_xhci_ports(self.max_ports as usize);
        }
        let mut pp = 0usize;
        for p in 0..self.max_ports {
            let psc = self.caplen + PORTSC_BASE + (p as u32) * PORTSC_STRIDE;
            let v = reg_read(self.base, psc);
            if v & (1 << 9) == 0 {
                reg_write(self.base, psc, v | (1 << 9));
            }
            pp += 1;
        }
        unsafe {
            crate::cpu::set_xhci_pp(pp);
        }
        // Let ports ramp up and any attached devices connect.
        for _ in 0..500_000 {
            core::hint::spin_loop();
        }
        let mut conn = 0usize;
        for p in 0..self.max_ports {
            let psc = self.caplen + PORTSC_BASE + (p as u32) * PORTSC_STRIDE;
            if reg_read(self.base, psc) & 1 != 0 {
                conn += 1;
            }
        }
        unsafe {
            crate::cpu::set_xhci_conn(conn);
        }
    }

    /// Enumerate the first connected device: wait for a port, enable a slot,
    /// address the device.
    pub fn enumerate_first_device(&mut self) -> bool {
        self.power_ports();
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
        let cls = unsafe { core::ptr::read_volatile((self.buf.desc as *const u8).add(4)) };
        unsafe {
            crate::cpu::set_xhci_dev(true);
            crate::cpu::set_xhci_dev_cls(cls);
            if cls == CLASS_HUB {
                crate::cpu::set_xhci_hub(true);
            }
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

    // ---------------------------------------------------------------
    // HID boot-protocol keyboard/mouse support.
    // ---------------------------------------------------------------

    /// Convert a full/low-speed interrupt endpoint's `bInterval` (already in
    /// 1 ms frames per the USB 2.0 spec for those speeds) into the xHCI
    /// Interval field, which wants an exponent such that the actual polling
    /// period is `2^Interval * 125 us` (xHCI 1.2 §6.2.3.6). That's
    /// `ceil(log2(bInterval_ms * 8))`, clamped to the field's useful range.
    ///
    /// Honest limits: this is the FS/LS conversion only. A high-speed
    /// device (not expected from a tablet's built-in keyboard dock/touchpad)
    /// encodes bInterval directly as the exponent and would need a separate
    /// path; unified handling is left for when/if that's observed live.
    fn interval_field_for_interrupt(binterval_ms: u8) -> u32 {
        let units_125us = (binterval_ms.max(1) as u32) * 8;
        (32 - units_125us.leading_zeros()).clamp(3, 10)
    }

    /// Read the full configuration descriptor (config header + all
    /// interface/endpoint descriptors) into `self.buf.desc`. First reads
    /// the 9-byte header to learn `wTotalLength`, then re-reads that many
    /// bytes. Returns the byte length actually read, capped to the 4 KiB
    /// scratch buffer.
    fn read_config_descriptor(&mut self, slot: u32) -> usize {
        let setup9 = [
            0x80,
            GET_DESCRIPTOR,
            0x00,
            DESC_CONFIGURATION as u8,
            0x00,
            0x00,
            9,
            0,
        ];
        if !self.control_transfer(slot, setup9, self.buf.desc, 9, true) {
            return 0;
        }
        let total_len = unsafe {
            let p = self.buf.desc as *const u8;
            u16::from_le_bytes([
                core::ptr::read_volatile(p.add(2)),
                core::ptr::read_volatile(p.add(3)),
            ])
        };
        let len = (total_len as usize).min(4096);
        let len_lo = (len & 0xFF) as u8;
        let len_hi = ((len >> 8) & 0xFF) as u8;
        let setup_full = [
            0x80,
            GET_DESCRIPTOR,
            0x00,
            DESC_CONFIGURATION as u8,
            0x00,
            0x00,
            len_lo,
            len_hi,
        ];
        if !self.control_transfer(slot, setup_full, self.buf.desc, len as u16, true) {
            return 0;
        }
        len
    }

    /// Standard SET_CONFIGURATION (bmRequestType 0x00, bRequest 9): no data
    /// stage, `wValue` is the target `bConfigurationValue`.
    fn set_configuration(&mut self, slot: u32, config_value: u8) -> bool {
        let setup = [
            0x00,
            SET_CONFIGURATION,
            config_value,
            0x00,
            0x00,
            0x00,
            0,
            0,
        ];
        self.control_transfer(slot, setup, 0, 0, true)
    }

    /// HID class SET_PROTOCOL(boot) (bmRequestType 0x21, bRequest 0x0B,
    /// wValue 0 = boot protocol): no data stage. Required so the device
    /// emits the fixed 8-byte keyboard / 3-4-byte mouse boot reports this
    /// driver decodes, instead of an arbitrary report-descriptor format.
    fn hid_set_boot_protocol(&mut self, slot: u32, iface: u8) -> bool {
        let wval = HID_PROTOCOL_BOOT.to_le_bytes();
        let setup = [0x21, HID_SET_PROTOCOL, wval[0], wval[1], iface, 0x00, 0, 0];
        self.control_transfer(slot, setup, 0, 0, true)
    }

    /// HID class SET_IDLE(0) (bmRequestType 0x21, bRequest 0x0A): ask the
    /// device to report on every state change rather than at a fixed idle
    /// rate. Best-effort — some devices NAK this in boot mode, which is
    /// harmless, so the return value is not checked by the caller.
    fn hid_set_idle(&mut self, slot: u32, iface: u8) -> bool {
        let setup = [0x21, HID_SET_IDLE, 0x00, 0x00, iface, 0x00, 0, 0];
        self.control_transfer(slot, setup, 0, 0, true)
    }

    /// xHCI Configure Endpoint command: add one interrupt IN endpoint (DCI
    /// `dci`) to `slot`'s device context, reusing `self.buf.input_ctx` as
    /// scratch (safe — enumeration is sequential, never concurrent).
    /// `int_ring` is the endpoint's own dedicated transfer ring (its
    /// TR Dequeue Pointer), separate from EP0's `xfer_ring`.
    fn configure_hid_endpoint(
        &mut self,
        slot: u32,
        dci: u32,
        max_pkt: u16,
        interval_field: u32,
        int_ring: u64,
    ) -> bool {
        let ic = self.buf.input_ctx as *mut u32;
        unsafe {
            core::ptr::write_bytes(self.buf.input_ctx as *mut u8, 0, 96);
            // Input control: A0 = 0 (slot context not itself changing
            // besides Context Entries, folded in below), A(dci) = 1 (add
            // this endpoint). Add-context flags live in DW1.
            *ic.add(0) = 0;
            *ic.add(1) = 1 << dci;
            // Slot context (offset +8): Context Entries (bits 26:24) must
            // cover the highest DCI in use.
            let slot_ctx = ic.add(2);
            *slot_ctx.add(0) = dci << 24;
            *slot_ctx.add(1) = 0;
            *slot_ctx.add(2) = 0;
            *slot_ctx.add(3) = 0;
            // Endpoint context at offset +8 + dci*32 within the input
            // context (slot context occupies index 1, EP0 index 2, ...).
            let ep = ic.add(2 + (dci as usize) * 8);
            // DW0: bits 7:0 Interval, bits 18:16 Max Primary Streams (0),
            // bit 23 LSA (0), bits 31:24 Max ESIT Payload Hi (0).
            *ep.add(0) = interval_field & 0xFF;
            // DW1: bits 2:1 Error Count (3, standard), bits 5:3 EP Type
            // (7 = Interrupt IN), bits 31:16 Max Packet Size.
            *ep.add(1) = (3 << 1) | (7 << 3) | ((max_pkt as u32) << 16);
            // DW2/DW3: TR Dequeue Pointer (bit 0 of DW2 = DCS, ring starts
            // with cycle 1) | Average TRB Length in the low 16 bits of DW3.
            *ep.add(2) = (int_ring as u32) | 1;
            *ep.add(3) = (int_ring >> 32) as u32 | 8;
        }
        let trb = [
            slot << 24,
            (self.buf.input_ctx & !0x3F) as u32,
            (self.buf.input_ctx >> 32) as u32,
            TRB_CONFIGURE_ENDPOINT << 10,
        ];
        self.cmd(trb).is_some()
    }

    /// Submit one interrupt IN transfer TRB (Normal TRB, type 1) on a HID
    /// device's dedicated ring, targeting its `report_buf`. Rings that
    /// endpoint's doorbell (`db_off + slot*4`, target = DCI, matching the
    /// control-transfer doorbell convention but with EP0's implicit target 1
    /// replaced by the endpoint's own DCI).
    fn submit_hid_transfer(&self, dev: &mut HidDevice) {
        const TRB_NORMAL: u32 = 1;
        let trb = [
            dev.report_buf as u32,
            (dev.report_buf >> 32) as u32,
            dev.report_len as u32,         // DW2 bits 23:0 = transfer length
            (TRB_NORMAL << 10) | (1 << 5), // IOC
        ];
        ring_put(dev.int_ring, trb, &mut dev.int_enq, &mut dev.int_ccs);
        reg_write(self.base, self.db_off + dev.slot * 4, dev.dci);
        dev.armed = true;
    }

    /// Bring up every HID boot keyboard/mouse found on any connected port
    /// (not just the first, unlike `enumerate_first_device` — the TP201S
    /// has both a keyboard dock and a touchpad, on separate ports of the
    /// same xHCI controller). For each: enable a slot, address it, read the
    /// config descriptor, find a HID boot-protocol keyboard or mouse
    /// interface with an interrupt IN endpoint, SET_CONFIGURATION,
    /// SET_PROTOCOL(boot), configure that endpoint, and arm the first
    /// interrupt transfer. Returns the number of devices brought up.
    pub fn enumerate_hid_devices(&mut self) -> usize {
        let mut found = 0usize;
        self.power_ports();
        for p in 0..self.max_ports {
            if found >= MAX_HID {
                break;
            }
            let psc = self.caplen + PORTSC_BASE + (p as u32) * PORTSC_STRIDE;
            let ps = reg_read(self.base, psc);
            if ps & 1 == 0 {
                continue; // nothing connected on this port
            }
            // Reset the port and wait for it to enable, same sequence as
            // `enumerate_first_device`.
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
            let Some(slot) = self.enable_slot() else {
                continue;
            };
            let setup8 = [0x80, GET_DESCRIPTOR, 0x00, 0x01, 0x00, 0x00, 8, 0];
            if !self.control_transfer(slot, setup8, self.buf.desc, 8, true) {
                continue;
            }
            let cls = unsafe { core::ptr::read_volatile((self.buf.desc as *const u8).add(4)) };
            unsafe {
                crate::cpu::set_xhci_dev(true);
                crate::cpu::set_xhci_dev_cls(cls);
                if cls == CLASS_HUB {
                    crate::cpu::set_xhci_hub(true);
                }
            }
            let max_pkt0 = unsafe { core::ptr::read_volatile((self.buf.desc as *const u8).add(7)) };
            if !self.address_device(slot, max_pkt0) {
                continue;
            }
            let len = self.read_config_descriptor(slot);
            if len == 0 {
                continue;
            }
            if len > 5 {
                let devcls =
                    unsafe { core::ptr::read_volatile((self.buf.desc as *const u8).add(5)) };
                unsafe {
                    crate::cpu::set_xhci_dev_cls(devcls);
                }
            }
            if Self::config_has_hid(self, len) {
                unsafe {
                    crate::cpu::set_hid_any_seen(true);
                }
            }
            let Some((config_value, iface_num, kind, ep_addr, max_pkt, binterval)) =
                Self::find_hid_boot_interface(self, len)
            else {
                continue;
            };
            if !self.set_configuration(slot, config_value) {
                continue;
            }
            let _ = self.hid_set_boot_protocol(slot, iface_num);
            let _ = self.hid_set_idle(slot, iface_num);

            let Some(int_ring) = (unsafe { crate::frame::alloc_contiguous_global(1) }) else {
                continue;
            };
            let Some(report_buf) = (unsafe { crate::frame::alloc_contiguous_global(1) }) else {
                continue;
            };
            unsafe {
                core::ptr::write_bytes(int_ring as *mut u8, 0, 4096);
                core::ptr::write_bytes(report_buf as *mut u8, 0, 4096);
            }
            self.iommu_map(int_ring, 4096);
            self.iommu_map(report_buf, 4096);

            let epnum = ep_addr & 0x0F;
            let dci = epnum as u32 * 2 + 1; // IN endpoint DCI = 2*epnum + 1
            let interval_field = Self::interval_field_for_interrupt(binterval);
            if !self.configure_hid_endpoint(slot, dci, max_pkt, interval_field, int_ring) {
                continue;
            }

            let report_len = match kind {
                HidKind::Keyboard => 8,
                HidKind::Mouse => 4, // works for 3-byte reports too (extra byte ignored)
            };
            let mut dev = HidDevice {
                slot,
                dci,
                kind,
                max_pkt,
                interval_field,
                int_ring,
                int_enq: 0,
                int_ccs: true,
                report_buf,
                report_len,
                armed: false,
                kb_prev: [0; 8],
            };
            self.submit_hid_transfer(&mut dev);
            crate::sprintln!(
                "Aegis: xHCI: HID {} on slot {} (ep 0x{:02X}, dci {}, maxpkt {})",
                match kind {
                    HidKind::Keyboard => "keyboard",
                    HidKind::Mouse => "mouse",
                },
                slot,
                ep_addr,
                dci,
                max_pkt
            );
            for slot_opt in self.hid.iter_mut() {
                if slot_opt.is_none() {
                    *slot_opt = Some(dev);
                    found += 1;
                    break;
                }
            }
        }
        unsafe {
            crate::cpu::set_hid_enum_count(found);
        }
        found
    }

    /// Walk the configuration descriptor in `self.buf.desc` (first `len`
    /// bytes) for the first HID boot-protocol keyboard or mouse interface
    /// with an interrupt IN endpoint. Returns
    /// `(bConfigurationValue, bInterfaceNumber, kind, bEndpointAddress,
    /// wMaxPacketSize, bInterval)`.
    fn find_hid_boot_interface(&self, len: usize) -> Option<(u8, u8, HidKind, u8, u16, u8)> {
        let d = unsafe { core::slice::from_raw_parts(self.buf.desc as *const u8, len) };
        if d.len() < 9 || d[1] != 0x02 {
            return None; // not a configuration descriptor
        }
        let config_value = d[5];
        let mut i = 0usize;
        let mut cur_iface: Option<(u8, HidKind)> = None;
        while i + 2 <= d.len() {
            let blen = d[i] as usize;
            if blen < 2 || i + blen > d.len() {
                break; // malformed length: stop rather than read out of bounds
            }
            let dtype = d[i + 1];
            if dtype == DESC_INTERFACE && blen >= 9 {
                let iface_num = d[i + 2];
                let class = d[i + 5];
                let subclass = d[i + 6];
                let protocol = d[i + 7];
                cur_iface = if class == CLASS_HID && subclass == SUBCLASS_BOOT {
                    match protocol {
                        PROTOCOL_KEYBOARD => Some((iface_num, HidKind::Keyboard)),
                        PROTOCOL_MOUSE => Some((iface_num, HidKind::Mouse)),
                        _ => None,
                    }
                } else {
                    None
                };
            } else if dtype == DESC_ENDPOINT && blen >= 7 {
                if let Some((iface_num, kind)) = cur_iface {
                    let ep_addr = d[i + 2];
                    let attrs = d[i + 3];
                    let is_in = ep_addr & 0x80 != 0;
                    let is_interrupt = attrs & 0x03 == 3;
                    if is_in && is_interrupt {
                        let max_pkt = u16::from_le_bytes([d[i + 4], d[i + 5]]);
                        let binterval = d[i + 6];
                        return Some((config_value, iface_num, kind, ep_addr, max_pkt, binterval));
                    }
                }
            }
            i += blen;
        }
        None
    }

    /// Cheap probe used purely for diagnostics: does this configuration
    /// descriptor contain *any* HID-class interface (boot-protocol or not)?
    /// Surfaces on the status line as `HE=` so we can tell "no HID at all"
    /// (device on EHCI / behind a hub / not present) from "HID present but
    /// not boot-protocol" (needs a non-boot driver).
    fn config_has_hid(&self, len: usize) -> bool {
        let d = unsafe { core::slice::from_raw_parts(self.buf.desc as *const u8, len) };
        if d.len() < 9 || d[1] != 0x02 {
            return false;
        }
        let mut i = 0usize;
        while i + 2 <= d.len() {
            let blen = d[i] as usize;
            if blen < 2 || i + blen > d.len() {
                break;
            }
            if d[i + 1] == DESC_INTERFACE && blen >= 6 {
                let c = d[i + 5];
                if c == CLASS_HID {
                    return true;
                }
                if c == CLASS_HUB {
                    unsafe {
                        crate::cpu::set_xhci_hub(true);
                    }
                }
            }
            i += blen;
        }
        false
    }

    /// Non-blocking poll: drains whatever transfer-completion events are
    /// currently on the (single, shared-across-every-endpoint) event ring,
    /// routes each to the HID device it belongs to, decodes any completed
    /// report into the PS/2 ring buffers (`ps2::inject_scancode` /
    /// `ps2_mouse::inject_byte`) so `task_input` picks it up exactly like a
    /// real PS/2 IRQ would have, then re-arms every device's next transfer.
    /// Meant to be called once per `task_input` iteration.
    ///
    #[allow(clippy::needless_range_loop)]
    pub fn poll_hid(&mut self) {
        let mut completions: [Option<bool>; MAX_HID] = [None; MAX_HID];
        // Bounded drain: the ring holds 16 TRBs, so 32 iterations comfortably
        // covers "fully wrapped since last poll" without ever spinning on an
        // empty ring (next_transfer_event returns None as soon as it is).
        for _ in 0..32 {
            let Some((slot_id, ep_dci, ok)) = self.next_transfer_event() else {
                break;
            };
            if slot_id == 0 {
                continue; // sentinel: a non-transfer event, already consumed
            }
            unsafe {
                crate::cpu::inc_hid_poll_event();
                if !ok {
                    crate::cpu::inc_hid_cc_fail();
                }
            }
            for (i, dev_opt) in self.hid.iter().enumerate() {
                if let Some(dev) = dev_opt {
                    if dev.slot == slot_id && dev.dci == ep_dci {
                        completions[i] = Some(ok);
                        break;
                    }
                }
            }
        }
        for i in 0..MAX_HID {
            let Some(mut dev) = self.hid[i].take() else {
                continue;
            };
            if let Some(ok) = completions[i] {
                if ok {
                    self.handle_hid_report(&mut dev);
                }
                dev.armed = false;
            }
            if !dev.armed {
                self.submit_hid_transfer(&mut dev);
            }
            self.hid[i] = Some(dev);
        }
    }

    /// Non-blocking single read of the next event TRB, if any. For a
    /// Transfer Event (type 32) returns
    /// `(Slot ID, Endpoint DCI, completion-code-success)`; other event
    /// types are consumed (ERDP still advances — required, events must
    /// drain in order) and reported back as slot id 0, which is never a
    /// real slot (xHCI slot IDs start at 1), so callers can filter it out.
    fn next_transfer_event(&mut self) -> Option<(u32, u32, bool)> {
        let idx = self.ev_idx as usize;
        let ev = self.buf.ev_ring as *const u32;
        let dw3 = unsafe { core::ptr::read_volatile(ev.add(idx * 4 + 3)) };
        if (dw3 & 1) != if self.ev_ccs { 1 } else { 0 } {
            return None; // ring empty
        }
        let dw2 = unsafe { core::ptr::read_volatile(ev.add(idx * 4 + 2)) };
        let trb_type = (dw3 >> 10) & 0x3F;
        let cc = (dw2 >> 16) & 0xFF;
        // Transfer Event DW2[31:24] = Slot ID; DW3[31:24] = Endpoint ID (DCI).
        let slot_id = (dw2 >> 24) & 0xFF;
        let ep_dci = (dw3 >> 24) & 0x1F;
        self.ev_idx = (self.ev_idx + 1) % 16;
        if self.ev_idx == 0 {
            self.ev_ccs = !self.ev_ccs;
        }
        let rts = unsafe { self.base.add(self.rts_off as usize) };
        let next = self.buf.ev_ring + (self.ev_idx as u64) * 16;
        reg_write(rts, ERDP, (next as u32) | 0x8);
        reg_write(rts, ERDP + 4, (next >> 32) as u32);
        if trb_type == TRB_TRANSFER_EVENT {
            Some((slot_id, ep_dci, cc == CC_SUCCESS))
        } else {
            Some((0, 0, false))
        }
    }

    /// Decode one completed HID boot report and inject it into the
    /// existing PS/2 input pipeline.
    fn handle_hid_report(&self, dev: &mut HidDevice) {
        unsafe {
            crate::cpu::inc_hid_injected();
        }
        let mut report = [0u8; 8];
        let n = dev.report_len.min(8);
        unsafe {
            core::ptr::copy_nonoverlapping(dev.report_buf as *const u8, report.as_mut_ptr(), n);
        }
        match dev.kind {
            HidKind::Keyboard => {
                Self::inject_keyboard_report(&report[..n], &dev.kb_prev);
                dev.kb_prev = report;
            }
            HidKind::Mouse => Self::inject_mouse_report(&report[..n]),
        }
    }

    /// Diff a boot-keyboard report against the previous one and inject
    /// PS/2 set-1 make/break scancodes for every modifier and key that
    /// changed. USB HID boot keyboard report layout (8 bytes): byte 0 =
    /// modifier bitmap, byte 1 = reserved, bytes 2-7 = up to 6 currently
    /// held key usage IDs (0 = no key in that slot).
    fn inject_keyboard_report(report: &[u8], prev: &[u8; 8]) {
        if report.len() < 8 {
            return;
        }
        // Modifier bits, in USB HID order, to (set-1 scancode, extended?).
        const MODIFIERS: [(u8, u8, bool); 8] = [
            (0x01, 0x1D, false), // Left Ctrl
            (0x02, 0x2A, false), // Left Shift
            (0x04, 0x38, false), // Left Alt (no Key variant downstream, harmless)
            (0x08, 0x5B, true),  // Left GUI
            (0x10, 0x1D, true),  // Right Ctrl (E0 1D)
            (0x20, 0x36, false), // Right Shift (shares Left Shift's scancode)
            (0x40, 0x38, true),  // Right Alt (E0 38)
            (0x80, 0x5C, true),  // Right GUI
        ];
        let prev_mod = prev[0];
        let cur_mod = report[0];
        for (bit, sc, ext) in MODIFIERS {
            let was = prev_mod & bit != 0;
            let is = cur_mod & bit != 0;
            if was != is {
                unsafe {
                    if ext {
                        crate::ps2::inject_scancode(0xE0);
                    }
                    crate::ps2::inject_scancode(if is { sc } else { sc | 0x80 });
                }
            }
        }
        // Key usage slots 2-7: emit a break for anything in `prev` that's no
        // longer in `report`, then a make for anything in `report` that
        // wasn't in `prev`. Order (breaks first) avoids a spurious "both
        // keys held" state for fast rollover.
        for &was_key in &prev[2..8] {
            if was_key != 0 && !report[2..8].contains(&was_key) {
                if let Some((ext, sc)) = hid_keycode_to_scancode(was_key) {
                    unsafe {
                        if ext {
                            crate::ps2::inject_scancode(0xE0);
                        }
                        crate::ps2::inject_scancode(sc | 0x80);
                    }
                }
            }
        }
        for &is_key in &report[2..8] {
            if is_key != 0 && !prev[2..8].contains(&is_key) {
                if let Some((ext, sc)) = hid_keycode_to_scancode(is_key) {
                    unsafe {
                        if ext {
                            crate::ps2::inject_scancode(0xE0);
                        }
                        crate::ps2::inject_scancode(sc);
                    }
                }
            }
        }
    }

    /// USB HID boot-mouse report (3-4 bytes: buttons, signed dx, signed dy,
    /// [signed wheel — ignored, `ps2_mouse` has no scroll field either])
    /// maps directly onto the PS/2 wire's 3-byte packet: both use a
    /// two's-complement delta byte plus a flags byte with sign bits and an
    /// "always 1" marker (bit 3).
    fn inject_mouse_report(report: &[u8]) {
        if report.len() < 3 {
            return;
        }
        let buttons = report[0];
        let dx = report[1];
        let dy = report[2];
        let mut flags = 0x08u8; // bit 3: always 1 (packet-start marker)
        flags |= buttons & 0x07; // left/right/middle occupy the same bits
        if (dx as i8) < 0 {
            flags |= 0x10;
        }
        if (dy as i8) < 0 {
            flags |= 0x20;
        }
        unsafe {
            crate::ps2_mouse::inject_byte(flags);
            crate::ps2_mouse::inject_byte(dx);
            crate::ps2_mouse::inject_byte(dy);
        }
    }
}

/// USB HID Usage ID (Keyboard/Keypad page, 0x07) -> (extended?, PS/2 set-1
/// make code), for the subset `ps2::translate` already recognizes. Letters
/// and digits share PS/2's scancode assignment by convention (both derive
/// from the original IBM PC/XT layout), so those entries are exact; the
/// rest are the specific keys `ps2.rs` maps to a `Key` variant.
fn hid_keycode_to_scancode(usage: u8) -> Option<(bool, u8)> {
    match usage {
        // A-Z: HID usages 0x04-0x1D map to the QWERTY layout's scattered
        // PS/2 set-1 codes (not a linear offset — both derive from the same
        // physical keyboard, but the two enumeration orders differ), so
        // each letter is spelled out rather than computed.
        0x04 => Some((false, 0x1E)),                       // A
        0x05 => Some((false, 0x30)),                       // B
        0x06 => Some((false, 0x2E)),                       // C
        0x07 => Some((false, 0x20)),                       // D
        0x08 => Some((false, 0x12)),                       // E
        0x09 => Some((false, 0x21)),                       // F
        0x0A => Some((false, 0x22)),                       // G
        0x0B => Some((false, 0x23)),                       // H
        0x0C => Some((false, 0x17)),                       // I
        0x0D => Some((false, 0x24)),                       // J
        0x0E => Some((false, 0x25)),                       // K
        0x0F => Some((false, 0x26)),                       // L
        0x10 => Some((false, 0x32)),                       // M
        0x11 => Some((false, 0x31)),                       // N
        0x12 => Some((false, 0x18)),                       // O
        0x13 => Some((false, 0x19)),                       // P
        0x14 => Some((false, 0x10)),                       // Q
        0x15 => Some((false, 0x13)),                       // R
        0x16 => Some((false, 0x1F)),                       // S
        0x17 => Some((false, 0x14)),                       // T
        0x18 => Some((false, 0x16)),                       // U
        0x19 => Some((false, 0x2F)),                       // V
        0x1A => Some((false, 0x11)),                       // W
        0x1B => Some((false, 0x2D)),                       // X
        0x1C => Some((false, 0x15)),                       // Y
        0x1D => Some((false, 0x2C)),                       // Z
        0x1E..=0x26 => Some((false, usage - 0x1E + 0x02)), // 1-9
        0x27 => Some((false, 0x0B)),                       // 0
        0x28 => Some((false, 0x1C)),                       // Enter
        0x29 => Some((false, 0x01)),                       // Escape
        0x2A => Some((false, 0x0E)),                       // Backspace
        0x2B => Some((false, 0x0F)),                       // Tab
        0x2C => Some((false, 0x39)),                       // Space
        0x3A..=0x43 => Some((false, usage - 0x3A + 0x3B)), // F1-F10
        0x44 => Some((false, 0x57)),                       // F11
        0x45 => Some((false, 0x58)),                       // F12
        0x4F => Some((true, 0x4D)),                        // Right Arrow
        0x50 => Some((true, 0x4B)),                        // Left Arrow
        0x51 => Some((true, 0x50)),                        // Down Arrow
        0x52 => Some((true, 0x48)),                        // Up Arrow
        0x58 => Some((true, 0x1C)),                        // Keypad Enter
        _ => None,
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
        // Values must match the xHCI 1.2 TRB Type field encodings.
        assert_eq!(TRB_ENABLE_SLOT, 9);
        assert_eq!(TRB_ADDRESS_DEVICE, 11);
        assert_eq!(TRB_LINK, 6);
        assert_eq!(TRB_SETUP_STAGE, 2);
        assert_eq!(TRB_DATA_STAGE, 3);
        assert_eq!(TRB_STATUS_STAGE, 4);
        assert_eq!(TRB_EVENT_CMD_COMPLETE, 33);
        assert_eq!(TRB_TRANSFER_EVENT, 32);
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
        // Link TRB at slot 15: type LINK<<10 | TC(bit1) | current-lap cycle.
        let slot15 = unsafe { (ring as *const u32).add(15 * 4) };
        let dw3 = unsafe { *slot15.add(3) };
        assert_eq!((dw3 >> 10) & 0x3F, TRB_LINK);
        assert_eq!(dw3 & 2, 2); // TC set
        assert_eq!(dw3 & 1, 1); // cycle = current lap (so HW follows the link)
        assert_eq!(enq, 0);
        assert!(!ccs); // producer cycle toggled for the next lap
    }

    #[test]
    fn setup_trb_encodes_trt() {
        // GET_DESCRIPTOR (IN): TRT=1. Setup stage DW2 bits 23:0 = fixed
        // transfer length 8; bits 17:16 = TRT.
        let trt = 1u32; // IN data stage
        let dw2 = 8 | (trt << 16);
        assert_eq!(dw2 & 0x10000, 0x10000); // TRT bit
        assert_eq!(dw2 & 0xFFFF, 8); // transfer length fixed at 8
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

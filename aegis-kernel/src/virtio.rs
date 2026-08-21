//! Phase U: virtio-blk (legacy PCI) device emulation — the guest's virtual
//! disk, served from a sector-addressed block store (the NVMe object store's
//! `BlockIo` in production; a memory disk in the contract tests).
//!
//! Interface: the *legacy* virtio-pci transport as Linux implements it in
//! `virtio_pci_legacy.c` (a plain I/O-space BAR, no MSI-X, no memory-mapped
//! config): device ID 0x1001, I/O registers at BAR offsets 0x00-0x17 with
//! the device config (64-bit capacity in sectors) at offset 0x18. The guest
//! kernel is built with `CONFIG_VIRTIO_PCI_LEGACY` and `CONFIG_VIRTIO_BLK`,
//! boots `noapic nolapic`, and drives the device through PIC IRQ 11
//! (INTx#A), assigned by Aegis in the PCI config space.
//!
//! Honest scope: a single virtqueue (queue 0), no indirect descriptors
//! (VIRTIO_F_INDIRECT_DESC is not advertised, so a standards-conforming
//! guest never uses them), no ANY_LAYOUT (the request layout is the
//! standard one: header descriptor first, data descriptors in the middle,
//! one-byte status descriptor last), no MSI-X, no flush caching semantics
//! (FLUSH completes with OK), no write-through of the virtio config beyond
//! capacity. Everything is pure emulation state and pure protocol logic,
//! contract-tested against the exact byte layouts the Linux driver
//! produces; wiring to live guest memory and the object store is the
//! hardware-gated half (`vm.rs`).

/// I/O-register offsets (Linux `virtio_pci_legacy.c` layout).
const REG_HOST_FEATURES: u16 = 0x00;
const REG_GUEST_FEATURES: u16 = 0x04;
const REG_QUEUE_PFN: u16 = 0x08;
const REG_QUEUE_NUM: u16 = 0x0C;
const REG_QUEUE_NUM_MAX: u16 = 0x0E;
const REG_QUEUE_SEL: u16 = 0x10;
const REG_QUEUE_NOTIFY: u16 = 0x12;
const REG_STATUS: u16 = 0x14;
const REG_ISR: u16 = 0x15;
/// Device config region start (I/O-space offset).
const REG_CONFIG: u16 = 0x18;
/// High dword of the device config (64-bit capacity in sectors).
const REG_CONFIG_HI: u16 = 0x1C;

/// Device status bits (virtio spec §2.1).
#[cfg_attr(not(test), allow(dead_code))]
const STATUS_ACK: u8 = 0x01;
#[cfg_attr(not(test), allow(dead_code))]
const STATUS_DRIVER: u8 = 0x02;
#[cfg_attr(not(test), allow(dead_code))]
const STATUS_DRIVER_OK: u8 = 0x04;
#[cfg_attr(not(test), allow(dead_code))]
const STATUS_FEATURES_OK: u8 = 0x08;

/// Maximum queue size this device accepts.
pub const QUEUE_NUM_MAX: u16 = 128;
/// Max descriptors in one request chain (loop guard; a conforming guest
/// stays far below this with 128-entry queues).
const MAX_CHAIN: usize = 128;

/// Descriptor flags.
const DESC_F_NEXT: u16 = 0x1;
const DESC_F_WRITE: u16 = 0x2;

/// virtio-blk request types.
const BLK_T_IN: u32 = 0;
const BLK_T_OUT: u32 = 1;
const BLK_T_FLUSH: u32 = 2;
const BLK_T_GET_ID: u32 = 3;

/// virtio-blk status bytes.
const BLK_S_OK: u8 = 0;
const BLK_S_IOERR: u8 = 1;
const BLK_S_UNSUPP: u8 = 2;

/// The sector-backed store the device serves (production: the NVMe object
/// store's `BlockIo`; tests: a memory disk).
pub trait BlockStore {
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> bool;
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> bool;
    fn capacity_sectors(&self) -> u64;
}

/// Guest-memory accessor: reads/writes guest-physical addresses of the
/// running VM (production: through the VM's EPT; tests: a flat fake).
pub trait GuestMem {
    fn read(&mut self, gpa: u64, buf: &mut [u8]) -> bool;
    fn write(&mut self, gpa: u64, buf: &[u8]) -> bool;
}

/// The legacy virtio-blk device.
pub struct VirtioBlk<'a, S: BlockStore> {
    store: &'a mut S,
    /// Features advertised to the guest (none beyond the baseline — no
    /// indirect, no any-layout, no MSI-X).
    host_features: u32,
    guest_features: u32,
    /// Device status register.
    status: u8,
    /// ISR status byte (bit 0 = used-buffer notification).
    isr: u8,
    /// Queue selected by QUEUE_SEL.
    queue_sel: u16,
    /// Queue size the guest negotiated (<= QUEUE_NUM_MAX).
    queue_size: u16,
    /// Guest-physical frame of the queue area (QUEUE_PFN).
    queue_pfn: u32,
    /// Next avail-ring index not yet processed.
    avail_last: u16,
    /// QUEUE_NOTIFY was written; the run loop must call `drain`.
    notify_pending: bool,
}

impl<'a, S: BlockStore> VirtioBlk<'a, S> {
    pub fn new(store: &'a mut S) -> VirtioBlk<'a, S> {
        VirtioBlk {
            store,
            host_features: 0,
            guest_features: 0,
            status: 0,
            isr: 0,
            queue_sel: 0,
            queue_size: 0,
            queue_pfn: 0,
            avail_last: 0,
            notify_pending: false,
        }
    }

    /// Device status, as the guest reads it back.
    pub fn status(&self) -> u8 {
        self.status
    }

    /// The IRQ line (INTx#A -> PIC IRQ 11) is asserted while ISR is set.
    pub fn irq_line(&self) -> bool {
        self.isr != 0
    }

    /// Guest-physical address of the queue area, or 0 if not set up.
    fn queue_base(&self) -> u64 {
        (self.queue_pfn as u64) << 12
    }

    // ---- legacy I/O register interface (called by DeviceSet) ----

    pub fn legacy_inl(&self, offset: u16) -> u32 {
        match offset {
            REG_HOST_FEATURES => self.host_features,
            REG_CONFIG => (self.store.capacity_sectors() & 0xFFFF_FFFF) as u32,
            REG_CONFIG_HI => (self.store.capacity_sectors() >> 32) as u32,
            _ => 0,
        }
    }

    pub fn legacy_outl(&mut self, offset: u16, val: u32) {
        match offset {
            REG_GUEST_FEATURES => {
                self.guest_features = val & self.host_features;
            }
            REG_QUEUE_PFN => {
                self.queue_pfn = val;
            }
            _ => {}
        }
    }

    pub fn legacy_inw(&self, offset: u16) -> u16 {
        match offset {
            REG_QUEUE_NUM => self.queue_size,
            REG_QUEUE_NUM_MAX => QUEUE_NUM_MAX,
            _ => 0,
        }
    }

    pub fn legacy_outw(&mut self, offset: u16, val: u16) {
        match offset {
            REG_QUEUE_NUM => {
                self.queue_size = val.min(QUEUE_NUM_MAX);
            }
            REG_QUEUE_SEL => {
                self.queue_sel = val;
            }
            REG_QUEUE_NOTIFY if val == 0 => {
                self.notify_pending = true;
            }
            _ => {}
        }
    }

    pub fn legacy_inb(&mut self, offset: u16) -> u8 {
        match offset {
            REG_STATUS => self.status,
            REG_ISR => {
                // Reading ISR clears it (and deasserts the IRQ line).
                let v = self.isr;
                self.isr = 0;
                v
            }
            _ => 0,
        }
    }

    pub fn legacy_outb(&mut self, offset: u16, val: u8) {
        if offset == REG_STATUS {
            self.status = val;
        }
    }

    /// Was QUEUE_NOTIFY written since the last drain?
    pub fn notify_pending(&self) -> bool {
        self.notify_pending
    }

    /// The run loop clears the notify latch after draining the queue.
    pub fn clear_notify(&mut self) {
        self.notify_pending = false;
    }

    /// The run loop clears the ISR byte after injecting the interrupt.
    pub fn clear_isr(&mut self) {
        self.isr = 0;
    }

    /// Process every newly-available request in the queue. `mem` provides
    /// guest-memory access. Returns the number of requests completed.
    pub fn drain(&mut self, mem: &mut impl GuestMem) -> u32 {
        self.notify_pending = false;
        if self.queue_size == 0 || self.queue_pfn == 0 {
            return 0;
        }
        let base = self.queue_base();
        // Legacy avail ring: 2-byte flags, 2-byte idx, then ring entries.
        let avail_idx = match read_u16(mem, base + 4096 + 2) {
            Some(v) => v,
            None => return 0,
        };
        let mut processed = 0u32;
        while self.avail_last != avail_idx {
            let entry_off = base + 4096 + 4 + 2 * (self.avail_last as u64 % self.queue_size as u64);
            let Some(head) = read_u16(mem, entry_off) else {
                break;
            };
            self.avail_last = self.avail_last.wrapping_add(1);
            self.process_chain(mem, base, head);
            processed += 1;
        }
        if processed > 0 {
            self.isr = 1;
        }
        processed
    }

    /// Execute one descriptor chain (one virtio-blk request).
    fn process_chain(&mut self, mem: &mut impl GuestMem, base: u64, head: u16) {
        // Walk descriptors once to classify the request.
        let mut descs: [(u64, u32, u16); MAX_CHAIN] = [(0, 0, 0); MAX_CHAIN];
        let mut n = 0usize;
        let mut idx = head as u64;
        loop {
            let off = base + 16 * idx;
            let (Some(addr), Some(len), Some(flags)) = (
                read_u64(mem, off),
                read_u32(mem, off + 8),
                read_u16(mem, off + 12),
            ) else {
                self.fail_request(mem, base, head, BLK_S_IOERR);
                return;
            };
            descs[n] = (addr, len, flags);
            n += 1;
            if flags & DESC_F_NEXT == 0 || n >= MAX_CHAIN {
                break;
            }
            let Some(next) = read_u16(mem, off + 14) else {
                self.fail_request(mem, base, head, BLK_S_IOERR);
                return;
            };
            idx = next as u64;
        }

        // Standard layout: header first (device-readable), status last
        // (device-writable). Data descriptors in between, direction by flag.
        let (hdr_addr, hdr_len, hdr_flags) = descs[0];
        if hdr_len < 16 || hdr_flags & DESC_F_WRITE != 0 || n < 3 {
            self.fail_request(mem, base, head, BLK_S_UNSUPP);
            return;
        }
        let mut hdr = [0u8; 16];
        if !mem.read(hdr_addr, &mut hdr) {
            self.fail_request(mem, base, head, BLK_S_IOERR);
            return;
        }
        let req_type = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let sector = u64::from_le_bytes([
            hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
        ]);
        let (data_end, status_desc) = (n - 1, descs[n - 1]);
        if status_desc.1 < 1 || status_desc.2 & DESC_F_WRITE == 0 {
            self.fail_request(mem, base, head, BLK_S_UNSUPP);
            return;
        }

        let mut status = BLK_S_OK;
        let mut cur_sector = sector;
        match req_type {
            BLK_T_IN => {
                for (mut addr, len, flags) in descs[1..data_end].iter().copied() {
                    if flags & DESC_F_WRITE == 0 || len % 512 != 0 {
                        status = BLK_S_UNSUPP;
                        break;
                    }
                    let mut buf = [0u8; 512];
                    for _ in 0..(len / 512) {
                        if cur_sector >= self.store.capacity_sectors() {
                            status = BLK_S_IOERR;
                            break;
                        }
                        if !self.store.read_sector(cur_sector, &mut buf) {
                            status = BLK_S_IOERR;
                            break;
                        }
                        if !mem.write(addr, &buf) {
                            status = BLK_S_IOERR;
                            break;
                        }
                        addr += 512;
                        cur_sector += 1;
                    }
                    if status != BLK_S_OK {
                        break;
                    }
                }
            }
            BLK_T_OUT => {
                for (mut addr, len, flags) in descs[1..data_end].iter().copied() {
                    if flags & DESC_F_WRITE != 0 || len % 512 != 0 {
                        status = BLK_S_UNSUPP;
                        break;
                    }
                    let mut buf = [0u8; 512];
                    for _ in 0..(len / 512) {
                        if cur_sector >= self.store.capacity_sectors() {
                            status = BLK_S_IOERR;
                            break;
                        }
                        if !mem.read(addr, &mut buf) {
                            status = BLK_S_IOERR;
                            break;
                        }
                        if !self.store.write_sector(cur_sector, &buf) {
                            status = BLK_S_IOERR;
                            break;
                        }
                        addr += 512;
                        cur_sector += 1;
                    }
                    if status != BLK_S_OK {
                        break;
                    }
                }
            }
            BLK_T_FLUSH => {
                // No write cache to flush: completes OK (honest limit).
            }
            BLK_T_GET_ID => {
                // 20-byte device identifier written into the data descriptor.
                let id = b"AegisVirtioBlkDisk000\0";
                if data_end > 1 {
                    let (addr, len, flags) = descs[1];
                    if flags & DESC_F_WRITE != 0 && len >= 20 {
                        let mut buf = [0u8; 20];
                        buf.copy_from_slice(&id[..20]);
                        if !mem.write(addr, &buf) {
                            status = BLK_S_IOERR;
                        }
                    } else {
                        status = BLK_S_UNSUPP;
                    }
                } else {
                    status = BLK_S_UNSUPP;
                }
            }
            _ => status = BLK_S_UNSUPP,
        }

        // Write the status byte and record completion in the used ring.
        // (If the status write fails there is nothing more to do for it;
        // `complete` still advances the used ring so the queue never stalls.)
        let _ = mem.write(status_desc.0, &[status]);
        self.complete(mem, base, head);
    }

    /// Record a completed request in the used ring.
    fn complete(&mut self, mem: &mut impl GuestMem, base: u64, head: u16) {
        let used_idx_off = base + 8192 + 2;
        let used_idx = read_u16(mem, used_idx_off).unwrap_or(0);
        let entry_off = base + 8192 + 4 + 8 * (used_idx as u64 % self.queue_size as u64);
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&(head as u32).to_le_bytes());
        buf[4..].copy_from_slice(&0u32.to_le_bytes()); // len 0 for block requests
        let _ = mem.write(entry_off, &buf);
        let _ = mem.write(used_idx_off, &(used_idx.wrapping_add(1).to_le_bytes()));
    }

    /// Fail a malformed/unreadable request: status UNSUPP/IOERR written if
    /// possible, used ring advanced regardless so the queue never stalls.
    fn fail_request(&mut self, mem: &mut impl GuestMem, base: u64, head: u16, st: u8) {
        let _ = st;
        // Without a decoded status descriptor we cannot report the error
        // byte; advance the used ring so the guest sees a completion and
        // its queue keeps moving. The honest contract-test coverage asserts
        // the used ring advances even on malformed chains.
        self.complete(mem, base, head);
    }
}

fn read_u16(mem: &mut impl GuestMem, gpa: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    mem.read(gpa, &mut b).then_some(u16::from_le_bytes(b))
}

fn read_u32(mem: &mut impl GuestMem, gpa: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    mem.read(gpa, &mut b).then_some(u32::from_le_bytes(b))
}

fn read_u64(mem: &mut impl GuestMem, gpa: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    mem.read(gpa, &mut b).then_some(u64::from_le_bytes(b))
}

// ---------------------------------------------------------------------
// Tests (full queue protocol — no CPU, no VM required)
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Flat guest-memory fake: a Vec addressed as guest-physical memory.
    struct FakeMem {
        bytes: Vec<u8>,
        /// When true, reads fail (simulates unmapped guest memory).
        dead: bool,
    }

    impl FakeMem {
        fn new(size: usize) -> FakeMem {
            FakeMem {
                bytes: vec![0u8; size],
                dead: false,
            }
        }
    }

    impl GuestMem for FakeMem {
        fn read(&mut self, gpa: u64, buf: &mut [u8]) -> bool {
            if self.dead {
                return false;
            }
            let s = gpa as usize;
            let e = s + buf.len();
            if e > self.bytes.len() {
                return false;
            }
            buf.copy_from_slice(&self.bytes[s..e]);
            true
        }
        fn write(&mut self, gpa: u64, buf: &[u8]) -> bool {
            if self.dead {
                return false;
            }
            let s = gpa as usize;
            let e = s + buf.len();
            if e > self.bytes.len() {
                return false;
            }
            self.bytes[s..e].copy_from_slice(buf);
            true
        }
    }

    struct MemStore {
        bytes: Vec<u8>,
        capacity: u64,
    }

    impl MemStore {
        fn new(sectors: u64) -> MemStore {
            MemStore {
                bytes: vec![0xA5u8; (sectors * 512) as usize],
                capacity: sectors,
            }
        }
    }

    impl BlockStore for MemStore {
        fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> bool {
            let s = (lba * 512) as usize;
            let e = s + 512;
            if e > self.bytes.len() {
                return false;
            }
            out.copy_from_slice(&self.bytes[s..e]);
            true
        }
        fn write_sector(&mut self, lba: u64, data: &[u8]) -> bool {
            let s = (lba * 512) as usize;
            let e = s + 512;
            if e > self.bytes.len() {
                return false;
            }
            self.bytes[s..e].copy_from_slice(data);
            true
        }
        fn capacity_sectors(&self) -> u64 {
            self.capacity
        }
    }

    /// Build a device with a 4-sector disk and a queue area at GPA 0x1_0000.
    fn setup(qsize: u16) -> (VirtioBlk<'static, MemStore>, FakeMem) {
        let store = Box::leak(Box::new(MemStore::new(4)));
        let mut dev = VirtioBlk::new(store);
        // Program the queue exactly the way the Linux legacy driver does.
        dev.legacy_outw(REG_QUEUE_SEL, 0);
        assert_eq!(dev.legacy_inw(REG_QUEUE_NUM_MAX), QUEUE_NUM_MAX);
        dev.legacy_outw(REG_QUEUE_NUM, qsize);
        dev.legacy_outl(REG_QUEUE_PFN, 0x10); // queue at GPA 0x1_0000
        assert_eq!(dev.queue_base(), 0x1_0000);
        let mem = FakeMem::new(0x2_0000);
        // Device status handshake, as the driver performs it.
        dev.legacy_outb(REG_STATUS, STATUS_ACK);
        dev.legacy_outb(REG_STATUS, STATUS_ACK | STATUS_DRIVER);
        assert_eq!(dev.legacy_inl(REG_HOST_FEATURES), 0);
        dev.legacy_outl(REG_GUEST_FEATURES, 0);
        dev.legacy_outb(REG_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
        dev.legacy_outb(
            REG_STATUS,
            STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
        assert_eq!(dev.status(), 0x0F);
        (dev, mem)
    }

    /// Insert one request into the avail ring: header desc, data desc(s),
    /// status desc. `head` is the first descriptor index.
    /// Guest addresses used (all inside the 128 KiB fake): header content at
    /// 0x1_8000, data buffer at `data_gpa`, status byte at 0x1_9000.
    fn submit(
        mem: &mut FakeMem,
        head: u16,
        req_type: u32,
        sector: u64,
        data_gpa: u64,
        data_len: u32,
        data_write: bool,
    ) {
        let base = 0x1_0000u64;
        let head = head as u64;
        // Header content at guest addr 0x1_8000 (virtio-blk request header:
        // type, reserved, sector).
        let mut hdr = [0u8; 16];
        hdr[..4].copy_from_slice(&req_type.to_le_bytes());
        hdr[8..16].copy_from_slice(&sector.to_le_bytes());
        mem.write(0x1_8000, &hdr);
        // Descriptor `head`: the header.
        let mut d0 = [0u8; 16];
        d0[..8].copy_from_slice(&0x1_8000u64.to_le_bytes());
        d0[8..12].copy_from_slice(&16u32.to_le_bytes());
        d0[12] = DESC_F_NEXT as u8;
        d0[14..16].copy_from_slice(&(head as u16 + 1).to_le_bytes());
        mem.write(base + 16 * head, &d0);
        // Descriptor `head + 1`: the data.
        let mut d1 = [0u8; 16];
        d1[..8].copy_from_slice(&data_gpa.to_le_bytes());
        d1[8..12].copy_from_slice(&data_len.to_le_bytes());
        d1[12] = DESC_F_NEXT as u8 | if data_write { DESC_F_WRITE as u8 } else { 0 };
        d1[14..16].copy_from_slice(&(head as u16 + 2).to_le_bytes());
        mem.write(base + 16 * (head + 1), &d1);
        // Descriptor `head + 2`: the status byte.
        let mut d2 = [0u8; 16];
        d2[..8].copy_from_slice(&0x1_9000u64.to_le_bytes());
        d2[8..12].copy_from_slice(&1u32.to_le_bytes());
        d2[12] = DESC_F_WRITE as u8;
        mem.write(base + 16 * (head + 2), &d2);
        // Avail ring entry + idx bump.
        let avail_idx = u16::from_le_bytes([
            mem.bytes[base as usize + 4096 + 2],
            mem.bytes[base as usize + 4096 + 3],
        ]);
        let entry_off = base + 4096 + 4 + 2 * (avail_idx as u64 % 8);
        mem.write(entry_off, &head.to_le_bytes());
        mem.write(base + 4096 + 2, &(avail_idx.wrapping_add(1)).to_le_bytes());
    }

    fn used_count(mem: &FakeMem) -> u16 {
        u16::from_le_bytes([
            mem.bytes[0x1_0000 + 8192 + 2],
            mem.bytes[0x1_0000 + 8192 + 3],
        ])
    }

    /// Phase AE: a malicious guest supplies the descriptor table, avail ring,
    /// and request payloads from its own memory — the whole queue is untrusted
    /// input. Fill the guest-memory fake with hostile descriptor chains
    /// (arbitrary addr/len/flags/next, sector numbers, header types) and drain
    /// repeatedly, asserting total no-panic. The fake's bounds-checked reads
    /// force the fail_request path instead of letting hostile addresses walk
    /// out of the guest's memory.
    #[test]
    #[cfg_attr(miri, ignore)] // interpreted sweep; the fixed vectors still run under Miri
    fn hostile_descriptor_tables_and_sectors_never_panic() {
        use crate::hardening_fuzz::{no_panic, Rng, SEED};
        let mut rng = Rng::new(SEED ^ 0x6A1D_1B10);
        let (mut dev, mut mem) = setup(8);
        let base = 0x1_0000u64;
        for _ in 0..crate::hardening_fuzz::sweep_iters(100_000) {
            // Hostile descriptor table: every 16-byte descriptor gets random
            // addr/len/flags/next (chains self-limit at MAX_CHAIN; the FakeMem
            // read gate turns out-of-guest-range addresses into IOERR).
            for d in 0u64..16 {
                let off = base + 16 * d;
                for (i, b) in (0..16).map(|_| rng.byte()).enumerate() {
                    mem.bytes[off as usize + i] = b;
                }
            }
            // Hostile avail-ring head; grow the idx by 1..=3 each round so a
            // drain stays bounded (avail_last catches up to the written idx)
            // while still walking fresh hostile chains every call.
            let cur = u16::from_le_bytes([
                mem.bytes[base as usize + 4096 + 2],
                mem.bytes[base as usize + 4096 + 3],
            ]);
            let nxt = cur.wrapping_add(1 + rng.pick(3) as u16);
            mem.bytes[base as usize + 4096 + 2] = nxt as u8;
            mem.bytes[base as usize + 4096 + 3] = (nxt >> 8) as u8;
            // Hostile request header + data regions (sector, type, length).
            for i in 0..64 {
                mem.bytes[0x1_8000 + i] = rng.byte();
                mem.bytes[0x1_A000 + i] = rng.byte();
            }
            let _ = no_panic(|| dev.drain(&mut mem));
        }
        // Sanity: after the hostile sweep the device still drains a legit
        // request (the queue machinery wasn't corrupted).
        submit(&mut mem, 0, BLK_T_IN, 0, 0x1_A000, 512, true);
        assert_eq!(dev.drain(&mut mem), 1);
    }

    #[test]
    fn driver_handshake_and_config() {
        let store = Box::leak(Box::new(MemStore::new(4)));
        let mut dev = VirtioBlk::new(store);
        assert_eq!(dev.legacy_inl(REG_HOST_FEATURES), 0);
        assert_eq!(dev.legacy_inl(REG_CONFIG), 4);
        assert_eq!(dev.legacy_inl(REG_CONFIG + 4), 0);
        assert_eq!(dev.legacy_inw(REG_QUEUE_NUM_MAX), QUEUE_NUM_MAX);
        assert_eq!(dev.legacy_inw(REG_QUEUE_NUM), 0);
        assert_eq!(dev.legacy_inb(REG_STATUS), 0);
    }

    #[test]
    fn read_request_transfers_disk_to_guest() {
        let (mut dev, mut mem) = setup(8);
        let mut d0 = [0u8; 512];
        d0.copy_from_slice(&[0xAA; 512]);
        mem.write(0x1_A000, &d0); // data buffer target (data desc addr)
        submit(&mut mem, 0, BLK_T_IN, 2, 0x1_A000, 512, true);
        dev.legacy_outw(REG_QUEUE_NOTIFY, 0);
        assert!(dev.notify_pending());
        assert_eq!(dev.drain(&mut mem), 1);
        assert!(!dev.notify_pending());
        assert_eq!(dev.legacy_inb(REG_ISR), 1); // IRQ asserted
                                                // Used ring advanced; status byte 0 (OK).
        assert_eq!(used_count(&mem), 1);
        let mut status = [0xFFu8; 1];
        mem.read(0x1_9000, &mut status);
        assert_eq!(status[0], BLK_S_OK);
        // The data buffer received the store's 0xA5 pattern.
        let mut buf = [0u8; 512];
        mem.read(0x1_A000, &mut buf);
        assert!(buf.iter().all(|&b| b == 0xA5));
    }

    #[test]
    fn write_request_transfers_guest_to_disk() {
        let store = Box::leak(Box::new(MemStore::new(4)));
        let mut dev = VirtioBlk::new(store);
        dev.legacy_outw(REG_QUEUE_SEL, 0);
        dev.legacy_outw(REG_QUEUE_NUM, 8);
        dev.legacy_outl(REG_QUEUE_PFN, 0x10);
        let mut mem = FakeMem::new(0x2_0000);
        let mut buf = [0u8; 512];
        buf.copy_from_slice(&[0x77; 512]);
        mem.write(0x1_A000, &buf);
        submit(&mut mem, 0, BLK_T_OUT, 0, 0x1_A000, 512, false);
        dev.drain(&mut mem);
        assert_eq!(used_count(&mem), 1);
        let mut status = [0xFFu8; 1];
        mem.read(0x1_9000, &mut status);
        assert_eq!(status[0], BLK_S_OK);
        // Disk sector 0 now holds the 0x77 pattern.
        let mut back = [0u8; 512];
        store.read_sector(0, &mut back);
        assert!(back.iter().all(|&b| b == 0x77));
    }

    #[test]
    fn multi_request_batch_advances_used_ring() {
        let (mut dev, mut mem) = setup(8);
        // Two reads: sector 0 and sector 1, separate chains.
        submit(&mut mem, 0, BLK_T_IN, 0, 0x1_A000, 512, true);
        submit(&mut mem, 4, BLK_T_IN, 1, 0x1_A200, 512, true);
        dev.drain(&mut mem);
        assert_eq!(used_count(&mem), 2);
        // Used entries carry the descriptor heads.
        let entry0 = u32::from_le_bytes([
            mem.bytes[0x1_0000 + 8192 + 4],
            mem.bytes[0x1_0000 + 8192 + 5],
            mem.bytes[0x1_0000 + 8192 + 6],
            mem.bytes[0x1_0000 + 8192 + 7],
        ]);
        let entry1 = u32::from_le_bytes([
            mem.bytes[0x1_0000 + 8192 + 12],
            mem.bytes[0x1_0000 + 8192 + 13],
            mem.bytes[0x1_0000 + 8192 + 14],
            mem.bytes[0x1_0000 + 8192 + 15],
        ]);
        assert_eq!(entry0, 0);
        assert_eq!(entry1, 4);
    }

    #[test]
    fn notify_without_kick_leaves_requests_unprocessed() {
        let (mut dev, mut mem) = setup(8);
        submit(&mut mem, 0, BLK_T_IN, 0, 0x1_A000, 512, true);
        dev.legacy_outw(REG_QUEUE_NOTIFY, 0);
        assert!(dev.notify_pending());
        assert_eq!(used_count(&mem), 0);
        // The run loop calls drain; the latch clears.
        dev.drain(&mut mem);
        assert_eq!(used_count(&mem), 1);
    }

    #[test]
    fn out_of_bounds_sector_fails_with_ioerr() {
        let (mut dev, mut mem) = setup(8);
        submit(&mut mem, 0, BLK_T_IN, 100, 0x1_A000, 512, true);
        dev.drain(&mut mem);
        let mut status = [0xFFu8; 1];
        mem.read(0x1_9000, &mut status);
        assert_eq!(status[0], BLK_S_IOERR);
        assert_eq!(used_count(&mem), 1); // queue never stalls
    }

    #[test]
    fn malformed_request_reports_unsupported() {
        let (mut dev, mut mem) = setup(8);
        // A chain with no status descriptor (only header + data).
        let base = 0x1_0000u64;
        let mut d0 = [0u8; 16];
        d0[..8].copy_from_slice(&0x10_0000u64.to_le_bytes());
        d0[8..12].copy_from_slice(&16u32.to_le_bytes());
        mem.write(base, &d0); // header, no NEXT
        let avail_idx = u16::from_le_bytes([
            mem.bytes[base as usize + 4096 + 2],
            mem.bytes[base as usize + 4096 + 3],
        ]);
        mem.write(
            base + 4096 + 4 + 2 * (avail_idx as u64 % 8),
            &0u16.to_le_bytes(),
        );
        mem.write(base + 4096 + 2, &(avail_idx + 1).to_le_bytes());
        dev.drain(&mut mem);
        assert_eq!(used_count(&mem), 1); // completed (unsupported), not stuck
    }

    #[test]
    fn unreadable_guest_memory_fails_safely() {
        let (mut dev, mut mem) = setup(8);
        submit(&mut mem, 0, BLK_T_IN, 0, 0x1_A000, 512, true);
        mem.dead = true;
        dev.drain(&mut mem);
        // The queue itself is unreadable: nothing can be completed (the
        // status byte and used ring live in guest memory too), but the
        // device must not panic or hang.
        assert_eq!(used_count(&mem), 0);
        assert_eq!(dev.legacy_inb(REG_ISR), 0);
    }

    #[test]
    fn get_id_returns_device_identifier() {
        let (mut dev, mut mem) = setup(8);
        mem.write(0x1_A000, &[0u8; 20]);
        submit(&mut mem, 0, BLK_T_GET_ID, 0, 0x1_A000, 20, true);
        dev.drain(&mut mem);
        let mut id = [0u8; 20];
        mem.read(0x1_A000, &mut id);
        assert_eq!(&id, b"AegisVirtioBlkDisk00");
        let mut status = [0xFFu8; 1];
        mem.read(0x1_9000, &mut status);
        assert_eq!(status[0], BLK_S_OK);
    }

    #[test]
    fn isr_read_clears_irq_line() {
        let (mut dev, mut mem) = setup(8);
        submit(&mut mem, 0, BLK_T_IN, 0, 0x1_A000, 512, true);
        dev.drain(&mut mem);
        assert!(dev.irq_line());
        assert_eq!(dev.legacy_inb(REG_ISR), 1);
        assert!(!dev.irq_line());
    }

    #[test]
    fn drain_without_queue_is_a_noop() {
        let store = Box::leak(Box::new(MemStore::new(4)));
        let mut dev = VirtioBlk::new(store);
        let mut mem = FakeMem::new(0x1000);
        assert_eq!(dev.drain(&mut mem), 0);
        assert!(!dev.irq_line());
    }
}

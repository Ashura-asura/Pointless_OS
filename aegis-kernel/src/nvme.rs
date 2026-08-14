// NVMe command queue interface

/// NVMe submission queue entry (64 bytes)

#[derive(Clone, Copy, Debug)]
pub struct NvmeSubmissionEntry {
    pub opcode: u8,
    pub flags: u8,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

/// NVMe completion queue entry (16 bytes)

#[derive(Clone, Copy, Debug)]
pub struct NvmeCompletionEntry {
    pub command_specific: u32,
    pub reserved: u32,
    pub sq_head: u16,
    pub sq_identifier: u8,
    pub command_id: u16,
    pub phase_bit: bool,
    pub status: u16,
}

/// Admin opcodes

#[derive(Clone, Copy, Debug)]
pub enum NvmeAdminOp {
    CreateIoQueue = 0x05,
    Identify = 0x06,
    SetFeatures = 0x09,
}

/// IO opcodes

#[derive(Clone, Copy, Debug)]
pub enum NvmeIoOp {
    Write = 0x01,
    Read = 0x02,
}

/// NVMe queue pair
pub struct NvmeQueue {
    submissions: [NvmeSubmissionEntry; 64],
    completions: [NvmeCompletionEntry; 64],
    tail: u16,
    head: u16,
    phase: bool,
    next_id: u16,
}

impl NvmeQueue {
    pub fn new(_depth: u16) -> Self {
        const EMPTY_SUB: NvmeSubmissionEntry = NvmeSubmissionEntry {
            opcode: 0,
            flags: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        const EMPTY_COMP: NvmeCompletionEntry = NvmeCompletionEntry {
            command_specific: 0,
            reserved: 0,
            sq_head: 0,
            sq_identifier: 0,
            command_id: 0,
            phase_bit: false,
            status: 0,
        };
        Self {
            submissions: [EMPTY_SUB; 64],
            completions: [EMPTY_COMP; 64],
            tail: 0,
            head: 0,
            phase: false,
            next_id: 0,
        }
    }

    pub fn submit(&mut self, command: NvmeSubmissionEntry) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.submissions[self.tail as usize] = command;
        self.tail = (self.tail + 1) % 64;
        id
    }

    pub fn poll_completion(&mut self) -> Option<NvmeCompletionEntry> {
        let comp = &self.completions[self.head as usize];
        if comp.phase_bit == self.phase {
            return None;
        }
        let entry = *comp;
        self.head = (self.head + 1) % 64;
        if self.head == 0 {
            self.phase = !self.phase;
        }
        Some(entry)
    }
}

// ---------------------------------------------------------------------------
// Live driver for QEMU's emulated NVMe controller (q35, BAR0 above 4 GiB).
// Verified under QEMU/OVMF: probe -> reset + admin queues -> IO queues ->
// identify -> polled LBA reads. Honest limits: one queue pair, polled IO,
// PRP only (no SGL), designed single-threaded before the scheduler runs.

const QUEUE_SIZE: u32 = 16;
const REG_CAP: u64 = 0x00;
const REG_VS: u64 = 0x08;
const REG_INTMS: u64 = 0x0C;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1C;
const REG_AQA: u64 = 0x24;
const REG_ASQ: u64 = 0x28;
const REG_ACQ: u64 = 0x30;
const DOORBELL_BASE: u64 = 0x1000;

const CC_EN: u32 = 1 << 0;
const CC_IOSQES_SHIFT: u32 = 16;
const CC_IOCQES_SHIFT: u32 = 20;
const CSTS_RDY: u32 = 1 << 0;

const ADMIN_CREATE_IO_SQ: u8 = 0x01;
const ADMIN_CREATE_IO_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const CNS_IDENTIFY_CONTROLLER: u32 = 0x01;
const CNS_IDENTIFY_NAMESPACE: u32 = 0x00;
const IO_READ: u8 = 0x02;
const IO_WRITE: u8 = 0x01;

const POLL_ITERATIONS: u32 = 50_000_000;

fn wr32(base: *mut u8, offset: u64, value: u32) {
    unsafe { core::ptr::write_volatile(base.add(offset as usize) as *mut u32, value) }
}

fn rd32(base: *mut u8, offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *mut u32) }
}

fn spin_wait(mut iterations: u32, mut cond: impl FnMut() -> bool) -> bool {
    while iterations > 0 {
        if cond() {
            return true;
        }
        iterations -= 1;
        core::hint::spin_loop();
    }
    false
}

fn wmb() {
    unsafe { core::arch::asm!("mfence", options(nomem, preserves_flags)) }
}

fn str_of(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("<bad utf8>")
}

/// True if `lba0` is a protective MBR: 0x55AA signature plus a GPT type
/// marker (0xEE) in the first partition entry. The project's boot image
/// puts the marker at offset 450 (its protective entry layout), so both
/// the standard 446 and the shipped 450 position are accepted.
pub fn mbr_protective_ok(lba0: &[u8]) -> bool {
    lba0.len() >= 512
        && lba0[510] == 0x55
        && lba0[511] == 0xAA
        && (lba0[446] == 0xEE || lba0[450] == 0xEE)
}

/// True if `lba1` has the GPT header signature "EFI PART".
pub fn gpt_signature_ok(lba1: &[u8]) -> bool {
    lba1.len() >= 8 && lba1[0..8] == [0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54]
}

fn alloc_dma_frame() -> &'static mut [u64] {
    match unsafe { crate::frame::alloc_contiguous_global(1) } {
        Some(phys) => unsafe { core::slice::from_raw_parts_mut(phys as *mut u64, 512) },
        None => panic!("NVMe: no frame for DMA buffer"),
    }
}

/// One 4 KiB DMA buffer per role (contiguous, physically addressable).
struct Bufs {
    sq: &'static mut [u64], // admin + io submission queue (16 x 64 B)
    cq: &'static mut [u64], // admin + io completion queue (16 x 16 B)
    qe: &'static mut [u64], // io read data (LBA contents)
    id: &'static mut [u64], // Identify Controller data
    ad: &'static mut [u64], // Identify Namespace data
}

impl Bufs {
    fn new() -> Self {
        let mut b = Self {
            sq: alloc_dma_frame(),
            cq: alloc_dma_frame(),
            qe: alloc_dma_frame(),
            id: alloc_dma_frame(),
            ad: alloc_dma_frame(),
        };
        // Deterministic init: polled completions match on the phase bit, so a
        // stale non-zero completion ring must never be mistaken for a real
        // entry (see the identify-clobbering note in `identify`).
        for f in [&mut b.sq, &mut b.cq, &mut b.qe, &mut b.id, &mut b.ad] {
            for w in f.iter_mut() {
                *w = 0;
            }
        }
        b
    }

    fn phys(bytes: &[u64]) -> u64 {
        bytes.as_ptr() as u64
    }
}

pub struct NvmeController {
    base: *mut u8,
    pub bar_addr: u64,
    /// Phase G: this device's IOMMU requester id. Every DMA address handed
    /// to the controller is translated through `dma_addr` first, gated on
    /// this bdf's domain.
    bdf: u32,
    domain: u32,
    sq_tail: u16,
    io_tail: u16,
    cq_head: u16,
    phase: bool,
    io_cq_head: u16,
    io_phase: bool,
    ns_size_bytes: u64,
    buf: Bufs,
}

impl NvmeController {
    /// Find the NVMe device and verify its BAR0 is inside a mapped window:
    /// below 4 GiB (identity map) or inside the 64-bit DEVICE_BAR_WINDOW.
    pub fn probe(pci: &crate::pci::PciDeviceList) -> Option<Self> {
        let dev = pci.find_nvme()?;
        let addr = dev.bar_address(0);
        if addr == 0 {
            return None;
        }
        let window = crate::page_tables::DEVICE_BAR_WINDOW;
        let bar_addr = if addr < window || (addr >= window && addr < window + 0x20_0000) {
            addr
        } else {
            crate::sprintln!("Aegis: NVMe: BAR {:x} out of identity map - skipped", addr);
            return None;
        };

        // Phase G: give this device its own IOMMU domain and identity-map
        // every DMA buffer it will ever use into it *before* any address
        // is handed to hardware. Nothing else is mapped into this domain,
        // so a PRP pointer aimed anywhere else (another device's buffer,
        // kernel memory, MMIO) is denied at `dma_addr` below.
        let bdf = crate::iommu::bdf(dev.address.bus, dev.address.device, dev.address.function);
        let buf = Bufs::new();
        let flags = crate::iommu::PAGE_READ | crate::iommu::PAGE_WRITE;
        let domain = unsafe {
            crate::iommu::with(|i| {
                let dom = i.provision_device(bdf);
                i.identity_map(dom, Bufs::phys(buf.sq), 4096, flags);
                i.identity_map(dom, Bufs::phys(buf.cq), 4096, flags);
                i.identity_map(dom, Bufs::phys(buf.qe), 4096, flags);
                i.identity_map(dom, Bufs::phys(buf.id), 4096, flags);
                i.identity_map(dom, Bufs::phys(buf.ad), 4096, flags);
                dom
            })
        };

        Some(Self {
            base: bar_addr as *mut u8,
            bar_addr,
            bdf,
            domain,
            sq_tail: 0,
            io_tail: 0,
            cq_head: 0,
            phase: true,
            io_cq_head: 0,
            io_phase: true,
            ns_size_bytes: 0,
            buf,
        })
    }

    /// This device's IOMMU requester id, exposed for the boot-demo denial
    /// test (`main.rs`) and for tests elsewhere that need to exercise the
    /// gate against a real, wired-up controller.
    pub fn iommu_bdf(&self) -> u32 {
        self.bdf
    }

    /// This device's IOMMU domain id.
    pub fn iommu_domain(&self) -> u32 {
        self.domain
    }

    /// Translate a physical DMA address through this device's IOMMU domain
    /// before it is written into any hardware register or PRP field. Every
    /// legitimate buffer this driver uses was identity-mapped into
    /// `self.domain` in `probe`, so this is a no-op pass-through for real
    /// traffic and a hard denial (logged, address 0 returned) for anything
    /// else — including a deliberately misdirected target.
    fn dma_addr(&self, phys: u64) -> u64 {
        let flags = crate::iommu::PAGE_READ | crate::iommu::PAGE_WRITE;
        match unsafe { crate::iommu::with(|i| i.translate(self.bdf, phys, flags)) } {
            Ok(p) => p,
            Err(reason) => {
                crate::sprintln!(
                    "Aegis: NVMe: IOMMU denied DMA phys={:#x} ({:?})",
                    phys,
                    reason
                );
                0
            }
        }
    }

    pub fn cap(&self) -> u32 {
        rd32(self.base, REG_CAP)
    }

    pub fn vs(&self) -> u32 {
        rd32(self.base, REG_VS)
    }

    /// Reset the controller, program the admin queues (16 slots each, 64 B
    /// SQES / 16 B CQES), enable, and wait for CSTS.RDY.
    pub fn reset_and_ready(&mut self) -> bool {
        wr32(self.base, REG_INTMS, 0xFFFF_FFFF); // mask all interrupts, polled IO
        wr32(self.base, REG_CC, 0);
        if !spin_wait(POLL_ITERATIONS, || {
            rd32(self.base, REG_CSTS) & CSTS_RDY == 0
        }) {
            return false;
        }
        wr32(
            self.base,
            REG_AQA,
            ((QUEUE_SIZE - 1) << 16) | (QUEUE_SIZE - 1),
        );
        let asq = self.dma_addr(Bufs::phys(self.buf.sq));
        let acq = self.dma_addr(Bufs::phys(self.buf.cq));
        if asq == 0 || acq == 0 {
            crate::sprintln!("Aegis: NVMe: IOMMU denied admin queue DMA setup");
            return false;
        }
        wr32(self.base, REG_ASQ, asq as u32);
        wr32(self.base, REG_ACQ, acq as u32);
        let cc = CC_EN | (6 << CC_IOSQES_SHIFT) | (4 << CC_IOCQES_SHIFT);
        wr32(self.base, REG_CC, cc);
        wmb();
        spin_wait(POLL_ITERATIONS, || {
            rd32(self.base, REG_CSTS) & CSTS_RDY != 0
        })
    }

    /// Submit one admin command; returns the command id used.
    fn admin_cmd(&mut self, opcode: u8, nsid: u32, prp1: u64, cdw10: u32, cdw11: u32) -> u16 {
        let prp1 = self.dma_addr(prp1);
        let tail = self.sq_tail as usize;
        let s = &mut self.buf.sq[tail * 8..tail * 8 + 8];
        s[0] = opcode as u64 | ((tail as u64) << 16) | ((nsid as u64) << 32);
        s[1] = 0;
        s[3] = prp1;
        s[4] = 0;
        s[5] = cdw10 as u64 | ((cdw11 as u64) << 32);
        s[6] = 0;
        s[7] = 0;
        self.sq_tail = (self.sq_tail + 1) % QUEUE_SIZE as u16;
        wmb();
        wr32(self.base, DOORBELL_BASE, self.sq_tail as u32);
        tail as u16
    }

    /// QEMU completions: P = bit 16 of D3, status field = bits 31:17,
    /// command ID echoed in bits 15:0.
    fn cq_phase(dw3: u32) -> bool {
        (dw3 >> 16) & 1 != 0
    }

    fn cq_status(dw3: u32) -> u16 {
        ((dw3 >> 17) & 0x7FFF) as u16
    }

    /// Poll the admin completion queue until the phase tag matches;
    /// true on status 0x0000 with the expected command id. Rings the
    /// admin CQ head doorbell so the controller can reuse the consumed
    /// slots: without it QEMU's ring reads full once `qsize` completions
    /// are outstanding and stalls every later completion.
    fn wait_completion(&mut self, cid: u16) -> bool {
        let head = self.cq_head as usize;
        if !spin_wait(POLL_ITERATIONS, || {
            let dw3 = (self.buf.cq[head * 2 + 1] >> 32) as u32;
            Self::cq_phase(dw3) == self.phase
        }) {
            return false;
        }
        let dw3 = (self.buf.cq[head * 2 + 1] >> 32) as u32;
        let ok = Self::cq_status(dw3) == 0 && (dw3 as u16) == cid;
        self.cq_head = (self.cq_head + 1) % QUEUE_SIZE as u16;
        if self.cq_head == 0 {
            self.phase = !self.phase;
        }
        let stride = ((rd32(self.base, REG_CAP + 4) & 0xF) as u64) + 1;
        wr32(self.base, DOORBELL_BASE + stride * 4, self.cq_head as u32);
        wmb();
        ok
    }

    /// Poll the IO completion queue (in its own `ad` frame) until the phase
    /// tag matches; true on status 0x0000 with the expected command id.
    fn wait_io_completion(&mut self, cid: u16) -> bool {
        let head = self.io_cq_head as usize;
        if !spin_wait(POLL_ITERATIONS, || {
            let dw3 = (self.buf.ad[head * 2 + 1] >> 32) as u32;
            Self::cq_phase(dw3) == self.io_phase
        }) {
            #[cfg(not(test))]
            {
                let dw3 = (self.buf.ad[head * 2 + 1] >> 32) as u32;
                crate::sprintln!(
                    "Aegis: NVMe: io timeout cid={} head={} phase={} dw3={:08X} P={} S={:04X}",
                    cid,
                    head,
                    self.io_phase,
                    dw3,
                    Self::cq_phase(dw3),
                    Self::cq_status(dw3)
                );
            }
            return false;
        }
        let dw3 = (self.buf.ad[head * 2 + 1] >> 32) as u32;
        let ok = Self::cq_status(dw3) == 0 && (dw3 as u16) == cid;
        #[cfg(not(test))]
        if !ok {
            crate::sprintln!(
                "Aegis: NVMe: io done-bad cid={} head={} dw3={:08X} P={} S={:04X} gotcid={}",
                cid,
                head,
                dw3,
                Self::cq_phase(dw3),
                Self::cq_status(dw3),
                dw3 as u16
            );
        }
        self.io_cq_head = (self.io_cq_head + 1) % QUEUE_SIZE as u16;
        if self.io_cq_head == 0 {
            self.io_phase = !self.io_phase;
        }
        // IO CQ head doorbell (qid 1): free the consumed slot so QEMU can
        // keep posting. Without it the ring saturates at `qsize` outstanding
        // completions and the next completion never lands.
        let stride = ((rd32(self.base, REG_CAP + 4) & 0xF) as u64) + 1;
        wr32(
            self.base,
            DOORBELL_BASE + 3 * stride * 4,
            self.io_cq_head as u32,
        );
        wmb();
        ok
    }

    /// Create IO CQ and IO SQ (qid 1, 16 slots, physically contiguous).
    /// The IO CQ lives in its own frame (`ad`): QEMU keeps a separate head
    /// for it, and sharing the admin CQ buffer let stale admin completions
    /// impersonate IO completions (both rings start at phase 1).
    /// QSize is 0s-based (NVMe spec): QEMU builds queues of `qsize + 1`
    /// entries, so advertise `QUEUE_SIZE - 1` to keep the controller's ring
    /// exactly 16 entries like the driver's. Passing `QUEUE_SIZE` made QEMU
    /// create 17-entry rings; on the wrap it fetched one slot past the
    /// never-written end of `buf.sq` (all zeroes -> FLUSH, nsid 0) and the
    /// driver replied INVALID_NSID for a command it never issued.
    pub fn create_io_queues(&mut self) -> bool {
        let cid = self.admin_cmd(
            ADMIN_CREATE_IO_CQ,
            0,
            Bufs::phys(self.buf.ad),
            ((QUEUE_SIZE - 1) << 16) | 1,
            1,
        );
        if !self.wait_completion(cid) {
            return false;
        }
        let cid = self.admin_cmd(
            ADMIN_CREATE_IO_SQ,
            0,
            Bufs::phys(self.buf.sq),
            ((QUEUE_SIZE - 1) << 16) | 1,
            (1 << 16) | 1,
        );
        self.wait_completion(cid)
    }

    /// Identify controller (into `id`) and namespace 1 (into `ad`).
    /// `ad` doubles as the IO completion ring, so after the namespace
    /// identify lands we cache NSZE and clear the ring: leftover identify
    /// bytes must never be mistaken for completion entries (their phase bit
    /// would make the polled `wait_io_completion` return garbage).
    pub fn identify(&mut self) -> bool {
        let cid = self.admin_cmd(
            ADMIN_IDENTIFY,
            0,
            Bufs::phys(self.buf.id),
            CNS_IDENTIFY_CONTROLLER,
            0,
        );
        if !self.wait_completion(cid) {
            return false;
        }
        let cid = self.admin_cmd(
            ADMIN_IDENTIFY,
            1,
            Bufs::phys(self.buf.ad),
            CNS_IDENTIFY_NAMESPACE,
            0,
        );
        if !self.wait_completion(cid) {
            return false;
        }
        self.ns_size_bytes = self.buf.ad[0] * 512;
        for w in self.buf.ad.iter_mut() {
            *w = 0;
        }
        true
    }

    fn id_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.buf.id.as_ptr() as *const u8, 4096) }
    }

    pub fn identify_model(&self) -> &str {
        let d = self.id_bytes();
        str_of(d.get(0x18..0x18 + 40).unwrap_or(&[]))
    }

    pub fn identify_firmware(&self) -> &str {
        let d = self.id_bytes();
        str_of(d.get(0x40..0x40 + 8).unwrap_or(&[]))
    }

    /// Namespace size in bytes (NSZE x 512 B block), cached during identify.
    pub fn ns_size(&self) -> u64 {
        self.ns_size_bytes
    }

    /// Read one 512 B LBA into the DMA buffer; call `lba_data` afterwards.
    pub fn read_lba(&mut self, lba: u64) -> bool {
        let tail = self.io_tail as usize;
        let cid = tail as u16;
        // Translate before `self.buf.sq` is mutably borrowed: `dma_addr`
        // takes `&self` (whole struct), so it cannot run while the sq slice
        // holds an exclusive borrow.
        let qe_addr = self.dma_addr(Bufs::phys(self.buf.qe));
        let s = &mut self.buf.sq[tail * 8..tail * 8 + 8];
        s[0] = IO_READ as u64 | ((tail as u64) << 16) | (1 << 32);
        s[1] = 0;
        s[3] = qe_addr;
        s[4] = 0;
        s[5] = lba;
        s[6] = 0;
        s[7] = 0;
        self.io_tail = (self.io_tail + 1) % QUEUE_SIZE as u16;
        wmb();
        // IO SQ1 tail doorbell: stride = (DSTRD + 1) * 4 bytes.
        let stride = ((rd32(self.base, REG_CAP + 4) & 0xF) as u64) + 1;
        wr32(
            self.base,
            DOORBELL_BASE + 2 * stride * 4,
            self.io_tail as u32,
        );
        let ok = self.wait_io_completion(cid);
        // Order the completion observation before reading the DMA data.
        wmb();
        ok
    }

    pub fn lba_data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.buf.qe.as_ptr() as *const u8, 4096) }
    }

    /// Write one 512 B LBA from `data` (the first 512 bytes; anything beyond is
    /// ignored) via IO_WRITE (opcode 0x01), the exact mirror of `read_lba`:
    /// PRP1 points at the shared DMA frame, cdw10 = LBA, same polled
    /// completion. The payload is staged into the DMA buffer and an `mfence`
    /// runs before the doorbell so the controller's DMA read cannot observe a
    /// partially-written sector.
    pub fn write_lba(&mut self, lba: u64, data: &[u8]) -> bool {
        let qe = &mut self.buf.qe;
        unsafe {
            core::ptr::write_bytes(qe.as_mut_ptr() as *mut u8, 0, 4096);
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                qe.as_mut_ptr() as *mut u8,
                data.len().min(512),
            );
        }
        wmb();
        let tail = self.io_tail as usize;
        let cid = tail as u16;
        // Translate before `self.buf.sq` is mutably borrowed (same reason as
        // `read_lba`).
        let qe_addr = self.dma_addr(Bufs::phys(self.buf.qe));
        let s = &mut self.buf.sq[tail * 8..tail * 8 + 8];
        s[0] = IO_WRITE as u64 | ((tail as u64) << 16) | (1 << 32);
        s[1] = 0;
        s[3] = qe_addr;
        s[4] = 0;
        s[5] = lba;
        s[6] = 0;
        s[7] = 0;
        self.io_tail = (self.io_tail + 1) % QUEUE_SIZE as u16;
        wmb();
        // IO SQ1 tail doorbell: stride = (DSTRD + 1) * 4 bytes.
        let stride = ((rd32(self.base, REG_CAP + 4) & 0xF) as u64) + 1;
        wr32(
            self.base,
            DOORBELL_BASE + 2 * stride * 4,
            self.io_tail as u32,
        );
        let ok = self.wait_io_completion(cid);
        wmb();
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_increments_tail_pointer() {
        let _g = crate::kernel_state_guard();
        let mut q = NvmeQueue::new(64);
        assert_eq!(q.tail, 0);
        let cmd = NvmeSubmissionEntry {
            opcode: 0x02,
            flags: 0,
            nsid: 1,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0x1000,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        q.submit(cmd);
        assert_eq!(q.tail, 1);
        q.submit(cmd);
        assert_eq!(q.tail, 2);
    }

    #[test]
    fn submit_returns_sequential_command_ids() {
        let _g = crate::kernel_state_guard();
        let mut q = NvmeQueue::new(64);
        let cmd = NvmeSubmissionEntry {
            opcode: 0,
            flags: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        let id1 = q.submit(cmd);
        let id2 = q.submit(cmd);
        let id3 = q.submit(cmd);
        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
        assert_eq!(id3, 2);
    }

    #[test]
    fn poll_completion_returns_none_when_empty() {
        let _g = crate::kernel_state_guard();
        let mut q = NvmeQueue::new(64);
        assert!(q.poll_completion().is_none());
    }

    #[test]
    fn poll_completion_returns_entry_after_submit() {
        let _g = crate::kernel_state_guard();
        let mut q = NvmeQueue::new(64);
        q.completions[0] = NvmeCompletionEntry {
            command_specific: 42,
            reserved: 0,
            sq_head: 0,
            sq_identifier: 0,
            command_id: 0,
            phase_bit: true,
            status: 0,
        };
        let comp = q.poll_completion().unwrap();
        assert_eq!(comp.command_specific, 42);
    }

    #[test]
    fn phase_bit_toggles_on_completion() {
        let _g = crate::kernel_state_guard();
        let mut q = NvmeQueue::new(64);
        assert!(!q.phase);
        for i in 0..64 {
            q.completions[i] = NvmeCompletionEntry {
                command_specific: 0,
                reserved: 0,
                sq_head: 0,
                sq_identifier: 0,
                command_id: i as u16,
                phase_bit: true,
                status: 0,
            };
        }
        for _ in 0..64 {
            q.poll_completion();
        }
        assert!(q.phase);
    }
}

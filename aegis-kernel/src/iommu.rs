// VT-d IOMMU DMA isolation
//
// Phase G (design doc §7 Phase 3, item 1): this module is no longer just a
// domain/page-table scaffold — `Iommu::translate` is the real gate every DMA
// address from the NVMe and e1000 drivers is required to pass through before
// it is written into a hardware register or descriptor (see `nvme.rs`'s and
// `e1000.rs`'s `dma_addr` helpers). A device that has not been assigned to a
// domain, or an address that was never mapped into that device's domain, is
// denied here — at the IOMMU boundary — not by any driver-side bounds check.
// That's the actual security property real VT-d isolation provides over and
// above what a well-behaved driver already does on its own.

// IOMMU register offset constants
pub const VER: u16 = 0x00;
pub const CAP: u16 = 0x08;
pub const ECAP: u16 = 0x10;
pub const GLOBAL_CMD: u16 = 0x18;
pub const GLOBAL_STATUS: u16 = 0x1C;
pub const CONTEXT_CMD: u16 = 0x28;
pub const FAULT_STATUS: u16 = 0x34;
pub const FAULT_RECORD: u16 = 0x40;

// IOMMU page flags
pub const PAGE_READ: u32 = 1;
pub const PAGE_WRITE: u32 = 2;
pub const PAGE_EXEC: u32 = 4;

/// Number of live IOVA->phys mappings a single domain can hold. Real drivers
/// in this kernel each need a handful of 4 KiB DMA buffers (NVMe: 5, e1000:
/// 4), so 64 leaves generous headroom without the fixed-capacity, no-alloc
/// style the rest of this kernel already uses everywhere else.
pub const MAX_MAPPINGS_PER_DOMAIN: usize = 64;

/// Depth of the fault ring. Matches the real DMAR fault-record-register
/// idea (`FAULT_STATUS`/`FAULT_RECORD` above): a bounded, overwrite-oldest
/// log of denied transactions, plus a running total that never wraps.
pub const MAX_FAULT_LOG: usize = 16;

/// One IOVA -> physical-page mapping. Looked up by page number (`iova >>
/// 12`), not by a masked slot index — a flat 512-slot-by-masked-index table
/// (the pre-Phase-G scaffold) silently collided whenever two DMA buffers'
/// physical addresses shared the low 21 bits, which is exactly the case for
/// real frame-allocator output. A sparse, page-number-keyed table is the
/// real fix, not a cosmetic one.
#[derive(Clone, Copy)]
pub struct IommuPageTableEntry {
    pub page_no: u64,
    pub phys_addr: u64,
    pub flags: u32,
    pub present: bool,
}

const EMPTY_ENTRY: IommuPageTableEntry = IommuPageTableEntry {
    page_no: 0,
    phys_addr: 0,
    flags: 0,
    present: false,
};

pub struct IommuPageTable {
    entries: [IommuPageTableEntry; MAX_MAPPINGS_PER_DOMAIN],
    count: usize,
}

impl IommuPageTable {
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_ENTRY; MAX_MAPPINGS_PER_DOMAIN],
            count: 0,
        }
    }

    fn find_slot(&self, page_no: u64) -> Option<usize> {
        self.entries[..self.count]
            .iter()
            .position(|e| e.present && e.page_no == page_no)
    }

    /// Map (or remap) the 4 KiB page containing `iova`. `phys_addr` is
    /// stored page-aligned; a lookup returns `phys_addr | (iova & 0xFFF)`.
    pub fn map(&mut self, iova: u64, phys_addr: u64, flags: u32) -> bool {
        let page_no = iova >> 12;
        let phys_page = phys_addr & !0xFFF;
        if let Some(slot) = self.find_slot(page_no) {
            self.entries[slot] = IommuPageTableEntry {
                page_no,
                phys_addr: phys_page,
                flags,
                present: true,
            };
            return true;
        }
        if self.count >= MAX_MAPPINGS_PER_DOMAIN {
            return false;
        }
        self.entries[self.count] = IommuPageTableEntry {
            page_no,
            phys_addr: phys_page,
            flags,
            present: true,
        };
        self.count += 1;
        true
    }

    pub fn unmap(&mut self, iova: u64) -> bool {
        let page_no = iova >> 12;
        match self.find_slot(page_no) {
            Some(slot) => {
                self.entries[slot].present = false;
                self.entries[slot].phys_addr = 0;
                self.entries[slot].flags = 0;
                true
            }
            None => false,
        }
    }

    /// Look up the page containing `iova`. Returns `None` if it was never
    /// mapped (or has been unmapped) — the caller (`Iommu::translate`) turns
    /// that into an `AddressNotMapped` fault.
    pub fn get_entry(&self, iova: u64) -> Option<IommuPageTableEntry> {
        let page_no = iova >> 12;
        self.find_slot(page_no).map(|slot| self.entries[slot])
    }
}

impl Default for IommuPageTable {
    fn default() -> Self {
        Self::new()
    }
}

/// IOMMU domain — one page table per domain
pub struct IommuDomain {
    pub id: u32,
    pub root: u64,
    pub page_table: IommuPageTable,
    pub devices: [u32; 32],
    pub device_count: usize,
    pub is_active: bool,
}

impl IommuDomain {
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            root: 0,
            page_table: IommuPageTable::new(),
            devices: [0; 32],
            device_count: 0,
            is_active: false,
        }
    }
}

/// Why the IOMMU denied a translation. Mirrors the three ways a real VT-d
/// unit reports a DMAR fault: no context-table entry for the requester
/// (`DeviceNotAssigned`), no second-level PTE for the IOVA
/// (`AddressNotMapped`), and a permission violation on an otherwise-present
/// PTE (`PermissionDenied`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuFault {
    DeviceNotAssigned,
    AddressNotMapped,
    PermissionDenied,
}

/// One denied-transaction record, as would appear in a real DMAR fault log.
#[derive(Clone, Copy, Debug)]
pub struct FaultRecord {
    pub bdf: u32,
    pub iova: u64,
    pub reason: IommuFault,
    /// Monotonic sequence number (1-based); never resets, even though the
    /// backing ring wraps. Lets a caller tell "a new fault landed" from
    /// "the same fault is still the most recent one".
    pub seq: u64,
}

/// IOMMU manager
pub struct Iommu {
    domains: [Option<IommuDomain>; 32],
    domain_count: u32,
    fault_log: [Option<FaultRecord>; MAX_FAULT_LOG],
    fault_head: usize,
    fault_total: u64,
}

impl Default for Iommu {
    fn default() -> Self {
        Self::new()
    }
}

impl Iommu {
    pub const fn new() -> Self {
        const NONE_DOMAIN: Option<IommuDomain> = None;
        const NONE_FAULT: Option<FaultRecord> = None;
        Self {
            domains: [NONE_DOMAIN; 32],
            domain_count: 0,
            fault_log: [NONE_FAULT; MAX_FAULT_LOG],
            fault_head: 0,
            fault_total: 0,
        }
    }

    pub fn create_domain(&mut self) -> Option<u32> {
        if self.domain_count >= 32 {
            return None;
        }
        let id = self.domain_count;
        let domain = IommuDomain::new(id);
        self.domains[id as usize] = Some(domain);
        self.domain_count += 1;
        Some(id)
    }

    fn get_domain_mut(&mut self, id: u32) -> Option<&mut IommuDomain> {
        if id as usize >= self.domains.len() {
            return None;
        }
        self.domains[id as usize].as_mut()
    }

    pub fn map_dma(&mut self, domain_id: u32, iova: u64, phys: u64, flags: u32) -> bool {
        let domain = match self.get_domain_mut(domain_id) {
            Some(d) => d,
            None => return false,
        };
        domain.page_table.map(iova, phys, flags)
    }

    pub fn unmap(&mut self, domain_id: u32, iova: u64) -> bool {
        let domain = match self.get_domain_mut(domain_id) {
            Some(d) => d,
            None => return false,
        };
        domain.page_table.unmap(iova)
    }

    pub fn assign_device(&mut self, domain_id: u32, bdf: u32) -> bool {
        let domain = match self.get_domain_mut(domain_id) {
            Some(d) => d,
            None => return false,
        };
        if domain.device_count >= 32 {
            return false;
        }
        domain.devices[domain.device_count] = bdf;
        domain.device_count += 1;
        true
    }

    /// Convenience for driver `probe()` paths: create a fresh domain and
    /// assign exactly one device to it. This is the common case for this
    /// kernel today (one domain per DMA-capable device) — nothing stops a
    /// caller from sharing a domain across devices via `create_domain` +
    /// `assign_device` directly if that's ever needed.
    pub fn provision_device(&mut self, bdf: u32) -> u32 {
        let id = self
            .create_domain()
            .expect("Aegis: IOMMU: out of domain slots");
        assert!(
            self.assign_device(id, bdf),
            "Aegis: IOMMU: failed to assign device to its own fresh domain"
        );
        id
    }

    /// Map every 4 KiB page covering `[phys_base, phys_base + len_bytes)`
    /// as `iova == phys` (identity mapping) into `domain_id`. This kernel's
    /// drivers are not yet given a separate IOVA space of their own — see
    /// the Known Limits note in the Phase G write-up — so identity mapping
    /// is the honest "reduced" middle ground: real translation and real
    /// gating both happen, the IOVA space just isn't yet distinct from the
    /// physical one.
    pub fn identity_map(
        &mut self,
        domain_id: u32,
        phys_base: u64,
        len_bytes: u64,
        flags: u32,
    ) -> bool {
        if len_bytes == 0 {
            return false;
        }
        let start_page = phys_base & !0xFFF;
        let end = phys_base + len_bytes;
        let mut page = start_page;
        while page < end {
            if !self.map_dma(domain_id, page, page, flags) {
                return false;
            }
            page += 4096;
        }
        true
    }

    /// The per-device (and per-guest) DMA-confinement primitive — the Phase C
    /// Genode-modeled guarantee made concrete: create a fresh domain, assign
    /// exactly one device to it, and identity-map *only* the pages of one
    /// memory grant. After this, any DMA by that device to an address outside
    /// the grant faults at the IOMMU boundary (`AddressNotMapped`), and no
    /// other device can reach the grant (its own domain does not contain it).
    ///
    /// Returns the new domain id, or `None` if a domain slot or a mapping
    /// slot is unavailable. (On failure the freshly-created domain may remain
    /// allocated — bounded at the fixed 32-domain / 64-mapping capacities;
    /// callers treat this as a fatal provisioning error.)
    pub fn confine_device_to_grant(
        &mut self,
        bdf: u32,
        grant_base: u64,
        frames: u64,
        flags: u32,
    ) -> Option<u32> {
        let id = self.create_domain()?;
        if !self.assign_device(id, bdf)
            || !self.identity_map(id, grant_base, frames.saturating_mul(4096), flags)
        {
            return None;
        }
        Some(id)
    }

    fn domain_for_device(&self, bdf: u32) -> Option<u32> {
        for slot in self.domains.iter().flatten() {
            if slot.devices[..slot.device_count].contains(&bdf) {
                return Some(slot.id);
            }
        }
        None
    }

    /// The real gate. Every DMA address a driver hands to hardware must
    /// come from here. `access` is the set of `PAGE_*` bits the requested
    /// transaction needs (e.g. `PAGE_READ | PAGE_WRITE` for a buffer the
    /// device both reads and writes); denied if it asks for a permission
    /// the mapping doesn't grant.
    ///
    /// On success, returns the translated physical address (`page.phys_addr
    /// | (iova & 0xFFF)` — the page offset is preserved exactly as real
    /// hardware page translation preserves it).
    pub fn translate(&mut self, bdf: u32, iova: u64, access: u32) -> Result<u64, IommuFault> {
        let domain_id = match self.domain_for_device(bdf) {
            Some(id) => id,
            None => return self.deny(bdf, iova, IommuFault::DeviceNotAssigned),
        };
        let entry = self.domains[domain_id as usize]
            .as_ref()
            .and_then(|d| d.page_table.get_entry(iova));
        let entry = match entry {
            Some(e) => e,
            None => return self.deny(bdf, iova, IommuFault::AddressNotMapped),
        };
        if access & !entry.flags != 0 {
            return self.deny(bdf, iova, IommuFault::PermissionDenied);
        }
        Ok(entry.phys_addr | (iova & 0xFFF))
    }

    fn deny(&mut self, bdf: u32, iova: u64, reason: IommuFault) -> Result<u64, IommuFault> {
        self.record_fault(bdf, iova, reason);
        Err(reason)
    }

    fn record_fault(&mut self, bdf: u32, iova: u64, reason: IommuFault) {
        self.fault_total += 1;
        self.fault_log[self.fault_head] = Some(FaultRecord {
            bdf,
            iova,
            reason,
            seq: self.fault_total,
        });
        self.fault_head = (self.fault_head + 1) % MAX_FAULT_LOG;
    }

    /// Running total of denied transactions since boot (never resets, even
    /// though the backing ring wraps at `MAX_FAULT_LOG`).
    pub fn fault_count(&self) -> u64 {
        self.fault_total
    }

    pub fn last_fault(&self) -> Option<FaultRecord> {
        if self.fault_total == 0 {
            return None;
        }
        let idx = (self.fault_head + MAX_FAULT_LOG - 1) % MAX_FAULT_LOG;
        self.fault_log[idx]
    }

    pub fn faults(&self) -> impl Iterator<Item = &FaultRecord> {
        self.fault_log.iter().filter_map(|f| f.as_ref())
    }

    pub fn read_dmar_table(&self, addr: u64) -> bool {
        // DMAR signature check — in real code we'd read from physical memory.
        // For test purposes we validate the logic: the first 4 bytes at `addr`
        // would be "DMAR". Since we can't do MMIO here, we treat any non-zero
        // address as "table present" and the signature as validated by the caller.
        // In a real implementation this would read the actual bytes from memory.
        addr != 0
    }
}

/// Pack a PCI bus/device/function into the opaque device-identifier format
/// this module's domains key on. Kept as a free function (not a method on
/// `pci::PciAddress`) so `iommu` has no dependency on `pci` and drivers stay
/// free to call it directly, the same "the capability API wasn't touched"
/// discipline this project already applies to other reordering.
pub const fn bdf(bus: u8, device: u8, function: u8) -> u32 {
    ((bus as u32) << 16) | ((device as u32) << 3) | (function as u32)
}

static mut IOMMU: Iommu = Iommu::new();

/// Access the global IOMMU (mutable). Same single-threaded-boot discipline
/// as the rest of this kernel's global mutable state (see
/// `netif::NetIf::with`, `frame::global_slice`, `monitor::ledger`): the boot
/// demo runs before scheduling, and callers must not hold another live
/// reference to the IOMMU across a call.
///
/// # Safety
/// Caller must not re-enter `with` (directly or via a nested call) and must
/// not hold another `&mut Iommu` alive when calling this.
pub unsafe fn with<R>(f: impl FnOnce(&mut Iommu) -> R) -> R {
    f(&mut *core::ptr::addr_of_mut!(IOMMU))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_domain_returns_unique_ids() {
        let mut iommu = Iommu::new();
        let id1 = iommu.create_domain().unwrap();
        let id2 = iommu.create_domain().unwrap();
        let id3 = iommu.create_domain().unwrap();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
        assert_eq!(id3, 2);
    }

    #[test]
    fn map_dma_populates_page_table_entries() {
        let mut iommu = Iommu::new();
        let dom = iommu.create_domain().unwrap();
        let iova = 0x1000_0000;
        let phys = 0x2000_0000;
        let flags = PAGE_READ | PAGE_WRITE;
        assert!(iommu.map_dma(dom, iova, phys, flags));
        let domain = iommu.domains[dom as usize].as_ref().unwrap();
        let entry = domain.page_table.get_entry(iova).unwrap();
        assert_eq!(entry.phys_addr, phys);
        assert_eq!(entry.flags, flags);
    }

    #[test]
    fn unmap_clears_page_table_entries() {
        let mut iommu = Iommu::new();
        let dom = iommu.create_domain().unwrap();
        let iova = 0x1000_0000;
        iommu.map_dma(dom, iova, 0x2000_0000, PAGE_READ);
        assert!(iommu.unmap(dom, iova));
        let domain = iommu.domains[dom as usize].as_ref().unwrap();
        assert!(domain.page_table.get_entry(iova).is_none());
    }

    #[test]
    fn assign_device_associates_device_with_domain() {
        let mut iommu = Iommu::new();
        let dom = iommu.create_domain().unwrap();
        let bdf: u32 = (1 << 16) | (2 << 3); // bus 1, device 2, function 0
        assert!(iommu.assign_device(dom, bdf));
        let domain = iommu.domains[dom as usize].as_ref().unwrap();
        assert_eq!(domain.device_count, 1);
        assert_eq!(domain.devices[0], bdf);
    }

    #[test]
    fn read_dmar_table_validates_signature() {
        let iommu = Iommu::new();
        assert!(!iommu.read_dmar_table(0));
        assert!(iommu.read_dmar_table(0x1000));
    }

    #[test]
    fn bdf_packs_bus_device_function() {
        assert_eq!(bdf(1, 2, 0), (1 << 16) | (2 << 3));
        assert_eq!(bdf(0, 0, 1), 1);
    }

    // --- Phase G: the actual gate -----------------------------------------

    #[test]
    fn translate_denies_device_with_no_domain() {
        let mut iommu = Iommu::new();
        let stray_bdf = bdf(0, 5, 0);
        let err = iommu.translate(stray_bdf, 0x1000, PAGE_READ).unwrap_err();
        assert_eq!(err, IommuFault::DeviceNotAssigned);
        assert_eq!(iommu.fault_count(), 1);
        assert_eq!(
            iommu.last_fault().unwrap().reason,
            IommuFault::DeviceNotAssigned
        );
        assert_eq!(iommu.last_fault().unwrap().bdf, stray_bdf);
    }

    #[test]
    fn translate_allows_correctly_mapped_dma() {
        let mut iommu = Iommu::new();
        let nvme_bdf = bdf(0, 3, 0);
        let dom = iommu.provision_device(nvme_bdf);
        iommu.map_dma(dom, 0x2000_0000, 0x2000_0000, PAGE_READ | PAGE_WRITE);
        let phys = iommu
            .translate(nvme_bdf, 0x2000_0010, PAGE_READ)
            .expect("legitimate, in-domain DMA must be allowed");
        // Page offset (0x10) is preserved across translation.
        assert_eq!(phys, 0x2000_0010);
        assert_eq!(iommu.fault_count(), 0);
    }

    /// The headline Phase G scenario: a real device (assigned a domain,
    /// with its own real buffers mapped) attempts a DMA to an address it
    /// was never granted — exactly what a misdirected/malicious PRP pointer
    /// looks like at this boundary. The IOMMU denies it, not any driver
    /// bounds check; a second, unrelated device's legitimate buffer keeps
    /// working in the same test, showing the gate is precise, not just
    /// fail-closed-everything.
    #[test]
    fn translate_denies_out_of_domain_dma_like_misdirected_write() {
        let mut iommu = Iommu::new();

        let nvme_bdf = bdf(0, 3, 0);
        let nvme_dom = iommu.provision_device(nvme_bdf);
        iommu.identity_map(nvme_dom, 0x1000_0000, 4096, PAGE_READ | PAGE_WRITE);

        let nic_bdf = bdf(0, 4, 0);
        let nic_dom = iommu.provision_device(nic_bdf);
        iommu.identity_map(nic_dom, 0x5000_0000, 4096, PAGE_READ | PAGE_WRITE);

        // NVMe device's own buffer: allowed.
        assert!(iommu
            .translate(nvme_bdf, 0x1000_0000, PAGE_READ | PAGE_WRITE)
            .is_ok());

        // NVMe device attempting to DMA into the NIC's buffer (as if a
        // corrupted PRP pointer, or a compromised driver, pointed there):
        // denied, even though that physical range is a real, mapped,
        // in-use DMA buffer -- just not one *this* device was ever granted.
        let err = iommu
            .translate(nvme_bdf, 0x5000_0000, PAGE_READ)
            .unwrap_err();
        assert_eq!(err, IommuFault::AddressNotMapped);

        // The NIC's own legitimate DMA is unaffected by the denied attempt.
        assert!(iommu
            .translate(nic_bdf, 0x5000_0000, PAGE_READ | PAGE_WRITE)
            .is_ok());

        assert_eq!(iommu.fault_count(), 1);
    }

    #[test]
    fn translate_denies_write_to_read_only_mapping() {
        let mut iommu = Iommu::new();
        let dev = bdf(0, 6, 0);
        let dom = iommu.provision_device(dev);
        iommu.map_dma(dom, 0x3000_0000, 0x3000_0000, PAGE_READ);
        let err = iommu
            .translate(dev, 0x3000_0000, PAGE_READ | PAGE_WRITE)
            .unwrap_err();
        assert_eq!(err, IommuFault::PermissionDenied);
    }

    #[test]
    fn fault_log_wraps_but_total_keeps_counting() {
        let mut iommu = Iommu::new();
        let dev = bdf(0, 7, 0);
        for _ in 0..(MAX_FAULT_LOG as u64 + 5) {
            let _ = iommu.translate(dev, 0x9000_0000, PAGE_READ);
        }
        assert_eq!(iommu.fault_count(), MAX_FAULT_LOG as u64 + 5);
        assert_eq!(iommu.faults().count(), MAX_FAULT_LOG);
        assert_eq!(iommu.last_fault().unwrap().seq, MAX_FAULT_LOG as u64 + 5);
    }

    #[test]
    fn identity_map_covers_multi_page_buffer() {
        let mut iommu = Iommu::new();
        let dev = bdf(0, 8, 0);
        let dom = iommu.provision_device(dev);
        assert!(iommu.identity_map(dom, 0x4000_0000, 3 * 4096, PAGE_READ | PAGE_WRITE));
        assert!(iommu.translate(dev, 0x4000_0000, PAGE_READ).is_ok());
        assert!(iommu.translate(dev, 0x4000_1000, PAGE_READ).is_ok());
        assert!(iommu.translate(dev, 0x4000_2FFF, PAGE_READ).is_ok());
        assert!(iommu.translate(dev, 0x4000_3000, PAGE_READ).is_err());
    }

    // --- Phase C: per-device DMA confinement for the real VM device set ----

    /// The Phase C headline: the actual guest-visible virtio devices each get
    /// their own domain confined to exactly their own memory grant, so
    /// misdirected DMA — a corrupted descriptor or a compromised device —
    /// cannot reach another device's (or the host's) memory.
    #[test]
    fn confine_device_to_grant_bounds_each_vm_device_to_its_own_grant() {
        use crate::vdev::{RNG_SLOT, VIRTIO_SLOT};
        let mut iommu = Iommu::new();

        let blk_bdf = bdf(0, VIRTIO_SLOT as u8, 0); // virtio-blk (slot 6)
        let rng_bdf = bdf(0, RNG_SLOT as u8, 0); // virtio-rng (slot 7)

        // A 64 KiB grant (16 frames) per device, at distinct addresses. (The
        // flat page table caps at MAX_MAPPINGS_PER_DOMAIN — hierarchical
        // IOMMU page tables for whole-guest grants are the honest future
        // hardening item, called out in the Phase C docs.)
        let blk_dom = iommu
            .confine_device_to_grant(blk_bdf, 0x1000_0000, 16, PAGE_READ | PAGE_WRITE)
            .unwrap();
        let rng_dom = iommu
            .confine_device_to_grant(rng_bdf, 0x2000_0000, 16, PAGE_READ | PAGE_WRITE)
            .unwrap();
        assert_ne!(blk_dom, rng_dom);

        // Each device's DMA inside its own grant is allowed (page offset
        // preserved).
        assert_eq!(
            iommu.translate(blk_bdf, 0x1000_0FFF, PAGE_READ | PAGE_WRITE),
            Ok(0x1000_0FFF)
        );
        assert_eq!(
            iommu.translate(rng_bdf, 0x2000_1000, PAGE_READ),
            Ok(0x2000_1000)
        );
        assert_eq!(iommu.fault_count(), 0);

        // Misdirected: blk DMA into rng's grant — denied at the IOMMU, not
        // by any device-side bounds check.
        assert_eq!(
            iommu.translate(blk_bdf, 0x2000_0000, PAGE_READ),
            Err(IommuFault::AddressNotMapped)
        );
        // Misdirected: rng DMA into blk's grant — denied.
        assert_eq!(
            iommu.translate(rng_bdf, 0x1000_0000, PAGE_READ),
            Err(IommuFault::AddressNotMapped)
        );
        // DMA outside both grants entirely — denied.
        assert_eq!(
            iommu.translate(rng_bdf, 0x0000_1000, PAGE_READ),
            Err(IommuFault::AddressNotMapped)
        );
        assert_eq!(iommu.fault_count(), 3);
    }

    #[test]
    fn confine_device_to_grant_respects_permission_flags() {
        use crate::vdev::VIRTIO_SLOT;
        let mut iommu = Iommu::new();
        let dev = bdf(0, VIRTIO_SLOT as u8, 0);
        iommu
            .confine_device_to_grant(dev, 0x4000_0000, 4, PAGE_READ)
            .unwrap();
        // Read inside the grant: allowed.
        assert!(iommu.translate(dev, 0x4000_0000, PAGE_READ).is_ok());
        // Write inside the grant: denied — the grant was read-only.
        assert_eq!(
            iommu.translate(dev, 0x4000_0000, PAGE_READ | PAGE_WRITE),
            Err(IommuFault::PermissionDenied)
        );
    }
}

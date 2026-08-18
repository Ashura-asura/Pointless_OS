//! Host-side ACPI discovery + SMP groundwork (Phase Y).
//!
//! The kernel reads the *real* ACPI tables the firmware exposes — RSDP,
//! RSDT/XSDT, MADT — and enumerates the CPUs/APICs as the first step toward
//! SMP. Everything that touches raw physical memory is `unsafe` and lives at
//! the very top (`read_phys`, `discover`); ALL parsing below it is pure and
//! total — every function returns `Option`/bounded structs and never panics
//! on garbage input.
//!
//! # Guest-flexibility seam
//!
//! `build_rsdp` / `build_madt` / `build_sdt_header` are a tested **encoder**
//! path built on the very same types the parsers consume. They are NOT yet
//! wired into the VM — a future guest-ACPI phase will use them to construct
//! the tables a guest OS sees. The round-trip tests (`build_rsdp_round_trips`,
//! `build_madt_round_trips`) are the contract that keeps the two directions
//! in lockstep. Nothing here is hard-coded to the host: discovery is a pure
//! function over supplied memory regions, so the same types serve both the
//! host-read and guest-write directions.
//!
//! # Honest limits
//!
//! - The identity map covers the first 4 GiB only, so any ACPI table above
//!   4 GiB is rejected during discovery (an XSDT entry `>= 0x1_0000_0000`
//!   fails the whole root-table parse rather than being truncated silently).
//! - This is CPU/APIC *enumeration* groundwork, not bring-up: BSP only, no AP
//!   boot (INIT-SIPI), no per-CPU LAPIC reprogramming, no per-CPU stacks.
//! - The search order is the Linux-style EBDA-then-F-seg scan; on real
//!   machines the RSDP can live elsewhere (vendor-specific locations), which
//!   this scan would miss — everything is QEMU/OVMF-verified, UNTESTED on
//!   physical hardware.

/// First four bytes of the RSDP signature ("RSD ").
pub const RSDP_SIG: [u8; 4] = *b"RSD ";
/// Trailing four bytes of the RSDP signature ("PTR ").
pub const RSDP_SIG_TAIL: [u8; 4] = *b"PTR ";
/// Maximum root-table entries we keep.
pub const MAX_TABLES: usize = 16;
/// Maximum LAPIC entries we keep.
pub const MAX_CPUS: usize = 8;
/// Maximum IRQ overrides we keep.
pub const MAX_OVERRIDES: usize = 8;
/// Physical address of the EBDA segment word (real-mode BIOS data area).
pub const EBDA_WORD_PHYS: u64 = 0x40Eu64;
/// Start of the BIOS F-segment scan window.
pub const F_SEG_START: u64 = 0xE0000u64;
/// Length of the F-segment scan window (0xE0000..0x100000).
pub const F_SEG_LEN: u64 = 0x20000u64;
/// Maximum number of UEFI ACPI Reclaim/NVS regions the boot map contributes
/// to the RSDP scan.
pub const MAX_ACPI_RANGES: usize = 32;
/// Largest single table read we ever attempt through the identity map — real
/// ACPI SDTs are a few hundred bytes; this bounds a corrupt `length` field.
const MAX_TABLE_READ: usize = 4096;

/// Root System Description Pointer (parsed view).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rsdp {
    pub revision: u8,
    pub rsdt_address: u32,
    pub xsdt_address: u64,
}

/// Parse an RSDP from a buffer. Requires at least 36 bytes (the ACPI 2.0
/// size — `scan_rsdp` always validates a 36-byte window), the 8-byte
/// signature `"RSD PTR "`, a valid ACPI 1.0 checksum over bytes 0..20, and —
/// for revision >= 2 — a valid extended checksum over bytes 0..36. Revision
/// 0/1 use `rsdt_address` only; revision >= 2 must still carry a nonzero
/// `rsdt_address` (RSDT is kept when XSDT is zero). Revisions above 2 are
/// rejected: future revisions must fail to parse, not be misread.
pub fn parse_rsdp(buf: &[u8]) -> Option<Rsdp> {
    if buf.len() < 36 {
        return None;
    }
    if buf[0..4] != RSDP_SIG || buf[4..8] != RSDP_SIG_TAIL {
        return None;
    }
    // ACPI 1.0 checksum over bytes 0..20 must sum to zero.
    if checksum(&buf[0..20]) != 0 {
        return None;
    }
    let revision = buf[15];
    if revision > 2 {
        return None;
    }
    let rsdt_address = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    if rsdt_address == 0 {
        return None;
    }
    if revision >= 2 {
        // Extended checksum over the full 36-byte ACPI 2.0 RSDP.
        if checksum(&buf[0..36]) != 0 {
            return None;
        }
    }
    let xsdt_address = if revision >= 2 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[24..32]);
        u64::from_le_bytes(b)
    } else {
        0
    };
    Some(Rsdp {
        revision,
        rsdt_address,
        xsdt_address,
    })
}

/// System Description Table header (the first 36 bytes of any SDT).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

/// Parse and validate an SDT header: length >= 36, length <= buf.len(),
/// byte-wise sum over the whole declared table == 0, and the signature is
/// not all-zero. Pure and total.
pub fn parse_sdt_header(buf: &[u8]) -> Option<SdtHeader> {
    if buf.len() < 36 {
        return None;
    }
    let length = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if length < 36 {
        return None;
    }
    if length as usize > buf.len() {
        return None;
    }
    let signature = [buf[0], buf[1], buf[2], buf[3]];
    if signature == [0u8; 4] {
        return None;
    }
    if checksum(&buf[0..length as usize]) != 0 {
        return None;
    }
    let oem_id = [buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]];
    let oem_table_id = [
        buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ];
    Some(SdtHeader {
        signature,
        length,
        revision: buf[9],
        checksum: buf[8],
        oem_id,
        oem_table_id,
        oem_revision: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        creator_id: u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
        creator_revision: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
    })
}

/// Addresses of the tables listed in an RSDT or XSDT.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TableList {
    pub entries: [u32; MAX_TABLES],
    pub count: usize,
}

/// Parse the root table (RSDT or XSDT) into a bounded list of 32-bit table
/// addresses. RSDT entries are 32-bit; XSDT entries are 64-bit and any entry
/// `>= 0x1_0000_0000` rejects the WHOLE parse (the identity map covers only
/// the first 4 GiB — see module honest limits) rather than truncating
/// silently. `count` is bounded by both `MAX_TABLES` and the declared
/// `(length - 36) / entry_size`; if the declared length overruns the buffer
/// we stop early with an honest partial list.
pub fn parse_table_entries(buf: &[u8]) -> Option<TableList> {
    if buf.len() < 36 {
        return None;
    }
    let sig = [buf[0], buf[1], buf[2], buf[3]];
    let is_rsdt = sig == *b"RSDT";
    let is_xsdt = sig == *b"XSDT";
    if !is_rsdt && !is_xsdt {
        return None;
    }
    let length = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    if length < 36 {
        return None;
    }
    // Declared length overruns the buffer: honest partial, bounded by what
    // we actually hold.
    let avail = length.min(buf.len());
    let entry_size = if is_rsdt { 4usize } else { 8usize };
    let count = ((avail - 36) / entry_size).min(MAX_TABLES);
    let mut entries = [0u32; MAX_TABLES];
    for (i, slot) in entries[..count].iter_mut().enumerate() {
        if is_rsdt {
            let base = 36 + i * 4;
            *slot = u32::from_le_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]]);
        } else {
            let base = 36 + i * 8;
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[base..base + 8]);
            let v = u64::from_le_bytes(b);
            if v >= 0x1_0000_0000 {
                // Out of the identity map: reject the whole parse, never
                // truncate silently (documented honest limit).
                return None;
            }
            *slot = v as u32;
        }
    }
    Some(TableList { entries, count })
}

/// One LAPIC entry from the MADT.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LapicEntry {
    pub acpi_processor_id: u8,
    pub apic_id: u8,
    pub enabled: bool,
}

/// One I/O APIC from the MADT (first one wins, per ACPI).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IoApic {
    pub id: u8,
    pub address: u32,
    pub global_interrupt_base: u32,
}

/// One interrupt-source override from the MADT.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IrqOverride {
    pub source: u8,
    pub global_interrupt: u32,
    pub flags: u16,
}

/// Multiple APIC Description Table (parsed view).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Madt {
    pub lapic_address: u32,
    pub flags: u32,
    pub cpus: [LapicEntry; MAX_CPUS],
    pub cpu_count: usize,
    pub ioapic: Option<IoApic>,
    pub overrides: [IrqOverride; MAX_OVERRIDES],
    pub override_count: usize,
}

/// Parse a MADT: header signature "APIC", valid SDT checksum over the whole
/// table, then walk the entries after the 44-byte fixed part (36-byte SDT
/// header + 8 bytes of LAPIC address/flags). Each entry is
/// `{ type: u8, length: u8, body }`; a length < 2 or an entry that overruns
/// the table length stops the walk (corrupt). Type 0 = LAPIC, type 1 =
/// IOAPIC (first kept), type 2 = IRQ override (bounded by MAX_OVERRIDES);
/// anything else is skipped by length. Never panics.
pub fn parse_madt(buf: &[u8]) -> Option<Madt> {
    let hdr = parse_sdt_header(buf)?;
    if hdr.signature != *b"APIC" {
        return None;
    }
    let length = hdr.length as usize;
    let lapic_address = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
    let flags = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
    let mut cpus = [LapicEntry {
        acpi_processor_id: 0,
        apic_id: 0,
        enabled: false,
    }; MAX_CPUS];
    let mut cpu_count = 0usize;
    let mut ioapic: Option<IoApic> = None;
    let mut overrides = [IrqOverride {
        source: 0,
        global_interrupt: 0,
        flags: 0,
    }; MAX_OVERRIDES];
    let mut override_count = 0usize;
    let mut pos = 44usize;
    while pos < length {
        if length - pos < 2 {
            break;
        }
        let ty = buf[pos];
        let elen = buf[pos + 1] as usize;
        if elen < 2 || pos + elen > length {
            break;
        }
        let body = &buf[pos + 2..pos + elen];
        match ty {
            0 if body.len() >= 6 && cpu_count < MAX_CPUS => {
                // LAPIC: ACPI processor UID, APIC ID, flags u32.
                let acpi_processor_id = body[0];
                let apic_id = body[1];
                let f = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
                cpus[cpu_count] = LapicEntry {
                    acpi_processor_id,
                    apic_id,
                    enabled: f & 1 != 0,
                };
                cpu_count += 1;
            }
            1 if body.len() >= 10 && ioapic.is_none() => {
                // IOAPIC: id, reserved, address u32, gsi_base u32.
                let id = body[0];
                let address = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
                let gsi = u32::from_le_bytes([body[6], body[7], body[8], body[9]]);
                ioapic = Some(IoApic {
                    id,
                    address,
                    global_interrupt_base: gsi,
                });
            }
            2 if body.len() >= 8 && override_count < MAX_OVERRIDES => {
                // IRQ override: bus, source, gsi u32, flags u16.
                let source = body[1];
                let gsi = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
                let f = u16::from_le_bytes([body[6], body[7]]);
                overrides[override_count] = IrqOverride {
                    source,
                    global_interrupt: gsi,
                    flags: f,
                };
                override_count += 1;
            }
            _ => {}
        }
        pos += elen;
    }
    Some(Madt {
        lapic_address,
        flags,
        cpus,
        cpu_count,
        ioapic,
        overrides,
        override_count,
    })
}

/// Scan `buf` for a valid RSDP signature, checking only 16-byte-aligned
/// offsets (relative to the start of `buf`). Returns the first offset whose
/// 36-byte window parses; `None` if absent.
pub fn scan_rsdp(buf: &[u8]) -> Option<usize> {
    let mut off = 0usize;
    while off + 36 <= buf.len() {
        if buf[off..off + 8] == *b"RSD PTR " && parse_rsdp(&buf[off..off + 36]).is_some() {
            return Some(off);
        }
        off += 16;
    }
    None
}

/// Read raw physical memory through the kernel's identity map as a slice.
///
/// # Safety
///
/// The caller must guarantee `buf_ptr + len` lies below 4 GiB (the identity
/// map covers only the first 4 GiB) and that the range is mapped at the time
/// of the call — the same discipline as `boot_info::locate_at`.
pub unsafe fn read_phys(buf_ptr: u64, len: usize) -> &'static [u8] {
    // SAFETY: caller-guaranteed mapped, below 4 GiB, and immutable — the
    // identity map stays valid for the whole kernel lifetime.
    unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) }
}

/// Compact per-CPU SMP view derived from a MADT. `cpu_count` counts only the
/// *enabled* LAPIC entries; all parsed entries are kept in the arrays with
/// their `enabled` flags.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SmpInfo {
    pub cpu_count: usize,
    pub apic_ids: [u8; MAX_CPUS],
    pub enabled: [bool; MAX_CPUS],
    pub ioapic: Option<IoApic>,
    pub lapic_address: u32,
}

/// Build the `SmpInfo` for a parsed MADT.
pub fn smp_info_from_madt(m: &Madt) -> SmpInfo {
    let mut apic_ids = [0u8; MAX_CPUS];
    let mut enabled = [false; MAX_CPUS];
    let mut cpu_count = 0usize;
    let n = m.cpu_count.min(MAX_CPUS);
    for i in 0..n {
        apic_ids[i] = m.cpus[i].apic_id;
        enabled[i] = m.cpus[i].enabled;
        if m.cpus[i].enabled {
            cpu_count += 1;
        }
    }
    SmpInfo {
        cpu_count,
        apic_ids,
        enabled,
        ioapic: m.ioapic,
        lapic_address: m.lapic_address,
    }
}

/// The full host-side discovery result.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    pub rsdp: Rsdp,
    pub root_signature: [u8; 4],
    pub root_entries: TableList,
    pub madt: Option<Madt>,
    /// Physical address of the parsed MADT (0 when absent) — used by the
    /// boot marker `MADT at 0x…`.
    pub madt_address: u64,
    pub smp: SmpInfo,
    /// Physical address the RSDP was found at (EBDA or F-seg base + offset).
    pub rsdp_offset: u64,
}

/// Total byte-sum mod 256 over a region.
fn checksum(bytes: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for &b in bytes {
        sum = sum.wrapping_add(b);
    }
    sum
}

/// The checksum byte that makes `bytes` sum to zero (used by the encoders).
fn checksum_complement(bytes: &[u8]) -> u8 {
    checksum(bytes).wrapping_neg()
}

/// Build a checksummed 36-byte SDT header. The checksum covers exactly the
/// 36 bytes emitted, so the caller must re-checksum if it appends a body (as
/// `build_madt` does). Pure; the guest-flexibility seam.
pub fn build_sdt_header(
    signature: &[u8; 4],
    length: u32,
    revision: u8,
    oem_id: &[u8; 6],
    oem_table_id: &[u8; 8],
) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[0..4].copy_from_slice(signature);
    b[4..8].copy_from_slice(&length.to_le_bytes());
    b[9] = revision;
    b[10..16].copy_from_slice(oem_id);
    b[16..24].copy_from_slice(oem_table_id);
    b[24..28].copy_from_slice(&0u32.to_le_bytes());
    b[28..32].copy_from_slice(&0u32.to_le_bytes());
    b[32..36].copy_from_slice(&0u32.to_le_bytes());
    b[8] = checksum_complement(&b[0..36]);
    b
}

/// Build a checksummed 36-byte RSDP (revision 0/1/2). Revision >= 2 carries
/// the length + XSDT address and both checksums; the extended checksum is set
/// only then. Pure; the guest-flexibility seam.
pub fn build_rsdp(rev: u8, rsdt: u32, xsdt: u64) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[0..8].copy_from_slice(b"RSD PTR ");
    b[9..15].copy_from_slice(b"AEGIS ");
    b[15] = rev;
    b[16..20].copy_from_slice(&rsdt.to_le_bytes());
    if rev >= 2 {
        b[20..24].copy_from_slice(&36u32.to_le_bytes());
        b[24..32].copy_from_slice(&xsdt.to_le_bytes());
    }
    // ACPI 1.0 checksum over bytes 0..20.
    b[8] = checksum_complement(&b[0..20]);
    if rev >= 2 {
        // Extended checksum over the full 36 bytes.
        b[32] = checksum_complement(&b[0..36]);
    }
    b
}

/// Build a checksummed MADT (44-byte fixed part + LAPIC/IOAPIC/IRQ-override
/// entries) into a fixed 256-byte buffer, returning the written length. The
/// entry layout exactly mirrors `parse_madt`, so the encoder round-trips
/// through the parser. Pure; the guest-flexibility seam — NOT yet wired into
/// the VM.
pub fn build_madt(m: &Madt) -> ([u8; 256], usize) {
    let mut buf = [0u8; 256];
    let mut len = 44usize;
    buf[0..4].copy_from_slice(b"APIC");
    buf[9] = 1; // revision
    buf[36..40].copy_from_slice(&m.lapic_address.to_le_bytes());
    buf[40..44].copy_from_slice(&m.flags.to_le_bytes());
    for c in m.cpus.iter().take(m.cpu_count) {
        if len + 8 > 256 {
            break;
        }
        buf[len] = 0; // LAPIC
        buf[len + 1] = 8;
        buf[len + 2] = c.acpi_processor_id;
        buf[len + 3] = c.apic_id;
        let flags = if c.enabled { 1u32 } else { 0 };
        buf[len + 4..len + 8].copy_from_slice(&flags.to_le_bytes());
        len += 8;
    }
    if let Some(io) = &m.ioapic {
        if len + 12 <= 256 {
            buf[len] = 1; // IOAPIC
            buf[len + 1] = 12;
            buf[len + 2] = io.id;
            buf[len + 3] = 0; // reserved
            buf[len + 4..len + 8].copy_from_slice(&io.address.to_le_bytes());
            buf[len + 8..len + 12].copy_from_slice(&io.global_interrupt_base.to_le_bytes());
            len += 12;
        }
    }
    for o in m.overrides.iter().take(m.override_count) {
        if len + 10 > 256 {
            break;
        }
        buf[len] = 2; // IRQ override
        buf[len + 1] = 10;
        buf[len + 2] = 0; // bus = ISA
        buf[len + 3] = o.source;
        buf[len + 4..len + 8].copy_from_slice(&o.global_interrupt.to_le_bytes());
        buf[len + 8..len + 10].copy_from_slice(&o.flags.to_le_bytes());
        len += 10;
    }
    buf[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    buf[8] = checksum_complement(&buf[0..len]);
    (buf, len)
}

/// Display helper for the boot marker: the enabled APIC IDs as a comma list
/// (e.g. `0,1`), matching the `SMP: N processor(s) (apic ids [..])` line.
pub struct ApicIdList<'a>(pub &'a SmpInfo);

impl core::fmt::Display for ApicIdList<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (i, en) in self.0.enabled.iter().enumerate() {
            if *en {
                if !first {
                    f.write_str(",")?;
                }
                core::write!(f, "{}", self.0.apic_ids[i])?;
                first = false;
            }
        }
        Ok(())
    }
}

/// An abstraction over physical-memory reads so the *decision* logic of
/// discovery can be a pure, total function over supplied regions, while the
/// live kernel supplies raw identity-mapped reads (`read_phys`). Tests supply
/// synthetic regions covering the addresses their synthetic tables live at.
trait PhysRead {
    fn read(&self, addr: u64, len: usize) -> Option<&[u8]>;
}

/// Live identity-mapped reader over the first 4 GiB.
struct LiveReader;

impl PhysRead for LiveReader {
    fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        if addr >= 0x1_0000_0000 {
            return None;
        }
        let avail = (0x1_0000_0000 - addr) as usize;
        let n = len.min(avail);
        if n == 0 {
            return None;
        }
        // SAFETY: addr is below 4 GiB and the identity map covers it.
        Some(unsafe { read_phys(addr, n) })
    }
}

/// Read an SDT by its address: first the 36-byte header to learn the declared
/// `length`, then the whole table — clamped to the 4 GiB boundary and
/// `MAX_TABLE_READ` so a corrupt length can never fault. Returns `None` for
/// unusable lengths.
fn read_table<R: PhysRead + ?Sized>(addr: u64, r: &R) -> Option<&[u8]> {
    let hdr = r.read(addr, 36)?;
    let length = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if length < 36 {
        return None;
    }
    let max_avail = (0x1_0000_0000 - addr) as usize;
    let n = length.min(max_avail).min(MAX_TABLE_READ);
    r.read(addr, n)
}

/// Pure discovery core over an abstract physical-memory reader. The standard
/// search order: (a) the EBDA segment word at `EBDA_WORD_PHYS`, if the
/// segment is sane (< 0x8000) scan the 1 KiB EBDA region at `segment * 16`;
/// (b) scan the F-seg 128 KiB window `0xE0000..0x100000`; (c) scan the UEFI
/// ACPI Reclaim + ACPI NVS regions from the boot memory map (`acpi_ranges`),
/// where firmware installs the RSDP/tables — OVMF keeps them at high
/// addresses (e.g. `0x1FB…`) unreachable from the legacy locations. First hit
/// wins. Then parse the root table at the RSDP's RSDT (or XSDT when the
/// revision says to and it is nonzero), find the `"APIC"` entry and parse the
/// MADT. `madt`/`smp` may be empty when no MADT exists. Never panics; returns
/// `None` when no usable ACPI is found.
fn discover_core<R: PhysRead + ?Sized>(r: &R, acpi_ranges: &[(u64, u64)]) -> Option<Discovered> {
    let mut offset = 0u64;
    // (a) EBDA: the real-mode word at 0x40E holds the EBDA segment.
    if let Some(w) = r.read(EBDA_WORD_PHYS, 2) {
        let seg = u16::from_le_bytes([w[0], w[1]]) as u64;
        if seg < 0x8000 {
            let base = seg * 16;
            let avail = 1024usize.min((0x1_0000_0000 - base) as usize);
            if let Some(buf) = r.read(base, avail) {
                if let Some(off) = scan_rsdp(buf) {
                    offset = base + off as u64;
                }
            }
        }
    }
    // (b) F-segment window.
    if offset == 0 {
        if let Some(buf) = r.read(F_SEG_START, F_SEG_LEN as usize) {
            if let Some(off) = scan_rsdp(buf) {
                offset = F_SEG_START + off as u64;
            }
        }
    }
    // (c) UEFI ACPI Reclaim/NVS regions from the boot memory map.
    if offset == 0 {
        for &(base, len) in acpi_ranges {
            if len == 0 || base >= 0x1_0000_0000 {
                continue;
            }
            let avail = (0x1_0000_0000 - base).min(len);
            if avail < 36 {
                continue;
            }
            if let Some(buf) = r.read(base, avail as usize) {
                if let Some(off) = scan_rsdp(buf) {
                    offset = base + off as u64;
                    break;
                }
            }
        }
    }
    if offset == 0 {
        return None;
    }
    let rsdp = parse_rsdp(r.read(offset, 36)?)?;
    let root_addr = if rsdp.revision >= 2 && rsdp.xsdt_address != 0 {
        rsdp.xsdt_address
    } else {
        rsdp.rsdt_address as u64
    };
    if root_addr == 0 || root_addr >= 0x1_0000_0000 {
        return None;
    }
    let root_buf = read_table(root_addr, r)?;
    let root_entries = parse_table_entries(root_buf)?;
    let root_signature = [root_buf[0], root_buf[1], root_buf[2], root_buf[3]];
    let mut madt: Option<Madt> = None;
    let mut madt_address = 0u64;
    for i in 0..root_entries.count {
        let addr = root_entries.entries[i] as u64;
        if addr == 0 || addr >= 0x1_0000_0000 {
            continue;
        }
        // A corrupt non-APIC table must not abort MADT discovery — skip it.
        if let Some(buf) = read_table(addr, r) {
            if buf.len() >= 36 && buf[0..4] == *b"APIC" {
                if let Some(m) = parse_madt(buf) {
                    madt = Some(m);
                    madt_address = addr;
                    break;
                }
            }
        }
    }
    let smp = match &madt {
        Some(m) => smp_info_from_madt(m),
        None => SmpInfo {
            cpu_count: 0,
            apic_ids: [0u8; MAX_CPUS],
            enabled: [false; MAX_CPUS],
            ioapic: None,
            lapic_address: 0,
        },
    };
    Some(Discovered {
        rsdp,
        root_signature,
        root_entries,
        madt,
        madt_address,
        smp,
        rsdp_offset: offset,
    })
}

/// Collect the UEFI ACPI Reclaim + ACPI NVS physical ranges from the boot
/// memory map — the regions firmware installs the RSDP and the ACPI tables
/// in. OVMF keeps them at high addresses (e.g. `0x1FB…`) that the legacy
/// EBDA/F-seg search cannot reach, so the boot path feeds them to
/// [`discover`] as the third scan tier. Pure and total.
pub fn acpi_ranges_from_map(
    entries: &[crate::boot_info::MapEntry],
) -> ([(u64, u64); MAX_ACPI_RANGES], usize) {
    let mut out = [(0u64, 0u64); MAX_ACPI_RANGES];
    let mut n = 0usize;
    for e in entries {
        if (e.ty == crate::boot_info::TYPE_ACPI_RECLAIM || e.ty == crate::boot_info::TYPE_ACPI_NVS)
            && n < MAX_ACPI_RANGES
        {
            out[n] = (e.base, e.pages * 4096);
            n += 1;
        }
    }
    (out, n)
}

/// Run the host-side ACPI discovery: scan the EBDA (via the segment word at
/// `EBDA_WORD_PHYS`), then the F-segment window, then the supplied UEFI ACPI
/// Reclaim/NVS regions for the RSDP, parse the root table, and enumerate the
/// MADT's CPUs/APICs.
///
/// # Safety
///
/// Reads raw physical memory through the identity map (`read_phys`). Only
/// meaningful on the live kernel after the page-table switch; the boot path
/// must tolerate `None` (no ACPI) without panicking.
pub unsafe fn discover(acpi_ranges: &[(u64, u64)]) -> Option<Discovered> {
    discover_core(&LiveReader, acpi_ranges)
}

/// Stashed host-side discovery result, extracted at boot and read later by
/// future SMP phases. The kernel is single-threaded at boot (the same
/// global-mut discipline as `boot_info::FLEET_CONFIG`), so a `static mut`
/// with unsafe access is safe here.
static mut DISCOVERED: Option<Discovered> = None;

/// Record the discovery result (or `None`) for later phases.
///
/// # Safety
/// Single-threaded boot path only; must not run concurrently with reads.
pub unsafe fn set_discovered(d: Option<Discovered>) {
    core::ptr::addr_of_mut!(DISCOVERED).write(d);
}

/// The currently-stashed discovery result, if any.
pub fn discovered() -> Option<&'static Discovered> {
    // SAFETY: written once by `set_discovered` on the single-threaded boot
    // path and never mutated after; mirrors `boot_info::fleet_config`.
    unsafe {
        core::ptr::addr_of!(DISCOVERED)
            .as_ref()
            .and_then(|d| d.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Patch the SDT checksum byte (offset 8) so `b[0..len]` sums to zero.
    fn set_checksum(b: &mut [u8], len: usize) {
        b[8] = 0;
        let mut s: u8 = 0;
        for &x in &b[0..len] {
            s = s.wrapping_add(x);
        }
        b[8] = s.wrapping_neg();
    }

    /// Independent RSDP fixture builder (deliberately not `build_rsdp`, so a
    /// bug in the encoder cannot mask a bug in the parser).
    fn make_rsdp(rev: u8, rsdt: u32, xsdt: u64) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[0..8].copy_from_slice(b"RSD PTR ");
        b[9..15].copy_from_slice(b"AEGIS ");
        b[15] = rev;
        b[16..20].copy_from_slice(&rsdt.to_le_bytes());
        if rev >= 2 {
            b[20..24].copy_from_slice(&36u32.to_le_bytes());
            b[24..32].copy_from_slice(&xsdt.to_le_bytes());
        }
        let mut s: u8 = 0;
        for &x in &b[0..20] {
            s = s.wrapping_add(x);
        }
        b[8] = s.wrapping_neg();
        if rev >= 2 {
            let mut s2: u8 = 0;
            for &x in &b[0..36] {
                s2 = s2.wrapping_add(x);
            }
            b[32] = s2.wrapping_neg();
        }
        b
    }

    /// Re-checksum an RSDP fixture after mutating a field.
    fn rechecksum_rsdp(b: &mut [u8; 36]) {
        b[8] = 0;
        b[32] = 0;
        let mut s: u8 = 0;
        for &x in &b[0..20] {
            s = s.wrapping_add(x);
        }
        b[8] = s.wrapping_neg();
        if b[15] >= 2 {
            let mut s2: u8 = 0;
            for &x in &b[0..36] {
                s2 = s2.wrapping_add(x);
            }
            b[32] = s2.wrapping_neg();
        }
    }

    fn make_rsdt(entries: &[u32]) -> ([u8; 256], usize) {
        let mut b = [0u8; 256];
        b[0..4].copy_from_slice(b"RSDT");
        b[9] = 1;
        let mut len = 36usize;
        for e in entries {
            b[len..len + 4].copy_from_slice(&e.to_le_bytes());
            len += 4;
        }
        b[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        set_checksum(&mut b, len);
        (b, len)
    }

    fn make_xsdt(entries: &[u64]) -> ([u8; 256], usize) {
        let mut b = [0u8; 256];
        b[0..4].copy_from_slice(b"XSDT");
        b[9] = 1;
        let mut len = 36usize;
        for e in entries {
            b[len..len + 8].copy_from_slice(&e.to_le_bytes());
            len += 8;
        }
        b[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        set_checksum(&mut b, len);
        (b, len)
    }

    fn lapic(uid: u8, id: u8, enabled: bool) -> LapicEntry {
        LapicEntry {
            acpi_processor_id: uid,
            apic_id: id,
            enabled,
        }
    }

    fn cpus_array(entries: &[LapicEntry]) -> [LapicEntry; MAX_CPUS] {
        let mut a = [lapic(0, 0, false); MAX_CPUS];
        for (i, e) in entries.iter().enumerate() {
            a[i] = *e;
        }
        a
    }

    fn overrides_array(entries: &[IrqOverride]) -> [IrqOverride; MAX_OVERRIDES] {
        let mut a = [IrqOverride {
            source: 0,
            global_interrupt: 0,
            flags: 0,
        }; MAX_OVERRIDES];
        for (i, e) in entries.iter().enumerate() {
            a[i] = *e;
        }
        a
    }

    fn sample_madt() -> Madt {
        Madt {
            lapic_address: 0xFEE00000,
            flags: 1,
            cpus: cpus_array(&[lapic(0, 0, true), lapic(1, 1, true)]),
            cpu_count: 2,
            ioapic: Some(IoApic {
                id: 0,
                address: 0xFEC00000,
                global_interrupt_base: 0,
            }),
            overrides: overrides_array(&[IrqOverride {
                source: 9,
                global_interrupt: 9,
                flags: 3,
            }]),
            override_count: 1,
        }
    }

    /// Hand-built MADT: one LAPIC, one unknown type (0x80), one IOAPIC, and a
    /// truncated trailing entry (claims 10 bytes with only 2 remaining).
    fn manual_madt() -> ([u8; 256], usize) {
        let mut b = [0u8; 256];
        b[0..4].copy_from_slice(b"APIC");
        b[9] = 1;
        b[36..40].copy_from_slice(&0xFEE00000u32.to_le_bytes());
        b[40..44].copy_from_slice(&0u32.to_le_bytes());
        let mut len = 44usize;
        b[len..len + 8].copy_from_slice(&[0u8, 8, 0, 0, 1, 0, 0, 0]); // LAPIC enabled
        len += 8;
        b[len..len + 4].copy_from_slice(&[0x80u8, 4, 0xAA, 0xBB]); // unknown type
        len += 4;
        b[len..len + 12].copy_from_slice(&[1u8, 12, 3, 0, 0x00, 0x00, 0xC0, 0xFE, 0, 0, 0, 0]);
        len += 12;
        b[len..len + 2].copy_from_slice(&[0u8, 10]); // truncated entry
        len += 2;
        b[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        set_checksum(&mut b, len);
        (b, len)
    }

    /// Test-only physical-memory reader over synthetic regions.
    struct RegionReader<'a> {
        regions: &'a [(u64, &'a [u8])],
    }

    impl<'a> PhysRead for RegionReader<'a> {
        fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
            for (base, buf) in self.regions {
                if addr >= *base && addr + len as u64 <= *base + buf.len() as u64 {
                    let off = (addr - base) as usize;
                    return Some(&buf[off..off + len]);
                }
            }
            None
        }
    }

    #[test]
    fn parse_rsdp_valid_acpi10() {
        let rsdp = make_rsdp(0, 0x12345678, 0);
        let p = parse_rsdp(&rsdp).expect("acpi 1.0 rsdp must parse");
        assert_eq!(p.revision, 0);
        assert_eq!(p.rsdt_address, 0x12345678);
        assert_eq!(p.xsdt_address, 0);
    }

    #[test]
    fn parse_rsdp_valid_acpi20_with_xsdt() {
        let rsdp = make_rsdp(2, 0x12345678, 0x1234567890);
        let p = parse_rsdp(&rsdp).expect("acpi 2.0 rsdp must parse");
        assert_eq!(p.revision, 2);
        assert_eq!(p.rsdt_address, 0x12345678);
        assert_eq!(p.xsdt_address, 0x1234567890);
    }

    #[test]
    fn parse_rsdp_rejects_bad_signature() {
        let mut rsdp = make_rsdp(1, 0x1234, 0);
        rsdp[0] = b'X';
        assert_eq!(parse_rsdp(&rsdp), None);
        let mut tail = make_rsdp(1, 0x1234, 0);
        tail[7] = b'X';
        assert_eq!(parse_rsdp(&tail), None);
    }

    #[test]
    fn parse_rsdp_rejects_bad_checksum() {
        let mut rsdp = make_rsdp(2, 0x1234, 0x99);
        rsdp[8] ^= 0xFF;
        assert_eq!(parse_rsdp(&rsdp), None);
        let mut ext = make_rsdp(2, 0x1234, 0x99);
        ext[32] ^= 0xFF;
        assert_eq!(parse_rsdp(&ext), None);
    }

    #[test]
    fn parse_rsdp_rejects_truncated() {
        let rsdp = make_rsdp(0, 0x1234, 0);
        assert_eq!(parse_rsdp(&rsdp[..20]), None);
        assert_eq!(parse_rsdp(&rsdp[..35]), None);
    }

    #[test]
    fn parse_rsdp_rejects_future_revision() {
        let mut rsdp = make_rsdp(2, 0x1234, 0x99);
        rsdp[15] = 3;
        rechecksum_rsdp(&mut rsdp);
        assert_eq!(parse_rsdp(&rsdp), None);
    }

    #[test]
    fn scan_rsdp_finds_at_aligned_offset_in_garbage() {
        let rsdp = make_rsdp(2, 0x1000, 0x2000);
        let mut buf = [0xAAu8; 0x20000];
        let off = 0x1000usize;
        buf[off..off + 36].copy_from_slice(&rsdp);
        assert_eq!(scan_rsdp(&buf), Some(off));
    }

    #[test]
    fn scan_rsdp_skips_misaligned_signature() {
        let rsdp = make_rsdp(0, 0x1234, 0);
        let mut buf = [0xAAu8; 256];
        // Signature at a NON-16-aligned offset: never probed.
        buf[8..8 + 36].copy_from_slice(&rsdp);
        assert_eq!(scan_rsdp(&buf), None);
        // Even a valid RSDP at offset 9 must be skipped.
        let mut buf2 = [0u8; 256];
        buf2[9..9 + 36].copy_from_slice(&rsdp);
        assert_eq!(scan_rsdp(&buf2), None);
    }

    #[test]
    fn parse_sdt_header_rejects_bad_checksum() {
        let mut b = [0u8; 36];
        b[0..4].copy_from_slice(b"FACP");
        b[4..8].copy_from_slice(&36u32.to_le_bytes());
        b[9] = 1;
        set_checksum(&mut b, 36);
        assert!(parse_sdt_header(&b).is_some());
        b[8] ^= 0xFF;
        assert_eq!(parse_sdt_header(&b), None);
    }

    #[test]
    fn parse_rsdt_reads_32bit_entries() {
        let (tbl, len) = make_rsdt(&[0x1000, 0x2000, 0x3000]);
        let l = parse_table_entries(&tbl[..len]).expect("rsdt must parse");
        assert_eq!(l.count, 3);
        assert_eq!(l.entries[0], 0x1000);
        assert_eq!(l.entries[1], 0x2000);
        assert_eq!(l.entries[2], 0x3000);
    }

    #[test]
    fn parse_xsdt_reads_64bit_entries() {
        let (tbl, len) = make_xsdt(&[0x1000, 0x2000, 0x4000]);
        let l = parse_table_entries(&tbl[..len]).expect("xsdt must parse");
        assert_eq!(l.count, 3);
        assert_eq!(l.entries[0], 0x1000);
        assert_eq!(l.entries[1], 0x2000);
        assert_eq!(l.entries[2], 0x4000);
    }

    #[test]
    fn parse_xsdt_rejects_entry_above_4gb() {
        let (tbl, len) = make_xsdt(&[0x1000, 0x1_0000_0000, 0x3000]);
        assert_eq!(parse_table_entries(&tbl[..len]), None);
        let (ok, olen) = make_xsdt(&[0x1000, 0xFFFF_FFFF, 0x3000]);
        assert!(parse_table_entries(&ok[..olen]).is_some());
    }

    #[test]
    fn parse_table_entries_honors_length_and_bounds() {
        // Declared length overruns the buffer: honest partial.
        let (tbl, len) = make_rsdt(&[0x1000, 0x2000]);
        let cut = &tbl[..38]; // 36 + 2 bytes of the first entry only
        let l = parse_table_entries(cut).expect("partial rsdt must parse");
        assert_eq!(l.count, 0);
        assert!(len > 38);

        // MAX_TABLES caps a huge list.
        let mut many = [0u32; 32];
        for (i, e) in many.iter_mut().enumerate() {
            *e = 0x1000 + i as u32 * 0x100;
        }
        let (big, blen) = make_rsdt(&many);
        let l = parse_table_entries(&big[..blen]).expect("big rsdt must parse");
        assert_eq!(l.count, MAX_TABLES);
        assert_eq!(
            l.entries[MAX_TABLES - 1],
            0x1000 + (MAX_TABLES - 1) as u32 * 0x100
        );

        // Wrong signature is rejected.
        let mut bad = [0u8; 36];
        bad[0..4].copy_from_slice(b"FACP");
        assert_eq!(parse_table_entries(&bad), None);
        // Header-only table parses with zero entries.
        let (hdr, hlen) = make_rsdt(&[]);
        assert_eq!(parse_table_entries(&hdr[..hlen]).unwrap().count, 0);
    }

    #[test]
    fn parse_madt_two_cpus_ioapic_override() {
        let m = sample_madt();
        let (buf, len) = build_madt(&m);
        let p = parse_madt(&buf[..len]).expect("madt must parse");
        assert_eq!(p.lapic_address, 0xFEE00000);
        assert_eq!(p.flags, 1);
        assert_eq!(p.cpu_count, 2);
        assert_eq!(p.cpus[0], lapic(0, 0, true));
        assert_eq!(p.cpus[1], lapic(1, 1, true));
        assert_eq!(p.cpus[2], lapic(0, 0, false));
        let io = p.ioapic.expect("ioapic must be present");
        assert_eq!(io.id, 0);
        assert_eq!(io.address, 0xFEC00000);
        assert_eq!(io.global_interrupt_base, 0);
        assert_eq!(p.override_count, 1);
        assert_eq!(p.overrides[0].source, 9);
        assert_eq!(p.overrides[0].global_interrupt, 9);
        assert_eq!(p.overrides[0].flags, 3);
    }

    #[test]
    fn parse_madt_skips_unknown_types_and_truncation() {
        let (buf, len) = manual_madt();
        let p = parse_madt(&buf[..len]).expect("manual madt must parse");
        assert_eq!(p.cpu_count, 1);
        assert_eq!(p.cpus[0], lapic(0, 0, true));
        // Unknown type 0x80 skipped, IOAPIC kept, truncated entry stops cleanly.
        let io = p.ioapic.expect("ioapic must be present");
        assert_eq!(io.id, 3);
        assert_eq!(io.address, 0xFEC00000);
        assert_eq!(p.override_count, 0);
    }

    #[test]
    fn parse_madt_rejects_bad_checksum() {
        let (mut buf, len) = manual_madt();
        buf[8] ^= 0xFF;
        assert_eq!(parse_madt(&buf[..len]), None);
    }

    #[test]
    fn parse_madt_bounds_checked() {
        // Ten LAPIC entries: capped at MAX_CPUS; a length-byte < 2 stops the
        // walk without panicking.
        let mut b = [0u8; 256];
        b[0..4].copy_from_slice(b"APIC");
        b[9] = 1;
        b[36..40].copy_from_slice(&0xFEE00000u32.to_le_bytes());
        b[40..44].copy_from_slice(&0u32.to_le_bytes());
        let mut len = 44usize;
        for i in 0..10u8 {
            b[len..len + 8].copy_from_slice(&[0u8, 8, i, i, 1, 0, 0, 0]);
            len += 8;
        }
        b[len..len + 2].copy_from_slice(&[0x80u8, 1]); // elen < 2 -> stop
        len += 2;
        b[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        set_checksum(&mut b, len);
        let p = parse_madt(&b[..len]).expect("must parse cleanly");
        assert_eq!(p.cpu_count, MAX_CPUS);
        assert_eq!(p.cpus[0].apic_id, 0);
        assert_eq!(p.cpus[7].apic_id, 7);
    }

    #[test]
    fn smp_info_counts_only_enabled_cpus() {
        let m = Madt {
            lapic_address: 0xFEE00000,
            flags: 0,
            cpus: cpus_array(&[
                lapic(0, 0, true),
                lapic(1, 1, false),
                lapic(2, 2, true),
                lapic(3, 3, false),
            ]),
            cpu_count: 4,
            ioapic: Some(IoApic {
                id: 0,
                address: 0xFEC00000,
                global_interrupt_base: 24,
            }),
            overrides: overrides_array(&[]),
            override_count: 0,
        };
        let s = smp_info_from_madt(&m);
        assert_eq!(s.cpu_count, 2);
        assert_eq!(s.apic_ids[0], 0);
        assert!(!s.enabled[1]);
        assert_eq!(s.apic_ids[2], 2);
        assert!(!s.enabled[3]);
        assert_eq!(s.lapic_address, 0xFEE00000);
        assert_eq!(s.ioapic.unwrap().global_interrupt_base, 24);
    }

    #[test]
    fn discover_end_to_end_over_synthetic_f_segment() {
        let mut fseg = [0xAAu8; F_SEG_LEN as usize];
        let madt_addr = 0xF1000u64;
        let rsdt_addr = 0xF0000u64;
        let m = sample_madt();
        let (madt_buf, madt_len) = build_madt(&m);
        let moff = (madt_addr - F_SEG_START) as usize;
        fseg[moff..moff + madt_len].copy_from_slice(&madt_buf[..madt_len]);
        let (rsdt, rsdt_len) = make_rsdt(&[madt_addr as u32]);
        let roff = (rsdt_addr - F_SEG_START) as usize;
        fseg[roff..roff + rsdt_len].copy_from_slice(&rsdt[..rsdt_len]);
        let rsdp = make_rsdp(1, rsdt_addr as u32, 0);
        let soff = 0x800usize; // 16-aligned
        fseg[soff..soff + 36].copy_from_slice(&rsdp);

        let region_list: [(u64, &[u8]); 1] = [(F_SEG_START, &fseg)];
        let reader = RegionReader {
            regions: &region_list,
        };
        let d = discover_core(&reader, &[]).expect("synthetic f-seg must be discovered");
        assert_eq!(d.rsdp.revision, 1);
        assert_eq!(d.rsdp.rsdt_address, rsdt_addr as u32);
        assert_eq!(d.rsdp_offset, F_SEG_START + soff as u64);
        assert_eq!(&d.root_signature, b"RSDT");
        assert_eq!(d.root_entries.count, 1);
        assert_eq!(d.root_entries.entries[0], madt_addr as u32);
        assert_eq!(d.madt_address, madt_addr);
        let madt = d.madt.expect("madt must be parsed");
        assert_eq!(madt.cpu_count, 2);
        assert_eq!(madt.ioapic.unwrap().address, 0xFEC00000);
        assert_eq!(d.smp.cpu_count, 2);
        assert_eq!(d.smp.apic_ids[0], 0);
        assert_eq!(d.smp.apic_ids[1], 1);
    }

    #[test]
    fn discover_absent_on_empty_f_segment() {
        let fseg = [0u8; F_SEG_LEN as usize];
        let region_list: [(u64, &[u8]); 1] = [(F_SEG_START, &fseg)];
        let reader = RegionReader {
            regions: &region_list,
        };
        assert_eq!(discover_core(&reader, &[]), None);
    }

    #[test]
    fn discover_absent_when_acpi_range_has_no_rsdp() {
        let fseg = [0u8; F_SEG_LEN as usize];
        let region_list: [(u64, &[u8]); 1] = [(F_SEG_START, &fseg)];
        let reader = RegionReader {
            regions: &region_list,
        };
        let empty_range: [(u64, u64); 1] = [(0x1FB70000u64, 0x12000u64)];
        assert_eq!(discover_core(&reader, &empty_range), None);
    }

    #[test]
    fn acpi_ranges_from_map_collects_reclaim_and_nvs_only() {
        let entries = [
            crate::boot_info::MapEntry {
                ty: crate::boot_info::TYPE_CONVENTIONAL,
                base: 0x100000,
                pages: 100,
            },
            crate::boot_info::MapEntry {
                ty: crate::boot_info::TYPE_ACPI_RECLAIM,
                base: 0x1FB6D000,
                pages: 18,
            },
            crate::boot_info::MapEntry {
                ty: crate::boot_info::TYPE_ACPI_NVS,
                base: 0x800000,
                pages: 8,
            },
            crate::boot_info::MapEntry {
                ty: 0, // EfiReservedMemoryType — must be ignored
                base: 0x900000,
                pages: 4,
            },
        ];
        let (ranges, n) = acpi_ranges_from_map(&entries);
        assert_eq!(n, 2);
        assert_eq!(ranges[0], (0x1FB6D000, 18 * 4096));
        assert_eq!(ranges[1], (0x800000, 8 * 4096));
    }

    #[test]
    fn discover_via_acpi_range_when_absent_from_f_segment() {
        // OVMF-style: F-seg empty, RSDP/RSDT/MADT high in an ACPI Reclaim
        // region the boot memory map reported.
        let fseg = [0u8; F_SEG_LEN as usize];
        let acpi_base = 0x1FB70000u64;
        let madt_addr = acpi_base + 0x1000;
        let rsdt_addr = acpi_base + 0x3000;
        let rsdp_addr = acpi_base + 0x4000;
        let mut acpi_region = [0xAAu8; 0x12000];
        let m = sample_madt();
        let (madt_buf, madt_len) = build_madt(&m);
        acpi_region[0x1000..0x1000 + madt_len].copy_from_slice(&madt_buf[..madt_len]);
        let (rsdt, rsdt_len) = make_rsdt(&[madt_addr as u32]);
        acpi_region[0x3000..0x3000 + rsdt_len].copy_from_slice(&rsdt[..rsdt_len]);
        let rsdp = make_rsdp(1, rsdt_addr as u32, 0);
        acpi_region[0x4000..0x4000 + 36].copy_from_slice(&rsdp);

        let region_list: [(u64, &[u8]); 2] = [(F_SEG_START, &fseg), (acpi_base, &acpi_region)];
        let reader = RegionReader {
            regions: &region_list,
        };
        let acpi_ranges: [(u64, u64); 1] = [(acpi_base, 0x12000u64)];
        let d = discover_core(&reader, &acpi_ranges).expect("acpi-region rsdp must be found");
        assert_eq!(d.rsdp_offset, rsdp_addr);
        assert_eq!(&d.root_signature, b"RSDT");
        assert_eq!(d.madt_address, madt_addr);
        assert_eq!(d.smp.cpu_count, 2);
    }

    #[test]
    fn discover_ignores_acpi_range_above_4g() {
        let fseg = [0u8; F_SEG_LEN as usize];
        let region_list: [(u64, &[u8]); 1] = [(F_SEG_START, &fseg)];
        let reader = RegionReader {
            regions: &region_list,
        };
        let ranges: [(u64, u64); 1] = [(0x1_0000_1000u64, 0x1000u64)];
        assert_eq!(discover_core(&reader, &ranges), None);
    }

    #[test]
    fn build_rsdp_round_trips() {
        for rev in [0u8, 1, 2] {
            let rsdt = 0x12345678u32;
            let xsdt = 0x1234567890u64;
            let b = build_rsdp(rev, rsdt, xsdt);
            let p = parse_rsdp(&b).expect("built rsdp must parse");
            assert_eq!(p.revision, rev);
            assert_eq!(p.rsdt_address, rsdt);
            assert_eq!(p.xsdt_address, if rev >= 2 { xsdt } else { 0 });
        }
    }

    #[test]
    fn build_madt_round_trips() {
        let m = sample_madt();
        let (buf, len) = build_madt(&m);
        // 44 + 2*8 + 12 + 10 = 82
        assert_eq!(len, 82);
        let p = parse_madt(&buf[..len]).expect("built madt must parse");
        assert_eq!(p, m);
    }
}

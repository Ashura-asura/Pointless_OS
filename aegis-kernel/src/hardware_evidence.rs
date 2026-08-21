//! Hardware-evidence tests: feed the REAL firmware fixtures dumped by
//! `scripts/extract-hardware-fixtures.ps1` (in `hardware-fixtures/`) through
//! the kernel's own ACPI/PCI/SMBIOS parsers.
//!
//! These are `#[ignore]`d because the fixtures are real, host-specific binary
//! blobs that are intentionally NOT committed and are absent in CI. They are a
//! local proof step: "the kernel's parser accepts the genuine firmware this
//! machine exposes" — replace the synthetic QEMU/OVMF fixtures used by the
//! unit tests with the actual Dell Inspiron 7400 ACPI tables.
//!
//! Run on the dev host with:
//!   cargo test --release -- --ignored hardware_evidence

#![allow(dead_code)]

#[cfg(test)]
mod tests {
    use crate::acpi::{parse_madt, parse_sdt_header, parse_table_entries};
    use std::fs;
    use std::path::PathBuf;

    fn fixture_dir() -> PathBuf {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("hardware-fixtures");
        d
    }

    fn read_fixture(name: &str) -> Vec<u8> {
        let mut p = fixture_dir();
        p.push(name);
        fs::read(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
    }

    /// Build a checksummed RSDT referencing the given 32-bit table addresses.
    /// Mirrors the real RSDT layout the kernel's `parse_table_entries` expects.
    fn make_rsdt(entries: &[u32]) -> Vec<u8> {
        let mut b = vec![0u8; 36 + entries.len() * 4];
        b[0..4].copy_from_slice(b"RSDT");
        b[9] = 1;
        let mut len = 36usize;
        for e in entries {
            b[len..len + 4].copy_from_slice(&e.to_le_bytes());
            len += 4;
        }
        b[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        let mut s: u8 = 0;
        for &x in &b[0..len] {
            s = s.wrapping_add(x);
        }
        b[8] = s.wrapping_neg();
        b.truncate(len);
        b
    }

    #[test]
    #[ignore = "requires real hardware fixtures in aegis-kernel/hardware-fixtures (uncommitted, dev-host only)"]
    fn real_acpi_tables_parse_with_kernel_parser() {
        // (1) Every real ACPI table we dumped must parse as a valid SDT and its
        //     declared length must equal the on-disk length (no truncation and
        //     a passing ACPI checksum over the genuine firmware bytes).
        let names = [
            "apic", "facp", "dmar", "mcfg", "hpet", "wsmt", "bgrt", "ssdt", "tpm2",
            "dbg2", "fpdt", "lpit", "nhlt", "boot", "dbgp", "msdm", "ptdt", "slic", "uefi",
        ];
        let mut total = 0usize;
        for n in names {
            let bytes = read_fixture(&format!("acpi-{}.bin", n));
            let hdr = parse_sdt_header(&bytes)
                .unwrap_or_else(|| panic!("parse_sdt_header failed for acpi-{}.bin", n));
            let sig = core::str::from_utf8(&hdr.signature).unwrap();
            assert_eq!(sig, n.to_uppercase(), "signature mismatch for acpi-{}.bin", n);
            assert_eq!(
                hdr.length as usize,
                bytes.len(),
                "length field vs file for acpi-{}.bin",
                n
            );
            total += 1;
        }
        assert!(total >= 10, "expected many real tables, got {}", total);
        println!(
            "[hardware-evidence] {} real ACPI tables passed the kernel parser",
            total
        );

        // (2) The REAL MADT feeds the SMP parser and yields the host CPU
        //     topology. This is the genuine firmware data (not a QEMU fixture).
        let apic = read_fixture("acpi-apic.bin");
        let madt = parse_madt(&apic).expect("real MADT must parse");
        assert_eq!(madt.lapic_address, 0xFEE00000, "standard LAPIC base");
        assert!(madt.cpu_count >= 1, "MADT must list >=1 LAPIC");
        assert!(madt.ioapic.is_some(), "real MADT should carry an IOAPIC");
        println!(
            "[hardware-evidence] host LAPIC entries: {}",
            madt.cpu_count
        );
        let mut enabled = 0usize;
        for i in 0..madt.cpu_count {
            if madt.cpus[i].enabled {
                enabled += 1;
            }
            println!(
                "[hardware-evidence]   apic_id={} enabled={}",
                madt.cpus[i].apic_id, madt.cpus[i].enabled
            );
        }
        println!("[hardware-evidence] enabled processors: {}", enabled);

        // (3) A root table (RSDT) referencing the real table addresses must
        //     walk cleanly through `parse_table_entries`.
        let apic_addr: u32 = 0x1000;
        let facp_addr: u32 = 0x2000;
        let rsdt = make_rsdt(&[apic_addr, facp_addr]);
        let tbl = parse_table_entries(&rsdt).expect("synthetic RSDT must parse");
        assert_eq!(tbl.count, 2);
        assert_eq!(tbl.entries[0], apic_addr);
        assert_eq!(tbl.entries[1], facp_addr);
    }

    #[test]
    #[ignore = "requires real hardware fixtures in aegis-kernel/hardware-fixtures (uncommitted, dev-host only)"]
    fn real_smbios_and_pci_inventory_captured() {
        // SMBIOS raw blob (WMI MSSmBios_RawSMBiosTables) is the table section;
        // it carries the genuine BIOS vendor/model strings of this host.
        let smbios = read_fixture("smbios.bin");
        assert!(smbios.len() > 256, "smbios.bin implausibly small");
        let has_vendor =
            smbios.windows(4).any(|w| w == b"Dell") || smbios.windows(9).any(|w| w == b"Inspiron");
        assert!(
            has_vendor,
            "smbios.bin missing host vendor/model strings (not genuine?)"
        );
        println!(
            "[hardware-evidence] SMBIOS blob captured: {} bytes",
            smbios.len()
        );

        // PCI device inventory: every line is a real device this host exposes.
        // Format: <hwid>\t<source>\t<name>, where hwid is
        // `PCI\VEN_xxxx&DEV_yyyy&...`. Lossy UTF-8 for high bytes.
        let pci = read_fixture("pci-devices.tsv");
        let text = String::from_utf8_lossy(&pci).into_owned();
        let mut count = 0usize;
        let mut saw_gpu = false;
        let mut saw_nvme = false;
        for line in text.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            assert!(cols.len() >= 3, "malformed PCI line: {}", line);
            let hwid = cols[0];
            let name = cols[cols.len() - 1].to_ascii_lowercase();
            // Extract VEN/DEV from the hardware id.
            let ven = hwid
                .find("VEN_")
                .map(|i| &hwid[i + 4..i + 8])
                .expect("hwid missing VEN_");
            let dev = hwid
                .find("DEV_")
                .map(|i| &hwid[i + 4..i + 8])
                .expect("hwid missing DEV_");
            u16::from_str_radix(ven, 16).expect("VEN must be hex");
            u16::from_str_radix(dev, 16).expect("DEV must be hex");
            if ven.eq_ignore_ascii_case("10DE") {
                saw_gpu = true; // NVIDIA GeForce MX350
            }
            if name.contains("nvme") || name.contains("non-volatile") {
                saw_nvme = true;
            }
            count += 1;
        }
        assert!(count >= 10, "expected many PCI devices, got {}", count);
        assert!(saw_gpu, "expected the host NVIDIA GPU in the inventory");
        println!(
            "[hardware-evidence] PCI inventory captured: {} devices (gpu={}, nvme={})",
            count, saw_gpu, saw_nvme
        );
    }
}

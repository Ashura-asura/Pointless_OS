// Windows PE binary loader (Phase 9).
//
// Parses the PE32+ (x64) format for the narrow, well-behaved app subset of
// the Windows compatibility layer: MZ signature, PE signature, machine type,
// optional-header entry point, and the section table with bounds checks.
// Honest limits: this proves the parse/mapping-plan logic against byte
// buffers; it does not map images into memory (that is the VM-based
// full-fidelity vehicle, not built in Phase 9). The design doc is explicit
// that full Windows compatibility is not solved by translation alone.

const MZ_MAGIC: u16 = 0x5A4D; // 'MZ'
const PE_MAGIC: u32 = 0x0000_4550; // 'PE\0\0'
const MACHINE_AMD64: u16 = 0x8664;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x20B;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const MAX_SECTIONS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeSection {
    pub name: [u8; 8],
    pub virtual_addr: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeImage {
    pub entry: u64,
    pub image_base: u64,
    pub sections: [PeSection; MAX_SECTIONS],
    pub section_count: usize,
    pub is_64bit: bool,
}

impl PeSection {
    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
}

fn u16_at(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn u32_at(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn u64_at(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

pub fn parse_pe(data: &[u8]) -> Result<PeImage, &'static str> {
    if data.len() < 64 {
        return Err("file too small");
    }
    if u16_at(data, 0) != MZ_MAGIC {
        return Err("missing MZ signature");
    }
    let pe_off = u32_at(data, 0x3C) as usize;
    if pe_off.checked_add(24).is_none_or(|end| end > data.len()) {
        return Err("PE header out of bounds");
    }
    if u32_at(data, pe_off) != PE_MAGIC {
        return Err("missing PE signature");
    }
    let machine = u16_at(data, pe_off + 4);
    if machine != MACHINE_AMD64 {
        return Err("not AMD64 machine");
    }
    let num_sections = u16_at(data, pe_off + 6) as usize;
    if num_sections == 0 || num_sections > MAX_SECTIONS {
        return Err("invalid section count");
    }
    let opt_size = u16_at(data, pe_off + 20) as usize;
    let opt_off = pe_off
        .checked_add(24)
        .ok_or("optional header offset overflow")?;
    if opt_off.checked_add(64).is_none_or(|end| end > data.len()) {
        return Err("optional header out of bounds");
    }
    let opt_magic = u16_at(data, opt_off);
    if opt_magic != OPTIONAL_MAGIC_PE32_PLUS {
        return Err("not PE32+ (x64)");
    }
    let entry = u32_at(data, opt_off + 16) as u64;
    let image_base = u64_at(data, opt_off + 24);

    let section_table = opt_off
        .checked_add(opt_size)
        .ok_or("section table offset overflow")?;
    let section_bytes = num_sections
        .checked_mul(40)
        .ok_or("section table offset overflow")?;
    if section_table
        .checked_add(section_bytes)
        .is_none_or(|end| end > data.len())
    {
        return Err("section table out of bounds");
    }
    let mut sections = [PeSection {
        name: [0; 8],
        virtual_addr: 0,
        virtual_size: 0,
        raw_size: 0,
        characteristics: 0,
    }; MAX_SECTIONS];
    for (i, section) in sections.iter_mut().enumerate().take(num_sections) {
        let s = section_table
            .checked_add(i * 40)
            .ok_or("section entry offset overflow")?;
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[s..s + 8]);
        *section = PeSection {
            name,
            virtual_addr: u32_at(data, s + 12),
            virtual_size: u32_at(data, s + 8),
            raw_size: u32_at(data, s + 16),
            characteristics: u32_at(data, s + 36),
        };
    }

    Ok(PeImage {
        entry,
        image_base,
        sections,
        section_count: num_sections,
        is_64bit: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE32+ file with the given number of zeroed sections.
    fn build_pe(num_sections: usize) -> Vec<u8> {
        let mut data = vec![0u8; 512 + num_sections * 40];
        // MZ header + pointer to PE header at 0x3C
        data[0..2].copy_from_slice(&MZ_MAGIC.to_le_bytes());
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature
        data[0x80..0x84].copy_from_slice(&PE_MAGIC.to_le_bytes());
        // Machine
        data[0x84..0x86].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        // Number of sections
        data[0x86..0x88].copy_from_slice(&(num_sections as u16).to_le_bytes());
        // Optional header size (PE32+ 64 bytes)
        data[0x94..0x96].copy_from_slice(&64u16.to_le_bytes());
        // Optional header starts at 0x98
        data[0x98..0x9A].copy_from_slice(&OPTIONAL_MAGIC_PE32_PLUS.to_le_bytes());
        // AddressOfEntryPoint at opt+16, ImageBase at opt+24
        data[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0xB0..0xB8].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        data
    }

    #[test]
    fn valid_pe_parses() {
        let data = build_pe(2);
        let img = parse_pe(&data).unwrap();
        assert_eq!(img.entry, 0x1000);
        assert_eq!(img.image_base, 0x1_4000_0000);
        assert_eq!(img.section_count, 2);
        assert!(img.is_64bit);
    }

    #[test]
    fn section_table_populated() {
        let mut data = build_pe(1);
        // Section at 0x98 + 64 = 0xD8; set name ".text" and flags RX
        let s = 0xD8;
        data[s..s + 5].copy_from_slice(b".text");
        data[s + 8..s + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual size
        data[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual addr
        data[s + 16..s + 20].copy_from_slice(&0x0200u32.to_le_bytes()); // raw size
        data[s + 36..s + 40]
            .copy_from_slice(&(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE).to_le_bytes());
        let img = parse_pe(&data).unwrap();
        let sec = img.sections[0];
        assert_eq!(&sec.name[..5], b".text");
        assert!(sec.is_readable());
        assert!(sec.is_executable());
        assert!(!sec.is_writable());
    }

    #[test]
    fn rejects_pe32_not_pe32_plus() {
        let mut data = build_pe(1);
        data[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes());
        assert_eq!(parse_pe(&data), Err("not PE32+ (x64)"));
    }

    #[test]
    fn rejects_wrong_machine() {
        let mut data = build_pe(1);
        data[0x84..0x86].copy_from_slice(&0x14Cu16.to_le_bytes()); // I386
        assert_eq!(parse_pe(&data), Err("not AMD64 machine"));
    }

    #[test]
    fn rejects_missing_mz() {
        let mut data = build_pe(1);
        data[0] = 0;
        data[1] = 0;
        assert_eq!(parse_pe(&data), Err("missing MZ signature"));
    }

    #[test]
    fn rejects_missing_pe_signature() {
        let mut data = build_pe(1);
        data[0x80..0x84].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_pe(&data), Err("missing PE signature"));
    }

    #[test]
    fn rejects_zero_sections() {
        let data = build_pe(0);
        assert_eq!(parse_pe(&data), Err("invalid section count"));
    }

    #[test]
    fn rejects_too_many_sections() {
        let data = build_pe(17);
        assert_eq!(parse_pe(&data), Err("invalid section count"));
    }

    #[test]
    fn rejects_truncated_file() {
        let mut data = build_pe(3);
        data.truncate(100);
        assert!(parse_pe(&data).is_err());
    }

    #[test]
    fn writable_section_detected() {
        let mut data = build_pe(1);
        let s = 0xD8;
        data[s..s + 5].copy_from_slice(b".data");
        data[s + 36..s + 40]
            .copy_from_slice(&(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE).to_le_bytes());
        let img = parse_pe(&data).unwrap();
        assert!(img.sections[0].is_writable());
        assert!(!img.sections[0].is_executable());
    }

    #[test]
    fn entry_point_within_image() {
        let data = build_pe(1);
        let img = parse_pe(&data).unwrap();
        assert_eq!(img.entry, 0x1000);
        assert!(img.entry < 0x1000_0000);
    }
}

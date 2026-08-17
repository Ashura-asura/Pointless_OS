//! Minimal ELF64 parser for loading kernel binaries.
//! Pure logic — no hardware dependencies — fully testable.

use alloc::vec::Vec;
extern crate alloc;

/// ELF64 header magic and class
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1; // Little-endian
const ET_EXEC: u16 = 2; // Executable file
const ET_DYN: u16 = 3; // Shared object / PIE (freestanding kernels link as PIE)
const EM_X86_64: u16 = 0x3E; // x86_64

/// Program header types
const PT_LOAD: u32 = 1;

/// Relocation types (x86_64 ABI, ELF64)
/// R_X86_64_RELATIVE = 8: B + A. With a link-time base of 0 (the convention
/// for freestanding PIE kernels), the runtime value equals the addend alone.
const R_X86_64_RELATIVE: u64 = 8;

/// Program header flags
/// Documented ELF p_flags values. Not referenced by the current boot path
/// (the kernel loader has not yet mapped segment permissions); reserved for
/// page-permission mapping when per-segment protection is enforced.
#[allow(dead_code)]
const PF_X: u32 = 1; // Execute
#[allow(dead_code)]
const PF_W: u32 = 2; // Write
#[allow(dead_code)]
const PF_R: u32 = 4; // Read

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfError;

/// Parsed ELF64 program header (one loadable segment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHeader {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

/// One base-0 relative relocation to apply after segments are loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    pub offset: u64,
    pub addend: u64,
}

/// Parsed ELF64 binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfBinary {
    pub entry: u64,
    pub segments: [ProgramHeader; 16], // Max 16 loadable segments
    pub segment_count: usize,
    pub relocations: Vec<Relocation>,
}

/// Parse an ELF64 executable binary from a byte slice.
///
/// Validates:
/// - Magic bytes (7F 45 4C 46)
/// - Class (ELFCLASS64)
/// - Endianness (little-endian)
/// - Type (ET_EXEC or ET_DYN; PIE kernels link with link-time base 0, so
///   segments load at their p_vaddr directly)
/// - Machine (EM_X86_64)
/// - At least one PT_LOAD segment
/// - No more than 16 loadable segments
pub fn parse_elf(data: &[u8]) -> Result<ElfBinary, ElfError> {
    // Minimum ELF header size: 64 bytes
    if data.len() < 64 {
        return Err(ElfError);
    }

    // Check magic
    if data[0..4] != ELF_MAGIC {
        return Err(ElfError);
    }
    // Check class (ELF64)
    if data[4] != ELFCLASS64 {
        return Err(ElfError);
    }
    // Check endianness (little-endian)
    if data[5] != ELFDATA2LSB {
        return Err(ElfError);
    }

    // e_type at offset 16 (2 bytes LE)
    let e_type = u16::from_le_bytes([data[16], data[17]]);
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfError);
    }

    // e_machine at offset 18 (2 bytes LE)
    let e_machine = u16::from_le_bytes([data[18], data[19]]);
    if e_machine != EM_X86_64 {
        return Err(ElfError);
    }

    // e_entry at offset 24 (8 bytes LE)
    let entry = u64::from_le_bytes(data[24..32].try_into().unwrap());

    // e_phoff at offset 32 (8 bytes LE) — program header table offset
    let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;

    // e_phentsize at offset 54 (2 bytes LE)
    let phentsize = u16::from_le_bytes([data[54], data[55]]) as usize;

    // e_phnum at offset 56 (2 bytes LE)
    let phnum = u16::from_le_bytes([data[56], data[57]]) as usize;

    if phentsize == 0 || phnum == 0 {
        return Err(ElfError);
    }

    // Parse program headers
    let mut segments = [ProgramHeader {
        vaddr: 0,
        offset: 0,
        filesz: 0,
        memsz: 0,
        flags: 0,
    }; 16];
    let mut segment_count = 0usize;

    for i in 0..phnum {
        if segment_count >= 16 {
            return Err(ElfError); // Too many segments
        }
        let start = phoff + i * phentsize;
        if start + phentsize > data.len() {
            return Err(ElfError);
        }

        let p_type = u32::from_le_bytes(data[start..start + 4].try_into().unwrap());
        let p_flags = u32::from_le_bytes(data[start + 4..start + 8].try_into().unwrap());
        let p_offset = u64::from_le_bytes(data[start + 8..start + 16].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(data[start + 16..start + 24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(data[start + 32..start + 40].try_into().unwrap());
        let p_memsz = u64::from_le_bytes(data[start + 40..start + 48].try_into().unwrap());

        if p_type == PT_LOAD {
            segments[segment_count] = ProgramHeader {
                vaddr: p_vaddr,
                offset: p_offset,
                filesz: p_filesz,
                memsz: p_memsz,
                flags: p_flags,
            };
            segment_count += 1;
        }
    }

    if segment_count == 0 {
        return Err(ElfError); // No loadable segments
    }

    let relocations = parse_relocations(data)?;

    Ok(ElfBinary {
        entry,
        segments,
        segment_count,
        relocations,
    })
}

/// Parse base-0 relocations (.rela.dyn/.rela.plt section headers).
///
/// Freestanding PIE kernels link with a link-time base of 0; every
/// R_X86_64_RELATIVE entry must be materialized by the loader writing
/// (base + addend) into the slot, which is simply the addend here. Any
/// other relocation type is rejected: symbolic relocations cannot be
/// resolved without a dynamic loader, so the binary is not loadable.
fn parse_relocations(data: &[u8]) -> Result<Vec<Relocation>, ElfError> {
    // e_shoff at 0x28, e_shentsize at 0x3A, e_shnum at 0x3C, e_shstrndx at 0x3E
    let shoff = u64::from_le_bytes(data[0x28..0x30].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes([data[0x3A], data[0x3B]]) as usize;
    let shnum = u16::from_le_bytes([data[0x3C], data[0x3D]]) as usize;
    let shstrndx = u16::from_le_bytes([data[0x3E], data[0x3F]]) as usize;

    if shoff == 0 || shnum == 0 || shentsize < 64 {
        return Ok(Vec::new()); // No section headers: no relocations to apply
    }
    if shstrndx >= shnum {
        return Err(ElfError);
    }

    let shstr_off = shoff + shstrndx * shentsize;
    let shstr_offset = u64::from_le_bytes(
        data[shstr_off + 24..shstr_off + 32]
            .try_into()
            .map_err(|_| ElfError)?,
    ) as usize;
    let shstr_size = u64::from_le_bytes(
        data[shstr_off + 32..shstr_off + 40]
            .try_into()
            .map_err(|_| ElfError)?,
    ) as usize;
    if shstr_offset + shstr_size > data.len() {
        return Err(ElfError);
    }
    let shstrtab = &data[shstr_offset..shstr_offset + shstr_size];

    let mut relocations = Vec::new();
    for i in 0..shnum {
        let sec_off = shoff + i * shentsize;
        let name_idx = u32::from_le_bytes(
            data[sec_off..sec_off + 4]
                .try_into()
                .map_err(|_| ElfError)?,
        ) as usize;
        let sec_offset = u64::from_le_bytes(
            data[sec_off + 24..sec_off + 32]
                .try_into()
                .map_err(|_| ElfError)?,
        ) as usize;
        let sec_size = u64::from_le_bytes(
            data[sec_off + 32..sec_off + 40]
                .try_into()
                .map_err(|_| ElfError)?,
        ) as usize;

        let name_end = shstrtab[name_idx..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_idx + p)
            .unwrap_or(shstrtab.len());
        let name = &shstrtab[name_idx..name_end];
        if name != b".rela.dyn" && name != b".rela.plt" {
            continue;
        }
        if sec_offset + sec_size > data.len() || sec_size % 24 != 0 {
            return Err(ElfError);
        }

        for j in (0..sec_size).step_by(24) {
            let entry = sec_offset + j;
            let r_offset = u64::from_le_bytes(data[entry..entry + 8].try_into().unwrap());
            let r_info = u64::from_le_bytes(data[entry + 8..entry + 16].try_into().unwrap());
            let r_type = r_info & 0xFFFF_FFFF;
            let r_addend = i64::from_le_bytes(data[entry + 16..entry + 24].try_into().unwrap());
            if r_type != R_X86_64_RELATIVE {
                return Err(ElfError); // Symbolic relocs unsupported
            }
            relocations.push(Relocation {
                offset: r_offset,
                addend: r_addend as u64,
            });
        }
    }
    Ok(relocations)
}

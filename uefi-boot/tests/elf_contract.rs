//! ELF parser contract test: verifies the parser validates ELF64 headers
//! and extracts loadable segments correctly.
//!
//! Honest limits: tests the parser logic against crafted byte buffers.
//! Does NOT test actual kernel loading (requires real hardware).

use std::vec::Vec;

// We need to include the elf module from uefi-boot.
// Since uefi-boot is #![no_std], we can't use it as a test dependency directly.
// Instead, we test the parser by copying its logic into the test.
// This is a deliberate choice: the parser is pure logic with no hardware deps.

/// ELF64 constants (duplicated from the source for test independence)
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3; // Shared object / PIE (freestanding kernels link as PIE)
const EM_X86_64: u16 = 0x3E;
const PT_LOAD: u32 = 1;
const R_X86_64_RELATIVE: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ElfError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProgramHeader {
    vaddr: u64,
    offset: u64,
    filesz: u64,
    memsz: u64,
    flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Relocation {
    offset: u64,
    addend: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ElfBinary {
    entry: u64,
    segments: [ProgramHeader; 16],
    segment_count: usize,
    relocations: Vec<Relocation>,
}

fn parse_elf(data: &[u8]) -> Result<ElfBinary, ElfError> {
    if data.len() < 64 {
        return Err(ElfError);
    }
    if data[0..4] != ELF_MAGIC {
        return Err(ElfError);
    }
    if data[4] != ELFCLASS64 {
        return Err(ElfError);
    }
    if data[5] != ELFDATA2LSB {
        return Err(ElfError);
    }
    let e_type = u16::from_le_bytes([data[16], data[17]]);
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfError);
    }
    let e_machine = u16::from_le_bytes([data[18], data[19]]);
    if e_machine != EM_X86_64 {
        return Err(ElfError);
    }
    let entry = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes([data[54], data[55]]) as usize;
    let phnum = u16::from_le_bytes([data[56], data[57]]) as usize;
    if phentsize == 0 || phnum == 0 {
        return Err(ElfError);
    }
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
            return Err(ElfError);
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
        return Err(ElfError);
    }
    let relocations = parse_relocations(data)?;
    Ok(ElfBinary {
        entry,
        segments,
        segment_count,
        relocations,
    })
}

fn parse_relocations(data: &[u8]) -> Result<Vec<Relocation>, ElfError> {
    let shoff = u64::from_le_bytes(data[0x28..0x30].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes([data[0x3A], data[0x3B]]) as usize;
    let shnum = u16::from_le_bytes([data[0x3C], data[0x3D]]) as usize;
    let shstrndx = u16::from_le_bytes([data[0x3E], data[0x3F]]) as usize;

    if shoff == 0 || shnum == 0 || shentsize < 64 {
        return Ok(Vec::new());
    }
    if shstrndx as usize >= shnum as usize {
        return Err(ElfError);
    }

    let shstr_off = shoff + shstrndx as usize * shentsize;
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
        let sec_off = shoff + i as usize * shentsize;
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
                return Err(ElfError);
            }
            relocations.push(Relocation {
                offset: r_offset,
                addend: r_addend as u64,
            });
        }
    }
    Ok(relocations)
}

/// Build a minimal valid ELF64 binary in memory.
fn build_test_elf(entry: u64, segments: &[(u64, u64, u64, u32)]) -> Vec<u8> {
    let ph_offset = 64u64; // Program headers start right after ELF header
    let ph_num = segments.len() as u16;
    let mut data = vec![0u8; 64 + ph_num as usize * 56];

    // ELF header
    data[0..4].copy_from_slice(&ELF_MAGIC);
    data[4] = ELFCLASS64;
    data[5] = ELFDATA2LSB;
    data[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    data[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    data[24..32].copy_from_slice(&entry.to_le_bytes());
    data[32..40].copy_from_slice(&ph_offset.to_le_bytes());
    data[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize = 56
    data[56..58].copy_from_slice(&ph_num.to_le_bytes());

    // Program headers
    for (i, &(vaddr, offset, filesz, flags)) in segments.iter().enumerate() {
        let start = 64 + i * 56;
        data[start..start + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        data[start + 4..start + 8].copy_from_slice(&flags.to_le_bytes());
        data[start + 8..start + 16].copy_from_slice(&offset.to_le_bytes());
        data[start + 16..start + 24].copy_from_slice(&vaddr.to_le_bytes());
        data[start + 32..start + 40].copy_from_slice(&filesz.to_le_bytes());
        data[start + 40..start + 48].copy_from_slice(&(filesz).to_le_bytes()); // memsz = filesz
    }

    data
}

#[test]
fn rejects_data_shorter_than_elf_header() {
    assert_eq!(parse_elf(&[0u8; 32]), Err(ElfError));
    assert_eq!(parse_elf(&[]), Err(ElfError));
}

#[test]
fn rejects_wrong_magic() {
    let mut data = build_test_elf(0x1000, &[(0, 0, 0x1000, 5)]);
    data[0] = 0x00; // Corrupt magic
    assert_eq!(parse_elf(&data), Err(ElfError));
}

#[test]
fn rejects_wrong_class() {
    let mut data = build_test_elf(0x1000, &[(0, 0, 0x1000, 5)]);
    data[4] = 1; // ELFCLASS32 instead of ELFCLASS64
    assert_eq!(parse_elf(&data), Err(ElfError));
}

#[test]
fn rejects_wrong_endianness() {
    let mut data = build_test_elf(0x1000, &[(0, 0, 0x1000, 5)]);
    data[5] = 2; // Big-endian instead of little-endian
    assert_eq!(parse_elf(&data), Err(ElfError));
}

#[test]
fn accepts_pie_type() {
    let mut data = build_test_elf(0x1000, &[(0, 0, 0x1000, 5)]);
    data[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN (PIE kernel)
    assert_eq!(parse_elf(&data), Ok(ElfBinary {
        entry: 0x1000,
        segments: {
            let mut segs = [ProgramHeader { vaddr: 0, offset: 0, filesz: 0, memsz: 0, flags: 0 }; 16];
            segs[0] = ProgramHeader { vaddr: 0, offset: 0, filesz: 0x1000, memsz: 0x1000, flags: 5 };
            segs
        },
        segment_count: 1,
        relocations: vec![],
    }));
}

/// Append section headers + shstrtab + a .rela.dyn section to a built ELF.
/// `relas` = (r_offset, r_type, r_addend) entries.
fn append_rela_section(mut data: Vec<u8>, relas: &[(u64, u64, i64)]) -> Vec<u8> {
    let relas_bytes = relas.len() * 24;
    let shstr = b"\0.rela.dyn\0";
    let shstr_offset = data.len() + relas_bytes;

    let rela_start = data.len();
    data.extend_from_slice(&vec![0u8; relas_bytes]);
    for (i, &(off, typ, add)) in relas.iter().enumerate() {
        let e = rela_start + i * 24;
        data[e..e + 8].copy_from_slice(&off.to_le_bytes());
        data[e + 8..e + 16].copy_from_slice(&typ.to_le_bytes());
        data[e + 16..e + 24].copy_from_slice(&add.to_le_bytes());
    }

    let shstr_start = data.len();
    data.extend_from_slice(shstr);

    let shoff = data.len();
    let shnum = 3usize; // null(0) + shstrtab(1) + .rela.dyn(2)
    data.extend_from_slice(&vec![0u8; shnum * 64]);

    // shstrtab section header (index 1)
    let shstr_sec = shoff + 1 * 64;
    data[shstr_sec + 0..shstr_sec + 4].copy_from_slice(&0u32.to_le_bytes());
    data[shstr_sec + 24..shstr_sec + 32].copy_from_slice(&(shstr_start as u64).to_le_bytes());
    data[shstr_sec + 32..shstr_sec + 40].copy_from_slice(&(shstr.len() as u64).to_le_bytes());

    // .rela.dyn section header (index 2)
    let rela_sec = shoff + 2 * 64;
    data[rela_sec + 0..rela_sec + 4].copy_from_slice(&1u32.to_le_bytes()); // name idx = 1
    data[rela_sec + 24..rela_sec + 32].copy_from_slice(&(rela_start as u64).to_le_bytes());
    data[rela_sec + 32..rela_sec + 40].copy_from_slice(&(relas_bytes as u64).to_le_bytes());

    // e_shoff / e_shentsize / e_shnum / e_shstrndx
    data[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
    data[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
    data[0x3C..0x3E].copy_from_slice(&(shnum as u16).to_le_bytes());
    data[0x3E..0x40].copy_from_slice(&1u16.to_le_bytes()); // shstrndx = 1

    data
}

#[test]
fn parses_relative_relocations() {
    let base = build_test_elf(0x1000, &[(0, 0, 0x1000, 5)]);
    let data = append_rela_section(base, &[(0x2BF0, 8, 0x16E0), (0x2BF8, 8, 0x13B0)]);
    let elf = parse_elf(&data).unwrap();
    assert_eq!(elf.relocations.len(), 2);
    assert_eq!(
        elf.relocations[0],
        Relocation { offset: 0x2BF0, addend: 0x16E0 }
    );
    assert_eq!(
        elf.relocations[1],
        Relocation { offset: 0x2BF8, addend: 0x13B0 }
    );
}

#[test]
fn rejects_symbolic_relocations() {
    let base = build_test_elf(0x1000, &[(0, 0, 0x1000, 5)]);
    let data = append_rela_section(base, &[(0x2BF0, 1, 0x16E0)]); // R_X86_64_64
    assert_eq!(parse_elf(&data), Err(ElfError));
}

#[test]
fn rejects_non_executable_type() {
    let mut data = build_test_elf(0x1000, &[(0, 0, 0x1000, 5)]);
    data[16..18].copy_from_slice(&4u16.to_le_bytes()); // ET_CORE instead of ET_EXEC/ET_DYN
    assert_eq!(parse_elf(&data), Err(ElfError));
}

#[test]
fn rejects_wrong_machine() {
    let mut data = build_test_elf(0x1000, &[(0, 0, 0x1000, 5)]);
    data[18..20].copy_from_slice(&0x03u16.to_le_bytes()); // ARM instead of x86_64
    assert_eq!(parse_elf(&data), Err(ElfError));
}

#[test]
fn rejects_no_loadable_segments() {
    // Build ELF with a PT_NULL segment (type 0) instead of PT_LOAD
    let mut data = build_test_elf(0x1000, &[(0, 0, 0x1000, 5)]);
    let ph_start = 64;
    data[ph_start..ph_start + 4].copy_from_slice(&0u32.to_le_bytes()); // PT_NULL
    assert_eq!(parse_elf(&data), Err(ElfError));
}

#[test]
fn parses_single_text_segment() {
    let data = build_test_elf(0x1000, &[(0x1000, 0x100, 0x200, 5)]); // READ+EXEC
    let elf = parse_elf(&data).unwrap();
    assert_eq!(elf.entry, 0x1000);
    assert_eq!(elf.segment_count, 1);
    assert_eq!(elf.segments[0].vaddr, 0x1000);
    assert_eq!(elf.segments[0].offset, 0x100);
    assert_eq!(elf.segments[0].filesz, 0x200);
    assert_eq!(elf.segments[0].flags, 5); // PF_R | PF_X
}

#[test]
fn parses_text_and_data_segments() {
    let data = build_test_elf(
        0x1000,
        &[
            (0x1000, 0x000, 0x3000, 5),  // .text: READ+EXEC
            (0x4000, 0x3000, 0x1000, 6), // .data: READ+WRITE
        ],
    );
    let elf = parse_elf(&data).unwrap();
    assert_eq!(elf.entry, 0x1000);
    assert_eq!(elf.segment_count, 2);
    assert_eq!(elf.segments[0].flags, 5); // PF_R | PF_X
    assert_eq!(elf.segments[1].flags, 6); // PF_R | PF_W
    assert_eq!(elf.segments[1].vaddr, 0x4000);
}

#[test]
fn parses_multiple_segments() {
    let data = build_test_elf(
        0xFFFF_FFFF_8000_0000,
        &[
            (0xFFFF_FFFF_8000_0000, 0x0000, 0x5000, 5), // .text
            (0xFFFF_FFFF_8000_5000, 0x5000, 0x1000, 6), // .rodata
            (0xFFFF_FFFF_8000_6000, 0x6000, 0x2000, 7), // .data (RWX for test)
        ],
    );
    let elf = parse_elf(&data).unwrap();
    assert_eq!(elf.entry, 0xFFFF_FFFF_8000_0000);
    assert_eq!(elf.segment_count, 3);
}

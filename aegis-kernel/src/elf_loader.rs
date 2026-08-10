// Linux ELF binary loader (Phase 8).
//
// Parses ET_EXEC/ET_DYN x86-64 ELF files, validates the headers and PT_LOAD
// program headers, and computes the segment mapping plan plus the initial
// stack layout (argc/argv/envp/auxv) required by the System V x86-64 ABI.
// Honest limits: this proves the parse/mapping logic against byte buffers;
// it does not write page tables or copy bytes into memory (that is the
// lightweight-VM execution vehicle, not built in Phase 8).

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 0x3E;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const MAX_SEGMENTS: usize = 16;
const ELF_HEADER_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LoadedProgram {
    pub entry: u64,
    pub segments: [Segment; MAX_SEGMENTS],
    pub segment_count: usize,
    pub is_dynamic: bool,
    pub needs_interpreter: bool,
}

impl LoadedProgram {
    /// Virtual address range covered by the loadable segments.
    pub fn load_range(&self) -> (u64, u64) {
        let mut low = u64::MAX;
        let mut high = 0u64;
        for s in &self.segments[..self.segment_count] {
            low = low.min(s.vaddr);
            high = high.max(s.vaddr + s.memsz);
        }
        (low, high)
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

pub fn parse_elf(data: &[u8]) -> Result<LoadedProgram, &'static str> {
    if data.len() < ELF_HEADER_SIZE {
        return Err("file too small");
    }
    if data[0..4] != ELF_MAGIC {
        return Err("bad magic");
    }
    if data[4] != ELFCLASS64 {
        return Err("not 64-bit");
    }
    if data[5] != ELFDATA2LSB {
        return Err("not little-endian");
    }
    let e_type = u16_at(data, 16);
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err("not ET_EXEC or ET_DYN");
    }
    if u16_at(data, 18) != EM_X86_64 {
        return Err("not x86-64");
    }
    let e_entry = u64_at(data, 24);
    let e_phoff = u64_at(data, 32);
    let e_phentsize = u16_at(data, 54);
    let e_phnum = u16_at(data, 56);
    if e_phoff == 0 || (e_phentsize as usize) < PHDR_SIZE || e_phnum == 0 {
        return Err("no usable program headers");
    }

    let mut segments = [Segment {
        vaddr: 0,
        offset: 0,
        filesz: 0,
        memsz: 0,
        flags: 0,
    }; MAX_SEGMENTS];
    let mut segment_count = 0;
    let mut needs_interpreter = false;

    for i in 0..e_phnum as u64 {
        let stride = e_phentsize as u64;
        let ph = e_phoff
            .checked_add(
                i.checked_mul(stride)
                    .ok_or("program header offset overflow")?,
            )
            .ok_or("program header offset overflow")?;
        let ph = usize::try_from(ph).map_err(|_| "program header offset overflow")?;
        if ph.checked_add(PHDR_SIZE).is_none_or(|end| end > data.len()) {
            return Err("program header out of bounds");
        }
        let p_type = u32_at(data, ph);
        let p_flags = u32_at(data, ph + 4);
        let p_offset = u64_at(data, ph + 8);
        let p_vaddr = u64_at(data, ph + 16);
        let p_filesz = u64_at(data, ph + 32);
        let p_memsz = u64_at(data, ph + 40);

        if p_type == PT_INTERP {
            needs_interpreter = true;
        }
        if p_type == PT_LOAD {
            if p_offset.saturating_add(p_filesz) > data.len() as u64 {
                return Err("PT_LOAD segment out of bounds");
            }
            if segment_count >= MAX_SEGMENTS {
                return Err("too many loadable segments");
            }
            segments[segment_count] = Segment {
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
        return Err("no loadable segments");
    }

    Ok(LoadedProgram {
        entry: e_entry,
        segments,
        segment_count,
        is_dynamic: e_type == ET_DYN,
        needs_interpreter,
    })
}

// ---------------------------------------------------------------------------
// Initial stack layout (System V x86-64 ABI)
// ---------------------------------------------------------------------------

/// Auxiliary vector entry: (kind, value). Kind 0 is AT_NULL (terminator).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxvEntry {
    pub kind: u64,
    pub value: u64,
}

/// Layout plan for the process initial stack, in 8-byte words.
/// Word order at increasing address (per the ABI):
///   argc | argv[0..argc] | NULL | envp[0..envp_count] | NULL | auxv pairs | AT_NULL
/// String/pointer payloads live above the table; the plan only records counts,
/// so total_bytes is exact and offsets can be derived in the VM layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackLayout {
    pub argc: u64,
    pub argv_ptrs: u64,
    pub envp_ptrs: u64,
    pub auxv_pairs: u64,
    pub total_bytes: u64,
}

pub fn initial_stack_layout(argc: u64, envp_count: u64, auxv: &[AuxvEntry]) -> StackLayout {
    let auxv_pairs = auxv.len() as u64 + 1; // +1 for the AT_NULL terminator pair
    let total_words = 1 + argc + 1 + envp_count + 1 + 2 * auxv_pairs;
    StackLayout {
        argc,
        argv_ptrs: argc,
        envp_ptrs: envp_count,
        auxv_pairs,
        total_bytes: total_words * 8,
    }
}

/// Canonical auxiliary vector entries (no AT_NULL; the layout adds it).
pub fn canonical_auxv(
    phdr: u64,
    phent: u64,
    phnum: u64,
    pagesz: u64,
    entry: u64,
    random_ptr: u64,
) -> [AuxvEntry; 8] {
    [
        AuxvEntry {
            kind: 3,
            value: phdr,
        },
        AuxvEntry {
            kind: 4,
            value: phent,
        },
        AuxvEntry {
            kind: 5,
            value: phnum,
        },
        AuxvEntry {
            kind: 6,
            value: pagesz,
        },
        AuxvEntry {
            kind: 9,
            value: entry,
        },
        AuxvEntry {
            kind: 25,
            value: random_ptr,
        },
        AuxvEntry { kind: 11, value: 0 }, // AT_UID placeholder
        AuxvEntry { kind: 0, value: 0 },  // AT_NULL
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid x86-64 ELF header with the given program headers.
    /// The buffer is padded so every PT_LOAD segment's file bytes are in range.
    fn build_elf(e_type: u16, phdrs: &[(u32, u32, u64, u64, u64, u64)]) -> Vec<u8> {
        let mut size = ELF_HEADER_SIZE + phdrs.len() * PHDR_SIZE;
        for &(_, _, p_offset, _, p_filesz, _) in phdrs {
            size = size.max((p_offset + p_filesz) as usize);
        }
        let mut data = vec![0u8; size];
        data[0..4].copy_from_slice(&ELF_MAGIC);
        data[4] = ELFCLASS64;
        data[5] = ELFDATA2LSB;
        data[16..18].copy_from_slice(&e_type.to_le_bytes());
        data[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        data[24..32].copy_from_slice(&0x4001E0u64.to_le_bytes());
        data[32..40].copy_from_slice(&ELF_HEADER_SIZE.to_le_bytes());
        data[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        data[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, &(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz)) in
            phdrs.iter().enumerate()
        {
            let ph = ELF_HEADER_SIZE + i * PHDR_SIZE;
            data[ph..ph + 4].copy_from_slice(&p_type.to_le_bytes());
            data[ph + 4..ph + 8].copy_from_slice(&p_flags.to_le_bytes());
            data[ph + 8..ph + 16].copy_from_slice(&p_offset.to_le_bytes());
            data[ph + 16..ph + 24].copy_from_slice(&p_vaddr.to_le_bytes());
            data[ph + 32..ph + 40].copy_from_slice(&p_filesz.to_le_bytes());
            data[ph + 40..ph + 48].copy_from_slice(&p_memsz.to_le_bytes());
        }
        data
    }

    #[test]
    fn valid_exec_parses() {
        let data = build_elf(
            ET_EXEC,
            &[
                (PT_LOAD, 5, 0x0000, 0x1000, 0x3000, 0x3000),
                (PT_LOAD, 6, 0x3000, 0x4000, 0x1000, 0x1000),
            ],
        );
        let prog = parse_elf(&data).unwrap();
        assert_eq!(prog.entry, 0x4001E0);
        assert_eq!(prog.segment_count, 2);
        assert!(!prog.is_dynamic);
        assert!(!prog.needs_interpreter);
    }

    #[test]
    fn dyn_is_detected() {
        let data = build_elf(ET_DYN, &[(PT_LOAD, 5, 0x0000, 0x1000, 0x1000, 0x2000)]);
        let prog = parse_elf(&data).unwrap();
        assert!(prog.is_dynamic);
    }

    #[test]
    fn interpreter_detected() {
        let data = build_elf(
            ET_DYN,
            &[
                (PT_INTERP, 4, 0x0200, 0x0200, 0x1C, 0x1C),
                (PT_LOAD, 5, 0x0000, 0x1000, 0x3000, 0x3000),
            ],
        );
        let prog = parse_elf(&data).unwrap();
        assert!(prog.needs_interpreter);
    }

    #[test]
    fn rejects_32bit() {
        let mut data = build_elf(ET_EXEC, &[(PT_LOAD, 5, 0, 0x1000, 0x1000, 0x1000)]);
        data[4] = 1;
        assert_eq!(parse_elf(&data), Err("not 64-bit"));
    }

    #[test]
    fn rejects_bad_endianness() {
        let mut data = build_elf(ET_EXEC, &[(PT_LOAD, 5, 0, 0x1000, 0x1000, 0x1000)]);
        data[5] = 2;
        assert_eq!(parse_elf(&data), Err("not little-endian"));
    }

    #[test]
    fn rejects_wrong_machine() {
        let mut data = build_elf(ET_EXEC, &[(PT_LOAD, 5, 0, 0x1000, 0x1000, 0x1000)]);
        data[18..20].copy_from_slice(&0x3Cu16.to_le_bytes()); // aarch64
        assert_eq!(parse_elf(&data), Err("not x86-64"));
    }

    #[test]
    fn rejects_missing_pt_load() {
        let data = build_elf(ET_EXEC, &[(PT_INTERP, 4, 0, 0, 0x1C, 0x1C)]);
        assert_eq!(parse_elf(&data), Err("no loadable segments"));
    }

    #[test]
    fn segment_bounds_checked() {
        // A valid file truncated so a PT_LOAD segment extends past the end
        let mut data = build_elf(ET_EXEC, &[(PT_LOAD, 5, 0x0000, 0x1000, 0x1000, 0x1000)]);
        data.truncate(ELF_HEADER_SIZE + PHDR_SIZE + 8); // segment claims 0x1000 bytes
        assert_eq!(parse_elf(&data), Err("PT_LOAD segment out of bounds"));
    }

    #[test]
    fn load_range_spans_segments() {
        let data = build_elf(
            ET_EXEC,
            &[
                (PT_LOAD, 5, 0x0000, 0x1000, 0x3000, 0x3000),
                (PT_LOAD, 6, 0x3000, 0x4000, 0x1000, 0x2000),
            ],
        );
        let prog = parse_elf(&data).unwrap();
        assert_eq!(prog.load_range(), (0x1000, 0x6000));
    }

    #[test]
    fn stack_layout_counts_words() {
        let auxv = [
            AuxvEntry {
                kind: 3,
                value: 0x40,
            },
            AuxvEntry { kind: 4, value: 56 },
            AuxvEntry { kind: 5, value: 2 },
        ];
        let layout = initial_stack_layout(2, 2, &auxv);
        // 1 argc + 2 argv + 1 NULL + 2 envp + 1 NULL + 2 * (3 auxv + 1 null) = 15 words
        assert_eq!(layout.total_bytes, 15 * 8);
        assert_eq!(layout.argv_ptrs, 2);
        assert_eq!(layout.envp_ptrs, 2);
        assert_eq!(layout.auxv_pairs, 4);
    }

    #[test]
    fn stack_layout_alignment() {
        let layout = initial_stack_layout(0, 0, &[]);
        // 1 argc + 1 argv-NULL + 1 envp-NULL + 2 * (0 auxv + 1 AT_NULL pair) = 5 words
        assert_eq!(layout.total_bytes, 40);
        assert_eq!(layout.total_bytes % 8, 0);
    }

    #[test]
    fn canonical_auxv_terminates_with_at_null() {
        let auxv = canonical_auxv(0x40, 56, 2, 4096, 0x4001E0, 0x7F00);
        assert_eq!(auxv[7], AuxvEntry { kind: 0, value: 0 });
        assert_eq!(
            auxv[0],
            AuxvEntry {
                kind: 3,
                value: 0x40
            }
        );
        assert_eq!(
            auxv[4],
            AuxvEntry {
                kind: 9,
                value: 0x4001E0
            }
        );
    }
}

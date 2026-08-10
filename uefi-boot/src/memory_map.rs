//! UEFI memory map enumeration and display.

use uefi::boot::{self, MemoryType};
use uefi::mem::memory_map::MemoryMap;

/// Print the UEFI memory map.
pub fn print_memory_map() {
    let map = boot::memory_map(MemoryType::LOADER_DATA).unwrap();

    uefi::println!("Aegis: UEFI memory map ({} entries):", map.len());
    uefi::println!(
        "  {:<20} {:<12} {:<12} {:<10}",
        "Type",
        "Physical",
        "Pages",
        "Attr"
    );

    for desc in map.entries() {
        let phys = desc.phys_start;
        let pages = desc.page_count;
        let ty = match desc.ty {
            MemoryType::CONVENTIONAL => "Conventional",
            MemoryType::LOADER_CODE => "LoaderCode",
            MemoryType::LOADER_DATA => "LoaderData",
            MemoryType::BOOT_SERVICES_CODE => "BootSvcCode",
            MemoryType::BOOT_SERVICES_DATA => "BootSvcData",
            MemoryType::RUNTIME_SERVICES_CODE => "RtSvcCode",
            MemoryType::RUNTIME_SERVICES_DATA => "RtSvcData",
            MemoryType::ACPI_RECLAIM => "ACPIReclaim",
            MemoryType::ACPI_NON_VOLATILE => "ACPINV",
            MemoryType::MMIO => "MMIO",
            MemoryType::MMIO_PORT_SPACE => "MMIOPort",
            MemoryType::UNUSABLE => "Unusable",
            MemoryType::PAL_CODE => "PALCode",
            MemoryType::PERSISTENT_MEMORY => "PMem",
            _ => "Other",
        };
        uefi::println!(
            "  {:<20} 0x{:010X} {:<12} 0x{:X}",
            ty,
            phys,
            pages,
            desc.att.bits()
        );
    }
}

#!/usr/bin/env python3
"""Create a bootable UEFI disk image with FAT16 filesystem."""
import struct
import os
import sys

def create_disk_image(efi_path, output_path, size_mb=64):
    """Create a GPT disk image with FAT16 EFI System Partition."""
    
    sector_size = 512
    total_sectors = (size_mb * 1024 * 1024) // sector_size
    
    # Read the EFI binary
    with open(efi_path, "rb") as f:
        efi_data = f.read()
    
    # FAT16 setup
    fat_start = 2048  # Start FAT at sector 2048 (1MB offset)
    fat_sectors = 128  # FAT size in sectors
    data_start = fat_start + fat_sectors
    data_sectors = total_sectors - data_start
    
    # Create filesystem image (just FAT16 with the EFI file)
    fs_size = data_sectors * sector_size
    fs = bytearray(fs_size)
    
    # Build the FAT16 directory entry for /EFI/BOOT/BOOTX64.EFI
    # We'll use a minimal FAT16 implementation
    
    # Boot sector (BPB for FAT16)
    bpb = bytearray(sector_size)
    bpb[0:3] = b'\xEB\x58\x90'  # JMP boot
    bpb[3:11] = b'MSDOS5.0'     # OEM
    struct.pack_into('<H', bpb, 11, sector_size)  # Bytes per sector
    bpb[13] = 4                  # Sectors per cluster
    struct.pack_into('<H', bpb, 14, 1)    # Reserved sectors
    bpb[16] = 1                  # Number of FATs
    struct.pack_into('<H', bpb, 17, 64)   # Root dir entries
    struct.pack_into('<H', bpb, 19, 0)    # Total sectors (16-bit, 0 = use 32)
    bpb[21] = 0xF8              # Media type
    struct.pack_into('<H', bpb, 22, fat_sectors)  # FAT size in sectors
    struct.pack_into('<H', bpb, 24, 1)    # Sectors per track
    struct.pack_into('<H', bpb, 26, 1)    # Number of heads
    struct.pack_into('<I', bpb, 28, 0)    # Hidden sectors
    struct.pack_into('<I', bpb, 32, 0)    # Total sectors (32-bit)
    bpb[36] = 0x80              # Drive number
    bpb[38] = 0x29              # Extended boot signature
    struct.pack_into('<I', bpb, 40, 0x12345678)  # Volume serial
    bpb[44:55] = b'AEGIS BOOT '  # Volume label
    bpb[55:63] = b'FAT16   '    # Filesystem type
    
    # Copy boot sector to filesystem area
    fs[0:sector_size] = bpb
    
    # FAT16 table: cluster 0 and 1 are reserved
    # Cluster 2 starts at data area
    fat = bytearray(fat_sectors * sector_size)
    fat[0:3] = b'\xF8\xFF\xFF'  # Reserved clusters
    fat[3] = 0xFF               # Cluster 2 (end of chain) - will be updated
    
    # Root directory starts right after FAT
    root_dir_offset = 0  # Relative to data_start
    
    # Create /EFI/ directory entry
    efi_dir = bytearray(32)
    efi_dir[0:11] = b'EFI        '  # Name (8.3)
    efi_dir[11] = 0x10             # Directory attribute
    efi_dir[26:28] = struct.pack('<H', 2)  # First cluster
    
    # Create /EFI/BOOT/ directory entry
    boot_dir = bytearray(32)
    boot_dir[0:11] = b'BOOT       '  # Name (8.3)
    boot_dir[11] = 0x10             # Directory attribute
    boot_dir[26:28] = struct.pack('<H', 3)  # First cluster
    
    # Calculate clusters needed for EFI file
    cluster_size = 4 * sector_size  # 4 sectors per cluster = 2048 bytes
    clusters_needed = (len(efi_data) + cluster_size - 1) // cluster_size
    
    # Build FAT chain for the EFI file
    fat_offset = lambda c: c * 2  # FAT16 = 2 bytes per entry
    
    for i in range(clusters_needed):
        cluster_num = 4 + i  # Start at cluster 4
        next_cluster = cluster_num + 1 if i < clusters_needed - 1 else 0xFFFF
        struct.pack_into('<H', fat, fat_offset(cluster_num), next_cluster)
    
    # File data for BOOTX64.EFI
    bootx64_entry = bytearray(32)
    bootx64_entry[0:8] = b'BOOTX64 '  # File name
    bootx64_entry[8:11] = b'EFI'       # Extension
    bootx64_entry[28:30] = struct.pack('<H', len(efi_data) & 0xFFFF)  # Size low
    bootx64_entry[26:28] = struct.pack('<H', 4)  # First cluster
    
    # Write root directory
    root_offset = fat_sectors * sector_size
    fs[root_offset:root_offset+32] = efi_dir
    fs[root_offset+32:root_offset+64] = boot_dir
    fs[root_offset+64:root_offset+96] = bootx64_entry
    
    # Write FAT
    fs[sector_size:sector_size + len(fat)] = fat
    
    # Write EFI file data starting at cluster 4
    data_offset = (4 - 2) * cluster_size  # Cluster 2 starts at offset 0 of data area
    fs[data_offset:data_offset + len(efi_data)] = efi_data
    
    # Create the full disk image with protective MBR + GPT
    disk = bytearray(total_sectors * sector_size)
    
    # Protective MBR (sector 0)
    mbr = bytearray(sector_size)
    mbr[446] = 0x00              # Status
    mbr[447] = 0x00              # CHS first
    mbr[448] = 0x01              # CHS type = GPT
    struct.pack_into('<I', mbr, 458, 1)   # Starting LBA
    struct.pack_into('<I', mbr, 462, total_sectors - 1)  # Size
    mbr[510:512] = b'\x55\xAA'  # Boot signature
    disk[0:sector_size] = mbr
    
    # GPT Header (sector 1)
    gpt_header = bytearray(sector_size)
    gpt_header[0:8] = b'EFI PART'
    struct.pack_into('<I', gpt_header, 8, 0x00010000)  # Revision 1.0
    struct.pack_into('<I', gpt_header, 12, 92)  # Header size
    struct.pack_into('<I', gpt_header, 16, 0)   # CRC32 (0 = skip)
    struct.pack_into('<I', gpt_header, 80, 2)   # My LBA
    struct.pack_into('<I', gpt_header, 88, total_sectors - 1)  # Alternate LBA
    struct.pack_into('<I', gpt_header, 96, 34)  # First usable LBA
    struct.pack_into('<I', gpt_header, 104, total_sectors - 33)  # Last usable LBA
    # Disk GUID
    struct.pack_into('<Q', gpt_header, 112, 0x12345678ABCDEF00)
    struct.pack_into('<Q', gpt_header, 120, 0x00FEDCBA98765432)
    struct.pack_into('<I', gpt_header, 128, 2)  # Partition entry start LBA
    struct.pack_into('<I', gpt_header, 132, 128) # Number of partition entries
    struct.pack_into('<I', gpt_header, 136, 128) # Size of partition entry
    disk[sector_size:2*sector_size] = gpt_header
    
    # Partition entry 1 (EFI System Partition)
    part_entry = bytearray(128)
    # EFI System Partition GUID: C12A7328-F8C1-11D2-94A4-00504326F002
    part_type = bytes([0x28, 0x73, 0x2A, 0xC1, 0xC1, 0xF8, 0xD2, 0x11, 0x94, 0xA4, 0x00, 0x50, 0x43, 0x26, 0xF0, 0x02])
    part_entry[0:16] = part_type
    struct.pack_into('<I', part_entry, 20, 0x00000002)  # Starting LBA
    struct.pack_into('<I', part_entry, 24, total_sectors - 1 - 2)  # Ending LBA
    struct.pack_into('<Q', part_entry, 32, 0x0000000000000002)  # Attributes
    part_entry[44:56] = b'EFI System Partition\x00'
    
    disk[2*sector_size:2*sector_size + 128] = part_entry
    
    # Copy filesystem data
    disk[data_start*sector_size:data_start*sector_size + len(fs)] = fs
    
    # Write the disk image
    with open(output_path, "wb") as f:
        f.write(disk)
    
    print(f"Disk image created: {output_path}")
    print(f"  Size: {len(disk)} bytes ({len(disk) // (1024*1024)} MB)")
    print(f"  EFI binary: {efi_path} ({len(efi_data)} bytes)")
    print(f"  EFI binary at LBA {data_start} + offset in FAT")
    print(f"  Boot path: /EFI/BOOT/BOOTX64.EFI")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    efi_path = os.path.join(script_dir, "target", "x86_64-unknown-uefi", "release", "uefi-boot.efi")
    output_path = os.path.join(script_dir, "aegis-boot.img")
    
    if not os.path.exists(efi_path):
        print(f"ERROR: EFI binary not found at {efi_path}")
        print("Run 'cargo build --release' first")
        sys.exit(1)
    
    create_disk_image(efi_path, output_path)

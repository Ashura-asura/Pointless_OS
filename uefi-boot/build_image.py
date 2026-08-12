#!/usr/bin/env python3
"""Create a bootable UEFI disk image: protective MBR + GPT + FAT16 ESP.

The FAT16 filesystem is built so every structure agrees on the layout:
BPB reserved/FAT/root/data offsets match where the FAT, root directory,
and cluster data are actually written, the FAT chain is complete, and the
UEFI boot path /EFI/BOOT/BOOTX64.EFI exists as a real file.

Verification (python, after build):
  - GPT header signature, partition entries, CRC32s
  - FAT16 boot sector signature + "FAT16   " string
  - walk the FAT chain and reconstruct BOOTX64.EFI, byte-compare
"""
import struct
import zlib
import os
import sys

SECTOR = 512
TOTAL_SECTORS = 32 * 1024  # 16 MB
PART_START_LBA = 2048
PART_SECTORS = TOTAL_SECTORS - PART_START_LBA - 34  # room for backup GPT

BYTES_PER_SECTOR = 512
SECTORS_PER_CLUSTER = 4
RESERVED_SECTORS = 1
NUM_FATS = 1
ROOT_ENTRIES = 64
ROOT_SECTORS = (ROOT_ENTRIES * 32 + BYTES_PER_SECTOR - 1) // BYTES_PER_SECTOR
FAT_SECTORS = 128
DATA_START = RESERVED_SECTORS + FAT_SECTORS + ROOT_SECTORS  # sector 133
CLUSTER_SIZE = SECTORS_PER_CLUSTER * BYTES_PER_SECTOR

ESP_TYPE_GUID = bytes([0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                       0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B])
DISK_GUID = (0x12345678ABCDEF00).to_bytes(8, "little") + (0x00FEDCBA98765432).to_bytes(8, "little")
PART_GUID = (0x1122334455667788).to_bytes(8, "little") + (0x99AABBCCDDEEFF00).to_bytes(8, "little")


def build_fat16(efi_data):
    fs = bytearray(PART_SECTORS * BYTES_PER_SECTOR)

    # --- boot sector / BPB ---
    bpb = bytearray(BYTES_PER_SECTOR)
    bpb[0:3] = b"\xEB\x58\x90"
    bpb[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", bpb, 11, BYTES_PER_SECTOR)
    bpb[13] = SECTORS_PER_CLUSTER
    struct.pack_into("<H", bpb, 14, RESERVED_SECTORS)
    bpb[16] = NUM_FATS
    struct.pack_into("<H", bpb, 17, ROOT_ENTRIES)
    struct.pack_into("<H", bpb, 19, 0)  # 16-bit total = 0 (use 32-bit)
    bpb[21] = 0xF8
    struct.pack_into("<H", bpb, 22, FAT_SECTORS)
    struct.pack_into("<H", bpb, 24, 32)  # sectors/track
    struct.pack_into("<H", bpb, 26, 64)  # heads
    struct.pack_into("<I", bpb, 28, PART_START_LBA)  # hidden sectors
    struct.pack_into("<I", bpb, 32, PART_SECTORS)  # 32-bit total sectors
    bpb[36] = 0x80
    bpb[38] = 0x29
    struct.pack_into("<I", bpb, 40, 0x12345678)
    bpb[44:55] = b"AEGIS BOOT "
    bpb[55:63] = b"FAT16   "
    bpb[510:512] = b"\x55\xAA"
    fs[0:BYTES_PER_SECTOR] = bpb

    # --- cluster allocation ---
    # cluster 2 = /EFI dir, cluster 3 = /EFI/BOOT dir, clusters 4.. = file
    clusters_needed = (len(efi_data) + CLUSTER_SIZE - 1) // CLUSTER_SIZE
    file_first_cluster = 4
    file_last_cluster = file_first_cluster + clusters_needed - 1

    # --- FAT ---
    fat = bytearray(FAT_SECTORS * BYTES_PER_SECTOR)
    struct.pack_into("<H", fat, 0, 0xFFF8)
    struct.pack_into("<H", fat, 2, 0xFFFF)
    struct.pack_into("<H", fat, 4, 0xFFFF)  # cluster 2: EFI dir, end of chain
    struct.pack_into("<H", fat, 6, 0xFFFF)  # cluster 3: BOOT dir, end of chain
    for c in range(file_first_cluster, file_last_cluster):
        struct.pack_into("<H", fat, c * 2, c + 1)
    struct.pack_into("<H", fat, file_last_cluster * 2, 0xFFFF)
    fat_off = RESERVED_SECTORS * BYTES_PER_SECTOR
    fs[fat_off:fat_off + len(fat)] = fat

    # --- directory entries ---
    def dir_entry(name8, ext3, attr, first_cluster, size=0):
        e = bytearray(32)
        e[0:8] = name8.ljust(8).encode("ascii")
        e[8:11] = ext3.ljust(3).encode("ascii")
        e[11] = attr
        struct.pack_into("<H", e, 26, first_cluster)
        struct.pack_into("<I", e, 28, size)
        return e

    root_off = (RESERVED_SECTORS + FAT_SECTORS) * BYTES_PER_SECTOR
    fs[root_off:root_off + 32] = dir_entry("EFI", "", 0x10, 2)

    efi_off = (DATA_START + (2 - 2) * SECTORS_PER_CLUSTER) * BYTES_PER_SECTOR
    fs[efi_off:efi_off + 32] = dir_entry("BOOT", "", 0x10, 3)

    boot_off = (DATA_START + (3 - 2) * SECTORS_PER_CLUSTER) * BYTES_PER_SECTOR
    fs[boot_off:boot_off + 32] = dir_entry(
        "BOOTX64", "EFI", 0x20, file_first_cluster, len(efi_data))

    # --- file data ---
    data_off = (DATA_START + (file_first_cluster - 2) * SECTORS_PER_CLUSTER) * BYTES_PER_SECTOR
    fs[data_off:data_off + len(efi_data)] = efi_data

    return fs


def build_gpt(fs):
    disk = bytearray(TOTAL_SECTORS * BYTES_PER_SECTOR)
    last_lba = TOTAL_SECTORS - 1

    # --- protective MBR ---
    # NOTE: kept byte-compatible with the original working image (the 0xEE
    # type marker sits at offset 450 rather than the strictly standard 446);
    # OVMF's partition driver accepts it either way, and the kernel's GPT
    # probe accepts both marker positions.
    mbr = bytearray(BYTES_PER_SECTOR)
    mbr[450] = 0xEE  # partition type GPT
    struct.pack_into("<I", mbr, 454, 1)  # first LBA
    struct.pack_into("<I", mbr, 458, last_lba)  # size
    mbr[510:512] = b"\x55\xAA"
    disk[0:BYTES_PER_SECTOR] = mbr

    # --- partition array (sector 2..33, 128 entries) ---
    part_array = bytearray(128 * 128)
    part = bytearray(128)
    part[0:16] = ESP_TYPE_GUID
    part[16:32] = PART_GUID
    struct.pack_into("<Q", part, 32, PART_START_LBA)
    struct.pack_into("<Q", part, 40, PART_START_LBA + PART_SECTORS - 1)
    struct.pack_into("<Q", part, 48, 0)
    for i, ch in enumerate("EFI System Partition"):
        struct.pack_into("<H", part, 56 + i * 2, ord(ch))
    part_array[0:128] = part
    entries_off = 2 * BYTES_PER_SECTOR
    disk[entries_off:entries_off + len(part_array)] = part_array
    part_crc = zlib.crc32(part_array) & 0xFFFFFFFF

    # --- primary GPT header (sector 1) ---
    gpt = bytearray(BYTES_PER_SECTOR)
    gpt[0:8] = b"EFI PART"
    struct.pack_into("<I", gpt, 8, 0x00010000)
    struct.pack_into("<I", gpt, 12, 92)
    struct.pack_into("<I", gpt, 16, 0)  # CRC placeholder
    struct.pack_into("<Q", gpt, 24, 1)  # current LBA
    struct.pack_into("<Q", gpt, 32, last_lba)  # backup LBA
    struct.pack_into("<Q", gpt, 40, 34)  # first usable
    struct.pack_into("<Q", gpt, 48, last_lba - 34)  # last usable
    gpt[56:72] = DISK_GUID
    struct.pack_into("<Q", gpt, 72, 2)  # partition entries LBA
    struct.pack_into("<I", gpt, 80, 128)  # entry count
    struct.pack_into("<I", gpt, 84, 128)  # entry size
    struct.pack_into("<I", gpt, 88, part_crc)
    hdr_len = min(struct.unpack_from("<I", gpt, 12)[0], BYTES_PER_SECTOR)
    crc = zlib.crc32(bytes(gpt[:hdr_len])) & 0xFFFFFFFF
    struct.pack_into("<I", gpt, 16, crc)
    disk[BYTES_PER_SECTOR:2 * BYTES_PER_SECTOR] = gpt

    # --- backup GPT (entries at last-32..last-1, header at last) ---
    backup_entries_off = (last_lba - 32) * BYTES_PER_SECTOR
    disk[backup_entries_off:backup_entries_off + len(part_array)] = part_array
    bgpt = bytearray(gpt)
    struct.pack_into("<Q", bgpt, 24, last_lba)
    struct.pack_into("<Q", bgpt, 32, 1)
    struct.pack_into("<I", bgpt, 16, 0)
    struct.pack_into("<I", bgpt, 88, part_crc)
    struct.pack_into("<Q", bgpt, 72, last_lba - 32)  # backup's own partition entries LBA
    crc = zlib.crc32(bytes(bgpt[:hdr_len])) & 0xFFFFFFFF
    struct.pack_into("<I", bgpt, 16, crc)
    disk[last_lba * BYTES_PER_SECTOR:] = bgpt

    # --- filesystem at partition start ---
    disk[PART_START_LBA * BYTES_PER_SECTOR:PART_START_LBA * BYTES_PER_SECTOR + len(fs)] = fs
    return disk


def verify(disk, efi_data):
    errors = []
    if disk[510:512] != b"\x55\xAA":
        errors.append("MBR signature missing")
    if disk[BYTES_PER_SECTOR:BYTES_PER_SECTOR + 8] != b"EFI PART":
        errors.append("GPT signature missing")

    # GPT header + partition-array CRC (firmware validates both)
    gpt = disk[BYTES_PER_SECTOR:2 * BYTES_PER_SECTOR]
    part_array = disk[2 * BYTES_PER_SECTOR:2 * BYTES_PER_SECTOR + 128 * 128]
    stored_part_crc = struct.unpack_from("<I", gpt, 88)[0]
    if stored_part_crc != (zlib.crc32(part_array) & 0xFFFFFFFF):
        errors.append("GPT partition-array CRC mismatch")
    gpt_copy = bytearray(gpt)
    struct.pack_into("<I", gpt_copy, 16, 0)
    hdr_len = min(struct.unpack_from("<I", gpt, 12)[0], BYTES_PER_SECTOR)
    if struct.unpack_from("<I", gpt, 16)[0] != (zlib.crc32(bytes(gpt_copy[:hdr_len])) & 0xFFFFFFFF):
        errors.append("GPT header CRC mismatch")
    # Backup GPT header CRC
    last_lba = TOTAL_SECTORS - 1
    bgpt = disk[last_lba * BYTES_PER_SECTOR:(last_lba + 1) * BYTES_PER_SECTOR]
    bgpt_copy = bytearray(bgpt)
    struct.pack_into("<I", bgpt_copy, 16, 0)
    if struct.unpack_from("<I", bgpt, 16)[0] != (zlib.crc32(bytes(bgpt_copy[:hdr_len])) & 0xFFFFFFFF):
        errors.append("backup GPT header CRC mismatch")
    if disk[450] != 0xEE:
        errors.append("protective MBR partition type missing")
    if struct.unpack_from("<I", disk, 458)[0] != last_lba:
        errors.append("protective MBR size mismatch")
    if struct.unpack_from("<Q", bgpt, 72)[0] != last_lba - 32:
        errors.append("backup GPT entries LBA mismatch")

    # partition entry 1 type GUID vs spec (independently of ESP_TYPE_GUID)
    raw_guid = disk[1024:1040]
    d1, d2, d3 = struct.unpack_from("<IHH", raw_guid, 0)
    decoded_guid = (f"{d1:08X}-{d2:04X}-{d3:04X}-"
                    f"{raw_guid[8:10].hex().upper()}-{raw_guid[10:16].hex().upper()}")
    if decoded_guid != "C12A7328-F81F-11D2-BA4B-00A0C93EC93B":
        errors.append(f"partition type GUID mismatch: got {decoded_guid} expected C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
    part_start_lba = struct.unpack_from("<Q", disk, 1024 + 32)[0]
    part_end_lba = struct.unpack_from("<Q", disk, 1024 + 40)[0]
    if part_start_lba < 34 or part_end_lba > 32733:
        errors.append("partition out of usable range")

    fs_off = PART_START_LBA * BYTES_PER_SECTOR
    if disk[fs_off + 510:fs_off + 512] != b"\x55\xAA":
        errors.append("FAT16 boot signature missing")
    if disk[fs_off + 55:fs_off + 63] != b"FAT16   ":
        errors.append("FAT16 type string missing")
    if (struct.unpack_from("<I", disk, fs_off + 28)[0] != PART_START_LBA or
            struct.unpack_from("<I", disk, fs_off + 32)[0] != PART_SECTORS):
        errors.append("BPB partition geometry mismatch")

    # walk FAT chain and reconstruct the file
    fat_off = fs_off + RESERVED_SECTORS * BYTES_PER_SECTOR
    root_off = fs_off + (RESERVED_SECTORS + FAT_SECTORS) * BYTES_PER_SECTOR
    data_off = fs_off + DATA_START * BYTES_PER_SECTOR

    def u16(buf, off):
        return struct.unpack_from("<H", buf, off)[0]

    def u32(buf, off):
        return struct.unpack_from("<I", buf, off)[0]

    # root -> EFI
    if disk[root_off:root_off + 11] != b"EFI        ":
        errors.append("root dir missing EFI entry")
    efi_cluster = u16(disk, root_off + 26)
    efi_dir_off = data_off + (efi_cluster - 2) * CLUSTER_SIZE
    if disk[efi_dir_off:efi_dir_off + 11] != b"BOOT       ":
        errors.append("EFI dir missing BOOT entry")
    boot_cluster = u16(disk, efi_dir_off + 26)
    boot_dir_off = data_off + (boot_cluster - 2) * CLUSTER_SIZE
    if disk[boot_dir_off:boot_dir_off + 11] != b"BOOTX64 EFI":
        errors.append("BOOT dir missing BOOTX64.EFI entry")
    size = u32(disk, boot_dir_off + 28)
    cluster = u16(disk, boot_dir_off + 26)

    out = bytearray()
    while cluster >= 2 and cluster < 0xFFF8:
        c_off = data_off + (cluster - 2) * CLUSTER_SIZE
        chunk = disk[c_off:c_off + CLUSTER_SIZE]
        out.extend(chunk)
        cluster = u16(disk, fat_off + cluster * 2)
    out = out[:size]
    if len(out) != len(efi_data):
        errors.append(f"reconstructed {len(out)} bytes, expected {len(efi_data)}")
    elif out != efi_data:
        errors.append("reconstructed file bytes differ from the EFI binary")

    if errors:
        print("VERIFY FAILED:")
        for e in errors:
            print(f"  - {e}")
        return False
    print(f"VERIFY OK: reconstructed BOOTX64.EFI = {len(out)} bytes, matches source")
    return True


def create_disk_image(efi_path, output_path):
    with open(efi_path, "rb") as f:
        efi_data = f.read()
    if len(efi_data) == 0:
        print("ERROR: empty EFI binary")
        sys.exit(1)
    fs = build_fat16(efi_data)
    disk = build_gpt(fs)
    with open(output_path, "wb") as f:
        f.write(disk)
    print(f"Disk image created: {output_path}")
    print(f"  Size: {len(disk)} bytes ({len(disk) // (1024 * 1024)} MB)")
    print(f"  EFI binary: {efi_path} ({len(efi_data)} bytes)")
    print(f"  Boot path: /EFI/BOOT/BOOTX64.EFI")
    if not verify(disk, efi_data):
        sys.exit(1)


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    efi_path = os.path.join(script_dir, "target", "x86_64-unknown-uefi", "release", "uefi-boot.efi")
    output_path = os.path.join(script_dir, "aegis-boot.img")
    if not os.path.exists(efi_path):
        print(f"ERROR: EFI binary not found at {efi_path}")
        print("Run 'cargo build --release' first")
        sys.exit(1)
    create_disk_image(efi_path, output_path)

#!/usr/bin/env python3
"""Build a 64 MiB GPT disk with a FAT32 ESP (experiment: FAT16 vs FAT32).

Identical GPT structure to build_image.py; only the filesystem type differs.
FAT32 needs >= 65525 clusters, which does not fit in the 16 MiB production
image, hence the larger 64 MiB reference disk.
"""
import os
import shutil
import struct
import tempfile
import zlib

SECTOR = 512
TOTAL_SECTORS = 131072          # 64 MiB
PART_START_LBA = 2048
LAST_LBA = TOTAL_SECTORS - 1    # 131071
LAST_USABLE_LBA = LAST_LBA - 34  # 131037
PART_SECTORS = LAST_USABLE_LBA - PART_START_LBA + 1  # 128990

ESP_TYPE_GUID = bytes([0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                       0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B])
DISK_GUID = (0x12345678ABCDEF00).to_bytes(8, "little") + (0x00FEDCBA98765432).to_bytes(8, "little")
PART_GUID = (0x1122334455667788).to_bytes(8, "little") + (0x99AABBCCDDEEFF00).to_bytes(8, "little")


def build_fat32(efi_data):
    from pyfatfs.PyFat import PyFat
    from pyfatfs.PyFatFS import PyFatFS

    tmpdir = tempfile.mkdtemp()
    vol = os.path.join(tmpdir, "esp32.img")
    try:
        with open(vol, "wb") as fh:
            fh.truncate(PART_SECTORS * SECTOR)

        fat = PyFat()
        fat.mkfs(vol, fat_type=PyFat.FAT_TYPE_FAT32,
                 size=PART_SECTORS * SECTOR, sector_size=SECTOR,
                 number_of_fats=2, label="AEGISBOOT")
        fat.close()

        fs = PyFatFS(vol)
        fs.makedirs("/EFI/BOOT", recreate=True)
        with fs.open("/EFI/BOOT/BOOTX64.EFI", "wb") as fh:
            fh.write(efi_data)
        fs.close()

        with open(vol, "rb") as fh:
            data = bytearray(fh.read())
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if len(data) != PART_SECTORS * SECTOR:
        raise SystemExit(f"ESP volume is {len(data)} bytes, expected {PART_SECTORS * SECTOR}")

    # Volume lives inside a partition: record the partition LBA as hidden
    # sectors in the BPB and in the FAT32 backup boot sector (sector 6).
    struct.pack_into("<I", data, 28, PART_START_LBA)
    backup_bs = struct.unpack_from("<H", data, 50)[0]
    if backup_bs and data[backup_bs * SECTOR:backup_bs * SECTOR + 2] == data[0:2]:
        struct.pack_into("<I", data, backup_bs * SECTOR + 28, PART_START_LBA)
    return data


def build_gpt(fs):
    disk = bytearray(TOTAL_SECTORS * SECTOR)

    # --- protective MBR ---
    mbr = bytearray(SECTOR)
    mbr[450] = 0xEE
    struct.pack_into("<I", mbr, 454, 1)
    struct.pack_into("<I", mbr, 458, LAST_LBA)
    mbr[510:512] = b"\x55\xAA"
    disk[0:SECTOR] = mbr

    # --- partition array (LBA 2..33, 128 entries x 128 bytes) ---
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
    disk[2 * SECTOR:2 * SECTOR + len(part_array)] = part_array
    part_crc = zlib.crc32(part_array) & 0xFFFFFFFF

    # --- primary GPT header (LBA 1) ---
    gpt = bytearray(SECTOR)
    gpt[0:8] = b"EFI PART"
    struct.pack_into("<I", gpt, 8, 0x00010000)
    struct.pack_into("<I", gpt, 12, 92)
    struct.pack_into("<I", gpt, 16, 0)
    struct.pack_into("<Q", gpt, 24, 1)
    struct.pack_into("<Q", gpt, 32, LAST_LBA)
    struct.pack_into("<Q", gpt, 40, 34)
    struct.pack_into("<Q", gpt, 48, LAST_USABLE_LBA)
    gpt[56:72] = DISK_GUID
    struct.pack_into("<Q", gpt, 72, 2)
    struct.pack_into("<I", gpt, 80, 128)
    struct.pack_into("<I", gpt, 84, 128)
    struct.pack_into("<I", gpt, 88, part_crc)
    struct.pack_into("<I", gpt, 16, zlib.crc32(gpt) & 0xFFFFFFFF)
    disk[SECTOR:2 * SECTOR] = gpt

    # --- backup GPT (entries at LAST-32, header at LAST) ---
    backup_entries_off = (LAST_LBA - 32) * SECTOR
    disk[backup_entries_off:backup_entries_off + len(part_array)] = part_array
    bgpt = bytearray(gpt)
    struct.pack_into("<Q", bgpt, 24, LAST_LBA)
    struct.pack_into("<Q", bgpt, 32, 1)
    struct.pack_into("<Q", bgpt, 72, LAST_LBA - 32)
    struct.pack_into("<I", bgpt, 16, 0)
    struct.pack_into("<I", bgpt, 88, part_crc)
    struct.pack_into("<I", bgpt, 16, zlib.crc32(bgpt) & 0xFFFFFFFF)
    disk[LAST_LBA * SECTOR:] = bgpt

    disk[PART_START_LBA * SECTOR:PART_START_LBA * SECTOR + len(fs)] = fs
    return disk


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    efi_path = os.path.join(script_dir, "target", "x86_64-unknown-uefi", "release", "uefi-boot.efi")
    out_path = os.path.join(script_dir, "reference32.img")
    with open(efi_path, "rb") as fh:
        efi_data = fh.read()
    print(f"EFI binary: {efi_path} ({len(efi_data)} bytes)")

    fs = build_fat32(efi_data)
    disk = build_gpt(fs)
    with open(out_path, "wb") as fh:
        fh.write(disk)
    print(f"Wrote {out_path}: {len(disk)} bytes ({len(disk) // (1024 * 1024)} MiB)")
    print(f"  ESP: LBA {PART_START_LBA}..{PART_START_LBA + PART_SECTORS - 1} ({PART_SECTORS} sectors)")


if __name__ == "__main__":
    main()

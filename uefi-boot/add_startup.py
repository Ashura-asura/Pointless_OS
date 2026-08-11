#!/usr/bin/env python3
"""Patch a STARTUP.NSH into the root of the FAT16 ESP in an existing disk image."""
import struct
import sys
import os

SECTOR = 512
PART_START_LBA = 2048
RESERVED_SECTORS = 1
FAT_SECTORS = 128
ROOT_ENTRIES = 64
ROOT_SECTORS = (ROOT_ENTRIES * 32 + SECTOR - 1) // SECTOR
DATA_START = RESERVED_SECTORS + FAT_SECTORS + ROOT_SECTORS  # 133
SECTORS_PER_CLUSTER = 4
CLUSTER_SIZE = SECTORS_PER_CLUSTER * SECTOR


def main():
    img_path = sys.argv[1] if len(sys.argv) > 1 else "aegis-boot.img"
    with open(img_path, "r+b") as f:
        disk = bytearray(f.read())

    fs_off = PART_START_LBA * SECTOR
    fat_off = fs_off + RESERVED_SECTORS * SECTOR
    root_off = fs_off + (RESERVED_SECTORS + FAT_SECTORS) * SECTOR
    data_off = fs_off + DATA_START * SECTOR

    # Find the first free cluster after the EFI binary's chain
    # Walk FAT to find end of chains
    max_cluster = 0
    c = 2
    while True:
        val = struct.unpack_from("<H", disk, fat_off + c * 2)[0]
        if val == 0xFFFF:
            max_cluster = max(max_cluster, c)
            break
        elif val >= 2:
            max_cluster = max(max_cluster, c)
            c = val
        else:
            break
    # Just scan all clusters to find the highest used one
    max_used = 0
    for c in range(2, 4096):
        val = struct.unpack_from("<H", disk, fat_off + c * 2)[0]
        if val != 0:
            max_used = max(max_used, c)

    # startup.nsh goes in the next free cluster after max_used
    startup_cluster = max_used + 1
    startup_content = b"FS0:\\EFI\\BOOT\\BOOTX64.EFI\r\n"
    # Pad to cluster size
    padded = startup_content + b"\x00" * (CLUSTER_SIZE - len(startup_content))

    # Write cluster data
    cluster_data_off = data_off + (startup_cluster - 2) * CLUSTER_SIZE
    disk[cluster_data_off:cluster_data_off + CLUSTER_SIZE] = padded

    # Mark cluster as end-of-chain in FAT
    struct.pack_into("<H", disk, fat_off + startup_cluster * 2, 0xFFFF)

    # Add root directory entry for STARTUP NSH
    # Find first free root entry slot
    for i in range(ROOT_ENTRIES):
        entry_off = root_off + i * 32
        if disk[entry_off] == 0x00 or disk[entry_off] == 0xE5:
            e = bytearray(32)
            e[0:8] = b"STARTUP "
            e[8:11] = b"NSH"
            e[11] = 0x20  # archive
            struct.pack_into("<H", e, 26, startup_cluster)
            struct.pack_into("<I", e, 28, len(startup_content))
            disk[entry_off:entry_off + 32] = e
            break
    else:
        print("ERROR: no free root directory slot")
        sys.exit(1)

    with open(img_path, "wb") as f:
        f.write(disk)
    print(f"Added STARTUP.NSH (cluster {startup_cluster}, {len(startup_content)} bytes) to {img_path}")


if __name__ == "__main__":
    main()

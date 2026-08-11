#!/usr/bin/env python3
"""Build reference.img: identical GPT/ESP layout to aegis-boot.img, but the
FAT volume is produced by a standard filesystem implementation (pyfatfs)
instead of the hand-built FAT16 in build_image.py.

GPT construction is reused verbatim from build_image.build_gpt so the only
difference between aegis-boot.img and reference.img is the FAT body.
"""
import os
import struct
import sys
import tempfile
import zlib

import build_image
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS

SECTOR = build_image.SECTOR
TOTAL_SECTORS = build_image.TOTAL_SECTORS
PART_START_LBA = build_image.PART_START_LBA
PART_SECTORS = build_image.PART_SECTORS

HERE = os.path.dirname(os.path.abspath(__file__))
EFI_PATH = os.path.join(HERE, "target", "x86_64-unknown-uefi", "release", "uefi-boot.efi")
OUT_PATH = os.path.join(HERE, "reference.img")

FAT_TYPE = int(os.environ.get("REF_FAT_TYPE", "16"))


def build_standard_fat(efi_data):
    fat_type = {12: PyFat.FAT_TYPE_FAT12,
                16: PyFat.FAT_TYPE_FAT16,
                32: PyFat.FAT_TYPE_FAT32}[FAT_TYPE]
    tmp = os.path.join(tempfile.gettempdir(), "reference_esp.fat")
    if os.path.exists(tmp):
        os.remove(tmp)
    with open(tmp, "wb") as f:
        f.truncate(PART_SECTORS * SECTOR)

    fat = PyFat()
    fat.mkfs(tmp, fat_type=fat_type, size=PART_SECTORS * SECTOR,
             sector_size=SECTOR, number_of_fats=2, label="AEGIS REF")
    fat.close()

    fs = PyFatFS(tmp)
    fs.makedirs("/EFI")
    fs.makedirs("/EFI/BOOT")
    fs.writebytes("/EFI/BOOT/BOOTX64.EFI", efi_data)
    fs.close()

    with open(tmp, "rb") as f:
        body = f.read()
    assert len(body) == PART_SECTORS * SECTOR, len(body)
    return bytearray(body), tmp


def main():
    with open(EFI_PATH, "rb") as f:
        efi_data = f.read()
    print(f"EFI binary: {EFI_PATH} ({len(efi_data)} bytes)")

    body, tmp = build_standard_fat(efi_data)
    print(f"standard FAT{FAT_TYPE} volume built by pyfatfs: {len(body)} bytes "
          f"({PART_SECTORS} sectors) -> {tmp}")

    disk = build_image.build_gpt(body)
    with open(OUT_PATH, "wb") as f:
        f.write(disk)
    print(f"wrote {OUT_PATH}: {len(disk)} bytes ({len(disk)//SECTOR} sectors, "
          f"{len(disk)/1024/1024:.0f} MiB)")


if __name__ == "__main__":
    if not os.path.exists(EFI_PATH):
        print("ERROR: EFI binary missing")
        sys.exit(1)
    main()

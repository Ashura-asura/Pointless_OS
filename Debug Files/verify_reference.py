#!/usr/bin/env python3
"""Independent verification of reference.img (does not use build_image.py)."""
import os
import struct
import sys
import zlib

from pyfatfs.PyFatFS import PyFatFS

HERE = os.path.dirname(os.path.abspath(__file__))
IMG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "reference.img")
EFI = os.path.join(HERE, "target", "x86_64-unknown-uefi", "release", "uefi-boot.efi")
SECTOR = 512

with open(IMG, "rb") as f:
    disk = f.read()
with open(EFI, "rb") as f:
    efi_data = f.read()

ok = True


def check(label, cond, detail=""):
    global ok
    ok = ok and bool(cond)
    print(f"[{'PASS' if cond else 'FAIL'}] {label}{(' -> ' + detail) if detail else ''}")


print(f"image: {IMG}")
check("image size 32768 sectors", len(disk) == 32768 * SECTOR,
      f"{len(disk)} bytes = {len(disk)//SECTOR} sectors = {len(disk)/1024/1024:.0f} MiB")
check("MBR signature 55AA @510", disk[510:512] == b"\x55\xAA", disk[510:512].hex().upper())
check("protective MBR type 0xEE @450", disk[450] == 0xEE, hex(disk[450]))
check("GPT 'EFI PART' @512", disk[512:520] == b"EFI PART", disk[512:520].decode("latin1"))

gpt = bytearray(disk[512:1024])
stored_hdr_crc = struct.unpack_from("<I", gpt, 16)[0]
tmp = bytearray(gpt)
struct.pack_into("<I", tmp, 16, 0)
check("primary GPT header CRC", stored_hdr_crc == (zlib.crc32(bytes(tmp[:92])) & 0xFFFFFFFF) or
      stored_hdr_crc == (zlib.crc32(bytes(tmp)) & 0xFFFFFFFF), hex(stored_hdr_crc))
parr = disk[1024:1024 + 128 * 128]
check("GPT partition-array CRC", struct.unpack_from("<I", gpt, 88)[0] == (zlib.crc32(parr) & 0xFFFFFFFF))

raw = disk[1024:1040]
d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
guid = f"{d1:08X}-{d2:04X}-{d3:04X}-{raw[8:10].hex().upper()}-{raw[10:16].hex().upper()}"
check("ESP type GUID @1024", guid == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", guid)

start = struct.unpack_from("<Q", disk, 1024 + 32)[0]
end = struct.unpack_from("<Q", disk, 1024 + 40)[0]
check("partition start LBA == 2048", start == 2048, str(start))
check("partition end LBA == 32733", end == 32733, str(end))
check("first usable LBA == 34", struct.unpack_from("<Q", gpt, 40)[0] == 34,
      str(struct.unpack_from("<Q", gpt, 40)[0]))
check("last usable LBA == 32733", struct.unpack_from("<Q", gpt, 48)[0] == 32733,
      str(struct.unpack_from("<Q", gpt, 48)[0]))

last_lba = len(disk) // SECTOR - 1
bgpt = bytearray(disk[last_lba * SECTOR:(last_lba + 1) * SECTOR])
stored_b = struct.unpack_from("<I", bgpt, 16)[0]
tmpb = bytearray(bgpt)
struct.pack_into("<I", tmpb, 16, 0)
check("backup GPT header @LBA 32767 + CRC",
      bgpt[0:8] == b"EFI PART" and (stored_b == (zlib.crc32(bytes(tmpb)) & 0xFFFFFFFF) or
                                    stored_b == (zlib.crc32(bytes(tmpb[:92])) & 0xFFFFFFFF)))

fs_off = 2048 * SECTOR
bpb = disk[fs_off:fs_off + SECTOR]
fstype16 = bytes(bpb[54:62])
fstype32 = bytes(bpb[82:90])
is16 = fstype16.startswith(b"FAT")
is32 = fstype32.startswith(b"FAT32")
check("ESP boot sector 55AA", bpb[510:512] == b"\x55\xAA")
check("BPB FS type string", is16 or is32,
      f"@54='{fstype16.decode('latin1')}' @82='{fstype32.decode('latin1')}'")
print(f"       BPB: bytes/sec={struct.unpack_from('<H', bpb, 11)[0]} "
      f"sec/clus={bpb[13]} reserved={struct.unpack_from('<H', bpb, 14)[0]} "
      f"nfats={bpb[16]} rootents={struct.unpack_from('<H', bpb, 17)[0]} "
      f"secs16={struct.unpack_from('<H', bpb, 19)[0]} media={hex(bpb[21])} "
      f"fatsz16={struct.unpack_from('<H', bpb, 22)[0]} "
      f"hidden={struct.unpack_from('<I', bpb, 28)[0]} "
      f"secs32={struct.unpack_from('<I', bpb, 32)[0]} "
      f"oem='{bpb[3:11].decode('latin1')}'")

esp_path = os.path.join(os.environ.get("TEMP", "."), "_verify_esp.fat")
with open(esp_path, "wb") as f:
    f.write(disk[fs_off:fs_off + 30686 * SECTOR])
fs = PyFatFS(esp_path)
exists = fs.exists("/EFI/BOOT/BOOTX64.EFI")
check("/EFI/BOOT/BOOTX64.EFI exists (read via pyfatfs)", exists)
if exists:
    data = fs.readbytes("/EFI/BOOT/BOOTX64.EFI")
    check("BOOTX64.EFI size == 22528", len(data) == 22528, str(len(data)))
    check("BOOTX64.EFI bytes == uefi-boot.efi", data == efi_data)
    print("       listing /EFI/BOOT:", fs.listdir("/EFI/BOOT"))
    print("       listing /:", fs.listdir("/"))
fs.close()
os.remove(esp_path)

print("\nRESULT:", "ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)

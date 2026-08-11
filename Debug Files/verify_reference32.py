#!/usr/bin/env python3
"""Read-only verification of reference32.img (GPT + FAT32 ESP + BOOTX64.EFI)."""
import os
import struct
import zlib

SECTOR = 512
TOTAL_SECTORS = 131072
PART_START_LBA = 2048
LAST_LBA = TOTAL_SECTORS - 1
EXPECT_END_LBA = LAST_LBA - 34
EXPECT_EFI_SIZE = 22528

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference32.img")
with open(path, "rb") as fh:
    disk = fh.read()

ok = True


def check(label, value, expected=None):
    global ok
    if expected is None:
        print(f"  {label}: {value}")
        return
    good = value == expected
    ok = ok and good
    print(f"  [{'OK ' if good else 'BAD'}] {label}: {value!r} (expected {expected!r})")


print(f"FILE: {path}")
check("size bytes", len(disk), TOTAL_SECTORS * SECTOR)

print("\nMBR / GPT:")
check("MBR signature @510", disk[510:512].hex().upper(), "55AA")
check("MBR part type @450", hex(disk[450]), hex(0xEE))
check("MBR first LBA @454", struct.unpack_from("<I", disk, 454)[0], 1)
check("MBR size @458", struct.unpack_from("<I", disk, 458)[0], LAST_LBA)
check("GPT signature @512", disk[512:520].decode("ascii", "replace"), "EFI PART")
check("first usable LBA", struct.unpack_from("<Q", disk, 512 + 40)[0], 34)
check("last usable LBA", struct.unpack_from("<Q", disk, 512 + 48)[0], EXPECT_END_LBA)
check("entries LBA", struct.unpack_from("<Q", disk, 512 + 72)[0], 2)
check("entry count", struct.unpack_from("<I", disk, 512 + 80)[0], 128)
check("entry size", struct.unpack_from("<I", disk, 512 + 84)[0], 128)

gpt = bytearray(disk[512:1024])
stored_hdr_crc = struct.unpack_from("<I", gpt, 16)[0]
struct.pack_into("<I", gpt, 16, 0)
check("primary header CRC32", hex(stored_hdr_crc), hex(zlib.crc32(bytes(gpt)) & 0xFFFFFFFF))
part_array = disk[1024:1024 + 128 * 128]
check("partition array CRC32", hex(struct.unpack_from("<I", disk, 512 + 88)[0]),
      hex(zlib.crc32(part_array) & 0xFFFFFFFF))

bgpt = bytearray(disk[LAST_LBA * SECTOR:(LAST_LBA + 1) * SECTOR])
stored_b_crc = struct.unpack_from("<I", bgpt, 16)[0]
struct.pack_into("<I", bgpt, 16, 0)
check("backup header signature", bytes(bgpt[0:8]).decode("ascii", "replace"), "EFI PART")
check("backup header CRC32", hex(stored_b_crc), hex(zlib.crc32(bytes(bgpt)) & 0xFFFFFFFF))
check("backup entries LBA", struct.unpack_from("<Q", disk, LAST_LBA * SECTOR + 72)[0], LAST_LBA - 32)
check("backup entries array CRC32",
      hex(zlib.crc32(disk[(LAST_LBA - 32) * SECTOR:(LAST_LBA - 32) * SECTOR + 128 * 128]) & 0xFFFFFFFF),
      hex(zlib.crc32(part_array) & 0xFFFFFFFF))

print("\nESP partition entry @1024:")
raw = disk[1024:1040]
d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
guid = f"{d1:08X}-{d2:04X}-{d3:04X}-{raw[8:10].hex().upper()}-{raw[10:16].hex().upper()}"
check("type GUID", guid, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
check("start LBA", struct.unpack_from("<Q", disk, 1024 + 32)[0], PART_START_LBA)
check("end LBA", struct.unpack_from("<Q", disk, 1024 + 40)[0], EXPECT_END_LBA)
name = disk[1024 + 56:1024 + 128].decode("utf-16-le").rstrip("\x00")
check("name", name, "EFI System Partition")

fs_off = PART_START_LBA * SECTOR
print("\nFAT32 boot sector @LBA 2048:")
check("FS type string @54", disk[fs_off + 82:fs_off + 90].decode("ascii", "replace"), "FAT32   ")
check("legacy @54 offset check", disk[fs_off + 54:fs_off + 62].decode("ascii", "replace"),
      disk[fs_off + 54:fs_off + 62].decode("ascii", "replace"))
check("boot signature @510", disk[fs_off + 510:fs_off + 512].hex().upper(), "55AA")

bps = struct.unpack_from("<H", disk, fs_off + 11)[0]
spc = disk[fs_off + 13]
reserved = struct.unpack_from("<H", disk, fs_off + 14)[0]
nfats = disk[fs_off + 16]
root_ents = struct.unpack_from("<H", disk, fs_off + 17)[0]
tot16 = struct.unpack_from("<H", disk, fs_off + 19)[0]
fatsz16 = struct.unpack_from("<H", disk, fs_off + 22)[0]
hidden = struct.unpack_from("<I", disk, fs_off + 28)[0]
tot32 = struct.unpack_from("<I", disk, fs_off + 32)[0]
fatsz32 = struct.unpack_from("<I", disk, fs_off + 36)[0]
root_clus = struct.unpack_from("<I", disk, fs_off + 44)[0]
label = disk[fs_off + 71:fs_off + 82].decode("ascii", "replace")

check("bytes/sector", bps, 512)
check("sectors/cluster", spc)
check("reserved sectors", reserved)
check("number of FATs", nfats)
check("root entry count (0 for FAT32)", root_ents, 0)
check("total sectors 16 (0 for FAT32)", tot16, 0)
check("FATSz16 (0 for FAT32)", fatsz16, 0)
check("FATSz32", fatsz32)
check("hidden sectors", hidden, PART_START_LBA)
check("total sectors 32", tot32, 128990)
check("root cluster", root_clus, 2)
check("volume label", label)

data_start = reserved + nfats * fatsz32
clusters = (tot32 - data_start) // spc
check("cluster count", clusters)
print(f"  [{'OK ' if clusters >= 65525 else 'BAD'}] clusters >= 65525 -> genuine FAT32: {clusters >= 65525}")
ok = ok and clusters >= 65525

data_off = fs_off + data_start * SECTOR
fat_off = fs_off + reserved * SECTOR
csize = spc * SECTOR


def fat_next(c):
    return struct.unpack_from("<I", disk, fat_off + c * 4)[0] & 0x0FFFFFFF


def read_chain(first):
    out = bytearray()
    c = first
    guard = 0
    while 2 <= c < 0x0FFFFFF8 and guard < 200000:
        off = data_off + (c - 2) * csize
        out += disk[off:off + csize]
        c = fat_next(c)
        guard += 1
    return bytes(out)


def walk(dir_bytes):
    entries = {}
    lfn = ""
    for i in range(0, len(dir_bytes), 32):
        e = dir_bytes[i:i + 32]
        if len(e) < 32 or e[0] == 0x00:
            break
        if e[0] == 0xE5:
            continue
        if e[11] == 0x0F:
            part = (e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le", "ignore")
            lfn = part.split("\x00")[0] + lfn
            continue
        short = e[0:8].decode("ascii", "replace").rstrip() + (
            "." + e[8:11].decode("ascii", "replace").rstrip() if e[8:11].strip() else "")
        name = lfn if lfn else short
        lfn = ""
        clus = (struct.unpack_from("<H", e, 20)[0] << 16) | struct.unpack_from("<H", e, 26)[0]
        entries[name.upper()] = (clus, struct.unpack_from("<I", e, 28)[0], e[11])
    return entries


print("\nFAT32 directory walk:")
root = walk(read_chain(root_clus))
print(f"  / entries: {sorted(root)}")
found = "EFI" in root
ok = ok and found
print(f"  [{'OK ' if found else 'BAD'}] /EFI present")
if found:
    efidir = walk(read_chain(root["EFI"][0]))
    print(f"  /EFI entries: {sorted(efidir)}")
    has_boot = "BOOT" in efidir
    ok = ok and has_boot
    print(f"  [{'OK ' if has_boot else 'BAD'}] /EFI/BOOT present")
    if has_boot:
        bootdir = walk(read_chain(efidir["BOOT"][0]))
        print(f"  /EFI/BOOT entries: {sorted(bootdir)}")
        key = "BOOTX64.EFI"
        has_file = key in bootdir
        ok = ok and has_file
        print(f"  [{'OK ' if has_file else 'BAD'}] /EFI/BOOT/BOOTX64.EFI present")
        if has_file:
            clus, size, _ = bootdir[key]
            check("BOOTX64.EFI size", size, EXPECT_EFI_SIZE)
            content = read_chain(clus)[:size]
            src = os.path.join(os.path.dirname(path), "target", "x86_64-unknown-uefi",
                               "release", "uefi-boot.efi")
            with open(src, "rb") as fh:
                orig = fh.read()
            same = content == orig
            ok = ok and same
            print(f"  [{'OK ' if same else 'BAD'}] file bytes match source EFI binary "
                  f"({len(content)} bytes, MZ header={content[:2]!r})")

print("\nRESULT:", "ALL CHECKS PASSED" if ok else "FAILURES PRESENT")

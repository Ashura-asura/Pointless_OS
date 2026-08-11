import struct
import sys
import uuid
import os

D = r"C:\Users\bisha\Desktop\Pointless_OS\uefi-boot"
SECTOR = 512
GOLDEN_SECTORS = 131072
PART_START_LBA = 2048
PART_SECTORS = 128990
ESP_SIZE = PART_SECTORS * SECTOR
RESERVED = 32
NFATS = 2
SPC = 1
FAT_SECTORS = 992
DATA_START_LBA = RESERVED + NFATS * FAT_SECTORS  # 2016
TOTAL32 = PART_SECTORS
ROOT_CLUSTER = 2
FIRST_DATA_CLUSTER_LBA = DATA_START_LBA

BOOT_DIR_ENTRIES = None

def mk_boot_sector():
    b = bytearray(SECTOR)
    b[0:3] = b"\xEB\x58\x90"
    b[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", b, 11, SECTOR)
    b[13] = SPC
    struct.pack_into("<H", b, 14, RESERVED)
    b[16] = NFATS
    struct.pack_into("<H", b, 17, 0)
    struct.pack_into("<H", b, 19, 0)
    b[21] = 0xF8
    struct.pack_into("<H", b, 22, 0)
    struct.pack_into("<H", b, 24, 32)
    struct.pack_into("<H", b, 26, 64)
    struct.pack_into("<I", b, 28, 0)
    struct.pack_into("<I", b, 32, TOTAL32)
    struct.pack_into("<I", b, 36, FAT_SECTORS)
    struct.pack_into("<H", b, 40, 0)
    struct.pack_into("<H", b, 42, 0)
    struct.pack_into("<I", b, 44, ROOT_CLUSTER)
    struct.pack_into("<H", b, 48, 1)
    struct.pack_into("<H", b, 50, 6)
    b[52] = 0x80
    b[53] = 0
    b[54] = 0x29
    struct.pack_into("<I", b, 55, 0x1234ABCD)
    b[59:70] = b"NO NAME    "
    b[71:82] = b"AEGISBOOT  "
    b[82:90] = b"FAT32   "
    b[510] = 0x55
    b[511] = 0xAA
    return b

def mk_fsinfo():
    b = bytearray(SECTOR)
    b[0:4] = b"RRaA"
    b[484:488] = b"rrAa"
    struct.pack_into("<I", b, 488, 0xFFFFFFFF)
    struct.pack_into("<I", b, 492, 0xFFFFFFFF)
    b[508] = 0x55
    b[509] = 0xAA
    return b

def make_dir_entries(cluster_entries):
    out = bytearray()
    for name, attr, cl, size in cluster_entries:
        e = bytearray(32)
        nb = name.encode("ascii")[:11]
        while len(nb) < 11:
            nb += b" "
        e[11] = attr
        e[20] = ((cl >> 16) & 0xFFFF)
        e[26] = (cl & 0xFFFF)
        e[28] = 0
        struct.pack_into("<H", e, 22, 0)
        struct.pack_into("<H", e, 24, 0x4452)
        struct.pack_into("<I", e, 28, size)
        out += e
    return out

def build_esp():
    esp = bytearray(ESP_SIZE)
    boot = mk_boot_sector()
    fsinfo = mk_fsinfo()
    esp[0:SECTOR] = boot
    esp[1 * SECTOR:2 * SECTOR] = fsinfo
    esp[6 * SECTOR:7 * SECTOR] = boot
    esp[7 * SECTOR:8 * SECTOR] = fsinfo

    root = make_dir_entries([
        (".", 0x10, 2, 0),
        ("..", 0x10, 2, 0),
        ("EFI        ", 0x10, 3, 0),
    ])
    efi = make_dir_entries([
        (".", 0x10, 3, 0),
        ("..", 0x10, 2, 0),
        ("BOOT       ", 0x10, 4, 0),
    ])
    bootdir = make_dir_entries([
        (".", 0x10, 4, 0),
        ("..", 0x10, 2, 0),
        ("BOOTX64 EFI", 0x20, 5, 22528),
    ])
    cluster_lba = lambda c: (FIRST_DATA_CLUSTER_LBA + (c - 2)) * SECTOR
    esp[cluster_lba(2):cluster_lba(2) + len(root)] = root
    esp[cluster_lba(3):cluster_lba(3) + len(efi)] = efi
    esp[cluster_lba(4):cluster_lba(4) + len(bootdir)] = bootdir

    with open(os.path.join(D, "BOOTX64.EFI"), "rb") as f:
        data = f.read()
    assert len(data) == 22528, len(data)
    ncl = (len(data) + SECTOR - 1) // SECTOR
    first = 5
    esp[cluster_lba(first):cluster_lba(first) + len(data)] = data

    fat = bytearray(FAT_SECTORS * SECTOR)
    def fat_set(i, v):
        fat[i * 4:i * 4 + 4] = struct.pack("<I", v)
    fat_set(0, 0x0FFFFFF8)
    fat_set(1, 0x0FFFFFFF)
    fat_set(2, 0x0FFFFFFF)
    fat_set(3, 0x0FFFFFFF)
    fat_set(4, 0x0FFFFFFF)
    for i in range(ncl):
        fat_set(first + i, first + i + 1)
    fat_set(first + ncl - 1, 0x0FFFFFFF)
    esp[RESERVED * SECTOR:(RESERVED + FAT_SECTORS) * SECTOR] = fat
    esp[(RESERVED + FAT_SECTORS) * SECTOR:(RESERVED + 2 * FAT_SECTORS) * SECTOR] = fat
    return esp

def build_golden_z():
    with open(os.path.join(D, "golden.img"), "wb") as f:
        f.truncate(GOLDEN_SECTORS * SECTOR)
    print("golden.img zeros written:", GOLDEN_SECTORS * SECTOR)

def assemble():
    esp = build_esp()
    with open(os.path.join(D, "esp.img"), "wb") as f:
        f.write(esp)
    print("esp.img written:", len(esp))

def overlay():
    with open(os.path.join(D, "esp.img"), "rb") as f:
        esp = f.read()
    with open(os.path.join(D, "golden.img"), "r+b") as f:
        f.seek(PART_START_LBA * SECTOR)
        f.write(esp)
    print("esp.img overlaid at LBA", PART_START_LBA)

def verify():
    g = open(os.path.join(D, "golden.img"), "rb").read()
    ok = True
    def chk(label, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL"), label)
        if not cond:
            ok = False
    chk("size == %d" % (GOLDEN_SECTORS * SECTOR), len(g) == GOLDEN_SECTORS * SECTOR)
    chk("'EFI PART' at 512", g[512:520] == b"EFI PART")
    gu = uuid.UUID(bytes_le=g[1024:1040])
    chk("GUID C12A7328-F81F-11D2-BA4B-00A0C93EC93B", str(gu).upper() == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
    chk("'FAT32   ' at 2048*512+82", g[2048 * 512 + 82:2048 * 512 + 90] == b"FAT32   ")
    with open(os.path.join(D, "BOOTX64.EFI"), "rb") as f:
        payload = f.read()
    off = PART_START_LBA * SECTOR + (FIRST_DATA_CLUSTER_LBA + 3) * SECTOR
    chk("BOOTX64.EFI payload at cluster 5", g[off:off + 22528] == payload)
    chk("boot sig 55AA at partition", g[2048 * 512 + 510:2048 * 512 + 512] == b"\x55\xAA")
    print("VERDICT:", "GOLDEN-FS OK" if ok else "GOLDEN-FS BAD")
    return ok

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "make-esp":
        assemble()
    elif cmd == "overlay":
        overlay()
    elif cmd == "verify":
        verify()
    elif cmd == "golden-z":
        build_golden_z()
    else:
        sys.exit("unknown cmd")
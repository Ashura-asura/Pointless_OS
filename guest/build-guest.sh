#!/bin/bash
# Phase U-1: build the real Linux guest image (kernel + embedded BusyBox
# initramfs) for Aegis's hypervisor work, inside WSL.
#
# Usage (from WSL, repo checked out at /mnt/c/...):
#   bash /mnt/c/Users/<you>/Desktop/Pointless_OS/guest/build-guest.sh \
#       /mnt/c/Users/<you>/Desktop/Pointless_OS/guest
#
# Produces, in <repo>/guest/out/:
#   bzImage       — minimal x86_64 Linux kernel with the initramfs embedded
#   initramfs.cpio.gz — the same initramfs standalone (for -initrd boots)
#   kernel.config — the exact .config the build used (committed evidence)
#   build.log     — full build transcript (committed evidence)
#
# The kernel is configured for the classic minimal-PC device set Aegis
# emulates: 16550 UART (ttyS0), 8254 PIT, i8259 PIC, virtio-blk-pci, and is
# booted with `console=ttyS0,115200 noapic nolapic` (PIC/PIT path, no
# LAPIC/IO-APIC/HPET — the honest minimum Aegis's hypervisor must emulate).
set -e

REPO_GUEST="${1:?usage: build-guest.sh <repo>/guest}"
LINUX_VER="${LINUX_VER:-6.12.103}"
BUSYBOX_VER="${BUSYBOX_VER:-1.37.0}"
JOBS="${JOBS:-$(nproc)}"
WORK="${AEGIS_GUEST_WORK:-$HOME/aegis-guest-build}"
mkdir -p "$WORK" "$REPO_GUEST/out" "$REPO_GUEST/initramfs"

echo "==> Aegis guest build (linux $LINUX_VER, busybox $BUSYBOX_VER, jobs=$JOBS)"

# ---- BusyBox static build ------------------------------------------------
cd "$WORK"
if [ ! -d busybox-$BUSYBOX_VER ]; then
    curl -fsSL -o busybox.tar.bz2 \
        "https://busybox.net/downloads/busybox-$BUSYBOX_VER.tar.bz2"
    tar xjf busybox.tar.bz2
fi
cd busybox-$BUSYBOX_VER
make defconfig >/dev/null
# BusyBox 1.37 does not ship scripts/config; enable CONFIG_STATIC in place.
sed -i 's/^# CONFIG_STATIC is not set$/CONFIG_STATIC=y/' .config
# `tc` no longer compiles against modern kernel headers (CBQ was removed
# from the uapi); the guest has no network anyway.
sed -i 's/^CONFIG_TC=y$/CONFIG_TC=n/' .config
make oldconfig >/dev/null
make -j"$JOBS" busybox
rm -rf "$REPO_GUEST/initramfs/bin"
make CONFIG_PREFIX="$REPO_GUEST/initramfs" install >/dev/null
echo "==> busybox installed: $(ls "$REPO_GUEST/initramfs/bin" | wc -l) applets"

# ---- Linux kernel build --------------------------------------------------
cd "$WORK"
if [ ! -d linux-$LINUX_VER ]; then
    curl -fsSL -o linux.tar.xz \
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VER.tar.xz"
    tar xJf linux.tar.xz
fi
cd linux-$LINUX_VER
make defconfig >/dev/null

./scripts/config \
    --enable SERIAL_8250 \
    --enable SERIAL_8250_CONSOLE \
    --enable SERIAL_CORE_CONSOLE \
    --enable EARLY_PRINTK \
    --enable DEVTMPFS \
    --enable DEVTMPFS_MOUNT \
    --enable BLK_DEV_INITRD \
    --enable VIRTIO \
    --enable VIRTIO_PCI \
    --enable VIRTIO_PCI_LEGACY \
    --enable VIRTIO_BLK \
    --enable RTC_DRV_CMOS \
    --enable PRINTK \
    --enable TTY \
    --disable MODULES \
    --disable NET \
    --disable SOUND \
    --disable USB \
    --disable X86_5LEVEL \
    --disable EFI_STUB \
    --set-str INITRAMFS_SOURCE "$REPO_GUEST/initramfs" \
    --set-str CMDLINE "console=ttyS0,115200 noapic nolapic"
make olddefconfig >/dev/null

make -j"$JOBS" bzImage > "$REPO_GUEST/out/build.log" 2>&1

cp arch/x86/boot/bzImage "$REPO_GUEST/out/bzImage"
cp .config "$REPO_GUEST/out/kernel.config"
# Standalone initramfs copy (for -initrd boots / inspection).
(cd "$REPO_GUEST/initramfs" && find . | cpio -o -H newc 2>/dev/null | gzip > "$REPO_GUEST/out/initramfs.cpio.gz")

echo "==> bzImage: $(stat -c%s "$REPO_GUEST/out/bzImage") bytes"
echo "==> kernel.config: $(wc -l < "$REPO_GUEST/out/kernel.config") lines"
echo "==> DONE: guest image built"
#!/bin/bash
# Phase U-1 evidence: boot the guest image STANDALONE under QEMU (TCG) and
# capture the serial console. This proves the image itself is real and boots
# to an interactive shell; the Aegis-side hypervisor hosting of the same
# image is the hardware-gated half of Phase U (see capability-model.md
# §Phase U limits).
#
# Notes:
#   - The defconfig kernel has CONFIG_EFI_STUB=y, so the bzImage is also a
#     PE image; QEMU's legacy SeaBIOS -kernel path does not load such images
#     (observed with QEMU 10.2), so we boot it through OVMF (UEFI). Set
#     AEGIS_OVMF=/path/to/OVMF.fd to override, or set AEGIS_NO_OVMF=1 to skip
#     the -bios argument entirely (works only for non-EFI-stub kernels).
#   - The serial input is paced: bytes fed while the guest is still booting
#     are dropped by the 16550 FIFO, so we wait for the shell prompt first.
#
# Usage (git-bash on the host, or WSL):
#   bash guest/boot-standalone.sh [guest-dir] [commands-file]
# Writes guest/out/boot-standalone-serial.log
set -e
GUEST_DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"
CMDS="${2:-$GUEST_DIR/evidence-commands.txt}"
QEMU="${QEMU:-qemu-system-x86_64}"
LOG="$GUEST_DIR/out/boot-standalone-serial.log"
BIOS="${AEGIS_OVMF:-/usr/share/ovmf/OVMF.fd}"
INITRD="$GUEST_DIR/out/initramfs.cpio.gz"

[ -f "$GUEST_DIR/out/bzImage" ] || { echo "bzImage missing — run build-guest.sh first"; exit 1; }

BIOS_ARGS=()
if [ -z "$AEGIS_NO_OVMF" ] && [ -f "$BIOS" ]; then
    BIOS_ARGS=(-bios "$BIOS")
fi
INITRD_ARGS=()
if [ -f "$INITRD" ]; then
    INITRD_ARGS=(-initrd "$INITRD")
fi

echo "==> booting standalone guest (bios=${BIOS_ARGS[*]:-legacy-sea-bios}, kernel=$(basename "$GUEST_DIR/out/bzImage"), initrd=${INITRD_ARGS[*]:-embedded})"

# Feed a scripted interaction into the serial console so the evidence shows
# a REAL interactive shell session (commands executed, output produced), not
# just a boot banner. The guest powers itself down at the end.
{
    sleep 12   # let the guest reach the shell prompt before sending anything
    if [ -f "$CMDS" ]; then
        sed 's/\r$//; s/$/\r/' "$CMDS"
        sleep 2
    fi
    printf 'poweroff -f\r'
    sleep 10   # give poweroff time to reach ACPI S5 and let QEMU exit
} | timeout 120 "$QEMU" \
    -machine pc \
    -cpu max \
    -m 512 \
    -display none \
    -serial stdio \
    -monitor none \
    -no-reboot \
    "${BIOS_ARGS[@]}" \
    -kernel "$GUEST_DIR/out/bzImage" \
    "${INITRD_ARGS[@]}" \
    -append 'console=ttyS0' \
    2>&1 | tee "$LOG"
RC=${PIPESTATUS[1]}

if [ "$RC" = "124" ]; then
    echo "==> WARNING: QEMU hit the timeout — guest did not power off itself."
elif [ "$RC" != "0" ]; then
    echo "==> WARNING: QEMU exited with status $RC"
fi
echo "==> serial log: $LOG ($(wc -l < "$LOG") lines)"
exit "$RC"

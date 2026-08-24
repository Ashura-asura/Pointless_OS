#!/bin/sh
# Track 2 KNOWN-GATE closure: copy the battery binaries (python3, git, vim,
# nano, gcc, make) plus their shared libraries and dynamic linker into the
# BusyBox initramfs, so the guest actually has them (BusyBox does not ship
# them). Run AFTER `build-guest.sh` populates <repo>/guest/initramfs and
# BEFORE the kernel embeds it; then re-bake the cpio + bzImage (see the
# "Native Linux (Kali) runbook" in Docs/TRACK2_GUEST_BATTERY.md).
#
# Usage:
#   bash enrich-initramfs.sh <path/to/guest/initramfs> [extra bins...]
set -e

INITRAMFS="${1:?usage: enrich-initramfs.sh <path/to/guest/initramfs> [bins...]}"
shift
BINS="${*:-python3 git vim nano gcc make}"

copy_libs() {
    bin="$1"
    # Each ldd line is either " lib.so => /path (0x..)" or " /path (0x..)".
    ldd "$bin" 2>/dev/null | while read -r line; do
        lib=$(printf '%s' "$line" | sed -n 's/.*=>[[:space:]]*\([^[:space:]]*\)[[:space:]]*(.*/\1/p')
        [ -z "$lib" ] && lib=$(printf '%s' "$line" | sed -n 's#^\([^[:space:]]*\)[[:space:]]*(.*#\1#p')
        case "$lib" in
            linux-vdso*|linux-gate*|""|/*ld-linux*|/*ld-*.so*) continue ;;
        esac
        [ -e "$lib" ] || continue
        dst="$INITRAMFS$lib"
        mkdir -p "$(dirname "$dst")"
        cp -L "$lib" "$dst"
    done
    # Dynamic linker (must exist at its exact absolute path for the binary).
    linker=$(ldd "$bin" 2>/dev/null | sed -n 's#.*\(/.*/ld-linux[^[:space:]]*\|/.*/ld-[^[:space:]]*\.so[^[:space:]]*\).*#\1#p' | head -1)
    if [ -n "$linker" ] && [ -e "$linker" ]; then
        dst="$INITRAMFS$linker"
        mkdir -p "$(dirname "$dst")"
        cp -L "$linker" "$dst"
    fi
}

for b in $BINS; do
    p=$(command -v "$b" 2>/dev/null) || { echo "enrich: $b not found, skip"; continue; }
    echo "enrich: $b -> $p"
    cp -L "$p" "$INITRAMFS/bin/$b"
    copy_libs "$p"
done

echo "enrich: done. initramfs/bin now has: $(ls "$INITRAMFS/bin" 2>/dev/null | tr '\n' ' ')"

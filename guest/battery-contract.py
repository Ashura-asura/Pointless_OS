#!/usr/bin/env python3
"""Track 2 guest-app battery contract harness (CI-ready).

Boots the Aegis Linux guest under QEMU, drives the named battery from
`AEGIS_USEFUL_PROMPT.md` §3 over the virtual serial console, and asserts each
item. Exits non-zero if any contract test FAILs, so it drops straight into a
CI battery step.

Environment (all optional, sensible defaults for this repo):
  QEMU        qemu-system-x86_64 binary   (default: qemu-system-x86_64)
  KERNEL      bzImage path                (default: guest/out/bzImage)
  INITRD      initramfs.cpio.gz path      (default: guest/out/initramfs.cpio.gz)
  SERIAL_PORT TCP port for the serial     (default: 1234)
  QEMU_EXTRA  extra QEMU args             (default: "")

Usage:
  python3 guest/battery-contract.py
  QEMU=/usr/bin/qemu-system-x86_64 python3 guest/battery-contract.py

This is the automated form of the manual probes in `TRACK2_GUEST_BATTERY.md`.
It is runnable the moment a Linux+QEMU host exists (it cannot run on the
Windows/VBS dev box that authored it — see that doc's "environment gates").
"""
import os
import socket
import subprocess
import sys
import time

QEMU = os.environ.get("QEMU", "qemu-system-x86_64")
KERNEL = os.environ.get("KERNEL", os.path.join("guest", "out", "bzImage"))
INITRD = os.environ.get("INITRD", os.path.join("guest", "out", "initramfs.cpio.gz"))
PORT = int(os.environ.get("SERIAL_PORT", "1234"))
QEMU_EXTRA = os.environ.get("QEMU_EXTRA", "")

# (name, command, substring-that-means-PASS, substring-that-means-FAIL)
CONTRACTS = [
    ("shell", "echo __SH__$(busybox --help 2>&1 | head -1)",
     "__SH__BusyBox", "not found"),
    ("job_control", "sleep 1 & jobs",
     "Running", "job control turned off"),
    ("procfs", "ls /proc/self 2>&1 | head -1",
     "status", "No such file or directory"),
    ("dev_nodes", "test -c /dev/null && test -c /dev/zero && echo DEVOK",
     "DEVOK", "DEVFAIL"),
    ("python3", "python3 -c 'print(1)' 2>&1",
     "1", "python3: not found"),
    ("git", "git --version 2>&1",
     "git version", "git: not found"),
    ("vim", "vim --version 2>&1 | head -1",
     "VIM", "vim: not found"),
    ("nano", "nano --version 2>&1 | head -1",
     "GNU nano", "nano: not found"),
    ("gcc", "gcc --version 2>&1 | head -1",
     "gcc", "gcc: not found"),
    ("make", "make --version 2>&1 | head -1",
     "GNU Make", "make: not found"),
    ("networking", "ip link 2>&1 | head -5",
     "lo:", "not found"),
]


def launch_qemu():
    cmd = [
        QEMU, "-machine", "pc", "-cpu", "max", "-m", "512",
        "-display", "none",
        "-serial", f"tcp::{PORT},server,nowait",
        "-kernel", KERNEL,
        "-initrd", INITRD,
        "-append", "console=ttyS0",
    ]
    if QEMU_EXTRA:
        cmd += QEMU_EXTRA.split()
    return subprocess.Popen(cmd)


def connect(retries=40, delay=0.5):
    last = None
    for _ in range(retries):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
            return s
        except OSError as e:
            last = e
            time.sleep(delay)
    raise RuntimeError(f"could not connect to QEMU serial on :{PORT}: {last}")


def drain(sock, marker=b"~ # ", timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    try:
        while marker not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf.decode("utf-8", "replace")


def main():
    if not os.path.exists(KERNEL) or not os.path.exists(INITRD):
        print(f"MISSING guest artifacts: {KERNEL} / {INITRD}", file=sys.stderr)
        return 2
    proc = launch_qemu()
    try:
        sock = connect()
        f = sock.makefile("rwb", buffering=0)
        time.sleep(1.0)
        # Wait for the shell prompt before issuing probes.
        drain(sock, b"# ")
        results = []
        for name, cmd, ok, bad in CONTRACTS:
            f.write((cmd + "\n").encode())
            out = drain(sock, b"# ")
            passed = (ok in out) and (bad not in out)
            results.append((name, passed, out.strip()[-200:]))
            print(f"{'ok' if passed else 'FAIL'} - {name}")
        f.write(b"poweroff -f\n")
        failed = [n for n, p, _ in results if not p]
        print(f"\n# Track 2 battery: {len(results)-len(failed)}/{len(results)} passed"
              + (f", FAILED: {failed}" if failed else ""))
        return 1 if failed else 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())

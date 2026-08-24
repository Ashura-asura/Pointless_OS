#!/bin/sh
# Track 2 guest-battery init: runs the named battery probes (shell/job
# control, python3, git, vim/nano, gcc/make, /proc, networking) and reports
# each to the serial console, then powers off. No interactive input needed.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

say() { printf '%s\n' "$*" > /dev/ttyS0 2>&1 || true; }

# Same early-plumbing the real /init does (devtmpfs may not be up yet).
mkdir -p /dev
[ -c /dev/console ] || mknod /dev/console c 5 1
[ -c /dev/ttyS0 ]   || mknod /dev/ttyS0 c 4 64
mount -t proc  proc  /proc 2>/dev/null || true
mount -t sysfs sysfs /sys  2>/dev/null || true

say "=== Track2 battery begin ==="
say "uname: $(uname -a)"
say "SHELL=$0 PS1=[$PS1]"
say "--- job control test (expect 'jobs' to list the background sleep) ---"
sleep 1 & jobs
say "--- python3 (battery item 2) ---"
python3 --version 2>&1 || say "python3: MISSING"
say "--- git (battery item 3) ---"
git --version 2>&1 || say "git: MISSING"
say "--- vim / nano (battery item 4) ---"
vim --version 2>&1 | head -1 || say "vim: MISSING"
nano --version 2>&1 | head -1 || say "nano: MISSING"
say "--- gcc / make (battery item 5) ---"
gcc --version 2>&1 | head -1 || say "gcc: MISSING"
make --version 2>&1 | head -1 || say "make: MISSING"
say "--- /proc (needed by ps/meminfo/top) ---"
ls /proc 2>&1 | head -5 || say "/proc: MISSING"
cat /proc/meminfo 2>&1 | head -3 || say "/proc/meminfo: MISSING"
say "--- networking (e1000e path target) ---"
ip a 2>&1 | head -5 || say "ip: MISSING"
ifconfig 2>&1 | head -5 || say "ifconfig: MISSING"
say "--- /dev (device surface) ---"
ls /dev 2>&1 | head -20
say "=== Track2 battery end ==="
poweroff -f

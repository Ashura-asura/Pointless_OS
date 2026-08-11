#!/bin/bash
echo "UID=$(id -u)"
echo "--- pyfatfs ---"
python3 -c 'import pyfatfs; print("pyfatfs OK")' 2>&1 | tail -1
echo "--- apt ---"
apt-get --version 2>/dev/null | head -1
echo "--- net check ---"
timeout 5 bash -c 'echo > /dev/tcp/archive.ubuntu.com/80' 2>&1 && echo "NET OK" || echo "NET FAIL"
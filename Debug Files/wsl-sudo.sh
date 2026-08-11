#!/bin/bash
sudo -n true 2>&1 && echo "SUDO_OK" || echo "SUDO_FAIL"
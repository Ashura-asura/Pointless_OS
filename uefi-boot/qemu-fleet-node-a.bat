@echo off
REM Node A: connects to node B's listening socket netdev. Launch B FIRST.
set QEMU_DIR=C:\Program Files\qemu
set REPO_DIR=C:\Users\bisha\Desktop\Pointless_OS
set IMG=%REPO_DIR%\uefi-boot\aegis-boot-node-a.img
set VARS=%REPO_DIR%\uefi-boot\OVMF_VARS_fleet_A.fd

start "" /b "%QEMU_DIR%\qemu-system-x86_64.exe" ^
  -machine q35 -m 512 -cpu max ^
  -drive if=pflash,format=raw,readonly=on,file="%QEMU_DIR%\share\edk2-x86_64-code.fd" ^
  -drive if=pflash,format=raw,file="%VARS%" ^
  -drive file="%IMG%",format=raw ^
  -monitor telnet:127.0.0.1:45457,server,nowait ^
  -serial file:"%REPO_DIR%\uefi-boot\serial-fleet-a.log" ^
  -vga std -no-reboot ^
  -netdev socket,id=fleetlink,connect=127.0.0.1:45561 ^
  -device e1000e,netdev=fleetlink,mac=52:54:00:aa:00:01 ^
  -display none

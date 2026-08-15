@echo off
REM Phase L chaos-demo boot: plain OVMF boot of aegis-boot.img (no fleet socket
REM NIC — chaos-demo needs no peer; mesh/fleet demos are feature-gated out).
REM The boot image must carry STARTUP.NSH (run `python add_startup.py aegis-boot.img`
REM after `python build_image.py aegis-boot.img`) or OVMF falls through to the
REM internal shell instead of auto-booting BOOTX64.EFI.
set QEMU_DIR=C:\Program Files\qemu
set REPO_DIR=C:\Users\bisha\Desktop\Pointless_OS
set IMG=%REPO_DIR%\uefi-boot\aegis-boot.img
set VARS=%REPO_DIR%\uefi-boot\OVMF_VARS.fd

start "" /b "%QEMU_DIR%\qemu-system-x86_64.exe" ^
  -machine q35 -m 512 -cpu max ^
  -drive if=pflash,format=raw,readonly=on,file="%QEMU_DIR%\share\edk2-x86_64-code.fd" ^
  -drive if=pflash,format=raw,file="%VARS%" ^
  -drive file="%IMG%",format=raw ^
  -monitor telnet:127.0.0.1:45470,server,nowait ^
  -serial file:"%REPO_DIR%\uefi-boot\serial-chaos.log" ^
  -vga std -no-reboot ^
  -display none

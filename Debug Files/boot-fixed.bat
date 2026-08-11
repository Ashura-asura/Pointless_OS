@echo off
cd /d C:\Users\bisha\Desktop\Pointless_OS\uefi-boot
start "" "C:\Program Files\qemu\qemu-system-x86_64.exe" -machine q35 -m 512 -cpu max -drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" -drive if=pflash,format=raw,file="C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\OVMF_VARS.fd" -drive file="C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\aegis-boot.img",format=raw,if=ide,index=0,media=disk -serial file:"C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\serial-boot-fixed.log" -display none

$ErrorActionPreference = "Stop"
Start-Process -FilePath "C:\Program Files\qemu\qemu-system-x86_64.exe" -ArgumentList @(
  "-machine", "q35", "-m", "512", "-cpu", "max",
  "-drive", "if=pflash,format=raw,readonly=on,file=C:\Program Files\qemu\share\edk2-x86_64-code.fd",
  "-drive", "if=pflash,format=raw,file=C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\OVMF_VARS_fleet_A.fd",
  "-drive", "file=C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\aegis-boot-node-a.img,format=raw",
  "-monitor", "telnet:127.0.0.1:45457,server,nowait",
  "-serial", "file:C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\serial-fleet-a.log",
  "-vga", "std", "-no-reboot",
  "-netdev", "socket,id=fleetlink,connect=127.0.0.1:45561",
  "-device", "e1000e,netdev=fleetlink,mac=52:54:00:aa:00:01",
  "-display", "none"
)
Write-Output "node A launched"

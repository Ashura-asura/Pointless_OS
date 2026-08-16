$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$log = Join-Path $wd 'probe-sataboot2.log'
Remove-Item $log -ErrorAction SilentlyContinue
$A = "-machine q35 -cpu max -m 512 " +
  '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
  "-drive if=pflash,format=raw,file=`"$wd\OVMF_VARS.fd`" " +
  "-drive file=`"$wd\aegis-boot-fc.img`",format=raw,if=ide,index=0 " +
  "-drive file=`"$wd\blank-16mb.img`",format=raw,if=none,id=nvme0 " +
  '-device nvme,serial=12345,drive=nvme0 ' +
  '-vga std -display none -no-reboot ' +
  "-serial file:`"$log`""
Start-Process -FilePath $qemu -WorkingDirectory $wd -ArgumentList $A
$deadline = (Get-Date).AddSeconds(100)
$ok = $false
while ((Get-Date) -lt $deadline) {
  if (Test-Path $log) { if (Select-String -Path $log -Pattern 'Aegis: kernel started' -Quiet) { $ok = $true; break } }
  Start-Sleep -Milliseconds 500
}
Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
Write-Output "sataboot2: started=$ok"

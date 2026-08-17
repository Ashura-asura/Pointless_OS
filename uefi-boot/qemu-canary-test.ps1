# QEMU regression test for the real-hardware canary image (aegis-canary.img):
# proves the storage write path is compiled OUT even with an NVMe device on
# the PCI bus. Usage: powershell -File qemu-canary-test.ps1
$ErrorActionPreference = 'Stop'
$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = $PSScriptRoot
$mon = 45476
$disk = Join-Path $env:TEMP 'aegis-canary-nvme-test.raw'
if (Test-Path $disk) { Remove-Item $disk }
$f = [System.IO.File]::OpenWrite($disk); $f.SetLength(64MB); $f.Close()

$A = @(
  '-machine','q35','-m','512','-cpu','max','-smp','1','-nic','none',
  '-drive',"if=pflash,format=raw,unit=0,readonly=on,file=$wd\OVMF_CODE.fd",
  '-drive',"if=pflash,format=raw,unit=1,file=$wd\OVMF_VARS.fd",
  '-vga','std','-display','none',
  '-serial',"file:$wd\serial-canary-demo.log",
  '-monitor',"telnet:127.0.0.1:$mon,server,nowait",
  '-drive',"file=$wd\aegis-canary.img,format=raw,if=ide,media=disk",
  '-device','nvme,serial=DEADBEEF,drive=nvme0',
  '-drive',"id=nvme0,file=$disk,format=raw,if=none",
  '-no-reboot'
)
$p = Start-Process -FilePath $qemu -ArgumentList $A -WorkingDirectory $wd -PassThru
Start-Sleep -Seconds 40
try {
  $c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $mon)
  $s = $c.GetStream()
  $w = New-Object System.IO.StreamWriter($s)
  $w.Write("screendump $wd\scr-canary-demo.ppm`n"); $w.Flush()
  $w.Write("quit`n"); $w.Flush()
  Start-Sleep -Seconds 2
  $c.Close()
} catch { Write-Warning "monitor not reachable: $_" }
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Remove-Item $disk -ErrorAction SilentlyContinue

$log = Get-Content "$wd\serial-canary-demo.log" -Raw
Write-Host "CANARY banner: $($log -match 'CANARY: storage path compiled out')"
Write-Host "NVMe probe (must be absent): $($log -match 'NVMe: BAR')"
Write-Host "Store (must be absent): $($log -match 'NVMe-store')"
Write-Host "FAT ESP (must be absent): $($log -match 'FAT16: ESP')"
Write-Host "Desktop blit: $($log -match 'compositor desktop shown')"
Write-Host "Exceptions: $(([regex]::Matches($log, 'KERNEL EXCEPTION')).Count)"
$ErrorActionPreference = 'Stop'
$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$workdir = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$log = Join-Path $workdir 'serial-gop-demo.log'
Remove-Item $log -ErrorAction SilentlyContinue
Remove-Item (Join-Path $workdir 'scr-gop-demo.ppm') -ErrorAction SilentlyContinue

$A = '-machine q35 -m 512 -cpu max ' +
  '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
  '-drive if=pflash,format=raw,file="C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\OVMF_VARS.fd" ' +
  '-drive file="C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\aegis-boot-editor.img",format=raw,if=ide,index=0,media=disk ' +
  '-monitor telnet:127.0.0.1:45461,server,nowait ' +
  '-vga std -display none -no-reboot ' +
  "-serial file:`"$log`""
Start-Process -FilePath $qemu -WorkingDirectory $workdir -ArgumentList $A

try {
  $deadline = (Get-Date).AddSeconds(120)
  $booted = $false
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $log) {
      if (Select-String -Path $log -Pattern 'compositor desktop shown' -Quiet) {
        $booted = $true
        break
      }
    }
    Start-Sleep -Milliseconds 500
  }
  if (-not $booted) { throw 'desktop did not come up within 120 s' }
  Start-Sleep -Seconds 2
  $telnet = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 45461)
  $stream = $telnet.GetStream()
  $writer = New-Object System.IO.StreamWriter($stream)
  $writer.AutoFlush = $true
  $writer.WriteLine('screendump scr-gop-demo.ppm')
  Start-Sleep -Milliseconds 1500
  $telnet.Close()
  Write-Output ('screen lines: ' + ((Select-String -Path $log -Pattern 'Aegis: (GPU|GOP):' | Measure-Object).Count))
  Select-String -Path $log -Pattern 'Aegis: (GPU|GOP):|compositor desktop shown|Aegis: kernel up|Aegis: display' | ForEach-Object { $_.Line }
} finally {
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
}
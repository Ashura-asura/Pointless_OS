$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$log = Join-Path $wd 'probe-timer-nonvme.log'
Remove-Item $log -ErrorAction SilentlyContinue

$listener = Start-Process -FilePath 'python' -ArgumentList "e1000_host_listener.py", '9001', "$wd\e1000-timer-nonvme.pcap" -WorkingDirectory $wd -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 800

$A = "-machine q35 -cpu max -m 512 " +
  '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
  "-drive if=pflash,format=raw,file=`"$wd\OVMF_VARS.fd`" " +
  "-drive file=`"$wd\aegis-boot-fc.img`",format=raw,if=ide,index=0 " +
  '-nic socket,connect=127.0.0.1:9001 ' +
  '-vga std -display none -no-reboot ' +
  "-serial file:`"$log`""
Start-Process -FilePath $qemu -WorkingDirectory $wd -ArgumentList $A

$deadline = (Get-Date).AddSeconds(200)
$ok = $false
while ((Get-Date) -lt $deadline) {
  if (Test-Path $log) { if (Select-String -Path $log -Pattern 'compositor desktop shown' -Quiet) { $ok = $true; break } }
  Start-Sleep -Milliseconds 500
}
if ($ok) { Start-Sleep -Seconds 45 }
Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
Stop-Process -Id $listener.Id -Force -ErrorAction SilentlyContinue

$preempts = 0; $input = 0; $ticks = 0; $nvme = 0
if (Test-Path $log) {
  $raw = Get-Content $log -Raw
  $preempts = ([regex]::Matches($raw, 'preempt')).Count
  $input = ([regex]::Matches($raw, '\[input\] online')).Count
  $nvme = ([regex]::Matches($raw, 'NVMe: BAR')).Count
  $m = [regex]::Match($raw, 'tick=(\d+)')
  if ($m.Success) { $ticks = $m.Groups[1].Value }
}
Write-Output "nonvme: desktop=$ok preempts=$preempts input_online=$input last_tick=$ticks nvme_bar=$nvme"
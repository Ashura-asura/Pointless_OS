$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$log = Join-Path $wd 'probe-head.log'
Remove-Item $log -ErrorAction SilentlyContinue
$A = '-machine q35 -m 512 -cpu max ' +
  '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
  "-drive if=pflash,format=raw,file=`"$wd\OVMF_VARS.fd`" " +
  "-drive file=`"$wd\aegis-boot-head.img`",format=raw,if=ide,index=0,media=disk " +
  "-serial file:`"$log`" -no-reboot"
Start-Process -FilePath $qemu -WorkingDirectory $wd -ArgumentList $A
$deadline = (Get-Date).AddSeconds(120)
$ok = $false
while ((Get-Date) -lt $deadline) {
  if (Test-Path $log) { if (Select-String -Path $log -Pattern 'interrupts enabled - entering idle loop' -Quiet) { $ok = $true; break } }
  Start-Sleep -Milliseconds 500
}
if ($ok) { Start-Sleep -Seconds 30 }
Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
$preempts = 0; $ticks = 0
if (Test-Path $log) {
  $raw = Get-Content $log -Raw
  $preempts = ([regex]::Matches($raw, 'preempt')).Count
  $m = [regex]::Match($raw, 'tick=(\d+)')
  if ($m.Success) { $ticks = $m.Groups[1].Value }
}
Write-Output "head: idle=$ok preempts=$preempts last_tick=$ticks"

$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$log = Join-Path $wd 'probe-timer2.log'
Remove-Item $log -ErrorAction SilentlyContinue

# Exact p12b-era QEMU args (qemu-live-demo.ps1 style): SATA boot only, default
# display, no -vga std, no -nic, no NVMe.
$A = '-machine q35 -m 512 -cpu max ' +
  '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
  "-drive if=pflash,format=raw,file=`"$wd\OVMF_VARS.fd`" " +
  "-drive file=`"$wd\aegis-boot-fc.img`",format=raw,if=ide,index=0,media=disk " +
  "-serial file:`"$log`" -no-reboot"
Start-Process -FilePath $qemu -WorkingDirectory $wd -ArgumentList $A

$deadline = (Get-Date).AddSeconds(200)
$ok = $false
while ((Get-Date) -lt $deadline) {
  if (Test-Path $log) { if (Select-String -Path $log -Pattern 'compositor desktop shown' -Quiet) { $ok = $true; break } }
  Start-Sleep -Milliseconds 500
}
if ($ok) { Start-Sleep -Seconds 45 }
Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue

$preempts = 0; $input = 0; $ticks = 0
if (Test-Path $log) {
  $raw = Get-Content $log -Raw
  $preempts = ([regex]::Matches($raw, 'preempt')).Count
  $input = ([regex]::Matches($raw, '\[input\] online')).Count
  $m = [regex]::Match($raw, 'tick=(\d+)')
  if ($m.Success) { $ticks = $m.Groups[1].Value }
}
Write-Output "timer2: desktop=$ok preempts=$preempts input_online=$input last_tick=$ticks"
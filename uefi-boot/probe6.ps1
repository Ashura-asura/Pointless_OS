$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'

function Try-Boot([string]$tag, [string]$img, [string]$vars, [string]$extra) {
  $log = Join-Path $wd "probe-$tag.log"
  Remove-Item $log -ErrorAction SilentlyContinue
  $A = "-machine q35 -cpu max -m 512 $extra " +
    '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
    "-drive if=pflash,format=raw,file=`"$vars`" " +
    "-drive file=`"$img`",format=raw,if=none,id=nvme0 " +
    '-device nvme,serial=12345,drive=nvme0 ' +
    '-vga std -display none -no-reboot ' +
    "-serial file:`"$log`""
  Start-Process -FilePath $qemu -WorkingDirectory $wd -ArgumentList $A
  $deadline = (Get-Date).AddSeconds(80)
  $ok = $false
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $log) { if (Select-String -Path $log -Pattern 'Aegis: kernel started' -Quiet) { $ok = $true; break } }
    Start-Sleep -Milliseconds 500
  }
  $extra1 = ''
  if (Test-Path $log) {
    $m = Select-String -Path $log -Pattern 'FLEET.CFG|no FLEET'
    if ($m) { $extra1 = ($m.Matches[0].Value -replace '[\r\n]','') }
  }
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
  Write-Output ("{0}: started={1} {2}" -f $tag, $ok, $extra1)
}

Try-Boot 'withfc' (Join-Path $wd 'aegis-boot-fc.img') (Join-Path $wd 'OVMF_VARS.fd') ''
Try-Boot 'freshvars2' (Join-Path $wd 'aegis-boot-fc.img') (Join-Path $wd 'OVMF_VARS-fresh.fd') ''

$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$img = Join-Path $wd 'aegis-boot-editor.img'

function Try-Boot([string]$tag, [string]$nvmeProps) {
  $log = Join-Path $wd "probe-$tag.log"
  Remove-Item $log -ErrorAction SilentlyContinue
  $A = "-machine q35 -cpu max -m 512 " +
    '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
    "-drive if=pflash,format=raw,file=`"$wd\OVMF_VARS.fd`" " +
    "-drive file=`"$img`",format=raw,if=none,id=nvme0 " +
    "-device nvme,serial=12345,drive=nvme0,$nvmeProps " +
    '-vga std -display none -no-reboot ' +
    "-serial file:`"$log`""
  Start-Process -FilePath $qemu -WorkingDirectory $wd -ArgumentList $A
  $deadline = (Get-Date).AddSeconds(75)
  $ok = $false
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $log) {
      if (Select-String -Path $log -Pattern 'Aegis: kernel started' -Quiet) { $ok = $true; break }
    }
    Start-Sleep -Milliseconds 500
  }
  $bar = ''
  if (Test-Path $log) { $m = Select-String -Path $log -Pattern 'NVMe: BAR ([0-9a-f]+)' ; if ($m) { $bar = $m.Matches[0].Groups[1].Value } }
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
  Write-Output ("{0}: kernel-started={1} BAR={2}" -f $tag, $ok, $bar)
}

Try-Boot 'msixexcl' 'msix-exclusive-bar=on'
Try-Boot 'numq1' 'num_queues=1'

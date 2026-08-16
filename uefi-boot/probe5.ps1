$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$img = Join-Path $wd 'aegis-boot-editor.img'

function Try-Boot([string]$tag, [string]$extra, [string]$varsFile) {
  $log = Join-Path $wd "probe-$tag.log"
  $vars = Join-Path $wd $varsFile
  Remove-Item $log -ErrorAction SilentlyContinue
  $A = "-machine q35 -cpu max $extra " +
    '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
    "-drive if=pflash,format=raw,file=`"$vars`" " +
    "-drive file=`"$img`",format=raw,if=none,id=nvme0 " +
    '-device nvme,serial=12345,drive=nvme0 ' +
    '-vga std -display none -no-reboot ' +
    "-serial file:`"$log`""
  Start-Process -FilePath $qemu -WorkingDirectory $wd -ArgumentList $A
  $deadline = (Get-Date).AddSeconds(90)
  $ok = $false
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $log) {
      if (Select-String -Path $log -Pattern 'Aegis: kernel started' -Quiet) { $ok = $true; break }
    }
    Start-Sleep -Milliseconds 500
  }
  $fault = ''
  if (Test-Path $log) { if (Select-String -Path $log -Pattern 'Page-Fault' -Quiet) { $fault = 'PF' } }
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
  Write-Output ("{0}: kernel-started={1} {2}" -f $tag, $ok, $fault)
}

Try-Boot 'ram36g' '-m 36G' 'OVMF_VARS.fd'
Try-Boot 'freshvars' '-m 512' 'OVMF_VARS-fresh.fd'

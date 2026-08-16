$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$img = Join-Path $wd 'aegis-boot-editor.img'

function Try-Global([string]$tag, [string]$g) {
  $log = Join-Path $wd "probe-$tag.log"
  Remove-Item $log -ErrorAction SilentlyContinue
  $A = "-machine q35 -cpu max -m 512 " +
    "-global `"$g`" " +
    '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
    "-drive if=pflash,format=raw,file=`"$wd\OVMF_VARS.fd`" " +
    "-drive file=`"$img`",format=raw,if=none,id=nvme0 " +
    '-device nvme,serial=12345,drive=nvme0 ' +
    '-vga std -display none -no-reboot ' +
    "-serial file:`"$log`""
  Start-Process -FilePath $qemu -WorkingDirectory $wd -ArgumentList $A
  Start-Sleep -Seconds 3
  $started = Test-Path $log
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
  Write-Output ("{0}: global=[{1}] qemu-started={2}" -f $tag, $g, $started)
}

Try-Global 'g1' 'q35-pci-host.pci-hole64-size=1G'
Try-Global 'g2' 'q35-pci-host.pci_hole64_size=1G'
Try-Global 'g3' 'pc-q35-6.2-machine.pci-hole64-size=1G'

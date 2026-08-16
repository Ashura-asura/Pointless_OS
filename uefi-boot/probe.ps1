$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$wd = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$img = Join-Path $wd 'aegis-boot-editor.img'
$blank = Join-Path $wd 'blank-16mb.img'

function Try-Boot([string]$tag, [string]$cpu, [string]$mem, [string]$nvmeOpt, [string]$extra) {
  $log = Join-Path $wd "probe-$tag.log"
  Remove-Item $log -ErrorAction SilentlyContinue
  $A = "-machine q35 $mem $cpu " +
    '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
    "-drive if=pflash,format=raw,file=`"$wd\OVMF_VARS.fd`" " +
    "-drive file=`"$img`",format=raw,if=none,id=nvme0 " +
    "-device nvme,serial=12345,drive=nvme0 $nvmeOpt " +
    "$extra " +
    '-vga std -display none -no-reboot ' +
    "-serial file:`"$log`""
  Start-Process -FilePath $qemu -WorkingDirectory $wd -ArgumentList $A
  $deadline = (Get-Date).AddSeconds(50)
  $ok = $false
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $log) {
      if (Select-String -Path $log -Pattern 'Aegis: kernel started' -Quiet) { $ok = $true; break }
    }
    Start-Sleep -Milliseconds 500
  }
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
  Write-Output ("{0}: kernel-started={1}" -f $tag, $ok)
}

Try-Boot 'addr03' '-cpu max' '-m 512' 'bus=pcie.0,addr=0x03' "-drive file=`"$blank`",format=raw,if=ide,index=0,media=disk"
Try-Boot 'mem1g'  '-cpu max' '-m 1024' '' ''
Try-Boot 'qemu64' '-cpu qemu64' '-m 512' '' ''

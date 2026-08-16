$ErrorActionPreference = "Stop"

# Live file-browser demo (Phase Q): boot the kernel with the boot image on a
# SATA volume (EDK2 cannot map the NVMe controller BAR, so the boot volume can
# never live on NVMe) and a real emulated NVMe (PCI 00:03.0, 16 MB namespace)
# as the Phase-7 object store backing the editor's memo.txt and the browser's
# listing. The host listener is required so the netif/TLS demos complete on
# schedule. Two boots prove the DoD:
#   boot 1: the browser window is the third app window (id 5), the boot log
#           reports its listing from the durable store, Tab cycles focus onto
#           it, F3 creates `file1.txt` (a blank file), and the serial log
#           records browser@create; screendumps capture the browser raised.
#   boot 2: the same image reboots against the same NVMe file; the browser
#           re-lists the durable boot view and the boot log shows the
#           `file1.txt` created in boot 1 — the listing survived the power
#           cycle (browser@boot listing [memo.txt,file1.txt]).

$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$workdir = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$img = Join-Path $workdir 'aegis-boot-editor.img'
$store = Join-Path $workdir 'blank-16mb.img'

# Stale logs must be removed so the boot-wait poll can never match leftover
# text from a previous run.
Remove-Item (Join-Path $workdir 'serial-browser-boot1.log') -ErrorAction SilentlyContinue
Remove-Item (Join-Path $workdir 'serial-browser-boot2.log') -ErrorAction SilentlyContinue
# The store disk is reset to zeros so boot 1 always starts fresh.
$stream = [System.IO.File]::Open($store, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
$stream.SetLength(16 * 1024 * 1024)
$stream.Close()

$script:MonStream = $null

function Send-Monitor([string]$cmd, [int]$waitMs) {
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($cmd + "`n")
  $script:MonStream.Write($bytes, 0, $bytes.Length)
  $script:MonStream.Flush()
  Start-Sleep -Milliseconds $waitMs
  if ($script:MonStream.DataAvailable) {
    $buf = New-Object byte[] 65536
    $null = $script:MonStream.Read($buf, 0, $buf.Length)
  }
}

function Start-Boot([string]$log, [int]$monPort, [string]$pcap) {
  Remove-Item $log -ErrorAction SilentlyContinue
  # The listener must be up before QEMU connects out to 127.0.0.1:9001.
  $script:Listener = Start-Process -FilePath 'python' -ArgumentList "e1000_host_listener.py", '9001', "$workdir\$pcap" -WorkingDirectory $workdir -PassThru -WindowStyle Hidden
  Start-Sleep -Milliseconds 800
  $A = '-machine q35 -m 512 -cpu max ' +
    '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
    '-drive if=pflash,format=raw,file="C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\OVMF_VARS.fd" ' +
    "-drive file=`"$img`",format=raw,if=ide,index=0 " +
    "-drive file=`"$store`",format=raw,if=none,id=nvme0 " +
    '-device nvme,serial=12345,drive=nvme0 ' +
    '-nic socket,connect=127.0.0.1:9001 ' +
    "-monitor telnet:127.0.0.1:$monPort,server,nowait " +
    '-vga std -display none -no-reboot ' +
    "-serial file:`"$log`""
  Start-Process -FilePath $qemu -WorkingDirectory $workdir -ArgumentList $A
}

function Wait-Log([string]$log, [string]$pattern, [int]$timeoutSec) {
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $log) {
      if (Select-String -Path $log -Pattern $pattern -Quiet) {
        return $true
      }
    }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function Connect-Monitor([int]$monPort) {
  $client = New-Object System.Net.Sockets.TcpClient
  $client.Connect('127.0.0.1', $monPort)
  $script:MonStream = $client.GetStream()
}

try {
  # ---------------- boot 1: browser listing, focus, F3 create ----------------
  $log1 = Join-Path $workdir 'serial-browser-boot1.log'
  Start-Boot $log1 45461 'e1000-browser-boot1.pcap'
  if (-not (Wait-Log $log1 'compositor desktop shown' 160)) {
    Write-Error "boot 1 did not reach 'compositor desktop shown' within 160 s"
  }
  # The boot log must report the browser window (id 5) and its honest listing
  # (memo.txt only, since the store was just seeded).
  if (-not (Select-String -Path $log1 -Pattern 'browser@boot listing \[memo\.txt\]' -Quiet)) {
    Write-Error "boot 1 browser listing did not show memo.txt (no 'browser@boot listing [memo.txt]' line)"
  }

  Connect-Monitor 45461

  # Baseline: shell focused; the browser (id 5) is below it in z-order.
  Send-Monitor 'screendump scr-browser-baseline.ppm' 600

  # Tab -> editor, Tab -> browser: the three-app cycle raises the browser.
  Send-Monitor 'sendkey tab' 400
  Send-Monitor 'screendump scr-browser-1.ppm' 600
  Send-Monitor 'sendkey tab' 400
  Send-Monitor 'screendump scr-browser-2.ppm' 600

  # F3 creates file1.txt (first unused N) in the durable store.
  Send-Monitor 'sendkey f3' 400
  Start-Sleep -Milliseconds 500
  Send-Monitor 'screendump scr-browser-3.ppm' 600

  if (-not (Select-String -Path $log1 -Pattern 'browser@create -> window id=5 created file \(9 name bytes\)' -Quiet)) {
    Write-Error "boot 1 did not record the F3 create ('browser@create ... 9 name bytes' missing)"
  }

  Send-Monitor 'quit' 500
  $script:MonStream.Close()
  Stop-Process -Id $script:Listener.Id -Force -ErrorAction SilentlyContinue

  # ---------------- boot 2: the created file persisted in the listing ----------------
  $log2 = Join-Path $workdir 'serial-browser-boot2.log'
  Start-Boot $log2 45462 'e1000-browser-boot2.pcap'
  if (-not (Wait-Log $log2 'compositor desktop shown' 160)) {
    Write-Error "boot 2 did not reach 'compositor desktop shown'"
  }
  # The browser re-lists the durable boot view: file1.txt from boot 1 must be
  # present alongside memo.txt.
  if (-not (Wait-Log $log2 'browser@boot listing \[memo\.txt,file1\.txt\]' 160)) {
    Write-Error "boot 2 browser listing did not include file1.txt from boot 1 ('browser@boot listing [memo.txt,file1.txt]' missing)"
  }

  Connect-Monitor 45462

  # Tab, Tab -> the browser raised again: the listing now shows both files.
  Send-Monitor 'sendkey tab' 400
  Send-Monitor 'sendkey tab' 400
  Send-Monitor 'screendump scr-browser-4.ppm' 600

  Send-Monitor 'quit' 500
  $script:MonStream.Close()
  Stop-Process -Id $script:Listener.Id -Force -ErrorAction SilentlyContinue

  Write-Output 'browser demo complete; see serial-browser-boot1.log, serial-browser-boot2.log, scr-browser-*.ppm'
} finally {
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
}
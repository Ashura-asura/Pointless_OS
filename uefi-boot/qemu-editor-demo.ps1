$ErrorActionPreference = "Stop"

# Live text-editor demo (Phase P): boot the kernel with the boot image on a
# SATA volume (EDK2 cannot map the NVMe controller BAR, so the boot volume can
# never live on NVMe) and a real emulated NVMe (PCI 00:03.0, 16 MB namespace)
# as the Phase-7 object store that backs the editor's memo.txt. The host
# listener is required so the netif/TLS demos complete on schedule. Two boots
# prove the DoD:
#   boot 1: editor seeds memo.txt, Tab focuses the editor, letters are typed
#           into it, F2 saves (a real content block lands in the store), PPMs
#           capture each step.
#   boot 2: the same image reboots against the same NVMe file; the editor
#           re-attaches to the anchored boot view and reopens memo.txt — the
#           boot log's "editor@reopen ... still edited = true" proves the typed
#           edit survived the power cycle.

$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$workdir = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$img = Join-Path $workdir 'aegis-boot-editor.img'
$store = Join-Path $workdir 'blank-16mb.img'

# Stale logs must be removed so the boot-wait poll can never match leftover
# "desktop shown" / "editor@reopen" text from a previous run.
Remove-Item (Join-Path $workdir 'serial-editor-boot1.log') -ErrorAction SilentlyContinue
Remove-Item (Join-Path $workdir 'serial-editor-boot2.log') -ErrorAction SilentlyContinue
# The store disk is reset to zeros so boot 1 always seeds memo.txt fresh
# (a previous run's anchor must not be re-opened as if it were a new boot 1).
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
  # ---------------- boot 1: seed, type, save ----------------
  $log1 = Join-Path $workdir 'serial-editor-boot1.log'
  Start-Boot $log1 45459 'e1000-editor-boot1.pcap'
  if (-not (Wait-Log $log1 'compositor desktop shown' 160)) {
    Write-Error "boot 1 did not reach 'compositor desktop shown' within 160 s"
  }
  if (-not (Select-String -Path $log1 -Pattern 'editor@seed memo.txt' -Quiet)) {
    Write-Error "boot 1 did not seed memo.txt (no 'editor@seed memo.txt' line)"
  }

  Connect-Monitor 45459

  # Baseline: shell focused; the editor window sits behind it (only its
  # non-overlapped band shows through the occlusion).
  Send-Monitor 'screendump scr-editor-baseline.ppm' 600

  # Tab -> the editor window is focused and raised above the shell.
  Send-Monitor 'sendkey tab' 400
  Send-Monitor 'screendump scr-editor-1.ppm' 600

  # Type a visible edit into the editor (appended after the seed), then save
  # with F2. sendkey sends press+release, so only the `pressed` edges matter.
  Send-Monitor 'sendkey h' 250
  Send-Monitor 'sendkey i' 250
  Send-Monitor 'sendkey spc' 250
  Send-Monitor 'sendkey t' 250
  Send-Monitor 'sendkey y' 250
  Send-Monitor 'sendkey p' 250
  Send-Monitor 'sendkey e' 250
  Send-Monitor 'sendkey d' 250
  Send-Monitor 'screendump scr-editor-2.ppm' 600

  Send-Monitor 'sendkey f2' 400
  Start-Sleep -Milliseconds 500
  Send-Monitor 'screendump scr-editor-3.ppm' 600

  if (-not (Select-String -Path $log1 -Pattern 'editor@save memo.txt' -Quiet)) {
    Write-Error "boot 1 did not record an F2 save ('editor@save memo.txt' missing)"
  }

  Send-Monitor 'quit' 500
  $script:MonStream.Close()
  Stop-Process -Id $script:Listener.Id -Force -ErrorAction SilentlyContinue

  # ---------------- boot 2: reopen, the edit persisted ----------------
  $log2 = Join-Path $workdir 'serial-editor-boot2.log'
  Start-Boot $log2 45460 'e1000-editor-boot2.pcap'
  if (-not (Wait-Log $log2 'editor@reopen memo.txt.*still edited = true' 160)) {
    Write-Error "boot 2 did not prove persistence ('editor@reopen ... still edited = true' missing)"
  }
  if (-not (Wait-Log $log2 'compositor desktop shown' 160)) {
    Write-Error "boot 2 did not reach 'compositor desktop shown'"
  }

  Connect-Monitor 45460

  # Tab so the reopened editor (with the saved edit) is the topmost window.
  Send-Monitor 'sendkey tab' 400
  Send-Monitor 'screendump scr-editor-4.ppm' 600

  Send-Monitor 'quit' 500
  $script:MonStream.Close()
  Stop-Process -Id $script:Listener.Id -Force -ErrorAction SilentlyContinue

  Write-Output 'editor demo complete; see serial-editor-boot1.log, serial-editor-boot2.log, scr-editor-*.ppm'
} finally {
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
}
$ErrorActionPreference = "Stop"

# Live PS/2 mouse demo (Phase N): boot the kernel with a telnet monitor and
# -display none, drive the emulated mouse with `mouse_move`, screendump the
# cursor at three points, and record everything in serial-mouse-demo.log.
#
# Note: if `-display none` yields black screendumps, remove `-display none`
# (windowed) and retry -- the evidence must show the cursor.

$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$workdir = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$log = Join-Path $workdir 'serial-mouse-demo.log'

# Same machine/flash/drive args as qemu-live-demo.ps1 (single quoted string
# so paths with spaces survive Start-Process), plus a telnet monitor
# (45459), std VGA, no display, -no-reboot, and a serial log.
$A = '-machine q35 -m 512 -cpu max ' +
  '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
  '-drive if=pflash,format=raw,file="C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\OVMF_VARS.fd" ' +
  '-drive file="C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\aegis-boot-now.img",format=raw,if=ide,index=0,media=disk ' +
  '-monitor telnet:127.0.0.1:45459,server,nowait ' +
  '-vga std -display none -no-reboot ' +
  "-serial file:`"$log`""
Start-Process -FilePath $qemu -WorkingDirectory $workdir -ArgumentList $A

try {
  # Wait (up to ~120 s) for the desktop to be shown, polling every 500 ms.
  $deadline = (Get-Date).AddSeconds(120)
  $booted = $false
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $log) {
      if (Select-String -Path $log -Pattern 'compositor desktop shown' -Quiet) {
        $booted = $true
        break
      }
    }
    Start-Sleep -Milliseconds 500
  }
  if (-not $booted) {
    Write-Error "boot did not reach 'compositor desktop shown' within 120 s (see $log)"
  }

  # Connect to the QEMU monitor over the telnet socket.
  $client = New-Object System.Net.Sockets.TcpClient
  $client.Connect('127.0.0.1', 45459)
  $stream = $client.GetStream()

  function Send-Monitor([string]$cmd, [int]$waitMs) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($cmd + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    Start-Sleep -Milliseconds $waitMs
    # Drain whatever the monitor echoed / answered (best-effort).
    if ($stream.DataAvailable) {
      $buf = New-Object byte[] 65536
      $n = $stream.Read($buf, 0, $buf.Length)
    }
  }

  # Relative move from the boot center (400,300): +120,+60 -> ~(520,360).
  Send-Monitor 'mouse_move 120 60' 1000
  Send-Monitor 'screendump scr-mouse-1.ppm' 500
  # -240,-120 -> ~(280,240).
  Send-Monitor 'mouse_move -240 -120' 1000
  Send-Monitor 'screendump scr-mouse-2.ppm' 500
  # +240,+120 -> back to ~(520,360) (same spot as capture 1, so the two
  # captures are byte-identical: no cursor trails).
  Send-Monitor 'mouse_move 240 120' 1000
  Send-Monitor 'screendump scr-mouse-3.ppm' 500

  $client.Close()
  Write-Output 'mouse demo complete; see serial-mouse-demo.log and scr-mouse-1..3.ppm'
} finally {
  # Shut QEMU down (also on any error above).
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow
}
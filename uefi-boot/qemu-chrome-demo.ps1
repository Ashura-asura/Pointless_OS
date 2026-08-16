$ErrorActionPreference = "Stop"

# Live window-chrome demo (Phase O): boot the kernel with a telnet monitor and
# -display none, drive the emulated mouse to drag the shell window by its title
# bar, resize it from its corner, and close it via its close button, recording
# everything in serial-chrome-demo.log with screendumps at each step.

$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$workdir = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$log = Join-Path $workdir 'serial-chrome-demo.log'

# Remove any stale log from a previous run so the boot-wait poll below can
# never match leftover "desktop shown" text before this QEMU has booted.
Remove-Item $log -ErrorAction SilentlyContinue

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

  # Baseline: shell window at (2,2) with its title bar.
  Send-Monitor 'screendump scr-chrome-baseline.ppm' 500

  # 1) DRAG: cursor starts at the boot center (400,300). Move to the title
  #    bar cell (30,2) -> pixel (80+30*8, 100+2*16) = (320,132). Note: the
  #    emulated PS/2 mouse reports Y inverted vs the monitor's mouse_move,
  #    so the dy sign is flipped from the naive math.
  Send-Monitor 'mouse_move -80 168' 500
  Send-Monitor 'mouse_button 1' 500          # press: grab_dx = 30-2 = 28
  Send-Monitor 'mouse_move 60 0' 500         # to (380,132) = cell (37,2): new x = 37-28 = 9
  Send-Monitor 'mouse_button 0' 500          # release
  Send-Monitor 'screendump scr-chrome-drag.ppm' 500

  # 2) RESIZE: window now at (9,2), 60x12. Handle at cell (68,13) ->
  #    pixel (80+68*8, 100+13*16) = (624,308). Cursor is at (380,132).
  Send-Monitor 'mouse_move 244 -176' 500
  Send-Monitor 'mouse_button 1' 500          # press
  Send-Monitor 'mouse_move -60 30' 500       # to (564,278) = cell (60,11): 52x10
  Send-Monitor 'mouse_button 0' 500          # release
  Send-Monitor 'screendump scr-chrome-resize.ppm' 500

  # 3) CLOSE: window now 52x10 at (9,2). Close button at cell (60,2) ->
  #    pixel (80+60*8, 100+2*16) = (560,132). Cursor is at (564,278).
  Send-Monitor 'mouse_move -4 146' 500
  Send-Monitor 'mouse_button 1' 500          # press
  Send-Monitor 'mouse_button 0' 500          # release: window destroyed
  Send-Monitor 'screendump scr-chrome-close.ppm' 500

  # Graceful quit (instead of the force-kill in the finally block) so QEMU
  # flushes the stdio-buffered serial file; otherwise the log tail is lost.
  Send-Monitor 'quit' 500

  $client.Close()
  Write-Output 'chrome demo complete; see serial-chrome-demo.log and scr-chrome-*.ppm'
} finally {
  # Shut QEMU down (also on any error above).
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow
}
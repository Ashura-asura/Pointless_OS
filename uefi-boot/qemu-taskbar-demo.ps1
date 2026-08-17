$ErrorActionPreference = "Stop"

# Live taskbar demo (Phase S): boot the kernel with a telnet monitor and
# -display none, drive the emulated mouse to click the taskbar segments
# (the status-bar window, row SH-1, repurposed as a real taskbar) and
# switch focus mouse-only between the shell, editor, and browser windows —
# the "launch the text editor, launch the file browser, click between them
# to bring each to front" loop from the Phase S DoD, without Tab.

$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$workdir = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$log = Join-Path $workdir 'serial-taskbar-demo.log'

# Remove any stale log from a previous run so the boot-wait poll below can
# never match leftover "desktop shown" text before this QEMU has booted.
Remove-Item $log -ErrorAction SilentlyContinue

$A = '-machine q35 -m 512 -cpu max ' +
  '-drive if=pflash,format=raw,readonly=on,file="C:\Program Files\qemu\share\edk2-x86_64-code.fd" ' +
  '-drive if=pflash,format=raw,file="C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\OVMF_VARS.fd" ' +
  '-drive file="C:\Users\bisha\Desktop\Pointless_OS\uefi-boot\aegis-boot-editor.img",format=raw,if=ide,index=0,media=disk ' +
  '-monitor telnet:127.0.0.1:45460,server,nowait ' +
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
  $client.Connect('127.0.0.1', 45460)
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

  # Baseline: the taskbar is visible on the last row, shell segment
  # (the boot-default focus) highlighted.
  Send-Monitor 'screendump scr-taskbar-baseline.ppm' 500

  # 1) Click the BROWSER segment. Taskbar row is SH-1 = 24; segment centers
  #    are cells 6 (shell), 18 (editor), 30 (browser) -> pixels (128,484),
  #    (224,484), (320,484). Cursor starts centered (400,300); the emulated
  #    PS/2 mouse reports Y inverted vs mouse_move (kernel y = 300 - dy),
  #    so reaching 484 needs dy = -184.
  Send-Monitor 'mouse_move -80 -184' 500
  Send-Monitor 'mouse_button 1' 300
  Send-Monitor 'mouse_button 0' 300
  Start-Sleep -Milliseconds 500
  Send-Monitor 'screendump scr-taskbar-browser.ppm' 500

  if (-not (Select-String -Path $log -Pattern 'taskbar@click -> window id=5 focused and raised' -Quiet)) {
    Write-Error "taskbar click did not focus+raise the browser ('taskbar@click -> window id=5 ...' missing)"
  }

  # 2) Click the EDITOR segment: from (320,484) to (224,484) = (-96, 0).
  Send-Monitor 'mouse_move -96 0' 500
  Send-Monitor 'mouse_button 1' 300
  Send-Monitor 'mouse_button 0' 300
  Start-Sleep -Milliseconds 500
  Send-Monitor 'screendump scr-taskbar-editor.ppm' 500

  if (-not (Select-String -Path $log -Pattern 'taskbar@click -> window id=4 focused and raised' -Quiet)) {
    Write-Error "taskbar click did not focus+raise the editor ('taskbar@click -> window id=4 ...' missing)"
  }

  # 3) Click the SHELL segment: from (224,484) to (128,484) = (-96, 0).
  Send-Monitor 'mouse_move -96 0' 500
  Send-Monitor 'mouse_button 1' 300
  Send-Monitor 'mouse_button 0' 300
  Start-Sleep -Milliseconds 500
  Send-Monitor 'screendump scr-taskbar-shell.ppm' 500

  if (-not (Select-String -Path $log -Pattern 'taskbar@click -> window id=3 focused and raised' -Quiet)) {
    Write-Error "taskbar click did not focus+raise the shell ('taskbar@click -> window id=3 ...' missing)"
  }

  # 4) Round-trip back to the editor: the same click again must work even
  #    though the window is already focused (no-op focus still reports).
  Send-Monitor 'mouse_move 96 0' 500
  Send-Monitor 'mouse_button 1' 300
  Send-Monitor 'mouse_button 0' 300
  Start-Sleep -Milliseconds 500

  if (-not (Select-String -Path $log -Pattern 'taskbar@click -> window id=4 focused and raised' -Quiet)) {
    Write-Error "repeat taskbar click did not report the editor focus"
  }

  # Graceful quit (instead of the force-kill in the finally block) so QEMU
  # flushes the stdio-buffered serial file; otherwise the log tail is lost.
  Send-Monitor 'quit' 500

  $client.Close()
  Write-Output 'taskbar demo complete; see serial-taskbar-demo.log and scr-taskbar-*.ppm'
} finally {
  # Shut QEMU down (also on any error above).
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
}
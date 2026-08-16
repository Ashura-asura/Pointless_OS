$ErrorActionPreference = "Stop"

# Live shell command-interpreter demo (Phase R): the shell window (id 3, the
# default post-boot surface) is now a command interpreter over the same boot
# view the editor and browser use, not a single-line echo. The boot volume
# again rides on SATA (EDK2 cannot map the NVMe controller BAR) while a real
# emulated NVMe (PCI 00:03.0, 16 MB namespace) backs the Phase-7 object store.
# The host listener is required so the netif/TLS demos complete on schedule.
# Two boots prove the DoD:
#   boot 1: the editor seeds memo.txt; the shell, still focused, runs a full
#           command sequence typed with real PS/2 scancodes — `help` (5 output
#           lines), `ls` ([memo.txt] = 1 row), `open 1` (prints the file), `new`
#           (creates file1.txt), `clear` (0 lines), then `ls` again ([memo.txt,
#           file1.txt] = 2 rows). The serial log records each Enter outcome
#           ("N char(s) -> M line(s) of output") and PPMs capture the scrollback.
#   boot 2: the same image reboots against the same NVMe file; the shell's `ls`
#           re-reads the durable boot view and reports both files — the shell's
#           commands, like the browser's, survive the power cycle.

$qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
$workdir = 'C:\Users\bisha\Desktop\Pointless_OS\uefi-boot'
$img = Join-Path $workdir 'aegis-boot-shell.img'
$store = Join-Path $workdir 'blank-16mb.img'

# Stale logs must be removed so the boot-wait poll can never match leftover
# text from a previous run.
Remove-Item (Join-Path $workdir 'serial-shell-boot1.log') -ErrorAction SilentlyContinue
Remove-Item (Join-Path $workdir 'serial-shell-boot2.log') -ErrorAction SilentlyContinue
# The store disk is reset to zeros so boot 1 always starts fresh (memo.txt is
# then seeded anew by the editor's boot-time handle).
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

function Type-Word([string]$word) {
  # Send one key per character with sendkey (press+release), exactly as the
  # editor demo types into its buffer. Space is 'spc', Enter is 'ret'.
  foreach ($ch in $word.ToCharArray()) {
    $key = if ($ch -eq ' ') { 'spc' } else { $ch.ToString() }
    Send-Monitor "sendkey $key" 300
  }
  Send-Monitor 'sendkey ret' 400
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

function Assert-Log([string]$log, [string]$pattern, [string]$what) {
  if (-not (Select-String -Path $log -Pattern $pattern -Quiet)) {
    Write-Error "$what ('$pattern' missing)"
  }
}

function Wait-Enter([string]$log, [string]$pattern, [string]$what) {
  if (-not (Wait-Log $log $pattern 60)) {
    Write-Error "$what ('$pattern' missing)"
  }
}

try {
  # ---------------- boot 1: run the shell's command sequence ----------------
  $log1 = Join-Path $workdir 'serial-shell-boot1.log'
  Start-Boot $log1 45463 'e1000-shell-boot1.pcap'
  if (-not (Wait-Log $log1 'compositor desktop shown' 160)) {
    Write-Error "boot 1 did not reach 'compositor desktop shown' within 160 s"
  }
  # Sanity: the durable boot view starts with memo.txt (seeded by the editor).
  Assert-Log $log1 'browser@boot listing \[memo\.txt\]' 'boot 1 browser listing did not show memo.txt'

  Connect-Monitor 45463

  # Baseline: the shell (id 3) is focused with an empty scrollback; the
  # prompt sits on the window's last row (Phase R).
  Send-Monitor 'screendump scr-shell-baseline.ppm' 600

  # help -> 5 output lines (HELP_LINES). The letter echoes prove the chars
  # reached the shell's line (window id=3), not another window.
  Type-Word 'help'
  Assert-Log $log1 "echo 'h' -> window id=3 line pos=0" 'boot 1 shell did not echo the first typed letter'
  Wait-Enter $log1 'submitted 4 char\(s\) -> 5 line\(s\) of output' 'boot 1 help did not print 5 lines'
  Send-Monitor 'screendump scr-shell-help.ppm' 600

  # ls -> one row ("1 memo.txt").
  Type-Word 'ls'
  Wait-Enter $log1 'submitted 2 char\(s\) -> 1 line\(s\) of output' 'boot 1 ls did not list the single file'
  Send-Monitor 'screendump scr-shell-ls.ppm' 600

  # open 1 -> prints memo.txt's content ("Aegis editor: first file").
  Type-Word 'open 1'
  Wait-Enter $log1 'submitted 6 char\(s\) -> 1 line\(s\) of output' 'boot 1 open 1 did not print the file'
  Send-Monitor 'screendump scr-shell-open.ppm' 600

  # new -> creates file1.txt (first unused N) in the durable store.
  Type-Word 'new'
  Wait-Enter $log1 'submitted 3 char\(s\) -> 1 line\(s\) of output' 'boot 1 new did not create a file'
  Send-Monitor 'screendump scr-shell-new.ppm' 600

  # clear -> empties the scrollback (0 lines).
  Type-Word 'clear'
  Wait-Enter $log1 'submitted 5 char\(s\) -> 0 line\(s\) of output' 'boot 1 clear did not empty the scrollback'
  Send-Monitor 'screendump scr-shell-clear.ppm' 600

  # ls again -> now TWO rows: memo.txt and the file1.txt just created.
  Type-Word 'ls'
  Wait-Enter $log1 'submitted 2 char\(s\) -> 2 line\(s\) of output' 'boot 1 second ls did not list both files'
  Send-Monitor 'screendump scr-shell-ls2.ppm' 600

  # Tab, Tab -> raise the browser: its listing was refreshed by the shell's
  # `new`, so it shows both files without any browser input.
  Send-Monitor 'sendkey tab' 400
  Send-Monitor 'sendkey tab' 400
  Send-Monitor 'screendump scr-shell-browser.ppm' 600

  Send-Monitor 'quit' 500
  $script:MonStream.Close()
  Stop-Process -Id $script:Listener.Id -Force -ErrorAction SilentlyContinue

  # ---------------- boot 2: the shell's ls sees the persisted file ----------------
  $log2 = Join-Path $workdir 'serial-shell-boot2.log'
  Start-Boot $log2 45464 'e1000-shell-boot2.pcap'
  if (-not (Wait-Log $log2 'compositor desktop shown' 160)) {
    Write-Error "boot 2 did not reach 'compositor desktop shown'"
  }
  # file1.txt from boot 1's shell `new` must have survived the power cycle.
  if (-not (Wait-Log $log2 'browser@boot listing \[memo\.txt,file1\.txt\]' 160)) {
    Write-Error "boot 2 listing did not include file1.txt from boot 1"
  }

  Connect-Monitor 45464

  # The shell's ls re-reads the durable view: both files, from the shell.
  Type-Word 'ls'
  Wait-Enter $log2 'submitted 2 char\(s\) -> 2 line\(s\) of output' 'boot 2 shell ls did not list both files'
  Send-Monitor 'screendump scr-shell-boot2.ppm' 600

  Send-Monitor 'quit' 500
  $script:MonStream.Close()
  Stop-Process -Id $script:Listener.Id -Force -ErrorAction SilentlyContinue

  Write-Output 'shell demo complete; see serial-shell-boot1.log, serial-shell-boot2.log, scr-shell-*.ppm'
} finally {
  Start-Process -FilePath 'taskkill' -ArgumentList '/F', '/IM', 'qemu-system-x86_64.exe' -Wait -NoNewWindow -ErrorAction SilentlyContinue
}
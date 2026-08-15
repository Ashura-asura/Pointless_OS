@echo off
REM Node A: connects to node B's listening socket netdev. Launch B FIRST.
set QEMU_DIR=C:\Program Files\qemu
set REPO_DIR=C:\Users\bisha\Desktop\Pointless_OS
set IMG=%REPO_DIR%\uefi-boot\aegis-boot-node-a.img
set VARS=%REPO_DIR%\uefi-boot\OVMF_VARS_fleet_A.fd

start "" /b "%QEMU_DIR%\qemu-system-x86_64.exe" ^
  -machine q35 -m 512 -cpu max ^
  -drive if=pflash,format=raw,readonly=on,file="%QEMU_DIR%\share\edk2-x86_64-code.fd" ^
  -drive if=pflash,format=raw,file="%VARS%" ^
  -drive file="%IMG%",format=raw ^
  -monitor telnet:127.0.0.1:45457,server,nowait ^
  -serial file:"%REPO_DIR%\uefi-boot\serial-fleet-a.log" ^
  -vga std -no-reboot ^
  -netdev socket,id=fleetlink,connect=127.0.0.1:45560 ^
  -device e1000e,netdev=fleetlink,mac=52:54:00:aa:00:01 ^
  -display none

REM Capture THIS node's real PID, disambiguated from node B by the unique
REM image filename in its command line — "qemu-system-x86_64.exe" alone
REM can't tell A from B (both run the same binary), and a /b-backgrounded
REM process has no distinct window title for tasklist to filter on. This
REM is what directly caused the "killed both VMs by mistake" incident: a
REM name-only kill can't target one node without the other. Short poll
REM loop covers the brief window between `start` and the process actually
REM registering with WMI.
set PIDFILE=%REPO_DIR%\uefi-boot\node-a.pid
del "%PIDFILE%" >nul 2>&1
for /l %%i in (1,1,20) do (
  for /f "skip=1 tokens=1" %%p in ('wmic process where "name='qemu-system-x86_64.exe' and commandline like '%%aegis-boot-node-a.img%%'" get processid 2^>nul') do (
    if not "%%p"=="" echo %%p> "%PIDFILE%"
  )
  if exist "%PIDFILE%" goto :found_a
  timeout /t 1 /nobreak >nul
)
:found_a
if exist "%PIDFILE%" (
  echo Node A PID captured in %PIDFILE% — kill it with kill-node-a.bat, NOT taskkill /IM.
) else (
  echo WARNING: could not capture node A's PID automatically — node-a.pid was not written.
  echo Do not blind-kill by image name ^(qemu-system-x86_64.exe^) — that kills node B too.
)

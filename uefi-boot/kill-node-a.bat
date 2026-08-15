@echo off
REM Kills ONLY node A, by exact PID captured at launch time in node-a.pid —
REM never by process name (both nodes run the identical qemu-system-x86_64.exe
REM binary, so a name-based kill takes down node B too, which is exactly what
REM happened during the last fail-closed test attempt).
REM
REM Untested by the author of this script (no Windows machine available to
REM run it against) — sanity-check the reported PID against Task Manager's
REM "Command line" column (or Process Explorer) before trusting it, the
REM first time you use it, to confirm it's really node A and not node B.

set REPO_DIR=C:\Users\bisha\Desktop\Pointless_OS
set PIDFILE=%REPO_DIR%\uefi-boot\node-a.pid

if not exist "%PIDFILE%" (
    echo node-a.pid not found.
    echo Was node A started via the current qemu-fleet-node-a.bat ^(which now
    echo writes this file automatically^), not an older copy of the script?
    exit /b 1
)

set /p NODE_A_PID=<"%PIDFILE%"

echo About to kill PID %NODE_A_PID% — verify this is node A before confirming.
echo Cross-check: tasklist /fi "PID eq %NODE_A_PID%" /v
tasklist /fi "PID eq %NODE_A_PID%"

choice /m "Proceed with taskkill /PID %NODE_A_PID% /F"
if errorlevel 2 (
    echo Aborted — no process killed.
    exit /b 1
)

taskkill /PID %NODE_A_PID% /F
echo Node A killed ^(PID %NODE_A_PID%^). Node B should still be running —
echo watch serial-fleet-b.log for the next "verify DENIED (fail-closed):
echo PeerStale" line once STALE_AFTER_TICKS elapses.

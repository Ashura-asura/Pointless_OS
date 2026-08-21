# Builds the real-hardware canary image (aegis-canary.img) from source.
# Usage: powershell -File build-canary.ps1
# Output: uefi-boot/aegis-canary.img (write to USB in DD mode, see ../Docs/hardware-milestones.md)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$kern = "$root\aegis-kernel"
$ub   = $PSScriptRoot

function ContainsBytes([byte[]]$haystack, [byte[]]$needle) {
    if ($needle.Length -gt $haystack.Length) { return $false }
    for ($i = 0; $i -le $haystack.Length - $needle.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $needle.Length; $j++) {
            if ($haystack[$i + $j] -ne $needle[$j]) { $match = $false; break }
        }
        if ($match) { return $true }
    }
    return $false
}

Push-Location $kern
try {
    $env:RUSTFLAGS = '-Dwarnings'
    cargo build --release --features kernel --target x86_64-unknown-none
    Copy-Item "target\x86_64-unknown-none\release\aegis-kernel" "$ub\aegis-kernel.bin" -Force
    cargo build --release --features kernel,canary --target x86_64-unknown-none
    Copy-Item "target\x86_64-unknown-none\release\aegis-kernel" "$ub\aegis-kernel-canary.bin" -Force
} finally { Pop-Location }

Push-Location $ub
try {
    # Loader builds run in ISOLATED target dirs: the loader embeds the kernel
    # via include_bytes!("../aegis-kernel.bin") at compile time, so the canary
    # loader must compile with the canary bin on disk. Isolated target dirs
    # (both fresh) make both builds deterministic — no include_bytes mtime
    # fingerprint games (cargo only rebuilds when an input is NEWER than the
    # artifact, and PowerShell Copy-Item preserves source mtimes).
    Copy-Item aegis-kernel.bin aegis-kernel.normal.bak -Force
    Copy-Item aegis-kernel-canary.bin aegis-kernel.bin -Force
    cargo build --release --features uefi --target x86_64-unknown-uefi --target-dir target-canary
    Copy-Item "target-canary\x86_64-unknown-uefi\release\uefi-boot.efi" aegis-canary.efi -Force

    # CANARY loader sanity check: the efi must embed the canary kernel.
    $bytes = [System.IO.File]::ReadAllBytes("$ub\aegis-canary.efi")
    $needle = [System.Text.Encoding]::ASCII.GetBytes("CANARY: storage path compiled out")
    if (-not (ContainsBytes $bytes $needle)) { throw "aegis-canary.efi does not embed the canary kernel - aborting" }

    python build_image.py aegis-canary.img aegis-canary.efi
    python add_startup.py aegis-canary.img

    # Restore the normal loader + image (normal build in its own fresh dir).
    Copy-Item aegis-kernel.normal.bak aegis-kernel.bin -Force
    Remove-Item aegis-kernel.normal.bak -Force
    cargo build --release --features uefi --target x86_64-unknown-uefi --target-dir target-normal
    Copy-Item "target-normal\x86_64-unknown-uefi\release\uefi-boot.efi" "target\x86_64-unknown-uefi\release\uefi-boot.efi" -Force
    $bytes = [System.IO.File]::ReadAllBytes("$ub\target\x86_64-unknown-uefi\release\uefi-boot.efi")
    if (ContainsBytes $bytes $needle) { throw "normal loader still embeds the canary kernel - aborting" }
    python build_image.py aegis-boot-editor.img
    python add_startup.py aegis-boot-editor.img
} finally { Pop-Location }

Write-Host "DONE: aegis-canary.img rebuilt (normal image restored)."
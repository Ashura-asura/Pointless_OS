# Extract REAL firmware / hardware descriptors from the running Windows host.
# Output: aegis-kernel/hardware-fixtures/*.bin + *.txt (raw bytes + readable summary).
#
# Hardware-evidence track (Phase AG follow-on). Sources used:
#  - SMBIOS raw : WMI root\wmi MSSmBios_RawSMBiosTables (real raw SMBIOS).
#  - ACPI tables: Win32 GetSystemFirmwareTable('ACPI', <sig>) — the real RSDT,
#                 XSDT, FADT, APIC (MADT) and DSDT bytes, user-mode, no driver.
#  - PCI identity: HKLM\SYSTEM\CurrentControlSet\Enum\PCI + Win32_PnPEntity
#                 (real VEN/DEV/SUBSYS/REV + class), fed to the kernel's PCI
#                 classification helpers.
#  - VT-x gate  : Win32_DeviceGuard (VirtualizationFirmwareEnabled) + the
#                 Memory-Integrity / VBS registry keys, to state whether VT-x
#                 is blocked by firmware or by Windows.
#
# Run:  powershell -NoProfile -ExecutionPolicy Bypass -File extract-hardware-fixtures.ps1
# From: repo root.

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Out  = Join-Path $Root "aegis-kernel\hardware-fixtures"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Dump-Bytes($bytes, $name) {
    if ($bytes -and $bytes.Length -gt 0) {
        [IO.File]::WriteAllBytes((Join-Path $Out $name), $bytes)
        Write-Host ("  wrote {0} ({1} bytes)" -f $name, $bytes.Length)
    } else { Write-Host ("  (no data for {0})" -f $name) }
}

# Win32 multicharacter literal: 'ABCD' == (A<<24)|(B<<16)|(C<<8)|D (big-endian-as-DWORD).
function Sig($s) {
    $b = [System.Text.Encoding]::ASCII.GetBytes($s)
    return ([int]$b[0] -shl 24) + ([int]$b[1] -shl 16) + ([int]$b[2] -shl 8) + [int]$b[3]
}

# ---- P/Invoke for GetSystemFirmwareTable -------------------------------------
$acpiType = @'
using System;
using System.Runtime.InteropServices;
public class Firmware {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int GetSystemFirmwareTable(int provider, int tableId, IntPtr buf, int size);
}
'@
Add-Type -TypeDefinition $acpiType

function Get-ACPI-Table($sig4) {
    # Provider 'ACPI' is the big-endian-as-DWORD literal (0x41435049), but the
    # per-table id is the little-endian DWORD of the signature bytes as they
    # sit in the table header (BitConverter on the 4 ASCII bytes), which is the
    # convention GetSystemFirmwareTable matches against the published tables.
    $prov = Sig "ACPI"
    $tid  = [BitConverter]::ToUInt32([System.Text.Encoding]::ASCII.GetBytes($sig4), 0)
    # First call: required size.
    $need = [Firmware]::GetSystemFirmwareTable($prov, $tid, [IntPtr]::Zero, 0)
    if ($need -le 0) { return $null }
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($need)
    try {
        $got = [Firmware]::GetSystemFirmwareTable($prov, $tid, $buf, $need)
        if ($got -le 0) { return $null }
        $bytes = New-Object byte[] $got
        [System.Runtime.InteropServices.Marshal]::Copy($buf, $bytes, 0, $got)
        return $bytes
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    }
}

# ---- 1. Raw SMBIOS (WMI) -----------------------------------------------------
Write-Host "[1] SMBIOS (raw)"
try {
    $smb = Get-CimInstance -Namespace root\wmi -ClassName MSSmBios_RawSMBiosTables -ErrorAction Stop
    if ($smb -and $smb.SMBiosData) { Dump-Bytes ([byte[]]@($smb.SMBiosData)) "smbios.bin" }
    else { Write-Host "  (no SMBiosData)" }
} catch { Write-Host ("  SMBIOS WMI failed: {0}" -f $_.Exception.Message) }

# ---- 2. ACPI tables via GetSystemFirmwareTable ------------------------------
Write-Host "[2] ACPI tables (GetSystemFirmwareTable)"
# Enumerate every ACPI table signature this firmware actually publishes
# (this laptop is XSDT-only: RSDT is not exposed, but MADT/FADT/DMAR/... are).
$enumType = @'
using System;
using System.Runtime.InteropServices;
public class Firmware2 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int EnumSystemFirmwareTables(int provider, IntPtr buf, int size);
}
'@
Add-Type -TypeDefinition $enumType -ErrorAction SilentlyContinue
$prov = (Sig "ACPI")
$esize = [Firmware2]::EnumSystemFirmwareTables($prov, [IntPtr]::Zero, 0)
$sigs = @()
if ($esize -gt 0) {
    $eb = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($esize)
    $eg = [Firmware2]::EnumSystemFirmwareTables($prov, $eb, $esize)
    $ea = New-Object byte[] $eg
    [System.Runtime.InteropServices.Marshal]::Copy($eb, $ea, 0, $eg)
    for ($i = 0; $i -lt $ea.Length; $i++) { } # noop
    for ($i = 0; $i -lt $ea.Length; $i += 4) { $sigs += (-join ($ea[$i..($i+3)] | % { [char]$_ })) }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($eb)
}
$sigSummary = @()
$sigSummary += ("enumerated signatures: " + ($sigs -join ","))
foreach ($sig in $sigs) {
    $b = Get-ACPI-Table $sig
    if ($b) {
        Dump-Bytes $b ("acpi-{0}.bin" -f $sig.ToLower())
        $sig4 = -join ($b[0..3] | % { [char]$_ })
        $sigSummary += ("{0}: {1} bytes (header sig '{2}')" -f $sig, $b.Length, $sig4)
    } else {
        $sigSummary += ("{0}: (not retrievable)" -f $sig)
    }
}
Set-Content -Path (Join-Path $Out "acpi-summary.txt") -Value $sigSummary

# ---- 3. Real PCI device identity -------------------------------------------
Write-Host "[3] PCI device identity"
$pciReg = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
$rows = @()
if (Test-Path $pciReg) {
    foreach ($dev in (Get-ChildItem $pciReg -ErrorAction SilentlyContinue)) {
        $hwId = $dev.PSChildName
        $ven = ""; $devId = ""
        if ($hwId -match 'VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})') { $ven = $Matches[1]; $devId = $Matches[2] }
        $desc = ""
        $sub = Get-ChildItem $dev.PSPath -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sub) {
            $prop = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
            if ($prop.DeviceDesc) { $desc = $prop.DeviceDesc }
        }
        $rows += ("{0}`t{1}`t{2}`t{3}" -f $hwId, $ven, $devId, $desc)
    }
}
try {
    foreach ($p in (Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue)) {
        if ($p.PNPDeviceID -and $p.PNPDeviceID.StartsWith("PCI")) {
            $rows += ("{0}`twmi`t{1}" -f $p.PNPDeviceID, $p.Name)
        }
    }
} catch { Write-Host ("  WMI PCI warn: {0}" -f $_.Exception.Message) }
if ($rows.Count -gt 0) {
    Set-Content -Path (Join-Path $Out "pci-devices.tsv") -Value $rows
    Write-Host ("  wrote pci-devices.tsv ({0} entries)" -f $rows.Count)
} else { Write-Host "  (no PCI devices)" }

# ---- 4. Host summary + VT-x gate -------------------------------------------
Write-Host "[4] Host summary + VT-x gate"
$sum = @()
try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem; $sum += "Manufacturer: $($cs.Manufacturer)"; $sum += "Model: $($cs.Model)" } catch {}
try { $bb = Get-CimInstance -ClassName Win32_BaseBoard; $sum += "BaseBoard: $($bb.Manufacturer) $($bb.Product)" } catch {}
try { $bios = Get-CimInstance -ClassName Win32_BIOS; $sum += "BIOS: $($bios.Manufacturer) $($bios.Version) ($($bios.ReleaseDate))" } catch {}
try { $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1; $sum += "CPU: $($cpu.Name) / cores=$($cpu.NumberOfCores) / logical=$($cpu.NumberOfLogicalProcessors)" } catch {}

# VT-x: who blocks it — firmware or Windows?
$vtx = @()
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if ($dg) {
        $vtx += "DeviceGuard.VirtualizationFirmwareEnabled: $($dg.VirtualizationFirmwareEnabled)"
        $vtx += "DeviceGuard.SecurityServicesConfigured: $($dg.SecurityServicesConfigured)"
        $vtx += "DeviceGuard.SecurityServicesRunning: $($dg.SecurityServicesRunning)"
        $vtx += "DeviceGuard.Version: $($dg.Version)"
        $fwVtx = $dg.VirtualizationFirmwareEnabled
    } else { $vtx += "DeviceGuard: (Win32_DeviceGuard unavailable in this session)" }
} catch { $vtx += "DeviceGuard query error: $($_.Exception.Message)" }

# Memory Integrity / VBS registry (no admin needed to read).
$miKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
$mi = "(unavailable)"
if (Test-Path $miKey) {
    $mp = Get-ItemProperty -Path $miKey -ErrorAction SilentlyContinue
    if ($mp.Enabled -ne $null) { $mi = switch ($mp.Enabled) { 0 {"disabled"} 1 {"enabled (default)"} 2 {"enabled (with UEFI lock)"} default { "enabled($($mp.Enabled))" } } }
}
$vbsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$vbs = "(unavailable)"
if (Test-Path $vbsKey) {
    $vp = Get-ItemProperty -Path $vbsKey -ErrorAction SilentlyContinue
    if ($vp.EnableVirtualizationBasedSecurity -ne $null) { $vbs = $vp.EnableVirtualizationBasedSecurity }
}
$vtx += "MemoryIntegrity (HVCI): $mi"
$vtx += "VBS EnableVirtualizationBasedSecurity: $vbs"

# Verdict.
if ($fwVtx -eq $false) {
    $vtx += "VT-x VERDICT: BLOCKED BY FIRMWARE (BIOS/UEFI disables virtualization). Re-enable in BIOS."
} elseif ($mi -match "enabled") {
    $vtx += "VT-x VERDICT: firmware supports it, but WINDOWS blocks it (Memory Integrity / VBS reserves VMX). Disabling Core Isolation (Windows Security -> Device Security -> Core Isolation) should unblock nested VMX."
} elseif ($vbs -match "1|2") {
    $vtx += "VT-x VERDICT: firmware supports it; Windows VBS is on. Disabling VBS/Memory Integrity should unblock VMX for a type-2 hypervisor."
} else {
    $vtx += "VT-x VERDICT: firmware supports virtualization and no Windows blocker detected; VMX should be available to a hypervisor."
}

$sum += "--- VT-x gate ---"
$sum += $vtx
Set-Content -Path (Join-Path $Out "host-summary.txt") -Value $sum
Set-Content -Path (Join-Path $Out "vtx-status.txt") -Value $vtx
Write-Host "  wrote host-summary.txt + vtx-status.txt"
Write-Host "Done. Fixtures in: $Out"

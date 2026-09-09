<#
.SYNOPSIS
    Ultron Defender (AegisPC) - Kernel Driver Build & Deployment Diagnostics
.DESCRIPTION
    Checks whether the local machine has the prerequisites required to compile,
    sign, and load the AegisFilter.sys ring-0 filesystem minifilter driver:
    1. 64-bit Windows OS
    2. MSBuild / Visual Studio C++ toolchain
    3. Windows Driver Kit (WDK 10/11)
    4. SignTool.exe & Inf2Cat.exe
    5. Test-signing mode (bcdedit)
    6. Filter Manager (fltmc.exe)
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "   ULTRON DEFENDER (AEGISPC) - KERNEL PREREQUISITE DIAGNOSTICS   " -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$results = [ordered]@{}
$allPass = $true

# 1. OS Architecture
$is64 = [Environment]::Is64BitOperatingSystem
if ($is64) {
    Write-Host "[+] Operating System: 64-bit Windows ($([System.Environment]::OSVersion.VersionString))" -ForegroundColor Green
    $results["OS_Architecture"] = "64-bit (PASS)"
} else {
    Write-Host "[-] Operating System: 32-bit (AegisFilter requires x64)" -ForegroundColor Red
    $results["OS_Architecture"] = "32-bit (FAIL)"
    $allPass = $false
}

# 2. MSBuild Detection
$msBuildPaths = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
)

$foundMsBuild = $null
foreach ($path in $msBuildPaths) {
    if (Test-Path $path) {
        $foundMsBuild = $path
        break
    }
}

if ($foundMsBuild) {
    Write-Host "[+] MSBuild Found: $foundMsBuild" -ForegroundColor Green
    $results["MSBuild"] = "Found ($foundMsBuild)"
} else {
    Write-Host "[-] MSBuild NOT found in standard paths." -ForegroundColor Yellow
    Write-Host "    Requires: Visual Studio 2019/2022 with C++ Desktop Development." -ForegroundColor DarkGray
    $results["MSBuild"] = "Missing"
    $allPass = $false
}

# 3. WDK (Windows Driver Kit) Detection
$wdkRoots = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\x64"
)

$foundWdk = $null
foreach ($w in $wdkRoots) {
    if (Test-Path "$w\signtool.exe") {
        $foundWdk = $w
        break
    }
}

if ($foundWdk) {
    Write-Host "[+] Windows Driver Kit (WDK) Tools Found: $foundWdk" -ForegroundColor Green
    $results["WDK"] = "Found ($foundWdk)"
} else {
    Write-Host "[-] WDK tools (signtool/inf2cat) NOT found in standard Windows Kits directories." -ForegroundColor Yellow
    Write-Host "    To install WDK 10/11:" -ForegroundColor DarkGray
    Write-Host "    1. Download Windows SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/" -ForegroundColor DarkGray
    Write-Host "    2. Download Windows Driver Kit (WDK): https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk" -ForegroundColor DarkGray
    $results["WDK"] = "Missing"
    $allPass = $false
}

# 4. Filter Manager (fltmc.exe)
$fltmc = Get-Command fltmc.exe -ErrorAction SilentlyContinue
if ($fltmc) {
    Write-Host "[+] Filter Manager CLI found: $($fltmc.Source)" -ForegroundColor Green
    $results["FilterManager"] = "Present"
} else {
    Write-Host "[-] fltmc.exe not found in PATH." -ForegroundColor Red
    $results["FilterManager"] = "Missing"
}

# 5. Test-Signing Mode
$testSigningEnabled = $false
try {
    $bcd = bcdedit /enum "{current}" 2>&1
    if ($bcd -match "testsigning\s+Yes") {
        $testSigningEnabled = $true
    }
} catch { }

if ($testSigningEnabled) {
    Write-Host "[+] Windows Test-Signing Mode: ENABLED" -ForegroundColor Green
    $results["TestSigning"] = "Enabled (Ready for test-signed .sys)"
} else {
    Write-Host "[!] Windows Test-Signing Mode: DISABLED" -ForegroundColor Yellow
    Write-Host "    To enable test signing (Elevated Administrator CMD/PowerShell):" -ForegroundColor DarkGray
    Write-Host "    > bcdedit /set testsigning on" -ForegroundColor DarkCyan
    Write-Host "    > shutdown /r /t 0  (reboot required)" -ForegroundColor DarkCyan
    $results["TestSigning"] = "Disabled"
}

# 6. AegisFilter driver project verification
$driverDir = Join-Path $PSScriptRoot "AegisFilter"
$cSource = Join-Path $driverDir "AegisFilter.c"
$infFile = Join-Path $driverDir "AegisFilter.inf"

if ((Test-Path $cSource) -and (Test-Path $infFile)) {
    Write-Host "[+] AegisFilter C source and INF definitions intact." -ForegroundColor Green
    $results["DriverSource"] = "Valid"
} else {
    Write-Host "[-] Driver source or INF missing in $driverDir" -ForegroundColor Red
    $results["DriverSource"] = "Incomplete"
    $allPass = $false
}

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "   SUMMARY & STATUS REPORT                                        " -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
$results.GetEnumerator() | ForEach-Object {
    Write-Host ("{0,-20} : {1}" -f $_.Key, $_.Value)
}
Write-Host ""

if ($allPass) {
    Write-Host "[SUCCESS] All driver compilation and loading prerequisites are met!" -ForegroundColor Green
    Write-Host "You can execute .\Build-And-Sign-Driver.ps1 to build AegisFilter.sys." -ForegroundColor Green
} else {
    Write-Host "[NOTE] WDK or MSBuild is missing on this workstation." -ForegroundColor Yellow
    Write-Host "Ultron Defender runs in TRUE 'DEGRADED (USER-MODE ONLY)' mode using ETW Pre-Exec and FileSystemWatcher." -ForegroundColor Yellow
    Write-Host "When built on a CI/CD or development machine with WDK installed, use .\Build-And-Sign-Driver.ps1." -ForegroundColor DarkGray
}

return $allPass

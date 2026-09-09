<#
.SYNOPSIS
    Ultron Defender (AegisPC) - AegisFilter Kernel Minifilter Build & Sign Pipeline
.DESCRIPTION
    Automates the compilation, catalog generation, test-signing, and local deployment
    of the AegisFilter.sys ring-0 filesystem minifilter driver.
.PARAMETER Configuration
    Build configuration (default: Release)
.PARAMETER Platform
    Target platform (default: x64)
.PARAMETER Install
    If specified, installs and loads the driver via rundll32 and fltmc (requires elevation)
.PARAMETER SkipBuild
    Skips compilation step (uses existing AegisFilter.sys)
.PARAMETER SkipSign
    Skips signing step
#>

[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [switch]$Install,
    [switch]$SkipBuild,
    [switch]$SkipSign
)

$ErrorActionPreference = "Stop"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "   ULTRON DEFENDER - KERNEL MINIFILTER BUILD & SIGN PIPELINE     " -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$driverDir = Join-Path $PSScriptRoot "AegisFilter"
$outputDir = Join-Path $PSScriptRoot "bin\$Platform\$Configuration"
$certSubject = "CN=Ultron Defender Driver Test Signing Authority"
$certFriendlyName = "Ultron Defender Driver Test Signing Authority"

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# -------------------------------------------------------------------------
# STEP 1: Toolchain Discovery (MSBuild & WDK)
# -------------------------------------------------------------------------
Write-Host "[*] STEP 1: Discovering MSBuild and Windows Driver Kit (WDK)..." -ForegroundColor Yellow

$msBuildExe = $null
$msBuildCandidates = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
)

foreach ($c in $msBuildCandidates) {
    if (Test-Path $c) {
        $msBuildExe = $c
        break
    }
}

$wdkBin = $null
$wdkCandidates = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64",
    "C:\Program Files (x86)\Windows Kits\10\bin\x64"
)

foreach ($w in $wdkCandidates) {
    if (Test-Path "$w\signtool.exe") {
        $wdkBin = $w
        break
    }
}

if ($wdkBin) {
    Write-Host "[+] WDK binary directory: $wdkBin" -ForegroundColor Green
    $env:PATH = "$wdkBin;$env:PATH"
}

# -------------------------------------------------------------------------
# STEP 2: Compilation (AegisFilter.vcxproj)
# -------------------------------------------------------------------------
if (-not $SkipBuild) {
    Write-Host ""
    Write-Host "[*] STEP 2: Compiling AegisFilter ($Configuration|$Platform)..." -ForegroundColor Yellow

    if (-not $msBuildExe) {
        Write-Error "[-] MSBuild.exe could not be located. Ensure Visual Studio with C++ tools is installed."
        exit 1
    }

    $projectPath = Join-Path $driverDir "AegisFilter.vcxproj"
    if (-not (Test-Path $projectPath)) {
        Write-Error "[-] Driver project file not found: $projectPath"
        exit 1
    }

    $buildArgs = @(
        "`"$projectPath`"",
        "/p:Configuration=$Configuration",
        "/p:Platform=$Platform",
        "/p:OutDir=`"$outputDir\`"",
        "/t:Rebuild",
        "/m"
    )

    Write-Host "Executing: & `"$msBuildExe`" $buildArgs" -ForegroundColor DarkGray
    & $msBuildExe $buildArgs

    if ($LASTEXITCODE -ne 0) {
        Write-Error "[-] Minifilter driver compilation failed with exit code $LASTEXITCODE."
        exit $LASTEXITCODE
    }

    Write-Host "[+] Minifilter driver compiled successfully: $outputDir\AegisFilter.sys" -ForegroundColor Green
} else {
    Write-Host "[*] STEP 2: Compilation skipped by user (-SkipBuild)." -ForegroundColor DarkGray
}

# Copy INF file to output directory
Copy-Item (Join-Path $driverDir "AegisFilter.inf") (Join-Path $outputDir "AegisFilter.inf") -Force
Write-Host "[+] Copied AegisFilter.inf to $outputDir" -ForegroundColor Green

# -------------------------------------------------------------------------
# STEP 3: Catalog (.cat) File Generation via Inf2Cat
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] STEP 3: Generating driver package catalog (.cat) file..." -ForegroundColor Yellow

$inf2cat = Get-Command inf2cat.exe -ErrorAction SilentlyContinue
if ($inf2cat) {
    & inf2cat.exe /driver:"$outputDir" /os:10_X64,Server2022_X64,Server2019_X64
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Driver catalog generated: $outputDir\AegisFilter.cat" -ForegroundColor Green
    } else {
        Write-Warning "[!] Inf2Cat exited with code $LASTEXITCODE. Continuing without catalog..."
    }
} else {
    Write-Warning "[!] inf2cat.exe not found. Catalog generation skipped."
}

# -------------------------------------------------------------------------
# STEP 4: Test Certificate Setup
# -------------------------------------------------------------------------
if (-not $SkipSign) {
    Write-Host ""
    Write-Host "[*] STEP 4: Verifying/Creating Test Signing Certificate..." -ForegroundColor Yellow

    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*Ultron Defender Driver Test Signing Authority*" } | Select-Object -First 1

    if (-not $cert) {
        Write-Host "[*] Generating new SHA256 Code-Signing Certificate in LocalMachine\My..." -ForegroundColor Cyan
        try {
            $cert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject $certSubject `
                -FriendlyName $certFriendlyName `
                -CertStoreLocation "Cert:\LocalMachine\My" `
                -HashAlgorithm "SHA256" `
                -KeyLength 2048 `
                -NotAfter (Get-Date).AddYears(5)

            # Add to Root and TrustedPublisher stores for driver loading
            $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
            $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $rootStore.Add($cert)
            $rootStore.Close()

            $pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
            $pubStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $pubStore.Add($cert)
            $pubStore.Close()

            Write-Host "[+] Installed certificate to Root and TrustedPublisher stores: $($cert.Thumbprint)" -ForegroundColor Green
        } catch {
            Write-Warning "[!] Failed to create LocalMachine certificate (requires Administrator). Attempting CurrentUser store..."
            $cert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject $certSubject `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -HashAlgorithm "SHA256"
        }
    } else {
        Write-Host "[+] Found existing test signing certificate: $($cert.Thumbprint)" -ForegroundColor Green
    }

    # -------------------------------------------------------------------------
    # STEP 5: Sign Driver & Catalog via SignTool
    # -------------------------------------------------------------------------
    Write-Host ""
    Write-Host "[*] STEP 5: Signing AegisFilter.sys and catalog with Authenticode SHA256..." -ForegroundColor Yellow

    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    $sysPath = Join-Path $outputDir "AegisFilter.sys"
    $catPath = Join-Path $outputDir "AegisFilter.cat"

    if ($signtool -and (Test-Path $sysPath)) {
        & signtool.exe sign /v /s My /n "Ultron Defender Driver Test Signing Authority" /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 "$sysPath"
        if (Test-Path $catPath) {
            & signtool.exe sign /v /s My /n "Ultron Defender Driver Test Signing Authority" /fd SHA256 /tr "http://timestamp.digicert.com" /td SHA256 "$catPath"
        }
        Write-Host "[+] Binary and catalog test-signing completed successfully!" -ForegroundColor Green
    } else {
        Write-Warning "[!] signtool.exe not found in PATH or $sysPath missing. Signing skipped."
    }
}

# -------------------------------------------------------------------------
# STEP 6: Optional Driver Installation
# -------------------------------------------------------------------------
if ($Install) {
    Write-Host ""
    Write-Host "[*] STEP 6: Installing and starting AegisFilter..." -ForegroundColor Yellow

    $infPath = Join-Path $outputDir "AegisFilter.inf"
    Write-Host "[*] Executing INF installation: rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 $infPath" -ForegroundColor DarkCyan
    Start-Process -FilePath "rundll32.exe" -ArgumentList "setupapi.dll,InstallHinfSection DefaultInstall 132 `"$infPath`"" -Wait

    Write-Host "[*] Loading minifilter via fltmc..." -ForegroundColor DarkCyan
    & fltmc load AegisFilter
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] AegisFilter driver successfully loaded into Windows Filter Manager!" -ForegroundColor Green
        & fltmc instances -n AegisFilter
    } else {
        Write-Warning "[!] fltmc load AegisFilter exited with code $LASTEXITCODE. Ensure 'bcdedit /set testsigning on' is enabled and the system has been rebooted."
    }
}

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "   BUILD & PACKAGING COMPLETE                                     " -ForegroundColor Cyan
Write-Host "   Output files: $outputDir                                        " -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan

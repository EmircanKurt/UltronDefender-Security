<#
.SYNOPSIS
    Ultron Defender (AegisPC) - Unified Production Binary Signing Utility
.DESCRIPTION
    Signs Ultron Defender binaries (drivers, COM DLLs, Windows services, executables, installer)
    with Authenticode SHA256 digital signature and RFC 3161 timestamping.
    Also verifies existing signatures and reports compliance status.
.PARAMETER CertificateThumbprint
    Specific certificate thumbprint to use from Cert:\CurrentUser\My or Cert:\LocalMachine\My
.PARAMETER TargetFiles
    List of explicit file paths to sign
.PARAMETER AutoFindBinaries
    Automatically searches and signs all compiled project binaries
.PARAMETER VerifyOnly
    Only checks and prints signature status without signing
#>

[CmdletBinding()]
param(
    [string]$CertificateThumbprint,
    [string[]]$TargetFiles,
    [switch]$AutoFindBinaries,
    [switch]$CreateSelfSignedIfMissing,
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Continue"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "   ULTRON DEFENDER (AEGISPC) - AUTHENTICODE SIGNING UTILITY       " -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$rootDir = Split-Path $PSScriptRoot -Parent
$certSubject = "Ultron Defender Code Signing Authority"
$timestampServer = "http://timestamp.digicert.com"

# 1. Discover SignTool.exe
$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signtool) {
    $wdkCandidates = @(
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
    )
    foreach ($c in $wdkCandidates) {
        if (Test-Path $c) {
            $signtool = Get-Item $c
            break
        }
    }
}

if ($signtool) {
    $signtoolDisplay = if ($signtool.FullName) { $signtool.FullName } else { $signtool.Source }
    Write-Host "[+] SignTool located: $signtoolDisplay" -ForegroundColor Green
} else {
    Write-Host "[!] SignTool.exe not found. Falling back to PowerShell Set-AuthenticodeSignature." -ForegroundColor Yellow
}

# 2. Resolve or Generate Code Signing Certificate
$cert = $null
if ($CertificateThumbprint) {
    $cert = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-Item "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
    }
}

if (-not $cert) {
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -like "*$certSubject*" } | Select-Object -First 1
    if (-not $cert) {
        $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Where-Object { $_.Subject -like "*$certSubject*" } | Select-Object -First 1
    }
}

if (-not $cert -and -not $VerifyOnly) {
    Write-Host "[*] No existing code-signing certificate found. Creating self-signed test certificate..." -ForegroundColor Cyan
    try {
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject "CN=$certSubject" `
            -FriendlyName "Ultron Defender Local Signing" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -HashAlgorithm "SHA256" `
            -KeyLength 2048 `
            -NotAfter (Get-Date).AddYears(5)
        Write-Host "[+] Certificate created: $($cert.Thumbprint) in Cert:\CurrentUser\My" -ForegroundColor Green
    } catch {
        Write-Error "[-] Failed to create self-signed certificate: $_"
        exit 1
    }
}

if ($cert) {
    Write-Host "[+] Active Certificate: $($cert.Subject) (Thumbprint: $($cert.Thumbprint))" -ForegroundColor Green
}

# 3. Determine Files to Process
$files = [System.Collections.Generic.List[string]]::new()

if ($TargetFiles) {
    foreach ($tf in $TargetFiles) {
        if (Test-Path $tf) { $files.Add((Get-Item $tf).FullName) }
    }
}

if ($AutoFindBinaries -or ($files.Count -eq 0)) {
    $searchPaths = @(
        "$rootDir\drivers\bin\x64\Release\AegisFilter.sys",
        "$rootDir\drivers\bin\x64\Release\AegisFilter.cat",
        "$rootDir\drivers\bin\x64\Debug\AegisFilter.sys",
        "$rootDir\drivers\bin\x64\Debug\AegisFilter.cat",
        "$rootDir\tools\AmsiProvider\bin\Release\AmsiProvider.dll",
        "$rootDir\tools\AmsiProvider\bin\x64\Release\AmsiProvider.dll",
        "$rootDir\tools\AmsiProvider\bin\x64\Debug\AmsiProvider.dll",
        "$rootDir\bin\Release\AmsiProvider.dll",
        "$rootDir\bin\Debug\AmsiProvider.dll",
        "$rootDir\src\AegisPC.Service\bin\Release\net8.0-windows\AegisPC.Service.exe",
        "$rootDir\src\AegisPC.Service\bin\Debug\net8.0-windows\AegisPC.Service.exe",
        "$rootDir\src\AegisPC.App\bin\Release\net8.0-windows\UltronDefender.exe",
        "$rootDir\src\AegisPC.App\bin\Debug\net8.0-windows\UltronDefender.exe"
    )
    foreach ($sp in $searchPaths) {
        if (Test-Path $sp) {
            $files.Add((Get-Item $sp).FullName)
        }
    }
}

Write-Host "`n[*] Discovered $($files.Count) binary target(s) to process." -ForegroundColor Cyan

# 4. Sign and/or Verify
$results = @()

foreach ($f in $files) {
    $fileName = Split-Path $f -Leaf
    if (-not $VerifyOnly) {
        Write-Host " -> Signing $fileName..." -NoNewline
        if ($signtool) {
            $signtoolPath = if ($signtool -is [System.IO.FileInfo]) { $signtool.FullName } else { $signtool.Source }
            & "$signtoolPath" sign /v /sha1 "$($cert.Thumbprint)" /fd SHA256 /tr "$timestampServer" /td SHA256 "$f" 2>&1 | Out-Null
        } else {
            Set-AuthenticodeSignature -FilePath "$f" -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $timestampServer | Out-Null
        }
    }

    $sig = Get-AuthenticodeSignature "$f"
    $statusColor = if ($sig.Status -eq "Valid") { "Green" } else { "Yellow" }
    Write-Host " Status: [$($sig.Status)]" -ForegroundColor $statusColor

    $results += [PSCustomObject]@{
        Binary = $fileName
        Status = $sig.Status
        Signer = $sig.SignerCertificate.Subject
        Digest = $sig.SignerCertificate.Thumbprint
        Path   = $f
    }
}

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "   SIGNATURE VERIFICATION SUMMARY                                 " -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
$results | Format-Table Binary, Status, Signer -AutoSize

Write-Host "[OK] Process completed." -ForegroundColor Cyan

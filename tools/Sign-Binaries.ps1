# Ultron Defender Binary Signing & Verification Script
param (
    [string]$TargetDir = "AegisPC_App"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Ultron Defender] Binary Code Signing & Verification" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Find Ultron Defender Code Signing Certificate
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object {
    $_.Subject -match "Ultron Defender" -or $_.Thumbprint -eq "74EF70CAD86983EBCB288B8D5C84E7D4BB7BA526"
} | Select-Object -First 1

if (-not $cert) {
    Write-Host "Mevcut sertifika bulunamadi, yeni test sertifikasi olusturuluyor..." -ForegroundColor Yellow
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=Ultron Defender Code Signing Authority, O=Ultron Security Technologies" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm SHA256
}

Write-Host "Secilen Sertifika:" -ForegroundColor Green
Write-Host "  Subject:    $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  ValidUntil: $($cert.NotAfter)`n"

# Files to sign
$filesToSign = @(
    (Join-Path $TargetDir "UltronDefender.exe"),
    (Join-Path $TargetDir "AegisPC.exe"),
    (Join-Path $TargetDir "Ultron Defender Security.exe"),
    (Join-Path $TargetDir "Ultron Defender Total Security.exe"),
    (Join-Path $TargetDir "Service\AegisPC.Service.exe"),
    (Join-Path $TargetDir "Helpers\AegisPC.ElevatedHelper.exe"),
    (Join-Path $TargetDir "Uninstall.exe")
)

$setupExe = "UltronDefenderSetup.exe"
if (Test-Path $setupExe) {
    $filesToSign += $setupExe
}

$results = @()
foreach ($file in $filesToSign) {
    if (Test-Path $file) {
        Write-Host "Imzalaniyor: $file ... " -NoNewline
        $sig = Set-AuthenticodeSignature -FilePath $file -Certificate $cert -HashAlgorithm SHA256
        $color = if ($sig.Status -eq "Valid") { "Green" } else { "Yellow" }
        Write-Host "[$($sig.Status)]" -ForegroundColor $color
        $results += $sig
    } else {
        Write-Host "Dosya bulunamadi (atlandi): $file" -ForegroundColor DarkGray
    }
}

Write-Host "`n--- Dogrulama Sonuclari ---" -ForegroundColor Cyan
$verified = Get-AuthenticodeSignature $filesToSign -ErrorAction SilentlyContinue
$verified | Select-Object Path, Status, StatusMessage, @{Name="Subject"; Expression={$_.SignerCertificate.Subject}} | Format-Table -AutoSize

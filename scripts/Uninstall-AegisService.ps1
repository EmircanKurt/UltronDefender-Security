# ==============================================================================
# AegisPC / Ultron Defender - Windows Protection Service Uninstaller
# ==============================================================================
# Run this script with Administrator privileges.

$ServiceName = "AegisPC Protection Service"

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Ultron Defender Windows Servis Kaldırma" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Servis durduruluyor..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    
    Write-Host "Servis kaydı siliniyor..." -ForegroundColor Yellow
    sc.exe delete $ServiceName
    
    Write-Host "Ultron Defender Protection Service başarıyla kaldırıldı." -ForegroundColor Green
} else {
    Write-Host "Kayıtlı '$ServiceName' servisi bulunamadı." -ForegroundColor Yellow
}

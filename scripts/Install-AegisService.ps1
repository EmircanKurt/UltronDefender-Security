# ==============================================================================
# AegisPC / Ultron Defender - Windows Protection Service Installer
# ==============================================================================
# Run this script with Administrator privileges.

$ServiceName = "AegisPC Protection Service"
$DisplayName = "AegisPC Protection Service"
$Description = "Ultron Defender gerçek zamanlı dosya kalkanı, fidye yazılımı engelleme ve IPC koruma hizmeti."

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BaseDir = Split-Path -Parent $ScriptDir
$ServiceExe = Join-Path $BaseDir "bin\Release\service\AegisPC.Service.exe"

if (-not (Test-Path $ServiceExe)) {
    $ServiceExe = Join-Path $BaseDir "src\AegisPC.Service\bin\Debug\net8.0-windows\AegisPC.Service.exe"
}

if (-not (Test-Path $ServiceExe)) {
    Write-Error "AegisPC.Service.exe bulunamadı! Lütfen önce projeyi derleyin (dotnet build)."
    exit 1
}

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Ultron Defender Windows Servis Kurulumu" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "Servis Yolu: $ServiceExe" -ForegroundColor Yellow

# Check if service already exists
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Mevcut servis durduruluyor ve siliniyor..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create Windows Service
Write-Host "Windows Hizmeti kaydediliyor..." -ForegroundColor Green
$binPath = "`"$ServiceExe`""
sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= $DisplayName

if ($LASTEXITCODE -ne 0) {
    Write-Error "Servis oluşturulamadı. Lütfen PowerShell'i Yönetici olarak çalıştırdığınızdan emin olun."
    exit 1
}

# Configure description and recovery
sc.exe description $ServiceName $Description
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000

# Start Service
Write-Host "Servis başlatılıyor..." -ForegroundColor Green
Start-Service -Name $ServiceName

$status = Get-Service -Name $ServiceName
Write-Host "Servis Durumu: $($status.Status)" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "Kurulum başarıyla tamamlandı!" -ForegroundColor Green

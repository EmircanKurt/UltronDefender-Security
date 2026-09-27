# =====================================================================
# Ultron Defender (AegisPC) - Kod Kapsama (Code Coverage) Raporlama Scripti
# =====================================================================
param(
    [string]$Configuration = "Release",
    [switch]$OpenReport = $false
)

$ErrorActionPreference = "Stop"
$rootDir = Resolve-Path "$PSScriptRoot\.."
$coverageDir = Join-Path $rootDir "coverage"
$reportDir = Join-Path $rootDir "coverage-report"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " Ultron Defender - Code Coverage Analizi Başlatılıyor" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# 1. Eski coverage verilerini temizle
if (Test-Path $coverageDir) {
    Remove-Item -Recurse -Force $coverageDir
}
if (Test-Path $reportDir) {
    Remove-Item -Recurse -Force $reportDir
}

New-Item -ItemType Directory -Force -Path $coverageDir | Out-Null
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

# 2. Testleri çalıştır ve Cobertura formatında coverage topla
Write-Host "`n[1/3] Birim ve Entegrasyon testleri koşturuluyor (coverlet)..." -ForegroundColor Yellow
$testProj = Join-Path $rootDir "tests\AegisPC.Tests\AegisPC.Tests.csproj"

dotnet test $testProj `
    -c $Configuration `
    --collect:"XPlat Code Coverage" `
    --results-directory $coverageDir `
    --settings "$PSScriptRoot\coverlet.runsettings" `
    --logger "console;verbosity=minimal"

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[HATA] Bazı testler başarısız oldu! Coverage raporu üretilmeden önce testlerin geçmesi gerekir." -ForegroundColor Red
    exit $LASTEXITCODE
}

# 3. ReportGenerator aracını kontrol et / kur
Write-Host "`n[2/3] ReportGenerator aracı kontrol ediliyor..." -ForegroundColor Yellow
$hasReportGen = (dotnet tool list -g | Select-String "dotnet-reportgenerator-globaltool")

if (-not $hasReportGen) {
    Write-Host "ReportGenerator kurulu değil. Global araç kuruluyor..." -ForegroundColor Magenta
    dotnet tool install -g dotnet-reportgenerator-globaltool
}

# 4. İnteraktif HTML ve Metin Özeti Raporu Üret
Write-Host "`n[3/3] HTML ve rozet raporları üretiliyor..." -ForegroundColor Yellow
$reportsPattern = "$coverageDir\**\coverage.cobertura.xml"

reportgenerator `
    "-reports:$reportsPattern" `
    "-targetdir:$reportDir" `
    "-reporttypes:Html;Badges;TextSummary" `
    "-title:Ultron Defender Total Security - Code Coverage"

$summaryFile = Join-Path $reportDir "Summary.txt"
if (Test-Path $summaryFile) {
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host " KAPSAMA ÖZETİ (Coverage Summary)" -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Green
    Get-Content $summaryFile | Select-Object -First 25 | Write-Host -ForegroundColor White
}

$htmlIndex = Join-Path $reportDir "index.html"
Write-Host "`n[BAŞARILI] Detaylı HTML raporu hazırlandı: $htmlIndex" -ForegroundColor Green

if ($OpenReport -and (Test-Path $htmlIndex)) {
    Start-Process $htmlIndex
}

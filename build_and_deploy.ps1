<#
.SYNOPSIS
    Ultron Defender Total Security - Build, Publish & Deploy Pipeline
#>

[CmdletBinding()]
param (
    [switch]$SkipTests,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$repoRoot = (Get-Location).Path

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Ultron Defender Total Security] Build & Deploy Pipeline" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. TEST STEP
if (-not $SkipTests) {
    Write-Host "`n[1/4] Testler calistiriliyor (Golden Test Suite)..." -ForegroundColor Yellow
    & dotnet test --filter "Golden" --logger "console;verbosity=minimal"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Golden Test Suite basarisiz oldu! Dagitim iptal edildi."
        exit 1
    }
    Write-Host "[OK] Golden Test Suite basariyla gecti!" -ForegroundColor Green
} else {
    Write-Host "`n[1/4] Testler atlandi (-SkipTests)." -ForegroundColor DarkGray
}

# 2. PUBLISH STEP
Write-Host "`n[2/4] Release ikilileri AegisPC_App klasorune yayimlaniyor..." -ForegroundColor Yellow
$appDir = Join-Path $repoRoot "AegisPC_App"
$helpersDir = Join-Path $appDir "Helpers"

# Calisan uygulama varsa dosya kilitlerini onlemek icin nazikce durdur
Stop-Process -Name "UltronDefender" -Force -ErrorAction SilentlyContinue

& dotnet publish "src\AegisPC.App\AegisPC.App.csproj" -c Release -r win-x64 --self-contained true -o $appDir
& dotnet publish "tools\AegisPC.ElevatedHelper\AegisPC.ElevatedHelper.csproj" -c Release -r win-x64 --self-contained true -o $helpersDir
& dotnet publish "tools\AegisPC.Uninstaller\AegisPC.Uninstaller.csproj" -c Release -r win-x64 --self-contained true -o $appDir

# 3. SHORTCUT & ALIAS SYNC
Write-Host "`n[3/4] Masaustu kisayolu ve takma ad ikilileri senkronize ediliyor..." -ForegroundColor Yellow
$exePath = Join-Path $appDir "UltronDefender.exe"
Copy-Item -Path $exePath -Destination (Join-Path $appDir "AegisPC.exe") -Force
Copy-Item -Path $exePath -Destination (Join-Path $appDir "Ultron Defender Security.exe") -Force
Copy-Item -Path $exePath -Destination (Join-Path $appDir "Ultron Defender Total Security.exe") -Force

$wsh = New-Object -ComObject WScript.Shell
$desktop = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$shortcutPath = Join-Path $desktop "Ultron Defender Total Security.lnk"
$d1 = $wsh.CreateShortcut($shortcutPath)
$d1.TargetPath = $exePath
$d1.WorkingDirectory = $appDir
$d1.Description = "Ultron Defender Total Security"
$icoPath = Join-Path $appDir "ultron_shield.ico"
if (Test-Path $icoPath) { $d1.IconLocation = "$icoPath,0" }
$d1.Save()
Write-Host "[OK] Kisayol guncellendi: $shortcutPath -> $exePath" -ForegroundColor Green

# 4. INNO SETUP INSTALLER
if (-not $SkipInstaller) {
    Write-Host "`n[4/4] Inno Setup ile kurulum paketi olusturuluyor..." -ForegroundColor Yellow
    $iscc = "C:\Users\PC\AppData\Local\Programs\Inno Setup 6\ISCC.exe"
    if (-not (Test-Path $iscc)) {
        $iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source
    }
    if ($iscc -and (Test-Path $iscc)) {
        & $iscc (Join-Path $repoRoot "installer.iss")
        if ($LASTEXITCODE -eq 0) {
            $setupPath = Join-Path $repoRoot "UltronDefenderSetup.exe"
            $setupSizeMb = [math]::Round((Get-Item $setupPath).Length / 1MB, 2)
            Write-Host "[OK] Kurulum paketi hazir: $setupPath ($setupSizeMb MB)" -ForegroundColor Green
        } else {
            Write-Warning "Inno Setup derlemesi hata kodu verdi: $LASTEXITCODE"
        }
    } else {
        Write-Warning "ISCC.exe bulunamadi, kurulum paketi uretimi atlandi."
    }
} else {
    Write-Host "`n[4/4] Kurulum paketi uretimi atlandi (-SkipInstaller)." -ForegroundColor DarkGray
}

$sw.Stop()
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Tamamlandi! Sure: $([math]::Round($sw.Elapsed.TotalSeconds, 1)) saniye" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

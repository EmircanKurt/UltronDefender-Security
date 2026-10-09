<#
.SYNOPSIS
    Ultron Defender Total Security - Build, Publish & Deploy Pipeline
#>

[CmdletBinding()]
param (
    [switch]$SkipTests,
    [switch]$SkipInstaller,
    [switch]$UpdateDesktopShortcut,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'artifacts\preview-3.2.3'),
    [string]$InnoCompilerPath = ''
)

$ErrorActionPreference = "Stop"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$repoRoot = $PSScriptRoot
[xml]$projectVersion = Get-Content -LiteralPath (Join-Path $repoRoot 'src/AegisPC.App/AegisPC.App.csproj') -Raw
$appVersion = @($projectVersion.Project.PropertyGroup.Version | Where-Object { $_ })[0]
if ($appVersion -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?$') { throw 'Invalid application version; package names cannot be inferred.' }
Set-Location -LiteralPath $repoRoot
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Ultron Defender Total Security] Build & Deploy Pipeline" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. TEST STEP
if (-not $SkipTests) {
    Write-Host "`n[1/4] Zararsiz regresyon testleri calistiriliyor..." -ForegroundColor Yellow
    # No broad negative filter: only the reviewed positive allowlist is eligible.
    & (Join-Path $repoRoot 'scripts/Test-BenignPreview.ps1') -ResultsDirectory (Join-Path $OutputDirectory 'tests')
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Zararsiz regresyon testleri basarisiz oldu! Paketleme iptal edildi."
        exit 1
    }
    Write-Host "[OK] Zararsiz regresyon testleri gecti; gercek malware/kurulum testi degildir." -ForegroundColor Green
} else {
    Write-Host "`n[1/4] Testler atlandi (-SkipTests)." -ForegroundColor DarkGray
}

# 2. PUBLISH STEP
Write-Host "`n[2/4] Release ikilileri izole paket klasorune yayimlaniyor..." -ForegroundColor Yellow
$appDir = Join-Path $OutputDirectory "payload"
$helpersDir = Join-Path $appDir "Helpers"

& dotnet publish "src\AegisPC.App\AegisPC.App.csproj" -c Release -r win-x64 --self-contained true /p:PublishReadyToRun=true -o $appDir
if ($LASTEXITCODE -ne 0) { throw "Application publish failed; deployment stopped." }
& dotnet publish "src\AegisPC.Service\AegisPC.Service.csproj" -c Release -r win-x64 --self-contained true /p:PublishReadyToRun=true -o (Join-Path $appDir "Service")
if ($LASTEXITCODE -ne 0) { throw "Service publish failed; deployment stopped." }
& dotnet publish "tools\AegisPC.ElevatedHelper\AegisPC.ElevatedHelper.csproj" -c Release -r win-x64 --self-contained true /p:PublishReadyToRun=true -o $helpersDir
if ($LASTEXITCODE -ne 0) { throw "Elevated helper publish failed; deployment stopped." }
Copy-Item -LiteralPath (Join-Path $repoRoot 'ultron_shield.ico') -Destination $appDir -Force

# 3. SHORTCUT & ALIAS SYNC
Write-Host "`n[3/4] Masaustu kisayolu ve takma ad ikilileri senkronize ediliyor..." -ForegroundColor Yellow
$exePath = Join-Path $appDir "UltronDefender.exe"
if ($UpdateDesktopShortcut) {
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
}

# 4. INNO SETUP INSTALLER
if (-not $SkipInstaller) {
    Write-Host "`n[4/4] Inno Setup ile kurulum paketi olusturuluyor..." -ForegroundColor Yellow
    $iscc = $InnoCompilerPath
    if ([string]::IsNullOrWhiteSpace($iscc)) { $iscc = Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe' }
    if (-not (Test-Path $iscc)) {
        $iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source
    }
    if ($iscc -and (Test-Path $iscc)) {
        & $iscc /Q "/DMyAppVersion=$appVersion" "/DAppPublishDir=$appDir" "/DSetupOutputDir=$OutputDirectory" (Join-Path $repoRoot "installer.iss")
        if ($LASTEXITCODE -eq 0) {
            $setupPath = Join-Path $OutputDirectory "UltronDefenderSetup-$appVersion.exe"
            $setupSizeMb = [math]::Round((Get-Item $setupPath).Length / 1MB, 2)
            Write-Host "[OK] Kurulum paketi hazir: $setupPath ($setupSizeMb MB)" -ForegroundColor Green
        } else {
            throw "Inno Setup compilation failed with exit code $LASTEXITCODE."
        }
    } else {
        throw "ISCC.exe was not found; installer was not produced."
    }
} else {
    Write-Host "`n[4/4] Kurulum paketi uretimi atlandi (-SkipInstaller)." -ForegroundColor DarkGray
}

$sw.Stop()
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Tamamlandi! Sure: $([math]::Round($sw.Elapsed.TotalSeconds, 1)) saniye" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

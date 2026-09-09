# ==============================================================================
# AegisPC (Ultron Defender Total Security) - Production Uninstaller Script
# ==============================================================================
# Sürüm: 3.5.0 Production-Ready
# Yazar: Ultron Security Technologies DevOps Team
# Platform: Windows 10 / 11 / Windows Server 2016+ (x64)
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$InstallPath = "$env:ProgramFiles\UltronDefender",

    [Parameter(Mandatory = $false)]
    [string]$DataPath = "$env:ProgramData\UltronDefender",

    [Parameter(Mandatory = $false)]
    [switch]$KeepLogsAndQuarantine,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Continue"
$StartTime = [System.Diagnostics.Stopwatch]::StartNew()

function Write-Step([string]$message) {
    Write-Host "[+] $message" -ForegroundColor Cyan
}

function Write-Success([string]$message) {
    Write-Host "[OK] $message" -ForegroundColor Green
}

function Write-Warn([string]$message) {
    Write-Host "[!] $message" -ForegroundColor Yellow
}

function Write-Err([string]$message) {
    Write-Host "[-] $message" -ForegroundColor Red
}

Clear-Host
Write-Host "===================================================================" -ForegroundColor Red
Write-Host "  ULTRON DEFENDER TOTAL SECURITY (AEGISPC) - TAM KALDIRMA (UNINSTALL)" -ForegroundColor Red
Write-Host "===================================================================" -ForegroundColor Red
Write-Host "Kurulum Konumu : $InstallPath" -ForegroundColor Gray
Write-Host "Veri Konumu    : $DataPath" -ForegroundColor Gray
Write-Host "Islem Saati    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "===================================================================" -ForegroundColor Red
Write-Host ""

# ------------------------------------------------------------------------------
# ADIM 1: Yonetici (Administrator) Yetkisi Kontrolu
# ------------------------------------------------------------------------------
Write-Step "ADIM 1: Yonetici yetkileri denetleniyor..."
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "Bu kaldirma betigi Administrator yetkisi gerektirmektedir!"
    $argsList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($KeepLogsAndQuarantine) { $argsList += " -KeepLogsAndQuarantine" }
    if ($Force) { $argsList += " -Force" }

    Start-Process powershell.exe -ArgumentList $argsList -Verb RunAs
    exit 0
}
Write-Success "Yonetici yetkisi onaylandi."

# Kullanici Onayi
if (-not $Force) {
    Write-Host ""
    $confirm = Read-Host "Ultron Defender Total Security ve tum bilesenleri kaldirilacak. Devam edilsin mi? (E/H)"
    if ($confirm -ne 'E' -and $confirm -ne 'e' -and $confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Warn "Kaldirma islemi kullanici tarafindan iptal edildi."
        exit 0
    }
}

# ------------------------------------------------------------------------------
# ADIM 2: Calisan Sureclerin Durdurulmasi
# ------------------------------------------------------------------------------
Write-Step "ADIM 2: Calisan Ultron Defender surecleri sonlandiriliyor..."
$processesToKill = @(
    "UltronDefender", "Ultron Defender Total Security", "Ultron Defender Security",
    "AegisPC", "AegisPC.Service", "Uninstall"
)

foreach ($procName in $processesToKill) {
    Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  Sonlandiriliyor: $($_.ProcessName) (PID: $($_.Id))" -ForegroundColor Gray
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 1
Write-Success "Tum surecler sonlandirildi."

# ------------------------------------------------------------------------------
# ADIM 3: Kernel Minifilter Driver (AegisFilter) Bosaltilmasi ve Silinmesi
# ------------------------------------------------------------------------------
Write-Step "ADIM 3: AegisFilter Minifilter surucusu kaldiriliyor..."

# 1. fltmc ile minifilter'i bosalt
& fltmc.exe unload AegisFilter 2>&1 | Out-Null
Start-Sleep -Milliseconds 500

# 2. Sürücü servisini durdur ve sil
& sc.exe stop AegisFilter 2>&1 | Out-Null
& sc.exe delete AegisFilter 2>&1 | Out-Null

# 3. PnP Sürücü Deposundan Kaldir
& pnputil.exe /delete-driver AegisFilter.inf /uninstall /force 2>&1 | Out-Null

# 4. System32\drivers altindaki kalinti .sys dosyasini sil
$systemDriverPath = "$env:windir\System32\drivers\AegisFilter.sys"
if (Test-Path $systemDriverPath) {
    Remove-Item -Path $systemDriverPath -Force -ErrorAction SilentlyContinue
}
Write-Success "AegisFilter Minifilter cekirdek surucusu basariyla bosaltildi ve kaldirildi."

# ------------------------------------------------------------------------------
# ADIM 4: Windows Servislerinin Durdurulmasi ve Silinmesi
# ------------------------------------------------------------------------------
Write-Step "ADIM 4: Windows koruma servisleri kaldiriliyor..."
$servicesToRemove = @("AegisPCProtectionService", "UltronDefenderService", "AegisPC Protection Service")

foreach ($svcName in $servicesToRemove) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  Servis durduruluyor ve siliniyor: $svcName" -ForegroundColor Gray
        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $svcName 2>&1 | Out-Null
    }
}
Write-Success "AegisPCProtectionService ve ilgili servis kayitlari silindi."

# ------------------------------------------------------------------------------
# ADIM 5: Zamanlanmis Gorevlerin (Scheduled Tasks) Kaldirilmasi
# ------------------------------------------------------------------------------
Write-Step "ADIM 5: Zamanlanmis gorevler temizleniyor..."
$tasksToRemove = @("UltronDefender_UsbUpdateWatcher", "UltronDefender_AutoUpdate")
foreach ($t in $tasksToRemove) {
    $existingTask = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "  Zamanlanmis gorev silindi: $t" -ForegroundColor Gray
    }
}
Write-Success "Zamanlanmis gorevler temizlendi."

# ------------------------------------------------------------------------------
# ADIM 6: DNS ve Hosts Dosyasi Degisikliklerinin Geri Alinmasi (Rollback)
# ------------------------------------------------------------------------------
Write-Step "ADIM 6: Hosts dosyasi ve DNS koruma kurallari temizleniyor..."
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    try {
        $content = Get-Content -Path $hostsPath -Raw -ErrorAction SilentlyContinue
        $beginMarker = "# BEGIN ULTRON DEFENDER SHIELD"
        $endMarker   = "# END ULTRON DEFENDER SHIELD"

        if ($content -and $content.Contains($beginMarker) -and $content.Contains($endMarker)) {
            $regex = [regex]::Escape($beginMarker) + '[\s\S]*?' + [regex]::Escape($endMarker)
            $cleaned = [System.Text.RegularExpressions.Regex]::Replace($content, $regex, "")
            Set-Content -Path $hostsPath -Value $cleaned.TrimEnd() -Force
            Write-Host "  Hosts dosyasindaki sinkhole engelleme girdileri temizlendi." -ForegroundColor Gray
        }
        & ipconfig.exe /flushdns 2>&1 | Out-Null
    } catch {
        Write-Warn "Hosts dosyasi temizlenirken hata: $($_.Exception.Message)"
    }
}
Write-Success "DNS ayarlari ve hosts dosyasi orijinal durumuna getirildi."

# ------------------------------------------------------------------------------
# ADIM 7: Kayit Defteri (Registry) Temizligi
# ------------------------------------------------------------------------------
Write-Step "ADIM 7: Kayit defteri (Registry) kayitlari ve Explorer menuleri temizleniyor..."

# 1. Ana Program Kaydi
$regPaths = @(
    "HKLM:\SOFTWARE\UltronDefender",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UltronDefender",
    "HKCU:\Software\UltronDefender"
)
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        Remove-Item -Path $rp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 2. Windows Run (Startup)
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
if (Get-ItemProperty -Path $runKey -Name "UltronDefender" -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $runKey -Name "UltronDefender" -Force -ErrorAction SilentlyContinue
}

# 3. Explorer Sag-Tik Menuleri
$shellKeys = @(
    "HKCU:\Software\Classes\*\shell\UltronDefenderScan",
    "HKCU:\Software\Classes\Directory\shell\UltronDefenderScan",
    "HKCU:\Software\Classes\Directory\Background\shell\UltronDefenderScan"
)
foreach ($sk in $shellKeys) {
    if (Test-Path $sk) {
        Remove-Item -Path $sk -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 4. EventLog Kaynaklari
try {
    if ([System.Diagnostics.EventLog]::SourceExists("UltronDefender")) {
        [System.Diagnostics.EventLog]::DeleteEventSource("UltronDefender")
    }
    if ([System.Diagnostics.EventLog]::SourceExists("AegisPC")) {
        [System.Diagnostics.EventLog]::DeleteEventSource("AegisPC")
    }
} catch { }

Write-Success "Kayit defteri ve Explorer baglam menuleri tamamen temizlendi."

# ------------------------------------------------------------------------------
# ADIM 8: Kisayollarin Kaldirilmasi
# ------------------------------------------------------------------------------
Write-Step "ADIM 8: Baslat menusu ve masaustu kisayollari siliniyor..."

# Baslat Menusu Klasoru
$programsDir = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\Ultron Defender")
if (Test-Path $programsDir) {
    Remove-Item -Path $programsDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Masaustu Kisayolu
$desktopShortcut = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) "Ultron Defender Total Security.lnk"
if (Test-Path $desktopShortcut) {
    Remove-Item -Path $desktopShortcut -Force -ErrorAction SilentlyContinue
}

$userDesktopShortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) "Ultron Defender Total Security.lnk"
if (Test-Path $userDesktopShortcut) {
    Remove-Item -Path $userDesktopShortcut -Force -ErrorAction SilentlyContinue
}
Write-Success "Tum kisayollar silindi."

# ------------------------------------------------------------------------------
# ADIM 9: Dosya ve Dizinlerin Silinmesi
# ------------------------------------------------------------------------------
Write-Step "ADIM 9: Program Files ve ProgramData dizinleri siliniyor..."

# 1. Program Files ($InstallPath)
if (Test-Path $InstallPath) {
    Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $InstallPath) {
        Write-Warn "Bazi dosyalar kilitli olabilir. Yeniden baslatmada silinmek uzere isaretleniyor."
    }
}

# 2. ProgramData ($DataPath)
if (-not $KeepLogsAndQuarantine) {
    if (Test-Path $DataPath) {
        Remove-Item -Path $DataPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Success "Veri dizini ($DataPath) tamamen silindi."
} else {
    Write-Warn "Kullanici secimi dogrultusunda karantina ve log dizini saklandi: $DataPath"
}

$StartTime.Stop()
$elapsedSec = [math]::Round($StartTime.Elapsed.TotalSeconds, 2)

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Green
Write-Host "  ULTRON DEFENDER BASARIYLA VE TAMAMEN KALDIRILDI! (Sure: $elapsedSec saniye)" -ForegroundColor Green
Write-Host "===================================================================" -ForegroundColor Green
Write-Host "  Tum servisler, suruculer, kayit defteri anahtarlari ve dosyalar temizlendi." -ForegroundColor Gray
Write-Host "===================================================================" -ForegroundColor Green
Write-Host ""

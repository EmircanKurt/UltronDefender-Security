# ==============================================================================
# AegisPC (Ultron Defender Total Security) - Production Installation Script
# ==============================================================================
# Sürüm: 3.5.0 - supplemental user-mode installation candidate
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
    [switch]$SkipDriver,

    [Parameter(Mandatory = $false)]
    [switch]$SkipStart,

    [Parameter(Mandatory = $false)]
    [switch]$NoDesktopShortcut,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
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
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "   ULTRON DEFENDER TOTAL SECURITY (AEGISPC) - PRODUCTION INSTALLER" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "Kurulum Hedefi : $InstallPath" -ForegroundColor Gray
Write-Host "Veri Dizini    : $DataPath" -ForegroundColor Gray
Write-Host "Baslangic Saati: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------------------------
# ADIM 1: Yonetici (Administrator) Yetkisi Kontrolu
# ------------------------------------------------------------------------------
Write-Step "ADIM 1: Yonetici yetkileri denetleniyor..."
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "Bu kurulum betigi Administrator yetkisi gerektirmektedir!"
    Write-Host "Yetki yukseltmesi yapilarak yeniden baslatiliyor..." -ForegroundColor Yellow
    
    $argsList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($SkipDriver) { $argsList += " -SkipDriver" }
    if ($SkipStart) { $argsList += " -SkipStart" }
    if ($NoDesktopShortcut) { $argsList += " -NoDesktopShortcut" }
    if ($Force) { $argsList += " -Force" }

    $argsList += " -InstallPath `"$InstallPath`" -DataPath `"$DataPath`""
    Start-Process powershell.exe -ArgumentList $argsList -Verb RunAs -WindowStyle Hidden
    exit 0
}
Write-Success "Yonetici yetkisi onaylandi."

# ------------------------------------------------------------------------------
# ADIM 2: Sistem On Gereksinimleri
# ------------------------------------------------------------------------------
Write-Step "ADIM 2: Sistem on gereksinimleri kontrol ediliyor..."
if ([IntPtr]::Size -ne 8) {
    Write-Err "Ultron Defender yalnizca 64-bit (x64) Windows mimarisini destekler!"
    exit 1
}

$systemDrive = [System.IO.Path]::GetPathRoot($InstallPath)
$driveInfo = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $systemDrive.TrimEnd('\') }
if ($driveInfo -and ($driveInfo.FreeSpace -lt 500MB)) {
    Write-Err "Yetersiz disk alani! En az 500 MB bos alan gereklidir."
    exit 1
}
Write-Success "Sistem mimarisi (x64) ve disk alani gereksinimleri karsilandi."

# ------------------------------------------------------------------------------
# ADIM 3: Kaynak Dosyalarinin Tespiti
# ------------------------------------------------------------------------------
Write-Step "ADIM 3: Kurulum kaynak dosyalari araniyor..."
$ScriptRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

# Kaynak dosya arama onceligi
$SourceAppDir = Join-Path $ScriptRoot "AegisPC_App"
if (-not (Test-Path (Join-Path $SourceAppDir "UltronDefender.exe"))) {
    $SourceAppDir = Join-Path $ScriptRoot "src\AegisPC.App\bin\Release\net8.0-windows"
}
if (-not (Test-Path (Join-Path $SourceAppDir "UltronDefender.exe"))) {
    $SourceAppDir = Join-Path $ScriptRoot "src\AegisPC.App\bin\Debug\net8.0-windows"
}

$SourceServiceDir = Join-Path $SourceAppDir "Service"
if (-not (Test-Path (Join-Path $SourceServiceDir "AegisPC.Service.exe"))) {
    $SourceServiceDir = Join-Path $ScriptRoot "src\AegisPC.Service\bin\Release\net8.0-windows"
}
if (-not (Test-Path (Join-Path $SourceServiceDir "AegisPC.Service.exe"))) {
    $SourceServiceDir = Join-Path $ScriptRoot "src\AegisPC.Service\bin\Debug\net8.0-windows"
}

if (-not (Test-Path (Join-Path $SourceAppDir "UltronDefender.exe"))) {
    Write-Err "UltronDefender.exe bulunamadi! Lutfen once cozumu derleyin."
    exit 1
}
if (-not (Test-Path (Join-Path $SourceServiceDir "AegisPC.Service.exe"))) {
    Write-Err "AegisPC.Service.exe bulunamadi! Lutfen once cozumu derleyin."
    exit 1
}
Write-Success "Kaynak dosyalar dogrulandi (App: $SourceAppDir, Service: $SourceServiceDir)."

# ------------------------------------------------------------------------------
# ADIM 4: Calisan Onceki Sureclerin ve Servislerin Durdurulmasi
# ------------------------------------------------------------------------------
Write-Step "ADIM 4: Calisan eski surecler guvenle sonlandiriliyor..."
$processesToStop = @("UltronDefender", "Ultron Defender Total Security", "Ultron Defender Security", "AegisPC", "AegisPC.Service")
foreach ($procName in $processesToStop) {
    Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  Durduruluyor: $($_.ProcessName) (PID: $($_.Id))" -ForegroundColor Gray
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}

$serviceNames = @("AegisPCProtectionService", "UltronDefenderService", "AegisPC Protection Service")
foreach ($svc in $serviceNames) {
    $existingSvc = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($existingSvc -and $existingSvc.Status -eq 'Running') {
        Write-Host "  Servis durduruluyor: $svc" -ForegroundColor Gray
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
}
Write-Success "Eski surecler ve servisler durduruldu."

# ------------------------------------------------------------------------------
# ADIM 5: Dizin Yapisi ve Guvenlik (NTFS ACL) Yapilandirmasi
# ------------------------------------------------------------------------------
Write-Step "ADIM 5: Hedef kurulum dizinleri ve erisim izinleri (ACL) olusturuluyor..."
$AppTargetDir     = Join-Path $InstallPath "App"
$ServiceTargetDir = Join-Path $InstallPath "Service"
$DriverTargetDir  = Join-Path $InstallPath "Driver"
$ToolsTargetDir   = Join-Path $InstallPath "Tools"

$SignaturesDataDir = Join-Path $DataPath "signatures"
$QuarantineDataDir = Join-Path $DataPath "quarantine"
$LogsDataDir       = Join-Path $DataPath "logs"
$CacheDataDir      = Join-Path $DataPath "cache"
$UpdatesDataDir    = Join-Path $DataPath "updates"

$allDirs = @(
    $InstallPath, $AppTargetDir, $ServiceTargetDir, $DriverTargetDir, $ToolsTargetDir,
    $DataPath, $SignaturesDataDir, $QuarantineDataDir, $LogsDataDir, $CacheDataDir, $UpdatesDataDir
)

foreach ($dir in $allDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# ACL Guvenlik Sikilastirmasi: Sadece SYSTEM ve Administrators tam yetkili, standart kullanicilar degistiremez
try {
    $acl = Get-Acl $InstallPath
    $acl.SetAccessRuleProtection($true, $false)
    $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ruleUsers  = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($ruleSystem)
    $acl.AddAccessRule($ruleAdmins)
    $acl.AddAccessRule($ruleUsers)
    Set-Acl -Path $InstallPath -AclObject $acl
} catch {
    Write-Warn "ACL izinleri uygulanirken uyari olustu: $($_.Exception.Message)"
}
Write-Success "Dizinler olusturuldu ve erisim izinleri sikilastirildi."

# ------------------------------------------------------------------------------
# ADIM 6: Dosyalarin Kopyalanmasi
# ------------------------------------------------------------------------------
Write-Step "ADIM 6: Uygulama ve servis bilesenleri kopyalaniyor..."

# 1. UI Dosyalari
Copy-Item -Path "$SourceAppDir\*" -Destination $AppTargetDir -Recurse -Force -Exclude "Service"

# 2. Servis Dosyalari
Copy-Item -Path "$SourceServiceDir\*" -Destination $ServiceTargetDir -Recurse -Force

# 3. Ikon Dosyasi
$icoSource = Join-Path $ScriptRoot "ultron_shield.ico"
if (Test-Path $icoSource) {
    Copy-Item -Path $icoSource -Destination $InstallPath -Force
    Copy-Item -Path $icoSource -Destination $AppTargetDir -Force
}

# 4. Imzalar ve Veritabani
$sigPackedSrc = Join-Path $ScriptRoot "src\AegisPC.Security\Data\signatures_packed.bin"
if (Test-Path $sigPackedSrc) {
    Copy-Item -Path $sigPackedSrc -Destination (Join-Path $SignaturesDataDir "signatures_packed.bin") -Force
}
$sigSqlSrc = Join-Path $ScriptRoot "database\import_threat_signatures.sql"
if (Test-Path $sigSqlSrc) {
    Copy-Item -Path $sigSqlSrc -Destination (Join-Path $SignaturesDataDir "import_threat_signatures.sql") -Force
}

Write-Success "Dosyalar basariyla kopyalandi."

# ------------------------------------------------------------------------------
# ADIM 7: Kernel Minifilter Driver (AegisFilter) Kurulumu
# ------------------------------------------------------------------------------
Write-Step "ADIM 7: Kullanici modu ek koruma secildi."
# Supplemental deployment must not install an unvalidated kernel driver or weaken Windows code integrity.
# Keep -SkipDriver accepted for backwards-compatible invocation; all ordinary installs now skip the driver.
Write-Warn "Kernel surucusu kurulmaz. Defender/kurumsal AV etkin kalmalidir; kernel modu henuz dogrulanmis urun kapsaminda degildir."

# ------------------------------------------------------------------------------
# ADIM 8: Windows Servisi Kurulumu ve Yapilandirmasi
# ------------------------------------------------------------------------------
Write-Step "ADIM 8: AegisPCProtectionService Windows Servisi kuruluyor..."
$ServiceName        = "AegisPC Protection Service"
$ServiceDisplayName = "Ultron Defender Core Security Service"
$ServiceDescription = "Ultron Defender supplemental user-mode file monitoring, scanning and ransomware alerts."
$ServiceBinaryPath  = Join-Path $ServiceTargetDir "AegisPC.Service.exe"

# Mevcut servis varsa sil
$currentService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($currentService) {
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# Preserve the quotes in the SCM image path; native PowerShell argv marshalling may strip embedded quotes.
$binPathArg = "`"$ServiceBinaryPath`""
New-Service -Name $ServiceName -BinaryPathName $binPathArg -StartupType Automatic -DisplayName $ServiceDisplayName -ErrorAction Stop | Out-Null

# Aciklama ve Hata Kurtarma Politikasi
& sc.exe description $ServiceName $ServiceDescription | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
& sc.exe sidtype $ServiceName unrestricted | Out-Null

Write-Success "AegisPCProtectionService basariyla kaydedildi (start= auto, failure recovery aktif)."

# ------------------------------------------------------------------------------
# ADIM 9: USB Otomatik Guncelleme Mekanizmasi (Güvenlik Nedeniyle Devre Dışı)
# ------------------------------------------------------------------------------
Write-Step "ADIM 9: USB üzerinden imza güncelleme mekanizması güvenlik nedeniyle devre dışı bırakılıyor..."
Write-Warn "USB/harici medya üzerinden paket veya imza kabul edilmez. Yalnızca HTTPS ve Authenticode ile doğrulanmış güncellemeler kullanılır."

try {
    $usbWatcherTask = Get-ScheduledTask -TaskName "UltronDefender_UsbUpdateWatcher" -ErrorAction SilentlyContinue
    if ($usbWatcherTask) {
        Unregister-ScheduledTask -TaskName "UltronDefender_UsbUpdateWatcher" -Confirm:$false
    }
}
catch {
    Write-Warn "Eski USB izleme görevi temizlenemedi: $($_.Exception.Message)"
}

# ------------------------------------------------------------------------------
# ADIM 10: Registry ve Windows Entegrasyonu
# ------------------------------------------------------------------------------
Write-Step "ADIM 10: Kayit defteri ve Windows Explorer entegrasyonu saglaniyor..."
$appExePath = Join-Path $AppTargetDir "UltronDefender.exe"

# 1. Ana Yazilim Bilgisi
$regPath = "HKLM:\SOFTWARE\UltronDefender"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "InstallPath" -Value $InstallPath -Force
Set-ItemProperty -Path $regPath -Name "DataPath" -Value $DataPath -Force
Set-ItemProperty -Path $regPath -Name "Version" -Value "3.5.0" -Force
Set-ItemProperty -Path $regPath -Name "InstallDate" -Value (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ") -Force

# 2. Windows Baslangicinda Calisma
$runReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $runReg -Name "UltronDefender" -Value "`"$appExePath`" --minimized" -Force

# 3. Windows Explorer Sag Tik "Ultron Defender ile Tara" Menusu
$shellTargets = @(
    "HKCU:\Software\Classes\*\shell\UltronDefenderScan",
    "HKCU:\Software\Classes\Directory\shell\UltronDefenderScan",
    "HKCU:\Software\Classes\Directory\Background\shell\UltronDefenderScan"
)

foreach ($st in $shellTargets) {
    if (-not (Test-Path $st)) { New-Item -Path $st -Force | Out-Null }
    Set-ItemProperty -Path $st -Name "(Default)" -Value "🛡️ Ultron Defender ile Tara" -Force
    Set-ItemProperty -Path $st -Name "Icon" -Value "`"$appExePath`",0" -Force
    
    $cmdPath = Join-Path $st "command"
    if (-not (Test-Path $cmdPath)) { New-Item -Path $cmdPath -Force | Out-Null }
    Set-ItemProperty -Path $cmdPath -Name "(Default)" -Value "`"$appExePath`" /scan `"%1`"" -Force
}
Write-Success "Kayit defteri ve Explorer sag-tik baglam menuleri eklendi."

# ------------------------------------------------------------------------------
# ADIM 11: Baslat Menusu ve Masaustu Kisayollari
# ------------------------------------------------------------------------------
Write-Step "ADIM 11: Baslat menusu ve masaustu kisayollari olusturuluyor..."
$wshShell = New-Object -ComObject WScript.Shell

$programsDir = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\Ultron Defender")
if (-not (Test-Path $programsDir)) { New-Item -ItemType Directory -Path $programsDir -Force | Out-Null }

# UI Kisayolu
$appShortcut = $wshShell.CreateShortcut((Join-Path $programsDir "Ultron Defender Total Security.lnk"))
$appShortcut.TargetPath = $appExePath
$appShortcut.WorkingDirectory = $AppTargetDir
$appShortcut.IconLocation = "$appExePath,0"
$appShortcut.Description = "Ultron Defender Total Security Guvenlik Merkezi"
$appShortcut.Save()

# Uninstall Kisayolu
$uninstallerScript = Join-Path $ScriptRoot "uninstall.ps1"
if (-not (Test-Path $uninstallerScript)) { $uninstallerScript = Join-Path $ToolsTargetDir "uninstall.ps1" }
$uninstShortcut = $wshShell.CreateShortcut((Join-Path $programsDir "Ultron Defender Kaldir (Uninstall).lnk"))
$uninstShortcut.TargetPath = "powershell.exe"
$uninstShortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$uninstallerScript`""
$uninstShortcut.IconLocation = "$env:windir\System32\shell32.dll,219"
$uninstShortcut.Description = "Ultron Defender Guvenlik Paketini Temizle ve Kaldir"
$uninstShortcut.Save()

# Masaustu Kisayolu
if (-not $NoDesktopShortcut) {
    $desktopDir = [Environment]::GetFolderPath('CommonDesktopDirectory')
    $desktopShortcut = $wshShell.CreateShortcut((Join-Path $desktopDir "Ultron Defender Total Security.lnk"))
    $desktopShortcut.TargetPath = $appExePath
    $desktopShortcut.WorkingDirectory = $AppTargetDir
    $desktopShortcut.IconLocation = "$appExePath,0"
    $desktopShortcut.Description = "Ultron Defender Total Security"
    $desktopShortcut.Save()
}
Write-Success "Baslat menusu ve masaustu kisayollari olusturuldu."

# ------------------------------------------------------------------------------
# ADIM 12: Servisin Baslatilmasi
# ------------------------------------------------------------------------------
if (-not $SkipStart) {
    Write-Step "ADIM 12: AegisPCProtectionService baslatiliyor..."
    & net.exe start $ServiceName | Out-Null
    
    # 10 saniye icinde baslama durumunu dogrula
    $retries = 10
    $started = $false
    while ($retries -gt 0) {
        $svcStatus = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svcStatus -and $svcStatus.Status -eq 'Running') {
            $started = $true
            break
        }
        Start-Sleep -Seconds 1
        $retries--
    }

    if ($started) {
        Write-Success "AegisPCProtectionService aktif durumda calisiyor (Status: Running)."
    } else {
        Write-Warn "Servis baslatildi ancak Running durumuna gecmesi bekleniyor."
    }
} else {
    Write-Warn "Servis baslatma adimi -SkipStart parametresi nedeniyle atlandi."
}

$StartTime.Stop()
$elapsedSec = [math]::Round($StartTime.Elapsed.TotalSeconds, 2)

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Green
Write-Host "  KURULUM BASARIYLA TAMAMLANDI! (Sure: $elapsedSec saniye)" -ForegroundColor Green
Write-Host "===================================================================" -ForegroundColor Green
Write-Host "  Uygulama Konumu : $AppTargetDir" -ForegroundColor Gray
Write-Host "  Servis Konumu   : $ServiceTargetDir" -ForegroundColor Gray
Write-Host "  Veri Dizini     : $DataPath" -ForegroundColor Gray
Write-Host "  Dogrulama       : powershell -File verify_install.ps1" -ForegroundColor Yellow
Write-Host "===================================================================" -ForegroundColor Green
Write-Host ""

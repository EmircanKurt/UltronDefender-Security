<#
.SYNOPSIS
    AegisPC (Ultron Defender) Çevrimdışı USB Tehdit İmzası Güncelleme Aracı
    
.DESCRIPTION
    Hava boşluklu (Air-Gapped) veya internet bağlantısı bulunmayan sistemlerde,
    USB flash bellek üzerinden sağlanan .sig / signatures_packed.bin / .sql imza
    paketlerini güvenli bir şekilde doğrular, ProgramData hedefine taşır,
    SHA-256 bütünlük kontrollerini yapar ve çalışan AegisPC servisine
    imzaları yeniden yükletir.

.PARAMETER UsbDriveLetter
    İsteğe bağlı USB sürücü harfi (Örn: "E:", "F:\"). Belirtilmezse takılı çıkarılabilir diskler taranır.

.PARAMETER SignatureFilePath
    İsteğe bağlı doğrudan imza paketi dosya yolu.

.PARAMETER RestartService
    İçe aktarım sonrası servisi yeniden başlatma anahtarı (Varsayılan: $true).

.EXAMPLE
    .\Import-UsbSignatures.ps1 -UsbDriveLetter "E:"
    .\Import-UsbSignatures.ps1 -SignatureFilePath "D:\threat_signatures_2026.sig"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$UsbDriveLetter,

    [Parameter(Mandatory = $false)]
    [string]$SignatureFilePath,

    [Parameter(Mandatory = $false)]
    [switch]$RestartService = $true
)

# Yönetici hakları kontrolü
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[HATA] Bu betik imza veritabanı ACL ve ProgramData yazma işlemleri için Yönetici (Elevated) olarak çalıştırılmalıdır."
    exit 1
}

$ErrorActionPreference = "Stop"

$TargetSigDir = Join-Path -Path $env:ProgramData -ChildPath "UltronDefender\signatures"
if (-not (Test-Path $TargetSigDir)) {
    New-Item -Path $TargetSigDir -ItemType Directory -Force | Out-Null
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " AegisPC (Ultron Defender) - Çevrimdışı USB İmza Yükleyici       " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Kaynak İmza Paketini Belirle
$foundPackage = $null

if ($SignatureFilePath -and (Test-Path $SignatureFilePath)) {
    $foundPackage = (Get-Item $SignatureFilePath).FullName
}
elseif ($UsbDriveLetter) {
    $drivePath = $UsbDriveLetter.TrimEnd('\') + "\"
    if (Test-Path $drivePath) {
        $foundPackage = (Get-ChildItem -Path $drivePath -Recurse -File -Include "*.sig", "signatures_packed.bin", "import_threat_signatures.sql" | Select-Object -First 1)?.FullName
    }
}
else {
    Write-Host "[*] Takılı çıkarılabilir USB sürücüler taranıyor..." -ForegroundColor Yellow
    $usbDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 2"
    foreach ($drive in $usbDrives) {
        $root = $drive.DeviceID + "\"
        Write-Host "    -> Sürücü denetleniyor: $root" -ForegroundColor Gray
        $candidate = (Get-ChildItem -Path $root -Recurse -File -Include "*.sig", "signatures_packed.bin", "import_threat_signatures.sql" -ErrorAction SilentlyContinue | Select-Object -First 1)?.FullName
        if ($candidate) {
            $foundPackage = $candidate
            break
        }
    }
}

if (-not $foundPackage -or -not (Test-Path $foundPackage)) {
    Write-Warning "[UYARI] USB sürücüsünde geçerli bir imza paketi (.sig, signatures_packed.bin, import_threat_signatures.sql) bulunamadı."
    exit 2
}

Write-Host "[+] İmza paketi tespit edildi: $foundPackage" -ForegroundColor Green
$pkgFileInfo = Get-Item $foundPackage

# 2. SHA-256 Sağlama Toplamı (Checksum) Doğrulaması
$sha256File = "$foundPackage.sha256"
$currentHash = (Get-FileHash -Path $foundPackage -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "[*] Paketin SHA-256 Özeti: $currentHash" -ForegroundColor DarkGray

if (Test-Path $sha256File) {
    $expectedHash = (Get-Content $sha256File).Trim().ToLowerInvariant()
    if ($expectedHash -ne $currentHash) {
        Write-Error "[GÜVENLİK İHLALİ] İmza paketinin SHA-256 sağlama toplamı eşleşmiyor! Dosya bozulmuş veya kurcalanmış (Tampered)."
        exit 3
    }
    Write-Host "[+] SHA-256 Bütünlük Doğrulaması: BAŞARILI" -ForegroundColor Green
}
else {
    Write-Warning "[!] Dikkat: Eşleşen .sha256 doğrulama dosyası bulunamadı, ancak işlem devam ediyor."
}

# 3. İmzaların Hedefe Konuşlandırılması
$targetFile = Join-Path -Path $TargetSigDir -ChildPath $pkgFileInfo.Name
Write-Host "[*] İmza dosyası ProgramData dizinine kopyalanıyor..." -ForegroundColor Yellow
Copy-Item -Path $foundPackage -Destination $targetFile -Force

# Paketin .sha256 dosyasını da kopyala / oluştur
$targetShaFile = "$targetFile.sha256"
Set-Content -Path $targetShaFile -Value $currentHash -Force

# Eğer signatures_packed.bin ise ana kopya adını garantiye al
if ($pkgFileInfo.Extension -eq ".sig" -or $pkgFileInfo.Name -eq "signatures_packed.bin") {
    $canonicalBin = Join-Path -Path $TargetSigDir -ChildPath "signatures_packed.bin"
    Copy-Item -Path $targetFile -Destination $canonicalBin -Force
    Set-Content -Path "$canonicalBin.sha256" -Value $currentHash -Force
}

# 4. Windows ACL İzinlerini Sıkılaştır
Write-Host "[*] İmza dizini ACL izinleri sıkılaştırılıyor (Anti-Tamper)..." -ForegroundColor Yellow
$acl = Get-Acl $TargetSigDir
$acl.SetAccessRuleProtection($true, $false) # Kalıtımı kaldır

$systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$adminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
$usersSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)

$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($usersSid, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))

Set-Acl -Path $TargetSigDir -AclObject $acl
Write-Host "[+] ACL sıkılaştırması tamamlandı: Yalnızca SYSTEM ve Administrators yazabilir." -ForegroundColor Green

# 5. Çalışan AegisPC Servisine Bildirim Gönder / Yeniden Başlat
$serviceName = "AegisPC.Service"
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($svc) {
    if ($RestartService -and $svc.Status -eq "Running") {
        Write-Host "[*] AegisPC Servisi yeni imzaları yüklemek için yeniden başlatılıyor..." -ForegroundColor Yellow
        Restart-Service -Name $serviceName -Force
        Write-Host "[+] Servis başarıyla yeniden başlatıldı ve yeni imzalar belleğe alındı." -ForegroundColor Green
    }
    else {
        Write-Host "[i] Servis durumu: $($svc.Status)" -ForegroundColor Gray
    }
}
else {
    Write-Host "[i] $serviceName Windows servisi kurulu değil veya geliştirme modunda çalışıyor." -ForegroundColor DarkYellow
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[BAŞARILI] Çevrimdışı Tehdit İmzaları Başarıyla Güncellendi!" -ForegroundColor Green
Write-Host "Konum: $TargetSigDir" -ForegroundColor Green
Write-Host "Dosya: $($pkgFileInfo.Name) ($([math]::Round($pkgFileInfo.Length / 1KB, 2)) KB)" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan

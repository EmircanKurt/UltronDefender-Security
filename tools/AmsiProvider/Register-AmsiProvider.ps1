<#
.SYNOPSIS
    Ultron Defender AMSI Provider COM Kayıt ve Kaldırma Betiği.
.DESCRIPTION
    Bu betik, Ultron Defender unmanaged AmsiProvider.dll COM bileşenini Windows AMSI
    sağlayıcı havuzuna (HKLM\SOFTWARE\Microsoft\AMSI\Providers) kaydeder veya kaldırır.
.PARAMETER DllPath
    Kaydedilecek AmsiProvider.dll dosyasının tam yolu.
.PARAMETER Unregister
    Kayıtlı AMSI sağlayıcısını ve COM CLSID anahtarlarını sistemden kaldırır.
.EXAMPLE
    .\Register-AmsiProvider.ps1 -DllPath "C:\Program Files\UltronDefender\AmsiProvider.dll"
    .\Register-AmsiProvider.ps1 -Unregister
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DllPath,

    [Parameter(Mandatory = $false)]
    [switch]$Unregister
)

$Clsid = "{638DC8E4-1B1C-4328-8C67-DF52445EFA10}"
$ProviderName = "Ultron Defender AMSI Security Provider"

# 1. Yönetici Yetkisi Doğrulaması (Elevation Check)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[HATA] Bu betik Windows Kayıt Defteri (HKLM) üzerinde değişiklik yapabilmek için Yönetici (Elevated/Admin) olarak çalıştırılmalıdır."
    exit 1
}

$AmsiProvidersKey = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\$Clsid"
$ComClsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$Clsid"

if ($Unregister) {
    Write-Host "[*] Ultron Defender AMSI Provider sistemden kaldırılıyor..." -ForegroundColor Yellow

    # 1. AMSI Providers kaydını sil
    if (Test-Path $AmsiProvidersKey) {
        Remove-Item -Path $AmsiProvidersKey -Force -Recurse
        Write-Host " [+] AMSI Provider kaydı silindi: $AmsiProvidersKey" -ForegroundColor Green
    } else {
        Write-Host " [-] AMSI Provider kaydı bulunamadı (zaten silinmiş)." -ForegroundColor Gray
    }

    # 2. COM CLSID kaydını sil
    if (Test-Path $ComClsidKey) {
        Remove-Item -Path $ComClsidKey -Force -Recurse
        Write-Host " [+] COM CLSID kaydı silindi: $ComClsidKey" -ForegroundColor Green
    }

    Write-Host "[OK] AMSI Provider başarıyla kaldırıldı." -ForegroundColor Cyan
    exit 0
}

# Kayıt İşlemi (Register)
if (-not $DllPath) {
    $defaultPath = Join-Path $PSScriptRoot "AmsiProvider.dll"
    if (Test-Path $defaultPath) {
        $DllPath = $defaultPath
    } else {
        $binPath = Join-Path (Split-Path $PSScriptRoot -Parent) "bin\Release\AmsiProvider.dll"
        if (Test-Path $binPath) {
            $DllPath = $binPath
        } else {
            Write-Error "[HATA] DllPath belirtilmedi ve varsayılan konumlarda AmsiProvider.dll bulunamadı."
            exit 1
        }
    }
}

$DllPath = [System.IO.Path]::GetFullPath($DllPath)
if (-not (Test-Path $DllPath)) {
    Write-Error "[HATA] Hedef DLL dosyası bulunamadı: $DllPath"
    exit 1
}

Write-Host "[*] Ultron Defender AMSI Provider kaydediliyor..." -ForegroundColor Cyan
Write-Host "    DLL Yolu : $DllPath"
Write-Host "    CLSID    : $Clsid"

try {
    # 1. COM CLSID Kaydı
    if (-not (Test-Path $ComClsidKey)) {
        New-Item -Path $ComClsidKey -Force | Out-Null
    }
    Set-ItemProperty -Path $ComClsidKey -Name "(Default)" -Value $ProviderName

    $InprocServerKey = Join-Path $ComClsidKey "InprocServer32"
    if (-not (Test-Path $InprocServerKey)) {
        New-Item -Path $InprocServerKey -Force | Out-Null
    }
    Set-ItemProperty -Path $InprocServerKey -Name "(Default)" -Value $DllPath
    Set-ItemProperty -Path $InprocServerKey -Name "ThreadingModel" -Value "Both"
    Write-Host " [+] COM InprocServer32 anahtarı oluşturuldu." -ForegroundColor Green

    # 2. Windows AMSI Sağlayıcılar Kaydı
    if (-not (Test-Path $AmsiProvidersKey)) {
        New-Item -Path $AmsiProvidersKey -Force | Out-Null
    }
    Set-ItemProperty -Path $AmsiProvidersKey -Name "(Default)" -Value $ProviderName
    Write-Host " [+] HKLM\SOFTWARE\Microsoft\AMSI\Providers altına kaydedildi." -ForegroundColor Green

    Write-Host "`n[OK] Ultron Defender AMSI Provider başarıyla kaydedildi!" -ForegroundColor Green
    Write-Host "     NOT: PowerShell, WScript, CScript veya Office makroları artık dinamik betikleri Ultron Defender üzerinden taratacaktır." -ForegroundColor Yellow
}
catch {
    Write-Error "[HATA] Kayıt işlemi sırasında hata oluştu: $_"
    exit 1
}

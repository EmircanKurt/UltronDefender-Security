<#
.SYNOPSIS
    Ultron Defender AMSI Provider COM Kayıt, Doğrulama ve Kaldırma Betiği.
.DESCRIPTION
    Bu betik, Ultron Defender unmanaged AmsiProvider.dll COM bileşenini Windows AMSI
    sağlayıcı havuzuna (HKLM\SOFTWARE\Microsoft\AMSI\Providers ve WOW6432Node) kaydeder,
    durumunu doğrular veya sistemden kaldırır.
.PARAMETER DllPath
    Kaydedilecek AmsiProvider.dll dosyasının tam yolu.
.PARAMETER Unregister
    Kayıtlı AMSI sağlayıcısını ve COM CLSID anahtarlarını sistemden kaldırır.
.PARAMETER Verify
    Mevcut kayıt durumunu, DLL varlığını ve dijital imza durumunu sorgular.
.EXAMPLE
    .\Register-AmsiProvider.ps1 -DllPath "C:\Program Files\UltronDefender\AmsiProvider.dll"
    .\Register-AmsiProvider.ps1 -Verify
    .\Register-AmsiProvider.ps1 -Unregister
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DllPath,

    [Parameter(Mandatory = $false)]
    [switch]$Unregister,

    [Parameter(Mandatory = $false)]
    [switch]$Verify
)

$Clsid = "{638DC8E4-1B1C-4328-8C67-DF52445EFA10}"
$ProviderName = "Ultron Defender AMSI Security Provider"

$AmsiProvidersKey64 = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\$Clsid"
$ComClsidKey64 = "HKLM:\SOFTWARE\Classes\CLSID\$Clsid"
$AmsiProvidersKey32 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\AMSI\Providers\$Clsid"
$ComClsidKey32 = "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$Clsid"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "   ULTRON DEFENDER - AMSI SECURITY PROVIDER REGISTRATION         " -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

# -------------------------------------------------------------------------
# VERIFY MODE (Does not require administrative privileges)
# -------------------------------------------------------------------------
if ($Verify) {
    Write-Host "[*] VERIFY: Windows AMSI Sağlayıcı Kayıt Durumu Sorgulanıyor..." -ForegroundColor Yellow

    $isRegistered64 = Test-Path $AmsiProvidersKey64
    $isCom64 = Test-Path $ComClsidKey64
    $isRegistered32 = Test-Path $AmsiProvidersKey32
    $isCom32 = Test-Path $ComClsidKey32

    Write-Host "    CLSID                    : $Clsid" -ForegroundColor Gray
    Write-Host "    AMSI Provider (64-bit)   : $(if ($isRegistered64) { '[KAYITLI]' } else { '[KAYITSIZ]' })" -ForegroundColor $(if ($isRegistered64) { 'Green' } else { 'Yellow' })
    Write-Host "    COM InprocServer (64-bit): $(if ($isCom64) { '[KAYITLI]' } else { '[KAYITSIZ]' })" -ForegroundColor $(if ($isCom64) { 'Green' } else { 'Yellow' })

    if ([Environment]::Is64BitOperatingSystem) {
        Write-Host "    AMSI Provider (WOW64)    : $(if ($isRegistered32) { '[KAYITLI]' } else { '[KAYITSIZ]' })" -ForegroundColor $(if ($isRegistered32) { 'Green' } else { 'Yellow' })
        Write-Host "    COM InprocServer (WOW64) : $(if ($isCom32) { '[KAYITLI]' } else { '[KAYITSIZ]' })" -ForegroundColor $(if ($isCom32) { 'Green' } else { 'Yellow' })
    }

    $registeredDll = $null
    if ($isCom64) {
        try {
            $inproc = Get-ItemProperty -Path "$ComClsidKey64\InprocServer32" -ErrorAction SilentlyContinue
            if ($inproc -and $inproc.'(Default)') {
                $registeredDll = $inproc.'(Default)'
                Write-Host "    Kayıtlı DLL Yolu         : $registeredDll" -ForegroundColor Cyan
                if (Test-Path $registeredDll) {
                    $sig = Get-AuthenticodeSignature $registeredDll
                    Write-Host "    DLL Dosya Durumu         : [MEVCUT] (İmza: $($sig.Status))" -ForegroundColor Green
                } else {
                    Write-Host "    DLL Dosya Durumu         : [DOSYA BULUNAMADI]" -ForegroundColor Red
                }
            }
        } catch {}
    }

    if ($isRegistered64 -and $isCom64) {
        Write-Host "`n[+] BAŞARILI: Ultron Defender AMSI Provider Windows sistemine aktif olarak bağlıdır!" -ForegroundColor Green
    } else {
        Write-Host "`n[-] BİLGİ: AMSI Provider kayıtlı değil. Sistem kullanıcı modu yedek tarayıcısında (In-Process Fallback) çalışmaktadır." -ForegroundColor Yellow
    }
    return
}

# -------------------------------------------------------------------------
# ELEVATION CHECK (Required for Registry mutation)
# -------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[HATA] Bu betik Windows Kayıt Defteri (HKLM) üzerinde değişiklik yapabilmek için Yönetici (Elevated/Admin) olarak çalıştırılmalıdır."
    exit 1
}

# -------------------------------------------------------------------------
# UNREGISTER MODE
# -------------------------------------------------------------------------
if ($Unregister) {
    Write-Host "[*] Ultron Defender AMSI Provider sistemden kaldırılıyor..." -ForegroundColor Yellow

    # 1. 64-bit Anahtarları Temizle
    if (Test-Path $AmsiProvidersKey64) {
        Remove-Item -Path $AmsiProvidersKey64 -Force -Recurse
        Write-Host " [+] AMSI Provider kaydı silindi: $AmsiProvidersKey64" -ForegroundColor Green
    }
    if (Test-Path $ComClsidKey64) {
        Remove-Item -Path $ComClsidKey64 -Force -Recurse
        Write-Host " [+] COM CLSID kaydı silindi: $ComClsidKey64" -ForegroundColor Green
    }

    # 2. WOW6432Node Anahtarlarını Temizle
    if (Test-Path $AmsiProvidersKey32) {
        Remove-Item -Path $AmsiProvidersKey32 -Force -Recurse
        Write-Host " [+] WOW64 AMSI Provider kaydı silindi: $AmsiProvidersKey32" -ForegroundColor Green
    }
    if (Test-Path $ComClsidKey32) {
        Remove-Item -Path $ComClsidKey32 -Force -Recurse
        Write-Host " [+] WOW64 COM CLSID kaydı silindi: $ComClsidKey32" -ForegroundColor Green
    }

    Write-Host "[OK] AMSI Provider başarıyla kaldırıldı." -ForegroundColor Cyan
    return
}

# -------------------------------------------------------------------------
# REGISTER MODE
# -------------------------------------------------------------------------
if (-not $DllPath) {
    $candidates = @(
        (Join-Path $PSScriptRoot "AmsiProvider.dll"),
        (Join-Path $PSScriptRoot "bin\Release\AmsiProvider.dll"),
        (Join-Path $PSScriptRoot "bin\x64\Release\AmsiProvider.dll"),
        (Join-Path (Split-Path $PSScriptRoot -Parent) "bin\Release\AmsiProvider.dll"),
        "C:\Program Files\UltronDefender\AmsiProvider.dll"
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) {
            $DllPath = $cand
            break
        }
    }
}

if (-not $DllPath -or -not (Test-Path $DllPath)) {
    Write-Error "[HATA] DllPath belirtilmedi veya hedef DLL dosyası bulunamadı: $DllPath"
    exit 1
}

$DllPath = [System.IO.Path]::GetFullPath($DllPath)
Write-Host "[*] Ultron Defender AMSI Provider kaydediliyor..." -ForegroundColor Cyan
Write-Host "    DLL Yolu : $DllPath"
Write-Host "    CLSID    : $Clsid"

try {
    # 1. 64-bit COM CLSID Kaydı
    if (-not (Test-Path $ComClsidKey64)) {
        New-Item -Path $ComClsidKey64 -Force | Out-Null
    }
    Set-ItemProperty -Path $ComClsidKey64 -Name "(Default)" -Value $ProviderName

    $Inproc64 = Join-Path $ComClsidKey64 "InprocServer32"
    if (-not (Test-Path $Inproc64)) {
        New-Item -Path $Inproc64 -Force | Out-Null
    }
    Set-ItemProperty -Path $Inproc64 -Name "(Default)" -Value $DllPath
    Set-ItemProperty -Path $Inproc64 -Name "ThreadingModel" -Value "Both"
    Write-Host " [+] 64-bit COM InprocServer32 anahtarı oluşturuldu." -ForegroundColor Green

    # 2. 64-bit Windows AMSI Sağlayıcı Kaydı
    if (-not (Test-Path $AmsiProvidersKey64)) {
        New-Item -Path $AmsiProvidersKey64 -Force | Out-Null
    }
    Set-ItemProperty -Path $AmsiProvidersKey64 -Name "(Default)" -Value $ProviderName
    Write-Host " [+] HKLM\SOFTWARE\Microsoft\AMSI\Providers altına kaydedildi." -ForegroundColor Green

    # 3. WOW6432Node Kaydı (32-bit betik motorları için)
    if ([Environment]::Is64BitOperatingSystem) {
        if (-not (Test-Path $ComClsidKey32)) {
            New-Item -Path $ComClsidKey32 -Force | Out-Null
        }
        Set-ItemProperty -Path $ComClsidKey32 -Name "(Default)" -Value $ProviderName

        $Inproc32 = Join-Path $ComClsidKey32 "InprocServer32"
        if (-not (Test-Path $Inproc32)) {
            New-Item -Path $Inproc32 -Force | Out-Null
        }
        Set-ItemProperty -Path $Inproc32 -Name "(Default)" -Value $DllPath
        Set-ItemProperty -Path $Inproc32 -Name "ThreadingModel" -Value "Both"

        if (-not (Test-Path $AmsiProvidersKey32)) {
            New-Item -Path $AmsiProvidersKey32 -Force | Out-Null
        }
        Set-ItemProperty -Path $AmsiProvidersKey32 -Name "(Default)" -Value $ProviderName
        Write-Host " [+] WOW6432Node AMSI ve COM anahtarları oluşturuldu." -ForegroundColor Green
    }

    Write-Host "`n[OK] Ultron Defender AMSI Provider başarıyla kaydedildi!" -ForegroundColor Green
    Write-Host "     PowerShell, WScript, CScript ve Office makroları artık dinamik betikleri Ultron Defender üzerinden taratacaktır." -ForegroundColor Yellow
}
catch {
    Write-Error "[HATA] Kayıt işlemi sırasında hata oluştu: $_"
    exit 1
}

@echo off
setlocal enabledelayedexpansion

echo ===================================================================
echo   ULTRON DEFENDER (AEGISPC) - WDK MINIFILTER BUILD ^& TEST-SIGN
echo ===================================================================
echo.

set SCRIPT_DIR=%~dp0
set DRIVER_DIR=%SCRIPT_DIR%AegisFilter
set OUTPUT_DIR=%SCRIPT_DIR%bin\x64\Release
set CERT_NAME=Ultron Defender Driver Test Signing Authority
set CERT_STORE=PrivateCertStore

if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
)

:: -------------------------------------------------------------------
:: ADIM 1: MSBuild ve WDK Ortam Tespiti
:: -------------------------------------------------------------------
echo [*] ADIM 1: MSBuild ve WDK araclari araniyor...

set MSBUILD_EXE=
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
) do (
    if exist %%P (
        set MSBUILD_EXE=%%P
        goto :FOUND_MSBUILD
    )
)

:FOUND_MSBUILD
if "%MSBUILD_EXE%"=="" (
    echo [-] HATA: MSBuild bulunamadi. Visual Studio 2019/2022 yuklu olmalidir.
    goto :WDK_CHECK
) else (
    echo [+] MSBuild bulundu: %MSBUILD_EXE%
)

:WDK_CHECK
set WDK_BIN_DIR=
for %%K in (
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64"
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64"
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64"
    "C:\Program Files (x86)\Windows Kits\10\bin\x64"
) do (
    if exist %%K\signtool.exe (
        set WDK_BIN_DIR=%%~K
        goto :FOUND_WDK_BIN
    )
)

:FOUND_WDK_BIN
if "%WDK_BIN_DIR%"=="" (
    echo [!] UYARI: WDK bin dizini standart yolda bulunamadi.
    echo     Test imzalama araclari PATH uzerinden cagrilacaktir.
) else (
    echo [+] WDK araclari bulundu: %WDK_BIN_DIR%
    set PATH=%WDK_BIN_DIR%;%PATH%
)

:: -------------------------------------------------------------------
:: ADIM 2: AegisFilter.sys Minifilter Derleme
:: -------------------------------------------------------------------
echo.
echo [*] ADIM 2: AegisFilter.sys Release x64 derleniyor...

if "%MSBUILD_EXE%"=="" (
    echo [-] MSBuild mevcut olmadigindan derleme adimi atlandi.
    goto :SIGN_INFO
)

"%MSBUILD_EXE%" "%DRIVER_DIR%\AegisFilter.vcxproj" /p:Configuration=Release /p:Platform=x64 /t:Rebuild /m
if %errorLevel% neq 0 (
    echo [-] Derleme sirasinda hata olustu.
    exit /b 1
)

echo [+] Derleme basarili: %OUTPUT_DIR%\AegisFilter.sys
copy /Y "%DRIVER_DIR%\AegisFilter.inf" "%OUTPUT_DIR%\AegisFilter.inf" >nul

:: -------------------------------------------------------------------
:: ADIM 3: Inf2Cat ile Katalog (.cat) Dosyasi Olusturma
:: -------------------------------------------------------------------
echo.
echo [*] ADIM 3: Inf2Cat ile katalog dosyasi uretiliyor...
where inf2cat.exe >nul 2>&1
if %errorLevel% equ 0 (
    inf2cat.exe /driver:"%OUTPUT_DIR%" /os:10_X64,Server2022_X64,Server2019_X64
    echo [+] AegisFilter.cat basariyla olusturuldu.
) else (
    echo [!] Inf2Cat.exe PATH'te bulunamadi, katalog adimi atlaniyor.
)

:: -------------------------------------------------------------------
:: ADIM 4: Test Sertifikasi Olusturma ve Guvenli Depoya Ekleme
:: -------------------------------------------------------------------
echo.
echo [*] ADIM 4: Test imzalama sertifikasi denetleniyor...

powershell -NoProfile -Command ^
    "$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*%CERT_NAME%*' } | Select-Object -First 1;" ^
    "if (-not $cert) {" ^
    "   Write-Host '[*] Yeni self-signed test sertifikasi olusturuluyor...';" ^
    "   $newCert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=%CERT_NAME%' -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm SHA256;" ^
    "   $storeRoot = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine');" ^
    "   $storeRoot.Open('ReadWrite'); $storeRoot.Add($newCert); $storeRoot.Close();" ^
    "   $storePub = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'LocalMachine');" ^
    "   $storePub.Open('ReadWrite'); $storePub.Add($newCert); $storePub.Close();" ^
    "   Write-Host '[+] Sertifika Root ve TrustedPublisher deposuna eklendi: ' $newCert.Thumbprint;" ^
    "} else {" ^
    "   Write-Host '[+] Mevcut test sertifikasi kullanilacak: ' $cert.Thumbprint;" ^
    "}"

:: -------------------------------------------------------------------
:: ADIM 5: Signtool ile Surucuyu ve Katologu Test Imzalama
:: -------------------------------------------------------------------
echo.
echo [*] ADIM 5: AegisFilter.sys ve AegisFilter.cat imzalanıyor...

where signtool.exe >nul 2>&1
if %errorLevel% equ 0 (
    signtool.exe sign /v /s My /n "%CERT_NAME%" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "%OUTPUT_DIR%\AegisFilter.sys"
    if exist "%OUTPUT_DIR%\AegisFilter.cat" (
        signtool.exe sign /v /s My /n "%CERT_NAME%" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "%OUTPUT_DIR%\AegisFilter.cat"
    )
    echo [+] Surucu basariyla test-imzalandi!
) else (
    echo [!] Signtool.exe PATH'te bulunamadi.
)

:SIGN_INFO
echo.
echo ===================================================================
echo   SURUCU KURULUM VE YUKLEME TALIMATLARI
echo ===================================================================
echo 1. Windows test-signing modunu acmak icin (Yonetici PowerShell/CMD):
echo    bcdedit /set testsigning on
echo    (Ardindan bilgisayari yeniden baslatin)
echo.
echo 2. INF uzerinden surucuyu yuklemek icin:
echo    rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 %OUTPUT_DIR%\AegisFilter.inf
echo.
echo 3. Minifilter surucusunu baslatmak icin:
echo    fltmc load AegisFilter
echo.
echo 4. Minifilter durumunu kontrol etmek icin:
echo    fltmc instances
echo.
echo 5. Surucuyu durdurmak icin:
echo    fltmc unload AegisFilter
echo ===================================================================
exit /b 0

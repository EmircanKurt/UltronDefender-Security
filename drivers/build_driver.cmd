@echo off
setlocal enabledelayedexpansion

echo ===================================================================
echo   ULTRON DEFENDER (AEGISPC) - KERNEL DRIVER BUILD AUTOMATION
echo ===================================================================

set SCRIPT_DIR=%~dp0
set DRIVER_SRC=%SCRIPT_DIR%AegisFilter
set OUTPUT_DIR=%SCRIPT_DIR%bin\x64\Release

if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
)

echo [*] Surucu kaynak dizini: %DRIVER_SRC%
echo [*] Cikti dizini: %OUTPUT_DIR%

:: 1. Detect MSBuild
set MSBUILD_EXE=
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\amd64\MSBuild.exe"
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
    echo [-] MSBuild bulunamadi. Visual Studio / WDK yuklu oldugundan emin olun.
) else (
    echo [+] MSBuild bulundu: %MSBUILD_EXE%
)

:: 2. Check for Windows Driver Kit (WDK)
set WDK_FOUND=0
if exist "C:\Program Files (x86)\Windows Kits\10\Include\wdf" set WDK_FOUND=1
if exist "C:\Program Files (x86)\Windows Kits\10\Include\km" set WDK_FOUND=1

if %WDK_FOUND% equ 0 (
    echo [!] UYARI: WDK (Windows Driver Kit) kurulu degil.
    echo     Surucuyu (.sys) derlemek icin Windows 10/11 WDK ve VS C++ Desktop bilesenleri gereklidir.
    echo     https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    echo.
    echo [*] Ultron Defender otomatik olarak User-Mode ETW + FileSystemWatcher Fallback modunda calismaya devam edecektir.
    exit /b 0
)

echo [+] WDK bulundu. AegisFilter.sys derleniyor...
"%MSBUILD_EXE%" "%DRIVER_SRC%\AegisFilter.vcxproj" /p:Configuration=Release /p:Platform=x64 /t:Build /m

if %errorLevel% neq 0 (
    echo [-] Derleme basarisiz oldu.
    exit /b 1
)

echo.
echo [+] BASARILI: AegisFilter.sys surucusu hazir: %OUTPUT_DIR%\AegisFilter.sys
echo [*] Surucuyu yuklemek icin yonetici komut satirinda:
echo     fltmc load AegisFilter
echo.
exit /b 0


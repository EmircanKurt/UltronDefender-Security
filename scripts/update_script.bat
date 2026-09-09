@echo off
setlocal enabledelayedexpansion

title AegisPC (Ultron Defender) - Offline Blocklist Updater
echo ====================================================================
echo  AEGISPC ULTRON DEFENDER - TEHDIT LISTESI GUNCELLEYICI
echo  (Offline DNS / URL Filtering Feed Updater)
echo ====================================================================
echo.

:: 1. Yonetici Yetkisi Kontrolu
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [UYARI] Bu script hosts ve sistem blocklist dosyalarini guncelleyebilmek icin
    echo         Yonetici (Administrator) yetkileriyle calistirilmalidir!
    echo.
    echo Yonetici olarak yeniden baslatiliyor...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: 2. Hedef Dizin Tanimlama
set "TARGET_DIR=%ProgramData%\UltronDefender\Blocklists"
if not exist "%TARGET_DIR%" (
    echo [*] Dizin olusturuluyor: %TARGET_DIR%
    mkdir "%TARGET_DIR%" >nul 2>&1
)

echo [*] Tehdit beslemeleri %TARGET_DIR% dizinine indirilecek...
echo.

:: 3. CURL Varligi Kontrolu
where curl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] curl.exe bulunamadi! Windows 10/11 yerlesik curl veya PowerShell gereklidir.
    goto :powershell_download
)

echo [1/4] abuse.ch URLhaus C2 ve Zararli Dagitim Alan Adlari indiriliyor...
curl -s -L -f --connect-timeout 15 "https://urlhaus.abuse.ch/downloads/hostfile/" -o "%TARGET_DIR%\c2_abusech.tmp"
if %errorlevel% equ 0 (
    move /y "%TARGET_DIR%\c2_abusech.tmp" "%TARGET_DIR%\c2_abusech.txt" >nul
    echo       [OK] c2_abusech.txt basariyla guncellendi.
) else (
    echo       [UYARI] abuse.ch erisilemedi. Yerel onbellek korundu.
)

echo [2/4] NoCoin Kripto Para Madenciligi (Cryptomining) Listesi indiriliyor...
curl -s -L -f --connect-timeout 15 "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt" -o "%TARGET_DIR%\cryptomining.tmp"
if %errorlevel% equ 0 (
    move /y "%TARGET_DIR%\cryptomining.tmp" "%TARGET_DIR%\cryptomining.txt" >nul
    echo       [OK] cryptomining.txt basariyla guncellendi.
) else (
    echo       [UYARI] Cryptomining listesi erisilemedi. Yerel onbellek korundu.
)

echo [3/4] OpenPhish Oltalama (Phishing) Alan Adlari indiriliyor...
curl -s -L -f --connect-timeout 15 "https://openphish.com/feed.txt" -o "%TARGET_DIR%\phishing.tmp"
if %errorlevel% equ 0 (
    move /y "%TARGET_DIR%\phishing.tmp" "%TARGET_DIR%\phishing.txt" >nul
    echo       [OK] phishing.txt basariyla guncellendi.
) else (
    echo       [UYARI] OpenPhish listesi erisilemedi. Yerel onbellek korundu.
)

echo [4/4] Peter Lowe Zararli Reklam (Malvertising) Listesi indiriliyor...
curl -s -L -f --connect-timeout 15 "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext" -o "%TARGET_DIR%\malvertising.tmp"
if %errorlevel% equ 0 (
    move /y "%TARGET_DIR%\malvertising.tmp" "%TARGET_DIR%\malvertising.txt" >nul
    echo       [OK] malvertising.txt basariyla guncellendi.
) else (
    echo       [UYARI] Malvertising listesi erisilemedi. Yerel onbellek korundu.
)

goto :finalize

:powershell_download
echo [*] PowerShell uzerinden indirme modu baslatiliyor...
powershell -NoProfile -Command ^
    "try { Invoke-WebRequest -Uri 'https://urlhaus.abuse.ch/downloads/hostfile/' -OutFile '%TARGET_DIR%\c2_abusech.txt' -TimeoutSec 15 } catch {};" ^
    "try { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt' -OutFile '%TARGET_DIR%\cryptomining.txt' -TimeoutSec 15 } catch {};" ^
    "try { Invoke-WebRequest -Uri 'https://openphish.com/feed.txt' -OutFile '%TARGET_DIR%\phishing.txt' -TimeoutSec 15 } catch {};" ^
    "try { Invoke-WebRequest -Uri 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext' -OutFile '%TARGET_DIR%\malvertising.txt' -TimeoutSec 15 } catch {};"

:finalize
echo.
echo [*] Windows DNS Onbellegi temizleniyor (ipconfig /flushdns)...
ipconfig /flushdns >nul 2>&1
echo [OK] DNS Onbellegi temizlendi.

echo.
echo ====================================================================
echo  GUNCELLEME TAMAMLANDI!
echo  Dosyalar: %TARGET_DIR%
echo  AegisPC DnsFilterService bir sonraki taramada kurallari otomatik yukleyecektir.
echo ====================================================================
echo.
pause

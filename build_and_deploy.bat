@echo off
setlocal
echo ==========================================================
echo  Ultron Defender Total Security - Build ^& Deploy
echo ==========================================================
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0build_and_deploy.ps1" %*
if errorlevel 1 (
    echo.
    echo [HATA] Derleme veya dagitim sirasinda hata olustu!
    pause
    exit /b 1
)
echo.
echo Islem basariyla tamamlandi.
pause

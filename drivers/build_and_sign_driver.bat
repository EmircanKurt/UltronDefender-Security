@echo off
setlocal
rem Delegate to the checked audit-only pipeline. No certificate/trust/boot/driver activation.
powershell.exe -NoProfile -File "%~dp0Build-And-Sign-Driver.ps1" %*
exit /b %errorLevel%

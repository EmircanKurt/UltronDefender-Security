@echo off
setlocal
rem An unsigned build still requires assignment evidence and checked catalog generation.
powershell.exe -NoProfile -File "%~dp0Build-And-Sign-Driver.ps1" -SkipSign %*
exit /b %errorLevel%


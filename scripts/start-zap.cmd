@echo off
setlocal
REM Wrapper to run PowerShell script without changing execution policy permanently
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-zap.ps1"
endlocal


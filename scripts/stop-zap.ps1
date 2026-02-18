$ErrorActionPreference = "Stop"

$RuntimeDir = Join-Path $PSScriptRoot "..\.runtime"
$PidFile    = Join-Path $RuntimeDir "zap.pid"

if (!(Test-Path $PidFile)) {
  Write-Host "No zap.pid found. ZAP may not be running (or wasn't started using start-zap.ps1)."
  exit 0
}

$pidText = (Get-Content $PidFile -Raw).Trim()
if (!($pidText -match '^\d+$')) {
  Remove-Item -Force $PidFile -ErrorAction SilentlyContinue | Out-Null
  throw "Invalid PID file content: '$pidText'"
}

$pid = [int]$pidText
$proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
if (!$proc) {
  Write-Host "Process PID $pid not found. Cleaning up pid file."
  Remove-Item -Force $PidFile -ErrorAction SilentlyContinue | Out-Null
  exit 0
}

Write-Host "Stopping OWASP ZAP (PID $pid)..."
try {
  Stop-Process -Id $pid -Force
  Start-Sleep -Seconds 1
} catch {
  Write-Host "Stop failed: $($_.Exception.Message)"
}

Remove-Item -Force $PidFile -ErrorAction SilentlyContinue | Out-Null
Write-Host "ZAP stopped."


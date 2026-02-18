$ErrorActionPreference = "Stop"

# --- Config ---
$ZapHome = "C:\Program Files\ZAP\Zed Attack Proxy"
$ZapBat  = Join-Path $ZapHome "zap.bat"
$Port    = 8090
$HostIp  = "127.0.0.1"

# Project local runtime folder for pid/logs
$RuntimeDir = Join-Path $PSScriptRoot "..\.runtime"
$PidFile    = Join-Path $RuntimeDir "zap.pid"
$OutLogFile = Join-Path $RuntimeDir "zap.out.log"
$ErrLogFile = Join-Path $RuntimeDir "zap.err.log"

New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null

if (!(Test-Path $ZapBat)) {
  throw "ZAP not found: $ZapBat"
}

# If already running (pid file exists and process alive), do nothing.
if (Test-Path $PidFile) {
  $existingPid = (Get-Content $PidFile -Raw).Trim()
  if ($existingPid -match '^\d+$') {
    $p = Get-Process -Id ([int]$existingPid) -ErrorAction SilentlyContinue
    if ($p) {
      Write-Host "ZAP already running (PID $existingPid) on port $Port"
      exit 0
    }
  }
  Remove-Item -Force $PidFile -ErrorAction SilentlyContinue | Out-Null
}

Write-Host "Starting OWASP ZAP in daemon mode..."
Write-Host "Path: $ZapBat"
Write-Host "Host: $HostIp  Port: $Port"
Write-Host "Out : $OutLogFile"
Write-Host "Err : $ErrLogFile"

# Start ZAP headless (daemon). API key disabled for local dev.
# If you want API key, remove api.disablekey=true and set zap.api.key in application.properties.
$args = @(
  "-daemon",
  "-host", $HostIp,
  "-port", "$Port",
  "-config", "api.disablekey=true",
  "-config", "api.addrs.addr.name=$HostIp",
  "-config", "api.addrs.addr.regex=false"
)

$proc = Start-Process -FilePath $ZapBat -ArgumentList $args -PassThru -NoNewWindow -RedirectStandardOutput $OutLogFile -RedirectStandardError $ErrLogFile
$proc.Id | Out-File -FilePath $PidFile -Encoding ascii -Force

Write-Host "ZAP started (PID $($proc.Id))."
Write-Host "Tip: stop with scripts\stop-zap.ps1"


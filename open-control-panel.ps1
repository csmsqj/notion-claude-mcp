$ErrorActionPreference = "Stop"
$url = "http://127.0.0.1:8876/"
try {
    $null = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8875/healthz" -TimeoutSec 2
} catch {
    Write-Host "The gateway does not seem to be running. Double-click START.cmd first." -ForegroundColor Yellow
    Write-Host "Control panel URL (once running): $url"
    Read-Host "Press Enter to close"
    exit 1
}
Write-Host "Opening $url"
Start-Process $url

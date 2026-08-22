$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$configDir = Join-Path $root "gateway\config"
$installer = Join-Path $root "install-notion-mcp-watchdog.ps1"
$serverPidFile = Join-Path $configDir "server.pid"
$watchdogPidFile = Join-Path $configDir "watchdog.pid"
$stateFile = Join-Path $configDir "watchdog-state.json"
$urlFile = Join-Path $configDir "current-url.txt"
$powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$success = $false
$baselineCheck = ""
$baselineRecovery = ""

try {
    & $powershellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $installer `
        -CheckIntervalSeconds 10 -FailureThreshold 1 -PublicFailureThreshold 1

    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        Start-Sleep -Seconds 1
        if (-not (Test-Path -LiteralPath $watchdogPidFile) -or -not (Test-Path -LiteralPath $stateFile)) { continue }
        $watchdogText = (Get-Content -LiteralPath $watchdogPidFile -Raw).Trim()
        $watchdogProcess = if ($watchdogText -match "^\d+$") { Get-CimInstance Win32_Process -Filter "ProcessId = $watchdogText" -ErrorAction SilentlyContinue } else { $null }
        if ($watchdogProcess -and "$($watchdogProcess.CommandLine)" -like "*-CheckIntervalSeconds 10*") {
            $baseline = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($stateFile, [System.Text.Encoding]::UTF8))
            $baselineCheck = "$($baseline.last_check)"
            $baselineRecovery = "$($baseline.last_recovery)"
            break
        }
    }
    if (-not $baselineCheck) { throw "Scheduled test watchdog did not publish a fresh health check." }

    $oldUrl = if (Test-Path -LiteralPath $urlFile) { (Get-Content -LiteralPath $urlFile -Raw).Trim() } else { "" }
    $serverText = (Get-Content -LiteralPath $serverPidFile -Raw).Trim()
    $serverProcess = if ($serverText -match "^\d+$") { Get-CimInstance Win32_Process -Filter "ProcessId = $serverText" -ErrorAction SilentlyContinue } else { $null }
    if (-not $serverProcess -or "$($serverProcess.CommandLine)" -notlike "*gateway-v21.py*") { throw "Gateway PID is not valid for fault injection." }
    & taskkill.exe /PID ([int]$serverText) /T /F *> $null
    Write-Host "Injected gateway process failure; waiting for scheduled automatic recovery..."

    for ($attempt = 0; $attempt -lt 24; $attempt++) {
        Start-Sleep -Seconds 5
        if (-not (Test-Path -LiteralPath $stateFile)) { continue }
        try {
            $state = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($stateFile, [System.Text.Encoding]::UTF8))
            Write-Host ("  {0}: status={1}, gateway={2}, public={3}" -f $state.last_check, $state.status, $state.gateway_healthy, $state.public_healthy)
            if (
                "$($state.last_recovery)" -ne $baselineRecovery -and
                $state.status -in @("healthy", "manual_reconnect_required") -and
                $state.gateway_healthy -and $state.public_healthy
            ) {
                $newUrl = if (Test-Path -LiteralPath $urlFile) { (Get-Content -LiteralPath $urlFile -Raw).Trim() } else { "" }
                if ($newUrl) {
                    Write-Host "Recovered MCP URL: $newUrl"
                    if ($oldUrl -and $oldUrl -ne $newUrl) { Write-Host "Quick Tunnel URL changed during recovery, as expected." }
                    $success = $true
                    break
                }
            }
        } catch { }
    }
    if (-not $success) { throw "Watchdog did not restore a healthy gateway within the test window." }
    Write-Host "Automatic recovery test passed." -ForegroundColor Green
} finally {
    & $powershellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $installer
}

if (-not $success) { exit 1 }

param(
    [ValidateRange(10, 3600)]
    [int]$CheckIntervalSeconds = 30,
    [ValidateRange(1, 20)]
    [int]$FailureThreshold = 3,
    [ValidateRange(1, 30)]
    [int]$PublicFailureThreshold = 3
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$configDir = Join-Path $root "gateway\config"
$logDir = Join-Path $root "gateway\logs"
$desiredStateFile = Join-Path $configDir "desired-state.txt"
$serverPidFile = Join-Path $configDir "server.pid"
$tunnelPidFile = Join-Path $configDir "tunnel.pid"
$urlFile = Join-Path $configDir "current-url.txt"
$watchdogPidFile = Join-Path $configDir "watchdog.pid"
$watchdogStateFile = Join-Path $configDir "watchdog-state.json"
$watchdogLog = Join-Path $logDir "watchdog.log"
$stopScript = Join-Path $root "stop-notion-mcp.ps1"
$startScript = Join-Path $root "start-notion-mcp-v21.ps1"
$pythonPath = [System.IO.Path]::GetFullPath((Join-Path $root ".venv\Scripts\python.exe"))
$cloudflaredPath = [System.IO.Path]::GetFullPath((Join-Path $root "bin\cloudflared.exe"))

New-Item -ItemType Directory -Force -Path $configDir, $logDir | Out-Null

function Write-WatchdogLog {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -LiteralPath $watchdogLog -Value $line -Encoding utf8
}

function Read-TextFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
    try { return (Get-Content -LiteralPath $Path -Raw).Trim() } catch { return "" }
}

function Get-TrackedProcess {
    param([string]$PidFile, [string]$ExpectedCommand, [string]$ExpectedExecutable = "")
    $trackedPid = Read-TextFile -Path $PidFile
    if ($trackedPid -notmatch "^\d+$") { return $null }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $trackedPid" -ErrorAction SilentlyContinue
    if ($null -eq $process -or "$($process.CommandLine)" -notlike "*$ExpectedCommand*") { return $null }
    if ($ExpectedExecutable) {
        $actual = "$($process.ExecutablePath)"
        if (-not $actual -or ([System.IO.Path]::GetFullPath($actual) -ine $ExpectedExecutable)) { return $null }
    }
    return $process
}

function Test-JsonHealth {
    param([string]$Uri)
    try {
        $response = Invoke-RestMethod -UseBasicParsing -Uri $Uri -TimeoutSec 5
        return $response.ok -eq $true -and $response.auth -eq "oauth2.1"
    } catch {
        return $false
    }
}

function Get-RuntimeTunnelMode {
    param($TunnelProcess, [string]$PublicUrl)
    if ($null -ne $TunnelProcess) {
        $command = "$($TunnelProcess.CommandLine)"
        if ($command -match "(?:^|\s)run(?:\s|$)" -and $command -match "--config") { return "named" }
        if ($command -match "--url") { return "quick" }
    }
    if ($PublicUrl -match "\.trycloudflare\.com/mcp/?$") { return "quick" }
    return "unknown"
}

function Save-WatchdogState {
    param(
        [string]$Status,
        [string]$Message,
        [bool]$GatewayProcess,
        [bool]$GatewayHealthy,
        [bool]$TunnelProcess,
        [bool]$PublicHealthy,
        [string]$PublicUrl,
        [string]$TunnelMode,
        [int]$GatewayFailures,
        [int]$TunnelFailures,
        [string]$LastRecovery
    )
    $payload = [ordered]@{
        version = 1
        pid = $PID
        last_check = [DateTimeOffset]::Now.ToString("o")
        desired_state = (Read-TextFile -Path $desiredStateFile)
        status = $Status
        message = $Message
        gateway_process = $GatewayProcess
        gateway_healthy = $GatewayHealthy
        tunnel_process = $TunnelProcess
        public_healthy = $PublicHealthy
        public_url = $PublicUrl
        tunnel_mode = $TunnelMode
        gateway_failures = $GatewayFailures
        tunnel_failures = $TunnelFailures
        last_recovery = $LastRecovery
    }
    $temporary = "$watchdogStateFile.tmp"
    $json = $payload | ConvertTo-Json
    [System.IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding $false))
    Move-Item -LiteralPath $temporary -Destination $watchdogStateFile -Force
}

function Invoke-GatewayRecovery {
    Write-WatchdogLog "Recovery started."
    # Keep launchers in this process. A child PowerShell pipeline can wait forever
    # when a resident gateway/tunnel process inherits its output handle.
    $stopOutput = & $stopScript -Recovery 2>&1 | Out-String
    if ($stopOutput.Trim()) { Write-WatchdogLog ($stopOutput.Trim() -replace "[\r\n]+", " | ") }

    $startOutput = & $startScript -Recovery -NoBrowser 2>&1 | Out-String
    if ($startOutput.Trim()) { Write-WatchdogLog ($startOutput.Trim() -replace "[\r\n]+", " | ") }
    Write-WatchdogLog "Recovery completed."
}

$mutex = New-Object System.Threading.Mutex($false, "Global\LocalFileMcpGatewayWatchdog")
$hasMutex = $false
try {
    try { $hasMutex = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $hasMutex = $true }
    if (-not $hasMutex) { exit 0 }

    $PID | Set-Content -LiteralPath $watchdogPidFile -Encoding ascii
    Write-WatchdogLog "Watchdog started (PID $PID, interval ${CheckIntervalSeconds}s)."

    $gatewayFailures = 0
    $tunnelFailures = 0
    $recoveryFailures = 0
    $nextRecoveryAt = [DateTimeOffset]::MinValue
    $lastRecovery = ""

    while ($true) {
        $desiredState = (Read-TextFile -Path $desiredStateFile).ToLowerInvariant()
        if ($desiredState -ne "running") {
            $gatewayFailures = 0
            $tunnelFailures = 0
            Save-WatchdogState -Status "standby" -Message "Manual stop is active." `
                -GatewayProcess $false -GatewayHealthy $false -TunnelProcess $false -PublicHealthy $false `
                -PublicUrl "" -TunnelMode "unknown" -GatewayFailures 0 -TunnelFailures 0 -LastRecovery $lastRecovery
            Start-Sleep -Seconds $CheckIntervalSeconds
            continue
        }

        $serverProcess = Get-TrackedProcess -PidFile $serverPidFile -ExpectedCommand "gateway-v21.py" -ExpectedExecutable $pythonPath
        $tunnelProcess = Get-TrackedProcess -PidFile $tunnelPidFile -ExpectedCommand "cloudflared" -ExpectedExecutable $cloudflaredPath
        $publicUrl = Read-TextFile -Path $urlFile
        $gatewayHealthy = $null -ne $serverProcess -and (Test-JsonHealth -Uri "http://127.0.0.1:8875/healthz")
        $publicHealthy = $false
        if ($null -ne $tunnelProcess -and $publicUrl -match "^https://") {
            $healthUrl = ($publicUrl -replace "/mcp/?$", "") + "/healthz"
            $publicHealthy = Test-JsonHealth -Uri $healthUrl
        }
        $tunnelMode = Get-RuntimeTunnelMode -TunnelProcess $tunnelProcess -PublicUrl $publicUrl

        if ($gatewayHealthy) { $gatewayFailures = 0 } else { $gatewayFailures++ }
        if ($null -ne $tunnelProcess -and $publicHealthy) { $tunnelFailures = 0 } else { $tunnelFailures++ }

        $thresholdReached = $gatewayFailures -ge $FailureThreshold
        if (-not $thresholdReached -and $null -eq $tunnelProcess) {
            $thresholdReached = $tunnelFailures -ge $FailureThreshold
        }
        if (-not $thresholdReached -and $null -ne $tunnelProcess -and -not $publicHealthy) {
            $thresholdReached = $tunnelFailures -ge $PublicFailureThreshold
        }

        if ($gatewayHealthy -and $publicHealthy) {
            $recoveryFailures = 0
            $nextRecoveryAt = [DateTimeOffset]::MinValue
            $healthyStatus = if ($tunnelMode -eq "quick" -and $lastRecovery) { "manual_reconnect_required" } else { "healthy" }
            $healthyMessage = if ($healthyStatus -eq "manual_reconnect_required") {
                "Gateway and Quick Tunnel recovered; the public URL changed, so MCP clients must be updated."
            } else { "Gateway and public tunnel are healthy." }
            Save-WatchdogState -Status $healthyStatus -Message $healthyMessage `
                -GatewayProcess $true -GatewayHealthy $true -TunnelProcess $true -PublicHealthy $true `
                -PublicUrl $publicUrl -TunnelMode $tunnelMode -GatewayFailures 0 -TunnelFailures 0 -LastRecovery $lastRecovery
        } elseif ($thresholdReached -and [DateTimeOffset]::Now -ge $nextRecoveryAt) {
            Save-WatchdogState -Status "recovering" -Message "Failure threshold reached; restarting gateway and tunnel." `
                -GatewayProcess ($null -ne $serverProcess) -GatewayHealthy $gatewayHealthy `
                -TunnelProcess ($null -ne $tunnelProcess) -PublicHealthy $publicHealthy `
                -PublicUrl $publicUrl -TunnelMode $tunnelMode -GatewayFailures $gatewayFailures -TunnelFailures $tunnelFailures -LastRecovery $lastRecovery
            try {
                Invoke-GatewayRecovery
                $lastRecovery = [DateTimeOffset]::Now.ToString("o")
                $gatewayFailures = 0
                $tunnelFailures = 0
                # Do not clear the backoff until a subsequent health check proves
                # that both the gateway and public tunnel are healthy.
                $nextRecoveryAt = [DateTimeOffset]::Now.AddSeconds($CheckIntervalSeconds)
            } catch {
                $recoveryFailures++
                $delayMinutes = [Math]::Min(30, [Math]::Pow(2, [Math]::Min(5, $recoveryFailures - 1)))
                $nextRecoveryAt = [DateTimeOffset]::Now.AddMinutes($delayMinutes)
                Write-WatchdogLog "Recovery failed: $($_.Exception.Message). Retry in $delayMinutes minute(s)." "ERROR"
            }
        } else {
            Save-WatchdogState -Status "degraded" -Message "A health check failed; waiting for the failure threshold." `
                -GatewayProcess ($null -ne $serverProcess) -GatewayHealthy $gatewayHealthy `
                -TunnelProcess ($null -ne $tunnelProcess) -PublicHealthy $publicHealthy `
                -PublicUrl $publicUrl -TunnelMode $tunnelMode -GatewayFailures $gatewayFailures -TunnelFailures $tunnelFailures -LastRecovery $lastRecovery
        }

        Start-Sleep -Seconds $CheckIntervalSeconds
    }
} finally {
    if ((Read-TextFile -Path $watchdogPidFile) -eq "$PID") {
        Remove-Item -LiteralPath $watchdogPidFile -Force -ErrorAction SilentlyContinue
    }
    if ($hasMutex) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}

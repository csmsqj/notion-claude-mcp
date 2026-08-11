$ErrorActionPreference = "Stop"

$root = "D:\notion"
$configDir = Join-Path $root "gateway\config"
$urlFile = Join-Path $configDir "current-url.txt"
$policyFile = Join-Path $configDir "policy.json"
$desiredStateFile = Join-Path $configDir "desired-state.txt"
$watchdogStateFile = Join-Path $configDir "watchdog-state.json"
$taskName = "Local File MCP Gateway Watchdog"
$pythonPath = [System.IO.Path]::GetFullPath((Join-Path $root ".venv\Scripts\python.exe"))
$cloudflaredPath = [System.IO.Path]::GetFullPath((Join-Path $root "bin\cloudflared.exe"))

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
        if (-not "$($process.ExecutablePath)" -or ([System.IO.Path]::GetFullPath("$($process.ExecutablePath)") -ine $ExpectedExecutable)) { return $null }
    }
    return $process
}

function Show-ProcessState {
    param($Process, [string]$Label)
    if ($null -eq $Process) {
        Write-Host "${Label}: stopped" -ForegroundColor Yellow
    } else {
        Write-Host "${Label}: running (PID $($Process.ProcessId))" -ForegroundColor Green
    }
}

function Test-JsonHealth {
    param([string]$Uri)
    try {
        $response = Invoke-RestMethod -UseBasicParsing -Uri $Uri -TimeoutSec 5
        return $response.ok -eq $true -and $response.auth -eq "oauth2.1"
    } catch { return $false }
}

$serverProcess = Get-TrackedProcess -PidFile (Join-Path $configDir "server.pid") -ExpectedCommand "gateway-v21.py" -ExpectedExecutable $pythonPath
$tunnelProcess = Get-TrackedProcess -PidFile (Join-Path $configDir "tunnel.pid") -ExpectedCommand "cloudflared" -ExpectedExecutable $cloudflaredPath
$watchdogProcess = Get-TrackedProcess -PidFile (Join-Path $configDir "watchdog.pid") -ExpectedCommand "watchdog-notion-mcp.ps1"
$desiredState = Read-TextFile -Path $desiredStateFile

Write-Host "Local file MCP gateway" -ForegroundColor Cyan
Write-Host "Desired state: $(if ($desiredState) { $desiredState } else { 'not set' })"
Show-ProcessState -Process $serverProcess -Label "Gateway"
Show-ProcessState -Process $tunnelProcess -Label "Cloudflare Tunnel"
Show-ProcessState -Process $watchdogProcess -Label "Auto-recovery watchdog"

try {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Write-Host "Logon task: installed ($($task.State))" -ForegroundColor Green
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
    $taskArguments = "$($task.Actions[0].Arguments)"
    Write-Host "  task_result=$($taskInfo.LastTaskResult)  args=$taskArguments"
} catch {
    Write-Host "Logon task: not installed (run INSTALL-AUTO-RECOVERY.cmd)" -ForegroundColor Yellow
}

$localHealthy = $null -ne $serverProcess -and (Test-JsonHealth -Uri "http://127.0.0.1:8875/healthz")
Write-Host "Local health: $(if ($localHealthy) { 'healthy' } else { 'unavailable' })" -ForegroundColor $(if ($localHealthy) { 'Green' } else { 'Red' })

$publicUrl = Read-TextFile -Path $urlFile
$publicHealthy = $false
if ($publicUrl -match "^https://" -and $null -ne $tunnelProcess) {
    $publicHealthUrl = ($publicUrl -replace "/mcp/?$", "") + "/healthz"
    $publicHealthy = Test-JsonHealth -Uri $publicHealthUrl
}
Write-Host "Public health: $(if ($publicHealthy) { 'healthy' } else { 'unavailable' })" -ForegroundColor $(if ($publicHealthy) { 'Green' } else { 'Red' })

if ($publicUrl) {
    $tunnelCommand = if ($null -ne $tunnelProcess) { "$($tunnelProcess.CommandLine)" } else { "" }
    $mode = if ($tunnelCommand -match "(?:^|\s)run(?:\s|$)" -and $tunnelCommand -match "--config") {
        "Named Tunnel"
    } elseif ($tunnelCommand -match "--url" -or $publicUrl -match "\.trycloudflare\.com/mcp/?$") {
        "Quick Tunnel"
    } else {
        "Unknown Tunnel"
    }
    Write-Host ""
    Write-Host "MCP URL ($mode):" -ForegroundColor Cyan
    Write-Host $publicUrl
    if ($mode -eq "Quick Tunnel") {
        Write-Host "Address stability: valid for this tunnel process only; recovery may create a new URL." -ForegroundColor Yellow
    } elseif ($mode -eq "Named Tunnel") {
        Write-Host "Address stability: fixed hostname; watchdog recovery keeps the same URL." -ForegroundColor Green
    } else {
        Write-Host "Address stability: unknown; verify the active tunnel configuration." -ForegroundColor Yellow
    }
    $publicOrigin = $publicUrl -replace "/mcp/?$", ""
    Write-Host "OAuth metadata: $publicOrigin/.well-known/oauth-authorization-server"
}

if (Test-Path -LiteralPath $watchdogStateFile -PathType Leaf) {
    try {
        $watchdogJson = [System.IO.File]::ReadAllText($watchdogStateFile, [System.Text.Encoding]::UTF8)
        $watchdogState = ConvertFrom-Json -InputObject $watchdogJson
        Write-Host ""
        Write-Host "Watchdog state:" -ForegroundColor Cyan
        Write-Host "  status=$($watchdogState.status)  checked=$($watchdogState.last_check)"
        Write-Host "  gateway_failures=$($watchdogState.gateway_failures)  tunnel_failures=$($watchdogState.tunnel_failures)"
        Write-Host "  message=$($watchdogState.message)"
        if ($watchdogState.last_recovery) { Write-Host "  last_recovery=$($watchdogState.last_recovery)" }
    } catch {
        Write-Host "Watchdog state file is unreadable." -ForegroundColor Yellow
    }
}

if ($null -ne $serverProcess) {
    Write-Host ""
    Write-Host "Local control panel:" -ForegroundColor Cyan
    Write-Host "http://127.0.0.1:8876/"
}

if (Test-Path -LiteralPath $policyFile) {
    try {
        $policyText = [System.IO.File]::ReadAllText($policyFile, [System.Text.Encoding]::UTF8)
        $policy = ConvertFrom-Json -InputObject $policyText
        Write-Host ""
        Write-Host "Authorized paths:" -ForegroundColor Cyan
        if (@($policy.roots).Count -eq 0) {
            Write-Host "(none yet - open the control panel to add folders)" -ForegroundColor Yellow
        } else {
            foreach ($item in $policy.roots) {
                $stateText = if ($item.enabled) { "enabled" } else { "disabled" }
                Write-Host ("  [level " + $item.level + "] " + $item.path + " (" + $stateText + ")")
            }
        }
        if ($policy.global_lock) { Write-Host "GLOBAL LOCK IS ON - every operation is denied." -ForegroundColor Red }
    } catch {
        Write-Host "Authorized path policy is unreadable: $($_.Exception.Message)" -ForegroundColor Red
    }
}

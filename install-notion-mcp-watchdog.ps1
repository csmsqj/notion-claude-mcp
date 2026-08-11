param(
    [switch]$Uninstall,
    [ValidateRange(10, 3600)][int]$CheckIntervalSeconds = 30,
    [ValidateRange(1, 20)][int]$FailureThreshold = 3,
    [ValidateRange(1, 20)][int]$PublicFailureThreshold = 3
)

$ErrorActionPreference = "Stop"
$root = "D:\notion"
$watchdogScript = Join-Path $root "watchdog-notion-mcp.ps1"
$configDir = Join-Path $root "gateway\config"
$desiredStateFile = Join-Path $configDir "desired-state.txt"
$watchdogPidFile = Join-Path $configDir "watchdog.pid"
$taskName = "Local File MCP Gateway Watchdog"
$powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

function Stop-ExistingWatchdog {
    if (-not (Test-Path -LiteralPath $watchdogPidFile)) { return }
    $trackedPid = (Get-Content -LiteralPath $watchdogPidFile -Raw).Trim()
    if ($trackedPid -match "^\d+$") {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $trackedPid" -ErrorAction SilentlyContinue
        if ($process -and "$($process.CommandLine)" -like "*watchdog-notion-mcp.ps1*") {
            Stop-Process -Id ([int]$trackedPid) -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $watchdogPidFile -Force -ErrorAction SilentlyContinue
}

if ($Uninstall) {
    Stop-ExistingWatchdog
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Automatic recovery watchdog was removed." -ForegroundColor Green
    exit 0
}

if (-not (Test-Path -LiteralPath $watchdogScript -PathType Leaf)) {
    throw "Missing watchdog script: $watchdogScript"
}
New-Item -ItemType Directory -Force -Path $configDir | Out-Null

# Register-ScheduledTask -Force does not replace a currently running instance.
# Stop it first so script updates are loaded immediately instead of keeping stale code.
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Stop-ExistingWatchdog
Start-Sleep -Milliseconds 500

$arguments = (
    "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass " +
    "-File `"$watchdogScript`" -CheckIntervalSeconds $CheckIntervalSeconds " +
    "-FailureThreshold $FailureThreshold -PublicFailureThreshold $PublicFailureThreshold"
)
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $powershellExe -Argument $arguments -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
    -MultipleInstances IgnoreNew `
    -RestartCount 10 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
if (-not (Test-Path -LiteralPath $desiredStateFile)) {
    "running" | Set-Content -LiteralPath $desiredStateFile -Encoding ascii
}
Start-ScheduledTask -TaskName $taskName

for ($attempt = 0; $attempt -lt 20; $attempt++) {
    if (Test-Path -LiteralPath $watchdogPidFile) {
        $trackedPid = (Get-Content -LiteralPath $watchdogPidFile -Raw).Trim()
        $process = if ($trackedPid -match "^\d+$") { Get-CimInstance Win32_Process -Filter "ProcessId = $trackedPid" -ErrorAction SilentlyContinue } else { $null }
        if ($process -and "$($process.CommandLine)" -like "*watchdog-notion-mcp.ps1*") {
            Write-Host "Automatic recovery watchdog is active (PID $trackedPid)." -ForegroundColor Green
            Write-Host "It starts at Windows logon and checks every $CheckIntervalSeconds seconds (threshold $FailureThreshold/$PublicFailureThreshold)."
            exit 0
        }
    }
    Start-Sleep -Milliseconds 250
}
throw "The scheduled task was registered, but the watchdog process did not start. Check Task Scheduler history."

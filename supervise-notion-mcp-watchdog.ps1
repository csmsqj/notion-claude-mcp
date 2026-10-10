param(
    [ValidateRange(30, 3600)][int]$StaleSeconds = 240
)
# Idempotent supervisor. Run from Task Scheduler every three minutes.
# A separate process supervises the long-lived watchdog so watchdog crashes
# cannot silently disable auto-recovery until the next Windows logon.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$watchdog = Join-Path $root "watchdog-notion-mcp.ps1"
$config = Join-Path $root "gateway\config"
$desired = Join-Path $config "desired-state.txt"
$pidFile = Join-Path $config "watchdog.pid"
$stateFile = Join-Path $config "watchdog-state.json"
$ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$lock = New-Object System.Threading.Mutex($false, "Global\LocalFileMcpGatewaySupervisor")
$acquired = $false
try {
    try { $acquired = $lock.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $acquired = $true }
    if (-not $acquired) { return }
    if (-not (Test-Path -LiteralPath $desired)) { return }
    if ((Get-Content -LiteralPath $desired -Raw).Trim() -ne "running") { return }
    $pidText = ""
    if (Test-Path -LiteralPath $pidFile) { $pidText = (Get-Content -LiteralPath $pidFile -Raw).Trim() }
    $process = $null
    if ($pidText -match "^\d+$") {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $pidText" -ErrorAction SilentlyContinue
    }
    $valid = $process -and "$($process.CommandLine)" -like "*watchdog-notion-mcp.ps1*" -and
        "$($process.ExecutablePath)" -and
        ([System.IO.Path]::GetFullPath("$($process.ExecutablePath)") -ieq [System.IO.Path]::GetFullPath($ps))
    $stale = $true
    if (Test-Path -LiteralPath $stateFile) {
        try {
            $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
            $checked = [DateTimeOffset]::Parse("$($state.last_check)")
            $stale = ([DateTimeOffset]::Now - $checked).TotalSeconds -gt $StaleSeconds
        } catch { $stale = $true }
    }
    if ($valid -and -not $stale) { return }
    # Refuse to terminate an unrelated process even when the PID was reused.
    if ($valid) { Stop-Process -Id ([int]$pidText) -Force -ErrorAction Stop }
    $args = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
        $watchdog + '" -CheckIntervalSeconds 30 -FailureThreshold 3 -PublicFailureThreshold 3'
    Start-Process -FilePath $ps -ArgumentList $args -WorkingDirectory $root -WindowStyle Hidden | Out-Null
} finally {
    if ($acquired) { $lock.ReleaseMutex() }
    $lock.Dispose()
}

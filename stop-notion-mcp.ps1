param([switch]$Recovery)

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$configDir = Join-Path $root "gateway\config"
$legacyConfigDir = Join-Path $root "config"
$desiredStateFile = Join-Path $configDir "desired-state.txt"
$pythonPath = [System.IO.Path]::GetFullPath((Join-Path $root ".venv\Scripts\python.exe"))
$cloudflaredPath = [System.IO.Path]::GetFullPath((Join-Path $root "bin\cloudflared.exe"))
$lifecycleMutex = New-Object System.Threading.Mutex($false, "Global\LocalFileMcpGatewayLifecycle")
$hasLifecycleMutex = $false

function Stop-TrackedProcess {
    param([string]$PidFile, [string]$Label, [string]$ExpectedCommand, [string]$ExpectedExecutable)
    if (-not (Test-Path -LiteralPath $PidFile)) { return }
    $trackedPid = (Get-Content -LiteralPath $PidFile -Raw).Trim()
    if ($trackedPid -match "^\d+$") {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $trackedPid" -ErrorAction SilentlyContinue
        $executableMatches = $null -ne $process -and "$($process.ExecutablePath)" -and ([System.IO.Path]::GetFullPath("$($process.ExecutablePath)") -ieq $ExpectedExecutable)
        if ($null -ne $process -and $executableMatches -and "$($process.CommandLine)" -like "*$ExpectedCommand*") {
            & taskkill.exe /PID ([int]$trackedPid) /T /F *> $null
            if ($LASTEXITCODE -ne 0 -and (Get-Process -Id ([int]$trackedPid) -ErrorAction SilentlyContinue)) {
                Stop-Process -Id ([int]$trackedPid) -Force -ErrorAction SilentlyContinue
            }
            for ($attempt = 0; $attempt -lt 20; $attempt++) {
                if (-not (Get-Process -Id ([int]$trackedPid) -ErrorAction SilentlyContinue)) { break }
                Start-Sleep -Milliseconds 100
            }
            if (Get-Process -Id ([int]$trackedPid) -ErrorAction SilentlyContinue) {
                throw "$Label PID $trackedPid could not be stopped."
            }
            Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
            Write-Host "$Label stopped (PID $trackedPid)."
        } elseif ($null -ne $process) {
            throw "$Label PID $trackedPid does not match the expected process; refusing to remove its tracking record."
        } else {
            Write-Host "$Label was not running (stale PID $trackedPid)."
            Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
    }
}

try {
try { $hasLifecycleMutex = $lifecycleMutex.WaitOne(120000) } catch [System.Threading.AbandonedMutexException] { $hasLifecycleMutex = $true }
if (-not $hasLifecycleMutex) { throw "Timed out waiting for another gateway start/stop operation to finish." }

if (-not $Recovery) {
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    "stopped" | Set-Content -LiteralPath $desiredStateFile -Encoding ascii
}

foreach ($dir in @($configDir, $legacyConfigDir)) {
    Stop-TrackedProcess -PidFile (Join-Path $dir "tunnel.pid") -Label "Cloudflare Tunnel" -ExpectedCommand "cloudflared" -ExpectedExecutable $cloudflaredPath
    Stop-TrackedProcess -PidFile (Join-Path $dir "server.pid") -Label "Local file MCP gateway" -ExpectedCommand "gateway-v21.py" -ExpectedExecutable $pythonPath
    Remove-Item -LiteralPath (Join-Path $dir "current-url.txt") -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $dir "notion-connection-details.txt") -Force -ErrorAction SilentlyContinue
}

Write-Host "Local file MCP gateway is stopped." -ForegroundColor Green
} finally {
    if ($hasLifecycleMutex) { $lifecycleMutex.ReleaseMutex() }
    $lifecycleMutex.Dispose()
}

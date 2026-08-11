param(
    [switch]$NoBrowser,
    [switch]$Recovery
)

$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8

$root = "D:\notion"
$python = Join-Path $root ".venv\Scripts\python.exe"
$gateway = Join-Path $root "runtime-patches\gateway-v21.py"
$cloudflaredExe = Join-Path $root "bin\cloudflared.exe"
$configDir = Join-Path $root "gateway\config"
$logDir = Join-Path $root "gateway\logs"
$serverPidFile = Join-Path $configDir "server.pid"
$tunnelPidFile = Join-Path $configDir "tunnel.pid"
$urlFile = Join-Path $configDir "current-url.txt"
$connectionDetailsFile = Join-Path $configDir "notion-connection-details.txt"
$desiredStateFile = Join-Path $configDir "desired-state.txt"
$tunnelSettingsFile = Join-Path $configDir "tunnel-settings.json"
$defaultNamedConfig = Join-Path $configDir "cloudflared.yml"
$serverOut = Join-Path $logDir "server.out.log"
$serverErr = Join-Path $logDir "server.err.log"
$tunnelOut = Join-Path $logDir "tunnel.out.log"
$tunnelErr = Join-Path $logDir "tunnel.err.log"
$mcpPort = 8875
$consolePort = 8876

function Assert-NotRunning {
    param([string]$PidFile, [string]$Label, [string]$ExpectedCommand, [string]$ExpectedExecutable)
    if (-not (Test-Path -LiteralPath $PidFile)) { return }
    $trackedPid = (Get-Content -LiteralPath $PidFile -Raw).Trim()
    if ($trackedPid -match "^\d+$") {
        $tracked = Get-CimInstance Win32_Process -Filter "ProcessId = $trackedPid" -ErrorAction SilentlyContinue
        $executableMatches = $tracked -and "$($tracked.ExecutablePath)" -and ([System.IO.Path]::GetFullPath("$($tracked.ExecutablePath)") -ieq [System.IO.Path]::GetFullPath($ExpectedExecutable))
        if ($tracked -and $executableMatches -and "$($tracked.CommandLine)" -like "*$ExpectedCommand*") {
            throw "$Label is already running (PID $trackedPid). Run STOP.cmd first."
        }
        Write-Warning "$Label PID file is stale or points to another process; removing it."
    }
    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
}

function Assert-PortFree {
    param([int]$Port, [string]$Label)
    $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -eq 0) { return }
    $owners = @($listeners | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($process) { "$($process.ProcessName) (PID $($_.OwningProcess))" } else { "PID $($_.OwningProcess)" }
    } | Select-Object -Unique)
    throw "$Label port $Port is already in use by $($owners -join ', '). Stop that service before starting D:\notion."
}

function Wait-ForGateway {
    param([System.Diagnostics.Process]$Process)
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($Process.HasExited) {
            throw "Gateway exited during startup. See gateway\logs\server.err.log."
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$mcpPort/healthz" -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                $health = $response.Content | ConvertFrom-Json
                if ($health.auth -ne "oauth2.1") {
                    throw "Port $mcpPort is serving a non-OAuth gateway."
                }
                return
            }
        } catch {
            Start-Sleep -Milliseconds 400
        }
    }
    throw "Gateway did not become ready on port $mcpPort."
}

function Wait-ForQuickTunnelUrl {
    param([System.Diagnostics.Process]$Process)
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        if ($Process.HasExited) {
            throw "Cloudflare Tunnel stopped during startup. See gateway\logs\tunnel.err.log."
        }
        $text = ""
        if (Test-Path -LiteralPath $tunnelOut) { $text += Get-Content -LiteralPath $tunnelOut -Raw }
        if (Test-Path -LiteralPath $tunnelErr) { $text += Get-Content -LiteralPath $tunnelErr -Raw }
        if ($text -match "https://[a-z0-9-]+\.trycloudflare\.com") { return "$($Matches[0])/mcp" }
        Start-Sleep -Milliseconds 500
    }
    throw "Cloudflare Quick Tunnel did not provide a public URL in time."
}

function Wait-ForPublicHealth {
    param([string]$PublicUrl, [bool]$Required)
    $healthUrl = ($PublicUrl -replace "/mcp/?$", "") + "/healthz"
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $healthUrl -TimeoutSec 4
            if ($response.StatusCode -eq 200) {
                $health = $response.Content | ConvertFrom-Json
                if ($health.auth -eq "oauth2.1") { return }
            }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    if ($Required) { throw "Cloudflare Tunnel did not pass its public health check: $healthUrl" }
    Write-Warning "Quick Tunnel started, but its public health check is still warming up."
}

function Stop-ProcessTree {
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    & taskkill.exe /PID $Process.Id /T /F *> $null
    if ($LASTEXITCODE -ne 0) { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue }
}

function Protect-ConfigDirectory {
    param([string]$Path)
    try {
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls.exe $Path /inheritance:r /grant:r `
            "*$($currentSid):(OI)(CI)F" `
            "*S-1-5-18:(OI)(CI)F" `
            "*S-1-5-32-544:(OI)(CI)F" *> $null
        if ($LASTEXITCODE -ne 0) { throw "icacls grant failed with exit code $LASTEXITCODE" }
        & icacls.exe $Path /remove:g "*S-1-5-11" "*S-1-5-32-545" *> $null
        if ($LASTEXITCODE -ne 0) { throw "icacls cleanup failed with exit code $LASTEXITCODE" }
    } catch {
        Write-Warning "Could not restrict OAuth configuration ACL: $($_.Exception.Message)"
    }
}

function Read-TunnelSettings {
    $defaults = [ordered]@{ mode = "quick"; hostname = ""; tunnel_name = "notion-local-gateway"; config_file = $defaultNamedConfig }
    if (-not (Test-Path -LiteralPath $tunnelSettingsFile)) { return [pscustomobject]$defaults }
    try {
        $loaded = Get-Content -LiteralPath $tunnelSettingsFile -Raw | ConvertFrom-Json
        foreach ($key in @("mode", "hostname", "tunnel_name", "config_file")) {
            if ($null -ne $loaded.$key -and "$($loaded.$key)" -ne "") { $defaults[$key] = "$($loaded.$key)" }
        }
    } catch {
        Write-Warning "Could not read tunnel-settings.json; using Quick Tunnel fallback."
    }
    return [pscustomobject]$defaults
}

$lifecycleMutex = New-Object System.Threading.Mutex($false, "Global\LocalFileMcpGatewayLifecycle")
$hasLifecycleMutex = $false
try {
try { $hasLifecycleMutex = $lifecycleMutex.WaitOne(120000) } catch [System.Threading.AbandonedMutexException] { $hasLifecycleMutex = $true }
if (-not $hasLifecycleMutex) { throw "Timed out waiting for another gateway start/stop operation to finish." }

foreach ($required in @($python, $gateway, $cloudflaredExe)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing required file: $required" }
}
New-Item -ItemType Directory -Force -Path $configDir, $logDir | Out-Null
Protect-ConfigDirectory -Path $configDir
if ($Recovery) {
    $desiredState = if (Test-Path -LiteralPath $desiredStateFile) { (Get-Content -LiteralPath $desiredStateFile -Raw).Trim().ToLowerInvariant() } else { "" }
    if ($desiredState -ne "running") {
        Write-Host "Recovery start cancelled because manual stop is active."
        return
    }
} else {
    "running" | Set-Content -LiteralPath $desiredStateFile -Encoding ascii
}
Assert-NotRunning -PidFile $serverPidFile -Label "Local file MCP gateway" -ExpectedCommand "gateway-v21.py" -ExpectedExecutable $python
Assert-NotRunning -PidFile $tunnelPidFile -Label "Cloudflare Tunnel" -ExpectedCommand "cloudflared" -ExpectedExecutable $cloudflaredExe
Assert-PortFree -Port $mcpPort -Label "MCP"
Assert-PortFree -Port $consolePort -Label "Console"

foreach ($file in @($serverOut, $serverErr, $tunnelOut, $tunnelErr, $urlFile, $connectionDetailsFile)) {
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
}

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$server = $null
$tunnel = $null

try {
    $server = Start-Process `
        -FilePath $python `
        -ArgumentList @($gateway, "--mcp-port", $mcpPort, "--console-port", $consolePort) `
        -WorkingDirectory (Join-Path $root "gateway") `
        -RedirectStandardOutput $serverOut `
        -RedirectStandardError $serverErr `
        -WindowStyle Hidden `
        -PassThru
    $server.Id | Set-Content -LiteralPath $serverPidFile -Encoding ascii
    Wait-ForGateway -Process $server
    $tunnelSettings = Read-TunnelSettings
    $tunnelMode = "$($tunnelSettings.mode)".ToLowerInvariant()
    if ($tunnelMode -eq "named") {
        $hostname = "$($tunnelSettings.hostname)".Trim().ToLowerInvariant()
        $tunnelName = "$($tunnelSettings.tunnel_name)".Trim()
        $namedConfig = "$($tunnelSettings.config_file)".Trim()
        if ($hostname -notmatch "^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$" -or $hostname -notmatch "\.") {
            throw "Invalid hostname in tunnel-settings.json: $hostname"
        }
        if (-not (Test-Path -LiteralPath $namedConfig -PathType Leaf)) {
            throw "Named tunnel config is missing: $namedConfig. Run SETUP-STABLE-TUNNEL.cmd once."
        }
        $tunnel = Start-Process `
            -FilePath $cloudflaredExe `
            -ArgumentList @("tunnel", "--no-autoupdate", "--config", $namedConfig, "run", $tunnelName) `
            -RedirectStandardOutput $tunnelOut `
            -RedirectStandardError $tunnelErr `
            -WindowStyle Hidden `
            -PassThru
        Start-Sleep -Seconds 2
        if ($tunnel.HasExited) { throw "Named Cloudflare Tunnel failed. See gateway\logs\tunnel.err.log." }
        $publicUrl = "https://$hostname/mcp"
        $stableUrl = $true
        $publicUrl | Set-Content -LiteralPath $urlFile -Encoding ascii
        Wait-ForPublicHealth -PublicUrl $publicUrl -Required $true
    } else {
        $tunnelMode = "quick"
        $tunnel = Start-Process `
            -FilePath $cloudflaredExe `
            -ArgumentList @("tunnel", "--no-autoupdate", "--protocol", "http2", "--url", "http://127.0.0.1:$mcpPort") `
            -RedirectStandardOutput $tunnelOut `
            -RedirectStandardError $tunnelErr `
            -WindowStyle Hidden `
            -PassThru
        $publicUrl = Wait-ForQuickTunnelUrl -Process $tunnel
        $stableUrl = $false
        $publicUrl | Set-Content -LiteralPath $urlFile -Encoding ascii
        Wait-ForPublicHealth -PublicUrl $publicUrl -Required ([bool]$Recovery)
    }

    $tunnel.Id | Set-Content -LiteralPath $tunnelPidFile -Encoding ascii
    $publicUrl | Set-Content -LiteralPath $urlFile -Encoding ascii
    $consoleUrl = "http://127.0.0.1:$consolePort/"
    @(
        "Local file MCP connection details",
        "",
        "MCP URL:",
        $publicUrl,
        "",
        "Authentication type:",
        "OAuth 2.1 (Authorization Code + PKCE)",
        "",
        "How to connect:",
        "Choose OAuth in Notion, Claude, ChatGPT, or another compatible MCP client.",
        "A one-time approval window will appear on this computer.",
        "No static MCP token is used.",
        "",
        "Tunnel mode:",
        $(if ($stableUrl) { "Named tunnel (fixed hostname; survives reconnects and restarts)" } else { "Quick Tunnel (available while this process runs; URL changes after stop/restart)" }),
        "",
        "Local console (this computer only):",
        $consoleUrl
    ) | Set-Content -LiteralPath $connectionDetailsFile -Encoding utf8
} catch {
    if ($null -ne $tunnel -and -not $tunnel.HasExited) { Stop-ProcessTree -Process $tunnel }
    if ($null -ne $server -and -not $server.HasExited) { Stop-ProcessTree -Process $server }
    Remove-Item -LiteralPath $serverPidFile, $tunnelPidFile, $urlFile, $connectionDetailsFile -Force -ErrorAction SilentlyContinue
    throw
}

$consoleUrl = "http://127.0.0.1:$consolePort/"
Write-Host ""
Write-Host "Local file MCP gateway v2.5.0 is running." -ForegroundColor Green
Write-Host ""
Write-Host "MCP URL (use in Notion, Claude, ChatGPT, or another MCP client):" -ForegroundColor Cyan
Write-Host $publicUrl
Write-Host ""
Write-Host "Authentication:" -ForegroundColor Cyan
Write-Host "OAuth 2.1 (Authorization Code + PKCE; no static MCP token)"
Write-Host "Approve the one-time OAuth prompt on this computer when the client connects."
Write-Host ""
if ($stableUrl) {
    Write-Host "Stable link: enabled. This hostname stays the same across reconnects and restarts." -ForegroundColor Green
} else {
    Write-Host "Quick Tunnel is active for the lifetime of this running gateway and tunnel process." -ForegroundColor Yellow
    Write-Host "For a restart-stable URL, run SETUP-STABLE-TUNNEL.cmd once to configure a named tunnel and domain." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Local control panel:" -ForegroundColor Cyan
Write-Host $consoleUrl
Write-Host ""
if (-not $NoBrowser) {
    Write-Host "Opening the control panel in your browser..." -ForegroundColor DarkGray
    Start-Process $consoleUrl
}
Write-Host "Keep this computer online. Use STOP.cmd to stop access."
} finally {
    if ($hasLifecycleMutex) { $lifecycleMutex.ReleaseMutex() }
    $lifecycleMutex.Dispose()
}

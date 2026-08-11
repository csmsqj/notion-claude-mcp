$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8

$root = "D:\notion"
$cloudflared = Join-Path $root "bin\cloudflared.exe"
$configDir = Join-Path $root "gateway\config"
$settingsFile = Join-Path $configDir "tunnel-settings.json"
$namedConfig = Join-Path $configDir "cloudflared.yml"

if (-not (Test-Path -LiteralPath $cloudflared -PathType Leaf)) {
    throw "Missing cloudflared.exe: $cloudflared"
}
New-Item -ItemType Directory -Force -Path $configDir | Out-Null

Write-Host ""
Write-Host "Stable Cloudflare Tunnel setup" -ForegroundColor Cyan
Write-Host "This one-time setup needs a Cloudflare account and a domain managed by Cloudflare."
Write-Host "The final MCP URL will remain unchanged across reconnects and app restarts."
Write-Host ""
$hostname = (Read-Host "Hostname to use (example: notion-mcp.example.com)").Trim().ToLowerInvariant()
if ($hostname -notmatch "^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$" -or $hostname -notmatch "\.") {
    throw "Invalid hostname: $hostname"
}
$tunnelName = (Read-Host "Tunnel name [notion-local-gateway]").Trim()
if (-not $tunnelName) { $tunnelName = "notion-local-gateway" }
if ($tunnelName -notmatch "^[A-Za-z0-9_-]+$") { throw "Tunnel name may contain only letters, numbers, underscore, and hyphen." }

Write-Host ""
Write-Host "Opening Cloudflare login in your browser..." -ForegroundColor DarkGray
& $cloudflared tunnel login
if ($LASTEXITCODE -ne 0) { throw "cloudflared tunnel login failed." }

$listJson = & $cloudflared tunnel list --output json 2>$null | Out-String
$tunnels = @()
if ($listJson.Trim()) { $tunnels = @(ConvertFrom-Json $listJson) }
$match = @($tunnels | Where-Object { $_.name -eq $tunnelName }) | Select-Object -First 1
if ($null -eq $match) {
    Write-Host "Creating named tunnel '$tunnelName'..." -ForegroundColor DarkGray
    & $cloudflared tunnel create $tunnelName
    if ($LASTEXITCODE -ne 0) { throw "Could not create the named tunnel." }
    $listJson = & $cloudflared tunnel list --output json 2>$null | Out-String
    $tunnels = @(ConvertFrom-Json $listJson)
    $match = @($tunnels | Where-Object { $_.name -eq $tunnelName }) | Select-Object -First 1
}
if ($null -eq $match -or -not $match.id) { throw "Could not determine the tunnel ID." }
$tunnelId = "$($match.id)"
$credentialsFile = Join-Path $env:USERPROFILE ".cloudflared\$tunnelId.json"
if (-not (Test-Path -LiteralPath $credentialsFile -PathType Leaf)) {
    throw "Tunnel credentials were not found at $credentialsFile"
}

Write-Host "Routing $hostname to tunnel $tunnelName..." -ForegroundColor DarkGray
& $cloudflared tunnel route dns $tunnelName $hostname
if ($LASTEXITCODE -ne 0) { throw "Could not create the Cloudflare DNS route." }

$yamlCredential = $credentialsFile.Replace("'", "''")
$yaml = @(
    "tunnel: $tunnelId",
    "credentials-file: '$yamlCredential'",
    "ingress:",
    "  - hostname: $hostname",
    "    service: http://127.0.0.1:8875",
    "  - service: http_status:404",
    ""
) -join "`r`n"
[System.IO.File]::WriteAllText($namedConfig, $yaml, (New-Object System.Text.UTF8Encoding $false))

$settings = [ordered]@{
    mode = "named"
    hostname = $hostname
    tunnel_name = $tunnelName
    tunnel_id = $tunnelId
    config_file = $namedConfig
}
$settingsJson = $settings | ConvertTo-Json
[System.IO.File]::WriteAllText($settingsFile, $settingsJson + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding $false))

Write-Host ""
Write-Host "Stable tunnel configured successfully." -ForegroundColor Green
Write-Host "MCP URL: https://$hostname/mcp" -ForegroundColor Cyan
Write-Host ""
Write-Host "If the gateway is currently running, use STOP.cmd and then START.cmd once."
Write-Host "After that, choose OAuth when adding the connection in Notion, Claude, ChatGPT, or another MCP client."

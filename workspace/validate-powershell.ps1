$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$files = @(
    (Join-Path $root "start-notion-mcp-v21.ps1"),
    (Join-Path $root "start-notion-mcp.ps1"),
    (Join-Path $root "setup-stable-tunnel.ps1"),
    (Join-Path $root "stop-notion-mcp.ps1"),
    (Join-Path $root "status-notion-mcp.ps1"),
    (Join-Path $root "watchdog-notion-mcp.ps1"),
    (Join-Path $root "install-notion-mcp-watchdog.ps1"),
    (Join-Path $root "open-control-panel.ps1"),
    (Join-Path $root "runtime-patches\oauth-consent.ps1")
)
$failed = $false
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        $failed = $true
        Write-Host "Parse errors in $file" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host $_.Message }
    } else {
        Write-Host "OK $file"
    }
}
if ($failed) { exit 1 }

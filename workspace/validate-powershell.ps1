$ErrorActionPreference = "Stop"
$files = @(
    "D:\notion\start-notion-mcp-v21.ps1",
    "D:\notion\start-notion-mcp.ps1",
    "D:\notion\setup-stable-tunnel.ps1",
    "D:\notion\stop-notion-mcp.ps1",
    "D:\notion\status-notion-mcp.ps1",
    "D:\notion\watchdog-notion-mcp.ps1",
    "D:\notion\install-notion-mcp-watchdog.ps1",
    "D:\notion\open-control-panel.ps1",
    "D:\notion\runtime-patches\oauth-consent.ps1"
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

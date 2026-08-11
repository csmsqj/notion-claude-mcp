$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8

# Compatibility entry point. The old script used a static Bearer token; all
# starts now use the OAuth 2.1 + PKCE launcher.
$oauthLauncher = Join-Path $PSScriptRoot "start-notion-mcp-v21.ps1"
if (-not (Test-Path -LiteralPath $oauthLauncher -PathType Leaf)) {
    throw "OAuth launcher is missing: $oauthLauncher"
}
& $oauthLauncher @args
exit $LASTEXITCODE

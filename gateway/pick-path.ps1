# Native Windows folder / file picker used by the local console.
#
# The result is written to -OutFile as UTF-8 JSON instead of stdout: PowerShell 5.1
# encodes stdout with the console code page (936 here), which corrupts non-ASCII
# paths. A file with an explicit encoding is the only reliable channel.
# ASCII-only source on purpose - a UTF-8 .ps1 is misparsed under a non-UTF8 code page.
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [string]$Mode = "folder",
    [string]$Initial = "",
    [string]$SelfTest = ""
)

$ErrorActionPreference = "Stop"

function Write-Result {
    param([hashtable]$Data)
    $json = $Data | ConvertTo-Json -Compress
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($OutFile, $json, $utf8NoBom)
}

if ($SelfTest -ne "") {
    Write-Result @{ ok = $true; path = $SelfTest; mode = $Mode; self_test = $true }
    exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# A 1px transparent owner form so the dialog shows up in front of the browser.
$owner = New-Object System.Windows.Forms.Form
$owner.Size = New-Object System.Drawing.Size(1, 1)
$owner.StartPosition = "CenterScreen"
$owner.ShowInTaskbar = $false
$owner.Opacity = 0
$owner.TopMost = $true
$owner.Show()
$owner.Activate()

try {
    if ($Mode -eq "file") {
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = "Select a file for the MCP client to access"
        $dialog.Multiselect = $false
        $dialog.CheckFileExists = $true
        if ($Initial -ne "" -and (Test-Path -LiteralPath $Initial)) { $dialog.InitialDirectory = $Initial }
        if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
            Write-Result @{ ok = $true; path = $dialog.FileName; mode = "file" }
        } else {
            Write-Result @{ ok = $false; cancelled = $true }
        }
    } else {
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "Select a folder for the MCP client to access"
        $dialog.ShowNewFolderButton = $true
        if ($Initial -ne "" -and (Test-Path -LiteralPath $Initial)) { $dialog.SelectedPath = $Initial }
        if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
            Write-Result @{ ok = $true; path = $dialog.SelectedPath; mode = "folder" }
        } else {
            Write-Result @{ ok = $false; cancelled = $true }
        }
    }
} finally {
    $owner.Close()
    $owner.Dispose()
}

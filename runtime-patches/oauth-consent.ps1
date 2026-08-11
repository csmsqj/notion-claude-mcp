# Native OAuth consent dialog for the local file MCP gateway.
# ASCII-only source for Windows PowerShell 5.1 compatibility.
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [string]$ClientName = "OAuth client",
    [string]$RedirectUri = "",
    [string]$RequestId = "",
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

function Write-Decision {
    param([string]$Decision)
    $json = @{ decision = $Decision; request_id = $RequestId } | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding $false))
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = "Local file MCP gateway - OAuth authorization"
$form.Size = New-Object System.Drawing.Size(620, 360)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.BackColor = [System.Drawing.Color]::White
$form.ForeColor = [System.Drawing.Color]::FromArgb(44, 44, 43)
$form.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 9.5)

$title = New-Object System.Windows.Forms.Label
$title.Text = "Allow this OAuth connection?"
$title.Location = New-Object System.Drawing.Point(24, 22)
$title.Size = New-Object System.Drawing.Size(550, 30)
$title.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 14, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($title)

$intro = New-Object System.Windows.Forms.Label
$intro.Text = "A client is asking to connect to the local file MCP gateway. Only approve a connection you just started."
$intro.Location = New-Object System.Drawing.Point(24, 58)
$intro.Size = New-Object System.Drawing.Size(550, 44)
$intro.ForeColor = [System.Drawing.Color]::FromArgb(110, 107, 102)
$form.Controls.Add($intro)

$clientLabel = New-Object System.Windows.Forms.Label
$clientLabel.Text = "Client"
$clientLabel.Location = New-Object System.Drawing.Point(24, 108)
$clientLabel.Size = New-Object System.Drawing.Size(100, 20)
$clientLabel.ForeColor = [System.Drawing.Color]::FromArgb(110, 107, 102)
$form.Controls.Add($clientLabel)

$clientBox = New-Object System.Windows.Forms.TextBox
$clientBox.Text = $ClientName
$clientBox.Location = New-Object System.Drawing.Point(24, 130)
$clientBox.Size = New-Object System.Drawing.Size(550, 26)
$clientBox.ReadOnly = $true
$clientBox.BackColor = [System.Drawing.Color]::FromArgb(249, 248, 247)
$clientBox.BorderStyle = "FixedSingle"
$form.Controls.Add($clientBox)

$redirectLabel = New-Object System.Windows.Forms.Label
$redirectLabel.Text = "Redirect URI"
$redirectLabel.Location = New-Object System.Drawing.Point(24, 166)
$redirectLabel.Size = New-Object System.Drawing.Size(120, 20)
$redirectLabel.ForeColor = [System.Drawing.Color]::FromArgb(110, 107, 102)
$form.Controls.Add($redirectLabel)

$redirectBox = New-Object System.Windows.Forms.TextBox
$redirectBox.Text = $RedirectUri
$redirectBox.Location = New-Object System.Drawing.Point(24, 188)
$redirectBox.Size = New-Object System.Drawing.Size(550, 26)
$redirectBox.ReadOnly = $true
$redirectBox.BackColor = [System.Drawing.Color]::FromArgb(249, 248, 247)
$redirectBox.BorderStyle = "FixedSingle"
$redirectBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$form.Controls.Add($redirectBox)

$countdown = New-Object System.Windows.Forms.Label
$countdown.Location = New-Object System.Drawing.Point(24, 228)
$countdown.Size = New-Object System.Drawing.Size(300, 28)
$countdown.ForeColor = [System.Drawing.Color]::FromArgb(125, 122, 117)
$form.Controls.Add($countdown)

$deny = New-Object System.Windows.Forms.Button
$deny.Text = "Deny"
$deny.Location = New-Object System.Drawing.Point(334, 264)
$deny.Size = New-Object System.Drawing.Size(110, 38)
$deny.BackColor = [System.Drawing.Color]::FromArgb(240, 239, 237)
$deny.ForeColor = [System.Drawing.Color]::FromArgb(44, 44, 43)
$deny.FlatStyle = "Flat"
$deny.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(220, 218, 215)
$deny.DialogResult = [System.Windows.Forms.DialogResult]::No
$form.Controls.Add($deny)

$approve = New-Object System.Windows.Forms.Button
$approve.Text = "Allow connection"
$approve.Location = New-Object System.Drawing.Point(456, 264)
$approve.Size = New-Object System.Drawing.Size(118, 38)
$approve.BackColor = [System.Drawing.Color]::FromArgb(39, 131, 222)
$approve.ForeColor = [System.Drawing.Color]::White
$approve.FlatStyle = "Flat"
$approve.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(39, 131, 222)
$approve.DialogResult = [System.Windows.Forms.DialogResult]::Yes
$form.Controls.Add($approve)

$form.CancelButton = $deny
$form.AcceptButton = $deny
$script:remaining = [Math]::Max(10, $TimeoutSeconds)
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    $script:remaining -= 1
    $countdown.Text = "Auto-deny in " + $script:remaining + " seconds"
    if ($script:remaining -le 0) {
        $timer.Stop()
        $form.Tag = "timeout"
        $form.Close()
    }
})
$countdown.Text = "Auto-deny in " + $script:remaining + " seconds"
$timer.Start()
$form.Add_Shown({ $form.Activate(); $deny.Focus() })
[System.Media.SystemSounds]::Asterisk.Play()
$result = $form.ShowDialog()
$timer.Stop()

if ($form.Tag -eq "timeout") {
    Write-Decision "timeout"
} elseif ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
    Write-Decision "approve"
} else {
    Write-Decision "deny"
}
$form.Dispose()

# Native approval dialog for the local file MCP gateway.
# ASCII-only source for Windows PowerShell 5.1 code-page compatibility.
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [string]$Operation = "",
    [string]$Path = "",
    [string]$Risk = "",
    [string]$Reason = "",
    [string]$Preview = "",
    [string]$ApprovalId = "",
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

function Write-Decision {
    param([string]$Decision)
    $json = @{ decision = $Decision; approval_id = $ApprovalId } | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding $false))
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = "MCP controlled operation - explicit approval required"
$form.Size = New-Object System.Drawing.Size(640, 410)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(27, 32, 41)
$form.ForeColor = [System.Drawing.Color]::FromArgb(230, 233, 239)
$form.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 9.5)

function New-Label {
    param([string]$Text, [int]$Top, [int]$Height, [bool]$Bold = $false, [System.Drawing.Color]$Color)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point(20, $Top)
    $label.Size = New-Object System.Drawing.Size(590, $Height)
    $label.ForeColor = $Color
    if ($Bold) { $label.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 11, [System.Drawing.FontStyle]::Bold) }
    $form.Controls.Add($label)
    return $label
}

$accent = [System.Drawing.Color]::FromArgb(248, 81, 73)
$dim = [System.Drawing.Color]::FromArgb(154, 164, 178)
$fg = [System.Drawing.Color]::FromArgb(230, 233, 239)

New-Label -Text $Operation -Top 16 -Height 26 -Bold $true -Color $accent | Out-Null
New-Label -Text $Risk -Top 44 -Height 20 -Color $dim | Out-Null

$pathBox = New-Object System.Windows.Forms.TextBox
$pathBox.Text = $Path
$pathBox.Location = New-Object System.Drawing.Point(20, 70)
$pathBox.Size = New-Object System.Drawing.Size(590, 24)
$pathBox.ReadOnly = $true
$pathBox.BackColor = [System.Drawing.Color]::FromArgb(15, 17, 21)
$pathBox.ForeColor = $fg
$pathBox.BorderStyle = "FixedSingle"
$pathBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$form.Controls.Add($pathBox)

$reasonBox = New-Object System.Windows.Forms.TextBox
$reasonBox.Text = $Reason
$reasonBox.Location = New-Object System.Drawing.Point(20, 104)
$reasonBox.Size = New-Object System.Drawing.Size(590, 54)
$reasonBox.ReadOnly = $true
$reasonBox.Multiline = $true
$reasonBox.BorderStyle = "None"
$reasonBox.BackColor = [System.Drawing.Color]::FromArgb(27, 32, 41)
$reasonBox.ForeColor = $dim
$form.Controls.Add($reasonBox)

if ($Preview -ne "") {
    $previewBox = New-Object System.Windows.Forms.TextBox
    $previewBox.Text = $Preview
    $previewBox.Location = New-Object System.Drawing.Point(20, 164)
    $previewBox.Size = New-Object System.Drawing.Size(590, 92)
    $previewBox.ReadOnly = $true
    $previewBox.Multiline = $true
    $previewBox.ScrollBars = "Vertical"
    $previewBox.BackColor = [System.Drawing.Color]::FromArgb(15, 17, 21)
    $previewBox.ForeColor = $fg
    $previewBox.BorderStyle = "FixedSingle"
    $previewBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $form.Controls.Add($previewBox)
}

$countdown = New-Label -Text "" -Top 268 -Height 34 -Color $dim

$approve = New-Object System.Windows.Forms.Button
$approve.Text = "Approve once"
$approve.Location = New-Object System.Drawing.Point(330, 310)
$approve.Size = New-Object System.Drawing.Size(130, 38)
$approve.BackColor = [System.Drawing.Color]::FromArgb(63, 185, 80)
$approve.ForeColor = [System.Drawing.Color]::FromArgb(6, 33, 12)
$approve.FlatStyle = "Flat"
$approve.DialogResult = [System.Windows.Forms.DialogResult]::Yes
$form.Controls.Add($approve)

$deny = New-Object System.Windows.Forms.Button
$deny.Text = "Deny"
$deny.Location = New-Object System.Drawing.Point(478, 310)
$deny.Size = New-Object System.Drawing.Size(130, 38)
$deny.BackColor = [System.Drawing.Color]::FromArgb(38, 45, 56)
$deny.ForeColor = $accent
$deny.FlatStyle = "Flat"
$deny.DialogResult = [System.Windows.Forms.DialogResult]::No
$form.Controls.Add($deny)

# Escape and window close are explicit denial. The focused default is Deny.
$form.CancelButton = $deny
$form.AcceptButton = $approve

$script:remaining = [Math]::Max(10, $TimeoutSeconds)
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    $script:remaining -= 1
    $countdown.Text = "No action for " + $script:remaining + "s: this attempt will be denied; nothing will run."
    if ($script:remaining -le 0) {
        $timer.Stop()
        $form.Tag = "timeout"
        $form.Close()
    }
})
$countdown.Text = "No action for " + $script:remaining + "s: this attempt will be denied; nothing will run."
$timer.Start()

$form.Add_Shown({ $form.Activate(); $deny.Focus() })
[System.Media.SystemSounds]::Exclamation.Play()
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

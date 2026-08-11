# Native approval dialog shown on the local desktop for a gated operation.
#
# The decision is written to -OutFile as UTF-8 JSON (stdout would be mangled by the
# console code page). Arguments arrive as UTF-16 through argv, so Chinese text is safe.
# ASCII-only source on purpose - a UTF-8 .ps1 is misparsed under a non-UTF8 code page.
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [string]$Operation = "",
    [string]$Path = "",
    [string]$Risk = "",
    [string]$Reason = "",
    [string]$Preview = "",
    [string]$ApprovalId = "",
    [int]$TimeoutSeconds = 60
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
$form.Text = "An MCP client is requesting a controlled operation"
$form.Size = New-Object System.Drawing.Size(640, 400)
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
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Location = New-Object System.Drawing.Point(20, $Top)
    $l.Size = New-Object System.Drawing.Size(590, $Height)
    $l.ForeColor = $Color
    if ($Bold) { $l.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 11, [System.Drawing.FontStyle]::Bold) }
    $form.Controls.Add($l)
    return $l
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
    $prev = New-Object System.Windows.Forms.TextBox
    $prev.Text = $Preview
    $prev.Location = New-Object System.Drawing.Point(20, 164)
    $prev.Size = New-Object System.Drawing.Size(590, 92)
    $prev.ReadOnly = $true
    $prev.Multiline = $true
    $prev.ScrollBars = "Vertical"
    $prev.BackColor = [System.Drawing.Color]::FromArgb(15, 17, 21)
    $prev.ForeColor = $fg
    $prev.BorderStyle = "FixedSingle"
    $prev.Font = New-Object System.Drawing.Font("Consolas", 9)
    $form.Controls.Add($prev)
}

$countdown = New-Label -Text "" -Top 268 -Height 20 -Color $dim

$approve = New-Object System.Windows.Forms.Button
$approve.Text = "Approve"
$approve.Location = New-Object System.Drawing.Point(330, 300)
$approve.Size = New-Object System.Drawing.Size(130, 38)
$approve.BackColor = [System.Drawing.Color]::FromArgb(63, 185, 80)
$approve.ForeColor = [System.Drawing.Color]::FromArgb(6, 33, 12)
$approve.FlatStyle = "Flat"
$approve.DialogResult = [System.Windows.Forms.DialogResult]::Yes
$form.Controls.Add($approve)

$deny = New-Object System.Windows.Forms.Button
$deny.Text = "Deny"
$deny.Location = New-Object System.Drawing.Point(478, 300)
$deny.Size = New-Object System.Drawing.Size(130, 38)
$deny.BackColor = [System.Drawing.Color]::FromArgb(38, 45, 56)
$deny.ForeColor = $accent
$deny.FlatStyle = "Flat"
$deny.DialogResult = [System.Windows.Forms.DialogResult]::No
$form.Controls.Add($deny)

# Deny is the safe default for Escape / window close.
$form.CancelButton = $deny
$form.AcceptButton = $approve

$script:remaining = $TimeoutSeconds
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    $script:remaining -= 1
    $countdown.Text = "No action for " + $script:remaining + "s leaves this pending (nothing will run)."
    if ($script:remaining -le 0) {
        $timer.Stop()
        $form.Tag = "timeout"
        $form.Close()
    }
})
$countdown.Text = "No action for " + $script:remaining + "s leaves this pending (nothing will run)."
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

@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$file = '%~dp0gateway\config\notion-connection-details.txt'; if (Test-Path -LiteralPath $file) { Start-Process notepad.exe -ArgumentList $file } else { Write-Host 'The local gateway is not running. Double-click START.cmd first.'; Read-Host 'Press Enter to close' }"

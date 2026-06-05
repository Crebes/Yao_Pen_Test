#Requires -Version 5.1
<#
.SYNOPSIS
    Starts the Yao Pentest live dashboard in your browser.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WslBase   = "/mnt/" + ($ScriptDir -replace "\\","/" -replace ":","").ToLower()
$Port      = 8888

Write-Host "`n  Starting Yao Pentest Dashboard on port $Port..." -ForegroundColor Cyan

# Start dashboard server inside WSL (background)
$job = Start-Job -ScriptBlock {
    param($wslBase, $port)
    wsl -d Ubuntu-24.04 -u root -- python3 "$wslBase/dashboard.py" $port
} -ArgumentList $WslBase, $Port

Start-Sleep -Seconds 2

# Open browser
Start-Process "http://localhost:$Port"
Write-Host "  Dashboard open at http://localhost:$Port" -ForegroundColor Green
Write-Host "  Close this window or press Ctrl+C to stop the dashboard.`n" -ForegroundColor Yellow

# Keep alive until user quits
try {
    while ($true) {
        Start-Sleep -Seconds 5
        if ($job.State -ne "Running") {
            Write-Host "  Dashboard server stopped unexpectedly." -ForegroundColor Red
            break
        }
    }
} finally {
    Stop-Job $job; Remove-Job $job -Force 2>$null
    Write-Host "  Dashboard stopped." -ForegroundColor Yellow
}

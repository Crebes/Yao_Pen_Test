#Requires -Version 5.1
<#
.SYNOPSIS
    Set up Windows Task Scheduler to run the Yao pentest weekly.
.DESCRIPTION
    Creates a scheduled task that runs every Monday at 02:00 AM.
    Uses WSL to run weekly-scan.sh which updates tools, refreshes
    password lists, runs the full batch scan, and emails the report.
.PARAMETER DayOfWeek
    Day to run (default: Monday)
.PARAMETER Time
    Time to run in HH:MM format (default: 02:00)
.PARAMETER Remove
    Remove the scheduled task instead of creating it
.EXAMPLE
    .\schedule.ps1                         # Run every Monday at 02:00
    .\schedule.ps1 -DayOfWeek Friday -Time "03:00"
    .\schedule.ps1 -Remove
#>

param(
    [ValidateSet("Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday")]
    [string]$DayOfWeek = "Monday",
    [string]$Time      = "02:00",
    [switch]$Remove
)

$TaskName  = "YaoPentestWeeklyScan"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WslBase   = "/mnt/" + ($ScriptDir -replace "\\","/" -replace ":","").ToLower()

function Write-Ok  { param($m) Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Info{ param($m) Write-Host "  [..] $m" -ForegroundColor Cyan }
function Write-Warn{ param($m) Write-Host "  [!!] $m" -ForegroundColor Yellow }

Write-Host "`n  Yao Pentest — Task Scheduler`n" -ForegroundColor Cyan

if ($Remove) {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Ok "Task '$TaskName' removed."
    } catch {
        Write-Warn "Task not found or could not be removed: $_"
    }
    exit 0
}

# Check email config exists
$emailConfig = Join-Path $ScriptDir "email-config.json"
if (-not (Test-Path $emailConfig)) {
    Write-Warn "email-config.json not found."
    Write-Host "  Copy email-config.example.json → email-config.json and fill in your SMTP details." -ForegroundColor Yellow
    $cont = Read-Host "  Continue anyway? (y/N)"
    if ($cont -ne "y") { exit 1 }
}

# Build the WSL command
$wslScript = "$WslBase/weekly-scan.sh"
$wslCmd    = "wsl.exe -d Ubuntu-24.04 -u root -- bash `"$wslScript`""

# Create task action — runs WSL with the weekly scan script
$action  = New-ScheduledTaskAction `
    -Execute "wsl.exe" `
    -Argument "-d Ubuntu-24.04 -u root -- bash `"$wslScript`""

# Weekly trigger
$trigger = New-ScheduledTaskTrigger `
    -Weekly `
    -DaysOfWeek $DayOfWeek `
    -At $Time

# Settings — run whether or not user is logged in, wake if sleeping
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 6) `
    -RunOnlyIfNetworkAvailable `
    -WakeToRun `
    -StartWhenAvailable

# Principal — run as SYSTEM so it works when no user is logged in
$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# Register
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask `
        -TaskName  $TaskName `
        -Action    $action `
        -Trigger   $trigger `
        -Settings  $settings `
        -Principal $principal `
        -Description "Weekly Yao security scan — updates tools, scans all targets, emails report"
    Write-Ok "Task '$TaskName' created."
    Write-Ok "Runs every $DayOfWeek at $Time"
    Write-Ok "Script: $wslScript"
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    Write-Host "  Try running this script as Administrator." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "  To run immediately:  Start-ScheduledTask -TaskName $TaskName" -ForegroundColor Cyan
Write-Host "  To remove:           .\schedule.ps1 -Remove" -ForegroundColor Cyan
Write-Host "  To change schedule:  .\schedule.ps1 -DayOfWeek Friday -Time 03:00" -ForegroundColor Cyan
Write-Host ""

# Offer to run now for a test
$run = Read-Host "  Run the scan now to test? (y/N)"
if ($run -eq "y") {
    Write-Info "Launching test run..."
    Start-ScheduledTask -TaskName $TaskName
    Write-Ok "Task started. Check the dashboard at http://localhost:8888 for progress."
}

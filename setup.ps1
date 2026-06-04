#Requires -Version 5.1
<#
.SYNOPSIS
    Yao Pentest Wizard — one-shot Windows installer
.DESCRIPTION
    Installs WSL2 + Ubuntu 24.04, then installs all pentest tools inside Ubuntu.
    Run once from an Administrator PowerShell terminal.
.EXAMPLE
    .\setup.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colours ───────────────────────────────────────────────
function Write-Ok   { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "  [..] $msg" -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "  [XX] $msg" -ForegroundColor Red }
function Write-Head { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

Write-Host @"

  ╔═══════════════════════════════════════════════════╗
  ║     Yao Pentest Wizard — Windows Setup            ║
  ║     Installs WSL2 + Ubuntu + all tools            ║
  ╚═══════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# ── Step 1: Admin check ────────────────────────────────────
Write-Head "Step 1/5 — Checking privileges"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail "This script must be run as Administrator."
    Write-Host "  Right-click PowerShell → 'Run as administrator', then try again." -ForegroundColor Yellow
    exit 1
}
Write-Ok "Running as Administrator"

# ── Step 2: WSL ────────────────────────────────────────────
Write-Head "Step 2/5 — Windows Subsystem for Linux"

$wslExe = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wslExe) {
    Write-Info "WSL not found — installing via winget..."
    winget install --id Microsoft.WSL --accept-source-agreements --accept-package-agreements --silent
    Write-Warn "WSL installed. A restart may be required."
    Write-Warn "If the script fails after this point, restart your PC and re-run setup.ps1"
} else {
    Write-Ok "WSL is available"
}

# Check if Ubuntu-24.04 is installed
$distros = wsl --list --quiet 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
$ubuntuInstalled = $distros | Where-Object { $_ -match "Ubuntu-24.04" }

if (-not $ubuntuInstalled) {
    Write-Info "Installing Ubuntu 24.04 LTS..."
    wsl --install Ubuntu-24.04 --no-launch
    Write-Ok "Ubuntu 24.04 downloaded and installed"
} else {
    Write-Ok "Ubuntu 24.04 already installed"
}

# ── Step 3: WSL DNS fix ────────────────────────────────────
Write-Head "Step 3/5 — Fixing WSL DNS"
Write-Info "Setting nameservers to 8.8.8.8 / 1.1.1.1..."
wsl -d Ubuntu-24.04 -u root -- bash -c @'
  echo "nameserver 8.8.8.8" > /etc/resolv.conf
  echo "nameserver 1.1.1.1" >> /etc/resolv.conf
  # Prevent WSL from overwriting resolv.conf on restart
  if ! grep -q "generateResolvConf" /etc/wsl.conf 2>/dev/null; then
    echo -e "\n[network]\ngenerateResolvConf = false" >> /etc/wsl.conf
  fi
'@
$dnsTest = wsl -d Ubuntu-24.04 -u root -- nslookup google.com 2>&1
if ($dnsTest -match "Address") {
    Write-Ok "DNS resolution working"
} else {
    Write-Warn "DNS check inconclusive — continuing anyway"
}

# ── Step 4: Install tools inside Ubuntu ────────────────────
Write-Head "Step 4/5 — Installing pentest tools in Ubuntu"

# Copy setup-ubuntu.sh into WSL and run it
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$setupSh   = Join-Path $scriptDir "setup-ubuntu.sh"

if (-not (Test-Path $setupSh)) {
    Write-Fail "setup-ubuntu.sh not found in $scriptDir"
    exit 1
}

$wslPath = "/mnt/" + ($scriptDir -replace "\\", "/" -replace ":", "").ToLower()
Write-Info "Running setup-ubuntu.sh inside Ubuntu..."
wsl -d Ubuntu-24.04 -u root -- bash "$wslPath/setup-ubuntu.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Fail "setup-ubuntu.sh failed (exit $LASTEXITCODE)"
    exit 1
}

# ── Step 5: Smoke test ─────────────────────────────────────
Write-Head "Step 5/5 — Smoke test"
$tools = @("nmap", "nikto", "hydra", "ffuf", "testssl.sh", "jwt_tool")
$allOk = $true
foreach ($t in $tools) {
    $path = wsl -d Ubuntu-24.04 -u root -- which $t 2>$null
    if ($path) {
        Write-Ok "$t — $($path.Trim())"
    } else {
        Write-Fail "$t — NOT FOUND"
        $allOk = $false
    }
}

Write-Host ""
if ($allOk) {
    Write-Host "  ╔══════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  Setup complete — all tools ready            ║" -ForegroundColor Green
    Write-Host "  ║                                              ║" -ForegroundColor Green
    Write-Host "  ║  Run a scan:                                 ║" -ForegroundColor Green
    Write-Host "  ║    .\pentest.ps1 https://app.stg.yao.legal   ║" -ForegroundColor Green
    Write-Host "  ║      --staging --yes                         ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Green
} else {
    Write-Warn "Some tools are missing. Re-run setup.ps1 or check setup-ubuntu.sh."
    exit 1
}

# KHEPRA License Signer - PowerShell Wrapper
# Runs the ML-DSA-65 license signing daemon
#
# Usage:
#   .\run-license-signer.ps1
#   .\run-license-signer.ps1 -KeyPath "C:\path\to\key" -Token "your-jwt-token"

param(
    [string]$KeyPath = "",
    [string]$Token = "",
    [string]$TelemetryUrl = "https://telemetry.souhimbou.org",
    [int]$PollInterval = 30
)

Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║       KHEPRA Protocol - License Signing Daemon            ║
║              ML-DSA-65 Post-Quantum Signatures            ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Check for key path
if (-not $KeyPath) {
    # Try common locations
    $possiblePaths = @(
        ".\khepra_master.key",
        "$env:USERPROFILE\.khepra\master.key",
        "$env:USERPROFILE\khepra_master.key",
        "$env:USERPROFILE\OneDrive - SecRed Knowledge Inc\khepra_master.key"
    )

    foreach ($p in $possiblePaths) {
        if (Test-Path $p) {
            $KeyPath = $p
            break
        }
    }
}

if (-not $KeyPath -or -not (Test-Path $KeyPath)) {
    Write-Host "❌ Private key not found!" -ForegroundColor Red
    Write-Host "   Specify -KeyPath or place key in one of:" -ForegroundColor Yellow
    Write-Host "   - .\khepra_master.key"
    Write-Host "   - $env:USERPROFILE\.khepra\master.key"
    exit 1
}

Write-Host "✅ Private key: $KeyPath" -ForegroundColor Green

# Check for admin token
if (-not $Token) {
    $Token = $env:KHEPRA_ADMIN_TOKEN
}

if (-not $Token) {
    Write-Host ""
    Write-Host "❌ Admin token not provided!" -ForegroundColor Red
    Write-Host "   Get a token by running:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host '   curl -X POST https://telemetry.souhimbou.org/admin/login \' -ForegroundColor Gray
    Write-Host '     -H "Content-Type: application/json" \' -ForegroundColor Gray
    Write-Host '     -d "{\"username\":\"admin\",\"password\":\"your-password\"}"' -ForegroundColor Gray
    Write-Host ""
    Write-Host "   Then run:" -ForegroundColor Yellow
    Write-Host "   .\run-license-signer.ps1 -Token 'your-jwt-token'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   Or set the KHEPRA_ADMIN_TOKEN environment variable" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Admin token: $(($Token).Substring(0, 20))..." -ForegroundColor Green
Write-Host "📡 Telemetry URL: $TelemetryUrl" -ForegroundColor Cyan
Write-Host "⏱️  Poll interval: ${PollInterval}s" -ForegroundColor Cyan
Write-Host ""

# Set environment variables
$env:KHEPRA_PRIVATE_KEY_PATH = $KeyPath
$env:KHEPRA_TELEMETRY_URL = $TelemetryUrl
$env:KHEPRA_ADMIN_TOKEN = $Token
$env:KHEPRA_POLL_INTERVAL = $PollInterval

# Change to scripts directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Run the Go program
Write-Host "🚀 Starting license signer..." -ForegroundColor Green
Write-Host "   Press Ctrl+C to stop" -ForegroundColor Gray
Write-Host ""

try {
    go run license-signer.go
}
catch {
    Write-Host "❌ Failed to run license signer: $_" -ForegroundColor Red
    Write-Host "   Make sure Go is installed and in PATH" -ForegroundColor Yellow
}

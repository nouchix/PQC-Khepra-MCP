<#
.SYNOPSIS
    Giza Cyber Shield - Bug Bounty Workflow Script
.DESCRIPTION
    Quick commands for bug bounty hunting workflow
.PARAMETER Command
    recon      - Run full reconnaissance on target
    quick      - Quick scan of current directory
    attest     - Generate risk attestation
    crawl      - Web application crawling
    critical   - View critical findings
    full       - Full workflow (recon + attest + report)
.EXAMPLE
    .\bounty-hunt.ps1 recon C:\path\to\target
    .\bounty-hunt.ps1 quick
    .\bounty-hunt.ps1 crawl https://target.example.com
#>

param(
    [Parameter(Position=0)]
    [ValidateSet("recon", "quick", "attest", "crawl", "critical", "high", "full", "validate", "help")]
    [string]$Command = "help",

    [Parameter(Position=1)]
    [string]$Target = "."
)

$BinDir = "$PSScriptRoot\..\bin"
$Sonar = "$BinDir\sonar.exe"
$AdinKhepra = "$BinDir\adinkhepra.exe"

# Enable dev mode
$env:ADINKHEPRA_DEV = "1"

function Show-Help {
    Write-Host @"

    ╔═══════════════════════════════════════════════════════════╗
    ║         GIZA CYBER SHIELD - BUG BOUNTY ARSENAL            ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  COMMANDS:                                                ║
    ║    recon <dir>    Full reconnaissance scan (signed)       ║
    ║    quick          Quick scan of current directory         ║
    ║    attest <file>  Generate risk attestation               ║
    ║    crawl <url>    Web application crawling                ║
    ║    critical       View critical severity findings         ║
    ║    high           View high severity findings             ║
    ║    full <dir>     Full workflow (recon + attest)          ║
    ║    validate       Verify tool installation                ║
    ╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
}

function Invoke-Recon {
    param([string]$Dir)
    Write-Host "[*] Running full reconnaissance on: $Dir" -ForegroundColor Yellow
    & $Sonar -dir $Dir -verbose -sign -out recon.json
    Write-Host "[+] Output: recon.json" -ForegroundColor Green
}

function Invoke-QuickScan {
    Write-Host "[*] Running quick scan..." -ForegroundColor Yellow
    & $Sonar -dir . -quick -out quick_recon.json
    Write-Host "[+] Output: quick_recon.json" -ForegroundColor Green
}

function Invoke-Attest {
    param([string]$File)
    Write-Host "[*] Generating attestation for: $File" -ForegroundColor Yellow
    & $AdinKhepra attest $File
    Write-Host "[+] Output: $File.attestation.json" -ForegroundColor Green
}

function Invoke-Crawl {
    param([string]$Url)
    Write-Host "[*] Crawling: $Url" -ForegroundColor Yellow
    & $AdinKhepra arsenal crawler $Url
}

function Show-Critical {
    if (Test-Path "recon.json.attestation.json") {
        Get-Content "recon.json.attestation.json" | jq '.findings[] | select(.severity == "CRITICAL")'
    } else {
        Write-Host "[!] No attestation file found. Run 'full' or 'attest' first." -ForegroundColor Red
    }
}

function Show-High {
    if (Test-Path "recon.json.attestation.json") {
        Get-Content "recon.json.attestation.json" | jq '.findings[] | select(.severity == "HIGH")'
    } else {
        Write-Host "[!] No attestation file found. Run 'full' or 'attest' first." -ForegroundColor Red
    }
}

function Invoke-FullWorkflow {
    param([string]$Dir)
    Write-Host @"

    ╔═══════════════════════════════════════════════════════════╗
    ║              STARTING FULL BOUNTY WORKFLOW                ║
    ╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    Write-Host "[1/4] Reconnaissance..." -ForegroundColor Yellow
    & $Sonar -dir $Dir -verbose -sign -out recon.json

    Write-Host "[2/4] Generating attestation..." -ForegroundColor Yellow
    & $AdinKhepra attest recon.json

    Write-Host "[3/4] Audit ingestion..." -ForegroundColor Yellow
    & $AdinKhepra audit ingest recon.json

    Write-Host "[4/4] Complete!" -ForegroundColor Green
    Write-Host @"

    ╔═══════════════════════════════════════════════════════════╗
    ║                    OUTPUTS GENERATED                      ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  recon.json                - Raw scan data                ║
    ║  recon.json.attestation.json - Signed risk assessment     ║
    ║  recon.json.risk_report.json - Detailed findings          ║
    ║  recon.json.superset.csv     - Analytics export           ║
    ║  recon.json.affine.md        - Executive summary          ║
    ╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
}

function Invoke-Validate {
    Write-Host "[*] Validating tools..." -ForegroundColor Yellow
    & $AdinKhepra validate
    Write-Host ""
    & $Sonar --help | Select-Object -First 5
    Write-Host "[+] Tools validated!" -ForegroundColor Green
}

switch ($Command) {
    "recon"    { Invoke-Recon -Dir $Target }
    "quick"    { Invoke-QuickScan }
    "attest"   { Invoke-Attest -File $Target }
    "crawl"    { Invoke-Crawl -Url $Target }
    "critical" { Show-Critical }
    "high"     { Show-High }
    "full"     { Invoke-FullWorkflow -Dir $Target }
    "validate" { Invoke-Validate }
    "help"     { Show-Help }
    default    { Show-Help }
}

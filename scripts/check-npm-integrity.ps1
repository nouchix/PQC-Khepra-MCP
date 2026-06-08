# =============================================================================
# KHEPRA MCP Server — npm Postinstall Hook Integrity Audit (PowerShell)
# =============================================================================
# Windows equivalent of check-npm-integrity.sh
# Usage: .\scripts\check-npm-integrity.ps1
# Exit codes: 0 = clean, 1 = violations found, 2 = error
# =============================================================================
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$NodeModulesPath = (Join-Path (Split-Path $PSScriptRoot -Parent) "node_modules"),
    [string]$AllowlistPath   = (Join-Path $PSScriptRoot "approved-hooks.txt")
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path $PSScriptRoot -Parent
$logDir = Join-Path $projectRoot ".khepra"
$null = New-Item -ItemType Directory -Force -Path $logDir
$logFile = Join-Path $logDir ("npm-integrity-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")

function Write-Log {
    param([string]$msg, [string]$color = "White")
    Write-Host $msg -ForegroundColor $color
    Add-Content -Path $logFile -Value $msg
}

Write-Log "[KHEPRA] npm postinstall hook audit — $(Get-Date)"
Write-Log "[KHEPRA] Scanning: $NodeModulesPath"

if (-not (Test-Path $NodeModulesPath)) {
    Write-Log "[SKIP] node_modules not found — skipping npm audit" "Yellow"
    exit 0
}

# Load allowlist
$approved = @()
if (Test-Path $AllowlistPath) {
    $approved = Get-Content $AllowlistPath |
        Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
}
Write-Log "[KHEPRA] Approved packages with hooks: $($approved.Count)"
Write-Log "---"

$violations = 0
$checked    = 0
$hookKeys   = @("postinstall", "install", "preinstall", "prepare")

# Direct deps only (depth=1)
Get-ChildItem -Path $NodeModulesPath -Depth 2 -Filter "package.json" |
    Where-Object { $_.FullName -notmatch '\\node_modules\\.*\\node_modules\\' } |
    ForEach-Object {
        $pkgJson = $_
        $pkgDir  = $pkgJson.DirectoryName
        $pkgName = Split-Path $pkgDir -Leaf

        # Handle scoped packages
        $parent = Split-Path (Split-Path $pkgDir -Parent) -Leaf
        if ($parent -like '@*') { $pkgName = "$parent/$pkgName" }

        $checked++

        try {
            $pkg = Get-Content $pkgJson.FullName -Raw | ConvertFrom-Json
        } catch { return }

        $scripts = $pkg.scripts
        if (-not $scripts) { return }

        $foundHooks = @()
        foreach ($key in $hookKeys) {
            $val = $scripts.$key
            if ($val) { $foundHooks += "${key}: $($val.Substring(0, [Math]::Min(120, $val.Length)))" }
        }
        if ($foundHooks.Count -eq 0) { return }

        $isApproved = $approved -contains $pkgName
        if ($isApproved) {
            Write-Log "[OK]   $pkgName" "Green"
            foreach ($h in $foundHooks) { Write-Log "       $h" }
        } else {
            Write-Log "[ALERT] UNAPPROVED POSTINSTALL HOOK: $pkgName" "Red"
            foreach ($h in $foundHooks) { Write-Log "        $h" "Red" }
            Write-Log "        Path: $pkgDir" "Red"
            $violations++
        }
    }

Write-Log "---"
Write-Log "[KHEPRA] Scanned: $checked packages"
Write-Log "[KHEPRA] Violations: $violations"

if ($violations -gt 0) {
    Write-Log "" 
    Write-Log "[FAIL] $violations unapproved postinstall hook(s) found." "Red"
    Write-Log "  1. Review each flagged package"
    Write-Log "  2. If legitimate, add to scripts\approved-hooks.txt"
    Write-Log "  3. If suspicious — remove and audit ~/.claude.json NOW"
    Write-Log "  4. See: docs\MCP_SECURITY_RUNBOOK.md"
    Write-Log "Log: $logFile"
    exit 1
}

Write-Log "[PASS] No unapproved postinstall hooks found." "Green"
Write-Log "Log: $logFile"
exit 0

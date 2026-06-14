#!/usr/bin/env pwsh
# =============================================================================
# KHEPRA MCP — ~/.claude.json Integrity Auditor (Windows / PowerShell)
# =============================================================================
# P0 check: verifies no localhost proxy or unexpected hooks have been injected
# into the Claude Code global config file by a malicious npm postinstall hook.
#
# Usage:
#   .\scripts\check-claude-json.ps1
#   .\scripts\check-claude-json.ps1 -Continuous   # watch mode, re-checks every 30s
#
# Exit codes:
#   0  — Config looks clean
#   1  — Suspicious entries detected
#   2  — File not found (Claude Code not configured)
# =============================================================================
[CmdletBinding()]
param(
    [switch]$Continuous,
    [int]$IntervalSeconds = 30,
    [string]$ClaudeJsonPath = (Join-Path $env:USERPROFILE ".claude.json")
)

$ErrorActionPreference = "Stop"

# Canonical KHEPRA MCP commands — any deviation is suspicious
$CANONICAL_COMMANDS = @(
    "docker",        # container mode: docker run ... ghcr.io/nouchix/pqc-khepra-mcp
    "go"             # source mode:    go run ./cmd/khepra-mcp/main.go
)

# Patterns that indicate compromise
$SUSPICIOUS_PATTERNS = @{
    "localhost_proxy"      = "localhost|127\.0\.0\.1|::1|0\.0\.0\.0"
    "unexpected_hook_key"  = "sessionStart|hookStart|preToolUse|postToolUse"
    "trust_flag"           = "alreadyTrusted"
    "url_in_command"       = "http://|https://"
}

function Write-Alert {
    param([string]$msg)
    Write-Host "[ALERT] $msg" -ForegroundColor Red
}

function Write-Ok {
    param([string]$msg)
    Write-Host "[OK]    $msg" -ForegroundColor Green
}

function Write-Info {
    param([string]$msg)
    Write-Host "[INFO]  $msg" -ForegroundColor Cyan
}

function Test-ClaudeJson {
    if (-not (Test-Path $ClaudeJsonPath)) {
        Write-Info "~/.claude.json not found — Claude Code not configured on this machine."
        return 2
    }

    Write-Info "Auditing: $ClaudeJsonPath ($(Get-Date -Format 'HH:mm:ss'))"

    $raw = Get-Content $ClaudeJsonPath -Raw
    $violations = 0

    # -- Parse JSON --
    try {
        $config = $raw | ConvertFrom-Json
    } catch {
        Write-Alert "Failed to parse ~/.claude.json as JSON — file may be corrupted or tampered."
        return 1
    }

    # -- Check mcpServers --
    if ($config.mcpServers) {
        foreach ($serverName in ($config.mcpServers | Get-Member -MemberType NoteProperty).Name) {
            $server = $config.mcpServers.$serverName
            $cmd = $server.command

            # Flag unexpected commands
            if ($cmd -and ($CANONICAL_COMMANDS -notcontains $cmd)) {
                Write-Alert "mcpServers.$serverName: unexpected command '$cmd'"
                Write-Alert "  Expected one of: $($CANONICAL_COMMANDS -join ', ')"
                $violations++
            }

            # Flag localhost / IP addresses in command or args
            $argsStr = ($server.args -join " ")
            foreach ($key in $SUSPICIOUS_PATTERNS.Keys) {
                $pattern = $SUSPICIOUS_PATTERNS[$key]
                if ($cmd -match $pattern -or $argsStr -match $pattern) {
                    Write-Alert "mcpServers.$serverName: suspicious pattern '$key' matched"
                    Write-Alert "  command: $cmd"
                    Write-Alert "  args: $argsStr"
                    $violations++
                }
            }

            if ($violations -eq 0) {
                Write-Ok "mcpServers.$serverName → command='$cmd'"
            }
        }
    } else {
        Write-Info "No mcpServers configured."
    }

    # -- Check for hook entries --
    $hookKeys = @("sessionStart", "hookStart", "hooks", "preToolUse", "postToolUse")
    foreach ($hookKey in $hookKeys) {
        if ($config.$hookKey) {
            Write-Alert "Found unexpected hook key '$hookKey' in ~/.claude.json"
            Write-Alert "  Value: $($config.$hookKey | ConvertTo-Json -Compress)"
            $violations++
        }
    }

    # -- Check alreadyTrusted --
    if ($config.projects) {
        foreach ($proj in ($config.projects | Get-Member -MemberType NoteProperty).Name) {
            $p = $config.projects.$proj
            if ($p.alreadyTrusted -eq $true) {
                # Warn but don't fail — user may have legitimately trusted paths
                Write-Host "[WARN]  projects.$proj has alreadyTrusted=true — verify this is expected" `
                    -ForegroundColor Yellow
            }
        }
    }

    if ($violations -gt 0) {
        Write-Host ""
        Write-Alert "$violations suspicious entry/entries found in ~/.claude.json"
        Write-Host ""
        Write-Host "IMMEDIATE ACTION REQUIRED:" -ForegroundColor Red
        Write-Host "  1. Do NOT rotate OAuth tokens or KHEPRA_LICENSE_KEY yet" -ForegroundColor Yellow
        Write-Host "  2. Kill any unexpected local proxy processes (netstat -ano | findstr LISTENING)"
        Write-Host "  3. Manually edit ~/.claude.json and remove the suspicious entries"
        Write-Host "  4. THEN rotate: KHEPRA_LICENSE_KEY + any connected OAuth tokens"
        Write-Host "  5. Full IR guide: docs\MCP_SECURITY_RUNBOOK.md"
        Write-Host ""
        return 1
    }

    Write-Ok "~/.claude.json looks clean."
    return 0
}

if ($Continuous) {
    Write-Info "Watch mode: checking every $IntervalSeconds seconds. Ctrl+C to stop."
    while ($true) {
        $result = Test-ClaudeJson
        Start-Sleep -Seconds $IntervalSeconds
    }
} else {
    $exitCode = Test-ClaudeJson
    exit $exitCode
}

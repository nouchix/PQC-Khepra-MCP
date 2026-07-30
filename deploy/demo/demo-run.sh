#!/usr/bin/env bash
# demo-run.sh — KHEPRA Pitch Pulse Live Demo Runner
# Verifies demo environment is healthy before pitch
# Run this 30 minutes before the July 10 presentation
# NouchiX / SecRed Knowledge Inc.

set -euo pipefail

DVWA_URL="http://127.0.0.1:4280"
FLIGHT_LOG="$HOME/.khepra/khepra-flight.ndjson"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   KHEPRA DEMO PRE-FLIGHT CHECK          ║"
echo "║   Pitch Pulse — July 10, 2026           ║"
echo "║   NouchiX / SecRed Knowledge Inc.       ║"
echo "╚══════════════════════════════════════════╝"
echo ""

PASS=0
FAIL=0

check() {
    local DESC="$1"
    local CMD="$2"
    if eval "$CMD" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[PASS]${NC} $DESC"
        ((PASS++))
    else
        echo -e "  ${RED}[FAIL]${NC} $DESC"
        ((FAIL++))
    fi
}

warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
}

echo "── Container Health ──────────────────────"
check "khepra-dvwa container running" \
    "docker ps --filter name=khepra-dvwa --filter status=running | grep khepra-dvwa"
check "khepra-demo-db container healthy" \
    "[ \"\$(docker inspect --format='{{.State.Health.Status}}' khepra-demo-db)\" = 'healthy' ]"

echo ""
echo "── Network Exposure ──────────────────────"
check "DVWA bound to localhost only (not 0.0.0.0)" \
    "! ss -tlnp | grep '0.0.0.0:4280'"
check "DVWA reachable on localhost:4280" \
    "curl -sf $DVWA_URL/login.php"

echo ""
echo "── DVWA Security Level ───────────────────"
LEVEL=$(curl -sf "$DVWA_URL/security.php" 2>/dev/null | \
    grep -oP 'Security Level[^<]*<[^>]*>[^<]*\K(low|medium|high|impossible)' 2>/dev/null || \
    echo "unknown")
if [ "$LEVEL" = "low" ]; then
    echo -e "  ${GREEN}[PASS]${NC} Security level: LOW (max findings for demo)"
elif [ "$LEVEL" = "unknown" ]; then
    warn "Could not verify security level — confirm manually at $DVWA_URL/security.php"
else
    warn "Security level is '$LEVEL' — set to LOW for maximum demo findings"
fi

echo ""
echo "── khepra-mcp Binary ─────────────────────"
check "khepra-mcp.exe exists" \
    "[ -f /opt/khepra-demo/khepra-mcp.exe ] || [ -f ./bin/khepra-mcp.exe ]"

echo ""
echo "── Flight Log ────────────────────────────"
if [ -f "$FLIGHT_LOG" ]; then
    FRAMES=$(wc -l < "$FLIGHT_LOG")
    warn "Flight log has $FRAMES existing frames — clear for clean demo run"
    echo "     Run: rm -f $FLIGHT_LOG"
else
    echo -e "  ${GREEN}[PASS]${NC} Flight log clean (no prior frames)"
fi

echo ""
echo "── Demo ERT Scan (dry run) ───────────────"
echo "  Testing ert_scan connectivity to DVWA..."
# Quick HTTP check confirms target is scannable
if curl -sf --max-time 5 "$DVWA_URL" | grep -qi "dvwa\|login\|Damn"; then
    echo -e "  ${GREEN}[PASS]${NC} DVWA responding — ERT target confirmed"
    echo ""
    echo "  Expected findings during pitch:"
    echo "    • MD5 password hashing     → SC-13 / CAT I  → \$1.8M"
    echo "    • SQL Injection             → SI-10 / CAT I  → \$2.4M"
    echo "    • Command Injection         → SI-10 / CAT I  → \$1.2M"
    echo "    • Missing HSTS header       → AC-17 / CAT II → \$450K"
    echo "    • Hardcoded DB credentials  → IA-5  / CAT I  → \$890K"
    echo "    • No CSP header             → SI-3  / CAT II → \$320K"
    echo "    • File Upload (no validate) → SI-7  / CAT I  → \$680K"
    echo "    ─────────────────────────────────────────────────────"
    echo "    TOTAL EXPOSURE:  ~\$7.7M     ROI: 621x"
else
    echo -e "  ${RED}[FAIL]${NC} DVWA not responding — check containers"
    ((FAIL++))
fi

echo ""
echo "══════════════════════════════════════════"
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}✓ ALL CHECKS PASSED — DEMO READY${NC}"
    echo "  You are cleared for Pitch Pulse July 10."
else
    echo -e "  ${RED}✗ $FAIL CHECK(S) FAILED — ACTION REQUIRED${NC}"
    echo "  Resolve failures before pitch."
fi
echo "══════════════════════════════════════════"
echo ""
echo "  Pitch MCP demo command:"
echo "    ert_scan target=http://127.0.0.1:4280"
echo "             framework=CMMC"
echo "             output_format=godfather"
echo ""

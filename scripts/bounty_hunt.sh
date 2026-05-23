#!/bin/bash
#
# Bug Bounty Hunting Automation Script
# Giza Cyber Shield - Professional Pentesting Workflow
#
# Usage:
#   ./scripts/bounty_hunt.sh <target_path_or_url> [output_dir]
#
# Examples:
#   ./scripts/bounty_hunt.sh /path/to/source ./reports
#   ./scripts/bounty_hunt.sh https://target.com ./reports

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << 'EOF'
 ██████╗ ██╗███████╗ █████╗      ██████╗██╗   ██╗██████╗ ███████╗██████╗
██╔════╝ ██║╚══███╔╝██╔══██╗    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
██║  ███╗██║  ███╔╝ ███████║    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
██║   ██║██║ ███╔╝  ██╔══██║    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
╚██████╔╝██║███████╗██║  ██║    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
 ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
                    BUG BOUNTY HUNTER - AUTOMATED WORKFLOW
EOF
echo -e "${NC}"

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}Error: Target not specified${NC}"
    echo "Usage: $0 <target_path_or_url> [output_dir]"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="${2:-./bounty_reports}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="$OUTPUT_DIR/$TIMESTAMP"

# Create output directory
mkdir -p "$REPORT_DIR"

echo -e "${GREEN}[*] Target: $TARGET${NC}"
echo -e "${GREEN}[*] Output: $REPORT_DIR${NC}"
echo ""

# Detect target type
IS_URL=false
if [[ "$TARGET" == http* ]]; then
    IS_URL=true
fi

# Get script directory (to find binaries)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BIN_DIR="$PROJECT_ROOT/bin"

# Check if binaries exist
if [ ! -f "$BIN_DIR/sonar" ] || [ ! -f "$BIN_DIR/adinkhepra" ]; then
    echo -e "${YELLOW}[!] Binaries not found. Building...${NC}"
    cd "$PROJECT_ROOT" && make build
fi

# Enable dev mode to skip license
export ADINKHEPRA_DEV=1

#==============================================================================
# PHASE 1: RECONNAISSANCE
#==============================================================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  PHASE 1: RECONNAISSANCE${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

if [ "$IS_URL" = false ]; then
    echo -e "${GREEN}[+] Running SONAR deep scan on source code...${NC}"
    "$BIN_DIR/sonar" \
        -dir "$TARGET" \
        -verbose \
        -sign \
        -out "$REPORT_DIR/sonar_scan.json" || true

    echo -e "${GREEN}[+] SONAR scan complete: $REPORT_DIR/sonar_scan.json${NC}"
else
    echo -e "${YELLOW}[!] URL target detected - skipping source code scan${NC}"
    echo '{"note": "URL target - source code scan skipped"}' > "$REPORT_DIR/sonar_scan.json"
fi

# Web crawling (for both URL and local targets)
if [ "$IS_URL" = true ]; then
    echo -e "${GREEN}[+] Running web crawler on $TARGET...${NC}"
    cd "$PROJECT_ROOT"
    "$BIN_DIR/adinkhepra" arsenal crawler "$TARGET" || true

    # Move crawler output to report dir
    CRAWLER_FILE=$(ls -t scan_*.json 2>/dev/null | head -1)
    if [ -n "$CRAWLER_FILE" ]; then
        mv "$CRAWLER_FILE" "$REPORT_DIR/crawler_scan.json"
        echo -e "${GREEN}[+] Crawler scan complete: $REPORT_DIR/crawler_scan.json${NC}"
    fi
fi

#==============================================================================
# PHASE 2: VULNERABILITY SCANNING
#==============================================================================
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  PHASE 2: VULNERABILITY SCANNING${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

if [ "$IS_URL" = false ]; then
    # CIS Compliance
    echo -e "${GREEN}[+] Running CIS compliance scan...${NC}"
    "$BIN_DIR/sonar" \
        -dir "$TARGET" \
        -compliance cis \
        -out "$REPORT_DIR/cis_compliance.json" || true

    # Check for Dockerfile
    if [ -f "$TARGET/Dockerfile" ]; then
        echo -e "${GREEN}[+] Scanning Dockerfile for misconfigurations...${NC}"
        "$BIN_DIR/sonar" \
            -container "$TARGET/Dockerfile" \
            -out "$REPORT_DIR/container_scan.json" || true
    fi
fi

#==============================================================================
# PHASE 3: SECRET DETECTION
#==============================================================================
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  PHASE 3: SECRET DETECTION${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

# Check for external tools
if command -v gitleaks &> /dev/null && [ "$IS_URL" = false ]; then
    echo -e "${GREEN}[+] Running Gitleaks...${NC}"
    gitleaks detect -s "$TARGET" -r "$REPORT_DIR/gitleaks.json" --no-git || true
fi

if command -v trufflehog &> /dev/null && [ "$IS_URL" = false ]; then
    echo -e "${GREEN}[+] Running TruffleHog...${NC}"
    trufflehog filesystem "$TARGET" --json > "$REPORT_DIR/trufflehog.json" 2>/dev/null || true
fi

echo -e "${YELLOW}[!] Note: Built-in secret scanner already ran during SONAR scan${NC}"

#==============================================================================
# PHASE 4: AGGREGATE FINDINGS
#==============================================================================
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  PHASE 4: AGGREGATE FINDINGS${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

cd "$PROJECT_ROOT"

# Build ingest command with available scan results
INGEST_CMD="$BIN_DIR/adinkhepra audit ingest $REPORT_DIR/sonar_scan.json"

if [ -f "$REPORT_DIR/gitleaks.json" ]; then
    INGEST_CMD="$INGEST_CMD -leaks $REPORT_DIR/gitleaks.json"
fi

if [ -f "$REPORT_DIR/trufflehog.json" ]; then
    INGEST_CMD="$INGEST_CMD -truffle $REPORT_DIR/trufflehog.json"
fi

if [ -f "$REPORT_DIR/crawler_scan.json" ]; then
    INGEST_CMD="$INGEST_CMD -crawler $REPORT_DIR/crawler_scan.json"
fi

echo -e "${GREEN}[+] Aggregating all scan results...${NC}"
eval "$INGEST_CMD" || true

# Move generated reports to report dir
mv "$REPORT_DIR/sonar_scan.json.risk_report.json" "$REPORT_DIR/risk_report.json" 2>/dev/null || true
mv "$REPORT_DIR/sonar_scan.json.superset.csv" "$REPORT_DIR/findings.csv" 2>/dev/null || true
mv "$REPORT_DIR/sonar_scan.json.affine.md" "$REPORT_DIR/executive_summary.md" 2>/dev/null || true

#==============================================================================
# PHASE 5: GENERATE ATTESTATION
#==============================================================================
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  PHASE 5: GENERATE RISK ATTESTATION${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

echo -e "${GREEN}[+] Generating PQC-signed risk attestation...${NC}"
"$BIN_DIR/adinkhepra" attest "$REPORT_DIR/sonar_scan.json" || true

mv "$REPORT_DIR/sonar_scan.json.attestation.json" "$REPORT_DIR/attestation.json" 2>/dev/null || true

#==============================================================================
# PHASE 6: SUMMARY
#==============================================================================
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  SCAN COMPLETE - SUMMARY${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

echo ""
echo -e "${GREEN}Report files generated in: $REPORT_DIR${NC}"
echo ""
ls -la "$REPORT_DIR"

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  NEXT STEPS${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "1. Review findings:"
echo "   cat $REPORT_DIR/risk_report.json | jq '.Risks'"
echo ""
echo "2. Check critical issues:"
echo "   cat $REPORT_DIR/attestation.json | jq '.findings[] | select(.severity == \"CRITICAL\")'"
echo ""
echo "3. View executive summary:"
echo "   cat $REPORT_DIR/executive_summary.md"
echo ""
echo "4. Export to spreadsheet:"
echo "   $REPORT_DIR/findings.csv"
echo ""
echo -e "${GREEN}Happy hunting!${NC}"

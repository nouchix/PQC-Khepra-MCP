#!/usr/bin/env bash
# =============================================================================
# KHEPRA MCP Server — npm Postinstall Hook Integrity Audit
# =============================================================================
# Scans all installed npm packages for postinstall lifecycle hooks and
# cross-references them against an approved allowlist.
#
# Usage:
#   bash scripts/check-npm-integrity.sh [--dir <node_modules_path>]
#
# Exit codes:
#   0  — All clear, no unapproved hooks found
#   1  — One or more unapproved postinstall hooks detected (CI should fail)
#   2  — Error (missing node_modules, bad args)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NODE_MODULES="${PROJECT_ROOT}/node_modules"
ALLOWLIST="${SCRIPT_DIR}/approved-hooks.txt"
LOG_FILE="${PROJECT_ROOT}/.khepra/npm-integrity-$(date +%Y%m%d-%H%M%S).log"

RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
RST='\033[0m'

mkdir -p "$(dirname "$LOG_FILE")"

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) NODE_MODULES="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
done

if [[ ! -d "$NODE_MODULES" ]]; then
  echo -e "${YLW}[SKIP] node_modules not found at $NODE_MODULES — skipping npm audit${RST}"
  exit 0
fi

# Load approved hooks allowlist (package names, one per line, # for comments)
APPROVED=()
if [[ -f "$ALLOWLIST" ]]; then
  while IFS= read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    APPROVED+=("$line")
  done < "$ALLOWLIST"
fi

echo "[KHEPRA] npm postinstall hook audit — $(date)" | tee "$LOG_FILE"
echo "[KHEPRA] Scanning: $NODE_MODULES" | tee -a "$LOG_FILE"
echo "[KHEPRA] Approved packages with hooks: ${#APPROVED[@]}" | tee -a "$LOG_FILE"
echo "---" | tee -a "$LOG_FILE"

VIOLATIONS=0
CHECKED=0

# Scan every package.json in node_modules (depth=1 only — direct deps)
while IFS= read -r pkg_json; do
  pkg_dir="$(dirname "$pkg_json")"
  pkg_name="$(basename "$pkg_dir")"

  # Handle scoped packages (@org/name)
  parent="$(basename "$(dirname "$pkg_dir")")"
  if [[ "$parent" == @* ]]; then
    pkg_name="${parent}/${pkg_name}"
  fi

  CHECKED=$((CHECKED + 1))

  # Check for postinstall / install / preinstall scripts
  hooks=$(python3 -c "
import json, sys
try:
    d = json.load(open('$pkg_json'))
    scripts = d.get('scripts', {})
    found = []
    for k in ('postinstall', 'install', 'preinstall', 'prepare'):
        if k in scripts:
            found.append(f'{k}: {scripts[k][:120]}')
    print('\n'.join(found))
except Exception as e:
    pass
" 2>/dev/null || true)

  if [[ -z "$hooks" ]]; then
    continue
  fi

  # Check against allowlist
  approved=false
  for allowed in "${APPROVED[@]}"; do
    if [[ "$pkg_name" == "$allowed" ]]; then
      approved=true
      break
    fi
  done

  if $approved; then
    echo -e "${GRN}[OK]  ${pkg_name}${RST}" | tee -a "$LOG_FILE"
    echo "      $hooks" | tee -a "$LOG_FILE"
  else
    echo -e "${RED}[ALERT] UNAPPROVED POSTINSTALL HOOK: ${pkg_name}${RST}" | tee -a "$LOG_FILE"
    echo "        $hooks" | tee -a "$LOG_FILE"
    echo "        Package path: $pkg_dir" | tee -a "$LOG_FILE"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi

done < <(find "$NODE_MODULES" -maxdepth 3 -name "package.json" ! -path "*/node_modules/*/node_modules/*")

echo "---" | tee -a "$LOG_FILE"
echo "[KHEPRA] Scanned: $CHECKED packages" | tee -a "$LOG_FILE"
echo "[KHEPRA] Violations: $VIOLATIONS" | tee -a "$LOG_FILE"

if [[ $VIOLATIONS -gt 0 ]]; then
  echo -e "${RED}[FAIL] $VIOLATIONS unapproved postinstall hook(s) found.${RST}" | tee -a "$LOG_FILE"
  echo "" | tee -a "$LOG_FILE"
  echo "Actions required:" | tee -a "$LOG_FILE"
  echo "  1. Review each flagged package — is it a known legitimate package?" | tee -a "$LOG_FILE"
  echo "  2. If legitimate, add its name to scripts/approved-hooks.txt" | tee -a "$LOG_FILE"
  echo "  3. If unknown or suspicious — REMOVE IT and audit ~/.claude.json immediately" | tee -a "$LOG_FILE"
  echo "  4. See: docs/MCP_SECURITY_RUNBOOK.md" | tee -a "$LOG_FILE"
  echo "" | tee -a "$LOG_FILE"
  echo "Log saved to: $LOG_FILE"
  exit 1
fi

echo -e "${GRN}[PASS] No unapproved postinstall hooks found.${RST}" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE"
exit 0

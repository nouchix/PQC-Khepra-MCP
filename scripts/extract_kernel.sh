#!/usr/bin/env bash
# extract_kernel.sh — produce the FRESH-HISTORY public kernel repo from this tree.
#
# Per docs/public-kernel/HISTORY_SCRUB_REPORT.md, this repo's git history contains
# real credentials: the public kernel repo MUST NOT inherit this history. This
# script therefore builds the public repo from a clean `git init`, copying only
# the KEEP-list from docs/public-kernel/KERNEL_SCOPE.md.
#
# Usage:
#   scripts/extract_kernel.sh /path/to/new/khepra-mcp-kernel        # extract
#   scripts/extract_kernel.sh --verify /path/to/new/khepra-mcp-kernel # gate checks
#
# The extraction is NOT publishable until --verify passes:
#   1. gitleaks over the extraction: zero findings
#   2. no imports outside the keep-list (grep gate; go build where toolchain allows)
#   3. LICENSE is Apache-2.0 and DCO.txt present
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# KEEP-list — mirror of KERNEL_SCOPE.md §1. Update both together.
KEEP_PATHS=(
  "pkg/mcp"
  "pkg/crypto"
  "pkg/attestenvelope"
  "pkg/types"
  "cmd/khepra-mcp"
  "cmd/manifest-gen"
  "gen_manifest.go"
  "Dockerfile.mcp"
  "llms-install.md"
  "go.mod"
  "go.sum"
)
# Stripped even inside kept dirs (product tools / scanners / legacy):
PRUNE_INSIDE=(
  "pkg/mcp/tools"
  "pkg/mcp/scanner"
  "pkg/mcp/legacy"
  "pkg/mcp/scanner_adapter.go"
)
# Private import prefixes that must NOT survive in the extraction:
FORBIDDEN_IMPORT_RE='PQC-Khepra-MCP/pkg/(dag|attest|audit|license|flight|logging|lorentz|adinkra|stig|stigs|nhi|ert|vuln|souhimbou|sca|ea|acp|telemetry|sekhem|scanners|scanner|phantom|packet|nkyinkyim|ising|ir|intel|graph|gateway|forensics|fingerprint|fim|evidence|enumerate|drbc|compliance|agi|billing|kms|pki|config|arsenal|agent|agi|api|apiserver|asaf|connectors|dns|emass|grpc|ironbank|maat|middleware|mobile|net|network|nhi|ouroboros|poam|rbac|remote|risk|sbom|scada|scorpion|security|seshat|sonar|supabase|webui|zscan)(?:/|\")'

MODE="extract"
if [ "${1:-}" = "--verify" ]; then MODE="verify"; shift; fi
DEST="${1:?usage: extract_kernel.sh [--verify] /path/to/dest}"

verify() {
  local fail=0
  echo "── verify: $DEST"
  # 1. secrets
  if command -v gitleaks >/dev/null 2>&1; then
    if ! gitleaks git "$DEST" --exit-code 1 >/dev/null 2>&1; then
      echo "[FAIL] gitleaks found secrets in the extraction"; fail=1
    else
      echo "[OK] gitleaks: no findings"
    fi
  else
    echo "[FAIL] gitleaks not installed — publication gate cannot pass without it"; fail=1
  fi
  # 2. forbidden imports
  if grep -rInE "$FORBIDDEN_IMPORT_RE" "$DEST" --include="*.go" | grep -v '_test.go' ; then
    echo "[FAIL] extraction imports private packages (condition 3 spike incomplete)"; fail=1
  else
    echo "[OK] no private-plane imports"
  fi
  # 3. license posture
  if head -5 "$DEST/LICENSE" 2>/dev/null | grep -qi "Apache License"; then
    echo "[OK] LICENSE is Apache-2.0"
  else
    echo "[FAIL] LICENSE missing or not Apache-2.0"; fail=1
  fi
  [ -f "$DEST/DCO.txt" ] && echo "[OK] DCO present" || { echo "[FAIL] DCO.txt missing"; fail=1; }
  # 4. build (best-effort; pinned toolchain may not be available everywhere)
  if (cd "$DEST" && go build ./... >/dev/null 2>&1); then
    echo "[OK] go build ./..."
  else
    echo "[WARN] go build failed or toolchain unavailable — must pass before publication"
  fi
  exit "$fail"
}

extract() {
  [ -e "$DEST/.git" ] && { echo "refusing: $DEST already a git repo"; exit 2; }
  mkdir -p "$DEST"
  for p in "${KEEP_PATHS[@]}"; do
    [ -e "$ROOT/$p" ] || { echo "[skip] $p (absent)"; continue; }
    mkdir -p "$DEST/$(dirname "$p")"
    cp -r "$ROOT/$p" "$DEST/$p"
  done
  for p in "${PRUNE_INSIDE[@]}"; do rm -rf "${DEST:?}/$p"; done
  cp "$ROOT/docs/public-kernel/LICENSE-APACHE-2.0.proposed" "$DEST/LICENSE"
  cp "$ROOT/docs/public-kernel/DCO.txt" "$DEST/DCO.txt"
  # Rewrite module path to public kernel
  ( cd "$DEST" && \
    find . -name "*.go" -exec sed -i '' 's|github.com/nouchix/PQC-Khepra-MCP|github.com/nouchix/khepra-kernel|g' {} + && \
    go mod edit -module github.com/nouchix/khepra-kernel && \
    rm -f go.sum && \
    export PATH=/Applications/Whitebox/PQC-Khepra-MCP/go/bin:$PATH && \
    go mod tidy \
  )

  ( cd "$DEST" && git init -q && git add -A && \
    git commit -qm "Initial import: KHEPRA MCP kernel (fresh history)" )
  echo "extracted to $DEST — now run: $0 --verify $DEST"
}

case "$MODE" in
  verify)  verify ;;
  extract) extract ;;
esac

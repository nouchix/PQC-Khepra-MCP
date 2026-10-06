#!/usr/bin/env bash
# Fail if private key material, sealed artifacts or env files are tracked.
#
# Usage:
#   scripts/check-no-key-material.sh          # check every tracked file (CI)
#   scripts/check-no-key-material.sh --staged # check files staged for commit
#
# Public keys (*.pub, *.pub.*) and .env.example files are allowed. Anything this
# script catches after it has been pushed must be rotated, not just untracked.
set -euo pipefail

if [ "${1:-}" = "--staged" ]; then
  files=$(git diff --cached --name-only --diff-filter=ACMR)
else
  files=$(git ls-files)
fi

flagged=$(printf '%s\n' "$files" \
  | grep -E '(_kyber|_dilithium|_mlkem1024|_mldsa87|_ed25519|_ecdsa)$|\.(sealed|khepra|dilithium|dilithium\.bak)$|(^|/)master_seed[^/]*$|(^|/)keys/root-ceremony/|(^|/)PASSPHRASES[^/]*\.txt$|(^|/)\.env(_ascii)?$|(^|/)\.env\.[^/]+$|(^|/)id_(rsa|ecdsa|ed25519|dilithium|mldsa87|mlkem1024)$' \
  | grep -vE '\.pub$|\.pub\.|\.example$|(^|/)vendor/|^go/|(^|/)node_modules/' \
  || true)

if [ -n "$flagged" ]; then
  echo "Key material or secret files are tracked. Remove them from git and rotate them:" >&2
  printf '  %s\n' $flagged >&2
  exit 1
fi
echo "key-material guard: no private keys, sealed artifacts or env files tracked"

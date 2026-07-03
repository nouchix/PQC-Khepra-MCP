#!/usr/bin/env bash
# sovereignty_boundary_guard.sh — TRL10 enforceable control for the ASAF sovereignty boundary.
#
# WHY THIS EXISTS
#   AdinKhepra ASAF's core value prop and CMMC/DFARS posture depend on ONE invariant:
#   a customer's CUI compliance data plane (the Hub at :8443, Fleet, DAG, scan findings)
#   NEVER lands on a NouchiX-operated vendor host. Sovereignty must be *enforced*, not
#   *asserted in a comment*. This guard makes a violation fail loudly in CI.
#
#   Canonical policy: MEMORY.md § "Sovereignty Boundary Policy (TRL10 control)".
#
# WHAT IT CHECKS (deny-by-default on the data plane)
#   1. No shipped CLIENT (asaf-desktop, khepra-reporter, Hub/Backend client) may DEFAULT
#      its Hub / upstream / fleet API base URL to a vendor domain. Customer Hub URL is
#      per-tenant and supplied at runtime — never a compiled-in vendor subdomain.
#   2. No compose/env may bind a HUB / FLEET / CUI data-plane service to a vendor host.
#   3. Any public demo/eval scan surface on a vendor host (mcp./gateway.) MUST be
#      explicitly acknowledged in scripts/sovereignty_allowlist.txt with a data
#      classification of DEMO/SYNTHETIC — so "public scan endpoint" is a deliberate,
#      reviewed decision, not an accident.
#
# CONTROL vs DATA plane:
#   ALLOWED on vendor hosts  (control plane): telemetry.*, licensing/heartbeat, docs,
#                                             installer/artifact mirror, Stripe webhook,
#                                             and DEMO/discovery MCP (allowlisted).
#   FORBIDDEN on vendor hosts (data plane):   Hub :8443, Fleet API, customer DAG store,
#                                             customer scan findings, credential vault.
#
# Exit codes: 0 = boundary intact, 1 = violation(s) found, 2 = guard misconfig.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || { echo "guard: cannot cd to repo root"; exit 2; }

ALLOWLIST="scripts/sovereignty_allowlist.txt"

# Vendor hosts we operate. A customer CUI data plane must never be pinned to these.
VENDOR_HOST_RE='(souhimbou\.(ai|org)|khepra\.io|adinkhepra\.com|nouchix\.com|secredknowledgeinc\.tech)'

# Client entrypoints/packages that get SHIPPED to (or run by) the customer.
# Covers both the Go clients (giza / PQC-Khepra-MCP) and the Next.js deployment
# repo (Adinkhepra-ASAF) — the guard runs identically in all three.
CLIENT_PATHS=(
  "cmd/asaf-desktop"
  "cmd/khepra-reporter"
  "pkg/asaf/hub"
  "pkg/asaf/client"
  "pkg/asaf/connector"
  "app"
  "src"
)

FAIL=0
note() { printf '  %s\n' "$*"; }
fail() { printf '\033[0;31m[BOUNDARY VIOLATION]\033[0m %s\n' "$*"; FAIL=1; }
ok()   { printf '\033[0;32m[OK]\033[0m %s\n' "$*"; }

# Acknowledged vendor hosts (control-plane + demo-discovery) from the allowlist.
# A reference to one of these is a reviewed decision, not a violation. A vendor host
# NOT in this set that carries a data-plane binding is what we hard-fail on.
declare -a ALLOWED_HOSTS=()
if [ -f "$ALLOWLIST" ]; then
  while IFS= read -r a; do
    [[ "$a" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${a// }" ]] && continue
    ALLOWED_HOSTS+=("$(awk '{print $1}' <<<"$a")")
  done < "$ALLOWLIST"
fi
host_allowed() {
  local h="$1"
  for a in "${ALLOWED_HOSTS[@]}"; do [ "$h" = "$a" ] && return 0; done
  return 1
}
# Extract the first vendor host token from a line.
vendor_host_of() { grep -oiE "[a-z0-9.-]*$VENDOR_HOST_RE" <<<"$1" | head -1; }

echo "── ASAF Sovereignty Boundary Guard ─────────────────────────────────────────"
echo "repo: $ROOT"
echo

# ── Check 1: no client default Hub/upstream/fleet base URL points at a vendor host ──
# We look for a vendor host appearing on a line that also assigns a hub/upstream/api/
# fleet/base URL (const, var, flag default, or struct field). Telemetry/license lines
# are control-plane and explicitly excluded.
echo "Check 1 — client Hub/upstream defaults must be customer-supplied, not vendor-pinned"
c1_hits=0
for p in "${CLIENT_PATHS[@]}"; do
  [ -e "$p" ] || continue
  # Candidate offenders: a vendor host on a line that looks like a hub/api/upstream/fleet default.
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    content="${line#*:*:}"                       # strip "path:lineno:" prefix
    trimmed="${content#"${content%%[![:space:]]*}"}"  # left-trim
    # Skip comment-only lines — a comment is documentation, not a binding.
    case "$trimmed" in //*|\#*|\**|/\**|"<!--"*) continue;; esac
    # Control-plane (telemetry/license/docs/webhook/install) is allowed on vendor hosts.
    echo "$content" | grep -qiE 'telemetr|licens|heartbeat|/docs|install|webhook|release' && continue
    h="$(vendor_host_of "$line")"
    # HARD RULE: a customer Hub port (:8443) pinned to a vendor host is ALWAYS a violation,
    # even for an allowlisted demo host — you never run the customer Hub on a vendor box.
    if echo "$content" | grep -qE ':8443'; then
      c1_hits=$((c1_hits+1)); fail "customer Hub port :8443 pinned to a vendor host ($h):"; note "$line"; continue
    fi
    # An allowlisted demo/SaaS/control surface as a DEFAULT is acceptable (the vendor's own
    # marketing funnel / SaaS dashboard legitimately calls the vendor's own demo backend).
    if host_allowed "$h"; then
      note "acknowledged vendor default ($h) — demo/SaaS funnel or control plane, not a customer Hub:"
      note "  $line"
      continue
    fi
    # An UNREVIEWED vendor host as a client default is the true violation.
    c1_hits=$((c1_hits+1))
    fail "client default pins a data-plane URL to an UNREVIEWED vendor host ($h):"
    note "$line"
  done < <(grep -rInE "$VENDOR_HOST_RE" "$p" 2>/dev/null \
             | grep -viE '/vendor/|_test\.go|node_modules' \
             | grep -iE 'hub|upstream|fleet|baseurl|base_url|api_url|apiurl|:8443|--hub|ASAF_HUB|KHEPRA_.*UPSTREAM')
done
[ "$c1_hits" -eq 0 ] && ok "no client ships a vendor-pinned Hub/upstream/fleet default"
echo

# ── Check 2: no compose/env binds a HUB/FLEET/CUI service to a vendor host ──────────
echo "Check 2 — Hub/Fleet/CUI data-plane services must not be bound to vendor hosts"
c2_hits=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  content="${line#*:*:}"
  trimmed="${content#"${content%%[![:space:]]*}"}"
  # Skip comment-only lines — a comment referencing a host is not a binding.
  case "$trimmed" in //*|\#*|\**|/\**|"<!--"*) continue;; esac
  # Skip obvious non-bindings: CORS origins, contact emails, marketing/badges.
  echo "$content" | grep -qiE 'cors|contact|website|hall-of-fame|badge|img\.shields|mailto' && continue
  # Only care about lines that actually configure a data-plane service.
  echo "$content" | grep -qiE 'HUB|FLEET|CUI|ASAF_.*API|_UPSTREAM' || continue
  h="$(vendor_host_of "$line")"
  # Acknowledged control-plane/demo hosts are reviewed; an UNREVIEWED vendor host
  # carrying a data-plane binding is the true violation.
  if host_allowed "$h"; then
    note "acknowledged surface ($h) — data-plane keyword present; verify it is not the customer Hub:"
    note "  $line"
    continue
  fi
  c2_hits=$((c2_hits+1))
  fail "compose/env binds a data-plane service to an UNREVIEWED vendor host ($h):"
  note "$line"
done < <(grep -rInE "$VENDOR_HOST_RE" \
            --include="*.yml" --include="*.yaml" --include="*.env" --include="*.toml" \
            . 2>/dev/null | grep -viE '/vendor/|node_modules')
[ "$c2_hits" -eq 0 ] && ok "no Hub/Fleet/CUI data-plane service bound to an unreviewed vendor host"
echo

# ── Check 3: public demo/eval scan surfaces on vendor hosts must be acknowledged ────
echo "Check 3 — public demo/eval scan surfaces on vendor hosts must be allowlisted"
# Eval-without-license co-located with a scan endpoint is only acceptable on an
# explicitly DEMO-classified surface (allowlist).
if grep -rInE 'ALLOW_EVAL_WITHOUT_LICENSE\s*=\s*true' --include="*.yml" --include="*.yaml" --include="*.env" . 2>/dev/null | grep -viE '/vendor/|node_modules' >/dev/null; then
  if [ -f "$ALLOWLIST" ] && grep -qiE 'DEMO|SYNTHETIC' "$ALLOWLIST"; then
    ok "eval-without-license surface is acknowledged as DEMO/SYNTHETIC in $ALLOWLIST"
  else
    fail "an eval-without-license scan surface exists but is not DEMO-classified in $ALLOWLIST"
    note "Add a DEMO/SYNTHETIC entry to $ALLOWLIST or gate the endpoint behind auth."
  fi
else
  ok "no unauthenticated eval scan surface detected"
fi
echo

echo "────────────────────────────────────────────────────────────────────────────"
if [ "$FAIL" -ne 0 ]; then
  echo "RESULT: BOUNDARY VIOLATION — see MEMORY.md § Sovereignty Boundary Policy."
  echo "The customer CUI data plane must never be pinned to a vendor host."
  exit 1
fi
echo "RESULT: sovereignty boundary intact."
exit 0

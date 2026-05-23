#!/bin/bash
# SouHimBou AI — Full Stack Deployment Script
# Usage:
#   ./scripts/deploy.sh              # Full deploy (Supabase + Fly + verify)
#   ./scripts/deploy.sh --supabase   # Edge Functions only
#   ./scripts/deploy.sh --fly        # Fly.io only
#   ./scripts/deploy.sh --verify     # Health checks only

set -e

# --- Configuration ---
FLY_APP="souhimbou-ai"
FLY_URL="https://${FLY_APP}.fly.dev"
SUPABASE_WORKDIR="souhimbou_ai/SouHimBou.AI"
HEALTH_TIMEOUT=90
HEALTH_INTERVAL=5

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✅ $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; }
info() { echo -e "${CYAN}ℹ️  $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }

# --- Pre-flight ---
preflight() {
  echo ""
  echo "====================================="
  echo "  🛡️  KHEPRA PROTOCOL — DEPLOY"
  echo "====================================="
  echo ""

  local missing=0

  if ! command -v fly &>/dev/null; then
    fail "fly CLI not found. Install: https://fly.io/docs/flyctl/install/"
    missing=1
  fi

  if ! npx supabase --version &>/dev/null 2>&1; then
    fail "supabase CLI not found. Install: npm i -g supabase"
    missing=1
  fi

  if [ $missing -eq 1 ]; then
    exit 1
  fi

  ok "Pre-flight checks passed"
}

# --- Check Supabase Secrets ---
check_supabase_secrets() {
  info "Checking Supabase secrets..."
  local secrets
  secrets=$(npx supabase secrets list --workdir "$SUPABASE_WORKDIR" 2>/dev/null || echo "")

  local required=("OTX_API_KEY" "SHODAN_API_KEY" "AUTOSEND_API_KEY")
  local missing=()

  for secret in "${required[@]}"; do
    if ! echo "$secrets" | grep -q "$secret"; then
      missing+=("$secret")
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    warn "Missing Supabase secrets: ${missing[*]}"
    warn "Run: ./scripts/deploy_config.sh to set them"
    return 1
  fi

  ok "All required Supabase secrets present"
  return 0
}

# --- Deploy Supabase Edge Functions ---
deploy_supabase() {
  echo ""
  info "Deploying Supabase Edge Functions..."

  npx supabase functions deploy --workdir "$SUPABASE_WORKDIR"

  if [ $? -eq 0 ]; then
    ok "Supabase Edge Functions deployed"
  else
    fail "Supabase deploy failed"
    exit 1
  fi
}

# --- Deploy Fly.io ---
deploy_fly() {
  echo ""
  info "Deploying to Fly.io ($FLY_APP)..."

  fly deploy --app "$FLY_APP"

  if [ $? -eq 0 ]; then
    ok "Fly.io deployed successfully"
  else
    fail "Fly.io deploy failed"
    exit 1
  fi
}

# --- Health Checks ---
verify() {
  echo ""
  info "Running health checks (timeout: ${HEALTH_TIMEOUT}s)..."

  # 1. Fly.io
  info "Checking Fly.io: $FLY_URL"
  local elapsed=0
  while [ $elapsed -lt $HEALTH_TIMEOUT ]; do
    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" "$FLY_URL/" 2>/dev/null || echo "000")
    if [ "$status" = "200" ]; then
      ok "Fly.io health check passed (HTTP $status)"
      break
    fi
    echo "  Waiting... (${elapsed}s, HTTP $status)"
    sleep $HEALTH_INTERVAL
    elapsed=$((elapsed + HEALTH_INTERVAL))
  done

  if [ $elapsed -ge $HEALTH_TIMEOUT ]; then
    fail "Fly.io health check timed out after ${HEALTH_TIMEOUT}s"
  fi

  # 2. Vercel (if deployed)
  info "Vercel deploys automatically when main is merged."
  info "Ensure these env vars are set in Vercel Dashboard:"
  echo "  AGENT_URL = $FLY_URL"
  echo "  NEXT_PUBLIC_API_URL = $FLY_URL"

  echo ""
  echo "====================================="
  echo "  🚀 DEPLOYMENT COMPLETE"
  echo "====================================="
  echo ""
  echo "  Fly.io:    $FLY_URL"
  echo "  Supabase:  Edge Functions deployed"
  echo "  Vercel:    Auto-deploys on git push"
  echo ""
}

# --- Main ---
preflight

case "${1:-all}" in
  --supabase)
    check_supabase_secrets || true
    deploy_supabase
    ;;
  --fly)
    deploy_fly
    ;;
  --verify)
    verify
    ;;
  all|"")
    check_supabase_secrets || true
    deploy_supabase
    deploy_fly
    verify
    ;;
  *)
    echo "Usage: $0 [--supabase|--fly|--verify]"
    exit 1
    ;;
esac

#!/bin/bash
# SouHimBou AI - Deployment Config Helper
# Sets all necessary secrets for Supabase Edge Functions and Fly.io.
# IMPORTANT: No secrets are hardcoded. All values are prompted at runtime.
#
# Current secret count: Supabase 27 + Fly.io 6 = 33 total

set -e

# --- Configuration ---
ORG_NAME="SouHimBou"
DOMAIN="souhimbou-ai.fly.dev"
SUPABASE_DIR="souhimbou_ai/SouHimBou.AI"

echo "🛡️  Setting up $ORG_NAME Security Secrets..."
echo "   This will configure 33 secrets across Supabase + Fly.io"
echo ""

# ========================================
# 1. Supabase Edge Function Secrets (27)
# ========================================
echo "📡 Configuring Supabase Edge Functions..."
echo ""

# --- Payments ---
read -sp "Enter Stripe Secret Key (sk_live_...): " STRIPE_SECRET
echo ""
read -sp "Enter Stripe Webhook Secret (whsec_...): " STRIPE_WEBHOOK
echo ""

# --- Email Delivery ---
read -sp "Enter Autosend API Key: " AUTOSEND_KEY
echo ""

# --- SMS / OpenPhone (Quo) ---
read -sp "Enter Quo API Key: " QUO_KEY
echo ""
read -p  "Enter Quo Phone Number ID (e.g. PNCe23euX4): " QUO_PHONE
read -sp "Enter Quo Webhook Secret (from OpenPhone webhook settings): " QUO_WEBHOOK_SECRET
echo ""

# --- Threat Intelligence ---
read -sp "Enter AlienVault OTX API Key: " OTX_KEY
echo ""
read -sp "Enter Shodan API Key: " SHODAN_KEY
echo ""
read -sp "Enter VirusTotal API Key: " VT_KEY
echo ""
read -sp "Enter AbuseIPDB API Key: " ABUSEIPDB_KEY
echo ""
read -sp "Enter URLVoid API Key: " URLVOID_KEY
echo ""

# --- AI ---
read -sp "Enter OpenAI API Key: " OPENAI_KEY
echo ""
read -sp "Enter Grok API Key (xAI): " GROK_KEY
echo ""

# --- Discord Bot ---
read -p  "Enter Discord Public Key: " DISCORD_PUB_KEY
read -sp "Enter Discord Bot Token: " DISCORD_TOKEN
echo ""

# --- Discord Webhooks (Security Ops) ---
read -p "Enter Alert Webhook URL (#critical-alerts): " WH_ALERT
read -p "Enter Threat Intel Webhook URL (#threat-intel): " WH_THREAT
read -p "Enter STIG Webhook URL (#stig-updates): " WH_STIG
read -p "Enter Deploy Webhook URL (#deploy-status): " WH_DEPLOY
read -p "Enter Uptime Webhook URL (#uptime-monitor): " WH_UPTIME

# --- Discord Webhooks (Business) ---
read -p "Enter License Webhook URL (#license-events): " WH_LICENSE

# --- Site & Security ---
read -p "Enter Vercel Site URL (https://...vercel.app): " SITE_URL

# Generate random secrets
KHEPRA_WEBHOOK=$(openssl rand -hex 32)
KHEPRA_SERVICE=$(openssl rand -hex 32)
echo "Generated KHEPRA_WEBHOOK_SECRET: $KHEPRA_WEBHOOK"
echo "Generated KHEPRA_SERVICE_SECRET: $KHEPRA_SERVICE"
echo "⚠️  SAVE THESE — they are used for DEMARC gateway authentication."
echo ""

echo "Setting 27 Supabase secrets..."

npx supabase --workdir "$SUPABASE_DIR" secrets set \
  "STRIPE_SECRET_KEY=$STRIPE_SECRET" \
  "STRIPE_WEBHOOK_SECRET=$STRIPE_WEBHOOK" \
  "AUTOSEND_API_KEY=$AUTOSEND_KEY" \
  "QUO_API_KEY=$QUO_KEY" \
  "QUO_PHONE_NUMBER=$QUO_PHONE" \
  "QUO_WEBHOOK_SECRET=$QUO_WEBHOOK_SECRET" \
  "OTX_API_KEY=$OTX_KEY" \
  "SHODAN_API_KEY=$SHODAN_KEY" \
  "VIRUSTOTAL_API_KEY=$VT_KEY" \
  "ABUSEIPDB_API_KEY=$ABUSEIPDB_KEY" \
  "URLVOID_API_KEY=$URLVOID_KEY" \
  "OPENAI_API_KEY=$OPENAI_KEY" \
  "GROK_API_KEY=$GROK_KEY" \
  "DISCORD_PUBLIC_KEY=$DISCORD_PUB_KEY" \
  "DISCORD_BOT_TOKEN=$DISCORD_TOKEN" \
  "ALERT_WEBHOOK_URL=$WH_ALERT" \
  "THREAT_INTEL_WEBHOOK_URL=$WH_THREAT" \
  "STIG_WEBHOOK_URL=$WH_STIG" \
  "DEPLOY_WEBHOOK_URL=$WH_DEPLOY" \
  "UPTIME_WEBHOOK_URL=$WH_UPTIME" \
  "LICENSE_WEBHOOK_URL=$WH_LICENSE" \
  "SITE_URL=$SITE_URL" \
  "KHEPRA_WEBHOOK_SECRET=$KHEPRA_WEBHOOK" \
  "KHEPRA_SERVICE_SECRET=$KHEPRA_SERVICE"

echo "✅ Supabase secrets set (27)."
echo ""

# ========================================
# 2. Fly.io Secrets (6)
# ========================================
echo "🛸 Configuring Fly.io Secure Gateway..."

GEN_KEY=$(openssl rand -hex 32)
echo "Generated Integrity Key: $GEN_KEY"
echo "⚠️  SAVE THIS KEY: It is used for HMAC integrity of the STIG cache."

read -sp "Enter STIGViewer API Token: " STIG_TOKEN
echo ""
read -sp "Enter Supabase Service Role Key: " SUPA_SERVICE_KEY
echo ""
read -sp "Enter Supabase JWT Secret: " SUPA_JWT
echo ""

fly secrets set \
  "INTEGRITY_KEY=$GEN_KEY" \
  "STIGVIEWER_API_KEY=$STIG_TOKEN" \
  "SUPABASE_URL=https://xjknkjbrjgljuovaazeu.supabase.co" \
  "SUPABASE_SERVICE_ROLE_KEY=$SUPA_SERVICE_KEY" \
  "SUPABASE_JWT_SECRET=$SUPA_JWT" \
  "KHEPRA_SERVICE_SECRET=$KHEPRA_SERVICE"

echo "✅ Fly.io secrets set (6)."
echo ""

# ========================================
# 3. Vercel Environment Variables (7)
# ========================================
echo "▲ Configuring Vercel Frontend..."

read -p  "Enter Supabase Anon Key (public): " SUPA_ANON_KEY

echo "Setting Vercel environment variables..."

# Vercel env vars for the Next.js frontend
vercel env add NEXT_PUBLIC_SUPABASE_URL production <<< "https://xjknkjbrjgljuovaazeu.supabase.co"
vercel env add NEXT_PUBLIC_SUPABASE_ANON_KEY production <<< "$SUPA_ANON_KEY"
vercel env add SUPABASE_SERVICE_ROLE_KEY production <<< "$SUPA_SERVICE_KEY"
vercel env add NEXT_PUBLIC_KHEPRA_API_URL production <<< "https://souhimbou-ai.fly.dev"
vercel env add STRIPE_SECRET_KEY production <<< "$STRIPE_SECRET"
vercel env add STRIPE_WEBHOOK_SECRET production <<< "$STRIPE_WEBHOOK"
vercel env add GROK_API_KEY production <<< "$GROK_KEY"

echo "✅ Vercel env vars set (7)."
echo ""
echo "🚀 All secrets configured (34 Supabase + 6 Fly.io + 7 Vercel). Run './scripts/deploy.sh' to deploy."

#!/usr/bin/env bash
# deploy/deploy.sh — one-shot VPS deploy for Khepra Protocol
#
# Run on Hostinger VPS (187.124.225.91) as:
#   cd /opt/khepra && bash deploy/deploy.sh
#
# Or from local machine via SSH:
#   ssh root@187.124.225.91 "cd /opt/khepra && git pull && bash deploy/deploy.sh"

set -euo pipefail

COMPOSE_FILE="deploy/docker-compose.vps.yml"
ENV_FILE="deploy/.env.vps"

echo "╔══════════════════════════════════════════════════════╗"
echo "║        KHEPRA PROTOCOL — VPS DEPLOY                 ║"
echo "╚══════════════════════════════════════════════════════╝"

# 1. Pull latest from GitHub
echo ""
echo "▶ Pulling latest from GitHub..."
git pull origin main

# 2. Verify .env exists
if [[ ! -f "$ENV_FILE" ]]; then
  echo ""
  echo "❌  Missing $ENV_FILE — copy deploy/.env.vps.example and fill in secrets."
  echo "    cp deploy/.env.vps.example deploy/.env.vps && nano deploy/.env.vps"
  exit 1
fi

# 3. Build and bring up
echo ""
echo "▶ Building Docker images..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" build --no-cache sekhem-gateway

echo ""
echo "▶ Bringing up services..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d

# 4. Health check
echo ""
echo "▶ Waiting for SEKHEM gateway to become healthy..."
sleep 10

HEALTH=$(docker compose -f "$COMPOSE_FILE" exec sekhem-gateway curl -sf http://localhost:9090/health 2>/dev/null || echo "UNHEALTHY")
if [[ "$HEALTH" == "UNHEALTHY" ]]; then
  echo "⚠️  Gateway not yet healthy — check logs:"
  echo "   docker compose -f $COMPOSE_FILE logs sekhem-gateway"
else
  echo "✅  SEKHEM gateway is healthy: $HEALTH"
fi

echo ""
echo "▶ Service status:"
docker compose -f "$COMPOSE_FILE" ps

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Deployment complete.                                ║"
echo "║                                                      ║"
echo "║  Endpoints live at:                                  ║"
echo "║    https://mcp.souhimbou.ai/health                  ║"
echo "║    https://gateway.souhimbou.ai/health              ║"
echo "║    https://gateway.souhimbou.ai/api/v1/scan/agent   ║"
echo "╚══════════════════════════════════════════════════════╝"

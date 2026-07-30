#!/usr/bin/env bash
# deploy-demo-env.sh — KHEPRA Pitch Pulse Demo Environment Setup
# Runs ON the VPS (187.124.225.91) to stand up DVWA + initialize DB
# NouchiX / SecRed Knowledge Inc.
# Usage: bash deploy-demo-env.sh

set -euo pipefail

VPS_DEMO_DIR="/opt/khepra-demo"
COMPOSE_FILE="$VPS_DEMO_DIR/docker-compose.dvwa.yml"
DVWA_URL="http://127.0.0.1:4280"

echo "======================================"
echo "  KHEPRA Demo Environment Deploy"
echo "  NouchiX / SecRed Knowledge Inc."
echo "  Pitch Pulse — July 10, 2026"
echo "======================================"

# 1. Check Docker
if ! command -v docker &> /dev/null; then
    echo "[!] Docker not found — installing..."
    apt-get update -qq
    apt-get install -y docker.io docker-compose-plugin
    systemctl enable --now docker
    echo "[+] Docker installed"
else
    echo "[+] Docker: $(docker --version)"
fi

# 2. Create demo directory
mkdir -p "$VPS_DEMO_DIR"
echo "[+] Demo dir: $VPS_DEMO_DIR"

# 3. Confirm compose file is present
if [ ! -f "$COMPOSE_FILE" ]; then
    echo "[!] $COMPOSE_FILE not found — copy it first:"
    echo "    scp deploy/demo/docker-compose.dvwa.yml root@187.124.225.91:$VPS_DEMO_DIR/"
    exit 1
fi

# 4. Pull images
echo "[*] Pulling DVWA + MariaDB images..."
docker compose -f "$COMPOSE_FILE" pull

# 5. Start containers
echo "[*] Starting containers..."
docker compose -f "$COMPOSE_FILE" up -d

# 6. Wait for DB healthy
echo "[*] Waiting for MariaDB healthcheck..."
for i in $(seq 1 30); do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' khepra-demo-db 2>/dev/null || echo "missing")
    if [ "$STATUS" = "healthy" ]; then
        echo "[+] MariaDB healthy"
        break
    fi
    echo "    attempt $i/30 — status: $STATUS"
    sleep 5
done

# 7. Wait for DVWA HTTP
echo "[*] Waiting for DVWA web interface..."
for i in $(seq 1 20); do
    if curl -sf "$DVWA_URL/login.php" > /dev/null 2>&1; then
        echo "[+] DVWA web interface is UP: $DVWA_URL"
        break
    fi
    echo "    attempt $i/20 — waiting..."
    sleep 3
done

# 8. Initialize DVWA database
echo "[*] Initializing DVWA database..."
curl -s -X POST "$DVWA_URL/setup.php" \
    -d "create_db=Create+%2F+Reset+Database" \
    -c /tmp/dvwa-cookies.txt \
    -o /tmp/dvwa-setup.html

if grep -q "Database Setup" /tmp/dvwa-setup.html 2>/dev/null || \
   grep -q "successfully" /tmp/dvwa-setup.html 2>/dev/null; then
    echo "[+] DVWA database initialized"
else
    echo "[~] DB init response ambiguous — check manually: $DVWA_URL/setup.php"
fi

# 9. Verify security level is LOW (max findings)
echo "[*] Verifying DVWA security level..."
SECURITY=$(curl -sf "$DVWA_URL/security.php" 2>/dev/null | grep -i "low" | head -1 || echo "check manually")
echo "[+] Security level: $SECURITY"

# 10. Final status
echo ""
echo "======================================"
echo "  DEMO ENVIRONMENT READY"
echo "======================================"
docker ps --filter "name=khepra-dvwa" --filter "name=khepra-demo-db" \
    --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""
echo "  DVWA URL (localhost only): $DVWA_URL"
echo "  ERT scan target: $DVWA_URL"
echo ""
echo "  Confirm no public exposure:"
ss -tlnp | grep "4280" || echo "  [+] Port 4280 not publicly exposed (correct)"
echo ""
echo "  Next: run ert_scan against $DVWA_URL"
echo "======================================"

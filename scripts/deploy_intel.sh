#!/bin/bash
set -e

# Khepra Intel Deployment Script
# Deploys the MITRE-Cyber-Security-CVE-Database for the Commando Autopilot.

DATA_DIR="data/cve-database"
REPO_URL="https://github.com/MITRE-Cyber-Security-CVE-Database/mitre-cve-database.git"

echo "[KHEPRA] Initializing Enterprise Threat Intelligence Database..."

# Ensure data directory exists
mkdir -p data

if [ -d "$DATA_DIR" ]; then
    echo "[KHEPRA] Database found at $DATA_DIR. Updating signal intelligence..."
    cd "$DATA_DIR"
    git pull
else
    echo "[KHEPRA] Database not found. Establishing link to MITRE Command..."
    git clone --depth 1 "$REPO_URL" "$DATA_DIR"
fi

# Run the repository's native fetch script if available to get latest NVD/CISA data
# (As described in the repository README provided by the user)
if [ -f "$DATA_DIR/fetch-cve-data.sh" ]; then
    echo "[KHEPRA] Executing Multi-Source Aggregation (NVD/CISA/Tenable)..."
    cd "$DATA_DIR"
    chmod +x fetch-cve-data.sh
    ./fetch-cve-data.sh
else
    echo "[WARNING] Fetch script not found. Using raw repo data."
fi

echo "[SUCCESS] Khepra Commando is now ARMED with global vulnerability data."

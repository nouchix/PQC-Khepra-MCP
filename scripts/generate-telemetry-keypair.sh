#!/bin/bash
# Generate Dilithium3 Keypair for Telemetry Signing
# This creates the PQC keypair used to sign telemetry beacons (anti-spoofing)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="$PROJECT_ROOT/telemetry-keys"

echo "=========================================="
echo "KHEPRA Telemetry Keypair Generator"
echo "=========================================="
echo ""

# Create keys directory
mkdir -p "$KEYS_DIR"

# Check if adinkhepra binary exists
if [ ! -f "$PROJECT_ROOT/bin/adinkhepra.exe" ] && [ ! -f "$PROJECT_ROOT/bin/adinkhepra" ]; then
    echo "[ERROR] adinkhepra binary not found. Please build first:"
    echo "  go build -o bin/adinkhepra.exe ./cmd/adinkhepra/*.go"
    exit 1
fi

# Generate keypair
echo "[1/3] Generating Dilithium3 keypair..."
PRIV_KEY_PATH="$KEYS_DIR/khepra-telemetry-v1"
if [ -f "$PROJECT_ROOT/bin/adinkhepra.exe" ]; then
    "$PROJECT_ROOT/bin/adinkhepra.exe" keygen \
        --comment "khepra-telemetry-v1" \
        --out "$PRIV_KEY_PATH"
else
    "$PROJECT_ROOT/bin/adinkhepra" keygen \
        --comment "khepra-telemetry-v1" \
        --out "$PRIV_KEY_PATH"
fi

echo ""
echo "[2/3] Converting private key to hex..."

# Read private key and convert to hex (for embedding in Dockerfile)
# adinkhepra generates files with _dilithium suffix for Dilithium keys
DILITHIUM_KEY="${PRIV_KEY_PATH}_dilithium"
if [ -f "$DILITHIUM_KEY" ]; then
    # Convert to hex (remove newlines)
    PRIV_KEY_HEX=$(cat "$DILITHIUM_KEY" | xxd -p | tr -d '\n')

    # Save to .env file for Docker builds
    echo "TELEMETRY_PRIVATE_KEY=$PRIV_KEY_HEX" > "$KEYS_DIR/.env"

    echo "[INFO] Private key hex saved to: $KEYS_DIR/.env"
    echo "[INFO] Key size: $(cat "$DILITHIUM_KEY" | wc -c) bytes"
else
    echo "[ERROR] Dilithium private key file not found at: $DILITHIUM_KEY"
    ls -la "$KEYS_DIR/"
    exit 1
fi

echo ""
echo "[3/3] Verifying keypair..."
echo "[INFO] Public key:  $DILITHIUM_KEY.pub"
echo "[INFO] Private key: $DILITHIUM_KEY"
echo "[INFO] Hex key (for Docker): $KEYS_DIR/.env"

echo ""
echo "=========================================="
echo "✅ Telemetry Keypair Generated!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Build Docker image with telemetry:"
echo "   source $KEYS_DIR/.env"
echo "   docker build --build-arg TELEMETRY_PRIVATE_KEY=\$TELEMETRY_PRIVATE_KEY \\"
echo "     -f Dockerfile.ironbank -t khepra:ironbank-telemetry ."
echo ""
echo "2. Deploy telemetry server with public key:"
echo "   export KHEPRA_TELEMETRY_PUBLIC_KEY=\$(cat $KEYS_DIR/khepra-telemetry-v1.pub | xxd -p | tr -d '\\n')"
echo ""
echo "⚠️  SECURITY: Keep the private key secure! It's used to prevent telemetry spoofing."
echo ""

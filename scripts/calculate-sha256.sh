#!/bin/bash
# SHA256 Hash Calculator for Iron Bank Hardening Manifest
# This script calculates SHA256 hashes for all resources listed in hardening_manifest.yaml

set -euo pipefail

echo "========================================="
echo "Iron Bank SHA256 Hash Calculator"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Create temporary directory for downloads
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

echo -e "${YELLOW}Temporary directory: ${TEMP_DIR}${NC}"
echo ""

# Function to download and hash
download_and_hash() {
    local url=$1
    local filename=$2
    local output_file="${TEMP_DIR}/${filename}"

    echo -e "${YELLOW}Processing: ${filename}${NC}"
    echo "  URL: ${url}"

    # Download file
    if curl -fsSL -o "${output_file}" "${url}"; then
        # Calculate SHA256
        if command -v sha256sum &> /dev/null; then
            hash=$(sha256sum "${output_file}" | awk '{print $1}')
        elif command -v shasum &> /dev/null; then
            hash=$(shasum -a 256 "${output_file}" | awk '{print $1}')
        else
            echo -e "${RED}  ERROR: No SHA256 tool found (sha256sum or shasum)${NC}"
            return 1
        fi

        echo -e "${GREEN}  SHA256: ${hash}${NC}"
        echo ""

        # Store result
        echo "${filename}|${hash}" >> "${TEMP_DIR}/hashes.txt"
    else
        echo -e "${RED}  ERROR: Failed to download${NC}"
        echo ""
        return 1
    fi
}

# Create source tarball from current repository
echo -e "${YELLOW}Step 1: Creating source tarball${NC}"
cd "$(dirname "$0")/.."
SOURCE_TARBALL="khepra-source-v1.0.0.tar.gz"

# Create tarball excluding sensitive files
tar --exclude='.git' \
    --exclude='bin' \
    --exclude='*.exe' \
    --exclude='*.key' \
    --exclude='*.pem' \
    --exclude='*.sealed' \
    --exclude='*.license' \
    --exclude='data/cve-database' \
    --exclude='tools/spiderfoot' \
    --exclude='node_modules' \
    --exclude='web' \
    -czf "${TEMP_DIR}/${SOURCE_TARBALL}" .

if [ -f "${TEMP_DIR}/${SOURCE_TARBALL}" ]; then
    if command -v sha256sum &> /dev/null; then
        source_hash=$(sha256sum "${TEMP_DIR}/${SOURCE_TARBALL}" | awk '{print $1}')
    elif command -v shasum &> /dev/null; then
        source_hash=$(shasum -a 256 "${TEMP_DIR}/${SOURCE_TARBALL}" | awk '{print $1}')
    fi
    echo -e "${GREEN}  Source tarball SHA256: ${source_hash}${NC}"
    echo "${SOURCE_TARBALL}|${source_hash}" >> "${TEMP_DIR}/hashes.txt"
else
    echo -e "${RED}  ERROR: Failed to create source tarball${NC}"
    exit 1
fi
echo ""

# Download and hash Go dependencies
echo -e "${YELLOW}Step 2: Downloading and hashing Go dependencies${NC}"
echo ""

download_and_hash \
    "https://proxy.golang.org/github.com/cloudflare/circl/@v/v1.6.1.zip" \
    "circl-v1.6.1.zip"

download_and_hash \
    "https://proxy.golang.org/golang.org/x/crypto/@v/v0.46.0.zip" \
    "golang-crypto-v0.46.0.zip"

download_and_hash \
    "https://proxy.golang.org/golang.org/x/sys/@v/v0.39.0.zip" \
    "golang-sys-v0.39.0.zip"

download_and_hash \
    "https://proxy.golang.org/tailscale.com/@v/v1.92.3.zip" \
    "tailscale-v1.92.3.zip"

download_and_hash \
    "https://proxy.golang.org/github.com/xuri/excelize/v2/@v/v2.10.0.zip" \
    "excelize-v2.10.0.zip"

download_and_hash \
    "https://proxy.golang.org/github.com/fsnotify/fsnotify/@v/v1.9.0.zip" \
    "fsnotify-v1.9.0.zip"

download_and_hash \
    "https://proxy.golang.org/github.com/mikesmitty/edkey/@v/v0.0.0-20170222072505-3356ea4e686a.zip" \
    "edkey-20170222072505-3356ea4e686a.zip"

# Generate YAML snippet for hardening_manifest.yaml
echo ""
echo "========================================="
echo "YAML Snippet for hardening_manifest.yaml"
echo "========================================="
echo ""
echo "Copy and paste the following into hardening_manifest.yaml:"
echo ""
echo "---"
echo "resources:"

while IFS='|' read -r filename hash; do
    case "${filename}" in
        khepra-source-v1.0.0.tar.gz)
            echo "  - url: https://github.com/EtherVerseCodeMate/giza-cyber-shield/archive/refs/tags/v1.0.0.tar.gz"
            echo "    filename: ${filename}"
            echo "    validation:"
            echo "      type: sha256"
            echo "      value: ${hash}"
            echo ""
            ;;
        circl-v1.6.1.zip)
            echo "  - url: https://proxy.golang.org/github.com/cloudflare/circl/@v/v1.6.1.zip"
            echo "    filename: ${filename}"
            echo "    validation:"
            echo "      type: sha256"
            echo "      value: ${hash}"
            echo ""
            ;;
        golang-crypto-v0.46.0.zip)
            echo "  - url: https://proxy.golang.org/golang.org/x/crypto/@v/v0.46.0.zip"
            echo "    filename: ${filename}"
            echo "    validation:"
            echo "      type: sha256"
            echo "      value: ${hash}"
            echo ""
            ;;
        golang-sys-v0.39.0.zip)
            echo "  - url: https://proxy.golang.org/golang.org/x/sys/@v/v0.39.0.zip"
            echo "    filename: ${filename}"
            echo "    validation:"
            echo "      type: sha256"
            echo "      value: ${hash}"
            echo ""
            ;;
        tailscale-v1.92.3.zip)
            echo "  - url: https://proxy.golang.org/tailscale.com/@v/v1.92.3.zip"
            echo "    filename: ${filename}"
            echo "    validation:"
            echo "      type: sha256"
            echo "      value: ${hash}"
            echo ""
            ;;
        excelize-v2.10.0.zip)
            echo "  - url: https://proxy.golang.org/github.com/xuri/excelize/v2/@v/v2.10.0.zip"
            echo "    filename: ${filename}"
            echo "    validation:"
            echo "      type: sha256"
            echo "      value: ${hash}"
            echo ""
            ;;
        fsnotify-v1.9.0.zip)
            echo "  - url: https://proxy.golang.org/github.com/fsnotify/fsnotify/@v/v1.9.0.zip"
            echo "    filename: ${filename}"
            echo "    validation:"
            echo "      type: sha256"
            echo "      value: ${hash}"
            echo ""
            ;;
        edkey-20170222072505-3356ea4e686a.zip)
            echo "  - url: https://proxy.golang.org/github.com/mikesmitty/edkey/@v/v0.0.0-20170222072505-3356ea4e686a.zip"
            echo "    filename: ${filename}"
            echo "    validation:"
            echo "      type: sha256"
            echo "      value: ${hash}"
            echo ""
            ;;
    esac
done < "${TEMP_DIR}/hashes.txt"

echo "---"
echo ""
echo -e "${GREEN}Hash calculation complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Update hardening_manifest.yaml with the SHA256 values above"
echo "  2. Create git tag: git tag -a v1.0.0 -m 'Release v1.0.0'"
echo "  3. Create GitHub release and upload source tarball"
echo "  4. Update hardening_manifest.yaml URL to match GitHub release"
echo "  5. Submit to Iron Bank GitLab repository"
echo ""

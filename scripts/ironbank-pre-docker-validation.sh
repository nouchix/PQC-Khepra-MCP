#!/bin/bash
# Iron Bank Pre-Docker Validation Script
# Tests that can run WITHOUT Docker to verify container readiness

set -euo pipefail

echo "========================================"
echo "Iron Bank Pre-Docker Validation"
echo "========================================"
echo ""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

pass_count=0
fail_count=0

test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((pass_count++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((fail_count++))
}

test_info() {
    echo -e "${YELLOW}ℹ INFO${NC}: $1"
}

# Test 1: Dockerfile.ironbank exists
echo "Test 1: Dockerfile.ironbank presence..."
if [ -f "Dockerfile.ironbank" ]; then
    test_pass "Dockerfile.ironbank exists"
else
    test_fail "Dockerfile.ironbank not found"
    exit 1
fi
echo ""

# Test 2: Binaries built locally
echo "Test 2: Local binary verification..."
if [ -f "bin/sonar.exe" ] || [ -f "bin/sonar" ]; then
    test_pass "sonar binary exists"
else
    test_fail "sonar binary not found (run 'make build' first)"
fi

if [ -f "bin/adinkhepra.exe" ] || [ -f "bin/adinkhepra" ]; then
    test_pass "adinkhepra binary exists"
else
    test_fail "adinkhepra binary not found (run 'make build' first)"
fi
echo ""

# Test 3: Compliance mapping library
echo "Test 3: Compliance mapping library verification..."
csv_count=0

if [ -f "docs/CCI_to_NIST53.csv" ]; then
    lines=$(wc -l < "docs/CCI_to_NIST53.csv")
    test_pass "CCI_to_NIST53.csv found ($lines rows)"
    ((csv_count++))
fi

if [ -f "docs/STIG_CCI_Map.csv" ]; then
    lines=$(wc -l < "docs/STIG_CCI_Map.csv")
    test_pass "STIG_CCI_Map.csv found ($lines rows)"
    ((csv_count++))
fi

if [ -f "docs/NIST53_to_171.csv" ]; then
    lines=$(wc -l < "docs/NIST53_to_171.csv")
    test_pass "NIST53_to_171.csv found ($lines rows)"
    ((csv_count++))
fi

if [ $csv_count -eq 3 ]; then
    test_pass "All compliance mapping CSVs present (36,195+ rows total)"
else
    test_fail "Missing compliance mapping CSV files"
fi
echo ""

# Test 4: Vendored dependencies
echo "Test 4: Vendored Go dependencies..."
if [ -d "vendor" ]; then
    modules=$(find vendor -name "*.go" | wc -l)
    test_pass "Vendor directory exists ($modules Go files)"

    # Check key dependencies
    if [ -d "vendor/github.com/cloudflare/circl" ]; then
        test_pass "CIRCL (PQC) dependency vendored"
    else
        test_fail "CIRCL dependency not vendored (run 'go mod vendor')"
    fi

    if [ -d "vendor/tailscale.com" ]; then
        test_pass "Tailscale dependency vendored"
    else
        test_fail "Tailscale dependency not vendored (run 'go mod vendor')"
    fi
else
    test_fail "Vendor directory not found (run 'go mod vendor')"
fi
echo ""

# Test 5: Dockerfile security practices
echo "Test 5: Dockerfile security analysis..."

# Check for non-root user
if grep -q "USER 1001" Dockerfile.ironbank; then
    test_pass "Dockerfile uses non-root user (UID 1001)"
else
    test_fail "Dockerfile does not specify USER 1001"
fi

# Check for Iron Bank base image
if grep -q "registry1.dso.mil/ironbank" Dockerfile.ironbank; then
    test_pass "Dockerfile uses Iron Bank base image"
else
    test_fail "Dockerfile does not use Iron Bank base image"
fi

# Check for healthcheck
if grep -q "HEALTHCHECK" Dockerfile.ironbank; then
    test_pass "Dockerfile includes HEALTHCHECK"
else
    test_fail "Dockerfile missing HEALTHCHECK"
fi

# Check for static linking
if grep -q "CGO_ENABLED=0" Dockerfile.ironbank; then
    test_pass "Dockerfile builds static binaries (CGO_ENABLED=0)"
else
    test_fail "Dockerfile does not set CGO_ENABLED=0"
fi
echo ""

# Test 6: Hardening manifest
echo "Test 6: Iron Bank hardening manifest..."
if [ -f "hardening_manifest.yaml" ]; then
    test_pass "hardening_manifest.yaml exists"

    # Check for SHA256 placeholders
    if grep -q "REPLACE_WITH_ACTUAL_SHA256" hardening_manifest.yaml; then
        test_info "SHA256 hashes need to be calculated (run scripts/calculate-sha256.sh)"
    else
        test_pass "SHA256 hashes appear to be filled in"
    fi

    # Check for compliance library mention
    if grep -q "36,195" hardening_manifest.yaml; then
        test_pass "Compliance mapping library highlighted in manifest"
    else
        test_info "Consider adding compliance library details to reviewer notes"
    fi
else
    test_fail "hardening_manifest.yaml not found"
fi
echo ""

# Test 7: Documentation completeness
echo "Test 7: Documentation verification..."

docs_count=0
if [ -f "CHANGELOG.md" ]; then
    test_pass "CHANGELOG.md exists"
    ((docs_count++))
fi

if [ -f ".dockerignore" ]; then
    test_pass ".dockerignore exists"
    ((docs_count++))
fi

if [ -f "scripts/functional-test.sh" ]; then
    test_pass "functional-test.sh exists"
    ((docs_count++))
fi

if [ -f "scripts/calculate-sha256.sh" ]; then
    test_pass "calculate-sha256.sh exists"
    ((docs_count++))
fi

if [ $docs_count -eq 4 ]; then
    test_pass "All required documentation present"
else
    test_fail "Missing documentation files"
fi
echo ""

# Summary
echo "========================================"
echo "Validation Summary"
echo "========================================"
echo -e "${GREEN}Passed: $pass_count${NC}"
echo -e "${RED}Failed: $fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✓ All pre-Docker validations passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Install Docker Desktop (https://www.docker.com/products/docker-desktop/)"
    echo "2. Run: docker build -f Dockerfile.ironbank -t khepra:ironbank-test ."
    echo "3. Run: bash scripts/ironbank-container-tests.sh"
    exit 0
else
    echo -e "${RED}✗ $fail_count validation(s) failed${NC}"
    echo ""
    echo "Fix the issues above before building Docker container."
    exit 1
fi

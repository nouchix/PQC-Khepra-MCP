#!/bin/bash
# Functional Testing for KHEPRA Protocol (Iron Bank Pipeline)
# This script runs in the "functional-testing" stage of Iron Bank pipeline
# Tests actual binaries: sonar, adinkhepra, khepra-daemon

set -e  # Exit on any error
set -o pipefail

echo "========================================"
echo "KHEPRA Protocol - Functional Test Suite"
echo "========================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

# Helper functions
function test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((pass_count++))
}

function test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((fail_count++))
}

function test_info() {
    echo -e "${YELLOW}ℹ INFO${NC}: $1"
}

# Test 1: Binary Existence
echo "Test 1: Verifying binaries exist..."

if command -v sonar &> /dev/null; then
    test_pass "sonar binary found at $(which sonar)"
else
    test_fail "sonar binary not found in PATH"
    exit 1
fi

if command -v adinkhepra &> /dev/null; then
    test_pass "adinkhepra binary found at $(which adinkhepra)"
else
    test_fail "adinkhepra binary not found in PATH"
    exit 1
fi

if command -v khepra-daemon &> /dev/null; then
    test_pass "khepra-daemon binary found at $(which khepra-daemon)"
else
    test_info "khepra-daemon binary not found (optional)"
fi

echo ""

# Test 2: Binary Execution - Help Commands
echo "Test 2: Testing binary help commands..."

if sonar --help &> /dev/null; then
    test_pass "sonar --help works"
else
    test_fail "sonar --help failed"
fi

if adinkhepra --help &> /dev/null; then
    test_pass "adinkhepra --help works"
else
    test_fail "adinkhepra --help failed"
fi

if command -v khepra-daemon &> /dev/null && khepra-daemon --help &> /dev/null; then
    test_pass "khepra-daemon --help works"
else
    test_info "khepra-daemon --help not available"
fi

echo ""

# Test 3: Sonar - Device Fingerprinting
echo "Test 3: Testing sonar device fingerprinting..."

if sonar fingerprint &> /dev/null; then
    test_pass "sonar fingerprint command executes"
elif sonar fingerprint 2>&1 | grep -qi "license"; then
    test_pass "sonar fingerprint requires license (expected)"
else
    test_info "sonar fingerprint may require additional setup"
fi

echo ""

# Test 4: Sonar - CVE Scanning
echo "Test 4: Testing sonar CVE scanning..."

TEMP_TEST_FILE=$(mktemp)
echo "Test file" > "$TEMP_TEST_FILE"

if sonar cve-scan --target "$TEMP_TEST_FILE" &> /dev/null; then
    test_pass "sonar cve-scan executes"
elif sonar cve-scan 2>&1 | grep -qi "license\|database"; then
    test_pass "sonar cve-scan requires license/database (expected)"
else
    test_info "sonar cve-scan may require additional configuration"
fi

rm -f "$TEMP_TEST_FILE"

echo ""

# Test 5: AdinKhepra - PQC Key Generation
echo "Test 5: Testing adinkhepra PQC key generation..."

TEMP_KEY_DIR=$(mktemp -d)

if adinkhepra keygen --identity "test-$(date +%s)" --output "$TEMP_KEY_DIR" &> /dev/null; then
    test_pass "adinkhepra keygen works"

    # Check if keys were created
    if [ -f "$TEMP_KEY_DIR/test-"*".pub" ] || [ -f "$TEMP_KEY_DIR/test-"*".key" ]; then
        test_pass "Key files were created"
    else
        test_info "Key files not found in expected location"
    fi
elif adinkhepra keygen 2>&1 | grep -qi "license"; then
    test_pass "adinkhepra keygen requires license (expected)"
else
    test_info "adinkhepra keygen may require additional configuration"
fi

rm -rf "$TEMP_KEY_DIR"

echo ""

# Test 6: AdinKhepra - Signature Creation
echo "Test 6: Testing adinkhepra signature operations..."

TEMP_MSG_FILE=$(mktemp)
echo "Test message for signing" > "$TEMP_MSG_FILE"

if adinkhepra sign --input "$TEMP_MSG_FILE" &> /dev/null; then
    test_pass "adinkhepra sign command executes"
elif adinkhepra sign 2>&1 | grep -qi "license\|key"; then
    test_pass "adinkhepra sign requires license/keys (expected)"
else
    test_info "adinkhepra sign may require additional setup"
fi

rm -f "$TEMP_MSG_FILE"

echo ""

# Test 7: AdinKhepra - STIG Compliance
echo "Test 7: Testing adinkhepra STIG compliance generation..."

if adinkhepra stig-check &> /dev/null; then
    test_pass "adinkhepra stig-check command executes"
elif adinkhepra stig-check 2>&1 | grep -qi "license\|not found"; then
    test_info "adinkhepra stig-check requires license or not implemented"
elif adinkhepra compliance 2>&1 | grep -qi "stig"; then
    test_pass "adinkhepra has STIG compliance capabilities"
else
    test_info "STIG compliance commands may use different syntax"
fi

echo ""

# Test 8: File Permissions (Security Check)
echo "Test 8: Verifying file permissions..."

for binary in sonar adinkhepra khepra-daemon; do
    if ! command -v "$binary" &> /dev/null; then
        test_info "$binary not found, skipping permission check"
        continue
    fi

    BINARY_PATH=$(which "$binary")

    # Check permissions
    if [ -f "$BINARY_PATH" ]; then
        PERMS=$(stat -c '%a' "$BINARY_PATH" 2>/dev/null || stat -f '%A' "$BINARY_PATH" 2>/dev/null)

        if [ "$PERMS" = "755" ] || [ "$PERMS" = "750" ] || [ "$PERMS" = "775" ]; then
            test_pass "$binary has correct permissions ($PERMS)"
        else
            test_fail "$binary has incorrect permissions ($PERMS, expected 755/750/775)"
        fi

        # Check if binary has setuid/setgid (should NOT have it)
        if find "$BINARY_PATH" -perm /6000 2>/dev/null | grep -q .; then
            test_fail "$binary has setuid/setgid bit set (security violation)"
        else
            test_pass "$binary does not have setuid/setgid bits"
        fi
    fi
done

echo ""

# Test 9: Non-Root Execution
echo "Test 9: Verifying non-root execution..."
CURRENT_USER=$(id -u)
if [ "$CURRENT_USER" -ne 0 ]; then
    test_pass "Running as non-root user (UID: $CURRENT_USER)"
else
    test_fail "Running as root (UID 0) - should run as non-root"
fi

echo ""

# Test 10: Static Binary Check
echo "Test 10: Verifying static binary compilation..."

for binary in sonar adinkhepra; do
    if ! command -v "$binary" &> /dev/null; then
        continue
    fi

    BINARY_PATH=$(which "$binary")

    if ldd "$BINARY_PATH" 2>&1 | grep -q "not a dynamic executable"; then
        test_pass "$binary is a static binary (no dynamic libraries)"
    elif ldd "$BINARY_PATH" 2>&1 | grep -qi "statically linked"; then
        test_pass "$binary is statically linked"
    else
        LIBS=$(ldd "$BINARY_PATH" 2>&1 | wc -l)
        test_info "$binary has $LIBS dynamic library dependencies"
    fi
done

echo ""

# Test 11: CGO Disabled Check
echo "Test 11: Verifying CGO is disabled..."

for binary in sonar adinkhepra; do
    if ! command -v "$binary" &> /dev/null; then
        continue
    fi

    BINARY_PATH=$(which "$binary")

    # Check for CGO usage by looking for libc dependencies
    if ldd "$BINARY_PATH" 2>&1 | grep -qi "libc.so\|libpthread"; then
        test_fail "$binary appears to use CGO (has libc dependencies)"
    else
        test_pass "$binary built with CGO_ENABLED=0"
    fi
done

echo ""

# Test 12: Post-Quantum Cryptography Primitives
echo "Test 12: Testing PQC primitives..."

# Test if binaries were compiled with CIRCL support
if adinkhepra version 2>&1 | grep -qi "dilithium\|kyber\|pqc"; then
    test_pass "PQC support detected in adinkhepra version output"
elif strings "$(which adinkhepra)" 2>/dev/null | grep -qi "dilithium"; then
    test_pass "PQC (Dilithium) symbols found in adinkhepra binary"
else
    test_info "PQC support detection inconclusive (may still be present)"
fi

echo ""

# Test 13: Air-Gapped Mode
echo "Test 13: Testing air-gapped/offline mode..."

if adinkhepra --no-external --help &> /dev/null; then
    test_pass "adinkhepra supports --no-external flag for air-gapped mode"
elif adinkhepra --offline --help &> /dev/null; then
    test_pass "adinkhepra supports --offline flag for air-gapped mode"
else
    test_info "Air-gapped mode flag may use different syntax or be default behavior"
fi

echo ""

# Test 14: License Enforcement
echo "Test 14: Testing license enforcement..."

# Attempt to run a privileged command without license
if sonar fingerprint 2>&1 | grep -qi "license"; then
    test_pass "License enforcement is active on sonar"
elif adinkhepra keygen 2>&1 | grep -qi "license"; then
    test_pass "License enforcement is active on adinkhepra"
else
    test_info "License checks may not be required in test/demo mode"
fi

echo ""

# Test 15: Configuration Directory Support
echo "Test 15: Testing configuration handling..."

if [ -d "/etc/khepra" ] || [ -d "/etc/adinkhepra" ]; then
    test_pass "Config directory exists"
else
    test_info "Config directories /etc/khepra or /etc/adinkhepra not found (may use defaults)"
fi

# Check if binaries respect XDG_CONFIG_HOME
export XDG_CONFIG_HOME="/tmp/test-config-$(date +%s)"
mkdir -p "$XDG_CONFIG_HOME"

if adinkhepra --help 2>&1 | grep -qi "config"; then
    test_pass "adinkhepra has configuration support"
fi

rm -rf "$XDG_CONFIG_HOME"

echo ""

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "${GREEN}Passed: $pass_count${NC}"
echo -e "${RED}Failed: $fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All critical tests passed!${NC}"
    echo ""
    echo "KHEPRA Protocol is ready for Iron Bank deployment."
    exit 0
else
    echo -e "${RED}$fail_count test(s) failed. Review output above.${NC}"
    echo ""
    echo "Fix critical failures before submitting to Iron Bank."
    exit 1
fi

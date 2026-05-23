#!/bin/bash
# Validation Test Suite Runner
#
# This script runs the validation test suite to ensure CI/CD validators work correctly.
# It tests both PASS (should succeed) and FAIL (should catch vulnerabilities) fixtures.

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/../fixtures"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Khepra Protocol Validation Test Suite             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to run test and check result
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_result="$3"  # "pass" or "fail"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    echo -n "  Testing: $test_name ... "

    if eval "$command" > /dev/null 2>&1; then
        actual_result="pass"
    else
        actual_result="fail"
    fi

    if [ "$actual_result" = "$expected_result" ]; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo -e "    ${YELLOW}Expected: $expected_result, Got: $actual_result${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# Test 1: Hardcoded Key Detection
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[1/3] Testing Hardcoded Key Detection${NC}"
echo "----------------------------------------"

# PASS: Clean files should not trigger detection
run_test "Clean crypto file (should pass)" \
    "! grep -rEi 'khepra-dev-key|aaru-realm-key|aten-realm-key' $FIXTURES_DIR/pass/clean_crypto.go" \
    "pass"

# FAIL: Hardcoded keys should be detected
run_test "Hardcoded dev key (should be detected)" \
    "grep -q 'khepra-dev-key' $FIXTURES_DIR/fail/hardcoded_keys.go" \
    "pass"

run_test "Hardcoded realm key (should be detected)" \
    "grep -q 'aaru-realm-key' $FIXTURES_DIR/fail/hardcoded_keys.go" \
    "pass"

run_test "Hardcoded aten key (should be detected)" \
    "grep -q 'aten-realm-key' $FIXTURES_DIR/fail/hardcoded_keys.go" \
    "pass"

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Test 2: SQL Injection Pattern Detection
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[2/3] Testing SQL Injection Pattern Detection${NC}"
echo "------------------------------------------------"

# PASS: Parameterized queries should not trigger detection
run_test "Safe parameterized queries (should pass)" \
    "! grep -n 'fmt.Sprintf.*SELECT\\|fmt.Sprintf.*INSERT\\|fmt.Sprintf.*UPDATE' $FIXTURES_DIR/pass/safe_database.go" \
    "pass"

# FAIL: String concatenation in SQL should be detected
run_test "SQL injection via fmt.Sprintf SELECT (should be detected)" \
    "grep -q 'fmt.Sprintf.*SELECT' $FIXTURES_DIR/fail/sql_injection.go" \
    "pass"

run_test "SQL injection via fmt.Sprintf UPDATE (should be detected)" \
    "grep -q 'fmt.Sprintf.*UPDATE' $FIXTURES_DIR/fail/sql_injection.go" \
    "pass"

run_test "SQL injection via fmt.Sprintf INSERT (should be detected)" \
    "grep -q 'fmt.Sprintf.*INSERT' $FIXTURES_DIR/fail/sql_injection.go" \
    "pass"

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Test 3: Command Injection Pattern Detection
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[3/3] Testing Command Injection Pattern Detection${NC}"
echo "---------------------------------------------------"

# PASS: Safe command execution should not trigger detection
run_test "Safe exec.Command usage (should pass)" \
    "! grep -n 'exec.Command.*fmt.Sprintf\\|exec.Command.*+' $FIXTURES_DIR/pass/safe_command.go" \
    "pass"

# FAIL: fmt.Sprintf in exec.Command should be detected
run_test "Command injection via fmt.Sprintf (should be detected)" \
    "grep -q 'fmt.Sprintf' $FIXTURES_DIR/fail/command_injection.go" \
    "pass"

run_test "Command injection via concatenation (should be detected)" \
    "grep -q 'operation.*+.*path' $FIXTURES_DIR/fail/command_injection.go" \
    "pass"

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Test 4: Secrets Detection
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[4/4] Testing Secrets Detection (Bonus)${NC}"
echo "----------------------------------------"

# FAIL: Hardcoded secrets should be detected
run_test "API key detection (should be detected)" \
    "grep -q 'sk_live_\\|api_key.*=.*\"' $FIXTURES_DIR/fail/exposed_secrets.go" \
    "pass"

run_test "Password detection (should be detected)" \
    "grep -qi 'password.*=.*\"' $FIXTURES_DIR/fail/exposed_secrets.go" \
    "pass"

run_test "Token detection (should be detected)" \
    "grep -qi 'token.*=.*\"' $FIXTURES_DIR/fail/exposed_secrets.go" \
    "pass"

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                     Test Summary                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Total Tests:  ${BLUE}$TOTAL_TESTS${NC}"
echo -e "  Passed:       ${GREEN}$PASSED_TESTS${NC}"
echo -e "  Failed:       ${RED}$FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ All validation tests passed!${NC}"
    echo -e "${GREEN}  The CI/CD validators are working correctly.${NC}"
    exit 0
else
    echo -e "${RED}✗ Some validation tests failed.${NC}"
    echo -e "${YELLOW}  Review the output above to identify issues.${NC}"
    exit 1
fi

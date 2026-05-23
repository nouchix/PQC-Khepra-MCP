# Validation Test Suite

This directory contains test cases for the CI/CD validation pipeline.

## Test Structure

```
tests/validation/
├── fixtures/
│   ├── pass/          # Files that should PASS validation
│   ├── fail/          # Files that should FAIL validation
│   └── samples/       # Sample data for testing
├── scripts/
│   └── run-validation-tests.sh
└── README.md
```

## Running Tests

```bash
# Run all validation tests
./tests/validation/scripts/run-validation-tests.sh

# Run specific test category
./tests/validation/scripts/run-validation-tests.sh security
./tests/validation/scripts/run-validation-tests.sh build-artifacts
```

## Test Categories

### 1. Build Artifact Validation
- Hardcoded key detection
- File synchronization checks
- Mock pattern detection

### 2. Security Scanning
- Secrets/credentials detection
- SQL injection pattern detection
- Command injection pattern detection

## Expected Behavior

**PASS fixtures**: Should complete validation without errors
**FAIL fixtures**: Should trigger validation failures (used to verify validators work correctly)

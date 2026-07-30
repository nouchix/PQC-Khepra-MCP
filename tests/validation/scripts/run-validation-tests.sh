#!/usr/bin/env bash
# Validation Test Suite Runner (TRL10)
#
# Drives the REAL security detector (tests/validation/detector.py) over labelled
# pass/fail fixtures and asserts no false negatives and no false positives.
# Pure Python (stdlib) — no Go/Node toolchain, so it cannot be broken by
# dependency or toolchain drift. Logic: tests/validation/run_validation.py.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../run_validation.py" "$@"

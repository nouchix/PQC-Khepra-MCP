#!/usr/bin/env bash
# Run tests without Go's cache
set -euo pipefail

go test -count=1 ./...

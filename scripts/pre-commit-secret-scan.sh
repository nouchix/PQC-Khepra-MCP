#!/bin/bash
# Pre-commit secret scanning hook powered by gitleaks & regex patterns
set -e

echo "🔍 Running pre-commit secret scan..."

if command -v gitleaks >/dev/null 2>&1; then
    gitleaks protect --staged --config .gitleaks.toml -v
else
    STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -v '\.env\.example' || true)
    if [ -n "$STAGED_FILES" ]; then
        if echo "$STAGED_FILES" | xargs grep -E '(sk_live_|sk-ant-api|cfut_|sbp_[a-f0-9]{40}|EYKsdy)' >/dev/null 2>&1; then
            echo "❌ ERROR: Potential API secret detected in staged files!"
            echo "Please remove the secret from staged files before committing."
            exit 1
        fi
    fi
fi

echo "✅ Pre-commit secret scan passed."

# History Scrub Report — PQC-Khepra-MCP

**Date:** 2026-07-24
**Scanner:** gitleaks 8.24.3, full history (76 scanned commits, 53 MB)
**Verdict: fresh-history extraction is REQUIRED for the public kernel repo.**
Real credentials exist in git history; redaction-in-place is not acceptable.
This satisfies the assessment step of ARCH-010 §4 condition 1 (khepra-trust-os
`docs/architecture/ARCH-010-convergence-and-public-split.md`).

## Findings: 24 total — 2 real, 22 synthetic

### Real (both were live in HEAD; fixed in this branch, ROTATION STILL REQUIRED)

| # | Location | What | Status |
|---|---|---|---|
| 1 | `public/console.html:320` (first landed in commit `0b5e03a4`) | Hardcoded MCP bearer token for `mcp.souhimbou.ai` (`kYIc…e7f848`) | Removed from HEAD — now runtime-supplied via `?mcpToken=` / `window.__DEMO_MCP_TOKEN`. **Token must be revoked server-side**: it shipped in a public-facing HTML file and lives in every clone's history |
| 2 | `pkg/compliance/sync.go:128` | Hardcoded `X-Khepra-Integrity` deployment-signing key for the STIG Viewer API (`2faf08c3…`) | Removed from HEAD — now read from `KHEPRA_STIGVIEWER_INTEGRITY_KEY` env var. **Key must be reissued** and the old value invalidated |

Rotation is not optional: fixing HEAD does not un-publish history. If this repo
has ever been public or cloned outside the org, treat both values as burned.

### Synthetic / false positives (22)

- `tests/validation/fixtures/fail/exposed_secrets.go` — deliberate fail-fixtures
  for the validator (JWT + PEM). Keep, but they must live only in the private
  repo or be clearly fixture-pathed in the kernel so scanners can allowlist.
- `pkg/gateway/layer2_auth_test.go`, `pkg/arsenal/arsenal_test.go` — test values
  (`khepra-test-key-12345`, `AKIA1234567890`).
- `pkg/mcp/scanner/{checks,findings}.go` — detector patterns/constants
  (`mlDSA65PrivKeyMin`, PEM header strings the scanner searches for).
- `pkg/dag/seed.go`, `pkg/mcp/dag_bridge.go`, `pkg/stig/pqc_stig.go` — algorithm
  identifiers (`ML-DSA-65-Dilithium3`) and import paths misread as keys.
- `pkg/souhimbou/probe_suite.go` — `alg:none` probe JWT (attack fixture).
- `src/components/discovery/SecureCredentialManager.tsx` — UI placeholder text
  (`-----BEGIN PRIVATE KEY-----` as a textarea placeholder).

## Consequences for the public kernel

1. The public repo **must start from a fresh-history extraction**
   (`scripts/extract_kernel.sh`) — never from this repo's history.
2. Before the extracted repo's first push: run gitleaks on the extraction and
   require zero findings (add it as a CI gate there).
3. Rotate finding #1 and #2 credentials regardless of extraction.
4. Re-run this scan whenever the extraction script's keep-list changes.

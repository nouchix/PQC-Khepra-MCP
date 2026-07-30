# Public Kernel Scope — Need-to-Know Strip Plan

**Date:** 2026-07-24
**Implements:** ARCH-010 §3–§4 (khepra-trust-os) — strip this repo to the minimum
credible open-source MCP kernel; everything else converges on the private
khepra-trust-os monorepo.

The rule is **need-to-know for a public audience**: a file stays public only if
an outside contributor needs it to build, run, audit, or extend the MCP kernel.
Product tools, commercial machinery, deployment internals, roadmap/memory docs,
and everything speculative is private by default.

## 1. KEEP-list (the public kernel)

| Path | Why public |
|---|---|
| `pkg/mcp/` **root only** (router, executor, manifest, sandbox, validation, transport, observability, security profiles, scope taxonomy, invocation tokens, signed audit log, call log) | The kernel itself |
| `pkg/crypto/` | PQC primitives (ML-DSA/ML-KEM wrappers) the kernel signs/verifies with |
| `pkg/types/`, minimal subset of `pkg/util/` | Shared types the kernel compiles against (trim to what `pkg/mcp` actually imports) |
| `cmd/khepra-mcp/` | The server binary (after decoupling — see §3) |
| `cmd/manifest-gen/`, `gen_manifest.go`, `manifest.json` schema docs | Tool-manifest authoring for third parties |
| `Dockerfile.mcp` | Reproducible kernel container |
| `llms-install.md`, MCP protocol/security docs (curated subset of `docs/`) | Adoption path |
| `SECURITY.md` (rewritten: disclosure policy only) | Responsible disclosure |
| Example tools: 2–3 **new** minimal reference tools (echo, file-hash, read-only HTTP GET) | Show the tool contract without shipping product tools |

## 2. STRIP-list (moves private to khepra-trust-os, or is deleted)

| Path | Disposition | Reason |
|---|---|---|
| `pkg/mcp/tools/` (26 files, the 72 product tools) | → private `core/` | Product surface; imports 12+ private engines (dag, lorentz, stig, nhi, ert, vuln, souhimbou, sca, ea, license, flight…) |
| `pkg/mcp/scanner/`, `pkg/mcp/legacy/` | → private / delete | Product scanner adapters; legacy code is noise for auditors |
| All other 70 `pkg/*` packages | → private `core/` per its README order | Product planes, commercial, long tail |
| All other 23 `cmd/*` binaries | → private | Operators, license issuance, ceremonies, agents |
| `MEMORY.md`, `Whitepaper.md`, `mcp-registry.json` internals, `adinkhepra.py`, `patch_validator.py`, `fix-*.go`, `check_desc.go` | → private / delete | Internal memory, roadmap, tooling — classic not-need-to-know |
| `aws-govcloud/`, `deploy/`, all non-MCP Dockerfiles (`fips`, `ironbank*`, `hub`, `dashboard`, `apiserver`, `mobile`, `phantom`), `docker-compose.yml` | → private `deploy/` | Deployment internals reveal customer architecture |
| `src/`, `packages/`, `public/` (Next.js UI + static consoles), `package.json`, next/postcss/eslint configs | → private / delete | Console (khepra-trust-os) is the only operator surface; static consoles were the direct-egress offenders |
| `adinkhepra_master*.pub` + `.json` | → private key-management docs | Public keys aren't secret, but ceremony artifacts invite questions the public repo shouldn't answer |
| `LICENSE` (KHEPRA Master License Agreement v3.0) | stays here (private repo) | The extracted kernel gets Apache-2.0 (§4) |
| `tests/validation/fixtures/fail/` secret fixtures | → private, or fixture-pathed + scanner-allowlisted | See scrub report |

Result: the kernel keeps roughly **4 of 75 packages and 2 of 25 binaries.**

## 3. Condition-3 decoupling spike (measured, not guessed)

Import analysis of `pkg/mcp` root (excluding `tools/`, `scanner/`, `legacy/`):
only **four** private packages are load-bearing, in six files —
`router.go` (flight, license, logging), `chain.go` (dag), `transport_http.go`
(dag), `dag_bridge.go` (dag), `signed_audit_log.go`, `manifest_store.go`.
`cmd/khepra-mcp` additionally pulls sekhem, agi, adinkra, config — those
assemblies move behind the same seams.

Define in a new `pkg/mcp/kernelports` package (no-op defaults in-package;
production implementations stay private and are injected at assembly):

```go
// Attestor anchors kernel events into an evidence store (private: pkg/dag+attest).
type Attestor interface {
    Attest(ctx context.Context, event Event) (NodeID string, err error)
}

// AuditSink receives signed audit records (private: pkg/audit / signed DAG log).
type AuditSink interface {
    Append(ctx context.Context, record AuditRecord) error
}

// LicenseChecker gates licensed capabilities (private: pkg/license).
// Kernel default: everything unlicensed-open (the OSS posture).
type LicenseChecker interface {
    Allow(feature string) bool
}

// FlightRecorder captures crash/flight telemetry (private: pkg/flight).
type FlightRecorder interface {
    Record(ctx context.Context, frame Frame)
}

// Logger is the kernel's structured logger seam (private: pkg/logging).
type Logger interface {
    Log(level string, msg string, kv ...any)
}
```

Spike exit criteria (blocking for any extraction):

1. `go build ./pkg/mcp/... ./cmd/khepra-mcp` succeeds with **zero** imports
   outside the KEEP-list (enforced by `extract_kernel.sh --verify`).
2. Kernel tests pass with the no-op implementations.
3. Private `core/` provides the production implementations and its own
   assembly of `khepra-mcp` (the sovereign build).

Note: this branch could not compile-verify (go.mod pins go 1.26.4; environment
has 1.24.7 and toolchain download is egress-blocked). The spike must run where
the pinned toolchain is available — or the pin should be revisited (the prior
review's §5.4 dependency-governance decision).

## 4. License posture of the extracted kernel

- `LICENSE-APACHE-2.0.proposed` — becomes the extracted repo's `LICENSE`.
  Apache-2.0's explicit patent grant is deliberate given the patent-pending
  portfolio: it defines exactly what contributors and users receive, and keeps
  DoD/prime consumption friction-free.
- `DCO.txt` — Developer Certificate of Origin; every external commit must be
  `Signed-off-by`. Lighter than a CLA and standard for national-security-adjacent
  OSS (kernel.dev lineage).
- **Owner sign-off required**: re-licensing the kernel paths from the KHEPRA
  Master License Agreement to Apache-2.0 is a business decision this branch
  only stages, and must be reconciled with patent counsel first.

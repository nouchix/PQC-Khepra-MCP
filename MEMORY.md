# PQC-Khepra-MCP — MEMORY.md
> Last Updated: 2026-06-15 — Sprint 3 Complete
> Maintainer: Souhimbou Doh Kone (SecRed Knowledge Inc. / NouchiX)

---

## What This Server Does

**PQC-Khepra-MCP** is the Model Context Protocol (MCP) server layer of the AdinKhepra ASAF (Automated Security & Attestation Framework). It intercepts AI agent tool calls and routes them through:

1. **CMMC/STIG compliance scanning** (36,195 cross-framework mappings)
2. **PQC attestation** (ML-DSA-65 / NIST FIPS 204 signing)
3. **SouHimBou AI Flight Recorder** (tamper-evident agent action logging)
4. **License-gated feature dispatch** (community → pilot → enterprise → master)

Patent Pending: **USPTO #73565085**

---

## Current State (June 15, 2026)

### Build & Infrastructure
- **Go**: 1.23+ with `saas` build tag for full feature set
- **gRPC**: `v1.81.0` in vendor (CVE-2025-22869 mitigated; upgrading to v1.81.1)
- **Docker images**: `ghcr.io/nouchix/pqc-khepra-mcp:latest`
- **FIPS builds**: `Dockerfile.fips` with `GOEXPERIMENT=boringcrypto`
- **IronBank**: `Dockerfile.ironbank` for DoD IL4/IL5 environments

### License Tiers (from `pkg/license/mcp_gate.go`)
| Tier | Stripe Price | Monthly | Features |
|------|-------------|---------|---------|
| Community | — | $0 | `ert_scan`, `stig_check`, `nist_map` (rate-limited) |
| Pilot | `price_1TiVvyDqGyad2D3V4mszc5v5` | $499 | + `cmmc_assess`, `agent_record` |
| Enterprise | `price_1TiVXoDqGyad2D3Vr78bgbTI` | $2,999 | + `attest_export`, `godfather_report`, SOAR, GovCloud |
| Master | Contact | Custom | All + sovereign deploy |

### MCP Tools Registered
| Tool | Tier Required | Handler |
|------|-------------|---------|
| `ert_scan` | Community | `pkg/mcp/tools/ert_scan_tool.go` |
| `stig_check` | Community | `pkg/mcp/tools/pqc_stig_tool.go` |
| `nist_map` | Community | `pkg/mcp/tools/nist_map_tool.go` |
| `cmmc_assess` | Pilot | `pkg/mcp/tools/cmmc_assess_tool.go` |
| `godfather_report` | Pilot | `pkg/mcp/tools/godfather_tool.go` |
| `attest_export` | Pilot | `pkg/mcp/tools/attest_export_tool.go` |
| `agent_record` | Community | `pkg/mcp/tools/agent_record_tool.go` |

### Stripe Integration (as of June 15, 2026)
All live prices in Stripe product `prod_UhvNflskmq9PoV`:
```
STRIPE_PRICE_AUTOPILOT=price_1TiVvyDqGyad2D3V4mszc5v5   # $499/mo  → Pilot
STRIPE_PRICE_STARTER=price_1TiVXPDqGyad2D3VSpr7L05X     # $299/mo  → Pilot
STRIPE_PRICE_PRO=price_1TiVXoDqGyad2D3V5AZQ0EiW          # $999/mo  → Pilot
STRIPE_PRICE_ENTERPRISE=price_1TiVXoDqGyad2D3Vr78bgbTI  # $2999/mo → Enterprise
STRIPE_PRICE_CERTIFY=price_1TiVvxDqGyad2D3VlUm3ba6s     # $99 one-time → Certify
STRIPE_PRICE_DIAGNOSTIC=price_1TiVXpDqGyad2D3VXMnYnrZP  # $1500 one-time
STRIPE_PRICE_ADVISORY=price_1TiVXqDqGyad2D3VQizyv9o7    # $5000 one-time
STRIPE_PRICE_SPRINT=price_1TiVw1DqGyad2D3VTs0ewSp0      # $15000 one-time
```

### Key Sprint Completed Work
- **Sprint 2C**: `pkg/license/validator.go` — `ValidateFromEnv()` wired into SEKHEM gateway
  - `mldsa65.Verify()` in `tryOfflineLicense()` (line 207 of manager.go)
  - All 3 license tests passing
- **Sprint 3A-D**: Full Stripe billing wiring:
  - `SimpleBilling.tsx` → `create-checkout-session` Edge Function
  - `stripe-webhook` → price→tier→features mapping
  - `license_gate.go` → Gin middleware + inline guards
  - Autopilot handlers gated on `FeatureCMMCAutopilot`

---

## Architecture

```
AI Agent (Claude/GPT/Gemini)
    ↓ MCP tool call
PQC-Khepra-MCP (this server)
    ├── License Gate (mcp_gate.go)  ← tier check FIRST
    ├── Tool Router
    │   ├── ert_scan       → pkg/mcp/tools/ert_scan_tool.go
    │   ├── stig_check     → pkg/mcp/tools/pqc_stig_tool.go
    │   ├── cmmc_assess    → 36K mappings in manifest.json
    │   ├── attest_export  → ML-DSA-65 sign → ADINKHEPRA seal
    │   └── agent_record   → SouHimBou Flight Recorder (Supabase)
    └── SEKHEM Gateway  ← PQC auth middleware (pqc_auth_middleware.go)
```

---

## Open Tasks
- [ ] Wire `license.Global` (from `khepra protocol`) into MCP gate dispatch
- [ ] Update SouHimBou.AI tier names to new Stripe price labels
- [ ] Add `create-checkout-session` Edge Function URL to `.mcp.json`
- [ ] Submit to MCP registry (server.json complete, mcp-registry.json complete)
- [ ] Cut `v1.1.0` tag after license gate wiring is complete

---

## Deployment

```bash
# Community (local)
docker run -i --rm ghcr.io/nouchix/pqc-khepra-mcp:latest

# Pilot/Enterprise (with license)
docker run -i --rm \
  -e KHEPRA_LICENSE_KEY=<key> \
  -e KHEPRA_TELEMETRY_URL=https://agent.souhimbou.ai \
  ghcr.io/nouchix/pqc-khepra-mcp:latest

# MCP config (Claude Desktop, Cursor, etc.)
# See .mcp.json in repo root
```

## Key Files
- `mcp-registry.json` — Registry submission config
- `server.json` — MCP server manifest
- `pkg/license/mcp_gate.go` — Tier gating logic
- `pkg/mcp/tools/` — Individual tool implementations
- `cmd/mcp/main.go` — Server entrypoint
- `.env.example` — All required environment variables

# PQC-Khepra-MCP — MEMORY.md
> Last Updated: 2026-07-13 — Tier system unified to Community/Pro/Enterprise/Sovereign; Egyptian tier system deleted
> Maintainer: Souhimbou Doh Kone (SecRed Knowledge Inc. / NouchiX)

---

## What This Server Does

**PQC-Khepra-MCP** is the Model Context Protocol (MCP) server layer of the AdinKhepra ASAF (Automated Security & Attestation Framework). It intercepts AI agent tool calls and routes them through:

1. **CMMC/STIG compliance scanning** (36,195 cross-framework mappings)
2. **PQC attestation** (ML-DSA-65 / NIST FIPS 204 signing)
3. **SouHimBou AI Flight Recorder** (tamper-evident agent action logging)
4. **License-gated feature dispatch** (community → pro → enterprise → sovereign → master[internal])

Patent Pending: **USPTO #73565085**

---

## Current State (June 15, 2026)

### Build & Infrastructure
- **Go**: 1.23+ with `saas` build tag for full feature set
- **gRPC**: `v1.81.0` in vendor (CVE-2025-22869 mitigated; upgrading to v1.81.1)
- **Docker images**: `ghcr.io/nouchix/pqc-khepra-mcp:latest`
- **FIPS builds**: `Dockerfile.fips` with `GOEXPERIMENT=boringcrypto`
- **IronBank**: `Dockerfile.ironbank` for DoD IL4/IL5 environments

### License Tiers — PQC-Khepra-MCP Server (2026-07-13 — canonical, supersedes prior conflicting tables)

Renamed/repriced from the old Community/Pilot("Sovereign")/Enterprise("Pharaoh") model —
the "Egyptian tier" node-quota system (`egyptian_tiers.go`, Khepri/Ra/Atum/Osiris) has been
deleted; `pkg/license/license_tiers.go` and `pkg/license/mcp_gate.go` now share one canonical
tier taxonomy (`community`/`pro`/`enterprise`/`sovereign`, plus internal-only `master`).
**Continuous compliance scanning (autopilot) is included in every paid tier.**

| Tier | Product | Stripe Price ID | Price | Features |
|------|---------|----------------|-------|----------|
| Community | — (free) | — | $0 | `ert_scan`, `stig_check`, `nist_map` (rate-limited) |
| Pro | PQC-Khepra-MCP Server `prod_UqvQtvapGfRbcP` | ⚠️ **NOT YET CREATED** — see below | $19/mo | Compliance reporting, ACP, NHI inventory, autopilot |
| Enterprise | PQC-Khepra-MCP Server `prod_UqvQtvapGfRbcP` | ⚠️ **NOT YET CREATED** — see below | $499/mo | All 76 tools, autopilot |
| Sovereign | PQC-Khepra-MCP Server `prod_UqvQtvapGfRbcP` | No self-serve checkout — Contact Sales | Custom | All 76 tools + air-gap/offline licensing + HSM, autopilot |

**Open action item**: the old `STRIPE_PRICE_MCP_SOVEREIGN` ($2,999/mo, `price_1TrDa4DqGyad2D3V7QqGxnjK`)
was a flat self-serve price for what's now the Sovereign tier — Sovereign is now custom/contact-sales,
so this price should be archived (not deleted — existing subscribers may still reference it) rather
than reused. Two **new** Stripe Price objects need to be created for Pro ($19/mo) and Enterprise
($499/mo) under `prod_UqvQtvapGfRbcP`, then wired into `pkg/apiserver/stripe_billing.go`'s
`PriceMapping` under namespaced keys (e.g. `mcp_pro`, `mcp_enterprise`) — **not** the bare
`pro`/`enterprise` keys, since `enterprise` is already taken by the SouHimBou AI product's own
$499/mo tier (`price_1TiVvyDqGyad2D3V4mszc5v5`, different Stripe product) and reusing it would
route MCP checkouts to the wrong product/price.

### MCP Tools Registered
| Tool | Tier Required | Handler |
|------|-------------|---------|
| `ert_scan` | Community | `pkg/mcp/tools/ert_scan_tool.go` |
| `stig_check` | Community | `pkg/mcp/tools/pqc_stig_tool.go` |
| `nist_map` | Community | `pkg/mcp/tools/nist_map_tool.go` |
| `cmmc_assess` | Enterprise | `pkg/mcp/tools/cmmc_assess_tool.go` |
| `godfather_report` | Pro | `pkg/mcp/tools/godfather_tool.go` |
| `attest_export` | Pro | `pkg/mcp/tools/attest_export_tool.go` |
| `agent_record` | Community | `pkg/mcp/tools/agent_record_tool.go` |

### SouHimBou AI Tiers (souhimbou.ai — `prod_UhvNflskmq9PoV`)
| Tier | Stripe Price ID | Price | MCP Tool Access |
|------|----------------|-------|-----------------|
| Free | — | $0/mo | Community tools via hosted endpoint |
| Certify | `price_1TiVvxDqGyad2D3VlUm3ba6s` | $99 one-time | Full compliance audit badge |
| Starter | `price_1TiVXPDqGyad2D3VSpr7L05X` | $299/mo | Pilot tools via hosted endpoint |
| Enterprise | `price_1TiVvyDqGyad2D3V4mszc5v5` | $499/mo | Enterprise tools via hosted endpoint |
| Professional | `price_1TiVXoDqGyad2D3V5AZQ0EiW` | $999/mo | Full SOC suite via hosted endpoint |

### Professional Services (consulting, not software)
| SKU | Stripe Price ID | Price | Description |
|-----|----------------|-------|-------------|
| Diagnostic | `price_1TiVXpDqGyad2D3VXMnYnrZP` | $1,500 one-time | Risk & Readiness Assessment |
| Advisory | `price_1TiVXqDqGyad2D3VQizyv9o7` | $5,000 one-time | Advisory Package |
| Sprint | `price_1TiVw1DqGyad2D3VTs0ewSp0` | $15,000 one-time | Deadline Sprint |

### Stripe Integration — Canonical Env Vars (as of 2026-07-09)
```
# SouHimBou AI — prod_UhvNflskmq9PoV
STRIPE_PRODUCT_SOC=prod_UhvNflskmq9PoV
STRIPE_PRICE_CERTIFY=price_1TiVvxDqGyad2D3VlUm3ba6s          # $99 one-time
STRIPE_PRICE_STARTER=price_1TiVXPDqGyad2D3VSpr7L05X          # $299/mo → TierPilot
STRIPE_PRICE_ENTERPRISE_SOC=price_1TiVvyDqGyad2D3V4mszc5v5   # $499/mo → TierEnterprise
STRIPE_PRICE_PROFESSIONAL=price_1TiVXoDqGyad2D3V5AZQ0EiW     # $999/mo → TierEnterprise

# PQC-Khepra-MCP Server — prod_UqvQtvapGfRbcP
STRIPE_PRODUCT_MCP=prod_UqvQtvapGfRbcP
STRIPE_PRICE_MCP_SOVEREIGN=price_1TrDa4DqGyad2D3V7QqGxnjK    # $2,999/mo → TierMaster

# Professional Services
STRIPE_PRICE_DIAGNOSTIC=price_1TiVXpDqGyad2D3VXMnYnrZP       # $1,500 one-time
STRIPE_PRICE_ADVISORY=price_1TiVXqDqGyad2D3VQizyv9o7         # $5,000 one-time
STRIPE_PRICE_SPRINT=price_1TiVw1DqGyad2D3VTs0ewSp0           # $15,000 one-time

# ARCHIVED (do not use):
# price_1TiVXoDqGyad2D3Vr78bgbTI  → old Sovereign on SouHimBou product (archive in Stripe)
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
- `docs/CONNECTIVE_TISSUE_BUILD_SPEC.md` — **Full July 15 build spec (source of truth)**

---

## 🔧 Connective Tissue Build Spec — July 15 Presight Target

> Full spec: `docs/CONNECTIVE_TISSUE_BUILD_SPEC.md`

### Canonical package ownership decision (2026-06-29)

**This repo owns** `pkg/ea`, `pkg/sekhem`, `pkg/ouroboros`, `pkg/agi`, `pkg/ising`. These packages exist as diverged forks in BOTH `PQC-Khepra-MCP` AND `khepra protocol` (giza-cyber-shield) — **every file differs** between the two copies. Decision: PQC-Khepra-MCP is the canonical source. Product A should vendor/import from here, not maintain an independent fork.

### What's live in this server right now (verified 2026-06-29)

| Status | Component |
|--------|-----------|
| ✅ MCP-registered | DEMARC gateway, polymorphic envelope, DAG attestation (ML-DSA-65), SSE live viewer |
| ✅ MCP-registered | `kasa_start`, `kasa_status`, `ea_evolve`, `ea_threat_score`, `ea_risk_summary`, `quantum_optimize` |
| ✅ MCP-registered | `ouroboros_waf_eye`, `ouroboros_stig_eye`, `ouroboros_vuln_eye`, `ouroboros_fim_eye` |
| ❌ NOT registered | `HandleKASATask`, `HandleKASAScan`, `HandleKASAForensics`, `HandleKASACryptoAgent` (dead code in `pkg/mcp/tools/kasa_tools.go`) |
| ⚠️ Disconnected | KASA autonomous loop writes to its own `dag.NewMemory()` store — NOT the same store the SSE viewer observes |

### Phase 1 tasks (do first, low risk)

1. Register `kasa_task`, `kasa_scan`, `kasa_forensics`, `kasa_crypto_agent` in `cmd/khepra-mcp/main.go` → rebuild manifest hash
2. Unify KASA's `kasaStore` with the router's observable DAG so autonomous KASA events surface in the SSE feed at `/events`
3. Smoke-test `kasa_start` → `kasa_task` → `kasa_status` → `kasa_crypto_agent` via stdio JSON-RPC with `KHEPRA_VIEWER_PORT` set

### Phase 2 tasks (reconcile drift)

1. Diff `pkg/ea`, `pkg/sekhem`, `pkg/ouroboros`, `pkg/agi`, `pkg/ising` file-by-file against `khepra protocol` copy
2. Port anything Product C lacks into this repo (canonical)
3. Add canonicity note to both repos' AGENTS.md

### Phase 3 tasks (demo readiness)

1. Verify SSE viewer renders KASA/EA/Ising events with readable labels
2. Rehearse: `kasa_start` → autonomous sweep in SSE → `ea_evolve`/`quantum_optimize` → `agent_record` attestation
3. Full stdio+SSE smoke test end-to-end before July 15

### Out of scope for July 15

- Real ML model for `KASACryptoAgent` (rule-based thresholds — do not claim ML in the room)
- `mitochondrial-proxy` Supabase Edge Function port
- SEKHEM WAF live filtering (no HTTP ingress in stdio path)
- Compliance Graph UI merge with Product C's live feed


# PQC-Khepra-MCP — MEMORY.md
> Last Updated: 2026-06-29 — Connective Tissue Build Spec added (July 15 Presight target)
> Maintainer: Souhimbou Doh Kone (SecRed Knowledge Inc. / NouchiX)

---

## What This Server Does

**PQC-Khepra-MCP** is the open-source Model Context Protocol (MCP) server kernel carrying post-quantum cryptographic primitives (`pkg/adinkra`), the DoD PQC STIG (`pqc_stig`), OWASP Agentic Top 10 assessment, DISA STIG Viewer API queries, and basic AI discovery tooling.

---

## Repository Boundary & Architecture Rule

- **Public Kernel (`PQC-Khepra-MCP`)**: Released under Apache License 2.0. Contains open-source PQC algorithms, public STIG benchmarks, base MCP tools, and Railway-style open infrastructure primitives (CLI, Agentpacks).
- **Private Landing Zone (`khepra-trust-os`)**: Private monorepo carrying proprietary commercial planes (AEO proof fabric, Agent Passports, Privileged Enforcement Daemon interposition, CMMC SSP generator, Autonomous Data Loop Engine, and commercial key management).
- **One-Way Dependency**: `khepra-trust-os` imports this repository as a Go module. This repository **never** imports private code.

---

## Autonomous Agent Governance Data Loop Platform

```
Agent Intent ──> Agentpack / Blueprint ──> ASAF Governance Evaluation ──> Actuation ──> PQC Proof (AEO) ──> Data Loop Learning
```

KHEPRA combines open infrastructure deployment primitives (`agentpack.yaml`) with the **ASAF Privileged Enforcement Engine** and **Proof Plane**, capturing the operational feedback loop around autonomous agent decisions.

---

## Build & Infrastructure
- **Go**: 1.23+
- **Docker images**: `ghcr.io/nouchix/pqc-khepra-mcp:latest`
- **FIPS builds**: `Dockerfile.fips` with `GOEXPERIMENT=boringcrypto`
- **IronBank**: `Dockerfile.ironbank` for DoD IL4/IL5 environments

### 85 Active Tools Inventory across 8 Security Suites
- **AI Security & Governance (6 tools)**: `owasp_agent_assess`, `agent_scan`, `scan_shadow_ai`, `attest_ai_policy`, `agent_record`, `compliance_model_check`.
- **PQC Cryptography & STIG (8 tools)**: `pqc_stig`, `pqc_sign`, `pqc_verify`, `pqc_keygen`, `stig_check`, `khepra_query_stig`, `stig_live_query`, `linux_hardening_check`.
- **Compliance & Framework Mapping (10 tools)**: `nist_map`, `cmmc_assess`, `khepra_export_attestation`, `khepra_export_poam`, `khepra_get_compliance_score`, `godfather_report`, `godfather_approve`, `asaf_lint`, `attest_export`, `flight_export`.
- **Supply Chain & Threat Intel (10 tools)**: `sbom_generate`, `threat_model`, `khepra_query_threat_intel`, `threat_lookup`, `dark_crypto_contribute`, `ert_scan`, `ert_readiness`, `ert_architect`, `ert_crypto`, `ert_godfather`.
- **Non-Human Identity & Access (8 tools)**: `acp_status`, `acp_issue`, `acp_revoke`, `nhi_inventory`, `nhi_orphans`, `nhi_excessive`, `nhi_expired`, `nhi_revoke`.
- **Recon & Attack Surface (10 tools)**: `enumerate_host`, `fingerprint_device`, `port_scan`, `vuln_scan`, `secret_scan`, `container_scan`, `compliance_scan`, `packet_analyze`, `attack_graph`, `discover_assets`.
- **Quantum Optimization & Brain (14 tools)**: `kasa_start`, `kasa_status`, `kasa_task`, `kasa_scan`, `kasa_forensics`, `kasa_crypto_agent`, `ea_evolve`, `ea_threat_score`, `ea_risk_summary`, `quantum_optimize`, `phantom_stealth`, `identity_shroud`, `identity_epiphany`, `drbc_backup/restore`.
- **Runtime Defense & Forensics (19 tools)**: `drift_detect`, `ir_incident`, `ir_add_ioc`, `flight_record`, `ouroboros_waf_eye/stig_eye/vuln_eye/fim_eye`, `forensic_snapshot`, `fim_baseline`, `audit_dag_integrity`, `playbook_execute`, `dag_write/query/audit/attestation`.

### License Tiers (from `pkg/license/mcp_gate.go`)
| Tier | Commercial Name | Price | Features & Tool Scope |
|------|----------------|-------|----------------------|
| Community | `Community` | $0 | 30+ Core Tools (`pqc_stig`, `nist_map`, `owasp_agent_assess`, `agent_record`, `linux_hardening_check`, `stig_live_query`) |
| Sovereign | `Sovereign` | $299/mo | + `scan_shadow_ai` (subnet CIDR), `attest_ai_policy`, `khepra_get_compliance_score`, `acp_issue`, `nhi_inventory` |
| Pharaoh | `Pharaoh` | $2,999/mo | + `cmmc_assess`, `nhi_revoke`, `ert_scan`, FIPS 140-3 paths, air-gapped SCIF deployments |

### Dependency Boundary
- **Public Open-Source Kernel Repository**: `PQC-Khepra-MCP` contains PQC primitives, STIG data, and 85 active tools.
- **One-Way Rule**: This repo NEVER imports `khepra-trust-os` (the private commercial landing zone).

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


# PQC-Khepra-MCP — Product Brief
**SecRed Knowledge Inc. (NouchiX) · Confidential**
**Version:** Current as of June 30, 2026 · Commit `e125d81`
**Patent:** USPTO #73565085 (provisional) — KHEPRA Protocol
**IP:** SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.

---

## What It Is

**PQC-Khepra-MCP is a standalone, modular Post-Quantum Cryptography security platform** — the most complete AI agent security infrastructure available today.

It serves dual roles simultaneously:

1. **Standalone product** — ships as a binary, Docker image, SDK, or installer and works independently of any NouchiX product. Any organization can deploy it to secure their AI agent infrastructure, audit compliance, or embed PQC cryptographic capabilities.

2. **Connective tissue** (Layer 4 of the KHEPRA Protocol) — the intelligence and routing backbone that connects AdinKhepra ASAF and SouHimBou AI. This is an internal architectural fact, not a product limitation.

### Delivery Formats

| Format | Command / Artifact |
|---|---|
| **Binary** | `bin/khepra-mcp` — single Go binary, zero runtime deps, `CGO_ENABLED=0` |
| **Docker / GHCR** | `ghcr.io/nouchix/pqc-khepra-mcp:latest` |
| **MCP Server** | stdio transport — native in Claude, Cursor, Windsurf, Copilot |
| **Go SDK** | `go get github.com/nouchix/PQC-Khepra-MCP/pkg/...` — any package importable |
| **TypeScript SDK** | Frontend/SDK wrappers for souhimbou.ai |
| **White-label** | Full source license, rebrandable, build-tag configurable (`community`/`premium`/`hsm`) |
| **Installer** | Kubernetes manifests (`deploy/k8s/`), Ansible playbooks, Docker Compose |
| **REST API** | `bin/apiserver` on port 45444 — exposes all tools over HTTP |

### Modular Capability Flags

Build tags control which capability tier ships:

```bash
# Community (open/Iron Bank)
go build -tags community -o bin/khepra-mcp ./cmd/khepra-mcp

# Premium (commercial)
go build -tags premium -o bin/khepra-mcp ./cmd/khepra-mcp

# HSM (hardware security module)
go build -tags hsm -o bin/khepra-mcp ./cmd/khepra-mcp

# FIPS-compliant
GOEXPERIMENT=boringcrypto go build -tags community ...
```

---

## Deployment Modes

Controlled by `KHEPRA_MODE` environment variable — the same binary adapts to any environment:

| Mode | Routes to | Use Case |
|---|---|---|
| `sovereign` | AdinKhepra ASAF | Air-gapped bare-metal, defense/government |
| `ironbank` | AdinKhepra ASAF | DISA Iron Bank / production DoD |
| `hybrid` | SouHimBou AI Enterprise | Hybrid cloud SOC |
| `edge` | SouHimBou AI Free/Pro | SaaS / MCP per-call |
| *(any)* | Standalone | Partner / OEM / white-label |

```bash
docker run --rm -i \
  -e KHEPRA_LICENSE_KEY \
  -e KHEPRA_MODE=sovereign \
  ghcr.io/nouchix/pqc-khepra-mcp:latest
```

---

## Architecture

### Trust Chain
```
DEMARCGateway → PolymorphicEngine → MCPGateway → Executor → Attestation
```
Every tool call traverses this chain. All responses are ML-DSA-65 signed and DAG-attested.

### The Flight Fabric (Stargate / Black Hole)
The central gravitational system. **Nothing executes outside its signed chain.**

```
flight.Global()  ← Process-level singleton (*Fabric)
      │
      ├─ Absorb()           — any event → signed FlightFrame → chained
      ├─ WrapHTTP()         — wraps HTTP handlers, absorbs every request
      ├─ WrapMCPTool()      — wraps MCP tools, absorbs every call
      ├─ WrapFunc()         — wraps any Go function
      ├─ AbsorbLLMCall()    — records every model inference
      ├─ AbsorbSOARAction() — records every SOAR playbook step
      ├─ AbsorbWAFVerdict() — records every WAF block/allow
      └─ AbsorbKASAScore()  — records every behavioral anomaly score
```

Each FlightFrame is content-addressed (SHA-256), ML-DSA-65 signed, causally linked —
the chain cannot be reordered or tampered without detection.

### SEKHEM Triad (Security Perimeter)
```
Ouroboros (Continuous Eye)  — WAF + STIG + Vuln + FIM monitoring
WAFShield                   — SQL injection, XSS, path traversal, header attacks
Maat Guardian               — Behavioral governance, autonomy gate, risk scoring
```

### KASA (AI Behavior Intelligence)
Evolutionary Algorithm (50-individual EA) scoring every AI agent decision. Anomaly detection feeding the Fabric in real-time.

---

## The Omnipotent AI Agent Security Scanner

The flagship standalone capability — an MCP tool that any AI assistant (Claude, Cursor, Copilot, custom) can invoke to blast any AI agent endpoint with a comprehensive 6-layer security analysis.

### What It Does
Points at **any AI agent** and runs:

```
Target: http://any-agent-endpoint:port
        │
Layer 1 — Network Surface (pkg/scanner/network)
        TCP port sweep (100 concurrent) · banner grab
        TLS/PKI: cert expiry, self-signed, weak ciphers (RC4/DES/3DES)
        Dangerous exposures: Docker API :2375, Redis :6379, Postgres :5432
        │
Layer 2 — Service Discovery + Agent Fingerprinting
        MCP tools/list JSON-RPC · OpenAI /v1/models
        LangServe /invoke · Ollama /api/tags
        12+ sensitive path probes: /.env, /.git/config,
        /metrics, /debug/pprof, /actuator, /api-docs
        │
Layer 3 — Horus Static Analysis (pkg/scanners)
        Secret detection: entropy-based credential scan
        CVE scan: dependency manifest matching
        Compliance gap: CIS/STIG/NIST checks
        │
Layer 4A — Sonar Backbone (pkg/sonar.UnifiedOrchestrator)
Layer 4B — 27 Adversarial Probes (in parallel)
        ┌─────────────────────────────────────────────────────┐
        │ Cat A — Injection (14): SQLi, XSS, SSTI, shell,    │
        │   path traversal, LDAP, XXE, prompt injection x4   │
        │ Cat B — Exfiltration (4): system prompt, memory,   │
        │   tool manifest, credential extraction              │
        │ Cat C — Permission (3): rate exhaustion,            │
        │   path traversal, cross-tenant                     │
        │ Cat D — Auth (3): no-auth tool exec,                │
        │   JWT alg:none, replay attack                       │
        │ Cat E — Availability (3): oversized payload,        │
        │   JSON depth bomb, Unicode bomb                    │
        │ Protocol adapters: MCP/OpenAI/LangServe/Ollama/HTTP│
        └─────────────────────────────────────────────────────┘
        │
Layer 5 — KASA Behavioral Analysis
        Injection reflection · Error/stack trace leakage
        Abnormal timing anomaly (>5s = DoS signal)
        Normalized anomaly score: 0.0–1.0
        │
Layer 6 — ERT Multi-lane (pkg/ert.ScanOrchestrator)
        Sonar network+service lane · DNS/PKI lane
        Horus vuln lane · Horus secret lane
        │
        ↓ All findings → Flight Fabric → DAG-attested AgentScanReport
```

### Tier Gating

| Tier | Probes | Sonar Crawler | ERT |
|---|---|---|---|
| `free` | A+B | ✗ | ✓ |
| `pro` | A+B+C+D | ✓ | ✓ |
| `enterprise` | A+B+C+D+E | ✓ | ✓ |

### MCP Invocation (any AI assistant)
```json
{ "method": "tools/call", "params": {
    "name": "agent_scan",
    "arguments": {
      "url": "http://target-agent:3000",
      "type": "mcp",
      "tier": "enterprise"
    }}}
```

---

## Compliance Framework Coverage

KHEPRA's compliance engine is **framework-agnostic by design** — the same DAG attestation chain, control mappings, and evidence export pipeline serve any regulatory regime a customer or partner operates under. Supported frameworks are configured at runtime via `KHEPRA_FRAMEWORKS`, not compiled in.

| Category | Examples of Supported Frameworks |
|---|---|
| **US Federal / Defense** | NIST 800-53, NIST 800-171, CMMC Level 1/2/3, STIG (RHEL-09 V1R3) |
| **AI Governance** | ISO/IEC 42001:2023 (AI Management System) |
| **Information Security** | ISO/IEC 27001, SOC 2 |
| **Data Protection** | GDPR-aligned and regional PDPL-style data protection regimes |
| **Sector / National** | Extensible mapping layer for national cybersecurity authorities and critical-infrastructure standards (e.g. sovereign IAS-style control sets) |

> The compliance capability in KHEPRA is a general-purpose, PQC-anchored control validation and evidence chain engine that maps to whichever frameworks a deployment requires — it is not tied to any single jurisdiction or regulator.

---

### The Gap KHEPRA Fills for AI Platform Operators

Any organization deploying AI agents across sensitive infrastructure — government, energy, finance, healthcare, critical services — faces questions they typically cannot answer today:

| Client Question | KHEPRA Capability |
|---|---|
| **"Can we prove what our AI did?"** | Flight Fabric — ML-DSA-65 signed, immutable causal chain. Every AI action is cryptographically attested. |
| **"Are our AI agents being manipulated?"** | `agent_scan` — 27 adversarial probes (prompt injection, exfiltration, replay, auth bypass). Points at any agent. |
| **"Is our AI cryptography quantum-safe?"** | ML-DSA-65 + ML-KEM-768 (FIPS 203/204). `pqc_sign`, `pqc_verify`, `ert_crypto`. |
| **"Can we detect AI agent anomalies before damage?"** | KASA EA (50-individual evolutionary algorithm) + SEKHEM WAF + real-time Fabric absorption. |
| **"Can we satisfy our compliance auditors?"** | DAG attestation, signed evidence export, compliance scan, control mapping — audit-ready packages for any configured framework. |
| **"Does our AI data pipeline meet data protection law?"** | `fim_baseline`, `secret_scan`, `dag_audit` — verifiable data lineage + integrity chain. |
| **"Can we run sovereign AI without cloud dependency?"** | Sovereign mode: zero egress, air-gap capable, bare-metal. |

---

### Partner Integration Models

KHEPRA is designed to be embedded by platform partners — system integrators, government AI vendors, MSSPs, or vertical SaaS platforms — who need a security and compliance layer under their own brand.

#### Model A — OEM / White-Label Integration
Partner embeds KHEPRA capabilities into their platform under their own brand:
- Individual Go packages importable (`pkg/flight`, `pkg/adinkra`, `pkg/souhimbou`, `pkg/agi`, etc.)
- Custom build tags to select capability tiers
- Partner controls UI, identity, and key management
- KHEPRA becomes the invisible PQC + attestation backbone of their platform

```go
// A partner embeds 3 lines into any of their AI agents:
fabric := flight.Global()
scanner := souhimbou.NewAgentScanner(fabric, dag.NewStore())
report, _ := scanner.Scan(ctx, souhimbou.AgentTarget{URL: agentURL, Tier: "enterprise"})
// → ML-DSA-65 signed evidence report in minutes
// → Compliance audit package ready for the partner's configured framework(s)
```

#### Model B — Binary / Docker Distribution to Partner Customers
Partner ships `khepra-mcp` to enterprise customers using Claude / Cursor / Copilot:
- Single binary, zero runtime dependencies, `KHEPRA_LICENSE_KEY` per account
- Partner acts as value-added reseller — adds margin on top of NouchiX license fees
- Customers get 82 MCP tools natively in their AI assistant workflows

#### Model C — Targeted Module Licensing

| Module | What the Partner Gets |
|---|---|
| **Flight Fabric** (`pkg/flight`) | Immutable, signed audit trail for every AI decision across the partner's platform. Audit-ready for any configured framework. |
| **KASA / EA** (`pkg/agi`) | Behavioral anomaly detection and AI risk scoring for agent fleets. |
| **PQC Primitives** (`pkg/adinkra`) | ML-DSA-65 signing for data provenance. Quantum-safe cryptography for sovereign data products. |
| **Agent Scanner** (`pkg/souhimbou`) | Security posture assessment for every AI agent the partner deploys — on-demand, MCP-callable. |
| **Compliance Engine** (`pkg/stig`, `pkg/compliance`) | General-purpose control validation framework, extensible to whatever frameworks the partner's customers require. |

#### Model D — Joint Go-to-Market
Combine a partner's existing customer relationships in a regulated vertical with KHEPRA's AI security IP:
- Partner co-sells KHEPRA as the **"AI Security Layer"** for their platform deployments
- Mutual interest: AI governance evidence is an emerging requirement across most regulated verticals
- KHEPRA provides what few platforms provide: **cryptographic proof of AI agent behavior**

---

### Key Talking Points for Partner Conversations

```
1. DATA SOVEREIGNTY ALIGNMENT
   For sovereignty-first partners: same posture, zero egress,
   air-gappable, sovereign-by-default. KHEPRA enhances an existing
   platform without requiring any external dependency.

2. AI GOVERNANCE REQUIREMENTS ARE EXPANDING GLOBALLY
   Regulators worldwide (national AI authorities, sector regulators)
   increasingly require AI governance evidence.
   KHEPRA produces ML-DSA-65 signed, cryptographically tamper-evident
   AI audit trails — ISO/IEC 42001-aligned compliance evidence,
   generated automatically.

3. MULTI-FRAMEWORK COMPLIANCE COVERAGE
   36,195 cross-framework control mappings (STIG/NIST/CMMC) plus an
   extensible mapping layer for additional frameworks.
   Partners' regulated customers can generate audit packages
   from the DAG chain without manual evidence collection.

4. AI AGENT SECURITY (ACTIVE RISK FOR ANY AI DEPLOYER)
   Any organization deploying AI to sensitive systems faces
   manipulation and exfiltration risk.
   KHEPRA's 27-probe adversarial scanner catches it before auditors do.

5. PATENT-PENDING IP — USPTO #73565085
   This is not replicable. KHEPRA Protocol is the moat.
   Early partners can secure preferential licensing terms.

6. 82 MCP TOOLS — NATIVE IN CLAUDE/CURSOR
   Any partner's developer or AI-product ecosystem gets a security
   layer that works inside existing developer workflows.
```

---

## MCP Tool Registry (82 tools)

### Security Scanning
| Tool | Description |
|---|---|
| `agent_scan` | **Omnipotent AI agent scanner** — 6-layer blast at any agent endpoint |
| `ert_scan` | Full ERT: SBOM, CVE, secrets, STIG, PQC inventory |
| `owasp_agent_assess` | OWASP Agentic Top 10 (2026) self-assessment (ASI01–ASI10) |
| `port_scan` | TCP port sweep via Sonar |
| `vuln_scan` | CVE vulnerability scan |
| `secret_scan` | Entropy-based secret/credential detection |
| `compliance_scan` | CIS/STIG/NIST compliance check |
| `container_scan` | Dockerfile/image misconfiguration |
| `packet_analyze` | Network packet analysis |
| `attack_graph` | Attack path visualization |
| `enumerate_host` | Host enumeration |
| `fingerprint_device` | Device fingerprinting |
| `kasa_scan` | KASA behavioral anomaly scan |
| `kasa_forensics` | KASA forensic analysis |

### STIG / CMMC / NIST
| Tool | Description |
|---|---|
| `stig_check` | RHEL-09-STIG V1R3 control validation |
| `pqc_stig` | PQC-specific STIG checks |
| `cmmc_assess` | CMMC Level 1/2/3 assessment |
| `nist_map` | CCI→NIST 800-53→NIST 800-171→CMMC translation |
| `khepra_query_stig` | Query the 36,195-row STIG DB |
| `khepra_get_compliance_score` | Aggregate compliance posture score |

### ERT Intelligence
| Tool | Description |
|---|---|
| `ert_readiness` | CMMC audit readiness |
| `ert_architect` | Security architecture recommendations |
| `ert_crypto` | PQC cryptography inventory |
| `ert_godfather` | Executive business-impact synthesis |
| `godfather_report` | Godfather executive report |
| `godfather_approve` | Approve Godfather remediation |

### Flight Recorder / Audit
| Tool | Description |
|---|---|
| `flight_record` | Record to Flight Fabric |
| `flight_export` | Export signed Fabric chain |
| `agent_record` | Forward agent action to Flight Recorder |
| `dag_write` | Write to immutable DAG |
| `dag_query` | Query DAG history |
| `dag_audit` | Audit DAG chain integrity |
| `dag_attestation` | Generate PQC-signed attestation |
| `audit_dag_integrity` | Verify full DAG chain |
| `khepra_export_attestation` | Export ML-DSA-65 signed evidence package |
| `khepra_export_poam` | Export POAM CSV |

### PQC Cryptography
| Tool | Description |
|---|---|
| `pqc_sign` | ML-DSA-65 (FIPS 204) sign |
| `pqc_verify` | ML-DSA-65 verify |
| `pqc_keygen` | Generate ML-DSA-65 / ML-KEM-768 key pair |

### KASA / EA / Threat Intel
| Tool | Description |
|---|---|
| `kasa_start` | Start KASA monitoring session |
| `kasa_status` | KASA health and anomaly status |
| `kasa_task` | Dispatch KASA task |
| `kasa_crypto_agent` | KASA cryptographic agent operations |
| `ea_evolve` | EA optimization cycle |
| `ea_threat_score` | EA-scored threat assessment |
| `ea_risk_summary` | EA risk population summary |
| `quantum_optimize` | Quantum-inspired optimization |
| `threat_lookup` | Threat intelligence lookup |
| `threat_model` | Structured threat modeling |
| `khepra_query_threat_intel` | Query threat intelligence DB |
| `drift_detect` | Configuration/behavioral drift detection |

### Incident Response
| Tool | Description |
|---|---|
| `ir_incident` | Open incident record |
| `ir_add_ioc` | Add indicator of compromise |
| `forensic_snapshot` | Collect forensic snapshot |

### Identity & Access
| Tool | Description |
|---|---|
| `acp_status` | Agent Credential Plane status |
| `acp_issue` | Issue ephemeral agent credential |
| `acp_revoke` | Revoke agent credential |
| `nhi_inventory` | Non-Human Identity inventory |
| `nhi_orphans` | Find orphaned NHI tokens |
| `nhi_excessive` | Find over-privileged NHIs |
| `nhi_expired` | Find expired NHIs |
| `nhi_revoke` | Revoke NHI credential |

### SEKHEM / Ouroboros
| Tool | Description |
|---|---|
| `ouroboros_waf_eye` | WAF inspection eye |
| `ouroboros_stig_eye` | STIG continuous eye |
| `ouroboros_vuln_eye` | Vulnerability continuous eye |
| `ouroboros_fim_eye` | File integrity monitoring eye |

### Phantom / Stealth
| Tool | Description |
|---|---|
| `phantom_stealth` | Phantom network stealth |
| `identity_shroud` | Identity obfuscation |
| `identity_epiphany` | Identity revelation |

### Integrity / Continuity
| Tool | Description |
|---|---|
| `fim_baseline` | FIM baseline |
| `sbom_generate` | CycloneDX SBOM generation |
| `drbc_backup` | Disaster recovery backup |
| `drbc_restore` | Disaster recovery restore |
| `khepra_get_dag_chain` | Retrieve full DAG chain |
| `khepra_watch` | Filesystem watch → continuous STIG scan |
| `discover_assets` | Network asset discovery |
| `dark_crypto_contribute` | Community PQC inventory contribution |

---

## Core Packages (65 packages)

### Cryptography & PQC
| Package | Role |
|---|---|
| `pkg/adinkra` | ML-DSA-65, ML-KEM-768, Adinkra symbol binding, D₈ transforms |
| `pkg/crypto` | FIPS wrapper, build tag abstraction (community/premium/hsm) |
| `pkg/pki` | PKI / TLS certificate management |
| `pkg/kms` | Key management service |

### Compliance & Intelligence
| Package | Role |
|---|---|
| `pkg/stig` | 36,195-row STIG DB (embed.FS): STIG→CCI→NIST 800-53→NIST 800-171→CMMC |
| `pkg/ert` | ERT Engine: CVE DB, STIG integration, Sonar, Godfather synthesis |
| `pkg/compliance` | PQC STIG checker, ASAF DSL evaluator |
| `pkg/sbom` | CycloneDX SBOM, CVE correlation, risk scoring |
| `pkg/emass` | eMASS integration |
| `pkg/poam` | POAM generation |

### Scanning & Intelligence
| Package | Role |
|---|---|
| `pkg/sonar` | Unified scanner (port+crawler+vuln+secrets+compliance+container) |
| `pkg/scanner` | Raw port scanner + SpiderFoot crawler |
| `pkg/scanner/network` | TCP port sweep, banner grab, service detection |
| `pkg/scanners` | Horus: entropy secret scan, manifest CVE, CIS/STIG compliance, container |
| `pkg/souhimbou/agent_scanner` | **Omnipotent AI agent scanner** (6-layer) |
| `pkg/souhimbou/probe_suite` | 27 adversarial AI probes (OWASP LLM Top 10 + MITRE ATLAS) |
| `pkg/fingerprint` | Device fingerprinting |
| `pkg/enumerate` | Host enumeration |
| `pkg/packet` | Network packet analysis |
| `pkg/zscan` | Zero-knowledge scanner capabilities |
| `pkg/vuln` | Vulnerability assessment engine |
| `pkg/intel` | Threat intelligence |

### AI / Behavior
| Package | Role |
|---|---|
| `pkg/agi` | KASA Orchestrator, EA Kernel (50-individual EA, AdinkraGenomes) |
| `pkg/souhimbou/agent` | SouHimBou Core Agent (reasoning + tool orchestration) |
| `pkg/souhimbou/threat_detector` | KASA threat detection |
| `pkg/souhimbou/wrapper` | Agent wrapping SDK — 3-line integration |
| `pkg/souhimbou/flight_recorder` | Flight Recorder integration |

### The Flight Fabric
| Package | Role |
|---|---|
| `pkg/flight/fabric` | Stargate — signs + chains every system event |
| `pkg/flight/frame` | FlightFrame: content-addressed, causally linked |
| `pkg/flight/recorder` | ML-DSA-65 signed NDJSON event recorder |
| `pkg/flight/reader` | Ring-buffer Recent(n) reader |
| `pkg/flight/replay` | DAG replay and forensic audit |

### Security Perimeter
| Package | Role |
|---|---|
| `pkg/sekhem` | SEKHEM Triad: Ouroboros + WAFShield + Maat Guardian |
| `pkg/maat` | Governance engine, autonomy gate |
| `pkg/ouroboros` | Continuous eye: WAF + STIG + Vuln + FIM |
| `pkg/phantom` | Phantom Network (classified) |
| `pkg/scorpion` | Scorpion Seal (integrity enforcement) |
| `pkg/arsenal` | Security tool arsenal |

### DAG & Audit
| Package | Role |
|---|---|
| `pkg/dag` | Immutable DAG: global singleton, PersistentMemory, AES-256-GCM encryption |
| `pkg/audit` | Audit types: Vulnerability, SecretFinding, ComplianceFinding |
| `pkg/logging` | DoD dual-tap logger: stdout JSON + DAG, 15+ field redaction patterns |
| `pkg/attest` | Attestation generation |
| `pkg/forensics` | Forensic snapshot collection |

### Infrastructure
| Package | Role |
|---|---|
| `pkg/mcp` | MCP server: DEMARC→Polymorphic→MCPGateway→Executor chain |
| `pkg/apiserver` | REST API + SEKHEM middleware |
| `pkg/auth` | Supabase JWT auth |
| `pkg/license` | ML-DSA-65 signed licenses, Egyptian tier system |
| `pkg/config` | Runtime config, NetworkPolicy, deployment mode |
| `pkg/connectors` | Polymorphic API Engine — connects to any external agent/tool |
| `pkg/nhi` | Non-Human Identity management |
| `pkg/acp` | Agent Credential Plane |
| `pkg/rbac` | Role-based access control |
| `pkg/billing` | Stripe billing integration |

---

## PQC Primitives

| Primitive | Standard | Use |
|---|---|---|
| **ML-DSA-65** | FIPS 204 | All signatures: DAG nodes, licenses, tool responses, Fabric frames |
| **ML-KEM-768** | FIPS 203 | Key encapsulation, session establishment |
| **AES-256-GCM** | FIPS 197 | DAG encryption at rest |
| **SHA-256 / SHA3-256** | FIPS 180 | Content addressing, frame hashing |

All via **Cloudflare CIRCL** — no custom cryptography.

---

## Compliance Database

```
pkg/stig/data/
├── STIG_CCI_Map.csv        28,639 rows   STIG → CCI
├── CCI_to_NIST53.csv        7,433 rows   CCI → NIST 800-53
├── NIST53_to_171.csv          123 rows   NIST 800-53 → NIST 800-171
└── CMMC mappings (cmmc.go)              NIST 800-171 → CMMC
Total: 36,195 cross-framework mappings — embedded in binary via embed.FS
Every scanner finding references this DB for CMMC + NIST control IDs
```

---

## Non-Negotiables

1. **Zero egress** in sovereign/ironbank mode — no telemetry, no external calls, air-gappable
2. **All DAG writes ML-DSA-65 signed** before persistence — unsigned nodes silently dropped
3. **No CGO** — `CGO_ENABLED=0` on all production binaries
4. **No hardcoded secrets** — env vars only, `.khepra/` keys never committed
5. **G0DM0D3 excluded** from all public/competition submissions (AGPL-3.0 conflict)
6. **Go primary** — no new Python production paths

---

## Compiled Binaries

| Binary | Purpose |
|---|---|
| `bin/khepra-mcp` | MCP stdio server (primary delivery) |
| `bin/adinkhepra.exe` | CLI: `ert full`, `validate`, `serve`, `ert-readiness/architect/crypto/godfather` |
| `bin/apiserver.exe` | REST API on port 45444 |
| `bin/agent.exe` | KASA agent runtime |
| `cmd/khepra-daemon` | System daemon (privileged OS execution) |
| `cmd/khepra-pentest` | Penetration testing binary |
| `cmd/phantom-node` | Phantom network node |
| `cmd/sonar` | Standalone Sonar scanner CLI |
| `cmd/gateway` | SEKHEM API gateway |

---

## Key Metrics (as of June 30, 2026)

| Metric | Value |
|---|---|
| Packages | 65+ |
| Compiled binaries | 9+ |
| MCP tools registered | **82** |
| Compliance mappings | **36,195 rows** |
| Adversarial probes | **27** (OWASP LLM Top 10 + MITRE ATLAS) |
| Scanner layers | **6** (Network → Sonar → Horus → Probes → KASA → ERT) |
| PQC primitives | ML-DSA-65 + ML-KEM-768 (FIPS 204/203) |
| DAG node signing | ML-DSA-65 on every write |
| Patent | USPTO #73565085 (provisional) |
| Build formats | Binary · Docker · Go SDK · White-label · Installer · REST API |
| Recent commits | `e125d81` (delivery), `ed9f6a6` (scanner), `a96647f` (Fabric) |

---

## TRL10 — Live ✅

What you now have at http://localhost:45444:

```
┌─ SECURITY ADVISOR (NL chat) ─┬─ SCAN OUTPUT / DAG GRAPH / 🔍 AI AGENT SCAN ─┬─ SECURITY LEDGER ─┐
│ Mode-aware prompts            │                                                 │ Live SSE stream   │
│ Multi-framework (config'able) │  AI AGENT SCAN tab:                            │ Nodes: N          │
│ ASAF_CMD → agent_scan pre-fill│  ┌ Target URL ──────────────────────── ┐       │ Signed: N         │
│                               │  │ Type: MCP/OpenAI/LangServe/Ollama   │       │ Framework: CMMC   │
│                               │  │ Tier: Free(8) / Pro(18) / Ent(27)   │       │                   │
│                               │  └──────────────────── [🔴 LAUNCH] ───┘       │ Chain nodes live  │
│                               │  L1 Network Surface   ████████░░ running       │ per finding       │
│                               │  L2 Service Discovery ████████░░ running       │                   │
│                               │  L3 Horus Static      ██████████ complete      │                   │
│                               │  L4 Adversarial Probes░░░░░░░░░░ queued        │                   │
│                               │  L5 KASA Behavioral   ░░░░░░░░░░ queued        │                   │
│                               │  L6 ERT Multi-lane    ░░░░░░░░░░ queued        │                   │
│                               │                                                 │                   │
│                               │  [📄 Export Signed Report]                      │                   │
└──────────────────────────────┴─────────────────────────────────────────────────┴───────────────────┘
Header: [API ●] [LLM ●] [WAF ●] [KASA ●]  sovereign  ML-DSA-65  v1.5.0
```

To demo for a specific partner or prospect — stop the server, set env vars, restart:

```powershell
$env:KHEPRA_FRAMEWORKS="NIST171,CMMC,ISO27001,ISO42001"
$env:KHEPRA_ORG_NAME="<Partner/Prospect Name>"
$env:KHEPRA_PRODUCT_NAME="<Partner/Prospect Name> · AI Security Platform"
.\bin\adinkhepra.exe watch
```

The UI will rebrand instantly — different suggestions, system prompt, ledger framework label, and header title. Zero code change needed.

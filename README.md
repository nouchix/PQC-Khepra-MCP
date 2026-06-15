# KHEPRA MCP Server

[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.nouchix%2Fpqc--khepra--mcp-blue?style=for-the-badge)](https://registry.modelcontextprotocol.io)
[![License](https://img.shields.io/badge/License-Community%20%2F%20Commercial-green?style=for-the-badge)](https://nouchix.com)
[![Container](https://img.shields.io/badge/Container-ghcr.io-green?style=for-the-badge&logo=docker)](https://ghcr.io/nouchix/pqc-khepra-mcp)
[![PQC](https://img.shields.io/badge/PQC-ML--DSA--65%20%2F%20FIPS%20204-purple?style=for-the-badge)](https://csrc.nist.gov/pubs/fips/204/final)

**Sovereign compliance engine with 36,195 STIG/CCI/NIST/CMMC mappings.**

Air-gappable. Zero token costs. Run `ert_scan` → get a Godfather Report with dollar-denominated business impact.  
The only MCP compliance server that runs on your metal — with the **World's First DoD PQC STIG** built in.

> **[PQC-01-STIG-V1R1 — Full Whitepaper →](docs/PQC-01-STIG-V1R1.md)**  
> 17 controls covering CNSA 2.0, FIPS 203/204/205, and the NSA's May 2026 MCP security advisory.  
> The world's first DoD-style Post-Quantum Cryptography STIG, including the first PQC controls for agentic AI and MCP deployments.

---

## Tiers

| Tier | License Key | Tools | Telemetry | Egress |
|------|-------------|-------|-----------|--------|
| **Community** | ❌ Not required | `pqc_stig` + 12 core tools | Opt-in Dark Crypto Intel | Zero (sovereign mode) |
| **Sovereign** | ✅ Required | All 32 tools | Zero | Zero |
| **Pharaoh** | ✅ Required | All 32 tools + priority support | Zero | Zero |

> **Community tier is free.** Run `pqc_stig` to assess your project's quantum readiness against  
> **PQC-01-STIG-V1R1** — the World's First DoD-style Post-Quantum Cryptography STIG — no license key needed.

---

## What It Does

KHEPRA MCP connects your AI assistant directly to a hardened compliance engine. Ask Claude or any MCP client to scan a system, map findings to STIG/NIST/CMMC controls, and generate an executive-ready risk report — all without sending data to external APIs.

**Key capabilities:**
- 36,195 STIG/CCI/NIST 800-53/800-171/CMMC mappings (offline, bundled)
- Post-quantum cryptographic attestation on every tool call (ML-DSA-65 / FIPS 204)
- **World's First DoD PQC STIG** — 17 controls covering CNSA 2.0 / FIPS 203/204/205 + agentic AI / MCP ([PQC-01-STIG-V1R1](docs/PQC-01-STIG-V1R1.md))
- Godfather Report: dollar-denominated business impact per finding (FAIR model)
- Air-gap and SCIF compatible — sovereign/ironbank modes make zero egress calls
- Flat annual licensing — no per-token or per-query charges
- Runs on your metal: on-prem, DoD, IC, classified environments

---

## Quick Install — Community (No License Key)

The Community tier starts immediately with no license key. You get `pqc_stig` and 12 core tools free.

### Add to Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "khepra": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "KHEPRA_MODE=sovereign",
        "-v", "/var/lib/khepra:/var/lib/khepra",
        "ghcr.io/nouchix/pqc-khepra-mcp:latest"
      ]
    }
  }
}
```

### Add to Cursor / VS Code (`.cursor/mcp.json` or `.vscode/mcp.json`)

```json
{
  "servers": {
    "khepra": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "KHEPRA_MODE=sovereign",
        "-v", "/var/lib/khepra:/var/lib/khepra",
        "ghcr.io/nouchix/pqc-khepra-mcp:latest"
      ]
    }
  }
}
```

## Quick Install — Sovereign / Pharaoh (License Key Required)

```json
{
  "mcpServers": {
    "khepra": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "KHEPRA_LICENSE_KEY",
        "-e", "KHEPRA_MODE=sovereign",
        "-v", "/var/lib/khepra:/var/lib/khepra",
        "-v", "/var/log/khepra:/var/log/khepra",
        "ghcr.io/nouchix/pqc-khepra-mcp:latest"
      ],
      "env": {
        "KHEPRA_LICENSE_KEY": "YOUR_LICENSE_KEY_HERE"
      }
    }
  }
}
```

Get a license key at [nouchix.com](https://nouchix.com) or email [sales@nouchix.com](mailto:sales@nouchix.com).

---

## MCP Tools

### Community Tier (Free — No License Key)

#### `pqc_stig` — World's First DoD PQC STIG ⭐
Assesses a source code directory against **PQC-01-STIG-V1R1**: 12 controls covering CNSA 2.0 algorithm approval, ML-DSA-65 key strength, ML-KEM-768 encapsulation, hybrid cryptography, key storage, constant-time implementation, and certificate chain requirements.

```
pqc_stig(scan_path?: string, profile?: "quick" | "full" | "executive")
```

> **Example:** *"Run pqc_stig on my project and tell me if I'm CNSA 2.0 compliant"*

#### `nist_map`
Map CCI identifiers or STIG findings to NIST 800-53 Rev 5 controls.

#### `khepra_query_stig`
Query the 36,195-row STIG/CCI/NIST/CMMC compliance database by control ID.

#### `dark_crypto_contribute` *(opt-in)*
Contribute anonymized cryptographic algorithm telemetry to the SouHimBou AI Dark Crypto Intelligence Network. No PII. Opt-in only — never fires without explicit invocation.

---

### Sovereign / Pharaoh Tier

#### `ert_scan`
Enterprise Risk & Threat scan across STIG, NIST 800-53, NIST 800-171, CMMC, and FedRAMP. Returns Godfather Report with dollar-denominated business impact.

```
ert_scan(target: string, frameworks?: string[], output_format?: "godfather" | "json" | "csv")
```

> **Example:** *"Run ert_scan on /etc and generate a Godfather Report"*

#### `stig_check`
Automated RHEL-09-STIG-V1R3 compliance scan against a live system or configuration path.

#### `cmmc_assess`
Full CMMC Level 1, 2, or 3 assessment with gap analysis and POA&M generation.

#### `godfather_report`
Generate an executive Godfather Report from prior scan results: top 10 findings ranked by dollar exposure, remediation ROI, and FAIR model business impact.

#### + 20 additional tools
`agent_record`, `dag_attestation`, `flight_export`, `khepra_get_dag_chain`, `nhi_inventory`, `acp_status`, `owasp_agent_assess`, `khepra_export_attestation`, `khepra_export_poam`, `khepra_get_compliance_score`, `ert_crypto`, `ert_readiness`, `stig_benchmark`, `ir_analysis`, `vuln_hunter`, `sbom_generate`, `threat_model`, `khepra_query_threat_intel`, `discover_assets`, and more.

---

## The Godfather Report

Unlike compliance scanners that output a wall of CVEs, KHEPRA translates findings into the language executives care about:

```
Finding: RHEL-09-212030 — No FIPS-validated crypto on /etc/ssh
Severity: CAT I (HIGH)
Business Impact: $2.4M estimated breach exposure (FAIR model)
Remediation Cost: $800 (4 hours engineer time)
ROI: 3,000x
```

Every finding includes control ID, framework mapping, business impact in dollars, remediation cost estimate, and ROI.

---

## Deployment Modes

| Mode | Air-Gap | Egress | Telemetry | Use Case |
|------|---------|--------|-----------|----------|
| `sovereign` | ✅ Yes | Zero | Zero | On-prem, SCIF, classified (DEFAULT) |
| `ironbank` | ✅ Yes | Zero | Zero | DoD/IC production, FIPS-only |
| `hybrid` | ❌ No | LAN | Zero | Edge + cloud coordination |
| `edge` | ❌ No | Unrestricted | Zero | Fully stateless SaaS |

Set via `KHEPRA_MODE` environment variable. Unknown values are rejected at startup and fall back to `sovereign` (fail-closed).

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KHEPRA_LICENSE_KEY` | Sovereign/Pharaoh only | — | License key. Community tier runs without one. Get at [nouchix.com](https://nouchix.com) |
| `KHEPRA_MODE` | No | `sovereign` | Deployment mode: `sovereign`, `ironbank`, `hybrid`, `edge` |
| `KHEPRA_HOME` | No | `/var/lib/khepra` | Data and compliance DB directory |
| `KHEPRA_LOG_DIR` | No | `/var/log/khepra` | Log directory |
| `KHEPRA_DAG_PATH` | No | `~/.khepra/dag` | DAG audit chain storage path |

---

## Air-Gap & SCIF Deployment

KHEPRA makes **zero external network calls** in `sovereign` and `ironbank` modes:
- License validated offline via ML-DSA-65 signed `license.adinkhepra` file
- Compliance databases (36,195 mappings) bundled in container — no external downloads
- No telemetry, no heartbeat, no egress — verified at the transport layer

```bash
# Transfer image to air-gapped network
docker save ghcr.io/nouchix/pqc-khepra-mcp:latest | gzip > khepra-mcp.tar.gz

# On air-gapped host:
docker load < khepra-mcp.tar.gz
```

> **Note on telemetry:** The `dark_crypto_contribute` tool (Community tier) sends anonymized cryptographic algorithm telemetry to the [SouHimBou AI](https://souhimbou.ai) intelligence network **only when explicitly invoked by the user**. It is never triggered automatically. In sovereign/ironbank mode, all network calls are blocked at the transport layer regardless.

---

## Compliance Coverage

| Framework | Version | Mappings |
|-----------|---------|----------|
| STIG (RHEL 9) | V1R3 | Automated scanning |
| NIST 800-53 | Rev 5 | 2,120 CCIs |
| NIST 800-171 | Rev 2 | 320 controls |
| CMMC | Level 3 | Full practice set |
| FedRAMP | High | Baseline scanning |
| **PQC-01-STIG-V1R1** | V1R1 | **12 PQC controls (CNSA 2.0)** |
| **Total** | | **36,195+ mappings** |

---

## Licensing

**Flat annual licensing — no per-token or per-query charges.**

| Tier | Cost | License Key | Tools |
|------|------|-------------|-------|
| Community | Free | Not required | `pqc_stig` + 12 core tools |
| Sovereign | Annual flat fee | Required | All 32 tools, air-gap, on-prem |
| Pharaoh | Annual flat fee | Required | All 32 tools + priority support + SLA |

- Community tier is permanently free — contribute to open-source PQC adoption
- Sovereign/Pharaoh: contact [sales@nouchix.com](mailto:sales@nouchix.com) or visit [nouchix.com](https://nouchix.com)

---

## About NouchiX

Veteran-led advisory firm translating CMMC, NIST, and STIG mandates into executive roadmaps.

- **Sales**: [sales@nouchix.com](mailto:sales@nouchix.com)
- **Support**: [support@nouchix.com](mailto:support@nouchix.com)
- **Website**: [https://nouchix.com](https://nouchix.com)
- **Phone**: (332) 275-4335

Developed by SecRed Knowledge Inc. dba NouchiX, Albany, NY.

# KHEPRA MCP Server

[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.nouchix%2Fpqc--khepra--mcp-blue?style=for-the-badge)](https://registry.modelcontextprotocol.io)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)](https://nouchix.com)
[![Container](https://img.shields.io/badge/Container-ghcr.io-green?style=for-the-badge&logo=docker)](https://ghcr.io/nouchix/pqc-khepra-mcp)

**Sovereign compliance engine with 36,195 STIG/CCI/NIST/CMMC mappings.**

Air-gappable. Zero token costs. Flat annual licensing. Run `ert_scan` → get a Godfather Report with dollar-denominated business impact. The only MCP compliance server that runs on your metal.

---

## What It Does

KHEPRA MCP connects your AI assistant directly to a hardened compliance engine. Ask Claude or any MCP client to scan a system, map findings to STIG/NIST/CMMC controls, and generate an executive-ready risk report — all without sending data to external APIs.

**Key capabilities:**
- 36,195 STIG/CCI/NIST 800-53/800-171/CMMC mappings (offline)
- Post-quantum cryptographic attestation (ML-DSA-65 / Dilithium3)
- Godfather Report: dollar-denominated business impact per finding
- Air-gap and SCIF compatible — no egress, no telemetry
- Flat annual licensing — no per-token or per-query charges
- Runs on your metal: on-prem, DoD, IC, classified environments

---

## Quick Install

### Prerequisites
- Docker (or compatible OCI runtime)
- KHEPRA license key — [get one at nouchix.com](https://nouchix.com) or email [sales@nouchix.com](mailto:sales@nouchix.com)

### Pull the container

```bash
docker pull ghcr.io/nouchix/pqc-khepra-mcp:latest
```

### Add to Claude Desktop (`claude_desktop_config.json`)

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

### Add to Cursor / VS Code (`.cursor/mcp.json` or `.vscode/mcp.json`)

```json
{
  "servers": {
    "khepra": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "KHEPRA_LICENSE_KEY",
        "-e", "KHEPRA_MODE=sovereign",
        "-v", "/var/lib/khepra:/var/lib/khepra",
        "ghcr.io/nouchix/pqc-khepra-mcp:latest"
      ],
      "env": {
        "KHEPRA_LICENSE_KEY": "YOUR_LICENSE_KEY_HERE"
      }
    }
  }
}
```

---

## MCP Tools

### `ert_scan`
Enterprise Risk & Threat scan. Scans a target directory, host, or configuration for compliance violations across STIG, CCI, NIST 800-53, NIST 800-171, CMMC, and FedRAMP frameworks. Returns structured findings mapped to controls with dollar-denominated business impact.

```
ert_scan(target: string, frameworks?: string[], output_format?: "godfather" | "json" | "csv")
```

**Example prompt to your AI assistant:**
> "Run ert_scan on /etc and generate a Godfather Report"

### `stig_check`
Check a specific system path or configuration against RHEL-09-STIG-V1R3 controls.

### `nist_map`
Map a list of CCI identifiers or STIG findings to NIST 800-53 Rev 5 controls.

### `cmmc_assess`
Assess a system or artifact against CMMC Level 1, 2, or 3 practices.

### `godfather_report`
Generate a Godfather Report from prior scan results: executive summary with dollar-denominated risk exposure, top 10 findings ranked by business impact, and remediation ROI.

---

## The Godfather Report

Unlike compliance scanners that output a wall of CVEs, KHEPRA translates findings into the language executives care about:

```
Finding: RHEL-09-212030 — No FIPS-validated crypto on /etc/ssh
Severity: HIGH
Business Impact: $2.4M estimated breach exposure (FAIR model)
Remediation Cost: $800 (4 hours engineer time)
ROI: 3,000x
```

Every finding includes control ID, framework mapping, business impact in dollars, remediation cost estimate, and ROI.

---

## Deployment Modes

| Mode | Description | Pricing |
|------|-------------|--------|
| `sovereign` | Air-gapped, full autonomous ops, zero external deps | On-Premise |
| `ironbank` | DoD/IC production, full compliance frameworks | Enterprise |
| `hybrid` | Edge + network-wide coordination | SaaS |
| `edge` | Autonomous endpoint security | SaaS |

Set via the `KHEPRA_MODE` environment variable.

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KHEPRA_LICENSE_KEY` | Yes | — | License key. Get at [nouchix.com](https://nouchix.com) |
| `KHEPRA_MODE` | No | `sovereign` | Deployment mode |
| `KHEPRA_HOME` | No | `/var/lib/khepra` | Data and compliance DB directory |
| `KHEPRA_LOG_DIR` | No | `/var/log/khepra` | Log directory |

---

## Air-Gap & SCIF Deployment

KHEPRA makes **zero external network calls** in sovereign mode:
- License validated offline via ML-DSA-65 signed `license.sig` file
- Compliance databases bundled in container (no external downloads)
- No telemetry, no heartbeat, no egress

```bash
# Transfer image to air-gapped network
docker save ghcr.io/nouchix/pqc-khepra-mcp:latest | gzip > khepra-mcp.tar.gz
# On air-gapped host:
docker load < khepra-mcp.tar.gz
```

---

## Compliance Coverage

| Framework | Version | Mappings |
|-----------|---------|----------|
| STIG (RHEL 9) | V1R3 | Automated scanning |
| NIST 800-53 | Rev 5 | 2,120 CCIs |
| NIST 800-171 | Rev 2 | 320 controls |
| CMMC | Level 3 | Full practice set |
| FedRAMP | High | Baseline scanning |
| **Total** | | **36,195 mappings** |

---

## Licensing

**Flat annual licensing — no per-token or per-query charges.**

- Free evaluation for DoD/IC contractors (non-production)
- Production use requires a commercial license
- Contact [sales@nouchix.com](mailto:sales@nouchix.com) or visit [nouchix.com](https://nouchix.com)

---

## About NouchiX

Veteran-led advisory firm translating CMMC, NIST, and STIG mandates into executive roadmaps.

- **Sales**: [sales@nouchix.com](mailto:sales@nouchix.com)
- **Support**: [support@nouchix.com](mailto:support@nouchix.com)
- **Website**: [https://nouchix.com](https://nouchix.com)
- **Phone**: (332) 275-4335

Developed by SecRed Knowledge Inc. dba NouchiX, Albany, NY.

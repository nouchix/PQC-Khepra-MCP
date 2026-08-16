# KHEPRA MCP Server

[![Release](https://img.shields.io/badge/Release-v2.0.0-blue?style=for-the-badge)](https://github.com/nouchix/PQC-Khepra-MCP/releases)
[![Downloads](https://img.shields.io/badge/Downloads-424%2B_Verified-blue?style=for-the-badge&logo=docker)](https://github.com/nouchix/PQC-Khepra-MCP/pkgs/container/pqc-khepra-mcp)
[![smithery badge](https://smithery.ai/badge/skone/pqc-khepra-mcp)](https://smithery.ai/servers/skone/pqc-khepra-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.nouchix%2Fpqc--khepra--mcp-blue?style=for-the-badge)](https://registry.modelcontextprotocol.io/?q=khepra)
[![mcpservers.org](https://img.shields.io/badge/mcpservers.org-nouchix%2Fpqc--khepra--mcp-orange?style=for-the-badge)](https://mcpservers.org/servers/nouchix/pqc-khepra-mcp)
[![Cline Marketplace](https://img.shields.io/badge/Cline_Marketplace-Issue_%231824-blueviolet?style=for-the-badge)](https://github.com/cline/mcp-marketplace/issues/1824)
[![License](https://img.shields.io/badge/License-Apache_2.0-green?style=for-the-badge)](LICENSE)
[![Container](https://img.shields.io/badge/Container-ghcr.io-green?style=for-the-badge&logo=docker)](https://ghcr.io/nouchix/pqc-khepra-mcp)
[![PQC](https://img.shields.io/badge/PQC-ML--DSA--65%20%2F%20FIPS%20204-purple?style=for-the-badge)](https://csrc.nist.gov/pubs/fips/204/final)
[![Live](https://img.shields.io/badge/Live-mcp.souhimbou.ai-brightgreen?style=for-the-badge)](https://mcp.souhimbou.ai/mcp/v1/health)

**Open-source post-quantum cryptographic MCP kernel & compliance discovery server.**

Powered by **ML-DSA-65 (FIPS 204)** and **Kyber-1024 (FIPS 203)** cryptography, featuring the **World's First DoD PQC STIG** built in.

> **[PQC-01-STIG-V1R1 — Full Whitepaper →](docs/PQC-01-STIG-V1R1.md)**  
> 17 controls covering CNSA 2.0, FIPS 203/204/205, and MCP security advisories.  
> The world's first open-source DoD-style Post-Quantum Cryptography STIG for AI agents and MCP servers.

---

## Open-Source Reference Implementation & Commercial Upgrade Path

> [!NOTE]
> **v2.0.0 Architecture Clarification**:
> - **`PQC-Khepra-MCP` (This Public Repository)**: This is our **Open-Source Reference Implementation**, provided as a national security contribution to the community. It includes the foundational post-quantum MCP kernel, the DoD PQC STIG, OWASP Agentic Top 10 assessment, and baseline AI asset discovery. It is licensed under Apache 2.0.
> - **`Khepra Trust OS` (Commercial Closed-Source)**: For enterprise, defense, and CMMC-regulated customers requiring production-grade capabilities, Khepra Trust OS acts as the logical commercial upgrade path. It fully wraps this open-source kernel while introducing advanced AI Governance, Runtime Security, Privileged Enforcement (Actuation), and the proprietary AI Evidence Object (AEO) fabric. 
> - **Dependency Direction**: Strictly **one-way**. Khepra Trust OS imports this public kernel as a Go module; this public reference repository never imports private commercial code.

---

## Tiers & Feature Scope

| Tier | License Key | Open-Source / Commercial Scope | Egress |
|------|-------------|--------------------------------|--------|
| **Community** | ✅ Free Key Required | `pqc_stig` + 24 core tools (incl. `owasp_agent_assess`, `nist_map`, `scan_shadow_ai`) | Zero (Air-gapped) |
| **Sovereign** | ✅ Required | Full Shadow AI discovery, AI Policy Evaluator, AEO Evidence Graph, Passports | Zero (Air-gapped) |
| **Pharaoh** | ✅ Required | Privileged Enforcement Daemon interposition (`Deny`/`Quarantine`/`Lock`), FIPS 140-3 | Zero (Air-gapped) |

---

## What It Does

> [!IMPORTANT]
> **Zero Third-Party Analytics (By Design)**: Because KHEPRA runs entirely locally via `stdio` in Community/Enterprise modes, your tool calls are completely air-gapped. **We track absolutely zero telemetry on Smithery or any other registry.** This means you can scan sensitive DoD environments without risking your compliance data hitting a third-party proxy.

PQC-Khepra-MCP connects your AI assistant directly to a post-quantum compliance and security engine. Ask Claude, Cursor, or any MCP client to assess quantum readiness, run OWASP agentic security checks, and query DISA STIG benchmarks — all without sending data to external APIs.

**Key capabilities:**
- Post-quantum cryptographic attestation on tool calls (ML-DSA-65 / FIPS 204)
- **World's First DoD PQC STIG** — 17 controls covering CNSA 2.0 / FIPS 203/204/205 + agentic AI / MCP ([PQC-01-STIG-V1R1](docs/PQC-01-STIG-V1R1.md))
- OWASP Agentic Top 10 vulnerability assessment (`owasp_agent_assess`)
- Shadow AI asset discovery & port scanner (`scan_shadow_ai`)
- Live DISA STIG Viewer API v2 integration (`stig_live_query`)
- Practical Linux Hardening checks (`linux_hardening_check`) based on *The Practical Linux Hardening Guide*
- Air-gap and SCIF compatible — sovereign/ironbank modes make zero egress calls
- Flat annual licensing — no per-token or per-query charges
- Runs on your metal: on-prem, DoD, IC, classified environments

---

## Quickstart — Hosted Endpoint (Zero Install)

The fastest path to a live compliance tool in your AI client. No Docker, no binary, no build:

```json
{
  "mcpServers": {
    "khepra": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.souhimbou.ai/sse"]
    }
  }
}
```

Or if your client supports native SSE transport:
```
https://mcp.souhimbou.ai/sse
```

Health check: `https://mcp.souhimbou.ai/mcp/v1/health`

> **Data note:** The hosted endpoint runs in `edge` mode — DAG is in-memory and ephemeral. For persistent, signed audit trails and air-gap deployment, use the self-hosted options below.

---

## Self-Hosted Installation

For sovereign/air-gap deployment: **Docker** (recommended, no build required) or **compiled binary** (fastest startup, SCIF-ready). Both support the same environment variables and all MCP clients.

Choose your path:

| Method | Best For | Startup |
|--------|----------|---------|
| [Hosted endpoint](#quickstart--hosted-endpoint-zero-install) | Fastest start, cloud tools | Instant |
| [Docker](#option-a-docker-recommended) | Most users, easiest self-host | ~2s |
| [Compiled Binary](#option-b-compiled-binary) | Air-gap, SCIF, performance | ~300ms |

---

### Option A: Docker (Recommended)

Requires Docker Desktop or Docker Engine. The image is pre-built and ships the full compliance database — no additional downloads in sovereign mode.

```bash
# Pull once
docker pull ghcr.io/nouchix/pqc-khepra-mcp:latest

# Test it (should print the initialize response and exit)
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":0}' \
  | docker run --rm -i -e KHEPRA_MODE=sovereign ghcr.io/nouchix/pqc-khepra-mcp:latest
```

---

### Option B: Compiled Binary

Requires Go 1.21+ for building, or download a pre-built release from [GitHub Releases](https://github.com/nouchix/PQC-Khepra-MCP/releases).

```bash
git clone https://github.com/nouchix/PQC-Khepra-MCP.git
cd PQC-Khepra-MCP

# Build (cross-compile for your OS)
go build -o khepra-mcp ./cmd/khepra-mcp        # Linux / macOS
go build -o khepra-mcp.exe ./cmd/khepra-mcp    # Windows

# Test the binary
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":0}' \
  | KHEPRA_MODE=sovereign ./khepra-mcp
```

#### Windows — using the batch launcher

The repo ships a `run-mcp.bat` launcher for Windows. It uses the pre-built binary (fast path) and falls back to `go run` automatically:

```bat
:: run-mcp.bat is already in the repo at the root of PQC-Khepra-MCP
:: Point your MCP client to: cmd /c C:\path\to\PQC-Khepra-MCP\run-mcp.bat
```

---

## Adding to Your AI Client

### Claude Desktop

Config file location:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

#### Community tier — Docker (macOS / Linux)

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

#### Community tier — Docker (Windows)

```json
{
  "mcpServers": {
    "khepra": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "KHEPRA_MODE=sovereign",
        "-v", "C:\\Users\\YourName\\.khepra:/var/lib/khepra",
        "ghcr.io/nouchix/pqc-khepra-mcp:latest"
      ]
    }
  }
}
```

#### Community tier — Binary (Windows, fastest startup)

```json
{
  "mcpServers": {
    "khepra": {
      "command": "C:\\path\\to\\PQC-Khepra-MCP\\khepra-mcp.exe",
      "args": [],
      "env": {
        "KHEPRA_MODE": "sovereign",
        "KHEPRA_NETWORK_POLICY": "lan",
        "MCP_PQC_ENABLED": "true",
        "KHEPRA_MANIFEST_PATH": "C:\\path\\to\\PQC-Khepra-MCP\\manifest.json"
      }
    }
  }
}
```

#### Community tier — Binary via batch launcher (Windows)

```json
{
  "mcpServers": {
    "khepra": {
      "command": "cmd",
      "args": ["/c", "C:\\path\\to\\PQC-Khepra-MCP\\run-mcp.bat"],
      "env": {
        "KHEPRA_MODE": "sovereign",
        "KHEPRA_NETWORK_POLICY": "lan",
        "MCP_PQC_ENABLED": "true"
      }
    }
  }
}
```

#### Sovereign / Pharaoh tier (with license key)

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

After editing, restart Claude Desktop. Verify in **Settings → Developer** — you should see `khepra` with status **running** and all tools listed.

---

### Cursor

Config file: `.cursor/mcp.json` in your project root, or `~/.cursor/mcp.json` globally.

#### Docker (macOS / Linux)

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

#### Binary (macOS / Linux)

```json
{
  "servers": {
    "khepra": {
      "type": "stdio",
      "command": "/path/to/khepra-mcp",
      "args": [],
      "env": {
        "KHEPRA_MODE": "sovereign",
        "KHEPRA_MANIFEST_PATH": "/path/to/PQC-Khepra-MCP/manifest.json"
      }
    }
  }
}
```

#### Binary (Windows)

```json
{
  "servers": {
    "khepra": {
      "type": "stdio",
      "command": "C:\\path\\to\\PQC-Khepra-MCP\\khepra-mcp.exe",
      "args": [],
      "env": {
        "KHEPRA_MODE": "sovereign",
        "KHEPRA_MANIFEST_PATH": "C:\\path\\to\\PQC-Khepra-MCP\\manifest.json"
      }
    }
  }
}
```

---

### VS Code (with GitHub Copilot or Cline extension)

Config file: `.vscode/mcp.json` in your project, or user settings.

```json
{
  "servers": {
    "khepra": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "KHEPRA_MODE=sovereign",
        "-v", "${env:HOME}/.khepra:/var/lib/khepra",
        "ghcr.io/nouchix/pqc-khepra-mcp:latest"
      ]
    }
  }
}
```

Or via user `settings.json` for the Cline extension:

```json
{
  "cline.mcpServers": {
    "khepra": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "KHEPRA_MODE=sovereign",
        "ghcr.io/nouchix/pqc-khepra-mcp:latest"
      ]
    }
  }
}
```

---

### Windsurf

Config file: `~/.codeium/windsurf/mcp_config.json`

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

---

### Continue.dev

Config file: `~/.continue/config.json` — add to the `experimental.modelContextProtocolServers` array:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "khepra",
        "transport": {
          "type": "stdio",
          "command": "docker",
          "args": [
            "run", "--rm", "-i",
            "-e", "KHEPRA_MODE=sovereign",
            "ghcr.io/nouchix/pqc-khepra-mcp:latest"
          ]
        }
      }
    ]
  }
}
```

---

### Cloud / SaaS AI Tools (Claude.ai, ChatGPT, Gemini, etc.)

Use the **live hosted endpoint** at `mcp.souhimbou.ai` — no setup required:

#### Option 1 — Live hosted endpoint (recommended, zero setup)

```json
{
  "mcpServers": {
    "khepra": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.souhimbou.ai/sse"]
    }
  }
}
```

Or direct SSE URL for tools that accept it:
```
https://mcp.souhimbou.ai/sse
```

| Cloud Tool | Where to add MCP URL |
|------------|---------------------|
| Claude.ai (Pro/Team) | Settings → Integrations → MCP Servers |
| Cursor | `.cursor/mcp.json` → `url` field |
| OpenAI Assistants | API `tools` field with `type: "mcp"` |
| Glama.ai | Workspace → MCP Servers |
| Smithery.ai | Catalog → Self-hosted server |

#### Option 2 — `mcp-remote` proxy (local binary behind the bridge)

If you need sovereign mode (zero egress) proxied to a cloud tool:

```bash
# Install once
npm install -g mcp-remote

# Bridge your local sovereign instance
KHEPRA_MODE=sovereign mcp-remote \
  --server "docker run --rm -i -e KHEPRA_MODE=sovereign ghcr.io/nouchix/pqc-khepra-mcp:latest" \
  --port 3000

# Point cloud tool to:
# http://localhost:3000/sse
```

> **Security note:** In `sovereign`/`ironbank` mode, KHEPRA makes zero egress calls — only the bridge connection to the cloud tool carries data.

#### Option 3 — Smithery / MCP Registries (Community tier)

KHEPRA is listed across all major MCP discovery platforms. Cloud tools that support registry-based discovery can install it directly:

| Registry | URL |
|---|---|
| **Smithery.ai** | [smithery.ai/servers/skone/pqc-khepra-mcp](https://smithery.ai/servers/skone/pqc-khepra-mcp) |
| **MCP Registry (official)** | [registry.modelcontextprotocol.io/?q=khepra](https://registry.modelcontextprotocol.io/?q=khepra) |
| **mcpservers.org** | [mcpservers.org/servers/nouchix/pqc-khepra-mcp](https://mcpservers.org/servers/nouchix/pqc-khepra-mcp) |
| **Cline Marketplace** | [github.com/cline/mcp-marketplace/issues/1824](https://github.com/cline/mcp-marketplace/issues/1824) |
| **Live Hosted Endpoint** | [mcp.souhimbou.ai](https://mcp.souhimbou.ai/) |

```
Registry ID: io.github.nouchix/pqc-khepra-mcp
```

---

## Validation — Test Your Installation

Run this from your terminal to verify the server responds correctly:

```bash
# Docker
echo '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' \
  | docker run --rm -i -e KHEPRA_MODE=sovereign ghcr.io/nouchix/pqc-khepra-mcp:latest

# Binary (Linux / macOS)
echo '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' \
  | KHEPRA_MODE=sovereign ./khepra-mcp

# Binary (Windows PowerShell)
'{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' \
  | & ".\khepra-mcp.exe"
```

Expected output: a JSON-RPC response listing all available tools. If you see `"tools": [...]` with 12+ entries — you're connected.

#### Full protocol validation (Windows)

```powershell
# Runs the complete Claude Desktop handshake sequence and validates all responses
.\scripts\test-mcp-handshake.ps1 -BinaryPath ".\khepra-mcp.exe"

# Expected output:
# [PASS] initialize | protocolVersion=2025-11-25 | listChanged=False
# [PASS] tools/list | count=34
# TRL-10 READY - Server passes full Claude Desktop protocol validation
```

---

## MCP Tools

### Community Tier (Requires Free Key)

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
| `KHEPRA_LICENSE_KEY` | Yes (All tiers) | — | License key. Get your free Community key at [nouchix.com](https://nouchix.com) |
| `KHEPRA_MODE` | No | `sovereign` | Deployment mode: `sovereign`, `ironbank`, `hybrid`, `edge` |
| `KHEPRA_MANIFEST_PATH` | No | `manifest.json` | Path to signed tool manifest file |
| `KHEPRA_HOME` | No | `/var/lib/khepra` | Data and compliance DB directory |
| `KHEPRA_LOG_DIR` | No | `/var/log/khepra` | Log directory |
| `KHEPRA_DAG_PATH` | No | `~/.khepra/dag` | DAG audit chain storage path |
| `KHEPRA_AUDIT_LOG_PATH` | No | `~/.khepra/audit.ndjson` | Signed audit log path |
| `KHEPRA_MAX_CONCURRENT` | No | `5` | Max concurrent tool calls per agent |
| `KHEPRA_NETWORK_POLICY` | No | `lan` | Network scope: `lan`, `none`, `unrestricted` |
| `MCP_PQC_ENABLED` | No | `true` | Enable ML-DSA-65 PQC attestation on all responses |

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
| **PQC-01-STIG-V1R1** | V1R1 | **17 PQC controls (CNSA 2.0)** |
| **Total** | | **36,195+ mappings** |

---

## Licensing

**Flat annual licensing — no per-token or per-query charges.**

| Tier | Cost | License Key | Tools |
|------|------|-------------|-------|
| Community | Free | Required (Free) | `pqc_stig` + 24 core tools |
| Sovereign | Annual flat fee | Required | All 72 tools, air-gap, on-prem |
| Pharaoh | Annual flat fee | Required | All 72 tools + priority support + SLA |

- Community tier is permanently free — contribute to open-source PQC adoption
- Sovereign/Pharaoh: contact [contact@nouchix.com](mailto:contact@nouchix.com) or visit [nouchix.com](https://nouchix.com)

---

## Security

### Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Report privately via **[GitHub Security Advisories](https://github.com/nouchix/PQC-Khepra-MCP/security/advisories/new)** or email **[support@nouchix.com](mailto:support@nouchix.com)**.

| SLA | Target |
|-----|--------|
| Acknowledgement | 24 hours |
| Initial assessment | 5 business days |
| Patch / mitigation (Critical) | 30 days |

We accept encrypted reports via PGP (`keys/security_contact.asc`) and Post-Quantum channels (Dilithium / ML-DSA-65 keys in `keys/`). See [SECURITY.md](SECURITY.md) for the full disclosure policy and ASAF event taxonomy.

---

### Security Posture

> **Deploying advanced post-quantum cryptography, air-gapped isolation, and comprehensive STIG mappings — built in direct alignment with NSA & ASD Model Context Protocol guidelines.**

#### NSA & ASD MCP Security Alignment

The NSA and Australian Signals Directorate (ASD) have published specific threat vectors for AI systems interacting with local environments. KHEPRA MCP is explicitly designed to mitigate every identified vector:

| NSA/ASD Requirement | KHEPRA Implementation |
|---------------------|-----------------------|
| Cryptographic validation of tool responses | ML-DSA-65 (Dilithium) signatures on all JSON-RPC 2.0 payloads |
| Input validation & sanitization | Parameter injection resistance via strict JSON Schema validation |
| Principle of least privilege credentials | Short-lived ephemeral tokens tied to specific task execution windows |
| Comprehensive audit logging | Tamper-evident events compiled into an immutable DAG structure |
| Resource consumption limits | Rate limiting + backpressure for LLM request loops |
| Authorization gates for sensitive actions | Human-in-the-loop gate for destructive state changes |
| Environment isolation | Containerized execution with zero-egress sovereign mode |
| Software supply chain integrity | Manifest pinning for all loaded tools and dependencies |
| Network exposure reduction | Air-gappable — zero internet transit in `sovereign`/`ironbank` modes |
| Post-quantum resilience | PQC-signed DAG trail protecting against harvest-now-decrypt-later |

#### Compliance Certifications

| Framework | Status | Coverage |
|-----------|--------|----------|
| CMMC Level 2 | ✅ | Automates evidence collection for AU, CM, SI, SC domains |
| NIST SP 800-171 Rev 2 | ✅ | Logging, accountability, system integrity |
| NIST SP 800-53 Rev 5 | ✅ | Continuous monitoring (AU-2, SI-4) |
| FIPS 203 (ML-KEM) | ✅ | Key encapsulation for secure transit |
| FIPS 204 (ML-DSA) | ✅ | Digital signatures for payload authentication |
| NSM-10 PQC Mandate | ✅ | National Security Memorandum 10 compliance |
| DFARS 252.204-7012 | ✅ | Immutable forensic trails for cyber incident reporting |
| NSA MCP Security Guidelines | ✅ | Direct mapping to all published AI agent threat mitigations |

#### Live Deployment — Physical Edge

Running continuously on constrained edge hardware since **May 12, 2026** to prove efficiency in sovereign environments:

- **Hardware**: Raspberry Pi 2 · 1 GB RAM · 900 MHz ARM · Live Spectrum Router
- **SCADA Pod**: STM32U585 / QRB2210 · Modbus TCP · MQTT · Zephyr RTOS 3.4+ · Live Dilithium Signature Verification
- **Controls active**: 3 open ports secured · 12 STIG violations detected · 100% file integrity monitoring (AIDE) · 24/7 continuous operation

#### Academic Validation

| Event | Date | Institution |
|-------|------|-------------|
| **UAlbany AI Plus Symposium 2026** — *"KHEPRA Protocol: Quantum-Resilient Agentic AI Security Using Cultural Cryptography"* | March 7, 2026 | NSA CAE-CDE Institution · 200+ audience |
| **SUNY Albany Cybersecurity Showcase** — First PQC key ceremony on STM32-class device (SCADA Pod) | May 12–13, 2026 | Live demo · SCADA architecture poster |

> USPTO Provisional Patent **#73565085** — pending.  
> 🔒 Iron Bank containers in DISA vetting process.

---

## Find Us — MCP Registry Listings

> **A note on our public metrics**: You may notice our analytics or "tool execution counts" on platforms like Smithery appear very low or zero. **This is intentional.** KHEPRA installs via local `stdio` Docker connections, meaning your MCP traffic never routes through external proxy servers. Your compliance data stays on your machine, making third-party tracking cryptographically impossible.

PQC-Khepra-MCP is listed on every major MCP discovery platform:

| Platform | Link | Notes |
|---|---|---|
| **Smithery.ai** | [smithery.ai/servers/skone/pqc-khepra-mcp](https://smithery.ai/servers/skone/pqc-khepra-mcp) | One-click install for Claude, Cursor, Windsurf |
| **MCP Registry (official)** | [registry.modelcontextprotocol.io/?q=khepra](https://registry.modelcontextprotocol.io/?q=khepra) | Anthropic-curated registry — Registry ID: `io.github.nouchix/pqc-khepra-mcp` |
| **mcpservers.org** | [mcpservers.org/servers/nouchix/pqc-khepra-mcp](https://mcpservers.org/servers/nouchix/pqc-khepra-mcp) | Community discovery index |
| **Cline Marketplace** | [github.com/cline/mcp-marketplace/issues/1824](https://github.com/cline/mcp-marketplace/issues/1824) | VS Code / Cline extension marketplace |
| **Live Hosted Endpoint** | [mcp.souhimbou.ai](https://mcp.souhimbou.ai/) | Zero-install SSE endpoint — connect in 30 seconds |

---

## About NouchiX

Veteran-led advisory firm translating CMMC, NIST, and STIG mandates into executive roadmaps.

- **Sales / General**: [contact@nouchix.com](mailto:contact@nouchix.com)
- **Support**: [support@nouchix.com](mailto:support@nouchix.com)
- **Website**: [https://nouchix.com](https://nouchix.com)
- **Phone**: (518) 304-4450

Developed by SecRed Knowledge Inc. dba NouchiX, Albany, NY.




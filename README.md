# KHEPRA MCP Server

[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.nouchix%2Fpqc--khepra--mcp-blue?style=for-the-badge)](https://registry.modelcontextprotocol.io)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)](https://nouchix.com)
[![Container](https://img.shields.io/badge/Container-ghcr.io-green?style=for-the-badge&logo=docker)](https://ghcr.io/nouchix/pqc-khepra-mcp)
[![SLSA](https://img.shields.io/badge/SLSA-Level_3-blue?style=for-the-badge)](https://slsa.dev)

**Sovereign compliance engine with 36,195 STIG/CCI/NIST/CMMC mappings.**

Air-gappable. Zero token costs. Flat annual licensing. Run `ert_scan` → get a Godfather Report
with dollar-denominated business impact. The only MCP compliance server that runs on your metal.

Designed against the NSA "MCP Security Design Considerations" threat model — before NSA published it.

---

## What It Does

KHEPRA MCP connects your AI assistant directly to a hardened compliance engine. Ask Claude,
Cline, or any MCP client to scan a system, map findings to STIG/NIST/CMMC controls, and generate
an executive-ready risk report — all without sending data to external APIs.

**Key capabilities:**
- 36,195 STIG/CCI/NIST 800-53/800-171/CMMC mappings (offline BM25 index)
- Post-quantum cryptographic attestation (ML-DSA-65 / Dilithium3, FIPS 204)
- Godfather Report: dollar-denominated business impact per finding
- Human-in-the-loop gate: no report leaves the system without analyst approval
- Air-gap and SCIF compatible — zero egress, zero telemetry, zero token costs
- Flat annual licensing — no per-token or per-query charges
- Runs on your metal: on-prem, DoD, IC, classified environments
- SLSA Build Level 3 provenance + CycloneDX SBOM (every release)

---

## Quick Install

### Prerequisites
- Docker (or compatible OCI runtime)
- KHEPRA license key — [get one at nouchix.com](https://nouchix.com) or email [sales@nouchix.com](mailto:sales@nouchix.com)

### Pull the container

```bash
docker pull ghcr.io/nouchix/pqc-khepra-mcp:latest
```

### Claude Desktop (`claude_desktop_config.json`)

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

### Cursor / VS Code (`.cursor/mcp.json`)

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

## MCP Tools (13 total)

### Compliance Assessment

| Tool | Risk | Description |
|------|------|-------------|
| `ert_scan` | sandboxed | Enterprise Risk & Threat scan across STIG/NIST/CMMC/PQC. Returns structured findings with control mappings. |
| `stig_check` | sandboxed | Check a specific system path against RHEL-09-STIG-V1R3 controls. |
| `cmmc_assess` | sandboxed | Assess a system or artifact against CMMC Level 1, 2, or 3 practices. |
| `nist_map` | read-only | Offline BM25 semantic search across 36,195 STIG/CCI/NIST/CMMC mappings. Zero API calls. |

### Reporting

| Tool | Risk | Description |
|------|------|-------------|
| `godfather_report` | read-only | Generate Godfather Report (staged — requires approval). Dollar-denominated business impact per finding. |
| `godfather_approve` | read-only | Deliver a staged report after human analyst approval. HITL gate. |

### Continuous Monitoring

| Tool | Risk | Description |
|------|------|-------------|
| `khepra_watch` | read-only | Register filesystem-triggered scan. Fires `ert_scan` on path changes. |

### Agent Credential Plane (ACP)

| Tool | Risk | Description |
|------|------|-------------|
| `acp_status` | read-only | Show active agent credential status and permission scopes. |
| `acp_issue` | read-only | Issue a short-lived JIT credential for a specific agent + scope. |
| `acp_revoke` | destructive | Revoke an agent credential. Requires human confirmation. |

### Non-Human Identity (NHI)

| Tool | Risk | Description |
|------|------|-------------|
| `nhi_inventory` | read-only | Inventory all non-human identities (service accounts, API keys, tokens). |
| `nhi_orphans` | read-only | Find orphaned NHI credentials with no owning entity. |
| `nhi_excessive` | read-only | Find NHIs with excessive permissions beyond their stated purpose. |
| `nhi_expired` | read-only | Find NHI credentials past their expiry date. |
| `nhi_revoke` | destructive | Revoke an NHI credential. Requires human confirmation. |

---

## The Godfather Report

Every finding is translated into executive language:

```
Finding: RHEL-09-212030 — No FIPS-validated crypto on /etc/ssh
Severity: HIGH
Control: IA-7, SC-28, CM-6(1)
CMMC Practice: SC.L2-3.13.11
Business Impact: $2.4M estimated breach exposure (FAIR model)
Remediation Cost: $800 (4 hours engineer time)
ROI: 3,000x
Attestation: dag-node-abc123 (ML-DSA-65 signed, tamper-evident)
```

### Human-in-the-Loop Gate

```
Agent: godfather_report(framework="CMMC-L2", approval_required=true)
→ { staged_token: "abc123", summary: { total: 47, critical: 3 }, expires: "30min" }

You: Review summary. Click Approve.

Agent: godfather_approve(staged_token="abc123")
→ Full 50-page Godfather Report delivered
```

No full report is delivered without explicit human approval. Even if the agent is compromised,
the report cannot be exfiltrated without a human in the loop.

---

## Security Chain

Every tool call passes through a 9-step security chain before execution:

```
DEMARC → Rate+Concurrency → Scope Taxonomy → Loop Detect
→ Invocation Token → Manifest Pin → Polymorphic Provenance
→ RBAC/Injection → Docker Sandbox → DAG Attest → _khepra_sig
```

| Control | Implementation |
|---------|---------------|
| Signed responses | ML-DSA-65 `SecureEnvelope` + wire-level `_khepra_sig` (HMAC-SHA256) |
| Parameter injection | Scope taxonomy allow-list (STIG/NIST/CMMC) + command injection regex |
| Short-lived credentials | Per-invocation HMAC tokens (5min TTL, tool-bound, agent-bound) |
| Tamper-evident audit | ML-DSA-65-signed NDJSON chain, SHA3-256 chain-link per entry (DFARS 252.204-7012) |
| Rate limiting | Per-agent sliding-window rate limiter (default: 100 req/min) |
| Prompt-storm defense | Per-agent concurrency cap (default: 5 concurrent calls) |
| Loop detection | MistakeTracker: 5 consecutive errors or 3 identical calls → session pause |
| Sandbox isolation | Docker with Seccomp + AppArmor + per-tool CapabilityMounts |

---

## Deployment Modes

| Mode | Description |
|------|-------------|
| `sovereign` | Air-gapped, full autonomous ops, zero external deps (default) |
| `ironbank` | DoD/IC production, full compliance frameworks |
| `hybrid` | Edge + network-wide coordination |
| `edge` | Autonomous endpoint security |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KHEPRA_LICENSE_KEY` | Yes | — | License key. Get at [nouchix.com](https://nouchix.com) |
| `KHEPRA_MODE` | No | `sovereign` | Deployment mode |
| `KHEPRA_HOME` | No | `/var/lib/khepra` | Data directory |
| `KHEPRA_LOG_DIR` | No | `/var/log/khepra` | Log directory |

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

## Air-Gap Deployment

```bash
# Transfer to air-gapped host
docker save ghcr.io/nouchix/pqc-khepra-mcp:latest | gzip > khepra-mcp.tar.gz
# On air-gapped host:
docker load < khepra-mcp.tar.gz
```

In sovereign mode: zero external network calls. License validated offline via ML-DSA-65 signed
`license.sig`. No telemetry, no heartbeat, no egress.

---

## Supply Chain Security

- **SBOM**: CycloneDX JSON + XML generated on every release
- **Provenance**: SLSA Build Level 3 via GitHub Actions + Sigstore OIDC
- **Signature**: cosign keyless signing (Sigstore transparency log)
- **Vulnerability gate**: `govulncheck` on every commit — zero CVEs gate before push
- **OCI label**: `io.modelcontextprotocol.server.name` for registry ownership verification

---

## Integrations

- [Antigravity SDK](docs/antigravity-integration.md) — HITL pipeline with `ert_scan → godfather_approve`
- Claude Desktop, Cline, Cursor, VS Code — all supported via stdio transport

---

## Licensing

**Flat annual licensing — no per-token or per-query charges.**

- Free evaluation for DoD/IC contractors (non-production)
- Contact [sales@nouchix.com](mailto:sales@nouchix.com) or [nouchix.com](https://nouchix.com)

---

## About NouchiX

Veteran-led advisory firm translating CMMC, NIST, and STIG mandates into executive roadmaps.

- **Sales**: [sales@nouchix.com](mailto:sales@nouchix.com)
- **Support**: [support@nouchix.com](mailto:support@nouchix.com)
- **Security**: [cybersouhimbou@secredknowledgeinc.tech](mailto:cybersouhimbou@secredknowledgeinc.tech)
- **Website**: [https://nouchix.com](https://nouchix.com)
- **Phone**: (332) 275-4335

Developed by SecRed Knowledge Inc. dba NouchiX, Albany, NY.

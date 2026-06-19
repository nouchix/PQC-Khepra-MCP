# PQC-Khepra-MCP — AI Agent Installation Guide

> This file helps AI coding agents (Cline, Claude, Cursor, Windsurf) automatically install and configure PQC-Khepra-MCP.

## Prerequisites

- **Go 1.22+** installed and in PATH
- **Git** installed

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/nouchix/PQC-Khepra-MCP.git
cd PQC-Khepra-MCP
```

### 2. Build the Binary

```bash
go build -o khepra-mcp ./cmd/khepra-mcp/
```

On Windows, the output will be `khepra-mcp.exe`.

### 3. Create the Data Directory

```bash
# Linux/macOS
mkdir -p ~/.khepra

# Windows (PowerShell)
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.khepra"
```

### 4. Configure MCP Client

Add the following to your MCP client configuration:

#### For Cline / VS Code (`settings.json` → `mcpServers`)

```json
{
  "mcpServers": {
    "khepra-mcp": {
      "command": "/path/to/PQC-Khepra-MCP/khepra-mcp",
      "args": [],
      "env": {
        "KHEPRA_MODE": "sovereign",
        "KHEPRA_DATA_DIR": "/home/USER/.khepra",
        "KHEPRA_NETWORK_POLICY": "lan",
        "MCP_PQC_ENABLED": "true"
      }
    }
  }
}
```

#### For Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "khepra-mcp": {
      "command": "/path/to/PQC-Khepra-MCP/khepra-mcp",
      "args": [],
      "env": {
        "KHEPRA_MODE": "sovereign",
        "KHEPRA_DATA_DIR": "/home/USER/.khepra",
        "KHEPRA_NETWORK_POLICY": "lan",
        "MCP_PQC_ENABLED": "true"
      }
    }
  }
}
```

**Important:** Replace `/path/to/PQC-Khepra-MCP/khepra-mcp` with the actual absolute path to the built binary, and `/home/USER/.khepra` with the actual home directory path.

On Windows, use backslashes: `C:\\Users\\USERNAME\\blackbox\\PQC-Khepra-MCP\\khepra-mcp.exe`

### 5. Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `KHEPRA_MODE` | No | `sovereign` | Deployment mode: `sovereign`, `ironbank`, `hybrid`, `edge` |
| `KHEPRA_DATA_DIR` | No | `~/.khepra` | Directory for DAG storage, audit logs, and flight recorder |
| `KHEPRA_NETWORK_POLICY` | No | `lan` | Network policy: `lan` (local only), `wan` (remote allowed) |
| `MCP_PQC_ENABLED` | No | `true` | Enable ML-DSA-65 post-quantum signing on all tool calls |
| `KHEPRA_MANIFEST_PATH` | No | `manifest.json` | Path to signed tool manifest |
| `KHEPRA_LICENSE_KEY` | No | *(none)* | License key for Enterprise tier features |
| `PHANTOM_SYMBOL` | No | `Eban` | Adinkra symbol binding for OPSEC identity |
| `KHEPRA_MAX_CONCURRENT` | No | `5` | Max concurrent tool calls per agent |

### 6. Verify Installation

After configuring, restart your MCP client. The server should appear with **72 tools** available.

You can also test manually:

```bash
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}' | ./khepra-mcp
```

Expected: A JSON-RPC response on stdout with `serverInfo.name: "khepra-mcp"`.

### 7. Available Tool Categories (72 tools)

- **Compliance**: `stig_check`, `cmmc_assess`, `pqc_stig`, `nist_map`, `compliance_scan`
- **ERT Scanner**: `ert_scan`, `ert_readiness`, `ert_architect`, `ert_crypto`, `ert_godfather`
- **Threat Intel**: `threat_model`, `threat_lookup`, `drift_detect`, `attack_graph`
- **Incident Response**: `ir_incident`, `ir_add_ioc`
- **KASA AI**: `kasa_start`, `kasa_status`, `ea_evolve`, `ea_threat_score`, `ea_risk_summary`, `quantum_optimize`
- **PQC Crypto**: `pqc_sign`, `pqc_verify`, `pqc_keygen`
- **DAG Attestation**: `dag_write`, `dag_query`, `dag_audit`, `dag_attestation`
- **Forensics**: `forensic_snapshot`, `fim_baseline`, `audit_dag_integrity`
- **Scanning**: `enumerate_host`, `fingerprint_device`, `port_scan`, `vuln_scan`, `secret_scan`, `container_scan`, `sbom_generate`
- **Flight Recorder**: `agent_record`, `flight_record`, `flight_export`
- **OPSEC**: `phantom_stealth`, `identity_shroud`, `identity_epiphany`
- **Disaster Recovery**: `drbc_backup`, `drbc_restore`

## Troubleshooting

- **"manifest not found"**: The binary looks for `manifest.json` in the current working directory. Either set `KHEPRA_MANIFEST_PATH` or run from the repo root.
- **"PQC key generation failed"**: Ensure Go was built with CGO_ENABLED=0 (the binary uses pure-Go Cloudflare CIRCL).
- **No tools showing**: Check that stdout contains only JSON-RPC frames (no log output). All logs go to stderr by design.

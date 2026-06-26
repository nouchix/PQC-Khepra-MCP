# KHEPRA — PQC Compliance MCP for VS Code

Registers the [KHEPRA MCP server](https://github.com/nouchix/PQC-Khepra-MCP) with VS Code's built-in MCP client, so Copilot Chat / agent mode (and any other VS Code AI extension that consumes MCP servers) can call KHEPRA's STIG/NIST/CMMC compliance tools directly — no manual `mcp.json` editing required.

Community tier runs out of the box, no license key, zero egress (sovereign mode by default).

## What it does

On startup, this extension registers an MCP server definition that launches KHEPRA via Docker:

```
docker run --rm -i -e KHEPRA_MODE=sovereign ghcr.io/nouchix/pqc-khepra-mcp:latest
```

You'll see **KHEPRA Compliance Server** appear under VS Code's MCP servers list (Command Palette → "MCP: List Servers"). Ask Copilot Chat (agent mode) to run `pqc_stig` against your workspace to check quantum-readiness against PQC-01-STIG-V1R1 — no setup beyond installing Docker.

## Requirements

- VS Code 1.102 or later
- Docker (or a downloaded `khepra-mcp` binary, see Settings below)

## Settings

| Setting | Description |
|---|---|
| `khepra.mode` | `sovereign` (default, zero egress), `ironbank`, `hybrid`, or `edge` |
| `khepra.transport` | `docker` (default) or `binary` |
| `khepra.binaryPath` | Path to a compiled `khepra-mcp` binary, used when `transport` is `binary` (fastest startup, required for air-gapped/SCIF use) |
| `khepra.licenseKey` | Sovereign/Pharaoh tier license key. Leave blank for the free Community tier |

## Tiers

- **Community** (free, no key): `pqc_stig` + 12 core tools
- **Sovereign / Pharaoh** (license key required): all 34 tools, including `ert_scan` and the Godfather Report

See the [project README](https://github.com/nouchix/PQC-Khepra-MCP) for full tool documentation and the [PQC-01-STIG-V1R1 whitepaper](https://github.com/nouchix/PQC-Khepra-MCP/blob/main/Whitepaper.md).

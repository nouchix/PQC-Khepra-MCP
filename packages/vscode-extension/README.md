# KHEPRA — PQC Security & Flight Recording MCP for VS Code

Registers the [KHEPRA MCP server](https://github.com/nouchix/PQC-Khepra-MCP) with VS Code's built-in MCP client, so Copilot Chat / agent mode (and any other VS Code AI extension that consumes MCP servers) gets automatic ML-DSA-65 post-quantum signing, client-side autonomous flight recording, and local asset discovery — no manual `mcp.json` editing required.

Community tier runs out of the box, no license key, zero egress (sovereign mode by default). Zero STIG or compliance databases in the free community tier.

## What it does

On startup, this extension registers an MCP server definition that launches KHEPRA via Docker:

```
docker run --rm -i -e KHEPRA_MODE=sovereign ghcr.io/nouchix/pqc-khepra-mcp:latest
```

You'll see **KHEPRA Security Kernel** appear under VS Code's MCP servers list (Command Palette → "MCP: List Servers"). Every agent tool call is automatically attested with ML-DSA-65 signatures and recorded to an immutable NDJSON flight log. To unlock the full 100-tool Master Kernel with 36,195 STIG/CMMC compliance controls, ERT analysis, and automated C3PAO evidence packages, upgrade to KTOS.

## Requirements

- VS Code 1.102 or later
- Docker (or a downloaded `khepra-mcp` binary, see Settings below)

## Settings

| Setting | Description |
|---|---|
| `khepra.mode` | `sovereign` (default, zero egress), `ironbank`, `hybrid`, or `edge` |
| `khepra.transport` | `docker` (default) or `binary` |
| `khepra.binaryPath` | Path to a compiled `khepra-mcp` binary, used when `transport` is `binary` (fastest startup, required for air-gapped/SCIF use) |
| `khepra.licenseKey` | KTOS commercial subscription license key. Leave blank for the free Community tier |

## Tiers & Upgrade Path

- **Community (Free Open-Core Kernel, no key)**: 14 core tools including ML-DSA-65 post-quantum signing (`pqc_keygen`, `pqc_sign`, `pqc_verify`), autonomous flight recorder (`flight_record`, `flight_export`, `agent_record`), local host & asset discovery (`enumerate_host`, `fingerprint_device`, `discover_assets`), threat lookup, and NIST mapping teaser. Zero STIG databases.
- **KTOS Master Kernel (Subscription required)**: Full 100+ tools including `ert_scan`, Godfather Report, 36,195 DISA STIG / CMMC mappings, live STIGViewer API v2 batch crosswalks, SEKHEM L7 PQC-WAF, and automated C3PAO evidence packages.

See the [project README](https://github.com/nouchix/PQC-Khepra-MCP) for full tool documentation and architecture specifications.


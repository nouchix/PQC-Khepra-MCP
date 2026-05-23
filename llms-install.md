# KHEPRA MCP Server — AI Assistant Install Guide

This guide helps an AI assistant (Claude, Cline, Cursor, etc.) set up the KHEPRA MCP Server automatically.

## Step 1 — Check Docker

Verify Docker is installed and running:

```bash
docker --version
docker info
```

If Docker is not installed, direct the user to https://docs.docker.com/get-docker/ and stop.

## Step 2 — Pull the Container

```bash
docker pull ghcr.io/nouchix/pqc-khepra-mcp:latest
```

This is a ~200MB download. The container is fully self-contained — no external network calls after pull.

## Step 3 — Obtain a License Key

The user needs a `KHEPRA_LICENSE_KEY`.
- Free evaluation (DoD/IC non-production): email [sales@nouchix.com](mailto:sales@nouchix.com)
- Commercial license: [https://nouchix.com](https://nouchix.com)

Ask the user: **"Do you have a KHEPRA license key?"**
- If yes: proceed with their key.
- If no: stop and direct them to obtain one.

## Step 4 — Write the MCP Configuration

Detect the user's MCP client and write the appropriate config:

### Claude Desktop
Config file: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

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
        "KHEPRA_LICENSE_KEY": "<USER_LICENSE_KEY>"
      }
    }
  }
}
```

### Cline / VS Code
Config file: `~/.cline/mcp_settings.json` or VS Code settings

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
        "ghcr.io/nouchix/pqc-khepra-mcp:latest"
      ],
      "env": {
        "KHEPRA_LICENSE_KEY": "<USER_LICENSE_KEY>"
      }
    }
  }
}
```

### Cursor
Config file: `~/.cursor/mcp.json`

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
        "KHEPRA_LICENSE_KEY": "<USER_LICENSE_KEY>"
      }
    }
  }
}
```

## Step 5 — Verify Installation

Restart the MCP client. Then test with:

```
List the available KHEPRA tools
```

Expected: the assistant lists `ert_scan`, `stig_check`, `nist_map`, `cmmc_assess`, `godfather_report`.

Then run a smoke test:

```
Run ert_scan on /tmp and show me the summary
```

## Air-Gap Deployment

For SCIF / air-gapped environments:

```bash
# On internet-connected host:
docker save ghcr.io/nouchix/pqc-khepra-mcp:latest | gzip > khepra-mcp-1.0.0.tar.gz

# Transfer khepra-mcp-1.0.0.tar.gz via approved media

# On air-gapped host:
docker load < khepra-mcp-1.0.0.tar.gz
```

Then use the same MCP config above — the container makes no network calls.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `docker: command not found` | Install Docker Desktop or Docker Engine |
| `License validation failed` | Check `KHEPRA_LICENSE_KEY` value; contact support@nouchix.com |
| `Container exits immediately` | Check `docker logs` for error; verify volume mounts exist |
| Tools not appearing in client | Restart MCP client after config change |

## Support

- Email: [support@nouchix.com](mailto:support@nouchix.com)
- Website: [https://nouchix.com](https://nouchix.com)

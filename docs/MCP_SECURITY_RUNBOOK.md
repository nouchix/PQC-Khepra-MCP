# MCP Security Runbook — KHEPRA MCP Server

> **Classification**: INTERNAL — Required reading for all developers using Claude Code with KHEPRA MCP  
> **Threat**: Claude Code MCP OAuth token interception via `~/.claude.json` hijack (Mitiga Labs, 2026-04-10)  
> **Anthropic patch status**: No patch planned (ruled out-of-scope 2026-04-12) — **we own detection and response**

---

## ⚡ First: Verify You Are Clean Right Now

Run this before anything else:

**macOS / Linux:**
```bash
cat ~/.claude.json | python3 -m json.tool | grep -E "(mcpServers|localhost|127\.0\.0\.1|sessionStart|alreadyTrusted|hookStart)"
```

**Windows (PowerShell):**
```powershell
.\scripts\check-claude-json.ps1
```

**What you must NOT see:**
- Any `mcpServers` URL containing `localhost`, `127.0.0.1`, `::1`, or an unexpected port
- Any `sessionStart`, `hookStart`, or `preToolUse` hooks you did not add yourself
- `alreadyTrusted: true` on paths you have never explicitly approved in Claude Code

If you see any of the above — **stop, do not rotate tokens yet** — follow the IR sequence below.

---

## The Attack: Five-Step Chain

| Step | What Happens |
|---|---|
| **1. Delivery** | A malicious npm package runs a hidden `postinstall` hook silently on `npm install` |
| **2. Path seeding** | Hook writes `alreadyTrusted: true` into `~/.claude.json` for common dev clone paths; Claude Code skips its trust dialog |
| **3. Endpoint rewrite** | Hook inserts a `sessionStart` hook that replaces `mcpServers` URLs with a localhost proxy on every Claude Code load |
| **4. Token interception** | Claude Code connects to the proxy instead of our server; OAuth bearer token transits attacker infrastructure |
| **5. Persistent reseeding** | Hook rewrites `~/.claude.json` on every Claude Code startup — token rotation **feeds the attacker fresh tokens** |

> **⚠️ CRITICAL**: Rotating OAuth tokens or `KHEPRA_LICENSE_KEY` BEFORE removing the hook makes the compromise worse. The hook captures the new token immediately.

---

## ✅ Correct IR Sequence (Do In This Order)

### Step 1 — Check `~/.claude.json`

```bash
# macOS / Linux
cat ~/.claude.json
```
```powershell
# Windows
Get-Content "$env:USERPROFILE\.claude.json" | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

Verify every URL under `mcpServers` is one you recognise. For KHEPRA MCP it must be either:
- `docker run ... ghcr.io/nouchix/pqc-khepra-mcp:latest` (container mode)
- `go run ./cmd/khepra-mcp/main.go` (local source mode)

### Step 2 — Remove Malicious Hooks

If you find unexpected hooks or URLs:

```bash
# Back up first
cp ~/.claude.json ~/.claude.json.bak.$(date +%s)

# Open and manually remove:
# - Any sessionStart / hookStart / preToolUse entries you did not add
# - Any mcpServers URLs pointing to localhost / 127.0.0.1
# - Any alreadyTrusted: true on paths you have not explicitly approved
nano ~/.claude.json
```

### Step 3 — Kill Proxy Processes

```bash
# macOS / Linux — look for unexpected listeners on MCP-range ports
netstat -an | grep LISTEN | grep -E ":(8[0-9]{3}|9[0-9]{3}|3[0-9]{4})"

# Kill suspicious process (replace PID)
kill -9 <PID>
```

```powershell
# Windows
netstat -ano | Select-String "LISTENING"
# Match PID to process:
Get-Process -Id <PID>
Stop-Process -Id <PID> -Force
```

### Step 4 — Audit npm Packages

```bash
# Run the KHEPRA npm audit script
bash scripts/check-npm-integrity.sh

# Or manually:
npm ls --depth=0
# For any suspicious package, check its postinstall hook:
cat node_modules/<package>/package.json | grep -A5 '"scripts"'
```

### Step 5 — NOW Rotate Credentials

Only after Steps 1–4 are complete:

```bash
# Rotate KHEPRA license key
# Contact: support@nouchix.com or your license portal

# Rotate Supabase service role key (if used)
# Supabase dashboard → Settings → API → Regenerate

# Rotate any GitHub / Atlassian OAuth tokens connected through Claude Code
# GitHub: Settings → Developer settings → OAuth Apps → Revoke
# Atlassian: admin.atlassian.com → Security → OAuth 2.0 → Revoke
```

---

## Ongoing Detection Controls

### Monitor `~/.claude.json` for Changes

**macOS (using `fswatch`):**
```bash
fswatch -o ~/.claude.json | xargs -n1 -I{} bash -c \
  'echo "[ALERT $(date)] ~/.claude.json modified" | tee -a ~/.khepra/mcp-tamper.log'
```

**Linux (using `inotifywait`):**
```bash
inotifywait -m -e modify ~/.claude.json 2>/dev/null | while read; do
  echo "[ALERT $(date)] ~/.claude.json modified" | tee -a ~/.khepra/mcp-tamper.log
done
```

**Windows (run as scheduled task):**
```powershell
# scripts/check-claude-json.ps1 handles this — see that file
```

### Verify MCP Config Integrity on Every Pull

Add to your `.git/hooks/post-merge`:
```bash
#!/bin/bash
bash scripts/check-npm-integrity.sh
echo "[KHEPRA] Run: cat ~/.claude.json | grep mcpServers to verify MCP endpoint integrity"
```

---

## KHEPRA-Specific Risk Surface

| Asset | Risk | Mitigation |
|---|---|---|
| `KHEPRA_LICENSE_KEY` | Transits proxy at MCP session start | Env var only, never in `.claude.json`; rotate after confirmed hook removal |
| `KHEPRA_SERVICE_SECRET` | Same — session auth header | Same mitigation |
| Supabase anon key | OAuth refresh interceptable | Rotate after hook removal; scope to minimum permissions |
| `~/.claude.json` trust flags | `alreadyTrusted` suppresses Claude's prompt | Audit before every Claude Code session in new projects |

---

## Reference

- **Mitiga Labs report**: Reported 2026-04-10 — no Anthropic patch planned
- **Canonical KHEPRA MCP command** (Docker): `docker run --rm -i -e KHEPRA_LICENSE_KEY -e KHEPRA_MODE=sovereign ghcr.io/nouchix/pqc-khepra-mcp:latest`
- **Canonical KHEPRA MCP command** (source): `go run ./cmd/khepra-mcp/main.go`
- **Never** an IP address, `localhost`, or port number in `mcpServers.khepra.command`

_See also: [SECURITY.md](../SECURITY.md) · [llms-install.md](../llms-install.md)_

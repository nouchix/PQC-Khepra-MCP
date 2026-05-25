# KHEPRA + Antigravity SDK — Reference Integration

## Overview

This document shows how KHEPRA's MCP tools compose with the Antigravity agentic AI platform
to produce the `ert_scan → godfather_report → ask_user` pipeline — the exact agentic pattern
ASD/CISA endorses in "Careful Adoption of Agentic AI Services."

The pattern demonstrates three properties:
1. **Minimal footprint** — each tool has the narrowest possible capability scope
2. **Human-in-the-loop** — no compliance report leaves the system without analyst approval
3. **Cryptographic accountability** — every tool call is DAG-attested and `_khepra_sig`-verifiable

---

## The Pipeline

```
┌─────────────────────────────────────────────────────────┐
│  Antigravity Agent                                       │
│                                                          │
│  1. ert_scan(project_path, framework="CMMC-L2")         │
│     → ERT findings (SBOM + Grype + Secrets + PQC)       │
│                                                          │
│  2. godfather_report(                                    │
│       framework="CMMC-L2",                               │
│       approval_required=true   ← HITL gate engaged      │
│     )                                                    │
│     → { staged_token: "abc123", summary: { ... } }      │
│                                                          │
│  3. ask_user(                                            │
│       "Report staged. 47 findings (3 CRITICAL).          │
│        Review summary and approve?"                      │
│     )                                                    │
│     → User reviews, clicks "Approve"                    │
│                                                          │
│  4. godfather_approve(staged_token="abc123")             │
│     → Full 50-page Godfather Report delivered            │
└─────────────────────────────────────────────────────────┘
```

---

## Antigravity Agent Definition (YAML)

```yaml
# khepra_compliance_agent.yaml
name: khepra-compliance-agent
description: |
  Automated CMMC Level 2 assessment with human-in-the-loop Godfather Report delivery.
  Satisfies ASD/CISA agentic AI best practices: minimal footprint, human oversight,
  and cryptographically verifiable outputs.

tools:
  - name: ert_scan
    server: khepra-mcp
    risk: sandboxed

  - name: godfather_report
    server: khepra-mcp
    risk: read-only      # Staged — no sensitive output leaves without approval

  - name: godfather_approve
    server: khepra-mcp
    risk: read-only      # Validates staged token, delivers pre-computed report

  - name: nist_map
    server: khepra-mcp
    risk: read-only      # Zero-API offline control mapping

  - name: khepra_watch
    server: khepra-mcp
    risk: read-only      # Registers filesystem watch (no write access)

human_in_loop:
  enabled: true
  triggers:
    - tool: godfather_report
      condition: "args.approval_required == true"
      message_template: |
        Godfather Report staged for engagement {{ args.engagement_id }}.
        Summary: {{ result.summary.total_findings }} findings
        ({{ result.summary.critical_count }} CRITICAL, {{ result.summary.high_count }} HIGH).
        Token expires: {{ result.expires_at }}.
        **Approve delivery?**
      approval_action:
        tool: godfather_approve
        args:
          staged_token: "{{ result.staged_token }}"

steps:
  - id: scan
    tool: ert_scan
    args:
      project_path: "{{ input.project_path }}"
      framework: "{{ input.framework | default('CMMC-L2') }}"
      lanes: ["sast", "sca", "secrets", "sbom", "pqc"]

  - id: nist_lookup
    tool: nist_map
    args:
      query: "{{ steps.scan.result.summary.top_finding_title }}"
      framework: "{{ input.framework | default('CMMC-L2') }}"
      top_k: 5
    condition: "steps.scan.result.summary.total_findings > 0"

  - id: report
    tool: godfather_report
    args:
      framework: "{{ input.framework | default('CMMC-L2') }}"
      engagement_id: "{{ input.engagement_id }}"
      approval_required: true
```

---

## Security Properties

### 1. Minimal Footprint (ASD/CISA Principle 1)

`ert_scan` runs in Docker with `CapabilityMounts` — it reads only the directories declared
in its manifest. A RHEL-9 scan gets `/etc`, `/var/log`, `/opt/stig-db` and nothing else.

```json
{
  "name": "ert_scan",
  "capability_mounts": ["/etc", "/var/log", "/opt/stig-db"],
  "max_privilege": "read-only",
  "network_allowed": false
}
```

### 2. Human-in-the-Loop (ASD/CISA Principle 3)

`godfather_report` with `approval_required=true` never returns the full report. It returns
a summary + 30-minute TTL token. The full report is delivered only when a human calls
`godfather_approve`. Even if the agent is compromised, the full report cannot be exfiltrated
without human interaction.

### 3. Cryptographic Accountability

Every tool response includes:
- `envelope.signature` — ML-DSA-65 over the result body (FIPS 204)
- `_khepra_sig` — HMAC-SHA256 at the JSON-RPC wire level (verify without SDK)
- `envelope.attestation_id` — DAG node ID proving the result was recorded

```bash
# Verify any historical result
adinkhepra dag verify --node-id <attestation_id>
```

### 4. Invocation Tokens (ASD/CISA Short-Lived Credentials)

Each tool call issues a 5-minute HMAC token bound to the specific tool, agent identity,
and scan profile. Token reuse across sessions is rejected. An exfiltrated token expires in ≤5 minutes.

---

## Registering KHEPRA with Antigravity

```bash
antigravity mcp add \
  --name khepra-mcp \
  --transport stdio \
  --command "docker run --rm -i -e KHEPRA_LICENSE_KEY ghcr.io/nouchix/pqc-khepra-mcp:latest" \
  --env KHEPRA_LICENSE_KEY="${KHEPRA_LICENSE_KEY}" \
  --trust-level verified

antigravity agent run khepra_compliance_agent.yaml \
  --input project_path=/path/to/your/system \
  --input engagement_id=$(uuidgen) \
  --input framework=CMMC-L2
```

---

## Air-Gap Deployment

```bash
export ANTHROPIC_API_KEY=""
export OPENROUTER_API_KEY=""

adinkhepra mcp serve --offline
# [G0DM0D3] Provider: Offline (Rule-Based) — no external dependencies
# [MCP] Server: Ready — 13 tools registered
```

All 13 compliance tools work without any network access. G0DM0D3 responses are rule-based
rather than LLM-generated in offline mode; all compliance data is fully accurate.

---

## Compliance Evidence Package

| Artifact | Source | Location |
|---|---|---|
| ERT scan results | `ert_scan` | Returned in tool response |
| Godfather Report | `godfather_approve` | JSON report body |
| DAG attestation chain | All tool calls | `/var/lib/khepra/dag.db` |
| ML-DSA-65 signatures | Every envelope | Embedded in each response |
| Signed audit log | NDJSON per-entry chain | `/var/log/khepra/audit.ndjson` |
| SBOM | `supply-chain.yml` CI | `sbom-cyclonedx.json` |
| SLSA Build L3 provenance | `supply-chain.yml` CI | `khepra-mcp.intoto.jsonl` |

All artifacts constitute a CMMC Level 2 assessment evidence package that a C3PAO can
verify without requiring access to the system under assessment.

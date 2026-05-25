# KHEPRA MCP Security Posture
### One-Page Briefing for DoD Acquisition Officers and C3PAO Auditors

**Version 1.0 | Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY**

---

## The Threat KHEPRA Was Built to Defeat

The NSA "Model Context Protocol Security Design Considerations" advisory (2025) identifies
four primary attack vectors against AI-serving MCP servers:

1. **Unsigned JSON-RPC responses** — any network hop can tamper with tool output
2. **Parameter injection** — compromised agents pass malicious `target`, `scope`, or `profile` values
3. **Credential accumulation** — long-lived session tokens become high-value targets
4. **Prompt storms** — rapid invocation loops exhaust server resources

KHEPRA was designed against this exact threat model — before NSA published the document.

---

## Security Control Mapping

| NSA/ASD Requirement | KHEPRA Implementation | File Reference |
|---|---|---|
| Signed tool responses | ML-DSA-65 `SecureEnvelope` + wire-level `_khepra_sig` (SHA3-256 + HMAC) | `pkg/mcp/chain.go`, `pkg/mcp/router.go` |
| Parameter injection resistance | Scope taxonomy allow-list (STIG/NIST/CMMC) + generic injection detection | `pkg/mcp/scope_taxonomy.go`, `pkg/mcp/validation.go` |
| Short-lived credentials | Per-invocation HMAC tokens (5min TTL, tool-bound, agent-bound) | `pkg/mcp/invocation_token.go` |
| Tamper-evident audit logs | ML-DSA-65-signed NDJSON chain (SHA3-256 chain-link per entry) | `pkg/mcp/signed_audit_log.go` |
| Rate limiting + backpressure | Per-agent rate limiter + concurrent call cap (default: 5) | `pkg/mcp/validation.go` |
| Human-in-the-loop gate | `godfather_approve` staged report delivery with 30min TTL token | `pkg/mcp/tools/godfather_tools.go` |
| Sandbox isolation | Docker with Seccomp + AppArmor + per-tool CapabilityMounts | `pkg/mcp/sandbox.go` |
| Manifest pinning | SHA-256 + ML-DSA-65 signed tool manifest, fail-closed on mismatch | `pkg/mcp/manifest.go` |
| Loop detection | MistakeTracker with sliding-window dedup across agent+tool+args | `pkg/mcp/validation.go` |
| Air-gappable operation | OfflineProvider fallback (G0DM0D3 Layer 3 completely optional) | `pkg/g0dm0d3/server.go` |
| PQC-signed DAG trail | ML-DSA-65 + SHA3-256 every node, content-addressed immutable graph | `pkg/ea/engine.go` |

---

## What No Other MCP Compliance Server Can Claim

| Claim | Evidence |
|---|---|
| **Air-gappable at Layer 2** | `OfflineProvider{}` → zero external network calls, zero token spend |
| **PQC-native, not PQC-bolted-on** | Dilithium3 / ML-DSA-65 is the primary signing key, not a wrapper |
| **Evolutionarily self-hardening** | EA engine (`pkg/ea/`) continuously evolves security strategy genomes |
| **Tamper-evident evolution history** | Every EA generation is ML-DSA-65 signed and DAG-committed |
| **NSA/CISA/DISA three-way alignment** | STIG mappings, CMMC practices, and NSA PQC mandate in one engine |
| **DFARS 252.204-7012 audit chain** | Per-entry signed NDJSON log with SHA3-256 chain links |

---

## Deployment Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        KHEPRA MCP Server                                │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │  Security Chain (Layer 1 — MCP Transport)                       │   │
│  │  DEMARC → Rate+Concurrency → Scope Taxonomy → Loop Detect       │   │
│  │  → Invocation Token → Manifest Pin → Poly Provenance            │   │
│  │  → RBAC/Injection → Docker Sandbox → DAG Attest → _khepra_sig   │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │  Core Engine (Layer 2+4 — STIG/DAG/ASAF/PQC)                  │   │
│  │  ert_scan  stig_check  cmmc_assess  godfather_report            │   │
│  │  nist_map  acp_*  nhi_*  khepra_watch  godfather_approve         │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │  AI Layer (Layer 3 — G0DM0D3, isolated)                        │   │
│  │  Anthropic → OpenRouter → Offline (zero external calls)         │   │
│  └───────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Compliance Certifications Target

| Framework | Status |
|---|---|
| CMMC Level 2 (110 practices) | ✅ All 14 domains mapped |
| NIST SP 800-171 Rev 2 | ✅ 110 requirements, STIG-mapped |
| NIST SP 800-53 Rev 5 | ✅ Cross-referenced in nist_map |
| FIPS 203 (ML-KEM) | ✅ Kyber-1024 integrated |
| FIPS 204 (ML-DSA) | ✅ Dilithium3 primary signing key |
| NSM-10 PQC Mandate | ✅ Migration inventory via ert_scan |
| DFARS 252.204-7012 | ✅ Per-entry signed audit chain |

---

*For C3PAO evidence packages, run `godfather_report` with `framework=CMMC-L2`.
The resulting report includes the DAG node ID proving the assessment was signed and time-stamped.*

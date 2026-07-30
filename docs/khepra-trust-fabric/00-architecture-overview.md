# 00 — KHEPRA Trust Fabric: Architecture Overview

> Status: **Draft / RFC** · Owner: KHEPRA Core · Supersedes: none
> This document evolves the repository from `PQC-Khepra-MCP` (a post-quantum MCP
> security server) into the **KHEPRA Trust Fabric** — an identity, behavior,
> evidence, and citizenship layer for autonomous AI agents operating inside
> regulated enterprises.

## 1. Positioning

KHEPRA is **not** an MCP server. KHEPRA is a **trust infrastructure layer**
that allows organizations to deploy autonomous AI while maintaining
cryptographic proof, compliance alignment, and operational control.

| Rejected framing            | KHEPRA framing                               |
| --------------------------- | -------------------------------------------- |
| AI security                 | Agent citizenship infrastructure             |
| AI governance               | Cryptographic proof of autonomous action     |
| AI observability            | Behavioral attestation + residual intelligence |
| MCP security server         | Trust fabric for autonomous work             |

## 2. The core problem

Enterprises live in two disconnected realities:

```
Reality 1 — Doing security       Reality 2 — Proving security
─────────────────────────       ─────────────────────────────
patching                        audits
scanning                        customer questionnaires
configuring controls            authorization packages
monitoring                      certifications
enforcing policies              regulatory reviews

           Security Work
                |
                X   ← evidence layer is disconnected
                |
          Evidence Required
```

Traditional GRC produces documents *about* actions. KHEPRA produces
**cryptographic proof that an autonomous action happened under an authorized
policy, with mapped controls, and verified execution** — as a byproduct of the
action itself.

## 3. Protocol layers

```
                Agent
                  │
       Identity Attestation          ← PQC identity (ML-DSA / ML-KEM)
                  │
         Intent Declaration          ← signed pre-execution intent
                  │
          MCP Tool Execution         ← policy-decided, brokered call
                  │
   Residual Intelligence Capture     ← behavioral trace + side-effects
                  │
           Evidence Object           ← AEO (see doc 04)
                  │
            Trust Update             ← per-agent trust score delta
                  │
       Digital Citizenship Record    ← durable identity + rights + history
```

## 4. The Evidence Fabric (top-level concept)

```
                 KHEPRA EVIDENCE FABRIC

                     AI Agent
                        │
                     MCP Tool
                        │
                Policy Decision
                        │
                 Execution Event
                        │
          ┌─────────────┴─────────────┐
          │                           │
     PQC Signature              Evidence Record
          │                           │
          └─────────────┬─────────────┘
                        │
                Compliance Engine
                        │
             Continuous Authorization
                        │
                 Trust Dashboard
```

Every execution produces **two entangled artifacts**: a PQC-signed action
receipt and a structured Agent Evidence Object (AEO). Together they collapse
the gap between doing and proving.

## 5. Relationship to existing packages

| Existing (`pkg/…`)              | Fabric role                                        |
| ------------------------------- | -------------------------------------------------- |
| `pkg/auth` (PQC gateway, SAML)  | Identity Attestation layer                         |
| `pkg/mcp` / `pkg/tools`         | Intent Declaration + Tool Execution broker         |
| `pkg/attestation`               | Signature substrate for Evidence Objects           |
| `pkg/audit`                     | Feeder into Residual Intelligence + AEO store      |
| `pkg/compliance` / STIG Viewer  | Control mapping engine (doc 05 + `compliance/`)    |
| _new_ `pkg/citizenship`         | Digital citizenship + trust-score service          |
| _new_ `pkg/evidence`            | AEO schema, storage, verification                  |

## 6. Marketing / metrics implications

Do **not** lead with "MCP calls processed." Lead with **Trust Evidence
Metrics**: verified AI actions, evidence packages generated, controls
continuously monitored, unauthorized actions prevented, tool integrity checks,
real-time audit availability. See doc 06 for surfacing plan.

## 7. Documents in this set

- `00-architecture-overview.md` — this document
- `01-digital-citizenship-model.md` — identity, rights, obligations, revocation
- `02-residual-intelligence-spec.md` — behavioral trace capture
- `03-behavioral-attestation-protocol.md` — signed intent + execution binding
- `04-agent-evidence-object-schema.md` — canonical AEO schema
- `05-secure-mcp-extension.md` — MCP hardening + policy engine integration
- `06-roadmap.md` — sequencing, Lovable Trust Console handoff, doc reorg

## 8. Non-goals

- Replacing SIEM / EDR. KHEPRA consumes their signals; it does not duplicate them.
- Being an LLM provider or agent runtime. KHEPRA sits *beside* runtimes.
- Human-user IAM. Citizenship in this fabric is **agent-scoped**.
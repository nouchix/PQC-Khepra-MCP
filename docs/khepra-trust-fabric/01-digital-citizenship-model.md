# 01 — Digital Citizenship Model

> Status: **Draft / RFC**

## 1. Concept

An autonomous AI agent operating inside a regulated enterprise is not a
session, not an API key, and not a service account. It is a **digital
citizen** of the trust fabric: it has an identity, rights, obligations, a
behavior history, a trust score, and a lifecycle (birth, probation, full
citizenship, suspension, revocation).

Citizenship is the **primary key** across every other subsystem: evidence,
attestation, compliance mapping, and policy enforcement all resolve to a
citizenship record.

## 2. Citizenship record

```
CitizenshipRecord {
  citizen_id        : UUIDv7            // stable, non-reusable
  issued_at         : RFC3339
  issuer            : DID               // KHEPRA authority DID
  subject_kind      : enum { agent, workflow, ensemble, delegated_human }
  identity {
    pqc_pubkey      : ML-DSA-65 pubkey  // primary
    kem_pubkey      : ML-KEM-768 pubkey // for encrypted evidence delivery
    classical_pubkey: Ed25519 (optional, hybrid transition)
    hardware_root   : TPM/HSM binding (optional)
  }
  capabilities      : [CapabilityGrant] // see doc 05
  obligations       : [Obligation]      // logging, redaction, escalation
  attested_runtime  : RuntimeFingerprint (model, weights hash, harness)
  operator          : { org_id, human_owner_did, contact }
  trust_score       : TrustScore        // see §5
  status            : enum { probation, active, suspended, revoked, retired }
  lineage           : parent citizen_id? // for delegated / spawned agents
  policy_bundle     : content-address (hash of active policy set)
  metadata          : map<string, string>
  signature         : PQC signature over the canonical record
}
```

## 3. Lifecycle

```
  ┌──────────┐  attest+approve   ┌──────────┐  N verified evts  ┌────────┐
  │  birth   ├──────────────────▶│probation ├──────────────────▶│ active │
  └──────────┘                   └────┬─────┘                   └───┬────┘
                                      │policy violation             │
                                      ▼                             ▼
                                 ┌──────────┐   auto/manual    ┌────────┐
                                 │suspended │◀─────────────────│revoked │
                                 └──────────┘                  └────────┘
```

- **Birth**: keypair generated inside HSM/TPM or PQC gateway; record signed by
  KHEPRA authority; `status = probation`.
- **Probation**: elevated logging, narrower capability set, mandatory
  human-in-the-loop for `high` sensitivity tools.
- **Active**: full granted capabilities; behavioral drift continuously scored.
- **Suspended**: capabilities disabled; identity preserved; evidence retained.
- **Revoked**: keys added to KHEPRA revocation list; irreversible.
- **Retired**: graceful decommission; evidence + record archived under
  compliance retention policy.

## 4. Rights and obligations

**Rights** are what the citizen may attempt (capabilities + tool scopes).
**Obligations** are what the citizen must do for every attempt:

- emit a signed **Intent Declaration** before execution (doc 03)
- allow **Residual Intelligence** capture (doc 02)
- honor redaction and data-handling policy of the calling org
- surrender evidence to auditors on request

A citizen that cannot satisfy obligations for a given action MUST refuse the
action (fail-closed).

## 5. Trust score

A per-citizen scalar in `[0.0, 1.0]` with contributing components:

| Component            | Weight | Signal                                      |
| -------------------- | -----: | ------------------------------------------- |
| Identity integrity   |   0.20 | key rotation cadence, HSM binding, freshness |
| Behavioral conformance | 0.30 | intent-vs-effect drift, policy denials      |
| Evidence completeness |  0.20 | AEO validation pass rate                    |
| Control coverage     |   0.15 | fraction of mapped STIG/NIST controls green |
| Operator standing    |   0.10 | operator org's aggregate score              |
| Peer attestations    |   0.05 | co-signing agents' trust                    |

Drops below configured floor → automatic suspension. Recovery requires signed
remediation evidence, not manual override.

## 6. Revocation

- Short-lived signed **status tokens** (minutes) checked at policy decision
  time, plus a long-lived signed revocation list.
- OCSP-style stapling on Intent Declarations to avoid revocation-check races.

## 7. Data model (initial Go sketch)

```go
// pkg/citizenship/model.go (proposed)
type Citizen struct {
    ID           uuid.UUID
    IssuedAt     time.Time
    Kind         SubjectKind
    Identity     Identity
    Capabilities []CapabilityGrant
    Obligations  []Obligation
    Runtime      RuntimeFingerprint
    Operator     Operator
    Trust        TrustScore
    Status       Status
    Parent       *uuid.UUID
    PolicyHash   [32]byte
    Signature    []byte // ML-DSA
}
```

## 8. Open questions

- Cross-tenant citizenship portability (federation) — out of scope for v1.
- Human co-citizenship for delegated actions — spec in v2.
- Hardware attestation minimum bar (TPM 2.0 vs. Nitro/SEV-SNP) — pilot per
  customer.
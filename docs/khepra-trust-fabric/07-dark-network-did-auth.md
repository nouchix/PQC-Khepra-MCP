# 07 — Dark-Network Transport & DID Mutual Authentication

Status: Draft · Layer: Transport + Identity · Depends on: `01-digital-citizenship-model`, `03-behavioral-attestation-protocol`

## 1. Goal

Combine **network-layer dark routing (OpenZiti)** with **application-layer cryptographic identity (W3C DID + Verifiable Presentations)** so that:

- No autonomous system can complete a TCP handshake without a valid overlay-network token.
- No verified peer can execute a command without a fresh DID-signed challenge response.
- Every session opens with a cryptographic proof of both *network membership* and *behavioral clearance*.

This is the transport binding for the KHEPRA Trust Fabric: agents are dark to the public internet and mutually attested at the socket level.

## 2. Two-Layer Trust Model

```text
┌─────────────────────────────────────────────────────────┐
│ Layer 2 — Application Identity                          │
│   W3C DID Document · Ed25519 (→ ML-DSA-65) · VP+Nonce   │
├─────────────────────────────────────────────────────────┤
│ Layer 1 — Overlay Network                               │
│   OpenZiti service · mTLS · no public ports · no DNS    │
├─────────────────────────────────────────────────────────┤
│ Layer 0 — Underlay (untrusted internet)                 │
└─────────────────────────────────────────────────────────┘
```

An attacker who bypasses Layer 1 still hits Layer 2. An attacker who steals a DID key still cannot reach the socket.

## 3. Handshake Sequence

```text
Agent A                                                 Agent B
  │ 1. ctx.Dial(service)  ── OpenZiti overlay ─────────▶│  (Layer 1 mTLS)
  │                                                     │
  │◀────────── 2. AuthChallenge{nonce}                  │
  │                                                     │
  │ 3. Resolve B.DID → pubkey (VDR)                     │
  │                                                     │
  │ 4. sign(nonce || DID_A || ts) → VerifiablePresent. ▶│
  │                                                     │  5. verify(sig, pubkey_A)
  │                                                     │     check(ts fresh, nonce=issued)
  │                                                     │     check(trust_score ≥ policy.min)
  │◀═══════════ TRUST ESTABLISHED ═══════════════════════╡
  │                    (bidirectional stream)           │
```

Rules:

- **Nonce**: 128-bit CSPRNG, single-use, TTL ≤ 30 s, retained until reply or expiry.
- **Timestamp skew**: ±60 s. Older frames → `STATUS_REPLAY_REJECTED`.
- **Signed payload**: `nonce || DID || ts || service_id` — service binding prevents cross-service replay.
- **Both directions**: Server also presents a signed challenge before the client streams data (mutual DID auth).
- **Trust score gate**: Verifier queries the citizenship registry (`01-digital-citizenship-model`) and rejects peers below the service's minimum score.

## 4. Wire Format

```json
// Server → Client
{ "type": "auth.challenge",
  "nonce": "b1f2…", "service_id": "autonomous-telemetry-loop",
  "issued_at": "2026-07-23T14:00:00Z", "ttl_ms": 30000 }

// Client → Server (Verifiable Presentation)
{ "type": "auth.response",
  "did": "did:peer:agentA…",
  "nonce": "b1f2…",
  "issued_at": "2026-07-23T14:00:01Z",
  "alg": "Ed25519",              // MUST migrate to "ML-DSA-65" — see §7
  "signature": "base64…",
  "kid": "did:peer:agentA…#key-1" }
```

Encoded as `application/json` today; MUST become the canonical CBOR/COSE form defined in `04-agent-evidence-object-schema` before GA.

## 5. Reference Go Implementation

The illustrative wrapper in the request (`agent.go`, Ed25519 challenge/response over an OpenZiti listener) is the correct shape, with the following mandatory changes before merge into `pkg/trustnet/`:

- Import path: `github.com/openziti/sdk-golang/ziti` and `github.com/openziti/sdk-golang/ziti/config`.
- DID resolution MUST go through `pkg/did/resolver` (pluggable: `did:peer`, `did:web`, `did:key`) — never hardcode a `expectedClientPublicKey` argument. That parameter is a test-only shortcut and MUST NOT survive review.
- `handleAgentConnection` MUST enforce: (a) nonce equality, (b) `service_id` equality, (c) timestamp within skew, (d) trust-score gate, (e) failure → structured audit event to the Evidence Fabric before returning.
- Server-side nonce store: in-memory LRU with TTL; rejects reuse across parallel connections.
- Signing key MUST come from the platform HSM/TPM adapter (`pkg/keystore`) — never `crypto/rand` at process start except in unit tests.

## 6. OpenZiti Deployment Contract

Bootstrap:

1. Deploy the OpenZiti controller in the KHEPRA control-plane VPC. It is the only network component with a public endpoint.
2. Enroll each agent identity via `ziti edge create identity … -o agent_a.json`. Ship the identity JSON to the workload through a sealed secret; never bake it into an image.
3. Create the service (`ziti edge create service autonomous-telemetry-loop`). Bind server agents (`bind` policy) and dial clients (`dial` policy) with separate role attributes so the two sides can never be swapped.
4. Zero firewall exceptions on the workload side. All inbound is denied at the host firewall; OpenZiti dials outbound to the edge router.

Operational rules:

- Identity rotation is executed by the KHEPRA control plane, not by ops manually re-enrolling.
- Service policies are versioned artifacts checked into the fabric config repo; policy drift MUST fail CI.
- Each service has a matching DID policy (§3) — a service without a registered DID policy MUST be refused by the controller admission webhook.

## 7. Post-Quantum Migration (crosslink to `08-pqc-forensic-pipeline`)

Both layers migrate to NIST PQC on the same schedule:

| Layer | Today | Q3 2026 (Hybrid) | GA (Pure PQC) |
|---|---|---|---|
| Network KEX | X25519 (mTLS 1.3) | X25519MLKEM768 hybrid | ML-KEM-768 |
| DID signing | Ed25519 | Ed25519 + ML-DSA-65 dual-sig | ML-DSA-65 (`multikey`) |
| Frame signing | — | ML-DSA-65 (see §08) | ML-DSA-65 |

Migration rules:

- The DID Document MUST list both `Ed25519VerificationKey2020` and `Multikey`(ML-DSA-65) entries during the hybrid window. Verifiers accept either; producers sign with both.
- The `alg` field in the auth response is authoritative — verifiers MUST pick the key by `kid`, not by algorithm probing.
- Once the trust-network policy engine reports ≥ 99% of registered peers publish an ML-DSA-65 `Multikey`, the fabric flips to pure PQC and rejects Ed25519-only presentations.

## 8. Failure Modes & Audit Events

Every negative path emits a signed Agent Evidence Object (AEO — see `04-agent-evidence-object-schema`) with a specific `event_code`:

- `TRUSTNET.AUTH.NONCE_REUSE` — nonce already spent
- `TRUSTNET.AUTH.TS_SKEW` — timestamp outside window
- `TRUSTNET.AUTH.SIG_INVALID` — signature verification failed
- `TRUSTNET.AUTH.DID_UNRESOLVED` — VDR returned no key
- `TRUSTNET.AUTH.SCORE_BELOW_POLICY` — trust score under service minimum
- `TRUSTNET.AUTH.SERVICE_MISMATCH` — signed `service_id` ≠ dialed service

All events are streamed into the Evidence Fabric and count against the peer's trust score.

## 9. Test Vectors & Conformance

The spec ships with:

- `testdata/trustnet/happy-path.json` — challenge/response pair that MUST verify.
- `testdata/trustnet/replay.json` — same nonce reused; MUST fail with `NONCE_REUSE`.
- `testdata/trustnet/skew.json` — ts +120 s; MUST fail with `TS_SKEW`.
- `testdata/trustnet/xsw.json` — signature over `nonce` only (missing service binding); MUST fail with `SIG_INVALID`.

Conformance requires all four vectors to pass on every SDK (Go, Rust, Python) before it is listed on the connector marketplace.

## 10. Open Questions

- DID method matrix for GA (peer/web/key vs. `did:khepra:*` custom method with on-fabric VDR)?
- Should the OpenZiti controller itself run inside the fabric (dogfooding) or in a separate trust domain?
- Rotation SLA: max age of an authenticated session before forced re-handshake (proposed: 15 min).

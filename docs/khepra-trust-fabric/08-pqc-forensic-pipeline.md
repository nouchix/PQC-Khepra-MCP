# 08 — Post-Quantum Forensic Telemetry Pipeline

Status: Draft · Layer: Evidence Fabric + Transport · Depends on: `04-agent-evidence-object-schema`, `07-dark-network-did-auth`

## 1. Goal

Lock the KHEPRA remote-acquisition stream — eBPF/DSP capture on the edge → central Evidence Fabric — against **harvest-now/decrypt-later** and **retroactive tampering** threats using the NIST-standardized PQC algorithms:

- **FIPS 203 · ML-KEM (Kyber-768)** — key encapsulation on the transport (TLS 1.3 hybrid).
- **FIPS 204 · ML-DSA (Dilithium-65)** — per-frame signatures for non-repudiation.
- **AES-256-GCM** — symmetric at-rest encryption of the forensic vault (quantum-tolerant under Grover).

Every telemetry frame is signed at the edge before it leaves the process, so a later breach of the central vault cannot forge or backdate history.

## 2. Pipeline

```text
[ eBPF / DSP capture ] ─► [ Edge agent ]
                              │
                              │  frame = { ts, pid, ebpf_bytes, dsp_freqs }
                              │  sig   = ML-DSA-65.Sign(agent_sk, canonical(frame))
                              ▼
                    ┌─────────────────────────┐
                    │  TelemetryFrame (proto) │
                    │  + mldsa_public_key     │
                    │  + mldsa_signature      │
                    └─────────────────────────┘
                              │
      TLS 1.3 · X25519MLKEM768 (hybrid KEM) · OpenZiti overlay (spec 07)
                              ▼
                 [ Central Forensics gRPC vault ]
                 verify sig → append to immudb → AEO
```

Every stage is auditable: capture → sign → transit → verify → seal.

## 3. Protobuf Contract

The `microsonic.os.v1.RemoteAcquisitionService` in the request is adopted as the initial wire format, with these normative changes so it composes with the rest of the Trust Fabric:

```proto
syntax = "proto3";
package khepra.evidence.v1;
option go_package = "github.com/nouchix/khepra/proto/evidence/v1;evidencev1";

service RemoteAcquisitionService {
  rpc StreamTelemetry(stream TelemetryFrame) returns (AcquisitionResponse);
}

message TelemetryFrame {
  // --- Identity binding (REQUIRED) ---
  string agent_did       = 1;   // did:khepra:...  — MUST match peer DID from spec 07
  string session_id      = 2;   // uuid, bound to the OpenZiti auth session
  int64  timestamp_nanos = 3;
  uint32 agent_process_id = 4;

  // --- Payload ---
  bytes raw_ebpf_metrics = 10;
  repeated double dsp_frequencies = 11;

  // --- PQC evidence envelope ---
  string signature_alg   = 20;  // "ML-DSA-65" (frozen; no downgrade)
  bytes  mldsa_public_key = 21; // MUST equal the key advertised in agent_did doc
  bytes  mldsa_signature = 22;  // over canonical(fields 1..11)

  // --- Chaining (REQUIRED) ---
  bytes  prev_frame_hash = 30;  // SHA3-256(canonical(previous frame in session))
  uint64 sequence        = 31;  // monotonic per session, starts at 0
}

message AcquisitionResponse {
  enum Status {
    STATUS_UNSPECIFIED       = 0;
    STATUS_VERIFIED_SUCCESS  = 1;
    STATUS_SIGNATURE_INVALID = 2;
    STATUS_DID_MISMATCH      = 3;
    STATUS_SEQUENCE_GAP      = 4;
    STATUS_REPLAY            = 5;
  }
  Status status = 1;
  string frame_receipt_hash = 2;   // SHA3-256(frame) as returned by immudb
  uint64 immudb_index = 3;         // tamper-evident position
}
```

Rules the request's draft was missing and that MUST be enforced:

1. **Identity binding.** `agent_did` and the DID that authenticated the OpenZiti session (spec 07) MUST be equal. Any mismatch → `STATUS_DID_MISMATCH` and the session is terminated.
2. **Hash chaining.** Frame *n* carries `prev_frame_hash = H(frame n-1)` and `sequence = n`. The verifier drops the session on any gap. This turns a session into a per-agent Merkle chain that immudb anchors globally.
3. **Canonicalization.** Fields 1..11 are serialized with deterministic proto encoding (RFC 8785-style ordering, no unknown fields) before signing. Signers and verifiers use the same canonicalizer, versioned as `khepra/canonical/v1`.
4. **No algorithm negotiation.** `signature_alg` is informational; a verifier that receives anything other than the fabric-configured algorithm rejects the frame. Downgrade attacks are refused, not negotiated.

## 4. Go Reference Implementation Notes

The `github.com/cloudflare/circl` implementations of `sign/mldsa/mldsa65` and `kem/mlkem/mlkem768` are the reference dependency. Corrections to the request's snippet before it lands in `pkg/evidence/pqc/`:

- **Sign the full canonical frame, not just `rawMetrics`.** The example signs only the raw metrics; the spec requires signing the canonical serialization of fields 1..11. Anything less lets an attacker rewrite timestamps, DIDs, or sequences on the wire.
- **Key lifecycle.** ML-DSA-65 keys are minted once per agent and stored in the platform keystore (HSM/TPM adapter), not regenerated in `NewTelemetryClient`. Client construction resolves the existing key by DID `kid`.
- **KEM ownership.** `mlkem768.NewScheme()` is used inside the TLS stack (via a hybrid KEM group `X25519MLKEM768`), not called from application code. Application code MUST NOT roll its own KEM handshake.
- **Streaming context.** `StreamTelemetry` is a bidi stream; the server sends `AcquisitionResponse` after each frame with `immudb_index`. The client MUST persist the last acknowledged `sequence` for crash recovery.
- **Backpressure.** On `STATUS_SEQUENCE_GAP`, the client re-opens the stream and replays from the last acknowledged sequence — it never rewrites history to close the gap.

## 5. Transport Binding (crosslink to spec 07)

The gRPC channel runs **inside** the OpenZiti overlay defined by spec 07. Layering:

```text
gRPC (HTTP/2) · TLS 1.3 · KEM group = X25519MLKEM768 (hybrid)
     ▲                              (RFC 9794 hybrid PQC groups)
     │
OpenZiti overlay (mTLS · dark listener)
     ▲
underlay TCP
```

- TLS is configured with the hybrid group only; the classic-only fallback is disabled.
- The peer certificate presented over mTLS is bound to the same DID as the gRPC-layer `agent_did`. Any mismatch fails the connection before the first frame.
- Session keys derived from the hybrid KEM are used for AES-256-GCM record protection — the same AEAD is reused for at-rest vault encryption (§6) so the KMS surface is a single algorithm.

## 6. Vault (immudb) & Cold Storage

- Every verified frame is appended to immudb keyed by `(agent_did, session_id, sequence)`. The immudb response index is returned to the client so the edge can prove inclusion.
- Cold-storage snapshots of immudb are AES-256-GCM encrypted; KEKs are wrapped with an ML-KEM-768 envelope key held in the platform HSM. Rotating the KEK does not require re-signing frames because integrity lives in the ML-DSA signatures, not the storage layer.
- Retention policy per-agent is expressed in the citizenship registry (`01-digital-citizenship-model`) — Layer 8 policy, not a storage flag.

## 7. Verifier Algorithm (normative)

For each incoming frame `F` on session `S`:

1. Assert `F.agent_did == S.authenticated_did` else → `DID_MISMATCH`, close stream.
2. Assert `F.sequence == S.expected_next_sequence` else → `SEQUENCE_GAP`, close stream.
3. Assert `F.prev_frame_hash == S.last_frame_hash` (or all-zero if `sequence==0`) else → `REPLAY`, close stream.
4. Resolve `F.agent_did` → DID Document; select the `Multikey` entry matching `F.mldsa_public_key`. If none → `SIGNATURE_INVALID`.
5. Verify `mldsa65.Verify(pk, canonical(F.fields[1..11]), F.mldsa_signature)` → on false, `SIGNATURE_INVALID`.
6. Append to immudb; set `S.last_frame_hash = SHA3-256(canonical(F))`; increment `expected_next_sequence`.
7. Emit an AEO of type `evidence.telemetry.frame` referencing `immudb_index`, and return `STATUS_VERIFIED_SUCCESS`.

## 8. Threat Model & Mitigations

| Threat | Mitigation |
|---|---|
| Harvest-now/decrypt-later on transit | Hybrid X25519+ML-KEM-768 TLS group; classic-only refused. |
| Retroactive forgery of history | Per-frame ML-DSA-65 signature over canonical bytes + immudb append-only ledger. |
| Vault operator tampering | Signatures bind to agent keys, not vault keys; immudb inclusion proofs shared with regulators. |
| Session hijack after auth | DID binding at both mTLS (spec 07) and application (`agent_did`) layers; mismatch closes stream. |
| Frame reordering / gap injection | Monotonic `sequence` + `prev_frame_hash` chain; gap ⇒ session terminated. |
| Downgrade to classical algs | `signature_alg` is informational, verifier enforces fabric-configured algorithm; no negotiation. |
| Compromised edge key | Key rotation via `pkg/keystore`, DID Document revocation, and trust-score decay in `01-digital-citizenship-model`. |

## 9. Blueprint Table

| Cryptographic Task | NIST Protocol | Where used in KHEPRA |
|---|---|---|
| Data-in-transit protection | ML-KEM-768 (FIPS 203) | TLS 1.3 `X25519MLKEM768` on the OpenZiti-tunneled gRPC channel. |
| Forensic non-repudiation | ML-DSA-65 (FIPS 204) | Per-frame signature at the edge; verified before immudb append. |
| At-rest vault encryption | AES-256-GCM | immudb snapshots and cold-storage tiers; KEKs wrapped with ML-KEM-768. |
| DID auth (transitional) | Ed25519 → ML-DSA-65 | Spec 07 handshake during the hybrid window; pure ML-DSA-65 at GA. |

## 10. Conformance & Test Vectors

Ships with:

- `testdata/pqc/frame-happy.bin` — verifies against a pinned ML-DSA-65 pubkey.
- `testdata/pqc/frame-tampered-ts.bin` — timestamp rewritten post-sign; MUST fail `SIGNATURE_INVALID`.
- `testdata/pqc/frame-seq-gap.bin` — sequence jump; MUST fail `SEQUENCE_GAP`.
- `testdata/pqc/frame-did-mismatch.bin` — `agent_did` ≠ session DID; MUST fail `DID_MISMATCH`.
- `testdata/pqc/tls-hybrid-transcript.pcap` — captured X25519MLKEM768 handshake.

Any SDK submitted to the marketplace MUST pass all five vectors and demonstrate refusal of classical-only TLS groups.

## 11. Open Questions

- Should Falcon (FIPS 206 candidate) be admitted as a small-signature alternative for constrained edge agents?
- Batch signature aggregation for high-frequency DSP capture (10+ kHz frame rates) — worth the added spec surface?
- Where do we anchor immudb inclusion proofs externally (public transparency log, partner witnesses, or both)?

---

*Next phase candidates (per user prompt): (a) Predictive Replay Engine using time-domain Kalman filters over the verified frame stream, (b) Evolutionary anomaly-rule optimizer trained on the immudb history. Both consume this pipeline unchanged.*

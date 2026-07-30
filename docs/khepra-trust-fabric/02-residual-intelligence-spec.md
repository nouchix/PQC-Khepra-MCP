# 02 — Residual Intelligence Specification

> Status: **Draft / RFC**

## 1. Definition

**Residual Intelligence (RI)** is the structured, signed trace of everything
an agent *did, saw, and considered* while executing an intent — captured as
a byproduct of execution rather than as after-the-fact logging.

RI is the raw substrate from which the **Agent Evidence Object** (doc 04) is
derived and against which **Behavioral Attestation** (doc 03) is verified.

## 2. Capture scope

| Channel                 | Captured                                              | Notes                     |
| ----------------------- | ----------------------------------------------------- | ------------------------- |
| Prompt / system messages | Full text, role, ordering, digest                    | Redaction pre-storage     |
| Retrieved context        | Chunk content hash + source URI + retrieval score    | Content optional per policy |
| Model responses          | Full output, token-stream digest, logprobs (if avail) | Sampling params recorded  |
| Tool invocations         | Tool ID, args, decision, latency, obligations applied | Signed by broker          |
| External effects         | Pre/post state hashes, target system, reversal token  | For mutating tools        |
| Policy decisions         | Rule ID, allow/deny, obligations                     | Every eval, not only denies |
| Runtime signals          | Model + weights hash, harness version, host DID      | Fingerprint per session   |
| Timing                   | Monotonic + wall clock per event                     | For replay                |

## 3. Envelope

Each RI event is emitted as a canonical CBOR record, signed with the citizen's
ML-DSA key by the agent-side capture SDK **and** counter-signed by the KHEPRA
broker that observed the event:

```
RIEvent {
  event_id     : ULID
  session_id   : UUID
  citizen_id   : UUID
  seq          : uint64          // monotonic within session
  prev_hash    : bytes[32]       // hash-chained
  kind         : enum { prompt, retrieval, model_out, tool_call,
                        tool_result, effect, policy_decision, runtime }
  payload      : CBOR (kind-specific)
  ts_mono_ns   : uint64
  ts_wall      : RFC3339
  agent_sig    : bytes           // ML-DSA over canonical event
  broker_sig   : bytes           // ML-DSA over (event || agent_sig)
}
```

Hash-chaining makes gaps and reordering detectable; two independent signatures
prevent unilateral rewriting by either agent or broker.

## 4. Storage model

- **Hot tier**: append-only per-session log (object store, immutable prefix).
- **Warm tier**: session-rolled up into a Merkle DAG whose root is anchored on
  the KHEPRA attestation DAG (`pkg/attestation`).
- **Cold tier**: encrypted archive keyed to citizen ML-KEM pubkey; auditors
  receive scoped decapsulation keys per investigation.

Retention follows the calling org's compliance policy (default 7 years for
CMMC/NIST 800-171 scope).

## 5. Redaction

Redaction is **pre-signature** for content, **post-signature** for hashes.
A redacted payload retains its content hash so evidence integrity is preserved
even when raw content is later purged (GDPR erasure, classified spillage).

```
payload = { content: "redacted", content_hash: <original>, redacted_by: <op> }
```

## 6. Access control

- Only the citizen's operator and authorized auditors may request warm-tier
  replay.
- Every access is itself an RI event (`kind: reviewer_action`) recorded on the
  reviewer's own citizenship record — auditors are citizens too.

## 7. SDK surface (proposed)

```go
// pkg/residual/sdk.go
type Recorder interface {
    StartSession(citizenID uuid.UUID, intent IntentDeclaration) (Session, error)
}
type Session interface {
    Emit(kind Kind, payload any) (EventID, error)
    Close(outcome Outcome) (SessionDigest, error) // returns Merkle root
}
```

## 8. Non-goals

- RI is **not** a metrics pipeline. Latency/error counters live in
  `pkg/telemetry` and are referenced by digest, not duplicated.
- RI is **not** a debugger. It is evidence-grade capture; developer-time
  tracing uses OTel with a separate export.
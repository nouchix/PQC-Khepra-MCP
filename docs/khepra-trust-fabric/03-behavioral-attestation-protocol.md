# 03 — Behavioral Attestation Protocol

> Status: **Draft / RFC**

## 1. Purpose

Prove — cryptographically and after the fact — that:

1. The agent **declared its intent** before acting.
2. The action executed was **the declared action, under an authorized policy**.
3. The observed effects match the declared intent within a bounded envelope.

This is the layer that converts raw Residual Intelligence (doc 02) into a
verifiable **claim about behavior**.

## 2. Flow

```
 1. Agent constructs IntentDeclaration (ID)                    ─┐
 2. Agent signs ID with ML-DSA (citizen key)                    │  pre-exec
 3. Broker evaluates policy against ID + citizen capabilities   │
 4. Broker issues signed ExecutionTicket (ET) binding ID→policy─┘
 5. Broker executes tool call under ET                         ─┐
 6. Residual Intelligence stream emitted, hash-chained          │  exec
 7. Broker computes EffectDigest from RI stream                 │
 8. Broker emits BehavioralAttestation (BA) linking ID+ET+RI   ─┘  post-exec
```

## 3. Intent Declaration

```
IntentDeclaration {
  intent_id     : ULID
  citizen_id    : UUID
  session_id    : UUID
  tool          : { id, version, integrity_hash }
  arguments     : CBOR (canonical)
  purpose       : short human-readable string
  sensitivity   : enum { low, medium, high, restricted }
  expected_effects : [EffectClaim]      // e.g. "writes to table X"
  policy_context : { bundle_hash, control_refs: [STIG/NIST ids] }
  not_before, not_after : RFC3339
  nonce         : bytes[16]
  citizen_sig   : ML-DSA
}
```

`expected_effects` is the **contract** the agent commits to; drift between
claimed and observed effects is the primary behavioral signal.

## 4. Execution Ticket

Issued by the KHEPRA broker only if:

- citizen `status ∈ {probation, active}` and trust score ≥ policy floor,
- capability grants cover the requested tool + args,
- policy evaluation returns `allow` (with obligations enumerated),
- runtime fingerprint matches the citizen's attested runtime.

```
ExecutionTicket {
  ticket_id     : ULID
  intent_id     : ULID
  broker_id     : DID
  policy_decision : { rule_ids, obligations, decision_hash }
  effect_bounds : Envelope           // e.g. max rows, allowed targets
  ttl           : duration
  broker_sig    : ML-DSA
}
```

Missing/invalid ticket → tool call refused at the connector layer. Tickets
are single-use; replay is rejected by nonce cache.

## 5. Behavioral Attestation

```
BehavioralAttestation {
  ba_id           : ULID
  intent_id       : ULID
  ticket_id       : ULID
  ri_root         : bytes[32]        // Merkle root of RI stream
  effect_digest   : EffectDigest     // canonicalized observed effects
  drift {
    conforms      : bool             // effect_digest ⊆ effect_bounds
    deltas        : [Delta]          // enumerated deviations
  }
  obligations_fulfilled : [ObligationProof]
  broker_sig      : ML-DSA
  witness_sigs    : [ML-DSA]         // optional peer/HSM co-signers
}
```

A BA with `drift.conforms = false` is **still emitted** — evidence of
non-conforming behavior is more valuable than silence. It flows into the
trust score (doc 01 §5) and can trigger auto-suspension.

## 6. Verification algorithm

```
verify(BA):
  ID  = fetch(BA.intent_id);        require ID.citizen_sig valid
  ET  = fetch(BA.ticket_id);        require ET.broker_sig valid
  require ET.intent_id == ID.intent_id
  require RI Merkle root == BA.ri_root
  recompute effect_digest from RI;  require == BA.effect_digest
  require effect_digest ⊆ ID.expected_effects ∪ ET.effect_bounds
  require obligations_fulfilled covers ET.policy_decision.obligations
  require all signatures valid under non-revoked keys at BA.ts
```

Any failed step → BA rejected; incident opened; trust score penalized.

## 7. Anchoring

BA hashes are batched and anchored on the KHEPRA attestation DAG
(`pkg/attestation`) at fixed intervals (default 60s) with Merkle inclusion
proofs, so third parties can later verify a BA existed at time T without
trusting the broker's storage.

## 8. Failure modes and fail-closed rules

- No valid ticket → refuse execution.
- RI capture failure mid-stream → mark session poisoned; emit BA with
  `conforms=false`, `deltas=[capture_gap]`.
- Signature verification failure at any layer → refuse and quarantine.
- Missing revocation freshness → refuse for `sensitivity ≥ high`.
# 05 — Secure MCP Extension

> Status: **Draft / RFC**

## 1. Motivation

Vanilla MCP is a productivity protocol. It assumes cooperative tools, benign
agents, and trusting operators. In regulated deployments none of those hold.

The **Secure MCP Extension (S-MCP)** wraps MCP so that every tool call is
brokered through the KHEPRA fabric: identity-attested, policy-decided,
evidence-producing, and control-mapped — without breaking MCP interop.

## 2. What S-MCP adds on top of MCP

| Concern              | Vanilla MCP                    | S-MCP addition                                      |
| -------------------- | ------------------------------ | --------------------------------------------------- |
| Identity             | Transport-level (bearer/mTLS)  | PQC citizen identity per call (doc 01)              |
| Tool integrity       | Trust on first use             | Signed tool manifests, hash pinning, revocation list |
| Authorization        | Implicit                       | Explicit `IntentDeclaration` + `ExecutionTicket`    |
| Effects              | Best-effort logs               | Pre/post state hashes, reversal tokens              |
| Evidence             | None                           | AEO per call (doc 04)                               |
| Policy               | App-level                      | Central policy engine, obligations returned         |
| Compliance mapping   | External                       | Control refs on every call (STIG / NIST / CMMC)     |
| Replay defense       | None                           | Nonce cache + ticket TTL                            |
| Transport            | JSON-RPC over stdio/HTTP       | Same, plus signed envelope frame                    |

## 3. Envelope

S-MCP wraps the MCP JSON-RPC message in a signed envelope. Vanilla MCP
clients see plain MCP; KHEPRA-aware clients see the fabric metadata.

```
SMCPEnvelope {
  mcp                 : <raw MCP JSON-RPC message>
  intent_declaration  : IntentDeclaration        // doc 03
  citizen_id          : UUID
  policy_bundle_hash  : bytes[32]
  nonce               : bytes[16]
  ts                  : RFC3339
  citizen_sig         : ML-DSA over canonical form of the above
}
```

The broker validates the envelope, evaluates policy, mints an
`ExecutionTicket`, forwards the inner MCP message to the target tool, and
captures RI on the return path.

## 4. Tool manifests

Every tool exposed through S-MCP MUST publish a signed manifest:

```
ToolManifest {
  tool_id            : "mcp:postgres.exec"
  version            : "1.4.2"
  integrity_hash     : sha256 of tool binary/container
  supported_args     : JSON Schema
  effect_profile     : { reads: [Selector], writes: [Selector], external: bool }
  required_capabilities : [CapabilityRef]
  control_refs       : [ControlRef]     // STIG / NIST / CMMC
  provider_sig       : ML-DSA
  khepra_countersig  : ML-DSA (optional certification)
}
```

Broker refuses to broker any tool whose current integrity hash does not
match its manifest, or whose manifest is not present in the operator's
allow-list.

## 5. Policy engine integration

Policies are Rego bundles (or equivalent) evaluated per call with input:

```
{
  "citizen":  <CitizenshipRecord snapshot>,
  "intent":   <IntentDeclaration>,
  "tool":     <ToolManifest>,
  "context":  { org, env, time, incident_flags }
}
```

Decision output:

```
{
  "allow": bool,
  "obligations": ["log_full_ri", "notify_owner", "require_witness"],
  "effect_bounds": { ... },
  "control_refs": ["CMMC-L2:AU.L2-3.3.1", "STIG:V-238215"],
  "rule_ids": ["p.tools.db.write.v3"]
}
```

Obligations are enforced by the broker, not by the policy — the policy
*declares*, the broker *acts*.

## 6. Failure modes (fail-closed)

- Envelope signature invalid           → 401, no downstream call, RI event logged.
- Citizen suspended/revoked            → 403, incident opened.
- Tool manifest missing/mismatch       → 424, tool disabled globally until re-signed.
- Policy engine unavailable            → 503, refuse `sensitivity ≥ medium`
  (configurable per operator; default is refuse-all).
- Downstream tool exceeds `effect_bounds` → transaction rolled back via
  reversal token when supported, otherwise incident + citizen suspension.

## 7. Backwards compatibility

- Broker exposes a **passthrough mode** for legacy MCP tools without
  manifests; sensitivity is capped at `low`, no writes allowed, RI still
  captured. Passthrough is an operator-level opt-in.
- Legacy MCP clients can connect; broker synthesizes an anonymous
  probation citizen with narrow capabilities.

## 8. Relationship to `pkg/mcp`, `pkg/tools`, `pkg/auth`

- `pkg/auth` gates envelope validation (PQC citizen sig).
- `pkg/mcp` gains a `Broker` interface implementing the envelope path.
- `pkg/tools` grows manifest registry + integrity checks.
- New `pkg/policy` hosts the engine adapter; new `pkg/evidence` produces AEOs.
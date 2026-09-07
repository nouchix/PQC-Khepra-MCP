# Autonomy Ground Truth — Forensic Audit Against the L4 Specification

**Scope:** `PQC-Khepra-MCP` (primary), `khepra-trust-os` (comparative)
**Method:** Read-only trace of enforcing control flow. Comments, doc-strings, struct names and README claims were not accepted as evidence.
**Date:** 2026-09-06
**Status:** Read-and-report. No feature code was written.

---

## 1. Verdict

The central finding is an inversion of the expected gap.

The usual failure mode for an autonomy claim is a system operating at L1 that markets itself as L4. This codebase is the opposite: **it already executes at L4 — no human token is required for any action class — while satisfying none of the eight L4 preconditions.** The autonomy is real. The safety architecture that is supposed to license it is not.

Put plainly: the system is not trying and failing to reach L4. It is already there, without the preconditions, and the controls that would constrain it are present in the repository as unwired libraries.

| Action class | Honest level today | Justification |
|---|---|---|
| `RiskReadOnly` (~50 tools: `nhi_inventory`, `ert_scan`, `stig_check`) | **L4** | No gate is reached on this path at all. |
| `RiskSandboxed` | **L4** | No gate, plus silent in-process fallback when the sandbox is unavailable ([executor.go:132-164](../pkg/mcp/executor.go#L132-L164)). |
| `RiskDestructive` (`acp_issue`, `acp_revoke`, `nhi_revoke`, `drbc_restore`) | **L3.5, and L4 by env var** | Router requires `_confirm: true` ([router.go:394-428](../pkg/mcp/router.go#L394-L428)), but the flag is supplied by the calling model in its own argument map, and the error text instructs it to retry with the flag set. `KHEPRA_SKIP_CONFIRM=1` removes the gate entirely ([router.go:396](../pkg/mcp/router.go#L396)). |
| Host remediation (`RemediateFIPSMode`, `RemediatePackageInstall`, `RemediateServiceEnable`) | **L4, irreversible** | Mutates kernel crypto policy and package state with no pre-state capture and no reversal. |
| Fleet HTTP handlers (`pkg/asaf/stargate/`) | **L4, unbounded** | Never routed through the MCP router; unbounded loops over caller-supplied target lists. |

**No action class in this codebase is L1 or L2.** Nothing requires a human token.

The two independently blocking defects for any legitimate L4 claim are **E** (no signed evidence exists at the moment any effect becomes externally visible) and **G** (no kill authority the system cannot route around, over a fail-open revocation path).

---

## 2. Precondition Matrix

| # | Precondition | Status | Evidence | Gap to L4 |
|---|---|---|---|---|
| **A** | Autonomy-level state machine | **ABSENT** | `pkg/sekhem/triad.go:33-46,71,171`. `KHEPRA_MODE` read once into a struct field; no setter, never persisted, never mutated. Only consumers are `IsAirGapped()` (`triad.go:54`) and `aten.go:117`, whose branch body is a log statement. `duat.go:116-127` executes with no level consultation; `h.Autonomous` is read once at `duat.go:135` and written to a log map. `aaru.go:221-236` prints "executing" and dispatches nothing. | Needs a level variable, persistence, transition function, trigger conditions, and at least one consultation site at the gate. Note the ladder also runs backwards: `triad.go:87,96` grant *more* realms in `sovereign`/`ironbank`, and `sovereign` is the default (`factory.go:52-56`). There is no downshift direction. |
| **B** | Actuation gate (human approval token) | **PARTIAL** | Router gate is real but self-issued: `router.go:394-428`. Executor gate is a no-op in every shipping binary — `cmd/khepra-mcp/main.go:23-26` and `cmd/asaf-hub/main.go:383-386` are both `log` + `return nil`. These are the only two non-test `ConfirmationGate` implementations. Despite the name, `stdioConfirmGate` performs no I/O and cannot return non-nil. | Token must be bound to a human identity, a session, and a signature — not a boolean in the model's own argument map. Remove the `KHEPRA_SKIP_CONFIRM` bypass. |
| **C** | Fail-closed default | **PARTIAL** | Closed: unknown risk class (`executor.go:110-112`), nil gate (`executor.go:171-173`), manifest structure (`manifest.go:47-60`), license signature pinned to compiled-in key (`pkg/license/mcp_gate.go:286`). Open: sandbox fallback (`executor.go:132-164`, fail-closed requires opt-*in*), manifest signature (see F), attestation (see E), license parse — a signature failure is downgraded to a warning and the server continues (`cmd/khepra-mcp/main.go:218-219`). | Invert the sandbox default. Make signature failure terminal. |
| **D** | Deterministic reversibility | **PARTIAL — one function** | `RemediateSSHConfig` is the only armed, executed reversal: pre-state capture at `pkg/stig/remediator.go:164`, fails closed if the snapshot fails (`:166-169`), real byte copy (`:208-221`), reversal invoked at `:181` and `:190`. | Three defects even here: no post-state equality check; rollback error discarded by every caller (`:181`, `:190` are bare calls); and it is a **no-op on remote targets** — `:226-228` returns `nil` without acting, while `:200-203` returns the string literal `"remote_agent_snapshot"` as the "backup". `RemediatePackageInstall`, `RemediateServiceEnable`, `RemediateFirewalld` and `RemediateFIPSMode` have no reversal at all; the last enables FIPS mode at boot level and merely appends `" [REBOOT REQUIRED]"` to a string (`:154`). |
| **E** | Pre-effect attestation | **ABSENT** | Ordering in `HandleToolCall` is unambiguous: `router.go:444` `r.exec.Execute(...)` ← effect; `router.go:540` `r.attest.Append(...)` ← DAG write; `router.go:562` `SignEnvelope(...)` ← signature. Everything before `:444` is authorization checks, not a signed evidence object. **Execute-then-sign.** `core/aeo/recorder.go:58` is post-hoc by API construction — its `latency` and `outcome` parameters cannot exist before the call completes. | At `router.go:540-545`, if `Append` fails the function returns "attestation failed" **after the tool has already run**. The effect is externally visible with no record. Sign-then-execute requires a two-phase commit: sign intent, execute, sign outcome. |
| **F** | Bounded ODD | **PARTIAL** | Real: manifest is ML-DSA-65 signed and fails closed at load (`manifest.go:63-65`; `manifest_store.go:83-88`), enforced at `router.go:339-348` for tool name and pinned schema. Scope/RBAC at `router.go:369`, CIDR at `:256`. | Constrains **tool name, schema, scope and origin only**. **No time window** and **no data classification** exist in this repo. KTOS has a sensitivity lattice (`core/enforce/enforce.go:126-153`, ceiling enforced at `:351-354`), but the `Grant` carrying it is unsigned, unversioned and expiry-less (`:155-162`) — and at `core/mcp/ai_tools.go:302-306` the grant is **fabricated from the request being evaluated**, authorizing the tool because the agent named it. The signed APDL policy compiler (`pkg/asaf/policy/compiler.go:80-143`) has **zero call sites outside its own package**. |
| **G** | Revocation supremacy | **ABSENT** | No fleet-freeze primitive exists. SOAR revocation is a self-declared stub — `pkg/souhimbou/soar.go:394-401` logs and returns `nil`, while `:184` emits "🚨 Agent quarantined (production)" for an action that did not occur. `ACP.RevokeCredential` is genuine (`pkg/acp/control_plane.go:174-198`) but in-memory only, callable under the agent's own authority, and **never consulted at the actuation gate** — zero revocation checks in `router.go`. License CRL is explicitly fail-open (`pkg/license/sovereign.go:272-275`, error printed and discarded) over a single fetch to `cloudflare-ipfs.com`, a gateway Cloudflare has sunset; an empty `crlCID` returns `nil`, making such licenses unrevokable by construction. `core/citizenship/passport.go:65` has a `Revoked` field but **no `Revoke()` method and no consumer**. | Needs an authority the agent's own process cannot exercise, a persistent CRL, and a check at the gate. An env var is not an authority boundary. |
| **H** | Bounded blast radius per cycle | **ABSENT** | Only per-request throttles exist: `router.go:433` concurrency semaphore (`MaxConcurrent: 10`) caps simultaneous calls per agent, not targets per call. Fleet paths are unbounded: `pkg/asaf/stargate/handlers_fleet.go:283` loops over caller-supplied `body.Rows` with no length check; `:531` selects the entire registry with empty filters. Zero repo-wide hits for `MaxTargets`, `MaxBatch`, `BlastRadius`. | The only re-attestation machinery runs backwards: `pkg/apiserver/autopilot.go:254` auto-re-attests on a drift heuristic with `AutoReAttest: true` by default — it **removes** a human from the loop rather than inserting a checkpoint. |

### Supporting layers (rubric scope: `pkg/agi`, `pkg/dag`, `pkg/adinkra`)

| Component | Status | Evidence |
|---|---|---|
| KASA `DetectTampering` | **PARTIAL** | `pkg/agi/kasa_crypto_agent.go:95-129`. Computes real values, but the model is a self-labeled stub — `AnomalyDetectionModel struct{}` at `:437-439`; `PredictAnomaly` (`:445-471`) is four `if` statements on entropy and payload size; `AnalyzeBehavior` (`:478-517`) is substring matching plus a wall-clock hour check. Threshold `anomalyScore > 0.85` (`:127`) is deterministically false for typical tool payloads. |
| KASA `AutoSegment` | **PARTIAL** | `:225-285`. Encrypts a hardcoded 3-key stub map (`fetchComponentData`, `:398-404`) into an in-memory quarantine map no gate reads. `revokeCredentials` and `blockNetworkAccess` (`:408-417`) are `log.Printf` with "wire to … to complete". |
| KASA wired to an enforcing gate in `khepra-mcp` | **ABSENT** | The only enforcing call site is `pkg/souhimbou/wrapper.go:221-226`, gated on `BlockOnKASACritical`, a plain `bool` defaulting to false. `cmd/khepra-mcp` does not import `souhimbou` at all. |
| DAG encryption at rest | **ABSENT** | `pkg/dag/encryption.go` implements real AES-256-GCM at `:29`, `:68`, `:101` with **zero callers**. Actual write path is `persistence.go:98-105`: pretty-printed JSON at mode `0644`, world-readable. |
| DAG nodes signed on write | **ABSENT** | `Node.Sign` is real (`dag.go:80-94`) and never invoked by `PersistentMemory.Add` (`persistence.go:50-82`) or `Memory.Add` (`dag.go:96-138`). `Signature` is `omitempty`, so unsigned nodes serialize cleanly. |
| DAG chain verified on load | **ABSENT** | `persistence.go:173-176` explicitly bypasses `Add()` — "bypass Add() to avoid re-flushing" — so no hash recomputation, no signature check, no parent-existence check. The only rejection criterion is whether the file parses as JSON. Anyone with write access to the store can rewrite history undetected. |
| `AuditDAGIntegrity` | **ABSENT (dead code)** | `pkg/dag/dod_logger.go:77-124` walks and recomputes hashes correctly, but has zero callers. It would also pass unsigned nodes anyway (`:101-106`). |
| `pkg/dag` wired into the MCP router | **ABSENT** | Neither `cmd/khepra-mcp/main.go` nor `pkg/mcp/router.go` imports `pkg/dag`. DAG writes happen only as side effects inside individual leaf tool handlers. |
| Attestor in the shipping binary | **ABSENT (Noop)** | `main.go:256` → `kernelports.Defaults().Attestor` → `&NoopAttestor{}` (`kernelports.go:85`). `Append` (`:97-100`) returns `sha256(input‖output)` — persists nothing, chains nothing, omits `toolName` from the digest. `SignEnvelope` (`:102-104`) is the identity function. **No non-Noop Attestor implementation exists in the repository.** |
| `SignAgentAction` / `VerifyAgentAction` | **IMPLEMENTED, but off-path** | Real at `pkg/adinkra/khepra_pqc.go:147-175`. Zero call sites in `cmd/khepra-mcp`, `pkg/mcp/router.go`, or any executor. |

---

## 3. The Delta to L4 — ordered, smallest real gap first

Target the first action class only: **`RiskDestructive`**. It already has the most gate machinery, so it is the cheapest honest win.

1. **Make the manifest verifier real.** Replace `BootstrapManifestVerifier` at `cmd/khepra-mcp/main.go:122,132` (and `cmd/asaf-hub/main.go:397,407`) with `AdinkraManifestVerifier`. This is the highest-leverage single change in the audit: because the manifest is the sole source of truth for risk classification (`executor.go:20`) and its signature is never checked in any shipping binary, an attacker who edits one JSON file can reclassify `nhi_revoke` from `RiskDestructive` to `RiskReadOnly` and delete every control in B and C at once. One line, `manifest_store.go:102` `return nil`, currently voids the chain.

2. **Wire a real attestor.** Implement `DAGAttestor` over `pkg/dag` and inject it at `main.go:256`. The repository already knows this is missing and says so in its own scanner text at `pkg/mcp/scanner/checks.go:197`.

3. **Invert the attestation ordering (E).** Split `attest.Append` into sign-intent before `router.go:444` and sign-outcome after. Until a signed intent record exists prior to `Execute`, no L4 claim is defensible for any action class.

4. **Give the confirm token an identity.** Replace the `_confirm` boolean with a signed approval token bound to a human principal, a session and an expiry. Delete `KHEPRA_SKIP_CONFIRM` (`router.go:396`). Replace both auto-approving `stdioConfirmGate` implementations with a gate that actually blocks.

5. **Enforce revocation at the gate (G).** Add a revocation check to `HandleToolCall`, backed by a persistent CRL rather than an in-memory map. Make the license CRL path fail closed. Give revocation an authority the agent's process cannot exercise.

6. **Sign the DAG on write and verify on load.** `Node.Sign` and `AuditDAGIntegrity` already exist; wire them, and stop bypassing `Add()` at `persistence.go:173`. Call the existing `encryption.go` from the persistence path and drop the mode from `0644`.

7. **Bound the blast radius (H).** Add a per-decision target cap and a cumulative cycle counter with a mandatory re-attestation checkpoint before `handlers_fleet.go:283` and `:531`. Reconsider `autopilot.go:254`, which currently automates the human out of re-attestation.

8. **Arm rollback (D).** Add post-state equality checks to `RemediateSSHConfig`, stop discarding its rollback errors, and either implement real remote rollback or make the remote path refuse to act. Add pre-state capture to the four unreversed remediations, or reclassify them as requiring human execution.

9. **Build the authority ladder (A).** This is last deliberately. A state machine is only meaningful once there is a gate for it to modulate; built first, it would be another recorded-but-never-consulted field.

---

## 4. Honesty Flags

Places where a doc, comment, name, or public artifact currently asserts a capability the code does not enforce. Each needs either the code or the claim corrected.

| Claim | Where | Reality |
|---|---|---|
| "Verify always returns nil (**development-only** bypass)" | `pkg/mcp/manifest_store.go:99-104` | It is the only verifier constructed in any shipping binary, including the on-disk-manifest path. Not development-only. |
| `stdioConfirmGate` — name implies a stdio approval prompt | `cmd/khepra-mcp/main.go:23-26`, `cmd/asaf-hub/main.go:383-386` | Performs no I/O, cannot return non-nil, logs `auto-approve`. |
| Hub comment: risky ops "must be dispatched as ChangeRequests through Imhotep" | `cmd/asaf-hub/main.go` | No code enforces that routing. |
| `actionRevokeToken`, `actionRateLimit`, `actionExportFrames`, `actionOpenTicket` | `pkg/souhimbou/soar.go:394-420` | All log-only stubs returning `nil`. |
| "🚨 Agent quarantined (production)" Slack notification | `pkg/souhimbou/soar.go:184` | Emitted for a quarantine that did not occur. **This is an operator-facing false assurance and should be the first thing fixed in this table.** |
| `aaru.go` logs "executing action '%s'" | `pkg/agi`/`pkg/sekhem/aaru.go:221-236` | Prints the word "executing" and dispatches nothing. The "Auto-Isolate Catastrophic Threats" policy (`aaru.go:311`) isolates nothing. |
| `AutoSegment` "quarantine" | `pkg/agi/kasa_crypto_agent.go:225-285` | Encrypts a synthetic stub map into a map no gate consults; revoke and network-block are `log.Printf`. |
| `EncryptedNode` struct with `FIPSMode = true` | `pkg/dag/encryption.go:62` | Unreachable — zero callers on the whole file. |
| Attestation ID returned to clients | `router.go:540`, `kernelports.go:97-100` | An unstored, unchained, non-PQC SHA-256 presented as an attestation. |
| `DAGHash` emitted with `Metadata: {"phase": "signed"}` | `router.go:557` | The envelope is returned unsigned by `SignEnvelope`'s identity function. |
| Audit claim `tool_rug_attack_mitigated: true` (external threat-mapping doc) | not in code | The string does not exist anywhere in the repository. Must not appear in investor or compliance material. |
| `"local-sandbox"` documented as an `AllowedBackend` value | `pkg/mcp/types.go:87` | The string appears nowhere else; it would silently route to the Docker runner. |
| `LatencyVector` in the KTOS behavioral signature | `core/aeo/aeo.go:65-70` | Signed but never compared. No latency anomaly detection exists. |

---

## 5. Acceptance-Test Reality Check

| Precondition | Coverage | Detail |
|---|---|---|
| Rollback-on-fault | **0%** | Zero tests reference `Remediator` or `rollbackFile`. `pkg/ir/remediation_test.go` tests script *string generation*, not execution or reversal. No fault-injection test anywhere makes an action fail and asserts pre-state restoration. |
| ODD-boundary rejection | **PARTIAL** | Best coverage in the codebase, and all of it is in KTOS: `core/enforce/enforce_test.go:48,58,71,93` and `core/enforce/interdict_test.go:54,81,145`. In PQC-Khepra-MCP only `pkg/mcp/license_gate_test.go` covers tier gating and the `_confirm` flag. **Nothing tests manifest-signature rejection.** Nothing tests a time window or grant expiry, because neither exists. |
| Fail-closed-on-timeout | **0%** | No test drives a timeout or cancellation through an authorization or attestation path and asserts denial. The one explicitly fail-open branch, `sovereign.go:272-275`, has no test. |
| Pre-effect signing order | **0%** | No test asserts a DAG node or signature exists prior to executor invocation. `pkg/mcp` has exactly one test file; there is no `router_test.go` and no test that fails `attest.Append` and asserts the tool did not run. |

Compounding this: `pkg/flight` has no test file at all, and `.github/workflows/ci.yml:140-163` runs `go test -short` with a 60-second timeout over a hand-picked list it calls "safe packages", excluding `pkg/flight`, `pkg/sekhem` and `pkg/gateway` from CI entirely.

---

## 6. Closing Observation

The consistent pattern across all eight preconditions is that **the cryptographic primitives are genuine and correctly written, and they sit one import away from a call path that never calls them.** `pkg/dag/encryption.go`, `AuditDAGIntegrity`, `Node.Sign`-on-write, `SignAgentAction`, `AdinkraManifestVerifier`, and the APDL policy compiler are each complete, working implementations with no caller on the actuation path.

This is worth knowing before anyone proposes rewriting the crypto. The gap is wiring and ordering, not algorithms — which makes it far cheaper to close than the size of this document suggests, and far more urgent, because every one of those unwired components currently has a name, a log line, or a doc comment asserting that it is active.

# Product C Connective-Tissue Build Spec

Status snapshot: 2026-06-29. Target: Presight meeting 2026-07-15.

## Context

Three-product architecture (see memory `project_sprint_architecture` / `project_connective_tissue_components` for full provenance):

- **Product A** — AdinKhepra ASAF / Compliance Graph UI. CMMC/STIG installer bundle. Not part of this spec.
- **Product B** — SouHimBou AI Flight Recorder (adinkhepra.com → souhimbou.ai). Has a working beta dashboard with a live WebSocket DAG viewer (`KhepraDAGVisualization.tsx`). Not part of this spec except as a consumer.
- **Product C** — PQC-Khepra-MCP. This repo. Must stay the most modular of the three: the connective tissue any downstream UI (A's or B's) can consume.

Everything below was verified by reading source and running `go build`/`go test`/live stdio+SSE smoke tests today — not inferred from filenames or prior session summaries.

## Current state of Product C (verified)

**Already live and reachable via MCP tool calls today** (registered in `cmd/khepra-mcp/main.go`):
- DEMARC gateway (`pkg/api/demarc_api.go`) — stdio pre-auth identity, live in the security chain.
- Polymorphic envelope wrapping (`pkg/mcp/chain.go`'s `AdinkraPolymorphicEngine`) — live in every tool call.
- DAG attestation (`pkg/mcp/chain.go`'s `DAGAttestor`) — live, ML-DSA-65 signed, every tool call.
- Loopback SSE live viewer (`pkg/mcp/live_viewer.go`, built today) — `KHEPRA_VIEWER_PORT` env var, independent of stdio/HTTP transport, verified end-to-end against real stdin traffic.
- KASA orchestrator: `kasa_start`, `kasa_status` (registered).
- EA Kernel: `ea_evolve`, `ea_threat_score`, `ea_risk_summary` (registered).
- Ising optimizer: `quantum_optimize` (registered).
- Ouroboros monitoring eyes: `ouroboros_waf_eye`, `ouroboros_stig_eye`, `ouroboros_vuln_eye`, `ouroboros_fim_eye` (registered).

**Present as real, building, working Go code — NOT yet registered as MCP tools** (dead code from the MCP server's perspective):
- `tools.HandleKASATask`, `tools.HandleKASAScan`, `tools.HandleKASAForensics`, `tools.HandleKASACryptoAgent` (all in `pkg/mcp/tools/kasa_tools.go`).

**Present as real packages, build/test clean, but with NO live integration point yet**:
- `pkg/sekhem` (WAF, 10 files) — `ouroboros_waf_eye` reads from "the SEKHEM pipeline" per its own description, but nothing in `cmd/khepra-mcp` currently populates that pipeline from live request traffic (stdio MCP has no L7 ingress to filter). Likely only meaningful once/if `KHEPRA_HTTP_PORT` HTTP transport carries real external traffic.
- KASA's autonomous loop (`pkg/agi/engine.go`'s `Engine.loop()`) writes to its OWN separate in-memory DAG store (`kasaStore`, created via `dag.NewMemory()` in `kasa_tools.go`'s `getKASA()`), which is **not the same store** the router/live-viewer's `EventEmitter` observes. KASA's autonomous background actions (forensics every 15min, vuln hunts hourly, etc.) do not currently surface in the SSE live viewer.

**Confirmed NOT present in Product C** (exists only in `khepra protocol` / Product A's repo):
- `supabase/functions/mitochondrial-proxy/` — Supabase Edge Function, HTTP/web-facing OAuth+attestation gateway. This is an HTTP boundary concept; not obviously relevant to a stdio-first MCP server. **Not in scope for July 15** — flag only.

**Critical finding — full source drift, every single file**:
`pkg/ea`, `pkg/sekhem`, `pkg/ouroboros`, `pkg/agi`, `pkg/ising`, `pkg/api` all exist in BOTH `khepra protocol` and `PQC-Khepra-MCP`, and **every file differs** between the two copies (confirmed via `diff -rq`). Both copies build and test clean independently right now. There is no shared module — they are two forks of a common ancestor that have already diverged. This is the single biggest structural risk to "Product C as connective tissue": a fix or feature added to one fork silently does not exist in the other.

## Decision: PQC-Khepra-MCP is the canonical source for shared security-kernel packages

Going forward, `pkg/ea`, `pkg/sekhem`, `pkg/ouroboros`, `pkg/agi`, `pkg/ising` are owned by Product C. Product A (`khepra protocol`) should consume Product C as a dependency (Go module import or a vendored sync step with a one-way diff check) rather than maintain an independently-edited fork. Rationale: these packages are explicitly "connective tissue" per the user's own framing — Product C is supposed to be the most modular of the three, which means it's the one that should own shared infrastructure, not duplicate it.

This is a real architectural call, not a neutral default — flagging it explicitly so it can be overridden if wrong. If overridden, swap "Product C" for whichever repo should be canonical in the tasks below; the task shapes don't change.

## Build phases

### Phase 1 — Finish what's already 90% done (low risk, do first)

1. Register the four unregistered KASA handlers in `cmd/khepra-mcp/main.go`: `kasa_task`, `kasa_scan`, `kasa_forensics`, `kasa_crypto_agent` → `tools.HandleKASATask` / `HandleKASAScan` / `HandleKASAForensics` / `HandleKASACryptoAgent`. Add matching manifest tool-spec entries (mirror the existing `kasa_start` entry's shape). Rebuild manifest hash (`gen_manifest.go`) and confirm `khepra-mcp.exe` still passes `go vet`/`go test ./pkg/mcp/...`.
2. Unify KASA's DAG store with the router's observable event stream: either (a) have `getKASA()` accept and use the same `dag.Store` the router's attestor writes to, or (b) add an `EventEmitter` hook inside `Engine.loop()`/`logToDAG()` so autonomous KASA actions also call `viewer.Push`-compatible events. Acceptance: starting `kasa_start` and waiting >60s shows a `Routine Perimeter Sweep` (or similar autonomous) event in the SSE feed at `/events`, not just user-invoked tool calls.
3. Smoke-test `kasa_start` → `kasa_task` → `kasa_status` → `kasa_crypto_agent` through real stdio JSON-RPC (same method used to verify `agent_record` earlier), with `KHEPRA_VIEWER_PORT` set, confirming the SSE feed shows KASA's autonomous and directed actions live.

### Phase 2 — Reconcile drift (medium risk, do before adding anything new on top)

1. For each of `pkg/ea`, `pkg/sekhem`, `pkg/ouroboros`, `pkg/agi`, `pkg/ising`: diff PQC-Khepra-MCP's copy against `khepra protocol`'s copy file-by-file. Classify each diff as (a) PQC-Khepra-MCP has a fix/feature `khepra protocol` lacks, (b) the reverse, or (c) genuine intentional divergence (e.g. PQC-Khepra-MCP's `pkg/sekhem` has an extra `http_middleware.go` not present upstream — likely intentional, MCP-specific).
2. Port forward anything in category (b) into PQC-Khepra-MCP so it becomes the strict superset.
3. Document the decision (canonical = Product C) in both repos' top-level CLAUDE.md/AGENTS.md so future sessions don't re-fork by accident.

### Phase 3 — Demo readiness for July 15

1. Confirm the loopback SSE live viewer (`pkg/mcp/live_viewer.go`) renders KASA/EA/Ising events with readable labels — extend `liveViewerHTML`'s row rendering if KASA/EA event `Metadata` needs different formatting than plain tool-call exec/attest events.
2. Decide and rehearse the actual demo sequence: e.g. `kasa_start` (autonomous agent boots) → narrate the live feed as KASA runs its own perimeter sweep/forensics → `ea_evolve` or `quantum_optimize` to show the adaptive/evolutionary angle → an `agent_record` or real tool call to show signed attestation of an external action. This directly demos "agentic AI accountability" without touching Product A's CMMC framing or Product B's separate dashboard.
3. Re-run the full stdio+SSE smoke test end to end after Phase 1/2 changes, exactly as done earlier in this session, before calling it demo-ready.

## Explicitly out of scope for July 15

- Building a real trained ML model to replace `KASACryptoAgent`'s heuristic anomaly scoring. The agent shell is real; the "ML" is currently rule-based thresholds. Don't claim otherwise in the room; don't try to build a real model in two weeks.
- Porting `mitochondrial-proxy` into Product C. It's an HTTP/web boundary concept with no current consumer in the stdio-first MCP model.
- Wiring SEKHEM WAF into live request filtering. No live HTTP ingress exists in the demo path to filter.
- Merging Product A's Compliance Graph UI with Product C's live feed, or building Product A's missing 3D graph at all. Per the segregation decision already made, Product B's dashboard is the intended consumer for a Presight-facing demo, not Product A's.

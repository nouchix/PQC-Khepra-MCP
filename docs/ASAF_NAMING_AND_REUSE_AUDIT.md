# AdinKhepra ASAF Spec — Naming Collision & Reuse Audit

Audit of `AGENTS.md` / `ADINKHEPRA_ASAF_SPEC.md` / `SOUHIMBOU_AI_SPEC.md` against the
actual codebase (`nouchix/PQC-Khepra-MCP`, the real Go source — note `nouchix/adinkhepra-asaf`
is a signed-binary release drop, not the source repo).

## Decision

**Keep `pkg/asaf` exactly as-is.** It is live in production, wired into `cmd/apiserver`
(build tag `saas`, the SEKHEM Gateway) with public/authenticated endpoints already
shipped: `GET /api/v1/asaf/stream`, `POST /api/v1/asaf/record`, `GET /api/v1/asaf/sessions`,
`GET /api/v1/asaf/history`, plus the `ASAF_ALLOW_EVAL_WITHOUT_LICENSE` env var and CORS
origins bound to `adinkhepra.com` / `souhimbou.ai` / `nouchix.com`. Renaming it would break
any deployed client (dashboard, MCP bridge) calling those paths.

**The new AdinKhepra privileged-OS daemon described in `ADINKHEPRA_ASAF_SPEC.md` must use
different names.** Nothing for it exists yet, so this is a pure naming decision, not a
migration:

| Spec's proposed name | Renamed to | Why |
|---|---|---|
| `cmd/asaf-daemon` | `cmd/adinkhepra-daemon` | Collides with existing `cmd/khepra-daemon` ("the Father — hidden protector for SouHimBou.AI", port 45444) and with the live `pkg/asaf` flight recorder |
| `pkg/asaf/daemon`, `pkg/asaf/policy`, `pkg/asaf/staging` | `pkg/adinkhepra/daemon`, `pkg/adinkhepra/policy`, `pkg/adinkhepra/staging` | `pkg/asaf` is already a package with a different, shipped meaning |
| `pkg/asaf/policy_compiler.go` (APDL compiler) | `pkg/adinkhepra/policy_compiler.go` | same |

## What "ASAF" already means in this codebase (do not confuse with the new daemon)

`pkg/asaf` = **Agentic Security Attestation Framework** — SouHimBou AI's flight recorder:
- `wrapper.go` — `ASAFWrapper.WrapMCPAgent()` / `RecordAction()`: intercepts MCP tool calls
  from any AI agent (Claude Code, Copilot, Cursor) and writes a signed DAG node per action.
  This already implements the "$0 Free — Flight Recorder" tier described in
  `SOUHIMBOU_AI_SPEC.md`.
- `drift.go` — cosine-similarity behavioral drift detection against per-agent-type baselines
  (`claude-code`, `copilot`, `cursor`). This already implements the "DETECT" step of the
  SouHimBou Core Agent continuous loop (KASA anomaly scoring).
- `recorder.go` — SSE broadcast server for live dashboard feed + HTTP handlers for the
  endpoints listed above.

Recommendation for a future (separate) pass: rename this package's *Go identifiers* to
match `SOUHIMBOU_AI_SPEC.md` terminology (e.g. introduce `pkg/souhimbou` as a thin
re-export, or move incrementally with the `/api/v1/asaf/*` routes kept as permanent aliases)
— but that is out of scope for unblocking Sprint 1 and should be its own ticket.

## Second collision: `pkg/compliance` already implements most of the "Policy Editor /
Staging Gate" logic

`ADINKHEPRA_ASAF_SPEC.md` proposes building `pkg/asaf/policy_compiler.go` (APDL → Ansible
+ DAG schema) and a staging/remediation gate from scratch. Both already exist in
`pkg/compliance`:

- `engine.go` — `Engine.EvaluateCompliance()` scores a System Security Plan (SSP) against
  CMMC Level 2 controls and returns a COMPLIANT/NON-COMPLIANT report ("Ready for C3PAO
  Assessment" is a literal string in the output).
- `engine.go` — `Engine.AutoRemediate()` iterates failed controls and calls
  `ScannerInterface.RemediateControl(controlID)`, then writes `AUTO_REMEDIATED` status via
  `Manager.UpdateControl()` (signed update path).
- `stig_mapper.go`, `nist80053.go`, `nist80171/`, `nist80172/`, `rmf/`, `ssp.go`, `sync.go`,
  `checks_unix.go`, `checks_windows.go`, `gsa/`, `nemoclaw_checks.go` — a substantial,
  cross-platform compliance engine already covering STIG/NIST/CMMC/RMF mapping, SSP
  management, and OS-level checks (Unix + Windows).

**Implication for Sprint 1:** the new AdinKhepra daemon's job is narrower than the spec
assumes. It should be the **privileged execution + ML-DSA-65 authorization layer** that
`pkg/compliance.Engine.AutoRemediate()` calls into (replacing/wrapping
`ScannerInterface.RemediateControl`), not a parallel policy-compilation system. The APDL
language layer (human-readable `@symbol(Eban) control AC-2 { ... }` syntax) is still net-new
and doesn't exist anywhere — that part of the spec is accurate and unbuilt.

## Third item: `cmd/khepra-daemon` is a third "guardian" concept

`cmd/khepra-daemon/main.go` — "the Father — the hidden protector for SouHimBou.AI" — runs
on port 45444, exposes `/dag/add`, `/adinkra/weave`, `/adinkra/unweave`, `/attest/verify`,
`/status`. This is a PQC weave/attest service, distinct from both `pkg/asaf` and the planned
AdinKhepra daemon. No action needed beyond noting it exists so the new
`cmd/adinkhepra-daemon` doesn't duplicate its weave/attest endpoints — the new daemon should
call into `pkg/adinkra` directly for signing, not reinvent a second weave service.

## Summary for whoever starts Sprint 1

1. Use `cmd/adinkhepra-daemon` / `pkg/adinkhepra/*` for all new privileged-OS-execution code.
   Do not create anything under `pkg/asaf/`.
2. Before writing a new policy compiler, read `pkg/compliance/engine.go`,
   `stig_mapper.go`, and `ssp.go` — extend `ScannerInterface` / `Engine.AutoRemediate()`
   rather than duplicating CMMC scoring or remediation orchestration.
3. The APDL declaration language (`@symbol(Eban) control AC-2 {...}`) and the Compliance
   Graph UI frontend are genuinely unbuilt — these are accurate gaps in the spec.
4. LoC/file/binary counts in `AGENTS.md` are directionally plausible but unverified; treat
   as approximate, not load-bearing for planning.

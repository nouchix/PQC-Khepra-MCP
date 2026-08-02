# SouHimBou Four-Dimensional Audit Framework

**Status**: ACTIVE · **Spec version**: 2.0 · **Type**: Reusable audit methodology
**Provenance**: SouHimBou / SecRed Knowledge Inc. dba NouchiX · KHEPRA Protocol (USPTO #73565085)
**Applies to**: Any KHEPRA / ADINKHEPRA / ASAF codebase (drop this file into the repo root and run)

> This is the formal, portable specification of the audit framework first applied in
> `SOUHIMBOU_AUDIT_REPORT_2026-02-12.md`. Copy it into any repo unchanged; it is
> codebase-agnostic. To run an audit, follow §6 and emit a report from the §7 template.

---

## 1. Purpose & Core Principle

The framework exists to close the gap between **what a system claims** and **what it
actually does**. Its governing constraint is absolute:

> **NO STUBS · NO MOCKS · NO "DELAYED UNTIL PRODUCTION."**

An audit under this framework does not check style or taste. It hunts for one class of
defect above all others: **fabrication that appears real** — mock data on dashboards,
hardcoded keys behind "secure" APIs, strategy docs describing controls that do not
exist in code, and "in production this will…" comments on security-critical paths.

The insight of the framework is that a single traversal of a system never finds all of
these. You must walk the system along **four independent geometric axes**. Each axis
catches a defect class the others miss; together they give complete coverage.

---

## 2. The Geometric Model

Model the system as a vertical stack of layers — strategy/marketing at the top, running
code and infrastructure at the bottom:

```
        ┌─────────────────────────────────────────┐  Strategy / Claims / Docs
        │  ▲ BOTTOM-UP        TOP-DOWN ▼            │  Product / API contracts
        │       ╲              ╱                    │  Application code
   ↔ HORIZONTAL ─────────────────────── ↔          │  Services / crypto / data
        │       ╱  ⤡ DIAGONAL  ╲                   │  Infrastructure / storage
        └─────────────────────────────────────────┘  Hardware / network
```

Four ways to traverse the stack, four dimensions of the audit:

| Dimension | Axis | Direction | One-line question |
|---|---|---|---|
| **1. Top-Down** 🔽 | Vertical | Claims → Code | *Strategy claims X — does the code actually deliver X?* |
| **2. Bottom-Up** 🔼 | Vertical | Code → Claims | *Starting from real code — what's implemented vs. what's advertised?* |
| **3. Horizontal** ↔️ | Horizontal | Across one layer | *Are cross-cutting patterns consistent across the whole system?* |
| **4. Diagonal** ⤡ | Diagonal | Through all layers | *Tracing one feature end-to-end, where do trust boundaries break?* |

> **Why "Vertical" is two dimensions.** The vertical axis is walked in both directions
> because they catch opposite failures. **Top-Down** finds *promised-but-absent* controls
> (a doc claims Vault integration; no Vault code exists). **Bottom-Up** finds
> *present-but-misrepresented* code (a function returns mock data while the UI presents it
> as live). Running only one leaves half the vertical surface unaudited.

---

## 3. The Four Dimensions

### 3.1 — DIMENSION 1: Top-Down Audit 🔽 *(Vertical, Claims → Code)*

- **Question**: For every claim in strategy/marketing/architecture docs, does the code deliver it?
- **Catches**: Vaporware controls, aspirational security ("we use X"), compliance claims with no implementation.
- **Inputs**: Every `*.md` strategy/architecture/marketing doc, README, whitepaper, compliance roadmap, sales collateral, `SECURITY.md`.
- **Method**:
  1. Extract each concrete, testable claim ("uses HashiCorp Vault", "AES-256-GCM at rest", "MCP gateway with prompt-injection scanning").
  2. Grep/trace the codebase for the implementing component.
  3. Classify: **Delivered**, **Partial**, or **Absent**.
  4. Absent/Partial security claims → finding.
- **Finding prefix**: `TD-`

### 3.2 — DIMENSION 2: Bottom-Up Audit 🔼 *(Vertical, Code → Claims)*

- **Question**: Starting from the actual code, what is really implemented — and does anything real get misrepresented as more (or less) than it is?
- **Catches**: Stubs, mocks, `TODO`/`FIXME`/`panic("not implemented")`, hardcoded secrets/keys, placeholder returns, `if false`/dead paths, "in production this will…" comments on live paths.
- **Inputs**: Every package/module — walk `pkg/`, `src/`, `services/`, `cmd/`, functions/, migrations. No file is out of scope.
- **Method**:
  1. Scan for stub/mock/placeholder markers and hardcoded credentials.
  2. For each, determine whether it sits on a **production path** (reachable in a real deployment) or a **test path**.
  3. Production-path stubs/mocks → finding, weighted by what the surrounding code *claims* to do.
- **Finding prefix**: `BU-`

### 3.3 — DIMENSION 3: Horizontal Audit ↔️ *(across a single layer / cross-cutting)*

- **Question**: Are cross-cutting concerns implemented consistently everywhere, or only in some places?
- **Catches**: Inconsistent authn/authz, some endpoints validated and others not, uneven input sanitization, logging that redacts in one module and leaks in another, error handling that swallows in one place and exposes stack traces in another.
- **Inputs**: One concern at a time (auth, input validation, error handling, logging, rate limiting, crypto usage), swept across **all** components at the same layer.
- **Method**:
  1. Pick a cross-cutting concern.
  2. Enumerate every site that should implement it (all HTTP handlers, all tool entrypoints, etc.).
  3. Flag every site that deviates from the established pattern.
- **Finding prefix**: `HZ-`

### 3.4 — DIMENSION 4: Diagonal Audit ⤡ *(one feature, through every layer)*

- **Question**: Following a single feature or data element from entry to storage to UI, where do assumptions break at the seams between layers/languages/services?
- **Catches**: Trust-boundary failures — a signature verified in one layer but trusted-without-recheck in the next; data validated at the API but not at the worker; a Go binary's guarantee silently dropped by a Python proxy or a JS worker.
- **Inputs**: One representative end-to-end trace (e.g. "validate a license": Go → CLI → API → edge worker → DB → frontend).
- **Method**:
  1. Pick a security-critical feature/data path.
  2. Trace it through every layer and language boundary it crosses.
  3. At each seam, ask: *is the previous layer's guarantee re-verified or merely assumed?*
  4. Every unverified assumption across a seam → finding.
- **Finding prefix**: `DG-`
- **Worked example**: see `DIAGONAL_AUDIT.md` (license lifecycle: Go → API → Worker → D1 → React).

### 3.5 — Optional 5th Pass: Sunsum Harmonization *(extension)*

Some audits add a reconciliation pass ("Sunsum Harmonization / Nsohia Autonomy") that
takes the four dimensions' findings and checks the system's **self-consistency and
resilience** as a whole — that remediations in one dimension didn't regress another. Treat
it as an optional closing step, not a fifth axis.

---

## 4. Finding Schema

Every finding is one record:

```
### <PREFIX>-<NN> | <SEVERITY|RESOLVED> | <short title>
- **Claimed / Expected:** <what the doc/UI/contract promises>
- **Reality:** <what the code actually does>
- **Files:** <path:line, …>   (or "None exist" for absent claims)
- **Impact:** <concrete consequence if unaddressed>
- **Remediation:** <what to do>            # for OPEN findings
- **Resolution:** <what was done> — ✅ RESOLVED <date>   # for RESOLVED findings
```

- **PREFIX**: `TD` | `BU` | `HZ` | `DG` (the dimension that surfaced it).
- **NN**: zero-padded sequence within the dimension (`TD-01`, `TD-02`, …).
- Findings are immutable once assigned an ID; a fixed finding flips status to `RESOLVED` (keep the ID for traceability), it is never deleted or renumbered.

### Severity rubric

| Severity | Definition |
|---|---|
| **CRITICAL** | Active security vulnerability, or fabricated data on a path an operator will trust as real, or a claimed security control that is wholly absent. |
| **HIGH** | Real but broken/bypassable control, production-path stub on a security feature, or a cross-cutting gap that leaves a class of endpoints unprotected. |
| **MEDIUM** | Partial implementation, inconsistency with a real workaround, or a trust-seam assumption that currently holds but is unverified. |
| **LOW** | Hygiene: dead code, stale claim in docs, cosmetic inconsistency with no security impact. |
| **RESOLVED** | A previously logged finding since remediated; retained for the audit trail. |

---

## 5. Scoring & Verdict

Aggregate findings into the executive-summary matrix (§7). Then apply the verdict rubric:

- **Any CRITICAL open** → **NOT PRODUCTION READY.** Critical findings gate release.
- **CRITICAL = 0, HIGH > 0** → **CONDITIONAL.** May ship only with documented compensating controls and dated remediation for each HIGH.
- **CRITICAL = 0, HIGH = 0** → **PRODUCTION READY** for the audited scope.

The verdict is per-scope and per-audit-date; it is not a certification. Re-audit on the cadence in §9.

---

## 6. Execution Procedure

1. **Define scope** — list the paths in scope (`pkg/`, `src/`, `services/`, `cmd/`, `supabase/`, …) and the constraint (no stubs/mocks/deferrals).
2. **Assign an Audit ID** — `SAF-YYYY-MMDD-HHMM` (SouHimBou Audit Framework + timestamp).
3. **Run the four dimensions in order** — Top-Down → Bottom-Up → Horizontal → Diagonal. Order matters: Top-Down frames the claims, Bottom-Up grounds them in code, Horizontal generalizes, Diagonal integrates.
4. **Log every finding** using the §4 schema, prefixed by its dimension.
5. **Score & rule** per §5.
6. **Emit the report** from the §7 template.
7. **Track remediation** — flip findings to `RESOLVED` (with date + resolution) as they are fixed; never renumber.
8. **Re-audit** per §9; each run gets a new Audit ID and a fresh report, cross-referencing prior finding IDs.

---

## 7. Report Template

```markdown
# 🔱 SouHimBou Four-Dimensional Audit Report

**Audit Date:** <ISO-8601>
**Audit ID:** SAF-YYYY-MMDD-HHMM
**Auditor:** SouHimBou Audit Framework (Automated + Manual Review)
**Scope:** <paths in scope>
**Constraint:** NO STUBS / NO MOCKS / NO "DELAYED UNTIL PRODUCTION"

## Executive Summary

| Dimension | Findings | RESOLVED | CRITICAL | HIGH | MEDIUM | LOW |
|-----------|----------|----------|----------|------|--------|-----|
| **Top-Down** (Strategy → Code)   |  |  |  |  |  |  |
| **Bottom-Up** (Code → Claims)    |  |  |  |  |  |  |
| **Horizontal** (Cross-Cutting)   |  |  |  |  |  |  |
| **Diagonal** (Trust Boundary)    |  |  |  |  |  |  |
| **TOTAL**                        |  |  |  |  |  |  |

**Verdict:** <NOT PRODUCTION READY | CONDITIONAL | PRODUCTION READY> — <one-line justification>

## 🔽 DIMENSION 1: TOP-DOWN AUDIT
*Strategy documents claim X → does the code actually deliver X?*
<TD-NN findings…>

## 🔼 DIMENSION 2: BOTTOM-UP AUDIT
*Starting from actual code — what's really implemented vs. claimed?*
<BU-NN findings…>

## ↔️ DIMENSION 3: HORIZONTAL AUDIT
*Cross-cutting concerns: are patterns consistent across the entire system?*
<HZ-NN findings…>

## ⤡ DIMENSION 4: DIAGONAL AUDIT
*Trust boundaries — where do assumptions break across system seams?*
<DG-NN findings…>

## Final Verdict
- ✅ **Top-Down:** <summary>
- ✅ **Bottom-Up:** <summary>
- ✅ **Horizontal:** <summary>
- ✅ **Diagonal:** <summary>

*Report generated by SouHimBou Audit Framework v2.0*
*Audit ID: SAF-YYYY-MMDD-HHMM · Classification: INTERNAL — Security Sensitive*
```

---

## 8. Automation Hooks

The framework is designed to run partly automated, partly manual:

| Dimension | Automatable with | Manual review adds |
|---|---|---|
| Top-Down | Grep claims from `*.md`; check for implementing symbols | Judgement on whether an implementation truly satisfies the claim |
| Bottom-Up | `secret_scan`, static scan for `TODO/FIXME/panic/mock/stub`, `stig_check` | Deciding production-path vs. test-path |
| Horizontal | Lint rules / CodeQL for missing middleware, unauthenticated handlers | Confirming the intended pattern |
| Diagonal | `dag_write` trace + `threat_model` (STRIDE) per data path | Reasoning about trust-seam assumptions |

**KHEPRA integration**: findings map cleanly onto the KHEPRA evidence pipeline — export
each as an OSCAL `finding`/`observation` (see `pkg/evidence/oscal.go`) and seal the run to
the DAG via `dag_write`, so a SouHimBou audit produces auditor-grade, tamper-evident
evidence, not just a markdown report.

**CI hook (optional)**: run the Bottom-Up and Horizontal automatable checks on every PR;
gate merges on `CRITICAL = 0`. Run the full four-dimensional audit on a cadence (§9).

---

## 9. Cadence & Governance

- **Trigger a full audit** on: a major release, a new external integration, a change to
  any crypto/auth/trust-boundary code, or quarterly — whichever comes first.
- **Owner**: Security Lead (or GRC Lead) signs off the verdict.
- **Retention**: keep every dated report; findings are append-only across audits so the
  trail shows how the codebase's integrity evolved.
- **Cross-reference**: each new report links prior finding IDs it re-checked.

---

## 10. Provenance & Related Documents

- **Origin**: `SOUHIMBOU_AUDIT_REPORT_2026-02-12.md` (first full application, Audit ID `SAF-2026-0212-2149`).
- **Diagonal worked example**: `DIAGONAL_AUDIT.md`.
- **Crypto-focused application**: `SOUHIMBOU_AUDIT.md` (Adinkra Lattice; includes the optional Sunsum Harmonization pass).
- **Not this framework** (distinct, do not confuse): `docs/KHEPRA_PROTOCOL_AUDIT_FRAMEWORK.md` (PAIF) is a separate 5-point SaaS-SDLC checklist.

*IP: SouHimBou / SecRed Knowledge Inc. dba NouchiX — KHEPRA Protocol, USPTO #73565085.*
*"The Scarab watches. The Motherboard executes. The Logic is Eternal."*

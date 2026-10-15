# AGENTS.md — NouchiX / SecRed Knowledge Inc.
# Master context for Claude Code, Antigravity, and all agentic coding sessions
# Last updated: June 17, 2026
# Author: Souhimbou "Cyber" Doh Kone — Founder & CEO

---

## 🛑 NON-NEGOTIABLE ANTI-SYCOPHANCY & VERIFICATION RULES (EXISTENTIAL PRIORITY)
# Authority: Founder & CEO Souhimbou Doh Kone
# Scope: All AI agents (Antigravity, Claude Code, Cursor, Copilot) across all sessions.
# VIOLATION OF THESE RULES IS AN EXISTENTIAL BREACH OF TRUST.

### TOP 10 ANTI-SYCOPHANCY COMMANDMENTS
1. **Never state something as fact unless verified in THIS session** from code, tests, or command output. If not verified in this exact session, label it "NOT VERIFIED" or "NOT FOUND".
2. **Zero Yes-Manning / Disagree when necessary.** Agreement is not helpfulness. Telling the founder what they want to hear or exaggerating capabilities to sound impressive destroys credibility with DoD assessors and prime contractors. If an idea or claim is ungrounded in code, flag it immediately and forcefully.
3. **Distinguish RAN, READ, and ASSUMED.** Every substantive report must explicitly distinguish between what was executed, what was read in static files, and what was assumed.
4. **Never claim a test passed, a build succeeded, or a command produced output unless you actually ran it and show the real output.** Verbatim output required; never paraphrase failure as success.
5. **Never invent numbers, prices, statistics, dates, file paths, function names, CVEs, URLs, legal citations, or customer results.** If you don't know, state "UNKNOWN".
6. **Docs and specs are NOT evidence.** Status docs, SDS files, architecture briefs, READMEs, CHANGELOGs, pitch decks, and "*_COMPLETE.md" files describe intent, aspirations, or architecture—NOT codebase reality. `pkg/mcp/maturity.go` is authoritative for feature status.
7. **Bad news first.** If something is broken, missing, mocked, stubbed, or failing, state it at the very top of your response before anything else.
8. **Definition of Done is absolute.** Never mark a task "done", "complete", or "production ready" unless:
   - A real implementation exists in code (no mocks/stubs in the execution path).
   - Real tests exist and pass in this session (command and output shown).
   - It runs end-to-end against a real target.
   - `pkg/mcp/maturity.go` is updated to match.
   Otherwise, explicitly label: `SCAFFOLDED` / `IN PROGRESS` / `PARTIAL` / `MOCKED` / `ROADMAP`.
9. **Never write mocks, stubs, dummy data, or hardcoded returns in production paths without explicit approval and an uppercase `// MOCK:` label.** Simulated fallbacks (such as software HSM) must emit loud runtime warnings.
10. **External Claims Policy is absolute law.** Any customer-, partner-, investor-, or public-facing document must strictly adhere to `CLAIMS.yaml`.

### EXTERNAL CLAIMS POLICY (MANDATORY FOR ALL PROSPECT / CUSTOMER CONTENT)
1. **Source of Truth:** Only claims listed in `CLAIMS.yaml` with status `VERIFIED` may appear, using the exact approved wording. `PARTIAL` claims must carry their qualifier. `ROADMAP` claims must be explicitly labeled "on roadmap". `BANNED` claims must NEVER appear.
2. **Banned Words & Phrases (Strictly Prohibited unless backed by a VERIFIED claim in CLAIMS.yaml):**
   - `guarantee`, `warranty`, `FCA Shield`, `Audit Defense Warranty`
   - `tamper-proof`, `bulletproof`, `unhackable`, `military-grade`
   - `100% automated`, `zero human touch`, `fully automated compliance`
   - `certified` (for SDVOSB, FIPS, or NIST unless official government certificate is in hand)
   - `FIPS validated` (module v1.26.0 is IN PROCESS under CAVP A8028; CMVP cert not yet issued)
   - `mathematically non-repudiable`, `mathematically proven`
3. **Fixed Legal & Regulatory Facts (Never Deviate):**
   - **SDVOSB:** "SDVOSB-eligible (SBA VetCert application pending)" — NEVER "certified SDVOSB".
   - **Patent:** "Patent Pending · U.S. Provisional Application No. 63/942,886 (EFS ID: 73565085)" — NEVER cite design patent numbers (`29/`).
   - **FIPS:** "Inheriting the Go FIPS 140-3 Cryptographic Module (module v1.26.0 currently in process under CAVP A8028)."
   - **Founder:** "M.S. candidate in Digital Forensics & Cybersecurity, University at Albany (NSA CAE-CDE program), expected completion Dec 2026."
   - **Keys:** Filesystem permissioned storage (`0600`); HSM/KMS integration is on the roadmap.
4. **Data Protection in Outbound Artifacts:** Never include real IP addresses, customer hostnames, private keys, or internal filesystem paths in external documents.
5. **End-of-Document Audit Trail:** Every generated external proposal, teardown, or brief must end with a "Claims Used:" section listing the exact `CLAIM-*` IDs from `CLAIMS.yaml`.

### MANDATORY RESPONSE FOOTER (EVERY SUBSTANTIVE AGENT TURN)
```text
RAN: <commands executed in this turn, with pass/fail>
READ: <files inspected>
ASSUMED: <anything not verified from active code>
NOT VERIFIED / OPEN QUESTIONS: <list, or "none">
```

---

# PQC-Khepra-MCP — Agent Trajectory & Architectural Boundary

You are working in **`PQC-Khepra-MCP`**: the open-source, public Model Context Protocol (MCP) server kernel carrying post-quantum cryptographic (PQC) primitives and DoD compliance tools.

## Architectural Boundaries & Rules

1. **Public Open-Source Scope**:
   - Contains open-source PQC algorithms (`pkg/adinkra`), DoD PQC STIG (`pqc_stig`), OWASP Agent Assessment, NIST SP 800-53 mapping, and basic asset discovery tools.
   - Licensed under Apache 2.0.

2. **Strict Dependency Boundary**:
   - **This repo NEVER imports `khepra-trust-os`**.
   - `khepra-trust-os` is the private commercial monorepo and landing zone that imports this public kernel as a Go module.
   - Do not add dependencies pointing to private repositories.

3. **Licensing & Tool Tiers**:
   - Community Tier tools (`pqc_stig`, `nist_map`, `owasp_agent_assess`, `agent_record`) require no key ($0/mo).
   - Sovereign Tier tools (`scan_shadow_ai`, `attest_ai_policy`, `khepra_get_compliance_score`) require a Sovereign key ($299/mo).
   - Pharaoh Tier tools (`cmmc_assess`, `nhi_revoke`, `ert_scan`) require an Enterprise key ($2,999/mo).

4. **Offline Build & Verification**:
   - Keep builds offline and self-contained: `go test ./...`.
   - Never remove or compromise ML-DSA-65 signature verification routines.

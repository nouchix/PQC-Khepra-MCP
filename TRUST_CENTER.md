# NouchiX Trust Center — Source of Truth

**Repository:** `nouchix/PQC-Khepra-MCP`
**This repo's role:** KHEPRA MCP Server — the Model Context Protocol server exposing the KHEPRA compliance & evidence toolchain (`pqc_stig`, `attest_export`, `dag_write`, `ert_scan`, …). Origin of the OSCAL emitter (`pkg/evidence/oscal.go`).

> This is the **canonical, hyper-comprehensive Trust Center source of truth** for
> SecRed Knowledge Inc. dba **NouchiX** and the **KHEPRA Protocol** product family
> (USPTO #73565085). An identical copy is maintained on every NouchiX product repo so
> that posture questions can be answered consistently from any surface. It is the
> content source that seeds the OSCAL System Security Plan assembled in the private
> audit enclave (`asaf-compliance`). See `COMPLIANCE_AUDIT_ROADMAP.md` and
> `docs/AUDIT_ENCLAVE_PROPOSAL.md` for the program and enclave design.

---

## 0. Document Control

| Field | Value |
|---|---|
| **Document** | Trust Center — Source of Truth |
| **Owner** | GRC Lead, SecRed Knowledge Inc. dba NouchiX |
| **Classification** | Public (customer-shareable) |
| **Review cadence** | Quarterly, or on any material control change |
| **Version** | 0.1.0 (initial source-of-truth baseline) |
| **Last updated** | 2026-07 |
| **Canonical source** | This file seeds the OSCAL SSP in the audit enclave (`asaf-compliance`); once the enclave's assembled SSP is live, that render is authoritative and this file points to it. |

### Status legend

| Symbol | Meaning |
|---|---|
| ✅ | In place / operational and evidenced |
| 🟡 | In progress |
| 🟦 | Planned with a target date |
| ⬜ | Not started / not applicable |

> **Accuracy & status disclaimer.** This document states NouchiX's **actual, current**
> security and compliance posture. Where a certification or audit is not yet issued,
> it is marked *in progress* or *planned* with a target date — **it is never presented
> as complete**. No badge, logo, or statement in customer-facing material may claim a
> certification until the corresponding report or authorization has been formally
> issued. Statuses below reflect the `COMPLIANCE_AUDIT_ROADMAP.md` Master Timeline and
> MUST be updated as milestones complete. When in doubt, downgrade the claim.

---

## 1. Purpose & Scope

This Trust Center is the single, authoritative summary of how NouchiX secures its
products and data, which frameworks it aligns to, and how customers and auditors can
obtain evidence. It exists because NouchiX sells compliance tooling to DoD
contractors, FedRAMP vendors, and CMMC-seeking enterprises — customers who require
proof that NouchiX holds the posture it helps them achieve.

**In scope:** the KHEPRA Protocol product family (see §3), the infrastructure that
builds and distributes it, and the organizational controls around it.
**Out of scope:** customer-operated deployments (see §15, Shared Responsibility).

---

## 2. Organization & Legal Identity

| Field | Value |
|---|---|
| Operating company | **SecRed Knowledge Inc.** (dba **NouchiX**) |
| Intellectual-property holder | **SOUHIMBOU DOH KONE LLC** (exclusively licensed to SecRed Knowledge Inc.) |
| Core patent | **KHEPRA Protocol — USPTO #73565085** |
| Business classification | SDVOSB (Service-Disabled Veteran-Owned Small Business) <!-- confirm current SAM.gov status --> |
| Primary domain | nouchix.com |
| Product domain | adinkhepra.com |
| Security contact | cybersouhimbou@secredknowledgeinc.tech (PGP: `keys/security_contact.asc`) |
| Business/legal contact | contact@nouchix.com |

---

## 3. Product Portfolio & Deployment Tiers

KHEPRA is delivered in tiers with escalating assurance. The tier a customer runs
determines its cryptographic path and the compliance impact levels it can support.

| Tier | Audience | Crypto path | Network posture |
|---|---|---|---|
| **Community** | Evaluation, OSS, non-commercial | Standard TLS | Standard |
| **Sovereign** | DoD networks, air-gapped / SCIF, contractor systems | ML-DSA-65 offline license validation | **Zero egress** — all ops on operator infrastructure, no external calls |
| **Pharaoh / Iron Bank** | FedRAMP / IL4 / IL5 production | **FIPS 140-3 validated** path | Air-gapped binary, DoD Iron Bank provenance |

Proprietary (Sovereign / Pharaoh) features require a valid license key validated
**offline** via an ML-DSA-65 signed `license.adinkhepra` file. No external validation
endpoint is contacted in Sovereign or Iron Bank modes; absence of a valid key falls
back to Community functionality only.

**Impact-level alignment:**

| Target | Required tier | Crypto |
|---|---|---|
| FedRAMP Low | Community | Standard TLS |
| FedRAMP Moderate | Sovereign or Iron Bank | FIPS 140-3 (Iron Bank) |
| FedRAMP High / IL4–IL5 | Iron Bank | FIPS 140-3 + NSA-approved algorithms, air-gapped |

---

## 4. Compliance & Certification Status

> Honest status as of 2026-07. See §16 for how to request the underlying reports.

| Framework | Status | Detail / target |
|---|---|---|
| **SOC 2 Type II** (Security, Confidentiality) | 🟡 In progress | Audit window opens Q4 2026; report target **Q3 2027** |
| **CMMC Level 1** (FCI, self-attested) | 🟡 In progress | Self-attestation target **Q3 2026** |
| **CMMC Level 2** (CUI, C3PAO) | 🟦 Planned | C3PAO assessment Q2 2027; report **Q3 2027** |
| **FedRAMP Moderate** | 🟦 Planned | ATO target **Q4 2028** (CMMC L2 is a prerequisite) |
| **NIST SP 800-171 Rev 2** | 🟡 In progress | Self-assessment + SPRS score in progress; mapping complete (roadmap §3) |
| **NIST SP 800-53 Rev 5** | 🟡 In progress | Control mapping complete; used as FedRAMP baseline source |
| **PQC-01-STIG-V1R1** (NouchiX internal PQC STIG) | ✅ Defined & self-scanned | Enforced against own infrastructure via `pqc_stig`; CAT I remediation ongoing |
| **FIPS 140-3** | 🟡 Path available | Validated crypto path in Iron Bank tier; module validation status per build |
| **ISO/IEC 27001** | 🟡 Aligned, not certified | `SECURITY.md` controls align to ISO 27001 Annex A; certification not pursued yet |
| **NSM-10 / CNSA 2.0 (PQC mandate)** | ✅ On track | PQC transition posture ahead of 2026 priority / 2030 deadline |

**No certification above is claimed as issued.** Customer-facing badges are gated on
formal issuance (see §0 disclaimer).

---

## 5. Framework Control Mapping

The authoritative cross-framework matrix lives in `COMPLIANCE_AUDIT_ROADMAP.md` §3
and `aws-govcloud/DEPLOYMENT_SECURITY_CHECKLIST.md`. It is additionally published in
**machine-readable OSCAL**:

- **Component definition** — the KHEPRA Tool → Control mapping (roadmap §4) rendered
  as an OSCAL 1.1.2 `component-definition` by `pkg/evidence/oscal.go`. Each of the 14
  KHEPRA tools is a documented component with explicit control-satisfaction claims.
- **Assessment results** — every scan finding rendered as an OSCAL `assessment-results`
  document, mapped to NIST 800-171 / 800-53 control IDs, sealed to the KHEPRA DAG.

These feed the audit enclave (`asaf-compliance`), where `compliance-trestle` assembles
them into the SSP and Security Assessment Report. See `docs/AUDIT_ENCLAVE_PROPOSAL.md`.

---

## 6. Security Architecture

- **Sovereign mode (zero egress).** In Sovereign/Iron Bank tiers, no data leaves the
  operator's infrastructure — a direct compensating control for boundary protection
  and transmission confidentiality (SOC 2 CC6.6/CC6.7, NIST SC-7/SC-8).
- **Immutable DAG attestation.** Every remediation, finding, and evidence bundle is
  chained into a content-addressed, ML-DSA-65-signed causal DAG (`dag_write`),
  providing tamper-evident, sequence-provable audit records (CC7.2/CC7.3, AU-9).
- **Post-quantum by default.** License validation and attestation use ML-DSA-65
  (FIPS 204) signatures; key establishment uses ML-KEM (Kyber). See §7.
- **Agentic / MCP hardening.** MCP attack surface (tool poisoning, `~/.claude.json`
  hijack, prompt injection) is assessed with `owasp_agent_assess` and documented in
  `docs/MCP_SECURITY_RUNBOOK.md`.
- **Secure supply chain.** Signed containers, SBOM generation (`ert_scan`), and
  provenance for Iron Bank images (`docs`/`Dockerfile.ironbank`).

---

## 7. Cryptography & Post-Quantum Posture

| Function | Algorithm | Standard |
|---|---|---|
| Digital signatures (licenses, attestation, DAG) | **ML-DSA-65** (Dilithium) | FIPS 204 |
| Key encapsulation | **ML-KEM** (Kyber) | FIPS 203 |
| Hashing | SHA-256 / SHA3-256 | FIPS 180-4 / 202 |
| Transport | TLS 1.3 minimum | — |
| At rest (Iron Bank) | FIPS 140-3 validated path | FIPS 140-3 |

- **Public root keys** (auditable): `adinkhepra_master_dilithium.pub`,
  `adinkhepra_master_kyber.pub`. Only public keys are ever published or shared with
  auditors; private key material never leaves controlled key custody.
- **Key management.** Full lifecycle (generation via root ceremony, storage,
  rotation, revocation) documented for the master key pairs; verified free of weak
  primitives via `ert_crypto`.
- **Regulatory drivers.** NSM-10 and CNSA 2.0 mandate PQC for National Security
  Systems (priority systems by 2026, all by 2030). KHEPRA's native PQC posture and
  the internal **PQC-01-STIG-V1R1** standard position NouchiX ahead of these
  deadlines and provide quantum-readiness evidence no mainstream GRC framework yet
  covers.

---

## 8. Data Protection & Privacy

| Topic | Position |
|---|---|
| Data minimization | Sovereign/Iron Bank tiers process customer data **only on the operator's own infrastructure**; NouchiX receives none in those modes |
| Data classification | Public / Internal / Confidential / CUI — policy: `SECURITY.md` (expansion tracked in roadmap CC1) |
| Data residency | Operator-controlled in Sovereign/Iron Bank; <!-- confirm hosting region(s) for any managed/Community services --> |
| Encryption in transit | TLS 1.3 minimum |
| Encryption at rest | FIPS 140-3 path (Iron Bank); <!-- confirm at-rest posture for managed services --> |
| Retention | Evidence: SOC 2 → 7 yr, CMMC/FedRAMP → 3 yr (or ATO+3). Customer data: per contract/DPA |
| Privacy regulations | <!-- confirm applicability: GDPR/CCPA/etc. based on customer base --> |
| DPA availability | Available on request (contact@nouchix.com) |

---

## 9. Identity & Access Management

- **MFA** enforced for all production system access (KHEPRA license validation,
  AWS GovCloud, GitHub) — see `aws-govcloud/DEPLOYMENT_SECURITY_CHECKLIST.md`.
- **Least privilege / RBAC** across production systems; separation of duties between
  development, staging, and production.
- **Privileged access** (AWS root, GitHub org admin) restricted to ≤2 named
  individuals with a documented break-glass procedure.
- **Access reviews** conducted quarterly (evidence: `evidence/access_review_*.md`).
- **Credential hygiene** verified continuously via `secret_scan`; license keys are
  injected by environment variable, never logged, never committed.
- **Authentication assurance** — offline ML-DSA-65 license signing provides
  replay-resistant, PQC-grade authentication (maps to IA-2, IA-5, IA.L2-3.5.x).

---

## 10. Vulnerability Management & Secure SDLC

- **Continuous scanning in CI.** Each repo's `.github/workflows/` runs a defense-in-
  depth gate: CodeQL (SAST), Trivy (containers/deps), supply-chain SAST, DAST (ZAP),
  MCP/OWASP agent scan, secret pre-commit scan, and a sovereignty-boundary check.
- **Dependency management** via Dependabot + `vuln_scan` (Go modules, npm, Python).
- **Remediation SLAs.** Critical < 7 days, High < 30 days, Medium < 90 days
  (tracked in `docs/VULN_BASELINE.md`; KPIs in roadmap §13).
- **STIG hardening.** `stig_check` for CAT I/II/III findings; Iron Bank build is
  STIG-hardened (RHEL-09).
- **Evidence.** Findings and remediations are date-stamped, control-mapped, and
  DAG-sealed (see §11).

---

## 11. Continuous Monitoring & Evidence

NouchiX "eats its own dog food": KHEPRA tools run against NouchiX infrastructure and
produce the continuous, tamper-evident evidence trail auditors require.

| Cadence | Tools | Output |
|---|---|---|
| Nightly (CI) | `pqc_stig`, `ert_crypto`, `ert_scan`, `vuln_scan`, `container_scan`, `secret_scan`, `audit_collect`, `drift_detect` → sealed with `dag_write` | `evidence/*_<date>.json` + OSCAL + signed C3PAO ZIP |
| Continuous | `kasa_start` (threat hunting), `owasp_agent_assess` | `evidence/kasa_*.json`, `evidence/agent_assess_*.json` |
| Quarterly | Access review | `evidence/access_review_*.md` |
| Annual | Risk assessment (`threat_model`), IR tabletop, policy sign-off, training | per roadmap §11 |

**Integrity model (three independent controls):** git review trail on the OSCAL
source of truth, WORM S3 Object-Lock on raw blobs, and the ML-DSA-65 DAG on
sequence. Evidence is stored **outside** product source repos in the audit enclave
(`asaf-compliance`) and WORM storage — see `docs/AUDIT_ENCLAVE_PROPOSAL.md`.

---

## 12. Incident Response & Breach Notification

- **IR plan** derived from `docs/MCP_SECURITY_RUNBOOK.md`, exercised via annual
  tabletop during the audit window (evidence: `evidence/tabletop_*.md`).
- **Monitoring & alerting** for unauthorized access, anomalous API calls, and
  container exits.
- **Customer notification** — affected customers notified per contractual terms;
  target notification window <!-- confirm SLA, e.g. 72h --> after confirmed breach.
- **Reporting a security issue** — see §17.

---

## 13. Business Continuity & Availability

- **Distribution resilience.** If GHCR/registry is unavailable, the **sovereign
  binary mode** is the documented fallback (roadmap CC9).
- **Air-gapped operation.** Iron Bank tier runs fully air-gapped, immune to external
  outages by design.
- **Backups / RTO / RPO** — <!-- confirm and document backup strategy, RTO, RPO for managed services -->.
- **BCP/DR document** — maintained by GRC Lead <!-- link when finalized -->.

---

## 14. Subprocessors & Supply Chain

- **SBOM** generated per release via `ert_scan`; component authenticity via signed
  Iron Bank images with digest pinning (SR-3, SR-11).
- **Subprocessor list** (services with potential access to NouchiX data), pending
  confirmation and publication:

  | Subprocessor | Purpose | Data exposure |
  |---|---|---|
  | GitHub | Source control, CI/CD | Source, CI metadata |
  | AWS (GovCloud) | Infrastructure | <!-- confirm --> |
  | Supabase | <!-- confirm role --> | <!-- confirm --> |
  | Vercel | <!-- confirm role --> | <!-- confirm --> |

  <!-- GRC: verify this list against actual vendors before publishing to customers. -->

---

## 15. Shared Responsibility Model

| Domain | NouchiX | Customer / Operator |
|---|---|---|
| Product code security (SDLC, SAST/DAST, SBOM) | ✅ | — |
| Cryptographic algorithm correctness (PQC, FIPS path) | ✅ | — |
| Deployment configuration & hardening | Guidance | ✅ (operator) |
| Host / network / physical security (Sovereign/Iron Bank) | — | ✅ (operator) |
| License key custody | Issuance | ✅ (secure handling) |
| Customer data handling (Sovereign/Iron Bank) | — | ✅ (stays on operator infra) |
| Evidence generation tooling | ✅ | Runs tooling in their environment |

Iron Bank / Sovereign deployments run in the operator's boundary; the operator owns
host, network, and physical controls, while NouchiX owns product and cryptographic
assurance.

---

## 16. Audit Reports & Documentation Requests

Available to customers and prospects under NDA once issued:

| Artifact | Availability |
|---|---|
| SOC 2 Type II report | 🟡 On issuance (target Q3 2027), under NDA |
| CMMC assessment status / SPRS score | 🟡 On request, as milestones complete |
| PQC-01-STIG-V1R1 scan results (own infra) | ✅ Summary on request |
| SBOM | ✅ On request |
| Penetration test summary | 🟡 On request (post-engagement) |
| Architecture diagram (sovereign boundary) | ✅ On request |
| DPA / security questionnaire (CAIQ/SIG) | ✅ On request |

**To request:** email contact@nouchix.com with your company, use case, and the
artifacts needed. Report material (SOC 2, pentest) is released under NDA.

---

## 17. Vulnerability Disclosure & Security Contact

- **Report to:** cybersouhimbou@secredknowledgeinc.tech (encrypt with the PGP key at
  `keys/security_contact.asc`).
- **Acknowledgement:** within **24 hours**.
- **Do not** post vulnerabilities in public issues, and do not include proprietary
  algorithm detail in unencrypted reports.
- **Machine-readable:** a `security.txt` should be published at
  `/.well-known/security.txt` pointing to the address above <!-- add if not present -->.
- **Safe harbor:** good-faith research following this policy will not be pursued
  <!-- confirm exact safe-harbor language with legal -->.

---

## 18. Machine-Readable Artifacts

| Artifact | Location / format |
|---|---|
| OSCAL component-definition (tool → control) | Generated by `pkg/evidence/oscal.go`; assembled in `asaf-compliance` |
| OSCAL assessment-results | Nightly, sealed to DAG; in `asaf-compliance/assessment-results/` |
| OSCAL SSP | `asaf-compliance/system-security-plans/` (trestle-assembled) |
| OSCAL POA&M | `asaf-compliance/plan-of-action-and-milestones/` |
| SBOM | `evidence/sbom_<date>.json` (via `ert_scan`) |
| MCP server card | `.well-known/mcp/server-card.json` |
| security.txt | `/.well-known/security.txt` <!-- publish --> |

---

## 19. Trust Center Governance

- **This file is the content source of truth** for the public Trust Center. It is
  seeded on every product repo so any repo can answer "what is our posture?"
  identically.
- **Convergence:** as the audit enclave matures, `compliance-trestle` assembles the
  authoritative SSP; the public Trust Center renders from `asaf-compliance/trust-center/`.
  At that point this file's status tables are generated from the OSCAL SSP rather than
  hand-edited, and per-repo copies point to the published center to prevent drift.
- **Change control:** updates go through PR review; the GRC Lead approves any change
  to a compliance-status claim. Downgrades (a claim that was too strong) may be made
  immediately.
- **Review cadence:** quarterly, and on any material control or milestone change.

---

## 20. Change Log

| Version | Date | Change |
|---|---|---|
| 0.1.0 | 2026-07 | Initial Trust Center source-of-truth baseline established across all product repos. Honest, roadmap-aligned status. OSCAL feed (`pkg/evidence/oscal.go`) and audit enclave design (`docs/AUDIT_ENCLAVE_PROPOSAL.md`) referenced. |

---

*Related internal documents: `COMPLIANCE_AUDIT_ROADMAP.md` · `docs/AUDIT_ENCLAVE_PROPOSAL.md` · `SECURITY.md` · `docs/PQC-01-STIG-V1R1.md` · `docs/MCP_SECURITY_RUNBOOK.md` · `docs/API_SECURITY.md` · `aws-govcloud/DEPLOYMENT_SECURITY_CHECKLIST.md` · `docs/VULN_BASELINE.md`*

<!--
  TODO markers above (<!-- confirm ... -->) flag fields the GRC Lead must verify with
  real organizational data before any customer-facing publication. Do not publish
  this file externally with unresolved TODOs or unverified subprocessor entries.
-->

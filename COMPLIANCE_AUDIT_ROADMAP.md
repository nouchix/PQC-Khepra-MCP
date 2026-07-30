# NouchiX / KHEPRA — Compliance Audit Roadmap

**Organization**: SecRed Knowledge Inc. dba NouchiX  
**Product**: KHEPRA Protocol (USPTO #73565085)  
**Document owner**: GRC Lead  
**Review cadence**: Quarterly  
**Frameworks in scope**: SOC 2 Type II · CMMC Level 1 · CMMC Level 2 · FedRAMP Moderate  
**Last updated**: 2026-07

---

## Contents

1. [Why This Document Exists](#1-why-this-document-exists)
2. [How to Use This Roadmap](#2-how-to-use-this-roadmap)
3. [Framework Alignment Matrix](#3-framework-alignment-matrix)
4. [KHEPRA Tool → Evidence Mapping](#4-khepra-tool--evidence-mapping)
5. [Phase 0 — Audit Readiness Baseline (Do First)](#5-phase-0--audit-readiness-baseline-do-first)
6. [SOC 2 Type II Roadmap](#6-soc-2-type-ii-roadmap)
7. [CMMC Level 1 Roadmap](#7-cmmc-level-1-roadmap)
8. [CMMC Level 2 Roadmap](#8-cmmc-level-2-roadmap)
9. [FedRAMP Moderate Roadmap](#9-fedramp-moderate-roadmap)
10. [Cross-Framework Deduplication](#10-cross-framework-deduplication)
11. [Evidence Collection Playbook](#11-evidence-collection-playbook)
12. [Auditor Engagement Guide](#12-auditor-engagement-guide)
13. [Post-Audit Actions](#13-post-audit-actions)
14. [Vanta Integration Opportunity](#14-vanta-integration-opportunity)
15. [Master Timeline](#15-master-timeline)
16. [Anatomy of an Audit Report](#16-anatomy-of-an-audit-report)

---

## 1. Why This Document Exists

NouchiX sells compliance tooling to DoD contractors, FedRAMP-authorized vendors, and enterprises pursuing CMMC certification. Our customers need proof that *we* hold the certifications we help *them* achieve. A gap between what KHEPRA promises and NouchiX's own compliance posture is a sales blocker and a trust liability.

Additionally, NSM-10 and CNSA 2.0 mandate PQC transitions for all National Security Systems by 2030, with priority systems requiring action by 2026. KHEPRA's own cryptographic infrastructure — ML-DSA-65 signed licenses, Dilithium/Kyber key pairs (`adinkhepra_master_dilithium.pub`, `adinkhepra_master_kyber.pub`) — must be auditable and demonstrably compliant with our own PQC-01-STIG-V1R1 standard.

**Sequencing recommendation**: SOC 2 Type II → CMMC Level 1 → CMMC Level 2 → FedRAMP Moderate. Each builds on the prior. Do not attempt FedRAMP before CMMC Level 2 controls are mature.

---

## 2. How to Use This Roadmap

### Adapting Vanta's Five Audit Tips to NouchiX

The five principles from the [Vanta Audit Ready Checklist](https://www.vanta.com/resources/the-audit-ready-checklist) translate to NouchiX's context as follows:

| Vanta Tip | NouchiX Application |
|---|---|
| **1. Plan strategically** | Reserve Q4 for SOC 2 audit window close; avoid scheduling during CMMC C3PAO assessment seasons (typically heavy Jan–Mar) |
| **2. Prepare your team** | KHEPRA is a 4–8 person team — every engineer owns at least one control; assign owners in the control tables below |
| **3. Manage your evidence** | Use KHEPRA's own tools (`dag_write`, `audit_collect`, `drift_detect`) to generate continuous, tamper-evident evidence — not point-in-time screenshots |
| **4. Work closely with your auditor** | For CMMC Level 2 you need a C3PAO (not a self-attestation path); engage early, expect 8–16 weeks |
| **5. Take results to the next level** | Publish NouchiX's own Trust Center; use KHEPRA's `pqc_stig` results against our own codebase as proof of quantum-readiness before any external auditor arrives |

### Audit Window vs. Audit Duration

- **Audit window / review period**: The continuous period (minimum 3 months for SOC 2 Type II; 12 months for FedRAMP) during which evidence must show consistent controls. Start the clock when you first implement a control — not when you schedule the auditor.
- **Audit duration**: The 2–6 weeks the auditor is actively inside your systems.
- **Key risk**: Scheduling the auditor before your audit window is long enough. Build at least one full quarter of evidence before inviting a SOC 2 auditor; six months is better.

---

## 3. Framework Alignment Matrix

The source of truth for control cross-references is `aws-govcloud/DEPLOYMENT_SECURITY_CHECKLIST.md`. The matrix below extends it across all four target frameworks.

| Control Domain | NIST 800-171 | CMMC L1 | CMMC L2 | SOC 2 TSC | FedRAMP Mod | PQC-01-STIG-V1R1 |
|---|---|---|---|---|---|---|
| Access Control | 3.1.x | AC.L1-3.1.1/2 | AC.L2-3.1.x | CC6.1, CC6.2 | AC-2,3,6,17 | — |
| Audit & Accountability | 3.3.x | — | AU.L2-3.3.x | CC7.2, CC7.3 | AU-2,3,6,9,12 | PQC-01-000120 |
| Configuration Mgmt | 3.4.x | — | CM.L2-3.4.x | CC6.6, CC7.1 | CM-2,6,7,8 | — |
| Cryptography | 3.13.8/10 | — | SC.L2-3.13.8/10 | CC6.7 | SC-8,12,13,28 | PQC-01-000010–050 |
| PQC Algorithm Selection | — | — | SC.L2-3.13.8 | CC6.7 | SC-13 | PQC-01-000010 |
| PQC Key Strength | — | — | SC.L2-3.13.10 | CC6.7 | SC-12 | PQC-01-000020 |
| PQC Key Storage | — | — | SC.L2-3.13.10 | CC6.7 | SC-28 | PQC-01-000030 |
| Hybrid PQC Transition | — | — | SC.L2-3.13.8 | CC6.7 | SC-8 | PQC-01-000040 |
| Agentic AI / MCP PQC | — | — | SC.L2-3.13.x | CC7.5 | SC-8, SI-7 | PQC-01-A00010–050 |
| Identification & Auth | 3.5.x | IA.L1-3.5.1/2 | IA.L2-3.5.x | CC6.1 | IA-2,5,8 | — |
| Incident Response | 3.6.x | — | IR.L2-3.6.x | CC7.4 | IR-4,6,8 | — |
| Risk Assessment | 3.11.x | — | RA.L2-3.11.x | CC3.2, CC9.2 | RA-3,5 | — |
| System & Comm Protection | 3.13.x | SC.L1-3.13.1/5 | SC.L2-3.13.x | CC6.6, CC6.7 | SC-5,7,8 | PQC-01-000010–120 |
| System & Info Integrity | 3.14.x | SI.L1-3.14.1 | SI.L2-3.14.x | CC7.1–7.3 | SI-2,3,7 | — |
| Supply Chain / SBOM | — | — | SR.L2-3.x | CC9.2 | SA-12, SR-3 | — |

---

## 4. KHEPRA Tool → Evidence Mapping

**Principle**: KHEPRA eats its own dog food. Run these tools against NouchiX's own systems before your auditor runs anything. Evidence generated by `dag_write` is tamper-evident via the immutable DAG causal attestation chain — auditors cannot dispute the timestamp or sequence.

| KHEPRA Tool | What It Produces | Maps To | Audit Artifact |
|---|---|---|---|
| `pqc_stig` | PQC-01-STIG-V1R1 compliance report | CMMC SC.L2, FedRAMP SC-13, SC-8 | `evidence/pqc_stig_YYYYMMDD.json` |
| `ert_crypto` | Weak cryptographic primitive inventory + PQC migration plan | CMMC SC.L2-3.13.8, FedRAMP SC-12 | `evidence/crypto_inventory_YYYYMMDD.json` |
| `ert_scan` | SBOM + CVE scan + remediation roadmap | FedRAMP SA-12, CMMC SR.L2 | `evidence/sbom_YYYYMMDD.json` |
| `ert_readiness` | NIST 800-171 gap analysis | CMMC L2 all domains | `evidence/nist171_gaps_YYYYMMDD.json` |
| `stig_check` | CAT I/II/III findings | FedRAMP CM-6, CMMC CM.L2 | `evidence/stig_findings_YYYYMMDD.json` |
| `vuln_scan` | Dependency CVE report | FedRAMP RA-5, SI-2 | `evidence/vuln_scan_YYYYMMDD.json` |
| `container_scan` | Dockerfile misconfiguration + base image vulns | FedRAMP CM-7, SA-12 | `evidence/container_scan_YYYYMMDD.json` |
| `secret_scan` | Hardcoded credential detection | SOC 2 CC6.1, FedRAMP IA-5 | `evidence/secret_scan_YYYYMMDD.json` |
| `audit_collect` | Process list, system state snapshot | SOC 2 CC7.2, FedRAMP AU-12 | `evidence/audit_collect_YYYYMMDD.json` |
| `threat_model` | STRIDE analysis + MITRE ATT&CK mapping | SOC 2 CC3.2, FedRAMP RA-3 | `evidence/threat_model_YYYYMMDD.json` |
| `owasp_agent_assess` | Agentic AI Top 10 + MCP-specific risks | PQC-01-A00010–050, FedRAMP SI-7 | `evidence/agent_assess_YYYYMMDD.json` |
| `dag_write` | Tamper-evident attestation chain for all remediations | SOC 2 CC7.3, FedRAMP AU-9 | `evidence/dag_attestation_YYYYMMDD.json` |
| `drift_detect` | Configuration drift vs. baseline | SOC 2 CC7.1, FedRAMP CM-8 | `evidence/drift_YYYYMMDD.json` |
| `kasa_start` | Continuous threat hunting / daily pentest output | SOC 2 CC7.2, FedRAMP CA-8 | `evidence/kasa_YYYYMMDD.json` |

**Automation target**: Schedule all of the above to run nightly via CI/CD and push output to a write-protected `evidence/` path. Use `dag_write` as the final step to seal each run with a cryptographic attestation. This creates the continuous monitoring evidence trail auditors require without manual effort.

---

## 5. Phase 0 — Audit Readiness Baseline (Do First)

Before scheduling any external auditor, run this baseline. It takes approximately two weeks and gives you an honest picture of where you stand.

### Week 1 — Self-Assessment

- [ ] Run `ert_readiness` against all production systems → export to `evidence/baseline_nist171.json`
- [ ] Run `pqc_stig` against KHEPRA's own cryptographic infrastructure → verify FIPS 203/204/205 compliance of `adinkhepra_master_dilithium.pub` and `adinkhepra_master_kyber.pub`
- [ ] Run `vuln_scan` + `container_scan` → triage `docs/VULN_BASELINE.md` (current: 4 Critical, 20 High); resolve all Critical before audit window opens
- [ ] Run `secret_scan` → confirm no credentials in source; verify `adinkhepra_master.pub` files are public keys only, not private
- [ ] Review `docs/MCP_SECURITY_RUNBOOK.md` → confirm `~/.claude.json` hijack mitigations are deployed to all developer workstations
- [ ] Review `docs/API_SECURITY.md` and `docs/MCP_SECURITY_RUNBOOK.md` → assign control owners for each finding

### Week 2 — Gap Register

Create `evidence/gap_register.md` with columns: `Control | Gap Description | Owner | Target Close Date | Status`. Populate it from:

- `ert_readiness` output (NIST 800-171 gaps)
- `stig_check` CAT I/II findings
- `aws-govcloud/DEPLOYMENT_SECURITY_CHECKLIST.md` unchecked items
- Manual review of policies listed in Section 6–9 below

**Exit criterion**: Gap register exists, all Critical vulns remediated, all control owners assigned. Only then proceed to scheduling auditors.

---

## 6. SOC 2 Type II Roadmap

### What It Is

SOC 2 Type II evaluates whether NouchiX's controls were **consistently operating** over a defined period (minimum 3 months, typically 6–12). The five Trust Service Criteria (TSC) are: Security (required), Availability, Confidentiality, Processing Integrity, Privacy. For KHEPRA's initial audit, target Security + Confidentiality.

### Why KHEPRA Has a Natural Advantage

- **Sovereign mode** (zero egress) is direct evidence for CC6.7 (transmission encryption) and CC6.6 (boundary protection) — no data leaves the operator's infrastructure
- **ML-DSA-65 signed licenses** → tamper-evident license validation evidence for CC6.1 (logical access)
- **DAG attestation chain** → continuous, cryptographically sequenced audit log satisfying CC7.2 and CC7.3
- **`dag_write`** creates evidence chains auditors cannot dispute

### Control Checklist

#### CC1 — Control Environment
- [ ] Document organizational structure, roles, and responsibilities (assign GRC Lead, Security Lead, Engineering Lead)
- [ ] Maintain and communicate a security policy (exists: `SECURITY.md` — expand to cover employee behavior, acceptable use, data classification)
- [ ] Conduct annual security training with completion tracking
- [ ] Background checks for all personnel with system access

**Owner**: CEO / GRC Lead | **Evidence**: Policy docs, training completion records, HR files

#### CC2 — Communication and Information
- [ ] Maintain an asset inventory (run `ert_scan` SBOM quarterly; store in `evidence/sbom_YYYYMMDD.json`)
- [ ] Communicate security responsibilities to third parties (vendors, contractors) via DPAs and MSAs
- [ ] Maintain a vendor risk register (see CMMC SR.L2 section below — same register serves both)

**Owner**: GRC Lead | **Evidence**: Asset inventory, vendor contracts with security clauses, DPAs

#### CC3 — Risk Assessment
- [ ] Conduct formal annual risk assessment (use `threat_model` output + `ert_readiness` → document in `evidence/risk_assessment_YYYY.md`)
- [ ] Include PQC-specific risk (harvest-now-decrypt-later; CNSA 2.0 deadline) in risk register
- [ ] Evaluate agentic AI / MCP risks (ref: `docs/MCP_SECURITY_RUNBOOK.md`, `owasp_agent_assess` output)

**Owner**: Security Lead | **Evidence**: `evidence/threat_model_YYYYMMDD.json`, risk assessment document

#### CC6 — Logical and Physical Access
- [ ] MFA enforced for all production system access (KHEPRA license validation, AWS GovCloud, GitHub)
- [ ] Access reviews conducted quarterly → document who has access to what and why
- [ ] Privileged access (AWS root, GitHub org admin) restricted to ≤2 named individuals with break-glass procedure
- [ ] Sovereign mode deployment documented as a compensating control for data egress (CC6.6, CC6.7)
- [ ] KHEPRA_LICENSE_KEY handling documented: key injected via environment variable, never logged, never committed (verify with `secret_scan`)

**Owner**: Engineering Lead | **Evidence**: MFA enrollment records, access review logs, `secret_scan` output, architecture diagram showing sovereign mode boundary

#### CC7 — System Operations
- [ ] Monitoring alerts configured for unauthorized access attempts, anomalous API calls, container exits
- [ ] Run `audit_collect` + `dag_write` nightly → tamper-evident log chain
- [ ] Run `drift_detect` weekly → configuration drift alerts
- [ ] Incident response plan documented (adapt `docs/MCP_SECURITY_RUNBOOK.md` IR sequence into a general IR plan)
- [ ] Conduct at least one tabletop IR exercise during the audit window

**Owner**: Security Lead | **Evidence**: Alert configurations, `evidence/dag_attestation_*.json`, `evidence/drift_*.json`, IR plan, tabletop exercise notes

#### CC9 — Risk Mitigation
- [ ] Vendor/third-party risk assessments for all services with access to NouchiX data (GitHub, AWS, Supabase, Vercel — see `supabase/` and `next.config.mjs`)
- [ ] Business continuity plan: document what happens if GHCR goes down (sovereign binary mode fallback)
- [ ] Maintain `docs/VULN_BASELINE.md` as living document; remediate Highs within 30 days, Mediums within 90

**Owner**: GRC Lead | **Evidence**: Vendor risk register, BCP document, `evidence/vuln_scan_*.json`

### SOC 2 Scheduling Notes

| Milestone | Target Timing |
|---|---|
| Phase 0 baseline complete | Month 1 |
| All Critical/High vulns remediated | Month 2 |
| Policies written and communicated | Month 2 |
| Audit window opens (evidence starts accumulating) | Month 3 |
| Readiness assessment (internal or third-party) | Month 5 |
| External auditor engagement begins | Month 6 |
| Audit report issued | Month 8–9 |

---

## 7. CMMC Level 1 Roadmap

### What It Is

CMMC Level 1 covers **Federal Contract Information (FCI)** — 17 practices from FAR clause 52.204-21. It is self-attested annually. If NouchiX has any federal contracts (even commercial items sold to federal agencies), CMMC Level 1 is required.

### 17 Practices Checklist

Each maps to one of six domains:

**Access Control (AC.L1)** — 4 practices
- [ ] **AC.L1-3.1.1** Limit system access to authorized users and devices
- [ ] **AC.L1-3.1.2** Limit system access to transactions authorized users are permitted to execute
- [ ] **AC.L1-3.1.20** Verify and control all connections to external systems
- [ ] **AC.L1-3.1.22** Control information posted or processed on publicly accessible systems

**Identification & Authentication (IA.L1)** — 2 practices
- [ ] **IA.L1-3.5.1** Identify all users, processes, and devices
- [ ] **IA.L1-3.5.2** Authenticate the identities of users, processes, and devices before allowing access

**Media Protection (MP.L1)** — 1 practice
- [ ] **MP.L1-3.8.3** Sanitize or destroy information system media before disposal or reuse

**Physical Protection (PE.L1)** — 4 practices
- [ ] **PE.L1-3.10.1** Limit physical access to systems that process FCI to authorized individuals
- [ ] **PE.L1-3.10.3** Escort visitors and monitor visitor activity
- [ ] **PE.L1-3.10.4** Maintain audit logs of physical access
- [ ] **PE.L1-3.10.5** Control and manage physical access devices (keys, badges)

**System & Communications Protection (SC.L1)** — 2 practices
- [ ] **SC.L1-3.13.1** Monitor, control, and protect communications at external boundaries and key internal boundaries
- [ ] **SC.L1-3.13.5** Implement subnetworks for publicly accessible system components

**System & Information Integrity (SI.L1)** — 4 practices
- [ ] **SI.L1-3.14.1** Identify, report, and correct system flaws in a timely manner (vulnerability management — tie to `vuln_scan` nightly runs)
- [ ] **SI.L1-3.14.2** Provide protection from malicious code (anti-malware on all endpoints)
- [ ] **SI.L1-3.14.4** Update malware protection mechanisms
- [ ] **SI.L1-3.14.5** Perform periodic scans and real-time scans

**Evidence required for self-attestation**: A signed affirmation from an authorized NouchiX official plus documentation that all 17 practices are implemented. Keep this documentation package in `evidence/cmmc_l1_attestation_YYYY/`.

---

## 8. CMMC Level 2 Roadmap

### What It Is

CMMC Level 2 covers **Controlled Unclassified Information (CUI)** — 110 practices across 14 domains, aligned to NIST SP 800-171 Rev 2. **Requires C3PAO (third-party assessor) assessment** — no self-attestation for most contracts. Assessment cycle: every 3 years, with annual affirmations in between.

This is the gating requirement for most DoD DIB contracts above the simplified acquisition threshold. Achieving it positions NouchiX to sell KHEPRA to primes and subs across the DIB.

### Pre-Assessment: NIST 800-171 Self-Assessment Score

Run `ert_readiness` and calculate your SPRS (Supplier Performance Risk System) score before engaging a C3PAO. SPRS score = 110 (perfect) minus deductions for unmet practices. Submit score to SPRS database before contract award.

### Domain-by-Domain Checklist (Key Items)

#### Access Control (AC) — 22 practices
- [ ] Implement role-based access control (RBAC) for all KHEPRA production systems
- [ ] Enforce MFA for all privileged access (already required in `aws-govcloud/DEPLOYMENT_SECURITY_CHECKLIST.md` 1.4)
- [ ] Document and enforce separation of duties between development, staging, and production
- [ ] Control remote access sessions (VPN with MFA; no direct SSH to production)
- [ ] **AC.L2-3.1.14**: Route all remote access through managed access control points

**KHEPRA tool**: `audit_collect` for session evidence | **Evidence**: RBAC policy, MFA enrollment records, VPN logs

#### Audit and Accountability (AU) — 9 practices
- [ ] Audit events must include: login/logout, privilege escalation, policy changes, object access, account creation/deletion
- [ ] Protect audit logs from unauthorized access and modification
- [ ] **`dag_write` is the answer here**: immutable DAG chain satisfies AU.L2-3.3.1 (create and retain audit records) and AU.L2-3.3.2 (ensure audit actions are traceable to individual users)
- [ ] Retain audit logs for minimum 3 years (FedRAMP will require this anyway)

**KHEPRA tool**: `dag_write`, `audit_collect` | **Evidence**: `evidence/dag_attestation_*.json` (must span full 3-year window by FedRAMP stage)

#### Configuration Management (CM) — 9 practices
- [ ] Establish and document a baseline configuration for all KHEPRA Docker images, Dockerfiles, and Go binaries
- [ ] Run `drift_detect` weekly; document any deviations with `dag_write` attestation
- [ ] Control use of removable media (document policy; physically restrict in SCIF deployments)
- [ ] **CM.L2-3.4.6**: Employ the principle of least functionality — remove/disable unnecessary services, ports, protocols from Docker images (fix `hadolint` issues in `Dockerfile` and `Dockerfile.ironbank` as a CM control, not just a CI fix)

**KHEPRA tool**: `drift_detect`, `container_scan`, `stig_check` | **Evidence**: Baseline configuration docs, `evidence/drift_*.json`

#### Identification and Authentication (IA) — 11 practices
- [ ] Enforce minimum password complexity and rotation (90-day rotation already in `aws-govcloud/DEPLOYMENT_SECURITY_CHECKLIST.md` 1.5)
- [ ] Use replay-resistant authentication (MFA satisfies this)
- [ ] **IA.L2-3.5.4**: Employ replay-resistant authentication mechanisms — KHEPRA's ML-DSA-65 license signing directly demonstrates PQC-grade authentication; document this as evidence
- [ ] Disable/delete inactive accounts within 30 days

**KHEPRA tool**: `secret_scan` for credential hygiene | **Evidence**: IAM policies, account review logs, `adinkhepra_master_dilithium.pub` as PQC auth evidence

#### Risk Assessment (RA) — 3 practices
- [ ] Periodically assess risk to operations, assets, and individuals (annual minimum; use `threat_model` output)
- [ ] Scan for vulnerabilities in systems and applications periodically and when new vulnerabilities are identified (`vuln_scan` nightly CI integration satisfies this)
- [ ] Remediate vulnerabilities in accordance with risk assessments (tie `VULN_BASELINE.md` remediation dates to RA findings)

**KHEPRA tool**: `threat_model`, `vuln_scan`, `ert_scan` | **Evidence**: Annual risk assessment doc, `evidence/vuln_scan_*.json` series

#### System and Communications Protection (SC) — 16 practices
- [ ] **SC.L2-3.13.8**: Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission → KHEPRA sovereign mode, TLS 1.3 minimum
- [ ] **SC.L2-3.13.10**: Establish and manage cryptographic keys → document key lifecycle for `adinkhepra_master_dilithium.pub`, `adinkhepra_master_kyber.pub`; run `ert_crypto` to verify no weak primitives
- [ ] **PQC-01-STIG-V1R1 alignment**: Run `pqc_stig` against NouchiX infrastructure; CAT I findings (PQC-01-000010–000050) must be remediated before C3PAO assessment
- [ ] Separate user functionality from system management functionality (no mixing of MCP server functions with admin interfaces)

**KHEPRA tool**: `pqc_stig`, `ert_crypto` | **Evidence**: `evidence/pqc_stig_*.json`, key management policy, `evidence/crypto_inventory_*.json`

#### System and Information Integrity (SI) — 7 practices
- [ ] **SI.L2-3.14.6**: Monitor organizational systems to detect attacks and indicators of compromise → `kasa_start` continuous threat hunting satisfies this
- [ ] **SI.L2-3.14.7**: Identify unauthorized use of organizational systems → `owasp_agent_assess` for MCP/agentic attack surface
- [ ] Update software/firmware within 30 days of vulnerability disclosure; track via `vuln_scan` CI pipeline

**KHEPRA tool**: `kasa_start`, `owasp_agent_assess` | **Evidence**: `evidence/kasa_*.json`, monitoring alert configs

### C3PAO Engagement Notes

- C3PAO assessments take 8–16 weeks and cost $50K–$200K+
- The Cyber AB Marketplace (cyberab.org) is the only authorized source of C3PAOs
- Provide C3PAO with `ert_readiness` output as pre-work — it maps directly to the 110 practices and gives them a starting point
- Do not provide raw credentials, license keys, or private key material — provide the *policy documentation* and *evidence artifacts* only

---

## 9. FedRAMP Moderate Roadmap

### What It Is

FedRAMP Moderate Impact covers systems handling data where the loss of confidentiality, integrity, or availability would have **serious** adverse effects. It requires ~325 security controls from NIST SP 800-53 Rev 5 and an ATO (Authority to Operate) from a federal agency sponsor or through the FedRAMP Marketplace.

FedRAMP is NouchiX's longest-horizon target. Achieving CMMC Level 2 first is strongly recommended — approximately 60% of FedRAMP Moderate controls overlap with NIST 800-171.

### KHEPRA Tier Alignment

| FedRAMP Impact Level | KHEPRA Tier | Cryptographic Path |
|---|---|---|
| FedRAMP Low | Community (Docker) | Standard TLS, no FIPS requirement |
| FedRAMP Moderate | Sovereign or Ironbank | FIPS 140-3 validated path (Ironbank tier required) |
| FedRAMP High / IL4–IL5 | Ironbank (DoD Iron Bank) | FIPS 140-3 + NSA-approved algorithms, air-gapped binary |

For FedRAMP Moderate ATO, KHEPRA must run in **Ironbank mode** — `Dockerfile.ironbank`, deployed from DoD Iron Bank registry, FIPS 140-3 validated crypto path active.

### Key Control Families

#### Access Control (AC)
- **AC-2**: Account Management — implement automated account provisioning/deprovisioning with audit trail (`dag_write`)
- **AC-17**: Remote Access — all remote access via managed VPN with MFA; document in SSP (System Security Plan)
- **AC-20**: Use of External Information Systems — document policy for KHEPRA Community tier users connecting from non-NouchiX systems

#### Audit and Accountability (AU)
- **AU-2, AU-3, AU-6, AU-9, AU-12**: Event logging requirements are substantial
- KHEPRA's `dag_write` immutable attestation chain is a **differentiating control** here — it provides AU-9 (protection of audit information) natively
- Log retention: 3 years minimum for FedRAMP
- **AU-9 enhancement**: DAG chain with ML-DSA-65 signatures satisfies the cryptographic protection of audit records requirement

#### Identification and Authentication (IA)
- **IA-2(1)**: MFA for privileged accounts — already required
- **IA-5(1)**: Authenticator Management (passwords) — enforce minimum complexity, history, expiration
- **IA-8**: Identification and Authentication for Non-Organizational Users — document how KHEPRA authenticates its own license validation (offline ML-DSA-65 — document this explicitly in SSP)

#### System and Communications Protection (SC)
- **SC-8**: Transmission Confidentiality and Integrity — TLS 1.3 minimum; for IL4/IL5, must use NSA-approved PQC algorithms (KHEPRA's native capability)
- **SC-12**: Cryptographic Key Establishment and Management — full key lifecycle document required; use `ert_crypto` output as evidence input
- **SC-13**: Cryptographic Protection — **this is where PQC-01-STIG-V1R1 directly satisfies FedRAMP** — document `pqc_stig` scan results in SSP as evidence of FIPS 203/204/205 compliance
- **SC-28**: Protection of Information at Rest — encryption at rest with FIPS 140-3 validated algorithms (Ironbank mode)

#### Supply Chain Risk Management (SR) — new in 800-53 Rev 5
- **SR-3**: Supply Chain Controls and Plans — SBOM required; run `ert_scan` and store output; submit SBOM to agency sponsor
- **SR-6**: Supplier Assessments and Reviews — assess all dependencies (Go modules in `go.mod`, npm packages in `package.json`, Python dependencies in `adinkhepra.py`)
- **SR-11**: Component Authenticity — signed container images from Iron Bank; document image digest pinning

#### Planning (PL)
- **PL-2**: System Security Plan (SSP) — the SSP is the central FedRAMP document. It must describe every control and how it is implemented. Begin drafting early; it typically runs 200–500 pages
- Start SSP with the alignment matrix in Section 3 of this document; `aws-govcloud/DEPLOYMENT_SECURITY_CHECKLIST.md` maps to many SSP sections already

### FedRAMP Timeline (Realistic)

| Milestone | Estimate |
|---|---|
| SOC 2 Type II complete | Prerequisite |
| CMMC Level 2 complete | Prerequisite |
| SSP draft complete | +6 months after CMMC L2 |
| 3PAO engagement and SAP (Security Assessment Plan) | +8 months |
| Security Assessment Report (SAR) issued | +12 months |
| Plan of Action and Milestones (POA&M) remediation | +14 months |
| ATO issued | +16–24 months |

> **Note**: The fastest path to FedRAMP Moderate is through an agency sponsor willing to co-invest in the ATO. Target agencies whose missions align with PQC (NSA, CISA, DoD components). KHEPRA's PQC-01-STIG-V1R1 work is credentialing that makes NouchiX a natural partner for these agencies.

---

## 10. Cross-Framework Deduplication

Avoid duplicating evidence collection work. Controls that satisfy multiple frameworks simultaneously:

| Control Implementation | SOC 2 | CMMC L1 | CMMC L2 | FedRAMP |
|---|---|---|---|---|
| MFA on all production access | CC6.1 | IA.L1-3.5.2 | IA.L2-3.5.3 | IA-2(1) |
| `vuln_scan` nightly CI | CC7.1 | SI.L1-3.14.1 | RA.L2-3.11.2 | RA-5, SI-2 |
| `dag_write` audit chain | CC7.2 | — | AU.L2-3.3.1 | AU-9, AU-12 |
| `pqc_stig` scan | CC6.7 | — | SC.L2-3.13.8 | SC-13 |
| `drift_detect` weekly | CC7.1 | — | CM.L2-3.4.1 | CM-6, CM-8 |
| `secret_scan` in CI | CC6.1 | IA.L1-3.5.1 | IA.L2-3.5.x | IA-5 |
| Sovereign mode (zero egress) | CC6.6 | SC.L1-3.13.5 | SC.L2-3.13.1 | SC-7 |
| FIPS 140-3 Ironbank crypto | CC6.7 | — | SC.L2-3.13.8 | SC-13, SC-28 |
| Annual risk assessment | CC3.2 | — | RA.L2-3.11.1 | RA-3 |
| Vendor risk register | CC9.2 | — | SR.L2-3.x | SR-6 |
| Incident response plan + tabletop | CC7.4 | — | IR.L2-3.6.1 | IR-4, IR-8 |
| Employee security training | CC1.4 | — | AT.L2-3.2.1 | AT-2, AT-3 |

---

## 11. Evidence Collection Playbook

### Continuous Evidence (Automated — No Manual Work Once Set Up)

Set up the following in CI/CD (`Makefile` or GitHub Actions):

```bash
# Run nightly — output to evidence/ directory with date-stamped filenames
make evidence-collect DATE=$(date +%Y%m%d)
```

Targets to implement in `Makefile`:

```makefile
evidence-collect:
    khepra pqc_stig       > evidence/pqc_stig_$(DATE).json
    khepra ert_crypto     > evidence/crypto_inventory_$(DATE).json
    khepra ert_scan       > evidence/sbom_$(DATE).json
    khepra vuln_scan      > evidence/vuln_scan_$(DATE).json
    khepra container_scan > evidence/container_scan_$(DATE).json
    khepra secret_scan    > evidence/secret_scan_$(DATE).json
    khepra audit_collect  > evidence/audit_collect_$(DATE).json
    khepra drift_detect   > evidence/drift_$(DATE).json
    khepra dag_write attestation evidence/ > evidence/dag_attestation_$(DATE).json
```

The `dag_write` final step seals all evidence artifacts in a tamper-evident attestation — evidence generated this way is court-admissible and auditor-indisputable.

### Point-in-Time Evidence (Manual — Schedule These)

| Evidence Item | Frequency | Who | Where |
|---|---|---|---|
| Access review (who has what access) | Quarterly | Engineering Lead | `evidence/access_review_YYYYQQ.md` |
| Vendor risk assessment | Annual | GRC Lead | `evidence/vendor_risk_YYYY.md` |
| Risk assessment | Annual | Security Lead | `evidence/risk_assessment_YYYY.md` |
| IR tabletop exercise | Annual | All leads | `evidence/tabletop_YYYY.md` |
| Policy review and sign-off | Annual | CEO | `evidence/policy_signoff_YYYY.md` |
| Employee security training completion | Annual | GRC Lead | `evidence/training_completion_YYYY.csv` |
| PQC transition plan update | Annual | Engineering Lead | `evidence/pqc_transition_plan_YYYY.md` |
| SPRS score submission | Before each CMMC contract | GRC Lead | SPRS portal screenshot + `evidence/sprs_YYYY.pdf` |

### Evidence Storage and Integrity

- Store all evidence in a dedicated, access-controlled location (separate S3 bucket with write-once/read-many policy, or equivalent)
- `dag_write` output for each evidence bundle is the cryptographic proof of integrity
- Do NOT store evidence in the same GitHub repo as source code — use a private, restricted repo or an audit-specific S3 bucket with CloudTrail enabled
- Retain evidence for: SOC 2 → 7 years; CMMC → 3 years; FedRAMP → 3 years (or duration of ATO + 3 years)

---

## 12. Auditor Engagement Guide

### SOC 2 — CPA Firm Selection

- Select a CPA firm with SaaS / security software specialization
- Vanta's auditor network is a practical starting point (see [Vanta auditor directory](https://www.vanta.com/partners/find-a-partner?filters=Auditor+Partner))
- Provide auditor with:
  1. The `ert_readiness` gap analysis as pre-work
  2. Architecture diagram showing sovereign mode data boundary
  3. `evidence/` bundle for the prior 3 months minimum
  4. `SECURITY.md`, `docs/MCP_SECURITY_RUNBOOK.md`, and policy documents
- Do NOT provide: private key material (`adinkhepra_master_dilithium.pub` is the public key — confirm only public keys are shared), `KHEPRA_LICENSE_KEY` values, AWS credentials

### CMMC — C3PAO Selection

- Only use C3PAOs listed in the Cyber AB Marketplace (cyberab.org/marketplace)
- Engage 6–8 months before contract award requirement
- Provide C3PAO with:
  1. `ert_readiness` NIST 800-171 self-assessment output
  2. SPRS score and evidence package
  3. System boundary diagram (what systems are in scope for CUI)
  4. `evidence/` bundle
- C3PAO will issue a Final Assessment Report (CMMC Level 2 Assessment Report); NouchiX submits this to CMMC eMASS

### FedRAMP — 3PAO Selection

- Only use 3PAOs listed on the FedRAMP Marketplace (fedramp.gov/marketplace)
- 3PAO engagement requires an agency sponsor or CSP (Cloud Service Provider) pathway first
- Provide 3PAO with: completed SSP draft, `evidence/` bundle, architecture diagrams, `Dockerfile.ironbank` and Iron Bank provenance documentation

### Universal Rules for Auditor Engagement

1. **Assign a single point of contact** for the auditor — one person who can answer questions and marshal evidence within 24 hours
2. **Be transparent** — do not hide findings. Show `VULN_BASELINE.md` with remediation status. Auditors respect documented, managed risk over undiscovered surprises
3. **Let evidence speak** — `dag_write` attestation chains are self-explanatory; do not over-narrate
4. **Do not rotate secrets during an assessment** — this creates noise and looks suspicious. Freeze credential rotation during active assessment periods
5. **Keep a relationship with your auditor** — but rotate auditors every 3 years to avoid independence issues

---

## 13. Post-Audit Actions

### After SOC 2 Report

- [ ] Publish NouchiX Trust Center (Vanta's Trust Center product, or self-hosted equivalent) with SOC 2 report access for customers
- [ ] Update sales collateral: SOC 2 Type II badge, certification date, scope
- [ ] Track all exceptions, OFIs (Opportunities for Improvement), and nonconformities in `evidence/gap_register.md` with remediation owners and dates
- [ ] Begin continuous monitoring: `dag_write` nightly runs keep the evidence chain current for next year's audit
- [ ] Schedule next audit 10 months out (allows time to close gaps before report issuance)

### After CMMC Level 2

- [ ] Submit Final Assessment Report to CMMC eMASS
- [ ] Update SPRS with final score
- [ ] Annual affirmation: CEO/senior official affirms continued compliance each year between 3-year assessments
- [ ] Add CMMC Level 2 certification to DoD supplier representations in SAM.gov

### After FedRAMP ATO

- [ ] List KHEPRA on FedRAMP Marketplace
- [ ] Continuous monitoring: monthly vulnerability scanning, annual penetration test, significant change notifications to agency AO
- [ ] Conops (Continuous Monitoring Strategy) is a living document — update it when architecture changes

### KPIs to Track After Each Audit

| KPI | Target | Measurement |
|---|---|---|
| Mean time to remediate Critical vulns | < 7 days | `VULN_BASELINE.md` delta |
| Mean time to remediate High vulns | < 30 days | `VULN_BASELINE.md` delta |
| `pqc_stig` CAT I findings | 0 | `evidence/pqc_stig_*.json` |
| Phishing drill click rate | < 5% | Security training platform |
| Access review completion | 100% quarterly | `evidence/access_review_*.md` |
| Evidence collection uptime (nightly runs) | > 99% | CI/CD dashboard |
| Open audit findings (exceptions) | 0 unmitigated | `evidence/gap_register.md` |

---

## 14. Vanta Integration Opportunity

### Competitive Position

Vanta's framework list (SOC 2, ISO 27001, GDPR, HIPAA, HITRUST, CMMC, FedRAMP, etc.) covers the GRC automation layer but has **no PQC-specific controls**. Quantum readiness is absent from every framework Vanta supports. This is the gap KHEPRA fills.

### Integration Angle

Vanta announced MCP server support ("Run Compliance from Claude, Cursor, and Codex with Vanta"). This creates a direct integration path:

- **KHEPRA as a Vanta complement**: Vanta automates the 80% of GRC that is policy, access, and vendor management; KHEPRA adds the PQC layer that Vanta cannot provide
- **Integration pattern**: Vanta MCP → Claude → KHEPRA MCP → `pqc_stig` results feed back into Vanta evidence library
- **GTM message for Vanta users**: *"You've automated your SOC 2 and CMMC evidence with Vanta. KHEPRA adds the one layer Vanta can't: quantum-readiness proof that satisfies NSM-10, CNSA 2.0, and PQC-01-STIG-V1R1 before your auditor asks."*

### NouchiX Using Vanta for Internal GRC

Using Vanta to automate NouchiX's own SOC 2 evidence collection (access reviews, vendor management, policy tracking) while using KHEPRA for cryptographic and PQC evidence is the optimal split. This also creates a reference architecture NouchiX can demo to enterprise customers:

```
Vanta (GRC automation)  +  KHEPRA (PQC compliance)
       ↓                          ↓
  Access reviews              pqc_stig scans
  Vendor risk mgmt            ert_crypto audits
  Policy tracking             dag_write attestation
  Training completion         FIPS 203/204/205 evidence
       ↓                          ↓
           Unified audit evidence package
```

---

## 15. Master Timeline

| Quarter | Milestone | Framework |
|---|---|---|
| Q3 2026 | Phase 0 baseline complete; all Critical vulns remediated | All |
| Q3 2026 | Policies written (`SECURITY.md` expanded, IR plan, acceptable use, data classification) | All |
| Q3 2026 | CMMC Level 1 self-attestation submitted | CMMC L1 |
| Q4 2026 | SOC 2 audit window opens (evidence accumulation begins) | SOC 2 |
| Q4 2026 | `ert_readiness` NIST 800-171 self-assessment + SPRS score submitted | CMMC L2 |
| Q1 2027 | SOC 2 readiness assessment (internal tabletop) | SOC 2 |
| Q1 2027 | C3PAO engaged for CMMC Level 2 | CMMC L2 |
| Q2 2027 | SOC 2 external auditor engaged | SOC 2 |
| Q2 2027 | CMMC Level 2 C3PAO assessment | CMMC L2 |
| Q3 2027 | SOC 2 Type II report issued | SOC 2 |
| Q3 2027 | CMMC Level 2 Final Assessment Report submitted to eMASS | CMMC L2 |
| Q4 2027 | SSP draft complete; FedRAMP agency sponsor outreach begins | FedRAMP |
| Q2 2028 | 3PAO engaged; Security Assessment Plan initiated | FedRAMP |
| Q4 2028 | FedRAMP Moderate ATO issued (target) | FedRAMP |

---

## 16. Anatomy of an Audit Report

Understanding the report structure lets NouchiX prepare internal and external stakeholders in advance.

| Section | What It Contains | NouchiX Action |
|---|---|---|
| **Executive Summary** | Purpose, framework, audit period, overall opinion | Share with board and investors; use in Trust Center |
| **Scope** | Systems, services, and boundaries covered | Ensure sovereign mode deployment boundary is clearly defined in advance |
| **Testing Information** | All tests run: policy reviews, artifact evaluations, observations, penetration tests | `dag_write` evidence chain is the artifact trail; `kasa_start` output feeds pentest evidence |
| **Testing Results** | Results of each test; exceptions noted | Exceptions are not failures — they are documented risks; pre-populate `evidence/gap_register.md` so nothing surprises you |
| **Management Responses** | NouchiX's explanation for each exception and remediation plan | Write these in advance for any known gaps; be factual, specific, and include target close dates |
| **Conclusion** | Auditor's opinion (maturity rating, not pass/fail for SOC 2; pass/fail for CMMC/FedRAMP) | Communicate realistic expectations to stakeholders before report issues |

---

*Related internal documents: `SECURITY.md` · `docs/PQC-01-STIG-V1R1.md` · `docs/MCP_SECURITY_RUNBOOK.md` · `docs/API_SECURITY.md` · `aws-govcloud/DEPLOYMENT_SECURITY_CHECKLIST.md` · `docs/VULN_BASELINE.md`*

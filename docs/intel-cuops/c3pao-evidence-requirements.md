# C3PAO Evidence Requirements — CUOPS Intel
# NouchiX / SecRed Knowledge Inc.
# Classification: Product Intelligence — ASAF Roadmap
# Collected: 2026-07-07 | Relevance: AdinKhepra ASAF, PQC-MCP evidence export

---

## Strategic Significance for ASAF

This intel defines exactly what ASAF's C3PAO evidence package must produce to be
accepted — not just generated. The KHEPRA DAG is already positioned as the
technical answer to all five rejection categories below. This is the `Will I pass
my CMMC audit?` question answered with cryptographic certainty.

**Direct product implication:** Every ASAF evidence export must address the
five rejection patterns. The DAG attestation + ML-DSA-65 signatures + Examine/
Interview/Test triad output are ASAF's core differentiation from paper-tiger tools.

---

## C3PAO Assessment Methodology: Examine / Interview / Test

A control is considered **MET** only when ALL THREE methods are consistent:

| Method | What Assessors Look For | ASAF Answer |
|---|---|---|
| **Examine** | Policies, SSP, config screenshots, dated documentation | DAG-attested policy declarations (APDL), OSCAL export |
| **Interview** | Personnel understand and can describe the control | Training records, role assignments in DAG |
| **Test** | Technical verification that the control is enforced | ERT scan output, live STIG check results, PQC validation |

> **Key insight:** A policy document alone = 0/3. ASAF produces Test-layer technical
> evidence that most compliance tools cannot produce. This is the moat.

---

## Evidence Formatting and Organization Requirements

### 1. Centralized Repository
All artifacts in a single, organized location (compliance platform or structured binder).
**ASAF answer:** The immutable DAG is the centralized repository. Every action, finding,
and remediation is stored chain-linked with content-addressed SHA-256 node IDs.

### 2. Traceability Matrix (1-to-1 control to evidence mapping)
Each CMMC practice must link to specific evidence artifacts.
**ASAF answer:** The 36,195-row STIG->CCI->NIST 800-53->NIST 800-171->CMMC cross-reference
database provides automatic traceability for every finding.

### 3. Live vs. Static Evidence
Live dashboards preferred; dated screenshots acceptable if current.
**ASAF answer:** DAG nodes carry ISO 8601 timestamps and are ML-DSA-65 signed,
making them tamper-evident dated evidence that C3PAOs can independently verify.

### 4. Required Artifacts Checklist
```
[ ] System Security Plan (SSP)                  -> ASAF: auto-generated from DAG + APDL
[ ] Configuration screenshots (MFA, firewall)   -> ASAF: ERT Package C (Sonar scan)
[ ] Log review records                          -> ASAF: Flight Recorder NDJSON + DAG
[ ] Access control policies                     -> ASAF: APDL declarations, AC-* controls
[ ] Incident response test results              -> ASAF: SouHimBou SOAR playbook records
[ ] Security Protection Data (SPD)              -> ASAF: DAG export, ERT full report JSON
```

### 5. Security Protection Data (SPD)
Assessors require SPD (logs, config data) — DISTINCT from CUI.
**ASAF answer:** The C3PAO evidence package exports DAG chain + ERT findings as SPD.

---

## The Five Rejection Patterns with ASAF Counterpositions

### Pattern 1: Paper Tiger Failure — Policies Without Proof of Execution
**Rejection triggers:**
- Generic template policies not customized to the environment
- IR plans never exercised (no tabletop exercise records)
- Inconsistency: policy says MFA enforced, test shows bypass

**ASAF counterposition:**
ASAF generates technical execution proof, not policies. The ERT scanner runs against
the actual environment and produces ML-DSA-65 signed findings that are undeniable.
There is no gap between documented intent and operational reality because the DAG
records what was actually executed, not what was intended.

---

### Pattern 2: Scoping and Asset Inventory Errors
**Rejection triggers:**
- Missing cloud instances, remote endpoints, third-party systems handling CUI
- Network diagrams/SSP do not match live environment
- No Shared Responsibility Matrix (SRM) with External Service Providers (ESPs)

**ASAF counterposition:**
Package C (Sonar / Network Intelligence) auto-discovers the live environment via
port scan + banner grabbing + device fingerprinting. The SSP is generated from
what is actually running, not what is documented.

**ROADMAP:** ASAF needs an auto-generated Shared Responsibility Matrix section in
the SSP output listing every identified ESP and marking controls as ASAF-owned vs. ESP-owned.

---

### Pattern 3: Poor Evidence Hygiene and Format
**Rejection triggers:**
- Screenshots without visible timestamps, URLs, or user context
- Data dumps where assessors must hunt for the relevant control mapping
- Stale docs referencing old software versions or departed employees

**ASAF counterposition:**
Every ASAF artifact is:
- Timestamped (ISO 8601, embedded in DAG node)
- Signed (ML-DSA-65 — mathematically impossible to backdate)
- Mapped (36,195-row DB links every finding to its CMMC objective automatically)
- Scoped (targets the actual live environment, not a theoretical boundary)

**KEY DESIGN RULE:** The C3PAO JSON/OSCAL package must include for every finding:
timestamp, system hostname, IP, CMMC control ID, CCI number, NIST 800-171 reference,
and the ML-DSA-65 signature.

---

### Pattern 4: Incomplete Historical Records
**Rejection triggers:**
- Logs only for the week prior to the audit (require 90+ day retention)
- SIEM present but no evidence humans reviewed alerts
- No records of periodic access reviews after role changes or terminations

**ASAF counterposition:**
The DAG is a continuous, immutable audit log from genesis. The Flight Recorder
writes a continuous NDJSON stream. Together they provide the historical record
from first deployment forward.

**ROADMAP:** ASAF needs a historical trend report showing CMMC score over time
(weekly snapshots) to prove continuous monitoring, not just point-in-time.

---

### Pattern 5: Non-POA&M Eligible Gaps
**Rejection triggers:**
- High-impact controls (3 or 5 point weight) cannot be placed on POA&M
- Partially implemented on critical controls = immediate assessment failure
- Common fatal controls: CUI encryption at rest/transit, critical AC enforcement

**ASAF counterposition:**
The Godfather Report categorizes findings by POA&M eligibility. CAT I findings
(FIPS violations, SQL injection, RCE) are flagged NON-POA&M. The staging gate
workflow forces remediation before audit — not a promise on a POA&M.

**KEY DESIGN RULE:** The evidence export must include a POA&M section that explicitly
labels which findings CAN and CANNOT be POA&M'd.

---

## Evidence Rejection Taxonomy (for ASAF Finding Classification)

```
REJECT_REASON_1: PAPER_TIGER      -- policy exists, no technical proof
REJECT_REASON_2: SCOPE_GAP        -- asset not in inventory
REJECT_REASON_3: HYGIENE          -- undated, unmapped, stale artifact
REJECT_REASON_4: HISTORY_GAP      -- insufficient log retention / review records
REJECT_REASON_5: POAM_INELIGIBLE  -- non-POA&M control marked in progress
```

---

## C3PAO Evidence Package — Target Specification for ASAF v1.5

```
khepra-[timestamp]-c3pao-evidence/
├── 00-README.md                    # Package guide + ML-DSA-65 manifest signature
├── 01-SSP.md                       # Auto-generated System Security Plan
├── 02-traceability-matrix.csv      # Control ID -> Finding ID -> DAG Node Hash -> Evidence
├── 03-findings/
│   ├── [control-id]-[sev].json     # One file per finding (timestamped, signed, mapped)
│   └── ...
├── 04-dag-chain.json               # Full immutable DAG export
├── 05-flight-log.ndjson            # Continuous Flight Recorder output (historical record)
├── 06-ert-raw-output.json          # Raw ERT scanner output (SPD for assessors)
├── 07-poam-analysis.md             # POA&M eligibility analysis per finding
├── 08-shared-responsibility.md     # ESP/SRM matrix (auto-generated from Sonar scan)
└── manifest.json                   # ML-DSA-65 signed over SHA3-256(all above files)
```

---

## OSINT Sources

| Source | Content | Relevance |
|---|---|---|
| https://www.reddit.com/r/CMMC/comments/1pofdjr/ | Practitioner evidence examples | Evidence format ground truth |
| https://www.reddit.com/r/CMMC/comments/1jcz9hh/ | Beyond-policy evidence discussion | Paper tiger mitigation |
| https://www.reddit.com/r/CMMC/comments/1j9on2d/ | During-assessment practitioner intel | Real assessor behavior |
| https://cybersecinvestments.com/2025/06/first-time-c3pao-assessment-guide/ | First-time C3PAO guide | Checklist format |
| https://cyberab.org/Portals/0/CMMC Assessment Process v2.0.pdf | Official CMMC Assessment Process v2.0 | PRIMARY SOURCE |
| https://www.govinfo.gov/content/pkg/FR-2024-10-15/pdf/2024-22905.pdf | CMMC Final Rule (FR 2024-10-15) | Regulatory authority |
| https://cyberab.org/Catalog | C3PAO marketplace | Buyer research |

---

## Pitch Implications (Pitch Pulse July 10, 2026)

The five rejection patterns are the investor hook:

> "87% of CMMC assessments fail on their first attempt. The number one reason is
> not that companies are not secure — it is that they cannot prove it. Their evidence
> is undated, unmapped, and contradicted by what assessors actually find in the network.
> ASAF closes this gap: every finding is ML-DSA-65 signed, DAG-attested, and
> automatically mapped to its CMMC control. The C3PAO walks in and the audit is
> already done."

vs. Patero (quantum-safe network encryption):
- Patero encrypts traffic. ASAF proves the posture to an auditor with legal-grade evidence.
- Different layer, different buyer, different outcome.

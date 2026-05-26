# FAIR Methodology Brief — KHEPRA Godfather Report

**Standard:** Open FAIR (Factor Analysis of Information Risk), published by The Open Group as international standard O-RA and O-RT.
**Version:** 1.0 | **Audience:** CFO, CISO, Program Managers, C3PAO Evaluators

---

## Purpose of This Document

The KHEPRA Godfather Report translates raw compliance scan findings — STIG violations, NIST 800-53 control gaps, CMMC practice deficiencies — into dollar-denominated risk exposure and remediation ROI. This document explains the methodology behind those dollar figures so that non-technical stakeholders can evaluate, challenge, and act on the output with confidence.

The goal of the dollar figures is not actuarial precision. It is **priority sequencing**: helping decision-makers allocate remediation budget where it removes the most financial exposure per dollar spent.

---

## What FAIR Is

FAIR (Factor Analysis of Information Risk) is the only international standard quantitative model for cybersecurity and operational risk. It is published by The Open Group under standards O-RA (Risk Analysis) and O-RT (Risk Taxonomy) and maintained by the FAIR Institute.

FAIR replaces qualitative heat maps (red/yellow/green) with a causal model that produces a probability distribution of financial loss. It is used by Fortune 500 CISOs, federal risk officers, and cyber insurers to make risk-adjusted investment decisions.

KHEPRA's Godfather Report applies FAIR at the finding level: each STIG or CMMC violation is assessed individually through the FAIR loss model, producing a per-finding exposure estimate and a portfolio view of total organizational risk.

---

## The FAIR Loss Model

FAIR defines risk as a function of two primary factors:

```
Risk = f(Loss Event Frequency, Loss Magnitude)
```

Both factors decompose further:

```
Loss Event Frequency (LEF)
  ├── Threat Event Frequency (TEF)   — how often a threat actor acts against this asset
  └── Vulnerability (Vuln)           — probability the asset fails to resist given contact

Loss Magnitude (LM)
  ├── Primary Loss                   — direct costs (IR, forensics, notification, fines)
  └── Secondary Loss                 — indirect costs (litigation, reputation, lost contracts)
```

The Godfather Report uses simplified point estimates derived from published baselines (see Sources below) rather than full Monte Carlo simulation. Each estimate is expressed as a range (low / most-likely / high) rather than a single number.

---

## The Calculation Chain — Step by Step

### Step 1: Finding Identification

The `ert_scan` tool identifies a compliance violation and tags it with:

- **Control ID** (e.g., `RHEL-09-212030`)
- **Framework** (STIG / NIST 800-53 / CMMC)
- **CVSS Base Score** (0–10)
- **Asset Class** (see below)
- **Severity** (Low / Medium / High / Critical)

### Step 2: Asset Class Assignment

Each finding is assigned to one of five asset classes based on what the vulnerable component touches:

| Asset Class | Examples | Exposure Multiplier |
|---|---|---|
| **Credential Store** | SSH keys, PAM config, /etc/shadow | 2.5x |
| **Network Perimeter** | Firewall rules, SSH daemon, TLS config | 2.0x |
| **Data at Rest** | Encryption settings, filesystem permissions | 1.8x |
| **Audit / Logging** | Syslog config, auditd rules | 1.3x |
| **Application Config** | Service hardening, process isolation | 1.1x |

The multiplier scales the base exposure estimate upward based on the blast radius of exploitation.

### Step 3: Base Exposure Estimate

The base exposure is drawn from the IBM Cost of a Data Breach Report (current year) for the relevant industry sector. KHEPRA ships with a baseline table covering 17 industry verticals. The base figure represents the average total cost of a breach event for an organization of median size in that sector.

Default (cross-industry average, 2024): **$4.88M per breach event**

Sector-specific defaults shipped with KHEPRA:

| Sector | Avg. Breach Cost |
|---|---|
| Healthcare | $9.77M |
| Financial Services | $6.08M |
| Industrial / Manufacturing | $5.56M |
| Technology | $5.45M |
| Defense / Government | $4.93M |
| Retail | $3.48M |

### Step 4: Threat Event Frequency Adjustment

Not every vulnerability is equally likely to be exploited. TEF is adjusted based on:

- **Exploitability** (CVSS Attack Vector + Attack Complexity + Privileges Required)
- **Exposure** (internet-facing vs. internal vs. air-gapped)
- **Known exploitation** (whether the CVE or STIG finding class has documented active exploitation)

TEF produces a probability multiplier (0.0–1.0) applied to the base exposure:

```
Adjusted Exposure = Base Exposure × Asset Class Multiplier × TEF
```

### Step 5: Vulnerability Factor

Vulnerability (in FAIR terms) is the conditional probability that the asset fails to resist a threat event. For STIG/CMMC findings, this is simplified:

- **Critical** finding: Vuln = 0.85 (the control is effectively absent)
- **High** finding: Vuln = 0.65
- **Medium** finding: Vuln = 0.40
- **Low** finding: Vuln = 0.20

```
Loss Event Probability = TEF × Vulnerability
Expected Annual Loss (EAL) = Adjusted Exposure × Loss Event Probability
```

### Step 6: Remediation Cost Estimate

Remediation cost is calculated as:

```
Remediation Cost = Engineer Hours × Fully-Loaded Hourly Rate
```

Default fully-loaded rate: **$150/hr** (adjustable via `KHEPRA_LABOR_RATE` environment variable)

Hours per finding class are drawn from NIST SP 800-40 remediation complexity classifications and NouchiX field benchmarks:

| Finding Class | Estimated Hours |
|---|---|
| Missing patch / package update | 1–2 hrs |
| Configuration hardening (single file) | 2–4 hrs |
| Crypto algorithm migration | 4–8 hrs |
| Architecture-level control gap | 16–40 hrs |
| Policy / procedural gap | 8–16 hrs |

### Step 7: ROI Calculation

```
ROI = Expected Annual Loss ÷ Remediation Cost
```

A ROI of 3,000x means: for every $1 spent remediating this finding, $3,000 of modeled annual expected loss is removed from the organization's risk portfolio.

**How to present this to a CFO:** The ROI figure is not a financial return in the traditional sense. It is a *risk-adjusted remediation priority score* expressed in a familiar unit. The correct framing is: "Fixing this $800 problem removes $2.4M of expected annual loss from your risk profile. Which item on your CapEx list has a better return than that?"

---

## How to Read the Godfather Report

### Report Columns

| Column | What It Means |
|---|---|
| **Control ID** | STIG rule ID, NIST control, or CMMC practice reference |
| **Framework** | The compliance framework the finding maps to |
| **Severity** | CVSS-derived: Low / Medium / High / Critical |
| **Asset Class** | What the vulnerable component touches (see table above) |
| **Remediation Cost** | Estimated engineer cost to close the gap |
| **Expected Annual Loss** | FAIR-derived dollar exposure this finding contributes annually |
| **ROI** | EAL ÷ Remediation Cost — remediation priority score |
| **CMMC Practice** | If applicable: which CMMC Level 2 practice this satisfies when closed |
| **Evidence Hash** | ML-DSA-65 signature of this finding — tamper-proof, verifiable |

### Report Sections

**Executive Summary:** Total risk portfolio in dollars. Number of critical vs. high vs. medium findings. Estimated total remediation cost to reach baseline hardening. Contract eligibility impact (which CMMC practices remain open).

**Top 10 by ROI:** The ten findings where remediation removes the most dollar exposure per dollar spent. This is the action list for a constrained budget.

**CMMC Gate Analysis:** Which specific CMMC Level 2 practices are currently blocked by open findings. A company cannot self-attest or pass a C3PAO assessment while these remain open. This section translates findings directly into contract eligibility.

**Full Finding Detail:** Every finding with complete FAIR chain, evidence hash, and remediation steps.

---

## The CMMC Gate: Why Dollar Figures Understate the Real Cost

For defense industrial base (DIB) suppliers, CMMC compliance is binary: you either meet the practice requirements or you cannot bid on covered contracts. The Expected Annual Loss figure from FAIR captures breach-related costs but does not capture the cost of *contract exclusion*.

The full financial picture for a DIB supplier:

```
True Cost of Non-Compliance =
  Expected Annual Loss (FAIR)
  + Revenue at Risk (contracts requiring CMMC that cannot be bid)
  + Remediation Cost (the finding itself)
  + C3PAO Assessment Cost ($30K–$100K depending on scope)
  + POA&M carrying cost (time during which the gap remains open)
```

The Godfather Report's CMMC Gate Analysis section explicitly flags which findings block contract eligibility. For a supplier with $2M in annual federal contract revenue, a single blocking CMMC practice gap has a revenue-at-risk figure that dwarfs any FAIR loss estimate. The dollar-denominated FAIR output is the floor, not the ceiling.

---

## Limitations and How to Present Them

### What the FAIR estimates are

- Standardized, reproducible, methodology-backed priority scores
- Based on publicly verifiable industry baseline data
- Useful for comparing remediation priority across findings within the same scan
- Consistent with how cyber insurers and large enterprise risk teams model exposure

### What the FAIR estimates are not

- Actuarial guarantees of loss
- Organization-specific models (unless calibrated with client data)
- Legal representations of breach probability

### The one-sentence answer to "Who validated this?"

> "The methodology is FAIR — an international standard published by The Open Group, used by Fortune 500 CISOs and federal risk officers. The baseline figures come from IBM's annual Cost of a Data Breach Report. We're using a standardized model, not proprietary assumptions."

### When to offer calibration

For enterprise pilots, offer to calibrate two inputs: the fully-loaded labor rate (use the client's actual rate) and the sector baseline (use their specific vertical). This takes 30 minutes and makes the output significantly more defensible in an internal budget conversation.

---

## Cryptographic Verification of Findings

Every finding in the Godfather Report is signed with ML-DSA-65 (NIST FIPS 204, Dilithium3). The Evidence Hash column contains this signature.

This means:

- The report cannot be altered after generation without invalidating the signature
- The signed artifact is verifiable by any party with the public key — no trust in KHEPRA required
- The DAG (directed acyclic graph) anchors all findings into a tamper-evident chain, allowing point-in-time proof that a specific system state was scanned on a specific date

For C3PAO evaluators: the signed DAG export constitutes cryptographically verifiable evidence of scan execution. It satisfies the audit trail requirement without relying on KHEPRA's word that the scan occurred.

---

## Industry Baseline Sources

| Source | Usage in Model |
|---|---|
| IBM Cost of a Data Breach Report (annual) | Sector base exposure estimates |
| Verizon Data Breach Investigations Report (annual) | Threat event frequency by attack vector |
| NIST SP 800-40 | Remediation complexity classification |
| NIST SP 800-30 | Risk assessment methodology alignment |
| The Open Group O-RA / O-RT | FAIR model structure and taxonomy |
| FAIR Institute published research | Vulnerability probability calibration |
| NouchiX field benchmarks | Remediation hours by finding class |

---

## Glossary

| Term | Definition |
|---|---|
| **FAIR** | Factor Analysis of Information Risk — international standard quantitative risk model (The Open Group O-RA/O-RT) |
| **EAL** | Expected Annual Loss — probability-weighted dollar loss expected per year from a given finding |
| **TEF** | Threat Event Frequency — how often a threat actor is expected to act against a vulnerable asset in a given period |
| **Vulnerability** | In FAIR terms: the conditional probability that an asset fails to resist a threat event |
| **Loss Magnitude** | Total dollar cost if a loss event occurs — includes primary (direct) and secondary (indirect) losses |
| **ROI** | Remediation ROI — EAL divided by remediation cost; used for priority sequencing, not financial return |
| **CMMC Gate** | A finding that blocks a CMMC Level 2 practice, rendering the organization ineligible to self-attest or pass C3PAO assessment |
| **Godfather Report** | KHEPRA's executive-ready output: findings expressed as dollar-denominated risk, ranked by remediation ROI |
| **ML-DSA-65** | NIST FIPS 204 post-quantum digital signature algorithm (Dilithium3); used to sign all Godfather Report findings |
| **DAG** | Directed Acyclic Graph — tamper-evident chain anchoring all scan findings to a verifiable point-in-time state |
| **C3PAO** | Certified Third-Party Assessment Organization — the body that assesses CMMC Level 2 compliance |
| **POA&M** | Plan of Action and Milestones — the documented remediation plan required by DoD for open compliance gaps |

---

## Document Verification

This document is part of the KHEPRA compliance evidence package. The methodology described here is implemented in the `godfather_report` MCP tool. For questions about baseline calibration or methodology validation for a specific engagement, contact:

- **Sales / Pilot Engagements:** sales@nouchix.com
- **Technical:** support@nouchix.com
- **Website:** https://nouchix.com

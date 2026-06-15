# MEMORY.md — PQC-Khepra-MCP Project Knowledge Base
> Canonical source of truth for whitepapers, design decisions, and institutional knowledge.
> Last updated: June 2026

---

# PQC-01-STIG-V1R1
## The World's First DoD-Style Post-Quantum Cryptography STIG
### Filling the CNSA 2.0 Compliance Gap

---

| Field | Value |
|-------|-------|
| **Document ID** | PQC-01-STIG-V1R1 |
| **Authors** | NouchiX / SecRed Knowledge Inc. |
| **Version** | 1.1 |
| **Date** | June 2026 |
| **Classification** | UNCLASSIFIED // FOR PUBLIC RELEASE |
| **Contact** | contact@nouchix.com · nouchix.com |
| **Changelog** | v1.1: Added Section 3 (Agentic AI and MCP PQC Controls) reflecting NSA CSI U/OO/6030316-26 (May 2026) and ASD/CISA/NSA joint guidance on agentic AI services (2026) |

---

## Table of Contents

1. [Abstract](#abstract)
2. [The Policy Gap](#1-the-policy-gap)
   - 1.1 Mandates Without Checklists
   - 1.2 The Harvest-Now-Decrypt-Later Threat Is Active Today
   - 1.3 The Emerging Agentic AI Attack Surface
   - 1.4 What a PQC STIG Needs to Address
3. [PQC-01-STIG-V1R1: Twelve Core Controls](#2-pqc-01-stig-v1r1-twelve-core-controls)
   - CAT I Controls (High): PQC-01-000010 through PQC-01-000050
   - CAT II Controls (Medium): PQC-01-000060 through PQC-01-000100
   - CAT III Controls (Low): PQC-01-000110 through PQC-01-000120
4. [Agentic AI and MCP PQC Controls (NEW in v1.1)](#3-agentic-ai-and-mcp-pqc-controls)
   - 3.1 Why Agentic AI Requires PQC-Specific Controls
   - 3.2 MCP-Specific PQC Controls: PQC-01-A00010 through PQC-01-A00050
5. [Compliance Assessment Methodology](#4-compliance-assessment-methodology)
6. [KHEPRA MCP Server: Reference Implementation](#5-khepra-mcp-server-reference-implementation)
7. [Conclusion and Next Steps](#6-conclusion-and-next-steps)
8. [References](#references)

---

## Abstract

The Defense Information Systems Agency (DISA) has published Security Technical Implementation Guides (STIGs) for hundreds of technologies — operating systems, databases, web servers, containers — but as of June 2026, no STIG addresses post-quantum cryptographic (PQC) controls. A parallel gap exists for agentic AI systems and the Model Context Protocol (MCP), which the NSA identified in May 2026 as carrying significant, largely unaddressed security risks.

These gaps are consequential and compounding. The NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) mandates PQC transitions across all National Security Systems and Defense Industrial Base (DIB) contractors by 2030, with priority systems required by 2026. NIST finalized FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) in August 2024. Meanwhile, MCP — now the de facto standard for AI agent orchestration — was released with what the NSA characterized as a "flexible and underspecified design" that reverses familiar trust patterns and creates attack paths that are "largely not well-traced." Agentic AI systems, according to joint guidance from ASD, CISA, NSA, NCSC-UK, NCSC-NZ, and the Canadian Cyber Centre (2026), introduce "privilege risks, structural risks, and accountability risks" that existing frameworks do not adequately address.

This paper introduces **PQC-01-STIG-V1R1**, now updated to version 1.1, which covers two previously unaddressed domains:

**Section 2** presents the original 12 core controls governing PQC algorithm selection, key strength, key storage, hybrid transition, certificate validation, cryptographic inventory, testing, and audit logging — mapped to CCI identifiers, NIST 800-53 Rev 5 controls, and CNSA 2.0 requirements.

**Section 3** (new in v1.1) presents 5 supplementary controls governing PQC requirements specifically for agentic AI systems and MCP deployments — covering agent identity attestation, MCP message signing, agentic audit trail integrity, tool execution cryptographic authorization, and Flight Recorder requirements for AI agent actions.

Together, these 17 controls provide the first unified PQC compliance checklist spanning both classical cryptographic infrastructure and the emerging agentic AI attack surface.

The reference implementation described in Section 5 is built on the **KHEPRA Protocol** (USPTO #73565085, patent pending) — an Adinkra symbol-based cryptographic attestation framework developed by NouchiX / SecRed Knowledge Inc. that provides the patent-pending combination of symbol-bound PQC key derivation, immutable DAG causal attestation chains, and ASAF (Agentic Security Attestation Framework) primitives that underlie several controls in this document, particularly PQC-01-A00010 and PQC-01-A00030.

---

## 1. The Policy Gap

### 1.1 Mandates Without Checklists

NSM-10 (May 2022) directed all federal agencies to inventory cryptographic systems vulnerable to quantum attack and begin migration planning. OMB M-23-02 (January 2023) added reporting requirements. The CNSA 2.0 advisory (September 2022) set hard timelines:

| System Type | CNSA 2.0 Support Required | Full Transition |
|-------------|--------------------------|-----------------|
| NSS software and firmware | 2025 | 2030 |
| NSS hardware | 2026 | 2030 |
| Legacy NSS systems | Case-by-case | 2033 |

NIST's algorithmic work is complete:

| Standard | Algorithm | Cryptographic Basis | Finalized |
|----------|-----------|---------------------|-----------|
| FIPS 203 | ML-KEM (Kyber) | Lattice / Module-LWE | August 13, 2024 |
| FIPS 204 | ML-DSA (Dilithium) | Lattice / Module-LWE | August 13, 2024 |
| FIPS 205 | SLH-DSA (SPHINCS+) | Hash-based stateless | August 13, 2024 |

The organizational mechanism that translates policy requirements into testable technical controls — the STIG — is missing for PQC entirely.

### 1.2 The Harvest-Now-Decrypt-Later Threat Is Active Today

The compliance gap is not theoretical. Adversaries capable of eventually fielding cryptographically-relevant quantum computers are actively collecting encrypted data today for future decryption. Intelligence community and open-source reporting corroborate this as a current, active collection threat against NSS communications, CUI, and controlled technical data.

Data encrypted today with RSA-2048 or ECDSA P-256 may be decryptable within the decade. DIB contractors transmitting ITAR-controlled technical data or sharing CUI under acquisition programs generate this exposure daily. The cost of non-migration is not a future cost — it is a present liability.

### 1.3 The Emerging Agentic AI Attack Surface

A new dimension of PQC risk has emerged that the original CNSA 2.0 guidance did not anticipate: the deployment of agentic AI systems in NSS and DIB environments.

The NSA's May 2026 Cybersecurity Information Sheet on Model Context Protocol (U/OO/6030316-26) identified MCP as having security posture that is "highly dependent on implementation discipline rather than protocol guarantees." Specifically, the NSA found that MCP lacks mandatory authentication, has no defined role-based access control at the protocol level, relies on optional OAuth-style bearer tokens without lifecycle management, and produces inconsistent audit logs that vary by implementation.

Joint guidance from ASD, CISA, NSA, NCSC-UK, NCSC-NZ, and the Canadian Cyber Centre categorizes agentic AI risks into five domains — privilege risks, design and configuration risks, behaviour risks, structural risks, and accountability risks — all of which have PQC-specific dimensions the guidance does not address. Specifically:

- **Identity spoofing and agent impersonation** require cryptographic agent identity; the guidance recommends this but does not specify PQC requirements
- **Accountability risks** require tamper-evident audit logs; the guidance does not specify the cryptographic standard for that tamper-evidence
- **Structural risks** from inter-agent communication require authenticated channels; the guidance does not address quantum-safe authentication

These gaps create a specific PQC exposure: agentic AI systems in NSS contexts may meet behavioral security recommendations while remaining cryptographically vulnerable to harvest-now-decrypt-later attacks on their inter-agent communications and audit records.

A further gap exists at the *explainability* layer. Neither the NSA MCP advisory nor the joint agentic AI guidance addresses the question of what a PQC-signed audit record should *say* about why an agent took an action — only that the record should exist and be tamper-evident. This creates accountability gap: an audit record that proves *what* happened but cannot prove *why* is incomplete for RMF authorization packages and CMMC evidence submissions. The **KHEPRA Protocol** (USPTO #73565085, patent pending) addresses this gap by cryptographically binding Adinkra symbolic descriptors to lattice key parameters — each symbol encodes a compliance domain (e.g., Eban → DoD RMF / STIG; Fawohodie → CMMC / revocation), so that a KHEPRA-signed record carries not only tamper-evidence but verifiable semantic intent. This is the technical foundation for PQC-01-A00030's requirement that audit records include "causal chain fields" — KHEPRA Protocol provides the only patent-pending mechanism for cryptographically anchoring those fields.

### 1.4 What a PQC STIG Needs to Address

A DoD-style PQC STIG must provide auditable answers to eight operational questions — six for traditional cryptographic infrastructure, two newly required for agentic AI:

| # | Question | Scope |
|---|----------|-------|
| 1 | What algorithms are approved? | CNSA 2.0 algorithm catalog |
| 2 | What key sizes and parameter sets are required? | ML-DSA-65, ML-KEM-768 minimum |
| 3 | How must keys be stored and protected? | HSM requirements, key lifecycle |
| 4 | How must hybrid cryptography be implemented during transition? | Classical + PQC simultaneously |
| 5 | What implementation pitfalls create vulnerabilities? | Timing side-channels, non-constant-time ops |
| 6 | How must certificates and chains be validated in a PQC world? | Hybrid PKI, algorithm agility |
| 7 | How must AI agent identity be cryptographically anchored? | PQC agent certificates, attestation |
| 8 | How must agentic AI audit trails be cryptographically protected? | Tamper-evident Flight Recorder standards |

PQC-01-STIG-V1R1 addresses all eight.

---

## 2. PQC-01-STIG-V1R1: Twelve Core Controls

### Control Format

Each control follows DISA STIG structure and conventions:

| Field | Description |
|-------|-------------|
| **Finding ID** | PQC-01-XXXXXX namespace |
| **Severity** | CAT I (High) · CAT II (Medium) · CAT III (Low) |
| **NIST 800-53** | Mapped Rev 5 control family |
| **CCI** | Control Correlation Identifier |
| **Check** | How to audit the control — specific, testable criteria |
| **PASS** | Explicit pass condition |
| **Fix** | Remediation action |

---

### CAT I — HIGH SEVERITY

---

### PQC-01-000010 — CNSA 2.0 Algorithm Approval

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding:** The system uses cryptographic algorithms not approved under CNSA 2.0 in a National Security System context.

**Check:** Verify that all cryptographic operations conform to the following requirements:

| Operation | Required Algorithm | Prohibited Algorithms |
|-----------|------------------|-----------------------|
| Symmetric encryption | AES-256 | AES-128, 3DES, RC4 |
| Digital signatures | ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) | RSA, ECDSA, Ed25519 |
| Key encapsulation | ML-KEM (FIPS 203) | ECDH, X25519, DH, RSA-OAEP |
| Hashing | SHA-384 or SHA-512 | SHA-1, MD5, SHA-256 |

**PASS:** All production cryptographic operations use algorithms from the Required column. Configuration files, TLS negotiation lists, and IKE proposals contain no entries from the Prohibited column.

**FAIL:** Any prohibited algorithm appears in a production NSS context.

**Fix:** Replace all non-approved algorithms. Disable any TLS, IKE, or application-layer configurations that allow downgrade to prohibited cipher suites.

---

### PQC-01-000020 — ML-DSA Minimum Key Strength

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding:** The system implements ML-DSA below the ML-DSA-65 (NIST Security Level 3) parameter set.

| Parameter Set | Security Level | Public Key | Signature Size | NSS Approved |
|---------------|---------------|------------|----------------|--------------|
| ML-DSA-44 | NIST Level 2 | 1,312 bytes | 2,420 bytes | **No** |
| ML-DSA-65 | NIST Level 3 | 1,952 bytes | 3,309 bytes | Yes |
| ML-DSA-87 | NIST Level 5 | 2,592 bytes | 4,627 bytes | Yes |

**PASS:** All public keys are 1,952 bytes (ML-DSA-65) or 2,592 bytes (ML-DSA-87).

**Fix:** Upgrade to ML-DSA-65 at minimum. Reissue all key material and certificates at the correct parameter set.

---

### PQC-01-000030 — ML-KEM Minimum Encapsulation Strength

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

| Parameter Set | Security Level | Public Key | Ciphertext | NSS Approved |
|---------------|---------------|------------|------------|--------------|
| ML-KEM-512 | NIST Level 1 | 800 bytes | 768 bytes | **No** |
| ML-KEM-768 | NIST Level 3 | 1,184 bytes | 1,088 bytes | Yes |
| ML-KEM-1024 | NIST Level 5 | 1,568 bytes | 1,568 bytes | Yes |

**PASS:** Observed ciphertext sizes are 1,088 bytes (ML-KEM-768) or 1,568 bytes (ML-KEM-1024).

**Fix:** Migrate to ML-KEM-768 at minimum.

---

### PQC-01-000040 — Non-Constant-Time Implementation Detection

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

Approved constant-time libraries: **liboqs**, **Cloudflare CIRCL**, **BoringSSL / AWS-LC** (FIPS-mode).

**FAIL:** System uses a home-grown PQC implementation or a library without documented constant-time guarantees.

---

### PQC-01-000050 — Deprecated or Broken PQC Algorithm Detection

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

| Algorithm | Status | Reason |
|-----------|--------|--------|
| SIKE / SIDH | **Broken** | Castryck-Decru 2022 |
| Rainbow | **Broken** | Beullens 2022 |
| GeMSS | Not selected | NIST Round 3 alternate |
| NTRU Prime | Not selected | Not in final standardization |

**Fix:** Remove immediately. Replace with ML-KEM (FIPS 203) and ML-DSA (FIPS 204).

---

### CAT II — MEDIUM SEVERITY

---

### PQC-01-000060 — Hybrid Cryptography During Transition

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SC-8 |
| **CCI** | CCI-002418 |

For systems in active transition (2025–2030), implement hybrid key exchange:

| Classical | PQC | Hybrid |
|-----------|-----|--------|
| X25519 | ML-KEM-768 | X25519+ML-KEM-768 (IETF) |
| P-384 ECDH | ML-KEM-1024 | P-384+ML-KEM-1024 |

---

### PQC-01-000070 — PQC Key Material Storage

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SC-12 |
| **CCI** | CCI-000162 |

- HSM available: FIPS 140-3 Level 3 or higher
- No HSM: AES-256-GCM encrypted, KEK stored separately
- File permissions: 600 or stricter

---

### PQC-01-000080 — PQC Certificate Chain Validation

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SC-17 |
| **CCI** | CCI-002460 |

ML-DSA OIDs:
- ML-DSA-44: `2.16.840.1.101.3.4.3.17`
- ML-DSA-65: `2.16.840.1.101.3.4.3.18`
- ML-DSA-87: `2.16.840.1.101.3.4.3.19`

---

### PQC-01-000090 — Cryptographic Asset Inventory (CBOM)

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | PL-8 |
| **CCI** | CCI-000069 |

Required CBOM fields: libraries, certificates, symmetric keys, quantum-vulnerability classification (VULNERABLE / TRANSITIONAL / QUANTUM-SAFE), last-updated within 90 days. Format: CycloneDX 1.5 or SPDX 2.3.

---

### PQC-01-000100 — PQC Implementation Testing in Staging

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SA-11 |
| **CCI** | CCI-002824 |

Requires NIST Known-Answer Tests (KATs) for ML-KEM and ML-DSA before production deployment.

---

### CAT III — LOW SEVERITY

---

### PQC-01-000110 — PQC Cryptographic Event Audit Logging

| Field | Value |
|-------|-------|
| **Severity** | CAT III — Low |
| **NIST 800-53** | AU-2 |
| **CCI** | CCI-000169 |

Log entries must include: timestamp, subject identity, operation type, algorithm identifier, success/failure status. Written to a tamper-evident log store.

---

### PQC-01-000120 — PQC Migration Rollback Documentation

| Field | Value |
|-------|-------|
| **Severity** | CAT III — Low |
| **NIST 800-53** | CP-9 |
| **CCI** | CCI-000519 |

Rollback procedures must be documented and exercised in non-production within the past 12 months.

---

## 3. Agentic AI and MCP PQC Controls

### 3.1 Why Agentic AI Requires PQC-Specific Controls

The NSA's May 2026 CSI on MCP (U/OO/6030316-26) identified three PQC exposure gaps:

1. **The accountability gap** — audit records signed with ECDSA are vulnerable to retroactive forgery post-quantum
2. **The identity gap** — agent identity keys signed with classical algorithms are harvest-now-decrypt-later targets
3. **The MCP message signing gap** — MCP relies on TLS but "the protocol itself cannot enforce or verify encryption"

---

### CAT I — HIGH SEVERITY (Agentic AI)

---

### PQC-01-A00010 — AI Agent Identity Cryptographic Anchoring

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | IA-3 |
| **CCI** | CCI-001958 |
| **Related Guidance** | NSA U/OO/6030316-26; ASD/CISA Joint Guidance §Identity management |

**Check:**
1. Agent identity certificate signed with ML-DSA-65 or ML-DSA-87 (FIPS 204)
2. Key stored in FIPS 140-3 Level 3 HSM or equivalent
3. Inter-agent authentication uses mutual TLS with ML-DSA certificates
4. Certificate expiration ≤ 365 days

**FAIL:** Any agent identity certificate uses RSA, ECDSA, or Ed25519.

---

### PQC-01-A00020 — MCP Message Integrity Signing

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-8 |
| **CCI** | CCI-002418 |
| **Related Guidance** | NSA U/OO/6030316-26 §Sign and verify MCP messages |

**Check:**
1. `signature` field present in MCP JSON payloads
2. Algorithm: ML-DSA-65 (FIPS 204) or stronger
3. `expires_at` timestamp ≤ 5 minutes from `issued_at`
4. `nonce` / `message_id` enabling replay detection
5. Receiving side verifies and rejects expired/replayed nonces

---

### CAT II — MEDIUM SEVERITY (Agentic AI)

---

### PQC-01-A00030 — Agentic AI Audit Trail Cryptographic Integrity

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | AU-9 |
| **CCI** | CCI-001350 |
| **Related Guidance** | ASD/CISA Joint Guidance §Accountability risks; NSA U/OO/6030316-26 §Instrument for logging |

**Check:**
1. Each agent action produces a structured log entry
2. Entries signed with ML-DSA-65 (FIPS 204)
3. Fields: agent identity, action type, tool name, input parameters, output summary, timestamp, parent action ID
4. Log store is append-only (no delete/update by agent runtime)
5. Content hashes use SHA-384 or SHA-512

The **KHEPRA Protocol** (USPTO #73565085) provides the only patent-pending mechanism for cryptographically anchoring causal chain fields via DAG-based attestation.

---

### PQC-01-A00040 — Tool Execution Cryptographic Authorization

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | AC-3 |
| **CCI** | CCI-000213 |
| **Related Guidance** | NSA U/OO/6030316-26 §Constrain and sandbox; ASD/CISA Joint Guidance §Privilege risks |

**Check:**
1. Tool invocation requires ML-DSA-65-signed authorization token
2. Token scoped to: specific agent identity + specific tool name + parameter constraints + expiration ≤ 15 minutes
3. Tool validates token before execution
4. Authorization service logs each issuance with ML-DSA-65-signed record

---

### PQC-01-A00050 — MCP Server Cryptographic Identity Verification

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | IA-9 |
| **CCI** | CCI-001967 |
| **Related Guidance** | NSA U/OO/6030316-26 §Choose supported MCP projects; §Design for boundaries |

**Check:**
1. MCP server presents ML-DSA-65 certificate
2. Agent client validates against ISSO-maintained trusted registry before session establishment
3. Registry reviewed monthly for unauthorized additions
4. Client rejects connections to unregistered servers
5. Certificate includes approved tool name list as extension (capability changes require reissuance)

**Context:** NSA documented real-world "rug pull" attacks where MCP servers switched from benign to malicious descriptions after installation (WhatsApp MCP exploitation case).

---

## 4. Compliance Assessment Methodology

### Self-Assessment Sequence

1. **Cryptographic Asset Inventory** — produce CBOM (PQC-01-000090)
2. **Agentic AI System Inventory** — document agent runtimes, MCP servers, tools, audit mechanisms
3. **Algorithm Classification** — classify each asset against CNSA 2.0
4. **Control-by-Control Assessment** — PASS / FAIL / NOT APPLICABLE with evidence
5. **Prioritized Remediation** — CAT I first; PQC-01-A00010 and PQC-01-A00020 highest priority for agentic systems

### Evidence Package for C3PAO Assessments

| Evidence Item | Related Controls |
|--------------|-----------------|
| CBOM (CycloneDX 1.5 or SPDX 2.3) | PQC-01-000090 |
| Library constant-time attestation | PQC-01-000040 |
| HSM configuration records | PQC-01-000070 |
| Staging KAT test results | PQC-01-000100 |
| Rollback procedure + test evidence | PQC-01-000120 |
| AI agent identity certificate inventory | PQC-01-A00010 |
| MCP server trusted registry (ISSO-certified) | PQC-01-A00050 |
| Sample signed MCP message + verification | PQC-01-A00020 |
| Flight Recorder sample + ML-DSA-65 verification | PQC-01-A00030 |
| Tool authorization token lifecycle docs | PQC-01-A00040 |

---

## 5. KHEPRA MCP Server: Reference Implementation

### The Patent-Pending Foundation (USPTO #73565085)

Three inventions within KHEPRA Protocol directly underlie this STIG:

**1. Symbol-Bound PQC Key Derivation (ASAF cryptographic primitives)**
ML-DSA and ML-KEM seeded with Adinkra symbolic descriptors via D₈ group transformations:
- Eban → DoD RMF / STIG compliance domain
- Fawohodie → CMMC / revocation management
- Nkyinkyim → FedRAMP / GDPR
- Dwennimmen → PCI DSS / HIPAA

**2. Immutable DAG Causal Attestation Chain**
Every agent action is a content-addressed node in a directed acyclic graph, ML-DSA-65 signed with the preceding node's hash. Proves not just *what* happened but *why* — satisfying PQC-01-A00030's parent action ID requirement.

**3. ASAF Trust Score Binding**
Cryptographically binds a trust score (0–100) and compliance tag to each signed agent action. Authorization records state: "Agent X was permitted to invoke Tool Y with trust score 87 under CMMC AC.3.018 (Eban)."

### Production Container

```
ghcr.io/nouchix/pqc-khepra-mcp:1.0.0
```

MCP Tools exposed:
- `ert_scan` — Enterprise Risk & Threat scan (STIG/CMMC/NIST 800-171)
- `stig_check` — RHEL-09-STIG control validation
- `nist_map` — CCI → NIST 800-53 Rev 5 mapping (36,195 cross-framework entries)
- `cmmc_assess` — CMMC Level 1/2/3 maturity scoring
- `godfather_report` — Executive dollar-denominated cyber risk report
- `attest_export` — ML-DSA-65 / FIPS 204 PQC attestation package for C3PAO intake
- `agent_record` — SouHimBou AI Flight Recorder integration

### Deployment Modes

| Mode | Description | License |
|------|-------------|---------|
| `community` | Open source, no license key | Free |
| `sovereign` | Air-gapped, full STIG controls | Paid |
| `ironbank` | FedRAMP / Iron Bank certified | Paid |

Environment variables: `KHEPRA_MODE`, `KHEPRA_LICENSE_KEY`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`

---

## 6. Conclusion and Next Steps

PQC-01-STIG-V1R1 v1.1 provides 17 controls spanning:
- Classical PQC infrastructure (12 controls, CAT I–III)
- Agentic AI and MCP-specific PQC requirements (5 controls, CAT I–II)

**The convergence point:** As AI agents become primary actors in NSS environments, their cryptographic identity, their inter-agent communications, and their audit trails must all be quantum-resistant. Classical security frameworks address behavior; PQC-01-STIG-V1R1 addresses the cryptographic substrate beneath that behavior.

**Next actions for DIB organizations:**
1. Generate CBOM using KHEPRA ASAF or equivalent
2. Assess against PQC-01-000010 (algorithm inventory) first
3. For agentic AI deployments, assess PQC-01-A00010 and PQC-01-A00020 as immediate priorities
4. Deploy KHEPRA MCP Server as reference implementation for C3PAO evidence generation

---

## References

- NSA CNSA 2.0 Advisory, September 2022
- NSM-10, May 2022
- OMB M-23-02, January 2023
- NIST FIPS 203 (ML-KEM), August 13, 2024
- NIST FIPS 204 (ML-DSA), August 13, 2024
- NIST FIPS 205 (SLH-DSA), August 13, 2024
- NSA CSI U/OO/6030316-26, "Guidance on Model Context Protocol Security," May 2026
- ASD/CISA/NSA/NCSC-UK/NCSC-NZ/Canadian Cyber Centre Joint Guidance on Agentic AI, 2026
- KHEPRA Protocol, USPTO Application #73565085 (pending)
- DISA STIG Development Guide, current edition
- IETF Hybrid Key Exchange drafts (X25519+ML-KEM-768)

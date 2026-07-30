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

A further gap exists at the *explainability* layer. Neither the NSA MCP advisory nor the joint agentic AI guidance addresses the question of what a PQC-signed audit record should *say* about why an agent took an action — only that the record should exist and be tamper-evident. This creates an accountability gap: an audit record that proves *what* happened but cannot prove *why* is incomplete for RMF authorization packages and CMMC evidence submissions. The **KHEPRA Protocol** (USPTO #73565085, patent pending) addresses this gap by cryptographically binding Adinkra symbolic descriptors to lattice key parameters — each symbol encodes a compliance domain (e.g., Eban → DoD RMF / STIG; Fawohodie → CMMC / revocation), so that a KHEPRA-signed record carries not only tamper-evidence but verifiable semantic intent. This is the technical foundation for PQC-01-A00030's requirement that audit records include "causal chain fields" — KHEPRA Protocol provides the only patent-pending mechanism for cryptographically anchoring those fields.

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

**Finding**

The system uses cryptographic algorithms not approved under CNSA 2.0 in a National Security System context.

**Check**

Verify that all cryptographic operations conform to the following requirements:

| Operation | Required Algorithm | Prohibited Algorithms |
|-----------|------------------|-----------------------|
| Symmetric encryption | AES-256 | AES-128, 3DES, RC4 |
| Digital signatures | ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) | RSA, ECDSA, Ed25519 |
| Key encapsulation | ML-KEM (FIPS 203) | ECDH, X25519, DH, RSA-OAEP |
| Hashing | SHA-384 or SHA-512 | SHA-1, MD5, SHA-256 |

**PASS:** All production cryptographic operations use algorithms from the Required column. Configuration files, TLS negotiation lists, and IKE proposals contain no entries from the Prohibited column.

**FAIL:** Any prohibited algorithm appears in a production NSS context, regardless of whether it is actively negotiated.

**Fix**

Replace all non-approved algorithms. CNSA 2.0 does not permit algorithm negotiation to fall back to pre-quantum algorithms in production NSS contexts. Disable any TLS, IKE, or application-layer configurations that allow downgrade to prohibited cipher suites. Where backward compatibility with legacy partners is required, document a formal exception with a transition timeline approved by the AO.

---

### PQC-01-000020 — ML-DSA Minimum Key Strength

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding**

The system implements ML-DSA below the ML-DSA-65 (NIST Security Level 3) parameter set.

**Check**

Verify that all digital signature operations use ML-DSA-65 or ML-DSA-87:

| Parameter Set | Security Level | Public Key | Signature Size | NSS Approved |
|---------------|---------------|------------|----------------|--------------|
| ML-DSA-44 | NIST Level 2 | 1,312 bytes | 2,420 bytes | **No** |
| ML-DSA-65 | NIST Level 3 | 1,952 bytes | 3,309 bytes | Yes |
| ML-DSA-87 | NIST Level 5 | 2,592 bytes | 4,627 bytes | Yes |

**PASS:** All public keys are 1,952 bytes (ML-DSA-65) or 2,592 bytes (ML-DSA-87). Signature verification logic rejects key material at smaller sizes.

**FAIL:** Public key material is 1,312 bytes, indicating ML-DSA-44. Any system accepting or generating ML-DSA-44 signatures in production is a finding.

**Fix**

Upgrade to the ML-DSA-65 parameter set at minimum. ML-DSA-44 provides only NIST Level 2 security, below the threat model for NSS environments. Reissue all key material and certificates at the correct parameter set. Update all certificate validation logic to reject ML-DSA-44 material.

---

### PQC-01-000030 — ML-KEM Minimum Encapsulation Strength

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding**

The system uses ML-KEM-512 for key encapsulation rather than ML-KEM-768 or ML-KEM-1024.

**Check**

Verify that key encapsulation mechanisms use the ML-KEM-768 or ML-KEM-1024 parameter set:

| Parameter Set | Security Level | Public Key | Ciphertext | NSS Approved |
|---------------|---------------|------------|------------|--------------|
| ML-KEM-512 | NIST Level 1 | 800 bytes | 768 bytes | **No** |
| ML-KEM-768 | NIST Level 3 | 1,184 bytes | 1,088 bytes | Yes |
| ML-KEM-1024 | NIST Level 5 | 1,568 bytes | 1,568 bytes | Yes |

**PASS:** Observed ciphertext sizes are 1,088 bytes (ML-KEM-768) or 1,568 bytes (ML-KEM-1024). The system rejects encapsulation attempts using 768-byte ciphertexts.

**FAIL:** Ciphertext is 768 bytes, indicating ML-KEM-512.

**Fix**

Migrate to ML-KEM-768 at minimum. Add ciphertext size validation in integration tests to prevent silent parameter downgrade during library updates.

---

### PQC-01-000040 — Non-Constant-Time Implementation Detection

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding**

The system's PQC implementation uses operations that are not constant-time, creating timing side-channel vulnerabilities.

**Check**

Verify that the PQC library in use is a NIST-validated, constant-time implementation. Inspect the SBOM for known non-constant-time PQC implementations.

Approved constant-time libraries include:
- **liboqs** (Open Quantum Safe) — validated constant-time ML-KEM and ML-DSA
- **Cloudflare CIRCL** — Go implementation with constant-time guarantees
- **BoringSSL / AWS-LC** — FIPS-mode builds with validated PQC

**PASS:** The system uses a listed constant-time library or an equivalent with documented timing-attack mitigation. SBOM reflects no homegrown or unvalidated PQC implementations in the cryptographic path.

**FAIL:** The system uses a home-grown PQC implementation, a research prototype, or a library without documented constant-time guarantees in its production cryptographic path.

**Fix**

Replace non-validated PQC implementations with a library from the approved list. Do not use reference implementations from NIST specification documents directly in production — these are designed for readability, not timing-attack resistance.

---

### PQC-01-000050 — Deprecated or Broken PQC Algorithm Detection

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding**

The system uses post-quantum algorithms that were not selected by NIST or have been cryptanalytically broken.

**Check**

Scan the system for the following deprecated or broken PQC algorithms:

| Algorithm | Status | Reason |
|-----------|--------|--------|
| SIKE / SIDH | **Broken** | Cryptanalytically broken 2022 (Castryck-Decru) |
| Rainbow | **Broken** | Cryptanalytically broken 2022 (Beullens) |
| GeMSS | Not selected | NIST Round 3 alternate — not standardized |
| NTRU Prime | Not selected | Not selected in final NIST standardization |

**PASS:** No deprecated or broken PQC algorithms appear in the system's cryptographic configuration, SBOM, or TLS/IKE negotiation lists.

**FAIL:** SIKE, Rainbow, or any cryptanalytically broken algorithm is present. This is a non-negotiable finding requiring immediate remediation.

**Fix**

Remove all deprecated or broken PQC algorithms immediately. For SIKE and Rainbow, these algorithms are broken and provide zero security. Replace with NIST-standardized ML-KEM (FIPS 203) for key encapsulation and ML-DSA (FIPS 204) for signatures.

---

### CAT II — MEDIUM SEVERITY

---

### PQC-01-000060 — Hybrid Cryptography During Transition

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SC-8 — Transmission Confidentiality and Integrity |
| **CCI** | CCI-002418 |

**Finding**

The system in active PQC transition has not implemented hybrid (classical + PQC) key exchange, leaving it exposed to classical attacks if the PQC implementation has defects.

**Check**

For systems undergoing transition (2025–2030), verify that critical communications implement hybrid key exchange:

| Classical Component | PQC Component | Hybrid Construction |
|--------------------|---------------|---------------------|
| X25519 | ML-KEM-768 | X25519+ML-KEM-768 (IETF hybrid KEM) |
| P-384 ECDH | ML-KEM-1024 | P-384+ML-KEM-1024 |

**PASS:** All critical communications use an IETF-compliant hybrid key exchange during the transition period, OR the system has completed formal transition validation and the AO has formally accepted pure PQC-only operation for that specific system boundary.

**FAIL:** A system in active transition uses pure PQC-only key exchange without AO-accepted transition documentation, OR uses pure classical-only key exchange with no PQC component.

**Fix**

Implement hybrid key exchange for all critical communications during the transition period. Do not remove classical algorithms until PQC deployment is operationally validated and the transition is formally accepted by the authorizing official.

---

### PQC-01-000070 — PQC Key Material Storage

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SC-12 — Cryptographic Key Establishment and Management |
| **CCI** | CCI-000162 |

**Finding**

PQC private key material is stored in plaintext, in software-only key stores, or in locations accessible to unprivileged processes.

**Check**

Verify that ML-DSA and ML-KEM private keys are protected at rest:
- For systems with available HSM: keys must reside in FIPS 140-3 Level 3 or higher HSMs
- For systems without HSM: keys must be encrypted with AES-256-GCM, with the KEK stored separately
- Private key files must not be world-readable (Unix permissions 600 or stricter)

**PASS:** Private key material is in an HSM, or encrypted with a separately-stored KEK, and file permissions are 600 or stricter.

**FAIL:** Private key material is in plaintext files, software keystores with no additional encryption, or files with permissions broader than 600.

**Fix**

Migrate private keys to a FIPS 140-3 Level 3 HSM where available. Where HSM is unavailable, encrypt key material with AES-256-GCM and store the KEK in a separate protected location. Restrict file permissions immediately.

---

### PQC-01-000080 — PQC Certificate Chain Validation

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SC-17 — Public Key Infrastructure Certificates |
| **CCI** | CCI-002460 |

**Finding**

The system does not validate PQC algorithm identifiers in X.509 certificate chains, or accepts chains that mix approved and non-approved PQC algorithms.

**Check**

Verify that certificate validation logic recognizes ML-DSA OIDs, enforces the ML-DSA-65 minimum parameter set for all certificates in the chain, and rejects certificates using prohibited algorithms except in documented hybrid configurations.

Relevant OIDs:
- ML-DSA-44: 2.16.840.1.101.3.4.3.17
- ML-DSA-65: 2.16.840.1.101.3.4.3.18
- ML-DSA-87: 2.16.840.1.101.3.4.3.19

**PASS:** The system correctly validates ML-DSA certificate chains, enforces minimum parameter sets, and rejects prohibited algorithms except in documented hybrid configurations.

**FAIL:** The system accepts certificates signed with RSA or ECDSA in a non-hybrid context, or silently ignores PQC algorithm identifier validation errors.

**Fix**

Update TLS and PKI validation libraries to support PQC OIDs. Test certificate chain validation explicitly with both correct and intentionally malformed PQC certificate chains.

---

### PQC-01-000090 — Cryptographic Asset Inventory (CBOM)

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | PL-8 — Information Security Architecture |
| **CCI** | CCI-000069 |

**Finding**

The system does not maintain a current Cryptography Bill of Materials (CBOM) documenting all cryptographic assets, their locations, and their quantum-vulnerability classification.

**Check**

Verify that a CBOM exists and contains at minimum:
- All cryptographic libraries in use (name, version, algorithm support)
- All certificates (location, algorithm, key size, expiration)
- All symmetric keys in use (algorithm, length, storage location)
- Quantum-vulnerability classification for each entry (VULNERABLE / TRANSITIONAL / QUANTUM-SAFE)
- Last-updated date within 90 days

**PASS:** A CBOM exists, contains all required fields, is updated within 90 days, and is maintained in a configuration-managed location accessible to the ISSO.

**FAIL:** No CBOM exists, the CBOM is more than 90 days old, or critical cryptographic assets are not documented.

**Fix**

Generate a CBOM using a recognized tool (KHEPRA ASAF, Syft with crypto plugins, or equivalent). Establish a process to update the CBOM on software changes and at least quarterly. Format in CycloneDX 1.5 or SPDX 2.3 for interoperability.

---

### PQC-01-000100 — PQC Implementation Testing in Staging

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SA-11 — Developer Testing and Evaluation |
| **CCI** | CCI-002824 |

**Finding**

PQC algorithms are deployed in production without documented evidence of testing in a staging environment, including Known-Answer Tests (KATs) for ML-KEM and ML-DSA.

**Check**

Review change management records for PQC algorithm deployments. Verify that testing included both positive cases (correct operation with CNSA 2.0 algorithms) and negative cases (rejection of prohibited algorithms), and that NIST-published KAT results are documented.

**PASS:** Change management records contain documented KAT results from a staging environment prior to production deployment.

**FAIL:** PQC algorithms are in production with no documented pre-production testing, or test records do not include KAT results or negative test cases.

**Fix**

Establish a staging environment that mirrors production cryptographic configuration. Run NIST-published KATs for ML-KEM and ML-DSA prior to any production deployment. Retain results in the system's A&A package.

---

### CAT III — LOW SEVERITY

---

### PQC-01-000110 — PQC Cryptographic Event Audit Logging

| Field | Value |
|-------|-------|
| **Severity** | CAT III — Low |
| **NIST 800-53** | AU-2 — Event Logging |
| **CCI** | CCI-000169 |

**Finding**

The system does not generate audit log entries for PQC cryptographic operations, preventing forensic reconstruction of cryptographic events.

**Check**

Verify that the system generates audit log entries for key generation, certificate issuance and renewal, algorithm negotiation failures or downgrades, and key encapsulation and decapsulation operations in sensitive contexts. Log entries must include timestamp, subject identity, operation type, algorithm identifier, and success/failure status.

**PASS:** Audit logs capture the required event types with all required fields, written to a protected, tamper-evident log store.

**FAIL:** Cryptographic operations generate no audit log entries, or entries omit algorithm identifier and parameter set information.

**Fix**

Instrument the cryptographic layer to emit structured log events for each required event type. Write events to a protected log store. Ensure log entries include algorithm identifiers sufficient to reconstruct cryptographic decisions during incident response.

---

### PQC-01-000120 — PQC Migration Rollback Documentation

| Field | Value |
|-------|-------|
| **Severity** | CAT III — Low |
| **NIST 800-53** | CP-9 — System Backup |
| **CCI** | CCI-000519 |

**Finding**

The system lacks documented rollback procedures for PQC migrations, creating risk of extended outage if a PQC deployment fails.

**Check**

Verify that documented rollback procedures exist for each PQC component, including step-by-step reversion instructions, estimated rollback time, responsible personnel, and tested evidence that the rollback has been exercised within the past 12 months.

**PASS:** Rollback documentation exists, has been exercised in a non-production environment within the past 12 months, and key material backup supports rollback.

**FAIL:** No rollback documentation exists, or documented rollback has not been tested.

**Fix**

Document rollback procedures for each PQC component prior to production deployment. Exercise rollback in staging at least annually. Maintain a backup of pre-migration key material in an escrow location accessible to the system administrator independently of the production system.

---

## 3. Agentic AI and MCP PQC Controls

### 3.1 Why Agentic AI Requires PQC-Specific Controls

The NSA's May 2026 Cybersecurity Information Sheet on MCP (U/OO/6030316-26) identified a critical insight: MCP reverses the familiar client-server trust model. In MCP deployments, servers may query and execute actions *for* clients rather than responding to them. This inversion creates attack paths that classical security frameworks were not designed to address — and that PQC policy has not yet reached.

Joint guidance from ASD, CISA, NSA, and allied cyber agencies (2026) identified five categories of agentic AI risk, several of which have specific PQC dimensions:

**The accountability gap is the PQC exposure.** When an AI agent takes an action in an NSS context — invoking a tool, accessing CUI, making a compliance decision — that action generates an audit record. If that audit record is signed only with RSA or ECDSA, a harvest-now-decrypt-later adversary can collect it today and later prove the record is forged. The cryptographic integrity of agentic AI audit trails must survive the quantum transition.

**The identity gap is the PQC exposure.** The joint guidance recommends that "each agent [be treated] as a distinct principal, a cryptographically anchored identity with its own unique keys or certificates" and that "agents authenticate to services and to one another using secret keys or tokens." Neither recommendation specifies PQC requirements. In an NSS context, agent identity keys signed with classical algorithms are vulnerable to the same harvest-now-decrypt-later attacks as any other key material.

**The MCP message signing gap is the PQC exposure.** The NSA found that MCP "currently relies on transport layer encryption (e.g., TLS)" but "the protocol itself cannot enforce or verify encryption and is unaware of message integrity." The NSA recommended extending MCP with "cryptographic signatures directly within the JSON payload." In an NSS context, those signatures must use ML-DSA, not RSA or ECDSA.

The five controls in this section address these three gaps directly. They are formatted consistently with Section 2 controls and use the PQC-01-A namespace to distinguish them as agentic AI-specific.

---

### Control Format (Agentic AI Controls)

Agentic AI controls use an expanded Check format that specifies which system component is responsible for each verification step, reflecting the distributed nature of agentic systems.

---

### CAT I — HIGH SEVERITY (Agentic AI)

---

### PQC-01-A00010 — AI Agent Identity Cryptographic Anchoring

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | IA-3 — Device Identification and Authentication |
| **CCI** | CCI-001958 |
| **Related Guidance** | NSA U/OO/6030316-26 §Sign and verify MCP messages; ASD/CISA Joint Guidance §Identity management |

**Finding**

AI agents deployed in NSS or CUI environments authenticate to services and to each other using classical cryptographic credentials (RSA, ECDSA, Ed25519) that are vulnerable to harvest-now-decrypt-later attacks on stored agent-to-agent communications.

**Context**

The ASD/CISA/NSA joint guidance recommends constructing "each agent as a distinct principal, a cryptographically anchored identity with its own unique keys or certificates" and using "mutual transport layer security to ensure non-repudiation." In NSS contexts, these credentials must use CNSA 2.0 algorithms. An agent identity signed with RSA-2048 that is captured in transit today can be forged once a cryptographically-relevant quantum computer is available, enabling retroactive impersonation across the entire audit record of that agent's actions.

**Check**

For each AI agent deployed in the system:

1. Inspect the agent identity certificate or key material
2. Verify the signing algorithm is ML-DSA-65 or ML-DSA-87 (FIPS 204)
3. Verify the agent identity key is stored in a FIPS 140-3 Level 3 HSM or equivalent protected store
4. Verify that inter-agent authentication uses mutual TLS with ML-DSA certificates
5. Verify that agent identity certificates include a defined expiration not exceeding 365 days

**PASS:** All agent identity certificates use ML-DSA-65 or ML-DSA-87, are stored in a protected key store meeting PQC-01-000070 requirements, and inter-agent mTLS uses ML-DSA certificates with expiration no greater than 365 days.

**FAIL:** Any agent identity certificate uses RSA, ECDSA, or Ed25519. Any agent identity key is stored in an unprotected software keystore. Any inter-agent TLS session uses classical certificates.

**Fix**

Reissue all agent identity certificates using ML-DSA-65 at minimum. Deploy agent identity keys in FIPS 140-3 Level 3 HSMs where available. Update all inter-agent mTLS configurations to use ML-DSA certificates. Implement certificate lifecycle automation to enforce the 365-day expiration.

---

### PQC-01-A00020 — MCP Message Integrity Signing

| Field | Value |
|-------|-------|
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-8 — Transmission Confidentiality and Integrity |
| **CCI** | CCI-002418 |
| **Related Guidance** | NSA U/OO/6030316-26 §Sign and verify MCP messages |

**Finding**

MCP messages between agents, between agents and tools, and between agents and external services are not signed at the application layer with PQC signatures, relying solely on transport-layer TLS that the MCP protocol cannot verify or enforce.

**Context**

The NSA identified that MCP "currently relies on transport layer encryption (e.g., TLS)" but "the protocol itself cannot enforce or verify encryption and is unaware of message integrity." The NSA recommended extending MCP with "cryptographic signatures directly within the JSON payload" including "expiration timestamps and replay protection metadata." In NSS contexts, those payload-level signatures must use ML-DSA-65 or higher — not RSA or ECDSA — to protect against harvest-now-decrypt-later attacks on message archives.

**Check**

Inspect the MCP implementation for:

1. Presence of a `signature` field in MCP JSON payloads
2. Signature algorithm — must be ML-DSA-65 (FIPS 204) or stronger
3. Presence of an `expires_at` timestamp in each signed payload (must not exceed 5 minutes from `issued_at`)
4. Presence of a `nonce` or `message_id` field enabling replay detection
5. Signature verification logic on the receiving side that rejects expired or previously-seen nonces

**PASS:** All MCP messages in NSS-touching workflows include ML-DSA-65 payload signatures with expiration timestamps not exceeding 5 minutes and nonces verified against a seen-nonce store.

**FAIL:** MCP messages rely on transport-layer TLS only, with no application-layer signature. Any application-layer signature uses RSA or ECDSA. Expiration timestamps are absent or exceed 5 minutes.

**Fix**

Extend the MCP implementation to embed ML-DSA-65 signatures in each JSON-RPC payload. Implement a seen-nonce store at each MCP server to enable replay detection. Set expiration to no more than 5 minutes. Validate signatures and expiration on receipt before executing any tool invocation.

---

### CAT II — MEDIUM SEVERITY (Agentic AI)

---

### PQC-01-A00030 — Agentic AI Audit Trail Cryptographic Integrity

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | AU-9 — Protection of Audit Information |
| **CCI** | CCI-001350 |
| **Related Guidance** | ASD/CISA Joint Guidance §Accountability risks; NSA U/OO/6030316-26 §Instrument for logging and detection |

**Finding**

Agentic AI systems in the environment do not produce cryptographically-signed audit records of agent actions, tool invocations, and decision steps, making the audit trail subject to undetectable tampering and vulnerable to retroactive forgery once quantum computing is available.

**Context**

The ASD/CISA/NSA joint guidance identifies "accountability risks" as a primary agentic AI concern, noting that "agent actions and decision-making processes can be opaque, making agentic AI systems difficult to understand, monitor and audit." The guidance recommends "comprehensive artifact logging mechanisms by default" and "unified audit logs for all inter-agent interactions." In NSS contexts, the integrity of these logs must be cryptographically protected to survive the quantum transition.

The NSA recommends logging that includes "the exact parameters, identities involved, and (where feasible) cryptographic hashes of results or output." In NSS contexts, those hashes and any log signatures must use SHA-384 or SHA-512 (not SHA-256) and ML-DSA-65 (not ECDSA).

**Check**

For each agentic AI system:

1. Verify that each agent action (tool call, API invocation, decision branch, sub-agent spawn) produces a structured log entry
2. Verify that log entries are signed with ML-DSA-65 (FIPS 204)
3. Verify that log entries include: agent identity, action type, tool name (if applicable), input parameters, output summary, timestamp, and parent action ID enabling causal chain reconstruction
4. Verify that the log store is append-only (no delete or update operations available to the agent or its runtime)
5. Verify that log entry hashes use SHA-384 or SHA-512

**PASS:** All agent actions produce ML-DSA-65-signed log entries with the required fields, written to an append-only log store, with SHA-384 or SHA-512 hashes.

**FAIL:** Agent actions produce unsigned log entries, or entries signed with classical algorithms, or entries missing causal chain fields. The log store permits deletion or modification by agent processes.

**Fix**

Implement a PQC-signed Flight Recorder for all agentic AI operations in NSS contexts. Deploy the log store in an append-only configuration with write access restricted to the logging subsystem. Instrument all agent runtimes to emit structured log events for every action. Use ML-DSA-65 for log entry signing and SHA-384 or SHA-512 for content hashing.

---

### PQC-01-A00040 — Tool Execution Cryptographic Authorization

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | AC-3 — Access Enforcement |
| **CCI** | CCI-000213 |
| **Related Guidance** | NSA U/OO/6030316-26 §Constrain and sandbox tool execution; ASD/CISA Joint Guidance §Privilege risks |

**Finding**

Tool invocations by AI agents in NSS or CUI environments are authorized through classical access control mechanisms that do not produce quantum-resistant authorization evidence, preventing post-quantum verification of tool execution authorization records.

**Context**

The NSA identified that MCP "lacks support for exchanging Role Based Access Control (RBAC) permissions at instantiation" and that "many implementations omit authentication entirely." The ASD/CISA/NSA joint guidance recommends requiring "cryptographic signing for authorised commands and instructions" and "cryptographic integrity checks for task definitions and constraints." In NSS contexts, these cryptographic authorizations must use ML-DSA-65 to ensure the authorization records survive the quantum transition.

PQC-signed authorization tokens provide verifiable, time-bound evidence that a specific agent was authorized to invoke a specific tool at a specific time — evidence that remains verifiable against quantum-capable adversaries.

**Check**

For each tool invocable by AI agents:

1. Verify that tool invocation requires a signed authorization token issued by a central authorization service
2. Verify that authorization tokens are signed with ML-DSA-65 (FIPS 204)
3. Verify that authorization tokens are scoped to: specific agent identity, specific tool name, specific parameter constraints, and expiration not exceeding 15 minutes
4. Verify that the receiving tool validates the authorization token before execution
5. Verify that the authorization service logs each token issuance with a ML-DSA-65-signed record

**PASS:** All tool invocations require ML-DSA-65-signed, time-bound authorization tokens scoped to agent identity and tool name, validated by the tool before execution.

**FAIL:** Tool invocations use classical signed tokens, unsigned tokens, or no token-based authorization at all. Tokens lack expiration. Tokens are not scoped to specific tools or agents.

**Fix**

Deploy a central authorization service that issues ML-DSA-65-signed, time-bound authorization tokens for each tool invocation. Update tool execution logic to validate tokens before processing. Implement token expiration no greater than 15 minutes. Log all token issuances with ML-DSA-65-signed records.

---

### PQC-01-A00050 — MCP Server Cryptographic Identity Verification

| Field | Value |
|-------|-------|
| **Severity** | CAT II — Medium |
| **NIST 800-53** | IA-9 — Service Identification and Authentication |
| **CCI** | CCI-001967 |
| **Related Guidance** | NSA U/OO/6030316-26 §Choose supported MCP projects; §Design for boundaries |

**Finding**

AI agents connect to MCP servers without verifying the server's cryptographic identity using PQC certificates, creating exposure to tool name collision attacks and MCP server impersonation.

**Context**

The NSA identified real-world exploitation of "tool invocation path confusion," where MCP orchestrators were tricked into loading attacker-controlled code using naming collisions. The NSA also documented a case where "a malicious MCP server's tool descriptions manipulated the MCP client's behavior" — and the server "advertised a benign instruction at the time of installation and switched to a malicious instruction after the MCP server's second usage." In NSS contexts, server identity verification using classical certificates is vulnerable to harvest-now-decrypt-later attacks on captured certificate exchanges.

**Check**

For each MCP server in the environment:

1. Verify that the MCP server presents an ML-DSA-65 certificate for client authentication
2. Verify that AI agent MCP clients validate the server certificate against a trusted registry before establishing a session
3. Verify that the trusted registry is maintained by the ISSO and reviewed at least monthly for unauthorized additions
4. Verify that the agent MCP client rejects connections to servers not present in the trusted registry, regardless of tool description content
5. Verify that the MCP server certificate includes the approved tool name list as a certificate extension, preventing undisclosed capability changes

**PASS:** All MCP servers present ML-DSA-65 certificates, clients validate against an ISSO-maintained trusted registry, and certificates include approved tool lists that cannot change without certificate reissuance.

**FAIL:** MCP servers use RSA or ECDSA certificates, clients do not validate server identity before establishing sessions, or no trusted registry of approved MCP servers exists.

**Fix**

Issue ML-DSA-65 certificates to all MCP servers. Implement client-side certificate validation against an ISSO-maintained trusted registry before any MCP session is established. Include approved tool name lists as certificate extensions so that capability changes require explicit certificate reissuance and registry update. Alert the ISSO when a connection is attempted to an unregistered server.

---

## 4. Compliance Assessment Methodology

### Self-Assessment Approach

Organizations conducting self-assessment against PQC-01-STIG-V1R1 should proceed in the following sequence:

**Step 1 — Cryptographic Asset Inventory**
Before auditing individual controls, produce a complete CBOM (see PQC-01-000090). Controls referencing specific algorithms cannot be audited without knowing what algorithms the system uses. For agentic AI systems, extend the CBOM to include: all AI agent runtimes, all MCP servers, all tools accessible via MCP, and all inter-agent communication channels.

**Step 2 — Agentic AI System Inventory**
For organizations deploying AI agents, document: each agent's identity mechanism, each MCP server in use (name, version, certificate), each tool accessible via MCP, and the audit logging mechanism for agent actions.

**Step 3 — Algorithm Classification**
For each cryptographic asset in the CBOM, classify against the CNSA 2.0 algorithm table in PQC-01-000010. For each agent identity, MCP server certificate, and tool authorization mechanism, classify against PQC-01-A00010 through PQC-01-A00050.

**Step 4 — Control-by-Control Assessment**
For each control, apply the Check criteria and record PASS / FAIL / NOT APPLICABLE with supporting evidence. NOT APPLICABLE for agentic AI controls requires written justification that the system has no AI agents operating in NSS or CUI contexts.

**Step 5 — Prioritized Remediation**
Address CAT I findings first. For agentic AI systems, PQC-01-A00010 (agent identity) and PQC-01-A00020 (MCP message signing) are the highest-priority findings because they affect the integrity of all other controls — an agent that can be impersonated can produce false compliance evidence.

### Evidence Package for C3PAO Assessments

Third-party assessors conducting CMMC assessments where PQC controls are in scope should request the following evidence package:

| Evidence Item | Related Controls |
|--------------|-----------------|
| CBOM (CycloneDX 1.5 or SPDX 2.3) | PQC-01-000090 |
| Library version documentation with constant-time attestation | PQC-01-000040 |
| HSM configuration records or KEK storage documentation | PQC-01-000070 |
| Staging test results including KAT outputs | PQC-01-000100 |
| Rollback procedure documentation with test evidence | PQC-01-000120 |
| AI agent identity certificate inventory | PQC-01-A00010 |
| MCP server trusted registry (ISSO-certified) | PQC-01-A00050 |
| Sample signed MCP message with signature verification confirmation | PQC-01-A00020 |
| Flight Recorder sample output with ML-DSA-65 signature verification | PQC-01-A00030 |
| Tool authorization token lifecycle documentation | PQC-01-A00040 |

---

## 5. KHEPRA MCP Server: Reference Implementation

### The Patent-Pending Foundation

Every cryptographic claim in this STIG's reference implementation rests on the **KHEPRA Protocol** — a novel framework invented by Souhimbou D. Kone and filed with the USPTO as Application #73565085 (pending), titled *"Adinkra Symbol-Based Cryptographic Attestation System for Quantum-Resilient Autonomous AI Security."*

KHEPRA Protocol is not a compliance scanner. It is the cryptographic and ontological architecture that makes the controls in this document implementable as a unified system rather than a collection of disconnected tools. Three inventions within KHEPRA Protocol are directly relevant to this STIG:

**1. Symbol-Bound PQC Key Derivation (ASAF cryptographic primitives)**
KHEPRA extends ML-DSA and ML-KEM by deterministically seeding lattice parameters with Adinkra symbolic descriptors using D₈ group transformations. Each symbol encodes a compliance domain: Eban maps to DoD RMF and STIG, Fawohodie maps to CMMC and revocation management, Nkyinkyim maps to FedRAMP and GDPR, Dwennimmen maps to PCI DSS and HIPAA. A KHEPRA-signed record therefore carries two verifiable claims: that the signature is quantum-resistant (ML-DSA-65, FIPS 204), and that the signing context is semantically bound to a specific compliance framework. This is what PQC-01-A00010 requires under "agent identity cryptographic anchoring" — not merely a PQC certificate, but a PQC certificate whose key parameters encode the compliance authority under which the agent operates.

**2. Immutable DAG Causal Attestation Chain**
KHEPRA records every agent action, tool invocation, and compliance decision as a content-addressed node in a directed acyclic graph, with each node carrying the ML-DSA-65 signature of the preceding node's hash. This produces a tamper-evident causal chain — not a flat log — where the relationship between actions is cryptographically encoded, not merely timestamped. Auditors can verify not just that action B occurred, but that B was caused by A, and that neither record was modified after the fact. This is the technical mechanism underlying PQC-01-A00030's requirement for "parent action ID enabling causal chain reconstruction."

**3. ASAF Trust Score Binding**
KHEPRA's ASAF primitives cryptographically bind a numerical trust score (0–100) and a compliance tag to each signed agent action. This means an authorization record states not only "Agent X was permitted to invoke Tool Y" but "Agent X was permitted to invoke Tool Y with trust score 87 under CMMC AC.3.018 (Eban)" — a claim that can be independently verified by any party holding the KHEPRA public key. This is the basis for PQC-01-A00040's tool authorization token requirement.

### KHEPRA MCP Server: Production Deployment

The KHEPRA MCP Server (`ghcr.io/nouchix/pqc-khepra-mcp:1.0.0`) is the production implementation of KHEPRA Protocol as a containerized, Iron Bank-ready compliance tool. It exposes KHEPRA Protocol's capabilities to any MCP-compatible client — Claude, Cursor, Cline, GPT — via the MCP Registry at `io.github.nouchix/pqc-khepra-mcp`.

The KHEPRA MCP Server addresses the NSA's identified MCP security gaps as follows:

| NSA-Identified Gap (U/OO/6030316-26) | KHEPRA Protocol Implementation | Related Control |
|--------------------------------------|-------------------------------|-----------------|
| No authentication at protocol level | ML-DSA-65 server identity certificates with Adinkra symbol binding | PQC-01-A00050 |
| No RBAC at protocol level | ASAF-signed tool authorization tokens with compliance tag | PQC-01-A00040 |
| No application-layer message signing | ML-DSA-65 JSON payload signatures with replay protection | PQC-01-A00020 |
| Poor or missing audit logs | DAG causal attestation chain via SouHimBou AI Flight Recorder | PQC-01-A00030 |
| No trusted server registry | ISSO-maintained registry with ML-DSA-65 certificates and tool-list extensions | PQC-01-A00050 |

### Available Compliance Tools

| Tool | Function | Related Controls |
|------|----------|-----------------|
| `stig_check` | Validate configurations against all 17 PQC-01 controls | All |
| `nist_map` | Map CCI identifiers to NIST 800-53 Rev 5 via 36,195 pre-computed cross-framework mappings | All |
| `cmmc_assess` | Score maturity per CMMC Level 1–3 practice domain | PQC-01-A00010 through A00050 |
| `ert_scan` | Full STIG / CMMC / NIST 800-171 scan with dollar-denominated risk findings | All |
| `attest_export` | Export KHEPRA Protocol ASAF packages signed ML-DSA-65 / FIPS 204 for C3PAO intake | PQC-01-000010 through 000120 |
| `agent_record` | Send AI agent operations to SouHimBou AI Flight Recorder (KHEPRA DAG-anchored) | PQC-01-A00030 |
| `godfather_report` | Generate executive-facing, dollar-denominated cyber risk reports | All |

### Deployment Modes

| Mode | Use Case | Network | Key Capability |
|------|----------|---------|----------------|
| `community` | Evaluation and open use | Internet-connected | `pqc_stig` + 24 core tools, zero license key required |
| `sovereign` | Air-gapped / SCIF / on-prem DoD | Fully offline | All 32 tools, zero egress, all KHEPRA Protocol primitives |
| `ironbank` | FedRAMP / IL4 / IL5 production | Controlled enclave | Iron Bank hardened image, FIPS 140-3 validated crypto path |

All three modes produce ML-DSA-65 attestation on every cryptographic operation. The `sovereign` and `ironbank` modes make zero external network calls — every mapping, every signature, and every assessment runs entirely on the operator's infrastructure.

---

## 6. Conclusion and Next Steps

### What This Document Establishes

PQC-01-STIG-V1R1 establishes three things that did not previously exist in a single authoritative document:

1. **A testable PQC compliance checklist** — 12 core controls with explicit PASS/FAIL criteria, mapped to CCI identifiers, NIST 800-53 Rev 5, and CNSA 2.0 requirements. Program managers and ISSOs can open this document and begin a self-assessment today.

2. **The first PQC controls for agentic AI and MCP** — 5 supplementary controls grounded in the NSA's May 2026 MCP advisory and the ASD/CISA/NSA joint guidance on agentic AI, translated into the specific technical requirements those documents stop short of specifying. Organizations deploying AI agents in NSS or CUI contexts have no other published checklist to assess these risks against PQC requirements.

3. **A reference implementation** — the KHEPRA MCP Server demonstrates that all 17 controls are practically implementable in a production system today, not a theoretical future capability. The `attest_export` tool produces C3PAO-ready evidence packages. The `agent_record` tool provides DAG-anchored PQC audit trails for agentic AI operations.

### The Gap That Remains

DISA will publish an official PQC STIG — the question is when. This document is intended to serve until that guidance arrives and to inform its content. Organizations that implement PQC-01-STIG-V1R1 controls now will be well-positioned to map their existing controls to the official DISA guidance when it is released, rather than beginning from zero.

The agentic AI controls in Section 3 address a gap that official guidance is unlikely to fill quickly. The NSA's MCP advisory and the ASD/CISA/NSA joint agentic AI guidance are both recent (2026) and neither provides the specific PQC requirements in the format assessors need. PQC-01-A00010 through PQC-01-A00050 are intended to fill that gap for organizations that cannot wait for official guidance to catch up with deployment reality.

### Recommended Next Steps

**For DIB contractors:** Conduct a self-assessment against Section 2 controls using the evidence package in Section 4. If you are deploying AI agents in any CUI-handling workflow, add Section 3 controls to the assessment. Use `khepra ert_scan` to generate a prioritized finding list with remediation guidance.

**For ISSOs and authorizing officials:** Request CBOM and agentic AI system inventory from system owners before the next authorization decision. Add PQC algorithm compliance to ATO package requirements. The 2026 deadline for NSS software is not a future planning horizon — it is this year.

**For C3PAOs:** The evidence package table in Section 4 provides a starting point for requesting PQC-specific evidence during CMMC assessments. The `attest_export` tool produces ML-DSA-65-signed packages in the format described.

**For the community:** This document is published for public release. Share it. Reference it. Challenge it. The fastest path to an official PQC STIG is demonstrated community consensus on what the controls should say.

---

## References

| Reference | Title | Date |
|-----------|-------|------|
| NSM-10 | National Security Memorandum on Promoting United States Leadership in Quantum Computing | May 2022 |
| OMB M-23-02 | Migrating to Post-Quantum Cryptography | January 2023 |
| CNSA 2.0 | NSA Commercial National Security Algorithm Suite 2.0 Advisory (U/OO/194427-22) | September 2022 |
| FIPS 203 | Module-Lattice-Based Key-Encapsulation Mechanism Standard | August 13, 2024 |
| FIPS 204 | Module-Lattice-Based Digital Signature Standard | August 13, 2024 |
| FIPS 205 | Stateless Hash-Based Digital Signature Standard | August 13, 2024 |
| NSA U/OO/6030316-26 | Cybersecurity Information Sheet: Model Context Protocol | May 2026 |
| ASD/CISA/NSA Joint Guidance | Agentic AI: Considerations for Cybersecurity | 2026 |
| NIST SP 800-53 Rev 5 | Security and Privacy Controls for Information Systems and Organizations | September 2020 |
| DoDI 8510.01 | Risk Management Framework for DoD Systems | July 2017 |
| CMMC 2.0 Model | Cybersecurity Maturity Model Certification v2.0 | November 2021 |
| USPTO #73565085 | Adinkra Symbol-Based Cryptographic Attestation System for Quantum-Resilient Autonomous AI Security (Patent Pending) | 2025 |
| Castryck-Decru 2022 | An Efficient Key Recovery Attack on SIDH | August 2022 |
| Beullens 2022 | Breaking Rainbow Takes a Weekend on a Laptop | 2022 |

---

*PQC-01-STIG-V1R1 is an independent publication by NouchiX / SecRed Knowledge Inc. It is not affiliated with, endorsed by, or derived from any DISA publication. KHEPRA Protocol (USPTO #73565085) is patent pending. All rights reserved. Document published UNCLASSIFIED // FOR PUBLIC RELEASE.*

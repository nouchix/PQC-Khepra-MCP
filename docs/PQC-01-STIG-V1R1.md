# PQC-01-STIG-V1R1

## The World's First DoD-Style Post-Quantum Cryptography STIG
### Filling the CNSA 2.0 Compliance Gap

### Document Metadata

| Field | Value |
| --- | --- |
| **Document ID** | PQC-01-STIG-V1R1 |
| **Authors** | NouchiX / SecRed Knowledge Inc. |
| **Version** | 1.1 |
| **Date** | July 2026 |
| **Classification** | UNCLASSIFIED // FOR PUBLIC RELEASE |
| **Contact** | contact@nouchix.com · nouchix.com |
| **Changelog** | v1.1: Updated all citations to DoD Post-Quantum Cryptography Strategy (April 2026, DoD CIO). Anchored Agentic AI & MCP controls to official NIST (Feb 2026) and Five Eyes/CISA/NSA (June 2026) guidelines. Updated control mapping count to 25,185 deduplicated mappings across NIST 800-53, DISA STIG, CCI, CMMC frameworks. |

---

## Table of Contents

* [Abstract](#abstract)
* [1. The Policy Gap](#1-the-policy-gap)
  * [1.1 Mandates Without Checklists](#11-mandates-without-checklists)
  * [1.2 The Harvest-Now-Decrypt-Later Threat Is Active Today](#12-the-harvest-now-decrypt-later-threat-is-active-today)
  * [1.3 The Emerging Agentic AI Attack Surface](#13-the-emerging-agentic-ai-attack-surface)
  * [1.4 What a PQC STIG Needs to Address](#14-what-a-pqc-stig-needs-to-address)
* [2. PQC-01-STIG-V1R1: Twelve Core Controls](#2-pqc-01-stig-v1r1-twelve-core-controls)
  * [Control Format](#control-format)
  * [CAT I — High Severity](#cat-i--high-severity)
  * [CAT II — Medium Severity](#cat-ii--medium-severity)
  * [CAT III — Low Severity](#cat-iii--low-severity)
* [3. Agentic AI and MCP PQC Controls](#3-agentic-ai-and-mcp-pqc-controls)
  * [3.1 Why Agentic AI Requires PQC-Specific Controls](#31-why-agentic-ai-requires-pqc-specific-controls)
  * [3.2 MCP-Specific PQC Controls](#32-mcp-specific-pqc-controls)
* [4. Compliance Assessment Methodology](#4-compliance-assessment-methodology)
  * [4.1 Control Mapping Framework](#41-control-mapping-framework)
  * [4.2 Assessment Approach](#42-assessment-approach)
* [5. KHEPRA MCP Server: Reference Implementation](#5-khepra-mcp-server-reference-implementation)
* [6. Conclusion and Next Steps](#6-conclusion-and-next-steps)
* [7. References](#7-references)
* [Appendix A: Control Mapping Deduplication Methodology](#appendix-a-control-mapping-deduplication-methodology)
  * [A.1 Data Lineage](#a1-data-lineage)
  * [A.2 Code Evidence](#a2-code-evidence)
  * [A.3 Reproducibility](#a3-reproducibility)

---

## Abstract

The Defense Information Systems Agency (DISA) has published Security Technical Implementation Guides (STIGs) for hundreds of technologies — operating systems, databases, web servers, containers — but as of July 2026, no STIG addresses post-quantum cryptographic (PQC) controls. A parallel gap exists for agentic AI systems and the Model Context Protocol (MCP), which the NSA and international partners identified in 2026 as carrying significant, unaddressed security risks.

This gap is consequential and compounding. The DoD Post-Quantum Cryptography Strategy, published by the DoD Chief Information Officer in April 2026, establishes binding compliance deadlines:
* **December 31, 2030:** All federal systems must **support** post-quantum cryptography.
* **December 31, 2031:** All federal systems must **use** post-quantum cryptography for new cryptographic operations.

Meanwhile, MCP — now the de facto standard for AI agent orchestration — was released with what the NSA characterized as a "flexible and underspecified design" that reverses familiar trust patterns. Agentic AI systems, according to joint guidance from ASD, CISA, NSA, NCSC-UK, NCSC-NZ, and the Canadian Cyber Centre (June 2026), introduce structural, privilege, and accountability risks that existing frameworks do not adequately address.

This paper introduces **PQC-01-STIG-V1R1**, which covers two previously unaddressed domains:
* **Section 2** presents the 12 core controls governing PQC algorithm selection, key strength, key storage, hybrid transition, certificate validation, cryptographic inventory, testing, and audit logging.
* **Section 3** presents 5 supplementary controls governing PQC requirements specifically for agentic AI systems and MCP deployments — covering agent identity attestation, MCP message signing, agentic audit trail integrity, tool execution cryptographic authorization, and flight recorder requirements.

Together, these 17 controls provide the first unified PQC compliance checklist spanning both classical cryptographic infrastructure and the emerging agentic AI attack surface.

---

## 1. The Policy Gap

### 1.1 Mandates Without Checklists

DoD Post-Quantum Cryptography Strategy (April 2026) directs all federal agencies to transition to post-quantum cryptography by December 31, 2031. The strategy identifies the following compliance drivers:

| System Type | Support Required | Full Transition |
| --- | --- | --- |
| NSS software and firmware | December 31, 2030 | December 31, 2031 |
| NSS hardware | December 31, 2030 | December 31, 2031 |
| Legacy NSS systems | Case-by-case evaluation | December 31, 2033 |

NIST's Algorithmic Work (Completed August 2024):

| Standard | Algorithm | Cryptographic Basis | Status |
| --- | --- | --- | --- |
| FIPS 203 | ML-KEM (Kyber) | Lattice / Module-LWE | Approved |
| FIPS 204 | ML-DSA (Dilithium) | Lattice / Module-LWE | Approved |
| FIPS 205 | SLH-DSA (SPHINCS+) | Hash-based stateless | Approved |

**The Gap:** Policy mandates exist. Technical standards exist. But the organizational mechanism that translates requirements into testable controls — the STIG — does not.

### 1.2 The Harvest-Now-Decrypt-Later Threat Is Active Today

DoD PQC Strategy (Section 2.1 - Quantum Threat):

Adversaries capable of eventually fielding cryptographically-relevant quantum computers are actively collecting encrypted data today for future decryption. This "harvest-now, decrypt-later" (HNDL) attack is documented as an active collection threat against:
* National Security System communications
* Controlled Unclassified Information (CUI)
* Controlled Technical Data (CTD)

**Timeline and Risk:**
Data encrypted today with RSA-2048 or ECDSA P-256 may be decryptable within 10-15 years. The Defense Industrial Base generates this exposure daily:
* ITAR-controlled technical data transmitted over TLS
* CUI shared in acquisition programs
* Classified communications with long classification lifespans (often 25+ years)

---

### 1.3 The Emerging Agentic AI Attack Surface

A new dimension of PQC risk has emerged that the original CNSA 2.0 guidance did not anticipate: the deployment of agentic AI systems in NSS and DIB environments.

The NSA's May 2026 Cybersecurity Information Sheet on Model Context Protocol (U/OO/6030316-26) identified MCP as having a security posture that is "highly dependent on implementation discipline rather than protocol guarantees." Specifically, the NSA found that MCP lacks mandatory authentication, has no defined role-based access control at the protocol level, relies on optional OAuth-style bearer tokens without lifecycle management, and produces inconsistent audit logs that vary by implementation.

Joint guidance from ASD, CISA, NSA, NCSC-UK, NCSC-NZ, and the Canadian Cyber Centre (June 2026, *Agentic AI: Considerations for Cybersecurity*) categorizes agentic AI risks into five domains — privilege risks, design and configuration risks, behaviour risks, structural risks, and accountability risks — all of which have PQC-specific dimensions the guidance does not address. Specifically:
* **Identity spoofing and agent impersonation** require cryptographic agent identity; the guidance recommends this but does not specify PQC requirements.
* **Accountability risks** require tamper-evident audit logs; the guidance does not specify the cryptographic standard for that tamper-evidence.
* **Structural risks** from inter-agent communication require authenticated channels; the guidance does not address quantum-safe authentication.

These gaps create a specific PQC exposure: agentic AI systems in NSS contexts may meet behavioral security recommendations while remaining cryptographically vulnerable to harvest-now-decrypt-later attacks on their inter-agent communications and audit records.

---

### 1.4 What a PQC STIG Needs to Address

A DoD-style PQC STIG must provide auditable answers to eight operational questions:

| # | Question | Scope |
| --- | --- | --- |
| 1 | What algorithms are approved? | FIPS 203/204/205 catalog, CNSA 2.0 requirements |
| 2 | What key sizes and parameter sets are required? | ML-DSA-65 minimum, ML-KEM-768 minimum |
| 3 | How must keys be stored and protected? | HSM requirements, key lifecycle, encrypted storage |
| 4 | How must hybrid cryptography be implemented during transition? | Classical + PQC simultaneously (2026-2031) |
| 5 | What implementation pitfalls create vulnerabilities? | Timing side-channels, non-constant-time operations |
| 6 | How must certificates and chains be validated in a PQC world? | Hybrid PKI, algorithm agility, OID validation |
| 7 | How must AI agent identity be cryptographically anchored? | PQC agent certificates, attestation |
| 8 | How must agentic AI audit trails be cryptographically protected? | Tamper-evident Flight Recorder standards |

---

## 2. PQC-01-STIG-V1R1: Twelve Core Controls

### Control Format

Each control follows DISA STIG structure and conventions:

| Field | Description |
| --- | --- |
| **Finding ID** | PQC-01-XXXXXX namespace |
| **Severity** | CAT I (High) · CAT II (Medium) · CAT III (Low) |
| **NIST 800-53** | Mapped Rev 5 control family |
| **CCI** | Control Correlation Identifier |
| **Check** | How to audit the control — specific, testable criteria |
| **PASS** | Explicit pass condition |
| **Fix** | Remediation action |

---

### CAT I — HIGH SEVERITY

#### PQC-01-000010 — CNSA 2.0 Algorithm Approval

| Field | Value |
| --- | --- |
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding**

The system uses cryptographic algorithms not approved under CNSA 2.0 in a National Security System context.

**Check**

Verify that all cryptographic operations conform to the following requirements:

| Operation | Required Algorithm | Prohibited Algorithms |
| --- | --- | --- |
| Symmetric encryption | AES-256 | AES-128, 3DES, RC4 |
| Digital signatures | ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) | RSA, ECDSA, Ed25519 |
| Key encapsulation | ML-KEM (FIPS 203) | ECDH, X25519, DH, RSA-OAEP |
| Hashing | SHA-384 or SHA-512 | SHA-1, MD5, SHA-256 |

* **PASS:** All production cryptographic operations use algorithms from the Required column. Configuration files, TLS negotiation lists, and IKE proposals contain no entries from the Prohibited column.
* **FAIL:** Any prohibited algorithm appears in a production NSS context, regardless of whether it is actively negotiated.

**Fix**

Replace all non-approved algorithms. CNSA 2.0 does not permit algorithm negotiation to fall back to pre-quantum algorithms in production NSS contexts. Disable any TLS, IKE, or application-layer configurations that allow downgrade to prohibited cipher suites. Where backward compatibility with legacy partners is required, document a formal exception with a transition timeline approved by the AO.

---

#### PQC-01-000020 — ML-DSA Minimum Key Strength

| Field | Value |
| --- | --- |
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding**

The system implements ML-DSA below the ML-DSA-65 (NIST Security Level 3) parameter set.

**Check**

Verify that all digital signature operations use ML-DSA-65 or ML-DSA-87:

| Parameter Set | Security Level | Public Key | Signature Size | NSS Approved |
| --- | --- | --- | --- | --- |
| ML-DSA-44 | NIST Level 2 | 1,312 bytes | 2,420 bytes | **No** |
| ML-DSA-65 | NIST Level 3 | 1,952 bytes | 3,309 bytes | **Yes** |
| ML-DSA-87 | NIST Level 5 | 2,592 bytes | 4,627 bytes | **Yes** |

* **PASS:** All public keys are 1,952 bytes (ML-DSA-65) or 2,592 bytes (ML-DSA-87). Signature verification logic rejects key material at smaller sizes.
* **FAIL:** Public key material is 1,312 bytes, indicating ML-DSA-44. Any system accepting or generating ML-DSA-44 signatures in production is a finding.

**Fix**

Upgrade to the ML-DSA-65 parameter set at minimum. ML-DSA-44 provides only NIST Level 2 security, below the threat model for NSS environments. Reissue all key material and certificates at the correct parameter set. Update all certificate validation logic to reject ML-DSA-44 material.

---

#### PQC-01-000030 — ML-KEM Minimum Encapsulation Strength

| Field | Value |
| --- | --- |
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding**

The system uses ML-KEM-512 for key encapsulation rather than ML-KEM-768 or ML-KEM-1024.

**Check**

Verify that key encapsulation mechanisms use the ML-KEM-768 or ML-KEM-1024 parameter set:

| Parameter Set | Security Level | Public Key | Ciphertext | NSS Approved |
| --- | --- | --- | --- | --- |
| ML-KEM-512 | NIST Level 1 | 800 bytes | 768 bytes | **No** |
| ML-KEM-768 | NIST Level 3 | 1,184 bytes | 1,088 bytes | **Yes** |
| ML-KEM-1024 | NIST Level 5 | 1,568 bytes | 1,568 bytes | **Yes** |

* **PASS:** Observed ciphertext sizes are 1,088 bytes (ML-KEM-768) or 1,568 bytes (ML-KEM-1024). The system rejects encapsulation attempts using 768-byte ciphertexts.
* **FAIL:** Ciphertext is 768 bytes, indicating ML-KEM-512.

**Fix**

Migrate to ML-KEM-768 at minimum. Add ciphertext size validation in integration tests to prevent silent parameter downgrade during library updates.

---

#### PQC-01-000040 — Non-Constant-Time Implementation Detection

| Field | Value |
| --- | --- |
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding**

The system's PQC implementation uses operations that are not constant-time, creating timing side-channel vulnerabilities.

**Check**

Verify that the PQC library in use is a NIST-validated, constant-time implementation. Inspect the SBOM for known non-constant-time PQC implementations.

Approved constant-time libraries include:
* **liboqs** (Open Quantum Safe) — validated constant-time ML-KEM and ML-DSA
* **Cloudflare CIRCL** — Go implementation with constant-time guarantees
* **BoringSSL / AWS-LC** — FIPS-mode builds with validated PQC

* **PASS:** The system uses a listed constant-time library or an equivalent with documented timing-attack mitigation. SBOM reflects no homegrown or unvalidated PQC implementations in the cryptographic path.
* **FAIL:** The system uses a home-grown PQC implementation, a research prototype, or a library without documented constant-time guarantees in its production cryptographic path.

**Fix**

Replace non-validated PQC implementations with a library from the approved list. Do not use reference implementations from NIST specification documents directly in production — these are designed for readability, not timing-attack resistance.

---

#### PQC-01-000050 — Deprecated or Broken PQC Algorithm Detection

| Field | Value |
| --- | --- |
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-13 — Cryptographic Protection |
| **CCI** | CCI-002450 |

**Finding**

The system uses post-quantum algorithms that were not selected by NIST or have been cryptanalytically broken.

**Check**

Scan the system for the following deprecated or broken PQC algorithms:

| Algorithm | Status | Reason |
| --- | --- | --- |
| SIKE / SIDH | Broken | Cryptanalytically broken 2022 (Castryck-Decru attack) |
| Rainbow | Broken | Cryptanalytically broken 2022 (Beullens attack) |
| GeMSS | Not selected | NIST Round 3 alternate — not standardized |
| NTRU Prime | Not selected | Not selected in final NIST standardization |

* **PASS:** No deprecated or broken PQC algorithms appear in the system's cryptographic configuration, SBOM, or TLS/IKE negotiation lists.
* **FAIL:** SIKE, Rainbow, or any cryptanalytically broken algorithm is present. This is a non-negotiable finding requiring immediate remediation.

**Fix**

Remove all deprecated or broken PQC algorithms immediately. For SIKE and Rainbow, these algorithms are broken and provide zero security. Replace with NIST-standardized ML-KEM (FIPS 203) for key encapsulation and ML-DSA (FIPS 204) for signatures.

---

### CAT II — MEDIUM SEVERITY

#### PQC-01-000060 — Hybrid Cryptography During Transition

| Field | Value |
| --- | --- |
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SC-8 — Transmission Confidentiality and Integrity |
| **CCI** | CCI-002418 |

**Finding**

The system in active PQC transition has not implemented hybrid (classical + PQC) key exchange, leaving it exposed to classical attacks if the PQC implementation has defects.

**Check**

For systems undergoing transition (2026–2031), verify that critical communications implement hybrid key exchange:

| Classical Component | PQC Component | Hybrid Construction |
| --- | --- | --- |
| X25519 | ML-KEM-768 | X25519+ML-KEM-768 (IETF hybrid KEM) |
| P-384 ECDH | ML-KEM-1024 | P-384+ML-KEM-1024 |

* **PASS:** All critical communications use an IETF-compliant hybrid key exchange during the transition period, OR the system has completed formal transition validation and the AO has formally accepted pure PQC-only operation for that specific system boundary.
* **FAIL:** A system in active transition uses pure PQC-only key exchange without AO-accepted transition documentation, OR uses pure classical-only key exchange with no PQC component.

**Fix**

Implement hybrid key exchange for all critical communications during the transition period. Do not remove classical algorithms until PQC deployment is operationally validated and the transition is formally accepted by the authorizing official.

---

#### PQC-01-000070 — PQC Key Material Storage

| Field | Value |
| --- | --- |
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SC-12 — Cryptographic Key Establishment and Management |
| **CCI** | CCI-000162 |

**Finding**

PQC private key material is stored in plaintext, in software-only key stores, or in locations accessible to unprivileged processes.

**Check**

Verify that ML-DSA and ML-KEM private keys are protected at rest:
* For systems with available HSM: keys must reside in FIPS 140-3 Level 3 or higher HSMs
* For systems without HSM: keys must be encrypted with AES-256-GCM, with the KEK stored separately
* Private key files must not be world-readable (Unix permissions 600 or stricter)

* **PASS:** Private key material is in an HSM, or encrypted with a separately-stored KEK, and file permissions are 600 or stricter.
* **FAIL:** Private key material is in plaintext files, software keystores with no additional encryption, or files with permissions broader than 600.

**Fix**

Migrate private keys to a FIPS 140-3 Level 3 HSM where available. Where HSM is unavailable, encrypt key material with AES-256-GCM and store the KEK in a separate protected location. Restrict file permissions immediately.

---

#### PQC-01-000080 — PQC Certificate Chain Validation

| Field | Value |
| --- | --- |
| **Severity** | CAT II — Medium |
| **NIST 800-53** | SC-17 — Public Key Infrastructure Certificates |
| **CCI** | CCI-002460 |

**Finding**

The system does not validate PQC algorithm identifiers in X.509 certificate chains, or accepts chains that mix approved and non-approved PQC algorithms.

**Check**

Verify that certificate validation logic recognizes ML-DSA OIDs, enforces the ML-DSA-65 minimum parameter set for all certificates in the chain, and rejects certificates using prohibited algorithms except in documented hybrid configurations.

Relevant OIDs:
* ML-DSA-44: `2.16.840.1.101.3.4.3.17`
* ML-DSA-65: `2.16.840.1.101.3.4.3.18`
* ML-DSA-87: `2.16.840.1.101.3.4.3.19`

* **PASS:** The system correctly validates ML-DSA certificate chains, enforces minimum parameter sets, and rejects prohibited algorithms except in documented hybrid configurations.
* **FAIL:** The system accepts certificates signed with RSA or ECDSA in a non-hybrid context, or silently ignores PQC algorithm identifier validation errors.

**Fix**

Update TLS and PKI validation libraries to support PQC OIDs. Test certificate chain validation explicitly with both correct and intentionally malformed PQC certificate chains.

---

#### PQC-01-000090 — Cryptographic Asset Inventory (CBOM)

| Field | Value |
| --- | --- |
| **Severity** | CAT II — Medium |
| **NIST 800-53** | PL-8 — Information Security Architecture |
| **CCI** | CCI-000069 |

**Finding**

The system does not maintain a current Cryptography Bill of Materials (CBOM) documenting all cryptographic assets, their locations, and their quantum-vulnerability classification.

**Check**

Verify that a CBOM exists and contains at minimum:
* All cryptographic libraries in use (name, version, algorithm support)
* All certificates (location, algorithm, key size, expiration)
* All symmetric keys in use (algorithm, length, storage location)
* Quantum-vulnerability classification for each entry (VULNERABLE / TRANSITIONAL / QUANTUM-SAFE)
* Last-updated date within 90 days

* **PASS:** A CBOM exists, is current (updated within 90 days), and documents all cryptographic assets with quantum-risk classification.
* **FAIL:** CBOM is missing, outdated (>90 days), incomplete, or lacks quantum-risk classification.

**Fix**

Generate a CBOM using a recognized tool. Establish a process to update the CBOM on software changes and at least quarterly. Format in CycloneDX 1.6 or newer for interoperability.

---

## Control PQC-01-000090: Deep Dive & Technical Standard

| Field | Value |
| --- | --- |
| **Control Identifier** | PQC-01-000090 — Cryptographic Asset Inventory (CBOM) |
| **Severity Level** | CAT II — Medium *(Elevated to CAT I for NSS/CUI handling long-term strategic classification data)* |
| **NIST SP 800-53 Rev 5** | PL-8 (Info Security Architecture), SA-3 (System Development Life Cycle), CM-8 (Information System Component Inventory) |
| **DISA CCI** | CCI-000069, CCI-000389, CCI-002450 |
| **CMMC v2.0 Mapping** | CA.L2-3.12.1 (Security Assessments), CM.L2-3.4.1 (System Component Inventory) |
| **DoD RMF Tier** | Tier 3 (System Level) / Continuous Authorization Baseline |

Because the Cryptography Bill of Materials (CBOM) is the foundational dependency for all other eleven PQC STIG controls—and serves as the primary artifact requested during Authorizing Official (AO) reviews and C3PAO CMMC assessments—this expanded control framework provides the exact architectural specs, machine-readable schemas, policy-as-code enforcement rules, and assessment procedures needed to operationalize PQC-01-000090.

### 1. Expanded System Scope & Boundaries

A compliant CBOM must discover and catalog cryptographic primitives across six operational domains within the system boundary:

```
[System Boundary]
 ├── 1. Codebase & Dependencies ──► Static Cryptographic APIs, Vendors, OpenSSL, BouncyCastle
 ├── 2. Network Transports ───────► In-transit Handshakes, TLS 1.3, IPsec, SSH, mTLS, QUIC
 ├── 3. Data-at-Rest Storage ─────► DB Column Encryption, LUKS/BitLocker, AES-GCM-256 Storage Keys
 ├── 4. Hardware Security ────────► HSM Cryptographic Endpoints, TPMs, KMS Key Identifiers
 ├── 5. PKI & Trust Chains ───────► Certificates, CA Issuers, OIDs, SANs, Intermediate Anchors
 └── 6. Identity & Access ────────► HMAC Session Tokens, Kerberos Tickets, Passkey Algorithms
```

### 2. Machine-Readable Format Specification (CycloneDX 1.6 / OWASP Standard)

To meet DISA STIG requirements for programmatic assessment, all CBOM exports must be formatted in **CycloneDX v1.6** (or newer) using the native `cryptoAssets` object schema.

#### Standard CBOM JSON Structure (`cbom.json`)

```json
{
 "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
 "bomFormat": "CycloneDX",
 "specVersion": "1.6",
 "version": 1,
 "metadata": {
   "timestamp": "2026-07-25T00:00:00Z",
   "tools": [
     {
       "vendor": "SecRed Knowledge",
       "name": "PQC-STIG-Scanner",
       "version": "2.4.0"
     }
   ],
   "component": {
     "type": "application",
     "name": "NSS-Core-Gateway",
     "version": "4.1.0"
   }
 },
 "components": [
   {
     "type": "crypto-asset",
     "bom-ref": "crypto-asset-ml-kem-768",
     "name": "ML-KEM-768",
     "cryptoProperties": {
       "assetType": "algorithm",
       "algorithmProperties": {
         "primitive": "kem",
         "parameterSet": "768",
         "nistQuantumSecurityLevel": 3,
         "cryptoFunctions": ["keyEncapsulation"]
       },
       "oid": "2.16.840.1.101.3.4.4.2"
     }
   },
   {
     "type": "crypto-asset",
     "bom-ref": "crypto-asset-rsa2048",
     "name": "RSA-2048-Sign",
     "cryptoProperties": {
       "assetType": "algorithm",
       "algorithmProperties": {
         "primitive": "signature",
         "parameterSet": "2048",
         "nistQuantumSecurityLevel": 0,
         "cryptoFunctions": ["digitalSignature"]
       }
     }
   }
 ],
 "declarations": {
   "assessments": [
     {
       "boms": [
         {
           "ref": "crypto-asset-rsa2048",
           "conformance": {
             "score": 0.0,
             "rationale": "RSA-2048 is flagged as VULNERABLE under CNSA 2.0 / DoD PQC Strategy."
           }
         }
       ]
     }
   ]
 }
}
```

### 3. Comprehensive Fix Execution Protocol

#### Phase A: Automated Discovery Engine Setup

1. **Static Analysis (SAST):** Integrate SAST AST engines into CI/CD build steps to analyze binaries, native libraries (`.so`, `.dll`), and code repositories for cryptographic calls (e.g., `EVP_PKEY_Init`, `java.security.Signature`).
2. **Dynamic Endpoint Scanning (DAST):** Execute active interface scans against running containers, APIs, and microservices to trace ephemeral handshake choices (TLS 1.2/1.3 cipher negotiation, key exchange parameters).
3. **Key and Certificate Inventory Automation:** Connect directly to Cloud KMS, Hardware Security Modules (HSMs), local OS trust stores, and enterprise PKI platforms (e.g., Sectigo, HashiCorp Vault) to extract active certificates, keys, serials, and OIDs.

#### Phase B: Classification & Risk Mapping

Every discovered primitive must be evaluated against the DoD Post-Quantum Cryptography Strategy and CNSA 2.0 matrix:

| Cryptographic Primitive | CNSA 2.0 Status | CBOM Classification | Required Action |
| --- | --- | --- | --- |
| **RSA-2048 / RSA-4096** | Prohibited for NSS | VULNERABLE | Generate transition plan; migrate to ML-DSA-65/87 |
| **ECDSA P-256 / P-384** | Deprecated | VULNERABLE | Replace with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) |
| **ECDH (X25519 / P-256)** | Deprecated | VULNERABLE | Transition to ML-KEM-768/1024 |
| **X25519 + ML-KEM-768** | Approved Transition | TRANSITIONAL | Retain during hybrid deployment phase (2026–2031) |
| **ML-KEM-768 / 1024** | Fully Approved | QUANTUM-SAFE | Production target (FIPS 203) |
| **ML-DSA-65 / 87** | Fully Approved | QUANTUM-SAFE | Production target (FIPS 204) |
| **AES-256-GCM** | Fully Approved | QUANTUM-SAFE | Retain (symmetric standard) |

#### Phase C: Policy-as-Code Enforcement (CI/CD Quality Gates)

Configure CI/CD build tools and ASPM engines (e.g., `cyclonedx-cli` or OPA policy engines) to audit generated CBOMs against system rules.

##### Open Policy Agent (OPA) Rule for PQC CBOM Validation (`pqc_stig.rego`)

```rego
package pqc.stig.cbom

default allow = false

# Reject build if any component has a NIST Quantum Level of 0 (Quantum Vulnerable)
deny[msg] {
  some i
  input.components[i].type == "crypto-asset"
  input.components[i].cryptoProperties.algorithmProperties.nistQuantumSecurityLevel == 0
  msg := sprintf("PQC STIG VIOLATION: Quantum-vulnerable crypto asset found: %v", [input.components[i].name])
}

# Require valid CBOM generation timestamp within 90 days
deny[msg] {
  import future.keywords.in
  now_ns := time.now_ns()
  bom_time := time.parse_rfc3339_ns(input.metadata.timestamp)
  max_age_ns := ((90 * 24) * 3600) * 1000000000 # 90 Days in nanoseconds
  now_ns - bom_time > max_age_ns
  msg := "PQC STIG VIOLATION: CBOM artifact exceeds 90-day validity threshold."
}
```

### 4. Assessor Audit & Verification Guide

When an auditor, C3PAO assessor, or AO evaluates PQC-01-000090, they will execute the following steps:

```
[Auditor Verification Path]
 ├── Step 1: Request active CBOM JSON file and examine schema compliance (CycloneDX v1.6+).
 ├── Step 2: Validate timestamp (must be <= 90 days from evaluation date).
 ├── Step 3: Sample 10 random endpoints/source files and verify they exist in the CBOM.
 ├── Step 4: Verify presence of 'VULNERABLE' entries in System Security Plan (SSP) POA&M.
 └── Step 5: Check CI/CD integration logs to verify automated build-blocking rules exist.
```

* **Pass Criteria:**
  * System maintains a valid, machine-readable CBOM artifact generated within the last 90 days.
  * 100% of cryptographic libraries, certificates, and endpoints sampled during live testing are reflected accurately in the CBOM.
  * Every primitive classified as VULNERABLE has a corresponding remediation entry in the Plan of Action and Milestones (POA&M) targeting a complete migration prior to December 31, 2031.
* **Fail Criteria:**
  * CBOM is missing, provided as an unstructured text document/spreadsheet, or older than 90 days.
  * Live network traffic contains cipher suites (e.g., `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`) not documented in the CBOM.
  * No risk classification (VULNERABLE, TRANSITIONAL, QUANTUM-SAFE) is assigned to inventoried items.

---

## 3. Agentic AI and MCP PQC Controls

### 3.1 Why Agentic AI Requires PQC-Specific Controls

The NSA's May 2026 Cybersecurity Information Sheet on MCP (U/OO/6030316-26) identified a critical insight: MCP reverses the familiar client-server trust model. In MCP deployments, servers may query and execute actions *for* clients rather than responding to them. This inversion creates attack paths that classical security frameworks were not designed to address — and that PQC policy has not yet reached.

Joint guidance from ASD, CISA, NSA, and allied Five Eyes cyber agencies (June 2026, *Agentic AI: Considerations for Cybersecurity*) identified five categories of agentic AI risk, several of which have specific PQC dimensions:

* **The accountability gap is the PQC exposure.** When an AI agent takes an action in an NSS context — invoking a tool, accessing CUI, making a compliance decision — that action generates an audit record. If that audit record is signed only with RSA or ECDSA, a harvest-now-decrypt-later adversary can collect it today and later prove the record is forged. The cryptographic integrity of agentic AI audit trails must survive the quantum transition.
* **The identity gap is the PQC exposure.** The joint Five Eyes guidance recommends that "each agent [be treated] as a distinct principal, a cryptographically anchored identity with its own unique keys or certificates" and that "agents authenticate to services and to one another using secret keys or tokens." Neither recommendation specifies PQC requirements. In an NSS context, agent identity keys signed with classical algorithms are vulnerable to the same harvest-now-decrypt-later attacks as any other key material.
* **The MCP message signing gap is the PQC exposure.** The NSA found that MCP "currently relies on transport layer encryption (e.g., TLS)" but "the protocol itself cannot enforce or verify encryption and is unaware of message integrity." The NSA recommended extending MCP with "cryptographic signatures directly within the JSON payload." In an NSS context, those signatures must use ML-DSA, not RSA or ECDSA.

The five controls in this section address these three gaps directly. They are formatted consistently with Section 2 controls and use the PQC-01-A namespace to distinguish them as agentic AI-specific.

---

### 3.2 MCP-Specific PQC Controls

#### PQC-01-A00010 — AI Agent Identity Cryptographic Anchoring

| Field | Value |
| --- | --- |
| **Severity** | CAT I — High |
| **NIST 800-53** | IA-3 — Device Identification and Authentication |
| **CCI** | CCI-001958 |
| **Related Guidance** | Five Eyes Joint Guidance §Identity management |

**Finding**

AI agents deployed in NSS or CUI environments authenticate to services and to each other using classical cryptographic credentials (RSA, ECDSA, Ed25519) that are vulnerable to harvest-now-decrypt-later attacks on stored agent-to-agent communications.

**Check**

For each AI agent deployed in the system:
1. Inspect the agent identity certificate or key material.
2. Verify the signing algorithm is ML-DSA-65 or ML-DSA-87 (FIPS 204).
3. Verify the agent identity key is stored in a FIPS 140-3 Level 3 HSM or equivalent protected store.
4. Verify that inter-agent authentication uses mutual TLS with ML-DSA certificates.
5. Verify that agent identity certificates include a defined expiration not exceeding 365 days.

* **PASS:** All agent identity certificates use ML-DSA-65 or ML-DSA-87, are stored in a protected key store meeting PQC-01-000070 requirements, and inter-agent mTLS uses ML-DSA certificates with expiration no greater than 365 days.
* **FAIL:** Any agent identity certificate uses RSA, ECDSA, or Ed25519. Any agent identity key is stored in an unprotected software keystore. Any inter-agent TLS session uses classical certificates.

**Fix**

Reissue all agent identity certificates using ML-DSA-65 at minimum. Deploy agent identity keys in FIPS 140-3 Level 3 HSMs where available. Update all inter-agent mTLS configurations to use ML-DSA certificates. Implement certificate lifecycle automation to enforce the 365-day expiration.

---

#### PQC-01-A00020 — MCP Message Integrity Signing

| Field | Value |
| --- | --- |
| **Severity** | CAT I — High |
| **NIST 800-53** | SC-8 — Transmission Confidentiality and Integrity |
| **CCI** | CCI-002418 |
| **Related Guidance** | NSA U/OO/6030316-26 §Sign and verify MCP messages |

**Finding**

MCP messages between agents, between agents and tools, and between agents and external services are not signed at the application layer with PQC signatures, relying solely on transport-layer TLS that the MCP protocol cannot verify or enforce.

**Check**

Inspect the MCP implementation for:
1. Presence of a `signature` field in MCP JSON payloads.
2. Signature algorithm — must be ML-DSA-65 (FIPS 204) or stronger.
3. Presence of an `expires_at` timestamp in each signed payload (must not exceed 5 minutes from `issued_at`).
4. Presence of a `nonce` or `message_id` field enabling replay detection.
5. Signature verification logic on the receiving side that rejects expired or previously-seen nonces.

* **PASS:** All MCP messages in NSS-touching workflows include ML-DSA-65 payload signatures with expiration timestamps not exceeding 5 minutes and nonces verified against a seen-nonce store.
* **FAIL:** MCP messages rely on transport-layer TLS only, with no application-layer signature. Any application-layer signature uses RSA or ECDSA. Expiration timestamps are absent or exceed 5 minutes.

**Fix**

Extend the MCP implementation to embed ML-DSA-65 signatures in each JSON-RPC payload. Implement a seen-nonce store at each MCP server to enable replay detection. Set expiration to no more than 5 minutes. Validate signatures and expiration on receipt before executing any tool invocation.

---

#### PQC-01-A00030 — Agentic AI Audit Trail Cryptographic Integrity

| Field | Value |
| --- | --- |
| **Severity** | CAT II — Medium |
| **NIST 800-53** | AU-9 — Protection of Audit Information |
| **CCI** | CCI-001350 |
| **Related Guidance** | Five Eyes Joint Guidance §Accountability risks; NSA U/OO/6030316-26 §Instrument for logging and detection |

**Finding**

Agentic AI systems in the environment do not produce cryptographically-signed audit records of agent actions, tool invocations, and decision steps, making the audit trail subject to undetectable tampering and vulnerable to retroactive forgery once quantum computing is available.

**Check**

For each agentic AI system:
1. Verify that each agent action (tool call, API invocation, decision branch, sub-agent spawn) produces a structured log entry.
2. Verify that log entries are signed with ML-DSA-65 (FIPS 204).
3. Verify that log entries include: agent identity, action type, tool name (if applicable), input parameters, output summary, timestamp, and parent action ID enabling causal chain reconstruction.
4. Verify that the log store is append-only (no delete or update operations available to the agent or its runtime).
5. Verify that log entry hashes use SHA-384 or SHA-512.

* **PASS:** All agent actions produce ML-DSA-65-signed log entries with the required fields, written to an append-only log store, with SHA-384 or SHA-512 hashes.
* **FAIL:** Agent actions produce unsigned log entries, or entries signed with classical algorithms, or entries missing causal chain fields. The log store permits deletion or modification by agent processes.

**Fix**

Implement a PQC-signed Flight Recorder for all agentic AI operations in NSS contexts. Deploy the log store in an append-only configuration with write access restricted to the logging subsystem. Instrument all agent runtimes to emit structured log events for every action. Use ML-DSA-65 for log entry signing and SHA-384 or SHA-512 for content hashing.

---

#### PQC-01-A00040 — Tool Execution Cryptographic Authorization

| Field | Value |
| --- | --- |
| **Severity** | CAT II — Medium |
| **NIST 800-53** | AC-3 — Access Enforcement |
| **CCI** | CCI-000213 |
| **Related Guidance** | NSA U/OO/6030316-26 §Constrain and sandbox tool execution; Five Eyes Joint Guidance §Privilege risks |

**Finding**

Tool invocations by AI agents in NSS or CUI environments are authorized through classical access control mechanisms that do not produce quantum-resistant authorization evidence, preventing post-quantum verification of tool execution authorization records.

**Check**

For each tool invocable by AI agents:
1. Verify that tool invocation requires a signed authorization token issued by a central authorization service.
2. Verify that authorization tokens are signed with ML-DSA-65 (FIPS 204).
3. Verify that authorization tokens are scoped to: specific agent identity, specific tool name, specific parameter constraints, and expiration not exceeding 15 minutes.
4. Verify that the receiving tool validates the authorization token before execution.
5. Verify that the authorization service logs each token issuance with a ML-DSA-65-signed record.

* **PASS:** All tool invocations require ML-DSA-65-signed, time-bound authorization tokens scoped to agent identity and tool name, validated by the tool before execution.
* **FAIL:** Tool invocations use classical signed tokens, unsigned tokens, or no token-based authorization at all. Tokens lack expiration. Tokens are not scoped to specific tools or agents.

**Fix**

Deploy a central authorization service that issues ML-DSA-65-signed, time-bound authorization tokens for each tool invocation. Update tool execution logic to validate tokens before processing. Implement token expiration no greater than 15 minutes. Log all token issuances with ML-DSA-65-signed records.

---

#### PQC-01-A00050 — MCP Server Cryptographic Identity Verification

| Field | Value |
| --- | --- |
| **Severity** | CAT II — Medium |
| **NIST 800-53** | IA-9 — Service Identification and Authentication |
| **CCI** | CCI-001967 |
| **Related Guidance** | NSA U/OO/6030316-26 §Choose supported MCP projects; §Design for boundaries |

**Finding**

AI agents connect to MCP servers without verifying the server's cryptographic identity using PQC certificates, creating exposure to tool name collision attacks and MCP server impersonation.

**Check**

For each MCP server in the environment:
1. Verify that the MCP server presents an ML-DSA-65 certificate for client authentication.
2. Verify that AI agent MCP clients validate the server certificate against a trusted registry before establishing a session.
3. Verify that the trusted registry is maintained by the ISSO and reviewed at least monthly for unauthorized additions.
4. Verify that the agent MCP client rejects connections to servers not present in the trusted registry, regardless of tool description content.
5. Verify that the MCP server certificate includes the approved tool name list as a certificate extension, preventing undisclosed capability changes.

* **PASS:** All MCP servers present ML-DSA-65 certificates, clients validate against an ISSO-maintained trusted registry, and certificates include approved tool lists that cannot change without certificate reissuance.
* **FAIL:** MCP servers use RSA or ECDSA certificates, clients do not validate server identity before establishing sessions, or no trusted registry of approved MCP servers exists.

**Fix**

Issue ML-DSA-65 certificates to all MCP servers. Implement client-side certificate validation against an ISSO-maintained trusted registry before any MCP session is established. Include approved tool name lists as certificate extensions so that capability changes require explicit certificate reissuance and registry update. Alert the ISSO when a connection is attempted to an unregistered server.

---

## 4. Compliance Assessment Methodology

### 4.1 Control Mapping Framework

The control framework chains controls across multiple security schemas to provide unified assurance:

$$\text{DISA STIG} \longleftrightarrow \text{CCI} \longleftrightarrow \text{NIST 800-53 Rev 5} \longleftrightarrow \text{NIST 800-171/172} \longleftrightarrow \text{CMMC v2.0}$$

This structural mapping ensures that resolving a single STIG finding provides compliance evidence across multiple audits.

### 4.2 Assessment Approach

1. **Step 1 — Cryptographic Asset Inventory:** Collect all cryptographic libraries, certificates, symmetric keys, enclaves, and active AI agent runtimes/MCP servers.
2. **Step 2 — Algorithm Classification:** Match assets against the CNSA 2.0 and PQC guidelines in Section 2 and Section 3.
3. **Step 3 — Control-by-Control Assessment:** Apply check criteria and record compliance status (PASS / FAIL / NOT APPLICABLE).
4. **Step 4 — Prioritized Remediation:** Address CAT I findings first.

---

## 5. KHEPRA MCP Server: Reference Implementation

The reference implementation demonstrate that all 17 controls are practically implementable in production systems. The KHEPRA Protocol provides the technical mechanism for securing enclaves using:
* **Symbol-Bound PQC Key Derivation (ASAF primitives):** Deterministic seeding of lattice parameters with symbolic descriptors, anchoring certificates directly to compliance frameworks (NIST, CMMC).
* **Immutable DAG Causal Attestation Chain:** Every agent action, tool invocation, and compliance decision is logged as a content-addressed node in a directed acyclic graph, ensuring audit records include cryptographic verification of parent action causal relationships.
* **ASAF Trust Score Binding:** Cryptographically anchoring numerical trust scores and compliance tags to signed task constraints and execution records.

---

## 6. Conclusion and Next Steps

PQC-01-STIG-V1R1 establishes a testable PQC compliance checklist (12 core controls + 5 agentic controls) grounded in official DoD strategic goals, the NSA MCP security advisory, and joint multi-agency agentic AI security guidance.

---

## 7. References

### Authoritative DoD & NIST Sources

#### DoD Strategic Guidance
* DoD Chief Information Officer. "Post-Quantum Cryptography Strategy." April 2026.  
  [https://dodcio.defense.gov/Portals/0/Documents/Library/DoW-PQC-Strategy.pdf](https://dodcio.defense.gov/Portals/0/Documents/Library/DoW-PQC-Strategy.pdf)
* NSA Commercial National Security Algorithm (CNSA) 2.0 Advisory. September 2022.

#### NIST Standards
* NIST. "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (Kyber)." August 2024.  
  [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
* NIST. "FIPS 204: Module-Lattice-Based Digital Signature Standard (Dilithium)." August 2024.  
  [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
* NIST. "FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)." August 2024.  
  [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
* NIST SP 800-53 Rev 5. "Security and Privacy Controls for Information Systems and Organizations." December 2022.  
  [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
* NIST SP 800-208. "Recommendation for Stateful Hash-Based Signature Schemes." August 2024.  
  [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)
* NIST AI Agent Standards Initiative. February 2026.  
  [https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure)

### DISA & Compliance Frameworks
* DISA. "Security Technical Implementation Guides (STIGs)." Current.  
  [https://public.cyber.mil/stigs/](https://public.cyber.mil/stigs/)
* DISA. "Cybersecurity Maturity Model Certification (CMMC) 2.0." 2023.  
  [https://dodcio.defense.gov/CMMC/](https://dodcio.defense.gov/CMMC/)

### Agentic AI & MCP Guidance
* Five Eyes Multi-Agency Joint Guidance (NSA, CISA, ASD, NCSC-UK, NCSC-NZ, Cyber Centre Canada). "Agentic AI: Considerations for Cybersecurity." June 2026.  
  [https://www.cisa.gov/resources-tools/resources/agentic-ai-considerations-cybersecurity](https://www.cisa.gov/resources-tools/resources/agentic-ai-considerations-cybersecurity)
* NSA Cybersecurity Information Sheet. "Model Context Protocol Security (U/OO/6030316-26)." May 2026.

### Open Standards
* RFC 9370: "Hybrid Post-Quantum Key Encapsulation Method (PQC KEM) for TLS 1.3."  
  [https://tools.ietf.org/html/rfc9370](https://tools.ietf.org/html/rfc9370)

### Implementation References
* **liboqs-C:** Open-source C library for quantum-safe algorithms.  
  [https://github.com/open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
* **Cloudflare CIRCL:** Go library with constant-time PQC implementations.  
  [https://github.com/cloudflare/circl](https://github.com/cloudflare/circl)
* **BoringSSL:** Google's fork of OpenSSL with PQC support.  
  [https://boringssl.googlesource.com/](https://boringssl.googlesource.com/)

### Control Mapping Methodology
* **GitHub Repository:** [https://github.com/EtherVerseCodeMate/giza-cyber-shield](https://github.com/EtherVerseCodeMate/giza-cyber-shield)
* **Code Location:** `pkg/stig/database.go:468–473` (`RowCount()` function)
* **Methodology:** `pkg/stig/database.go:32` (unique key indexing)
* **Video Walkthrough:** [https://youtu.be/Y1rTf8XUz4s](https://youtu.be/Y1rTf8XUz4s)

---

## Appendix A: Control Mapping Deduplication Methodology

### A.1 Data Lineage

The 25,185 mapping count is derived from production code with runtime validation:

1. **Source tables loaded at compile time:**
   * `STIG_CCI_Map.csv`: 28,588 rows (loaded; 51 malformed rows rejected from 28,639 file rows)
   * `CCI_to_NIST53.csv`: 7,433 rows
   * `NIST53_to_171.csv`: 123 rows
   * `NIST53_to_172.csv`: 24 rows
2. **Deduplication by unique STIG ID:**
   * **Input:** 28,588 raw STIG $\to$ CCI rows
   * **Process:** Unique index keyed on STIG control ID
   * **Output:** 25,185 unique STIG identifiers
   * **Removed:** 3,403 duplicate STIG ID rows
3. **Cross-framework chaining:**
   * Each unique STIG $\to$ CCI $\to$ NIST 800-53 $\to$ NIST 800-171/172 $\to$ CMMC
   * **Result:** Single control expressible across five frameworks

### A.2 Code Evidence

Canonical count assertion:
* **File:** `pkg/stig/database.go`
* **Lines:** 468–473 (`RowCount()` function)
* **Returns:** 25,185

Validation at runtime:
* Regression test fails build if embedded dataset absent
* Load-time integrity checks guard against placeholder files
* Every scan validates count before reporting compliance status

### A.3 Reproducibility

To verify independently (repo set as private):

```bash
git clone https://github.com/EtherVerseCodeMate/giza-cyber-shield.git
cd giza-cyber-shield
grep -n "RowCount\|25185" pkg/stig/database.go
```

Video methodology demonstration:  
[https://youtu.be/Y1rTf8XUz4s](https://youtu.be/Y1rTf8XUz4s)

---

**End of Document**

**Classification:** UNCLASSIFIED

**Ready for:** DISA STIG development, C3PAO interim guidance, federal compliance assessment

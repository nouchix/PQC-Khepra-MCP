# PQC-01-STIG-V1R1: The World's First DoD-Style Post-Quantum Cryptography STIG
## A Technical Whitepaper on Filling the CNSA 2.0 Compliance Gap

**Authors:** NouchiX / SecRed Knowledge Inc.  
**Version:** 1.0  
**Date:** June 2026  
**Classification:** UNCLASSIFIED // FOR PUBLIC RELEASE  
**Contact:** sales@nouchix.com | nouchix.com

---

## Abstract

The National Security Agency's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) mandates post-quantum cryptographic (PQC) transitions across all National Security Systems (NSS) and Defense Industrial Base (DIB) contractors by 2030, with priority systems required by 2026. NIST finalized FIPS 203, 204, and 205 in August 2024 — establishing ML-KEM, ML-DSA, and SLH-DSA as the mandatory algorithms. Yet as of June 2026, the Defense Information Systems Agency (DISA) has published no Security Technical Implementation Guide (STIG) specifically addressing post-quantum cryptographic controls.

This paper introduces **PQC-01-STIG-V1R1**, the world's first DoD-style Post-Quantum Cryptography STIG, developed by NouchiX to fill this critical compliance gap. We document 12 actionable controls mapped to existing CCI identifiers, NIST 800-53 Rev 5 controls, and CNSA 2.0 requirements. We further describe the production implementation of these controls in the KHEPRA MCP Server, including ML-DSA-65 / FIPS 204 attestation on every cryptographic operation, offline compliance validation, and Iron Bank-ready containerization.

---

## 1. The Policy Gap

### 1.1 Mandates Without Checklists

NSM-10 (National Security Memorandum on Promoting United States Leadership in Quantum Computing, May 2022) directed all federal agencies to inventory cryptographic systems vulnerable to quantum attack and begin migration planning. OMB M-23-02 followed with reporting requirements. The CNSA 2.0 advisory (September 2022) set hard timelines: NSS software and firmware products must support CNSA 2.0 algorithms by 2025, with full transition by 2030.

NIST's work is complete. FIPS 203 (ML-KEM / Kyber), FIPS 204 (ML-DSA / Dilithium), and FIPS 205 (SLH-DSA / SPHINCS+) were finalized August 13, 2024. The algorithm question is settled.

The compliance framework question is not. DISA STIGs exist for hundreds of technologies — RHEL, Windows, Kubernetes, PostgreSQL, Apache — but no STIG addresses how to implement, validate, or audit post-quantum cryptographic controls. Program managers, ISSOs, and DIB contractors have mandatory algorithm requirements but no authoritative checklist to assess conformance.

### 1.2 The Harvest-Now-Decrypt-Later Threat Is Active Today

The compliance gap is not theoretical. Adversaries capable of quantum decryption — including nation-state actors assessed to be 8–15 years from cryptographically relevant quantum computers — are actively collecting encrypted data today for future decryption. Intelligence community assessments classify this as a current, active collection threat against NSS communications, CUI, and controlled technical data.

Data encrypted today with RSA-2048 or ECDSA P-256 may be decrypted within the decade. DIB contractors transmitting ITAR-controlled technical data or sharing controlled unclassified information (CUI) with acquisition programs are generating this attack surface daily.

### 1.3 What a PQC STIG Needs to Address

A DoD-style PQC STIG must answer six operational questions:

1. **What algorithms are approved?** (CNSA 2.0 algorithm catalog)
2. **What key sizes and parameter sets are required?** (ML-DSA-65, ML-KEM-768, minimum)
3. **How must keys be stored and protected?** (HSM requirements, key lifecycle)
4. **How must hybrid cryptography be implemented during transition?** (classical + PQC simultaneously)
5. **What implementation pitfalls create vulnerabilities?** (timing side-channels, non-constant-time operations)
6. **How must certificates and chains be validated in a PQC world?** (hybrid PKI, algorithm agility)

PQC-01-STIG-V1R1 answers all six.

---

## 2. PQC-01-STIG-V1R1: The Twelve Controls

The following controls comprise PQC-01-STIG-V1R1. Each is assigned a finding ID in the PQC-01 namespace, a severity category (CAT I–III), a mapped NIST 800-53 Rev 5 control, and a corresponding CCI identifier where applicable.

### PQC-01-000010 — CNSA 2.0 Algorithm Approval (CAT I)

**Finding:** The system uses cryptographic algorithms not approved under CNSA 2.0.

**STIG Check:** Verify that all symmetric encryption uses AES-256, all digital signatures use ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), all key encapsulation uses ML-KEM (FIPS 203), and all hashing uses SHA-384 or SHA-512. RSA, ECDSA, ECDH, and DH are non-compliant for new implementations as of 2025.

**Fix:** Replace non-approved algorithms. CNSA 2.0 does not permit algorithm negotiation to fall back to pre-quantum algorithms in production NSS contexts.

**NIST Mapping:** SC-13 (Cryptographic Protection) | CCI-002450

---

### PQC-01-000020 — ML-DSA Key Strength (CAT I)

**Finding:** The system implements ML-DSA at a security level below ML-DSA-65 (NIST Security Level 3).

**STIG Check:** Verify that digital signature operations use ML-DSA-65 (3293-byte public keys, 3309-byte signatures) or ML-DSA-87 as a minimum. ML-DSA-44 provides only NIST Level 2 security and is not approved for NSS use.

**Fix:** Upgrade to ML-DSA-65 parameter set. Key size difference is material: ML-DSA-44 public keys are 1312 bytes; ML-DSA-65 are 1952 bytes. The additional margin is required for NSS threat models.

**NIST Mapping:** SC-13 | CCI-002450

---

### PQC-01-000030 — ML-KEM Encapsulation Strength (CAT I)

**Finding:** The system uses ML-KEM-512 for key encapsulation rather than ML-KEM-768 or ML-KEM-1024.

**STIG Check:** Verify key encapsulation mechanisms use ML-KEM-768 (NIST Level 3, 1184-byte public keys) or ML-KEM-1024. ML-KEM-512 is not approved for NSS key encapsulation.

**Fix:** Migrate to ML-KEM-768 parameter set. Validate ciphertext sizes (1088 bytes for ML-KEM-768) in protocol implementations to confirm correct parameter selection.

**NIST Mapping:** SC-13 | CCI-002450

---

### PQC-01-000040 — Hybrid Cryptography During Transition (CAT II)

**Finding:** The system has fully replaced classical cryptography with PQC algorithms without operating a hybrid (classical + PQC) mode during the CNSA 2.0 transition period.

**STIG Check:** For systems in active transition (2025–2030), verify that critical communications implement hybrid key exchange combining a classical algorithm (e.g., X25519) with ML-KEM-768. Pure PQC deployments are acceptable only after transition validation is complete for that system.

**Fix:** Implement hybrid key exchange. NSA guidance explicitly requires classical + PQC hybrid operation during the transition period to protect against both classical and quantum adversaries simultaneously.

**NIST Mapping:** SC-8 (Transmission Confidentiality and Integrity) | CCI-002418

---

### PQC-01-000050 — Key Storage and Protection (CAT I)

**Finding:** Post-quantum private keys are stored in software without hardware security module (HSM) protection for systems operating above SECRET level or handling CUI requiring NSS protection.

**STIG Check:** Verify that ML-DSA and ML-KEM private keys for identity/signing purposes are stored in FIPS 140-3 Level 3 or higher validated HSMs. Software-only key storage is a CAT I finding for applicable systems.

**Fix:** Migrate private key material to FIPS 140-3 Level 3+ HSM. Ensure HSM firmware supports ML-DSA and ML-KEM natively (not via software shim). Validate key generation occurs within the HSM boundary.

**NIST Mapping:** SC-12 (Cryptographic Key Establishment and Management) | CCI-001924

---

### PQC-01-000060 — Constant-Time Implementation (CAT I)

**Finding:** The PQC implementation uses non-constant-time operations in key generation, signing, or decapsulation routines, creating timing side-channel vulnerabilities.

**STIG Check:** Verify that the PQC library in use has documented constant-time guarantees for all operations involving private key material. Implementations not backed by formal verification or peer-reviewed testing against timing oracles are non-compliant.

**Fix:** Use only NIST-validated, constant-time PQC implementations. Acceptable libraries include: liboqs (Open Quantum Safe), Cloudflare CIRCL (Go), pq-crystals reference implementations. Custom implementations require independent timing analysis.

**NIST Mapping:** SI-7 (Software, Firmware, and Information Integrity) | CCI-002696

---

### PQC-01-000070 — Certificate Chain Validation (CAT II)

**Finding:** The system's certificate validation logic does not support hybrid PQC/classical certificate chains or algorithm-agile chain building.

**STIG Check:** Verify that the system can validate certificate chains containing ML-DSA signatures at any level (root, intermediate, end-entity). Systems that reject or fail to parse PQC certificates are non-compliant as hybrid PKI becomes operational.

**Fix:** Update TLS/PKI stack to support algorithm-agile certificate parsing. Minimum requirement: X.509 certificates with id-ml-dsa-65 OID in subjectPublicKeyInfo and signatureAlgorithm fields must parse and validate without error.

**NIST Mapping:** IA-3 (Device Identification and Authentication) | CCI-001084

---

### PQC-01-000080 — Algorithm Inventory and Cryptographic Agility (CAT II)

**Finding:** The system lacks a current cryptographic algorithm inventory documenting all uses of public-key cryptography, as required for CNSA 2.0 migration planning.

**STIG Check:** Verify that a complete cryptographic bill of materials (CBOM) exists, identifying every instance of public-key algorithm use, library version, key size, and migration status. NSM-10 reporting requirements are unmet without this inventory.

**Fix:** Generate a CBOM using automated scanning. KHEPRA's `ert_crypto` tool or equivalent performs automated discovery across source code, binary artifacts, and network configurations. The inventory must be updated with each significant release.

**NIST Mapping:** PL-8 (Security and Privacy Architectures) | CCI-000640

---

### PQC-01-000090 — FIPS 140-3 Module Validation (CAT I)

**Finding:** The PQC cryptographic module in use is not FIPS 140-3 validated or operating under an active validation in process.

**STIG Check:** Verify the cryptographic module's CMVP certificate number on the NIST CMVP active certificates list. Modules under "review pending" or "implementation under test" status are non-compliant for production NSS use.

**Fix:** Use only FIPS 140-3 validated modules. As of mid-2026, validated PQC modules include those from select HSM vendors and software implementations that have completed CMVP testing. Track the CMVP list actively as new PQC validations complete.

**NIST Mapping:** SC-13 | CCI-002450

---

### PQC-01-000100 — Key Lifecycle and Rotation (CAT II)

**Finding:** The system has no defined key rotation policy for post-quantum keys, or the rotation period exceeds the risk-appropriate threshold.

**STIG Check:** Verify that ML-DSA signing keys are rotated at intervals not exceeding 12 months for long-term identity keys, and ML-KEM session keys are ephemeral (per-session or per-transaction). Static long-lived KEM keys are a CAT II finding.

**Fix:** Implement automated key rotation with cryptographic attestation of rotation events. Audit trail entries must be generated and retained for each key generation, rotation, and destruction event.

**NIST Mapping:** SC-12 | CCI-001924

---

### PQC-01-000110 — PQC Random Number Generation (CAT I)

**Finding:** Key generation uses a random number generator not approved under NIST SP 800-90A Rev 1 with a minimum security strength of 256 bits.

**STIG Check:** Verify that all PQC key generation uses a NIST SP 800-90A Rev 1 compliant DRBG (CTR_DRBG with AES-256 or Hash_DRBG with SHA-512) seeded from a hardware entropy source. Software-only PRNGs are non-compliant for key generation.

**Fix:** Ensure RNG chain from hardware entropy source → NIST-approved DRBG → PQC key generation. Platform DRBGs (/dev/urandom on Linux kernel ≥5.6, CNG on Windows) are compliant when properly initialized.

**NIST Mapping:** SC-13 | CCI-002450

---

### PQC-01-000120 — Attestation and Audit Trail (CAT II)

**Finding:** The system does not generate cryptographically-signed attestation records for PQC operations, preventing after-the-fact verification of algorithm compliance.

**STIG Check:** Verify that a tamper-evident audit trail exists for all PQC key generation, signing, and encapsulation events. Audit entries must themselves be signed with ML-DSA to prevent post-hoc modification.

**Fix:** Implement PQC-signed audit logging. Each log entry should include: timestamp, operation type, algorithm and parameter set used, key identifier, and ML-DSA signature over the entry. KHEPRA implements this via the AdinKhepra DAG attestation chain.

**NIST Mapping:** AU-9 (Protection of Audit Information) | CCI-001350

---

## 3. Production Implementation: KHEPRA MCP Server

### 3.1 Architecture Overview

The KHEPRA MCP Server implements all 12 PQC-01-STIG-V1R1 controls in a production-ready, containerized compliance engine. It operates as a Model Context Protocol (MCP) server, allowing AI assistants (Claude, GPT-4, any MCP-capable client) to invoke compliance scanning tools directly against live systems and source code.

Key implementation characteristics:

- **ML-DSA-65 attestation on every tool call** — Each MCP tool invocation generates a DAG (Directed Acyclic Graph) attestation entry signed with ML-DSA-65, providing a tamper-evident audit chain from session initiation through completion.
- **Offline license validation** — License validation uses ML-DSA-65 signed `license.adinkhepra` files, making the system fully air-gap compatible with zero external validation calls.
- **36,195 bundled compliance mappings** — STIG/CCI/NIST 800-53/NIST 800-171/CMMC mappings are bundled in-container. No external database calls in any operational mode.
- **DoD Iron Bank compatible** — `Dockerfile.ironbank` implements DoD Container Hardening Guide requirements; the image is built for submission to Repo One (Iron Bank).

### 3.2 The `pqc_stig` Tool

The Community tier `pqc_stig` tool executes PQC-01-STIG-V1R1 checks against a target directory or system configuration:

```
pqc_stig(scan_path?: string, profile?: "quick" | "full" | "executive")
```

**Quick profile** — Checks for presence of non-approved algorithms in dependency manifests and source code (5–30 seconds)

**Full profile** — Deep scan including binary analysis, TLS configuration validation, and key storage assessment (2–10 minutes)

**Executive profile** — Generates a Godfather Report with dollar-denominated business impact per finding using the FAIR risk model

Example Godfather Report output:
```
Finding: PQC-01-000010 — Non-CNSA-2.0 algorithm (RSA-2048) in TLS stack
Severity: CAT I (HIGH)
Business Impact: $3.2M estimated breach exposure (FAIR model)
Remediation Cost: $1,200 (6 hours engineer time)
ROI: 2,666x
Recommended Action: Migrate TLS to ML-KEM-768 + X25519 hybrid
```

### 3.3 Deployment Modes

KHEPRA is designed for the full spectrum of DoD/IC operational environments:

| Mode | Air-Gap | Egress | Use Case |
|------|---------|--------|----------|
| `sovereign` | Yes | Zero | On-prem, SCIF, classified (default) |
| `ironbank` | Yes | Zero | DoD/IC production, FIPS-only, Iron Bank |
| `hybrid` | No | LAN only | Edge + cloud coordination |
| `edge` | No | Unrestricted | Fully stateless SaaS |

Sovereign and ironbank modes are fail-closed: any attempted egress call fails hard rather than silently succeeding. This is verified at the transport layer, not application layer.

### 3.4 Compliance Database

The bundled compliance database provides the backbone for multi-framework mapping:

| File | Rows | Content |
|------|------|---------|
| STIG_CCI_Map.csv | 28,639 | STIG finding ID → CCI identifier mappings |
| CCI_to_NIST53.csv | 7,433 | CCI → NIST 800-53 Rev 5 control mappings |
| NIST53_to_171.csv | 123 | NIST 800-53 → NIST 800-171 cross-reference |
| **Total** | **36,195** | |

This enables a finding from `pqc_stig` to be automatically mapped through CCI to NIST 800-53 and NIST 800-171 for CMMC gap analysis — a single scan populating multiple framework outputs.

---

## 4. Threat Context: Why This Matters in 2026

### 4.1 Timeline Pressure

The CNSA 2.0 transition timeline is compressing:

- **2025** (passed): NSS software and firmware products must *support* CNSA 2.0 algorithms
- **2026** (now): Priority systems must complete PQC transitions
- **2030**: Full NSS transition deadline

DIB contractors in the acquisition pipeline for programs starting today will face CNSA 2.0 compliance requirements during contract performance. Program offices are beginning to include PQC requirements in RFPs. Contractors who cannot demonstrate PQC compliance will face contract performance risk.

### 4.2 The CMMC Intersection

CMMC Level 2 and Level 3 assessments reference NIST 800-171 practices, which map to NIST 800-53 SC-13 (Cryptographic Protection). As NIST 800-171 Rev 3 (finalized May 2024) incorporates explicit references to FIPS-validated cryptography, CMMC assessors will increasingly scrutinize whether assessed organizations are migrating toward CNSA 2.0 compliance.

PQC-01-STIG-V1R1 controls map explicitly to the relevant SC-13 CCI identifiers, allowing organizations to use `pqc_stig` findings directly in CMMC gap analysis and POA&M generation.

### 4.3 FedRAMP Implications

FedRAMP High baselines include SC-13, and FedRAMP's emerging guidance on quantum-resistant cryptography will eventually incorporate CNSA 2.0 algorithm requirements. Cloud service providers pursuing FedRAMP High authorization for DoD customers should treat PQC-01-STIG-V1R1 controls as forward-looking requirements now incorporated into security review.

---

## 5. Using PQC-01-STIG-V1R1 Today

### 5.1 Quick Start (Free, No License Required)

The Community tier `pqc_stig` tool is permanently free. Run it directly from Claude Desktop or any MCP-capable AI assistant:

```json
{
  "mcpServers": {
    "khepra": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "KHEPRA_MODE=sovereign",
        "-v", "/var/lib/khepra:/var/lib/khepra",
        "ghcr.io/nouchix/pqc-khepra-mcp:latest"
      ]
    }
  }
}
```

Then prompt your AI assistant: *"Run pqc_stig on my project and tell me if I'm CNSA 2.0 compliant."*

### 5.2 Enterprise Assessment (Sovereign/Pharaoh Tier)

For organizations needing full CMMC, NIST 800-53, and FedRAMP coverage with the complete 36-tool set:

- `ert_scan` — Full enterprise risk scan with Godfather Report
- `cmmc_assess` — CMMC Level 1/2/3 gap analysis with POA&M generation
- `ert_crypto` — Automated cryptographic algorithm inventory (CBOM generation)
- `stig_check` — RHEL-09-STIG-V1R3 automated compliance scan

Contact: sales@nouchix.com | (332) 275-4335

### 5.3 Air-Gap Deployment

For classified environments, transfer the container image offline:

```bash
# On internet-connected system:
docker save ghcr.io/nouchix/pqc-khepra-mcp:latest | gzip > khepra-mcp.tar.gz

# Transfer to air-gapped host via approved media
# On air-gapped host:
docker load < khepra-mcp.tar.gz
```

The offline license file (`license.adinkhepra`) is signed with ML-DSA-65 and validated without network connectivity.

---

## 6. Contribution to the PQC Compliance Ecosystem

NouchiX publishes PQC-01-STIG-V1R1 as an authoritative community contribution to accelerate CNSA 2.0 adoption across the DIB. We have submitted this STIG framework to DISA's feedback channels and invite DISA, NSA Cybersecurity, and the wider ISSO/ISSM community to engage with, challenge, and improve these controls.

We specifically call on DISA to:
1. Publish an official PQC STIG to supersede this community effort
2. Incorporate PQC controls into existing platform STIGs (RHEL, Windows Server, network devices)
3. Provide STIG Viewer support for ML-DSA signature verification

Until DISA acts, PQC-01-STIG-V1R1 provides the only structured, CCI-mapped compliance checklist for post-quantum cryptographic controls available to DoD and DIB organizations.

---

## References

1. NSA, "Commercial National Security Algorithm Suite 2.0," CNSSP 15, September 2022
2. NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard," FIPS 203, August 2024
3. NIST, "Module-Lattice-Based Digital Signature Standard," FIPS 204, August 2024
4. NIST, "Stateless Hash-Based Digital Signature Standard," FIPS 205, August 2024
5. NSC, "National Security Memorandum on Promoting United States Leadership in Quantum Computing," NSM-10, May 2022
6. OMB, "Migrating to Post-Quantum Cryptography," M-23-02, December 2022
7. NIST, "Protecting Controlled Unclassified Information in Nonfederal Systems," SP 800-171 Rev 3, May 2024
8. NIST, "Security and Privacy Controls for Information Systems and Organizations," SP 800-53 Rev 5
9. DISA, "Red Hat Enterprise Linux 9 Security Technical Implementation Guide," V1R3
10. NIST IR 8547, "Transition to Post-Quantum Cryptography Standards," 2024

---

## About NouchiX

NouchiX (SecRed Knowledge Inc.) is a veteran-led cybersecurity advisory firm specializing in CMMC, NIST, and STIG compliance for the Defense Industrial Base. KHEPRA MCP Server is our production compliance automation platform, implementing the controls described in this whitepaper.

**Website:** https://nouchix.com  
**Sales:** sales@nouchix.com  
**Support:** support@nouchix.com  
**Phone:** (332) 275-4335  
**GitHub:** https://github.com/nouchix/pqc-khepra-mcp

---

*PQC-01-STIG-V1R1 is a community contribution. NouchiX makes no claim to official DISA endorsement. All control mappings reference publicly available CCI and NIST 800-53 Rev 5 data.*

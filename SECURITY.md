# Security Policy - AdinKhepra ASAF Engine

## Overview

AdinKhepra Attestation Security Framework (ASAF) Engine is committed to ensuring the security and integrity of our software. This policy outlines our supported versions, vulnerability reporting process, and alignment with major security frameworks including NIST 800-53, CMMC 3.0, and ISO 27001.

---

## 🔒 PROPRIETARY CRYPTOGRAPHIC ALGORITHMS - RESTRICTED RIGHTS NOTICE

**IMPORTANT LEGAL NOTICE**: This software contains proprietary post-quantum cryptographic algorithms developed by NouchiX SecRed Knowledge Inc., representing over **$45,000,000 USD** in research and development investment.

### Federal Protection

This software is protected under multiple Federal statutes:

1. **Economic Espionage Act (18 U.S.C. § 1831-1839)**
   - Trade secret protection for proprietary lattice reduction algorithms
   - Criminal penalties: Up to **$5,000,000 fine** and **10 years imprisonment**
   - Civil damages: Up to **3x actual damages** plus attorney fees

2. **DMCA Anti-Circumvention (17 U.S.C. § 1201)**
   - Prohibition on circumvention of license validation mechanisms
   - Criminal penalties: Up to **$500,000 fine** and **5 years imprisonment**

3. **DoD FAR Supplement (DFARS 252.227-7013, 252.227-7015)**
   - Restricted rights in technical data and computer software
   - Government-purpose rights with specified limitations

### PROHIBITED ACTIVITIES

The following activities are **STRICTLY PROHIBITED** and constitute breach of contract and/or Federal crimes:

❌ **Reverse Engineering**: Decompilation, disassembly, or reverse engineering of cryptographic library components
❌ **Algorithm Extraction**: Analysis, extraction, or replication of proprietary lattice reduction algorithms
❌ **License Circumvention**: Modification, bypass, or circumvention of license validation mechanisms
❌ **Unauthorized Redistribution**: Distribution of binaries outside of authorized DoD networks or installations
❌ **Signature Removal**: Removal or modification of digital signatures or copyright notices
❌ **Unauthorized Derivative Works**: Creation of derivative works without explicit written permission

### AUTHORIZED USE

This software is available under a tiered licensing model:

✅ **Community tier** — Free, no license key required. Provides `pqc_stig` and 12 core compliance tools. May be used on any system for evaluation, open-source projects, and non-commercial compliance assessment.

✅ **Sovereign tier** — License key required. Authorized for DoD networks, air-gapped / SCIF environments, and contractor-operated systems under DoD authority. Zero egress — all operations run on the operator's infrastructure with no external network calls.

✅ **Pharaoh (Iron Bank) tier** — License key required. Authorized for FedRAMP / IL4 / IL5 production deployments. FIPS 140-3 validated cryptographic path.

**Proprietary features** (Sovereign/Pharaoh) require a valid license key validated offline via ML-DSA-65 signed `license.adinkhepra` file. No external validation endpoint is contacted in sovereign or ironbank modes. Failure to present a valid license key results in automatic fallback to Community tier functionality only.

### VIOLATION CONSEQUENCES

Unauthorized use, reverse engineering, or IP theft may result in:

⚖️ **Civil Liability** (18 U.S.C. § 1836)
- Injunctive relief
- Damages up to 3x actual damages
- Attorney fees and costs
- Exemplary damages up to 2x compensatory damages

⚖️ **Criminal Prosecution** (18 U.S.C. § 1832)
- Federal felony charges
- Fines up to $5,000,000 (organizations) or $250,000 (individuals)
- Imprisonment up to 10 years
- Asset forfeiture

⚖️ **Administrative Actions**
- Contract termination
- Suspension and debarment from Federal contracting
- Referral to DoD Inspector General
- Security clearance revocation
- DCAA audit and investigation

### CONTACT INFORMATION

**Security Issues**: cybersouhimbou@secredknowledgeinc.tech (PGP key: `keys/security_contact.asc`)
**License Inquiries**: contact@nouchix.com
**Legal Department**: contact@nouchix.com

**⚠️ DO NOT** disclose proprietary algorithm details in public security reports. Report IP-sensitive issues via encrypted channels only.

---

## Supported Versions

We actively support and provide security updates for the following versions of the AdinKhepra ASAF Engine. Users are strongly encouraged to upgrade to the latest supported version to ensure protection against known vulnerabilities.

| Version | Supported          | Security Updates | Terms |
| ------- | ------------------ | ---------------- | ----- |
| 1.0.x   | :white_check_mark: | Active           | Current Release |
| < 1.0   | :x:                | None             | End of Life (EOL) |

> **Note:** "Active" means we provide bug fixes and security patches. "Critical Only" means we only patch Critical/High severity CVEs.

## Reporting a Vulnerability

We take security issues seriously and appreciate the community's efforts to improve the security of the AdinKhepra ecosystem.

### How to Report
If you discover a security vulnerability in this project, please report it privately. **Do not disclose vulnerabilities in public issues or forums.**

1.  **Email**: Send a detailed report to the Project Security Team at **cybersouhimbou@secredknowledgeinc.tech**.
### Encryption & Secure Communication
We support both standard PGP/GPG and Post-Quantum Cryptography (PQC) for secure communication.

**PGP/GPG**:
- Please use our public key located at `keys/security_contact.asc` in this repository.
- Key Fingerprint: `[Run 'gpg --fingerprint' on your key to get this]`

**Post-Quantum Verification**:
- For high-assurance communication, we use ML-DSA-65 (FIPS 204) signing keys and ML-KEM-768 (FIPS 203) for key encapsulation — in conformance with CNSA 2.0 requirements and PQC-01-STIG-V1R1 controls PQC-01-000020 and PQC-01-000030.
- Public identity keys: `keys/id_mldsa.pub` (ML-DSA-65 / FIPS 204).
- Verify our signatures using the `khepra` CLI: `khepra verify --key keys/id_mldsa.pub <file>`.

3.  **Details to Include**:
    - Project version and component (e.g., Agent, Dashboard, CLI).
    - Description of the vulnerability (e.g., XSS, RCE, Improper Authentication).
    - Steps to reproduce the issue (PoC scripts are appreciated).
    - Impact assessment (confidentiality, integrity, availability).

### Response Timeline
- **Acknowledgement**: We will acknowledge your report within **24 hours**.
- **Assessment**: We will provide an initial assessment and expected timeline for a fix within **5 business days**.
- **Resolution**: We aim to release a patch or mitigation for critical issues within **30 days** of confirmation.

## Compliance & Framework Alignment

This security policy and the AdinKhepra architecture are designed to align with the following standards, supporting our submission to the DoD Iron Bank (Repo One).

### NIST Risk Management Framework (RMF) / NIST SP 800-53
AdinKhepra employs a continuous monitoring strategy aligned with the **Monitor** step of the RMF.
- **Continuous Monitoring (CA-7)**: Our "Sonar" agent provides real-time drift detection and configuration auditing.
- **System Integrity (SI-7)**: We utilize Post-Quantum Cryptography (PQC) and DAG-based verification to ensure software and data integrity.
- **Access Control (AC-1)**: Role-based access control (RBAC) and least privilege principles are enforced in the API and Dashboard.

### Cybersecurity Maturity Model Certification (CMMC) 3.0
We target **Level 2 (Advanced)** and **Level 3 (Expert)** practices for defense contractors.
- **Audit & Accountability (AU)**: All attestation events and security state changes are cryptographically signed and logged in a tamper-evident ledger.
- **Configuration Management (CM)**: Automated drift detection ensures systems remain in a secure, approved baseline.
- **Identification & Authentication (IA)**: Strong authentication mechanisms including token-based access.

### ISO/IEC 27001:2022
- **A.8.8 Management of Technical Vulnerabilities**: This policy and our patching cadence address the management of technical vulnerabilities.
- **A.8.25 Secure Development Lifecycle**: We adhere to secure coding practices, static analysis (SAST), and dependency scanning. For detailed information on our AS-series security controls (AS02-AS06), see our [Secure Software Development Lifecycle (SSDLC)](docs/SECURE_DEVELOPMENT_LIFECYCLE.md).

## Dependencies & Supply Chain Security
- **Dependabot**: We utilize automated dependency scanning (Dependabot) to detect and remediate vulnerabilities in upstream libraries (e.g., npm, Go modules).
- **SBOM**: Software Bill of Materials (SBOM) is generated for each release to provide full transparency of our supply chain.
- **Iron Bank Compliance**: All container images are hardened according to DoD Container Hardening Guide and scanned for CVEs before submission.

## Post-Quantum Cryptography (PQC)

AdinKhepra implements NIST-finalized PQC algorithms in conformance with NSA CNSA 2.0 requirements and the controls defined in **[PQC-01-STIG-V1R1](docs/PQC-01-STIG-V1R1.md)** — the world's first DoD-style Post-Quantum Cryptography STIG, authored by NouchiX / SecRed Knowledge Inc.

| Algorithm | Standard | Role | CNSA 2.0 Approved |
|-----------|----------|------|-------------------|
| ML-DSA-65 | FIPS 204 | Digital signatures and attestation | Yes (Level 3 minimum) |
| ML-KEM-768 | FIPS 203 | Key encapsulation | Yes (Level 3 minimum) |
| AES-256-GCM | FIPS 197 | Symmetric encryption | Yes |
| SHA-384 / SHA-512 | FIPS 180-4 | Hashing | Yes |

All cryptographic operations in the ASAF attestation engine produce ML-DSA-65 signatures, providing tamper-evident audit records that are quantum-resistant against Harvest-Now-Decrypt-Later collection. The KHEPRA Protocol (USPTO #73565085, patent pending) extends ML-DSA-65 with Adinkra symbol-bound key derivation and DAG causal attestation chains, as described in PQC-01-STIG-V1R1 Section 5.

**Deprecated algorithms with zero security (remove immediately if present):**
- SIKE / SIDH — cryptanalytically broken 2022 (Castryck-Decru attack) — see PQC-01-000050
- Rainbow — cryptanalytically broken 2022 (Beullens attack) — see PQC-01-000050

Note: "CRYSTALS-Dilithium" and "CRYSTALS-Kyber" are the NIST competition names. The finalized NIST standards are ML-DSA (FIPS 204) and ML-KEM (FIPS 203) respectively. All AdinKhepra references use the finalized standard names.

---

## MCP Transport Security — Claude Code Attack Chain (Mitiga Labs, 2026-04-10)

> **PQC context:** The MCP security controls in this section address behavioral and transport-layer threats. Post-quantum cryptographic requirements for MCP deployments — including ML-DSA-65 agent identity anchoring, application-layer message signing, and PQC-signed audit trails — are defined in [PQC-01-STIG-V1R1](docs/PQC-01-STIG-V1R1.md) Section 3, controls PQC-01-A00010 through PQC-01-A00050.

### Threat Summary

A five-step supply chain attack can silently redirect Claude Code's MCP traffic through attacker-controlled infrastructure, intercepting OAuth bearer tokens. Anthropic has ruled this out of scope — no patch is planned. Full detection and response responsibility falls on us and our customers.

**Attack vector**: Malicious npm `postinstall` hook → rewrites `~/.claude.json` → proxies MCP traffic → intercepts OAuth tokens on every session load (including after rotation).

### Our Controls

| Control | Implementation | Status |
|---|---|---|
| `~/.claude.json` audit script | `scripts/check-claude-json.ps1` | ✅ Shipped |
| npm postinstall hook detection | `scripts/check-npm-integrity.sh` + `.ps1` | ✅ Shipped |
| Approved hooks allowlist | `scripts/approved-hooks.txt` | ✅ Shipped |
| MCP transport integrity checker | `src/services/MCPTransportGuard.ts` | ✅ Shipped |
| Live dashboard monitor hook | `src/khepra/hooks/useMCPSecurityMonitor.ts` | ✅ Shipped |
| Developer IR runbook | `docs/MCP_SECURITY_RUNBOOK.md` | ✅ Shipped |

### ASAF Event Taxonomy

These events are emitted by `MCPTransportGuard` to the ASAF audit trail. All entries are signed with ML-DSA-65 (FIPS 204) and written to an append-only DAG store, in conformance with PQC-01-A00030 (Agentic AI Audit Trail Cryptographic Integrity).

| Event | Trigger | Severity |
|---|---|---|
| `mcp_config_tamper` | `mcpServers` URL/command changed from canonical value | CRITICAL |
| `mcp_localhost_proxy` | `mcpServers` URL resolves to loopback address | CRITICAL |
| `claude_json_trust_flag_set` | `alreadyTrusted: true` added to an unrecognised project path | MEDIUM |
| `postinstall_hook_detected` | Unexpected lifecycle hook key found in `~/.claude.json` | CRITICAL |
| `oauth_refresh_unknown_origin` | OAuth refresh originates from IP not in user's known device set | HIGH |

### Critical IR Rule

> **⚠️ Token rotation BEFORE hook removal actively feeds the attacker.**  
> The hook reasserts on every Claude Code load and captures the new token immediately.  
> Correct sequence: **Remove hook → kill proxy → THEN rotate credentials.**

Full runbook: [docs/MCP_SECURITY_RUNBOOK.md](docs/MCP_SECURITY_RUNBOOK.md)


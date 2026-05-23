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

This software is licensed **ONLY** for use on:

✅ DoD networks with active license validation via `telemetry.souhimbou.org`
✅ Systems registered with valid DoD contract authorization
✅ Installations with cryptographically-signed machine IDs
✅ Government-owned and contractor-operated (GOCO) facilities under DoD authority

**License Validation**: Premium cryptographic features require online validation. Failure to maintain license compliance will result in automatic fallback to community edition with open-source cryptography only.

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

**Security Issues**: security@souhimbou.ai (PGP key: `keys/security_contact.asc`)
**License Inquiries**: support@souhimbou.ai
**DoD Contracting**: souhimbou.d.kone.mil@army.mil (Secret clearance)
**Legal Department**: legal@souhimbou.ai

**⚠️ DO NOT** disclose proprietary algorithm details in public security reports. Report IP-sensitive issues via encrypted channels only.

---

## Supported Versions

We actively support and provide security updates for the following versions of the AdinKhepra ASAF Engine. Users are strongly encouraged to upgrade to the latest supported version to ensure protection against known vulnerabilities.

| Version | Supported          | Security Updates | Terms |
| ------- | ------------------ | ---------------- | ----- |
| 5.1.x   | :white_check_mark: | Active           | Current Release |
| 5.0.x   | :x:                | None             | End of Life (EOL) |
| 4.0.x   | :white_check_mark: | Critical Only    | Long Term Support (LTS) |
| < 4.0   | :x:                | None             | End of Life (EOL) |

> **Note:** "Active" means we provide bug fixes and security patches. "Critical Only" means we only patch Critical/High severity CVEs.

## Reporting a Vulnerability

We take security issues seriously and appreciate the community's efforts to improve the security of the AdinKhepra ecosystem.

### How to Report
If you discover a security vulnerability in this project, please report it privately. **Do not disclose vulnerabilities in public issues or forums.**

1.  **Email**: Send a detailed report to the Project Security Team at **skone@alumni.albany.edu**.
### Encryption & Secure Communication
We support both standard PGP/GPG and Post-Quantum Cryptography (PQC) for secure communication.

**PGP/GPG**:
- Please use our public key located at `keys/security_contact.asc` in this repository.
- Key Fingerprint: `[Run 'gpg --fingerprint' on your key to get this]`

**Post-Quantum Verification**:
- For high-assurance communication, we utilize Dilithium and Kyber keys.
- Public Identity Keys: `keys/id_dilithium.pub` and `keys/regalia_kyber.pub`.
- Verify our signatures using the `khepra` CLI tools.

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
AdinKhepra proactively addresses the quantum threat by implementing **NIST-standardized PQC algorithms** (CRYSTALS-Kyber, CRYSTALS-Dilithium) for key exchange and digital signatures, ensuring long-term data protection against "Harvest Now, Decrypt Later" attacks.

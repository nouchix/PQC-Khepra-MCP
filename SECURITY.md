# Security Policy — PQC-Khepra-MCP Open-Source Kernel

## Overview

**PQC-Khepra-MCP** is committed to the highest security standards for open-source post-quantum cryptographic primitives, STIG benchmarks, and AI agent assessment tools.

---

## 🔒 Open-Source Scope & Repository Boundary

- **Open-Source Scope (`PQC-Khepra-MCP`)**: Released under Apache License 2.0. Contains open-source PQC algorithms (`pkg/adinkra`), the World's First DoD PQC STIG (`pqc_stig`), OWASP Agentic Top 10 assessment, basic asset discovery, and DISA STIG Viewer API queries.
- **Private Landing Zone (`khepra-trust-os`)**: The private monorepo containing proprietary commercial engines (AI Evidence Objects, Agent Passports, Privileged Enforcement Daemon interposition, CMMC SSP generator, and commercial key management).
- **Dependency Rule**: `khepra-trust-os` imports this public repository as a Go module. This repository **never** imports private code.

---

## Cryptographic Standards

This kernel relies on NIST post-quantum cryptographic standards:
- **Digital Signatures**: ML-DSA-65 (NIST FIPS 204)
- **Key Encapsulation**: ML-KEM-1024 (NIST FIPS 203)
- **Hash Functions**: SHA-256 / SHA3-256

---

## Vulnerability Reporting Process

If you discover a security vulnerability in this open-source repository:

1. **Email Disclosures**: Send vulnerability details to `security@souhimbou.ai` / `security@nouchix.com`.
2. **Response SLA**: Initial triage response within 48 hours.
3. **Disclosure Policy**: Coordinated vulnerability disclosure. Fix patches are published via GitHub releases.

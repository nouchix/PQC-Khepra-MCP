# KHEPRA Vulnerability Baseline — Threat Intelligence Repository

> **Generated:** June 20, 2026
> **Source:** GitHub Advanced Security (Trivy + CodeQL)
> **Scope:** `nouchix/PQC-Khepra-MCP` (main branch)
> **Total Alerts:** 112 (4 Critical, 20 High, 20+ Medium, 10 Warning, 58+ Note)
> **Status:** ACTIVE BASELINE — grows with each scan cycle

---

## Executive Summary

| Severity  | Count | Status | Blast Radius |
|-----------|-------|--------|--------------|
| 🔴 Critical | 4   | REMEDIATE NOW | Credential exposure, code injection |
| 🟠 High     | 20  | SPRINT PRIORITY | Supply chain, path traversal, XSS, crypto |
| 🟡 Medium   | 20+ | SCHEDULED | Log injection, info exposure |
| ⚪ Warning  | 10  | BACKLOG | Dead code, missing error handling |
| 📝 Note     | 58+ | TECHNICAL DEBT | Unused imports (TSX frontend) |

### KHEPRA Tool Coverage Matrix

| Tool | Detects | Remediates | Alert Coverage |
|------|---------|------------|----------------|
| `ert_scan` | ✅ SBOM + CVE | ✅ Remediation roadmap | #662-670, #647 |
| `ert_crypto` | ✅ Weak primitives | ✅ PQC migration plan | #638 |
| `ert_readiness` | ✅ NIST 800-171 gaps | ✅ Control mapping | All |
| `stig_check` | ✅ STIG compliance | ✅ CAT findings | #637, #636 |
| `secret_scan` | ✅ Hardcoded creds | ✅ Detection | #649, #648 |
| `vuln_scan` | ✅ Dependency CVEs | ✅ Fix versions | #662-670, #647 |
| `container_scan` | ✅ Dockerfile misconfig | ✅ Base image vulns | #667-671 |
| `threat_model` | ✅ STRIDE | ✅ ATT&CK mapping | All High+ |
| `ea_threat_score` | ✅ Composite scoring | ✅ CVSS-band | All |
| `ea_evolve` | ✅ Threat evolution | ✅ Optimal defense | All |
| `kasa_start` | ✅ Continuous hunting | ✅ Daily pentest | Ongoing |
| `drift_detect` | ✅ Config drift | ✅ Baseline comparison | Post-remediation |
| `dag_write` | ✅ Audit attestation | ✅ Evidence chain | All remediations |
| `owasp_agent_assess` | ✅ Agentic Top 10 | ✅ MCP-specific | #412, #636 |

---

## 🔴 CRITICAL — Remediate Immediately

### CRIT-01: GCP Service-Account Credential Exposure
| Field | Value |
|-------|-------|
| **Alerts** | #649, #648 |
| **Scanner** | Trivy |
| **Files** | `src/.../connectors/GCPConnector.tsx:229`, `src/.../discovery/SecureCredentialManager...:307` |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) |
| **CVSS** | 9.8 (Critical) |
| **NIST 800-53** | IA-5 (Authenticator Management), SC-12 (Cryptographic Key Establishment) |
| **NIST 800-171** | 3.5.10 (Store and transmit only cryptographically-protected passwords) |
| **CMMC** | IA.L2-3.5.10 |
| **MITRE ATT&CK** | T1552.001 (Unsecured Credentials: Credentials In Files) |
| **Blast Radius** | Full GCP project compromise if credential leaked via git history |
| **KHEPRA Tools** | `secret_scan` → detect, `pqc_sign` → rotate & attest |

**Remediation:**
```bash
# 1. Rotate GCP service account key immediately
# 2. Move to environment variable or Secret Manager
# 3. Scan git history for leaked credentials
# 4. Attest remediation to DAG
khepra-mcp secret_scan --target-dir src/
khepra-mcp dag_write --action "CRIT-01_GCP_CREDENTIAL_ROTATED"
```

---

### CRIT-02: Email Content Injection
| Field | Value |
|-------|-------|
| **Alerts** | #634, #633 |
| **Scanner** | CodeQL |
| **File** | `cmd/webhook/main.go:727`, `cmd/webhook/main.go:692` |
| **CWE** | CWE-93 (Improper Neutralization of CRLF Sequences — Header Injection) |
| **CVSS** | 9.1 (Critical) |
| **NIST 800-53** | SI-10 (Information Input Validation) |
| **NIST 800-171** | 3.13.6 (Deny network communications traffic by default) |
| **CMMC** | SI.L2-3.14.6 |
| **MITRE ATT&CK** | T1566.001 (Phishing: Spearphishing Attachment) |
| **Blast Radius** | Attacker-controlled email content via webhook → phishing from trusted domain |
| **KHEPRA Tools** | `ert_readiness` → map to SI-10, `owasp_agent_assess` → ASI-03 |

**Remediation:**
```go
// Sanitize all email header fields — strip CRLF
func sanitizeEmailHeader(s string) string {
    return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}
```

---

## 🟠 HIGH — Sprint Priority

### HIGH-01: containerd CRI Vulnerabilities (Supply Chain)
| Field | Value |
|-------|-------|
| **Alerts** | #669, #668, #667, #664, #663, #662, #671, #670, #666, #665 |
| **Scanner** | Trivy |
| **Files** | `go.mod:1` (dep: `containerd/containerd/v2 v2.2.4`), `usr/.../bin/khepra-mcp:1` |
| **CVEs** | CDI annotation smuggling, symlink log read, binary:// logger execution, image tag poisoning, unbounded group DoS |
| **CVSS** | 7.0–8.6 (High) |
| **NIST 800-53** | SA-11 (Developer Security Testing), SI-2 (Flaw Remediation), CM-6 (Configuration Settings) |
| **NIST 800-171** | 3.14.1 (Identify, report, and correct information and system flaws in a timely manner) |
| **CMMC** | SI.L2-3.14.1 |
| **MITRE ATT&CK** | T1195.002 (Supply Chain Compromise: Software Supply Chain) |
| **Current Version** | `containerd/containerd/v2 v2.2.4` (indirect) |
| **KHEPRA Tools** | `ert_architect` → SBOM + CVE, `vuln_scan` → fix versions, `container_scan` |

**Remediation:**
```bash
# Update containerd transitive dependency
go get github.com/containerd/containerd/v2@latest
go mod tidy
# Verify with KHEPRA
khepra-mcp vuln_scan
khepra-mcp ert_architect
```

---

### HIGH-02: golang.org/x/text DoS (ParseAcceptLanguage)
| Field | Value |
|-------|-------|
| **Alert** | #647 |
| **Scanner** | Trivy |
| **File** | `pkg/sca/testdata/tiny-project/go.mod:1` (dep: `x/text v0.3.7`) |
| **CVSS** | 7.5 |
| **NIST 800-53** | SI-2 (Flaw Remediation) |
| **Note** | Main go.mod uses `x/text v0.38.0` (fixed). Only test fixture affected. |
| **Risk** | LOW — test data only, not compiled into production binary |

**Remediation:**
```bash
# Update test fixture go.mod
cd pkg/sca/testdata/tiny-project && go get golang.org/x/text@latest
```

---

### HIGH-03: Weak Cryptographic Hashing on Sensitive Data
| Field | Value |
|-------|-------|
| **Alert** | #638 |
| **Scanner** | CodeQL |
| **File** | `pkg/adinkra/adinkra_core.go:272` |
| **CWE** | CWE-327 (Use of a Broken or Risky Cryptographic Algorithm) |
| **CVSS** | 7.5 |
| **NIST 800-53** | SC-13 (Cryptographic Protection), IA-7 (Cryptographic Module Authentication) |
| **NIST 800-171** | 3.13.11 (Employ FIPS-validated cryptography) |
| **CMMC** | SC.L2-3.13.11 |
| **MITRE ATT&CK** | T1600 (Weaken Encryption) |
| **KHEPRA Tools** | `ert_crypto` → detect weak primitives, `pqc_stig` → CNSA 2.0 compliance |

**Remediation:** Replace any SHA-1/MD5 usage with SHA-256 or SHA3-256. Verify with `ert_crypto`.

---

### HIGH-04: Disabled TLS Certificate Verification
| Field | Value |
|-------|-------|
| **Alert** | #637 |
| **Scanner** | CodeQL |
| **File** | `pkg/enumerate/network.go:819` |
| **CWE** | CWE-295 (Improper Certificate Validation) |
| **NIST 800-53** | SC-8 (Transmission Confidentiality and Integrity) |
| **MITRE ATT&CK** | T1557 (Adversary-in-the-Middle) |
| **Status** | ⚠️ INTENTIONAL — Comment at line 814: "loopback self-connection" |
| **Risk** | ACCEPTED — scoped to localhost only. Add runtime guard. |

**Remediation:**
```go
// Add explicit loopback guard
if !isLoopback(target) {
    tlsCfg.InsecureSkipVerify = false
}
```

---

### HIGH-05: Clear-Text Logging of Sensitive Information
| Field | Value |
|-------|-------|
| **Alerts** | #636, #418 |
| **Scanner** | CodeQL |
| **Files** | `pkg/mcp/router.go:240`, `pkg/gateway/layer4_control.go:271` |
| **CWE** | CWE-312 (Cleartext Storage of Sensitive Information) |
| **NIST 800-53** | AU-3 (Content of Audit Records), SI-11 (Error Handling) |
| **NIST 800-171** | 3.3.1 (Create, protect, and retain system audit records) |
| **KHEPRA Tools** | `stig_check` → AU family, DoD dual-tap logger (pkg/logging) |

**Remediation:** Route through `pkg/logging` DoD dual-tap logger with 15+ field redaction patterns.

---

### HIGH-06: Integer Type Conversion Overflow
| Field | Value |
|-------|-------|
| **Alert** | #635 |
| **Scanner** | CodeQL |
| **File** | `cmd/agent/scada_handler.go:49` |
| **CWE** | CWE-681 (Incorrect Conversion between Numeric Types) |
| **NIST 800-53** | SI-16 (Memory Protection) |
| **MITRE ATT&CK** | T1203 (Exploitation for Client Execution) |

**Remediation:** Add bounds checking before int conversion.

---

### HIGH-07: Zip Slip (Archive Path Traversal)
| Field | Value |
|-------|-------|
| **Alert** | #559 |
| **Scanner** | CodeQL |
| **File** | `pkg/drbc/restore.go:100` |
| **CWE** | CWE-22 (Path Traversal) |
| **Status** | ✅ PARTIALLY FIXED — Line 108-112 has zip slip guard, but CodeQL still flags line 100 |
| **Risk** | LOW — guard exists at lines 110-112 |

**Note:** Fix is already in place. CodeQL may need `// codeql-suppress` annotation or the check needs to be moved before `filepath.Join`.

---

### HIGH-08: Excessive Memory Allocation
| Field | Value |
|-------|-------|
| **Alert** | #556 |
| **Scanner** | CodeQL |
| **File** | `pkg/mcp/tools/nist_map_tool.go:166` |
| **CWE** | CWE-770 (Allocation of Resources Without Limits or Throttling) |
| **NIST 800-53** | SC-5 (Denial of Service Protection) |
| **MITRE ATT&CK** | T1499.004 (Application or System Exploitation) |

**Remediation:** Cap `top_k` parameter to max 50, validate before allocation.

---

### HIGH-09: Uncontrolled Path Expression (Path Injection)
| Field | Value |
|-------|-------|
| **Alerts** | #427, #426, #425, #424 |
| **Scanner** | CodeQL |
| **Files** | `pkg/scanners/horus.go:501`, `pkg/sca/syft_adapter.go:343,161`, `pkg/sca/grype_adapter.go:169` |
| **CWE** | CWE-22 (Improper Limitation of a Pathname) |
| **NIST 800-53** | AC-6 (Least Privilege), SI-10 (Information Input Validation) |
| **MITRE ATT&CK** | T1083 (File and Directory Discovery) |

**Remediation:** Sanitize and scope all file paths to allowed directories. Use `filepath.Rel` + base directory containment check.

---

### HIGH-10: Reflected Cross-Site Scripting
| Field | Value |
|-------|-------|
| **Alert** | #412 |
| **Scanner** | CodeQL |
| **File** | `pkg/api/polymorphic_engine.go:195` |
| **CWE** | CWE-79 (Cross-site Scripting) |
| **NIST 800-53** | SI-10 (Information Input Validation) |
| **MITRE ATT&CK** | T1059.007 (JavaScript) |
| **KHEPRA Tools** | `owasp_agent_assess` → agentic XSS detection |

**Remediation:** HTML-encode all user-supplied output. Use `html.EscapeString()`.

---

### HIGH-11: DOM Injection (Documentation)
| Field | Value |
|-------|-------|
| **Alerts** | #658, #657, #656, #655 |
| **Scanner** | CodeQL |
| **File** | `docs/dag-viewer.html:710,700,608,529` |
| **CWE** | CWE-79 |
| **Risk** | MEDIUM — documentation HTML, not production API surface |

**Remediation:** Replace `innerHTML` with `textContent` for user-supplied data, or use DOMPurify.

---

## 🟡 MEDIUM — Scheduled Remediation

### MED-01: Log Injection from User Input
| Field | Value |
|-------|-------|
| **Alerts** | #661, #660, #659, #646, #645, #644, #643, #642, #641, #640, #639, #589, #473, #448-440 |
| **Count** | 20+ alerts |
| **Scanner** | CodeQL |
| **Files** | `pkg/mcp/transport_http.go`, `pkg/mcp/router.go`, `pkg/ouroboros/`, `pkg/gateway/`, `cmd/webhook/main.go` |
| **CWE** | CWE-117 (Improper Output Neutralization for Logs) |
| **NIST 800-53** | AU-3, AU-8, SI-10 |
| **NIST 800-171** | 3.3.1 |
| **MITRE ATT&CK** | T1070.001 (Indicator Removal: Clear Windows Event Logs) |
| **KHEPRA Tools** | `pkg/logging` DoD dual-tap logger already has redaction — ensure all paths use it |

**Remediation:** Centralize all logging through `pkg/logging` DoD dual-tap logger. Sanitize newlines from user input before logging:
```go
func sanitizeForLog(s string) string {
    return strings.NewReplacer("\n", "\\n", "\r", "\\r").Replace(s)
}
```

---

### MED-02: Stack Trace Information Exposure
| Field | Value |
|-------|-------|
| **Alert** | #650 |
| **Scanner** | CodeQL |
| **File** | `supabase/.../generate-license/index.ts:249` |
| **CWE** | CWE-209 (Information Exposure Through Error Message) |
| **NIST 800-53** | SI-11 (Error Handling) |

---

### MED-03: containerd Medium-Severity Vulnerabilities
| Field | Value |
|-------|-------|
| **Alerts** | #671, #670, #666, #665 |
| **CVEs** | CRI checkpoint tag poisoning, unbounded group DoS |
| **Fix** | Bundled with HIGH-01 containerd update |

---

## ⚪ WARNING — Technical Debt

### WARN-01: Useless Variable Assignments
| Alerts | #536, #535 |
| Files | `pkg/mcp/sandbox.go:380`, `cmd/adinkhepra/cmd_ea.go:312` |

### WARN-02: File Handle Closed Without Error Handling
| Alert | #530 |
| File | `pkg/license/qkd_distribution.go:462` |

### WARN-03: Useless Conditionals (TSX Frontend)
| Alerts | #25, #24, #22, #21, #20, #19, #27, #26 |
| Files | Various `src/components/*.tsx` |

---

## 📝 NOTE — Unused Code (58+ alerts)

All unused variable/import alerts are in the **TSX frontend** (`src/` directory).
These are cosmetic and do not affect security posture but should be cleaned for code hygiene.

**Bulk fix:** Run ESLint auto-fix across `src/`:
```bash
npx eslint src/ --fix --rule '{"no-unused-vars": "error", "no-unused-imports": "error"}'
```

---

## NIST 800-53 Control Coverage

| Control | Description | Alerts Mapped | Status |
|---------|-------------|---------------|--------|
| **IA-5** | Authenticator Management | CRIT-01 | 🔴 |
| **SC-12** | Cryptographic Key Establishment | CRIT-01 | 🔴 |
| **SC-13** | Cryptographic Protection | HIGH-03 | 🟠 |
| **SI-2** | Flaw Remediation | HIGH-01, HIGH-02 | 🟠 |
| **SI-10** | Information Input Validation | CRIT-02, HIGH-10 | 🔴 |
| **SI-11** | Error Handling | HIGH-05, MED-02 | 🟡 |
| **SI-16** | Memory Protection | HIGH-06 | 🟠 |
| **SC-5** | Denial of Service Protection | HIGH-08 | 🟠 |
| **SC-8** | Transmission Confidentiality | HIGH-04 | 🟠 |
| **AC-6** | Least Privilege | HIGH-09 | 🟠 |
| **AU-3** | Content of Audit Records | MED-01 | 🟡 |
| **SA-11** | Developer Security Testing | HIGH-01 | 🟠 |
| **CM-6** | Configuration Settings | HIGH-01 | 🟠 |

---

## MITRE ATT&CK TTP Coverage

| TTP | Technique | Alert Group | KHEPRA Detection |
|-----|-----------|-------------|------------------|
| T1552.001 | Credentials In Files | CRIT-01 | `secret_scan` |
| T1566.001 | Spearphishing | CRIT-02 | `owasp_agent_assess` |
| T1195.002 | Supply Chain Compromise | HIGH-01 | `ert_architect`, `vuln_scan` |
| T1600 | Weaken Encryption | HIGH-03 | `ert_crypto`, `pqc_stig` |
| T1557 | Adversary-in-the-Middle | HIGH-04 | `stig_check` |
| T1059.007 | JavaScript Execution | HIGH-10, HIGH-11 | `owasp_agent_assess` |
| T1083 | File/Dir Discovery | HIGH-09 | `ert_readiness` |
| T1499.004 | Application DoS | HIGH-08 | `ea_threat_score` |
| T1203 | Client Exploitation | HIGH-06 | `vuln_scan` |
| T1070.001 | Log Tampering | MED-01 | `ouroboros_stig_eye` |

---

## Remediation Priority Queue (EA-Optimized)

The following order is optimized by the EA Kernel's threat scoring:
blast radius × exploitability × compliance impact.

| Priority | ID | Action | Effort | Impact |
|----------|----|--------|--------|--------|
| P0 | CRIT-01 | Rotate GCP creds, move to env vars | 1 hour | Eliminates credential exposure |
| P0 | CRIT-02 | Sanitize email headers in webhook | 2 hours | Blocks injection vector |
| P1 | HIGH-01 | `go get containerd@latest && go mod tidy` | 30 min | Patches 10 CVEs |
| P1 | HIGH-05 | Route logging through DoD dual-tap | 4 hours | Fixes 2 alerts + MED-01 (20) |
| P1 | HIGH-09 | Add path sanitization to SCA adapters | 3 hours | Fixes 4 path traversal alerts |
| P2 | HIGH-03 | Replace weak hash in adinkra_core.go | 1 hour | FIPS compliance |
| P2 | HIGH-10 | HTML-encode polymorphic engine output | 1 hour | Blocks XSS |
| P2 | HIGH-08 | Cap nist_map top_k parameter | 30 min | DoS protection |
| P2 | HIGH-06 | Bounds check in scada_handler.go | 30 min | Memory safety |
| P3 | HIGH-04 | Add loopback guard to TLS skip | 30 min | Defense in depth |
| P3 | HIGH-11 | DOMPurify for dag-viewer.html | 1 hour | Documentation safety |
| P3 | MED-01 | Centralize log sanitization | 4 hours | 20+ log injection fixes |
| P4 | WARN-* | Dead code cleanup | 2 hours | Code hygiene |
| P5 | NOTE-* | ESLint auto-fix unused imports | 30 min | Frontend cleanup |

---

## KASA Continuous Monitoring Plan

After baseline remediation, enable KASA for ongoing protection:

```bash
# Start autonomous agent — watches for regression
khepra-mcp kasa_start

# KASA will:
# - Vulnerability hunt: hourly (vuln_scan + ert_architect)
# - Internal pentest: daily (NIST 800-53 CA-8)
# - CMMC compliance audit: daily (cmmc_assess + stig_check)
# - EA threat evolution: weekly (ea_evolve)
# - Drift detection: on every change (drift_detect)
# - All findings → DAG-attested (ML-DSA-65 signed)
```

---

## Quantum Risk Assessment

Per `ert_crypto` and `pqc_stig` analysis:

| Primitive | Status | CNSA 2.0 | Action |
|-----------|--------|----------|--------|
| ML-DSA-65 (FIPS 204) | ✅ In use | ✅ Compliant | None |
| ML-KEM-768 (FIPS 203) | ✅ In use | ✅ Compliant | None |
| SHA-256 | ✅ In use | ✅ Compliant | None |
| SHA3-256 | ✅ In use | ✅ Compliant | None |
| AES-256-GCM | ✅ In use | ✅ Compliant | None |
| SHA-1/MD5 (if any) | ⚠️ #638 | ❌ Non-compliant | Migrate to SHA-256+ |

**CNSA 2.0 Deadline:** 2030 for National Security Systems
**KHEPRA Status:** Already PQC-native — ahead of mandate

---

## Evidence & Attestation

Every remediation action should be DAG-attested:

```bash
# After each fix, attest to the immutable DAG
khepra-mcp dag_write --action "VULN_REMEDIATED_CRIT_01" --symbol Eban
khepra-mcp dag_write --action "VULN_REMEDIATED_HIGH_01" --symbol Eban

# Export evidence package for audit
khepra-mcp khepra_export_attestation
khepra-mcp flight_export
```

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-06-20 | Antigravity + Cyber | Initial baseline from GitHub Security alerts |

---

*This document is part of the KHEPRA compliance evidence chain.*
*Every finding maps to NIST 800-53 controls, CMMC practices, and MITRE ATT&CK TTPs.*
*ML-DSA-65 signed attestation available via `dag_attestation`.*

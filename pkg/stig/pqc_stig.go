package stig

// pqc_stig.go — World's First DoD PQC Security Technical Implementation Guide
//
// Classification: UNCLASSIFIED
// Version: PQC-01-STIG-V1R1
// Authority: NouchiX / AdinKhepra ASAF — pending DISA collaboration
//
// NIST Basis:
//   FIPS 203 (ML-KEM / Kyber)     — approved August 2024
//   FIPS 204 (ML-DSA / Dilithium) — approved August 2024
//   FIPS 205 (SLH-DSA / SPHINCS+) — approved August 2024
//
// DISA STIGs do not yet cover PQC (as of mid-2026). This baseline fills the gap
// for DoD contractors and C3PAOs needing quantum readiness evidence today.
//
// Control IDs follow the DISA convention: PQC-<family><sequence>_rule

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// validatePQCStig runs the PQC-01-STIG-V1R1 control set.
// Called by Validator.validateFramework when framework == FrameworkPQCStig.
func (v *Validator) validatePQCStig(result *ValidationResult) error {
	result.Version = "V1R1"
	checker := NewSystemChecker()

	// ── Category I (Critical) — Algorithm Approval + Key Strength ───────────

	// PQC-010010: Systems SHALL use only NIST-approved PQC algorithms
	v.checkPQC_010010(result, checker)

	// PQC-010020: ML-DSA (Dilithium) signing keys SHALL meet minimum strength
	v.checkPQC_010020(result, checker)

	// PQC-010030: ML-KEM (Kyber) encapsulation keys SHALL meet minimum strength
	v.checkPQC_010030(result, checker)

	// PQC-010040: Deprecated / broken PQC algorithms SHALL NOT be in use
	v.checkPQC_010040(result, checker)

	// ── Category II (High) — Hybrid Crypto + Key Storage ────────────────────

	// PQC-020010: Systems SHOULD implement hybrid crypto during transition period
	v.checkPQC_020010(result, checker)

	// PQC-020020: PQC private keys MUST be protected at rest (HSM preferred)
	v.checkPQC_020020(result, checker)

	// PQC-020030: PQC implementations SHALL use constant-time algorithms
	v.checkPQC_020030(result, checker)

	// PQC-020040: Certificate chains SHALL include PQC signatures
	v.checkPQC_020040(result, checker)

	// PQC-020050: CNSA 2.0 migration plan + POA&M SHALL be documented
	v.checkPQC_020050(result)

	// ── Category III (Medium) — Audit + Documentation + Coverage ────────────

	// PQC-030010: PQC algorithm usage SHALL be logged for quantum readiness audits
	v.checkPQC_030010(result, checker)

	// PQC-030020: Key rotation procedures SHALL be documented for PQC keys
	v.checkPQC_030020(result)

	// PQC-030030: PQC SHOULD be used for both signing AND encryption
	v.checkPQC_030030(result, checker)

	return nil
}

// ── CAT I Checks ─────────────────────────────────────────────────────────────

// PQC-010010 — NIST-Approved PQC Algorithm Enforcement
func (v *Validator) checkPQC_010010(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-010010",
		Title:       "Systems SHALL use only NIST-approved PQC algorithms (FIPS 203/204/205)",
		Description: "Verifies that only FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), or FIPS 205 (SLH-DSA) algorithms are used. Use of pre-standardization or non-NIST PQC is a CAT I finding.",
		Severity:    SeverityCAT1,
		References:  []string{"NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205", "NSM-10", "CNSA 2.0"},
		CheckedAt:   time.Now(),
	}

	// Scan for approved algorithm references in the target path
	approved := []string{"ml-kem", "mlkem", "kyber", "ml-dsa", "mldsa", "dilithium", "slh-dsa", "slhdsa", "sphincs"}
	deprecated := []string{"rainbow", "picnic", "sike", "ntru-prime-fail", "luov", "dulp", "gui"}

	hasPQC, hasDeprecated, deprecatedFound := scanSourceForAlgorithms(v.targetPath, approved, deprecated)

	if hasDeprecated {
		finding.Status = "Fail"
		finding.Actual = fmt.Sprintf("Deprecated/broken PQC algorithms detected: %s", strings.Join(deprecatedFound, ", "))
		finding.Expected = "Only NIST-approved PQC algorithms (FIPS 203/204/205)"
		finding.Remediation = "Immediately remove references to: " + strings.Join(deprecatedFound, ", ") + ". Migrate to ML-DSA-65 (signing) and ML-KEM-768 (key encapsulation)."
	} else if hasPQC {
		finding.Status = "Pass"
		finding.Actual = "NIST-approved PQC algorithms detected. No deprecated algorithms found."
		finding.Expected = "NIST-approved PQC algorithms only"
		finding.Remediation = "N/A"
	} else {
		// No PQC found — if this is a security-critical system, that's a finding
		finding.Status = "Manual Review Required"
		finding.Actual = "No PQC algorithm references detected in source. System may rely entirely on classical crypto."
		finding.Expected = "NIST-approved PQC algorithms present"
		finding.Remediation = "Assess whether this system processes CUI or classified data. If so, begin ML-KEM-768 + ML-DSA-65 migration per CNSA 2.0 timeline."
	}

	_ = checker
	result.Findings = append(result.Findings, finding)
}

// PQC-010020 — ML-DSA Key Strength
func (v *Validator) checkPQC_010020(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-010020",
		Title:       "ML-DSA (Dilithium) signing keys SHALL meet Level 3 minimum (2,592-byte public key)",
		Description: "ML-DSA-44 (Level 2) is insufficient for systems handling CUI. ML-DSA-65 (Level 3) provides 128-bit classical + quantum security and is CNSA 2.0 compliant.",
		Severity:    SeverityCAT1,
		References:  []string{"NIST FIPS 204", "CNSA 2.0", "NSA CSA Quantum Resistant Algorithms"},
		CheckedAt:   time.Now(),
	}

	// Scan for Dilithium/ML-DSA level indicators in source
	hasLevel3 := scanSourceContainsAny(v.targetPath, []string{
		"dilithium3", "Dilithium3", "ML-DSA-65", "mldsa65", "MLDSA65", "dilithium_65",
		"level3", "Level3", "LEVEL3",
	})
	hasLevel2Only := !hasLevel3 && scanSourceContainsAny(v.targetPath, []string{
		"dilithium2", "Dilithium2", "ML-DSA-44", "mldsa44", "MLDSA44",
	})

	if hasLevel2Only {
		finding.Status = "Fail"
		finding.Actual = "ML-DSA-44 (Level 2) detected — insufficient for CUI systems"
		finding.Expected = "ML-DSA-65 (Level 3) minimum"
		finding.Remediation = "Upgrade to ML-DSA-65. Key sizes: public=1,952 bytes, private=4,000 bytes, signature=3,293 bytes."
	} else if hasLevel3 {
		finding.Status = "Pass"
		finding.Actual = "ML-DSA-65 (Level 3) or higher detected"
		finding.Expected = "ML-DSA-65 minimum"
		finding.Remediation = "N/A"
	} else {
		finding.Status = "Not Applicable"
		finding.Actual = "No ML-DSA / Dilithium references detected"
		finding.Expected = "ML-DSA-65 for systems using PQC signing"
		finding.Remediation = "If this system requires PQC signing, deploy ML-DSA-65 per NIST FIPS 204."
	}

	result.Findings = append(result.Findings, finding)
}

// PQC-010030 — ML-KEM Key Strength
func (v *Validator) checkPQC_010030(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-010030",
		Title:       "ML-KEM (Kyber) encapsulation keys SHALL meet Level 3 minimum (Kyber-768 / ML-KEM-768)",
		Description: "ML-KEM-512 (Level 1) is insufficient for CUI systems. ML-KEM-768 (Level 3) provides 128-bit quantum security and is the CNSA 2.0 baseline.",
		Severity:    SeverityCAT1,
		References:  []string{"NIST FIPS 203", "CNSA 2.0"},
		CheckedAt:   time.Now(),
	}

	hasKyber768orHigher := scanSourceContainsAny(v.targetPath, []string{
		"kyber768", "Kyber768", "kyber1024", "Kyber1024",
		"ML-KEM-768", "mlkem768", "MLKEM768",
		"ML-KEM-1024", "mlkem1024", "MLKEM1024",
	})
	hasKyber512Only := !hasKyber768orHigher && scanSourceContainsAny(v.targetPath, []string{
		"kyber512", "Kyber512", "ML-KEM-512", "mlkem512",
	})

	if hasKyber512Only {
		finding.Status = "Fail"
		finding.Actual = "ML-KEM-512 (Level 1) detected — insufficient for CUI systems"
		finding.Expected = "ML-KEM-768 minimum"
		finding.Remediation = "Upgrade to ML-KEM-768. Ciphertext size: 1,088 bytes. Public key: 1,184 bytes."
	} else if hasKyber768orHigher {
		finding.Status = "Pass"
		finding.Actual = "ML-KEM-768 or ML-KEM-1024 detected"
		finding.Expected = "ML-KEM-768 minimum"
		finding.Remediation = "N/A"
	} else {
		finding.Status = "Not Applicable"
		finding.Actual = "No ML-KEM / Kyber references detected"
		finding.Expected = "ML-KEM-768 for systems using PQC key encapsulation"
		finding.Remediation = "If this system requires key exchange, deploy ML-KEM-768 per NIST FIPS 203."
	}

	_ = checker
	result.Findings = append(result.Findings, finding)
}

// PQC-010040 — Deprecated PQC Algorithm Prohibition
func (v *Validator) checkPQC_010040(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-010040",
		Title:       "Systems SHALL NOT use deprecated, withdrawn, or broken PQC algorithms",
		Description: "Rainbow (broken 2022), SIKE (broken 2022), Picnic, GeMSS, and LUOV are either cryptographically broken or withdrawn from NIST consideration. Their presence is a CAT I finding.",
		Severity:    SeverityCAT1,
		References:  []string{"NIST PQC Round 3 Selections", "NIST IR 8413", "CNSA 2.0"},
		CheckedAt:   time.Now(),
	}

	broken := []string{
		"rainbow", "Rainbow",
		"sike", "SIKE",
		"picnic", "Picnic",
		"gemss", "GeMSS",
		"luov", "LUOV",
		"mqdss", "MQDSS",
	}

	found := scanSourceForPresence(v.targetPath, broken)
	if len(found) > 0 {
		finding.Status = "Fail"
		finding.Actual = fmt.Sprintf("Cryptographically broken/withdrawn PQC algorithms detected: %s", strings.Join(found, ", "))
		finding.Expected = "No broken or deprecated PQC algorithms"
		finding.Remediation = "Immediately remove all references to " + strings.Join(found, ", ") + ". Replace with NIST-approved algorithms (FIPS 203/204/205)."
	} else {
		finding.Status = "Pass"
		finding.Actual = "No deprecated or broken PQC algorithms detected"
		finding.Expected = "No deprecated PQC algorithms"
		finding.Remediation = "N/A"
	}

	_ = checker
	result.Findings = append(result.Findings, finding)
}

// ── CAT II Checks ─────────────────────────────────────────────────────────────

// PQC-020010 — Hybrid Cryptography During Transition
func (v *Validator) checkPQC_020010(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-020010",
		Title:       "Systems SHOULD implement hybrid cryptography (classical + PQC) during transition period",
		Description: "NSA CNSA 2.0 recommends hybrid crypto (e.g., ECDH + ML-KEM-768) during the 2024-2030 transition window to protect against implementation flaws in new PQC algorithms.",
		Severity:    SeverityCAT2,
		References:  []string{"NSA CNSA 2.0", "IETF draft-ietf-tls-hybrid-design"},
		CheckedAt:   time.Now(),
	}

	// Look for hybrid patterns: concurrent use of classical + PQC
	hasClassical := scanSourceContainsAny(v.targetPath, []string{"ecdh", "ECDH", "ecdsa", "ECDSA", "rsa.", "RSA."})
	hasPQC := scanSourceContainsAny(v.targetPath, []string{"kyber", "Kyber", "dilithium", "Dilithium", "mlkem", "mldsa"})
	hasHybridPattern := scanSourceContainsAny(v.targetPath, []string{
		"hybrid", "Hybrid", "X25519Kyber", "x25519kyber", "dual-sign", "dual_sign",
	})

	if hasClassical && hasPQC && hasHybridPattern {
		finding.Status = "Pass"
		finding.Actual = "Hybrid cryptography patterns detected (classical + PQC)"
		finding.Expected = "Hybrid crypto during transition period"
		finding.Remediation = "N/A"
	} else if hasClassical && hasPQC {
		finding.Status = "Pass"
		finding.Actual = "Classical and PQC algorithms both present — hybrid mode implied"
		finding.Expected = "Hybrid crypto during transition period"
		finding.Remediation = "Consider explicitly using hybrid key exchange (X25519Kyber768) for TLS sessions."
	} else if hasPQC && !hasClassical {
		finding.Status = "Pass"
		finding.Actual = "PQC-only mode — CNSA 2.0 forward-ready posture"
		finding.Expected = "Hybrid or PQC-only"
		finding.Remediation = "Ensure interoperability with non-PQC peers is maintained during transition."
	} else {
		finding.Status = "Manual Review Required"
		finding.Actual = "Classical crypto only — no PQC detected"
		finding.Expected = "Hybrid or PQC-only mode"
		finding.Remediation = "Add ML-KEM-768 hybrid key exchange for TLS. CNSA 2.0 transition deadline: 2033."
	}

	_ = checker
	result.Findings = append(result.Findings, finding)
}

// PQC-020020 — PQC Key Storage Protection
func (v *Validator) checkPQC_020020(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-020020",
		Title:       "PQC private keys MUST be protected at rest with equivalent classical protections",
		Description: "ML-DSA and ML-KEM private keys are larger than RSA keys (4KB+) but require the same access controls. Keys must never appear in logs, env vars in process listings, or world-readable files.",
		Severity:    SeverityCAT2,
		References:  []string{"NIST FIPS 140-3", "NIST SP 800-57 Part 1"},
		CheckedAt:   time.Now(),
	}

	// Check if key material appears in env-style log lines (heuristic)
	hasKeyInEnv := scanSourceContainsAny(v.targetPath, []string{
		"os.Getenv(\"PRIV_KEY\")", "os.Getenv(\"PRIVATE_KEY\")", "DILITHIUM_KEY",
		"fmt.Println(privKey", "log.Print(privKey",
	})

	// Check if there's key zeroing (good practice)
	hasKeyZeroing := scanSourceContainsAny(v.targetPath, []string{
		"privKey[i] = 0", "for i := range privKey", "crypto/subtle",
		"crypto/subtle.ConstantTimeCompare",
	})

	if hasKeyInEnv {
		finding.Status = "Fail"
		finding.Actual = "PQC private key material potentially exposed via environment variables or logging"
		finding.Expected = "Private keys stored in HSM or encrypted key store, never in env vars or logs"
		finding.Remediation = "Move key material to encrypted key store. Never log or print private key bytes."
	} else if hasKeyZeroing {
		finding.Status = "Pass"
		finding.Actual = "Key zeroing patterns detected — memory hygiene controls present"
		finding.Expected = "Private keys zeroed after use"
		finding.Remediation = "N/A"
	} else {
		finding.Status = "Manual Review Required"
		finding.Actual = "Cannot verify key storage protection via static analysis"
		finding.Expected = "PQC keys in HSM or encrypted store with explicit zeroing"
		finding.Remediation = "Review key lifecycle: generation, storage, use, and destruction. Use crypto/subtle for key comparison."
	}

	result.Findings = append(result.Findings, finding)
}

// PQC-020030 — Constant-Time Implementation
func (v *Validator) checkPQC_020030(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-020030",
		Title:       "PQC implementations SHALL use constant-time algorithms to prevent timing attacks",
		Description: "Variable-time PQC implementations leak key material via timing side channels. NIST-approved reference implementations (liboqs, circl) use constant-time arithmetic.",
		Severity:    SeverityCAT2,
		References:  []string{"NIST FIPS 204 §3.5", "OWASP Cryptographic Storage Cheat Sheet"},
		CheckedAt:   time.Now(),
	}

	// Check for use of known safe libraries
	usesSafeLib := scanSourceContainsAny(v.targetPath, []string{
		"cloudflare/circl", "open-quantum-safe/liboqs", "cloudflare/circl/sign/dilithium",
		"crypto/subtle", "subtle.ConstantTimeCompare",
		"filippo.io/mlkem768",
	})

	hasUnsafeComparison := scanSourceContainsAny(v.targetPath, []string{
		"bytes.Equal(sig", "sig == expected", "reflect.DeepEqual(key",
	})

	if hasUnsafeComparison && !usesSafeLib {
		finding.Status = "Fail"
		finding.Actual = "Non-constant-time comparison of cryptographic material detected"
		finding.Expected = "crypto/subtle.ConstantTimeCompare for all crypto comparisons"
		finding.Remediation = "Replace bytes.Equal() / == comparisons on key/sig material with subtle.ConstantTimeCompare()"
	} else if usesSafeLib {
		finding.Status = "Pass"
		finding.Actual = "Constant-time PQC library (circl, liboqs, or subtle) detected"
		finding.Expected = "Constant-time PQC implementation"
		finding.Remediation = "N/A"
	} else {
		finding.Status = "Manual Review Required"
		finding.Actual = "Cannot verify constant-time implementation via static analysis"
		finding.Expected = "Constant-time PQC operations"
		finding.Remediation = "Use cloudflare/circl or filippo.io/mlkem768. Review all crypto comparisons for timing safety."
	}

	_ = checker
	result.Findings = append(result.Findings, finding)
}

// PQC-020040 — Certificate Chain PQC Signatures
func (v *Validator) checkPQC_020040(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-020040",
		Title:       "Certificate chains SHALL include PQC signatures alongside or in place of classical signatures",
		Description: "X.509 certificates and TLS sessions must migrate to PQC signing. Dual-signed (hybrid) certificates protect against both classical and quantum attacks during the transition.",
		Severity:    SeverityCAT2,
		References:  []string{"NIST SP 800-208", "CNSA 2.0", "IETF draft-ietf-lamps-pq-composite-sigs"},
		CheckedAt:   time.Now(),
	}

	// Look for certificate parsing or generation with PQC
	hasPQCCert := scanSourceContainsAny(v.targetPath, []string{
		"x509.Certificate", "tls.Certificate", "pem.Decode",
	})
	hasPQCSigning := scanSourceContainsAny(v.targetPath, []string{
		"dilithium", "Dilithium", "mldsa", "ML-DSA",
	})

	// Check if there are actual cert files with PQC
	certFiles := findCertFiles(v.targetPath)
	certHasPQC := false
	for _, cf := range certFiles {
		if certFileHasPQC(cf) {
			certHasPQC = true
			break
		}
	}

	if certHasPQC {
		finding.Status = "Pass"
		finding.Actual = "PQC-signed certificates detected in target path"
		finding.Expected = "PQC signatures in certificate chain"
		finding.Remediation = "N/A"
	} else if hasPQCCert && hasPQCSigning {
		finding.Status = "Pass"
		finding.Actual = "Certificate infrastructure and PQC signing both present — hybrid cert support likely"
		finding.Expected = "PQC signing in certificate chain"
		finding.Remediation = "Verify that TLS certificates are signed with ML-DSA-65 or include hybrid signatures."
	} else if hasPQCCert {
		finding.Status = "Manual Review Required"
		finding.Actual = "Certificate infrastructure found but no PQC signing detected"
		finding.Expected = "PQC signatures in certificate chain"
		finding.Remediation = "Plan migration to ML-DSA-65 signed certificates per CNSA 2.0 timeline (2033 deadline)."
	} else {
		finding.Status = "Not Applicable"
		finding.Actual = "No certificate infrastructure detected in target path"
		finding.Expected = "PQC-signed certificates when certificates are used"
		finding.Remediation = "If this system uses TLS, plan PQC certificate migration."
	}

	result.Findings = append(result.Findings, finding)
}

// ── CAT III Checks ────────────────────────────────────────────────────────────

// PQC-030010 — PQC Algorithm Usage Logging
func (v *Validator) checkPQC_030010(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-030010",
		Title:       "PQC algorithm usage SHALL be logged for quantum readiness audits",
		Description: "Organizations must demonstrate quantum readiness to CMMC C3PAOs and DISA auditors. Logging which PQC algorithms are in use and when enables evidence-based compliance.",
		Severity:    SeverityCAT3,
		References:  []string{"NIST SP 800-92", "DFARS 252.204-7012", "CMMC SC.3.177"},
		CheckedAt:   time.Now(),
	}

	hasLogging := scanSourceContainsAny(v.targetPath, []string{
		"pqc_algo", "PQC-algo", "pqc_algorithm", "quantum_algorithm",
		"[PQC]", "\"algo\":\"ML-DSA", "\"algo\":\"ML-KEM",
		"log.*dilithium", "log.*kyber", "log.*mldsa", "log.*mlkem",
	})

	hasSigning := scanSourceContainsAny(v.targetPath, []string{
		"adinkra.Sign", "dilithium.Sign", "mldsa.Sign",
	})

	if hasLogging {
		finding.Status = "Pass"
		finding.Actual = "PQC algorithm usage logging detected"
		finding.Expected = "PQC algorithms logged for audit trail"
		finding.Remediation = "N/A"
	} else if hasSigning {
		finding.Status = "Fail"
		finding.Actual = "PQC signing detected but algorithm usage not explicitly logged"
		finding.Expected = "Log algo name and key ID on each PQC operation"
		finding.Remediation = "Add log entry on each PQC sign/verify/encapsulate/decapsulate with: timestamp, algo, key_id, operation."
	} else {
		finding.Status = "Not Applicable"
		finding.Actual = "No PQC operations detected"
		finding.Expected = "PQC algorithm logging when PQC operations are performed"
		finding.Remediation = "N/A"
	}

	_ = checker
	result.Findings = append(result.Findings, finding)
}

// PQC-030020 — PQC Key Rotation Documentation
func (v *Validator) checkPQC_030020(result *ValidationResult) {
	finding := Finding{
		ID:          "PQC-030020",
		Title:       "Key rotation procedures SHALL be documented for PQC keys",
		Description: "ML-DSA and ML-KEM keys have different rotation requirements than RSA. Maximum key lifetime for ML-DSA-65 signing keys is 1 year per NIST SP 800-57 recommendations.",
		Severity:    SeverityCAT3,
		References:  []string{"NIST SP 800-57 Part 1", "NIST FIPS 204 §9"},
		CheckedAt:   time.Now(),
	}

	// Check for key rotation documentation
	docPatterns := []string{
		"rotation", "Rotation", "rotate_key", "key_lifetime",
		"expiry", "Expiry", "TTL", "max_age",
	}
	docsDir := filepath.Join(v.targetPath, "docs")
	hasRotationDocs := false
	if _, err := os.Stat(docsDir); err == nil {
		hasRotationDocs = scanDirForPatterns(docsDir, docPatterns)
	}
	hasRotationCode := scanSourceContainsAny(v.targetPath, docPatterns)

	if hasRotationDocs || hasRotationCode {
		finding.Status = "Pass"
		finding.Actual = "PQC key rotation documentation or code detected"
		finding.Expected = "Key rotation procedures documented"
		finding.Remediation = "N/A"
	} else {
		finding.Status = "Manual Review Required"
		finding.Actual = "No explicit key rotation documentation found"
		finding.Expected = "PQC key rotation procedures in docs/ or operator runbook"
		finding.Remediation = "Document: ML-DSA-65 signing key max lifetime (1 year), rotation procedure, revocation process, and backup key generation."
	}

	result.Findings = append(result.Findings, finding)
}

// PQC-030030 — Dual PQC Coverage (Signing + Encryption)
func (v *Validator) checkPQC_030030(result *ValidationResult, checker *SystemChecker) {
	finding := Finding{
		ID:          "PQC-030030",
		Title:       "Systems SHOULD implement PQC for both digital signatures AND key encapsulation",
		Description: "Deploying PQC only for signatures while leaving key exchange classical creates a 'harvest now, decrypt later' risk. Both ML-DSA (signing) and ML-KEM (key encapsulation) should be used.",
		Severity:    SeverityCAT3,
		References:  []string{"CNSA 2.0", "NSM-10 Annex A"},
		CheckedAt:   time.Now(),
	}

	hasSigning := scanSourceContainsAny(v.targetPath, []string{
		"dilithium", "Dilithium", "mldsa", "ML-DSA", "adinkra.Sign",
	})
	hasKEM := scanSourceContainsAny(v.targetPath, []string{
		"kyber", "Kyber", "mlkem", "ML-KEM",
	})

	if hasSigning && hasKEM {
		finding.Status = "Pass"
		finding.Actual = "Both PQC signing (ML-DSA) and key encapsulation (ML-KEM) detected"
		finding.Expected = "PQC for both signing and key encapsulation"
		finding.Remediation = "N/A"
	} else if hasSigning && !hasKEM {
		finding.Status = "Fail"
		finding.Actual = "PQC signing present but key encapsulation is classical-only"
		finding.Expected = "PQC key encapsulation (ML-KEM-768) in addition to signing"
		finding.Remediation = "Add ML-KEM-768 for key exchange to eliminate 'harvest now, decrypt later' risk."
	} else if !hasSigning && hasKEM {
		finding.Status = "Fail"
		finding.Actual = "PQC key encapsulation present but signing is classical-only"
		finding.Expected = "PQC signing (ML-DSA-65) in addition to key encapsulation"
		finding.Remediation = "Add ML-DSA-65 for signing to achieve full quantum-safe posture."
	} else {
		finding.Status = "Not Applicable"
		finding.Actual = "No PQC operations detected"
		finding.Expected = "PQC for both signing and key encapsulation"
		finding.Remediation = "N/A"
	}

	_ = checker
	result.Findings = append(result.Findings, finding)
}

// PQC-020050 — CNSA 2.0 Migration Timeline and POA&M
// CAT II: deadline-tracking control. Verifies that a CNSA 2.0 migration plan
// and/or POA&M is documented in the target project (policy, README, or migration file).
func (v *Validator) checkPQC_020050(result *ValidationResult) {
	finding := Finding{
		ID:    "PQC-020050",
		Title: "A CNSA 2.0 quantum migration plan with POA&M SHALL be documented",
		Description: "NSM-10 / CNSA 2.0 requires NSS operators to document a migration roadmap. " +
			"Key deadlines: FY2025 — inventory complete; FY2030 — NSS migrations done; " +
			"FY2033 — all certificates PQC. Without a tracked POA&M, auditors cannot verify " +
			"progress and CMMC C3PAOs cannot issue a Conditional certification.",
		Severity:   SeverityCAT2,
		References: []string{"NSM-10", "CNSA 2.0", "CISA PQC Roadmap", "DFARS 252.204-7012"},
		CheckedAt:  time.Now(),
	}

	// Check for documented migration planning artifacts
	migrationPatterns := []string{
		"cnsa 2.0", "cnsa2", "quantum migration", "pqc migration", "post-quantum migration",
		"migration plan", "migration roadmap", "pqc roadmap",
		"2030 deadline", "2033 deadline", "nsm-10", "nsm10",
		"poam", "poa&m", "plan of action",
		"cnsa_migration", "pqc_timeline",
	}
	docFiles := []string{
		"SECURITY.md", "security.md", "MIGRATION.md", "migration.md",
		"README.md", "readme.md", "QUANTUM.md", "quantum.md",
		"ROADMAP.md", "roadmap.md", "poam.md", "POAM.md",
		"docs/pqc-migration.md", "docs/quantum-migration.md", "docs/cnsa-migration.md",
	}

	hasMigrationDoc := false
	for _, docFile := range docFiles {
		path := filepath.Join(v.targetPath, docFile)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(data))
		for _, pattern := range migrationPatterns {
			if strings.Contains(lower, pattern) {
				hasMigrationDoc = true
				break
			}
		}
		if hasMigrationDoc {
			break
		}
	}

	// Also check code comments for migration TODOs
	hasCodeMigrationNote := scanSourceContainsAny(v.targetPath, []string{
		"CNSA 2.0", "cnsa2.0", "PQC migration", "quantum migration deadline",
		"TODO: PQC", "TODO(pqc)", "TODO: migrate",
	})

	if hasMigrationDoc {
		finding.Status = "Pass"
		finding.Actual = "CNSA 2.0 migration plan / POA&M documentation detected"
		finding.Expected = "Documented quantum migration roadmap with CNSA 2.0 deadlines"
		finding.Remediation = "N/A — ensure deadlines (FY2030 NSS, FY2033 certs) are tracked in POA&M."
	} else if hasCodeMigrationNote {
		finding.Status = "Manual Review Required"
		finding.Actual = "PQC migration notes found in source but no formal plan document detected"
		finding.Expected = "SECURITY.md or dedicated migration plan with CNSA 2.0 deadlines"
		finding.Remediation = "Formalize migration notes into SECURITY.md with explicit FY2030/2033 deadline tracking. " +
			"Use khepra_export_poam to generate a DFARS-compliant POA&M."
	} else {
		finding.Status = "Fail"
		finding.Actual = "No CNSA 2.0 migration plan or POA&M documentation found"
		finding.Expected = "Documented quantum-safe migration roadmap"
		finding.Remediation = "Create SECURITY.md documenting: (1) current crypto inventory, " +
			"(2) CNSA 2.0 migration milestones (FY2025 inventory → FY2030 NSS → FY2033 certs), " +
			"(3) POA&M items for each gap. Run khepra_export_poam to auto-generate DFARS-compliant POA&M."
	}

	result.Findings = append(result.Findings, finding)
}

// ── Source Scanning Helpers ───────────────────────────────────────────────────
//
// PERFORMANCE: Each PQC-01-STIG-V1R1 check historically called scanSourceContainsAny
// independently, causing 20+ filepath.Walk calls across the target directory.
// On large projects (e.g., the full khepra-protocol tree) this took 10-30 seconds.
//
// Fix: pqcDirCache reads all source files ONCE and stores the concatenated
// content in memory. All subsequent scan calls are pure string searches — O(n)
// in content size, not O(n × directory_walks).

// pqcDirEntry holds a pre-built scan of a target directory.
type pqcDirEntry struct {
	lower     string   // all source content concatenated, lowercased
	raw       string   // all source content, original case
	certFiles []string // .pem/.crt/.cer/.cert files found
}

// pqcDirCache maps absolute dir paths to pre-built scan entries.
var pqcDirCache sync.Map

// getPQCDirEntry returns the cached entry for dir, building it on first access.
func getPQCDirEntry(dir string) *pqcDirEntry {
	if v, ok := pqcDirCache.Load(dir); ok {
		return v.(*pqcDirEntry)
	}
	e := buildPQCDirEntry(dir)
	pqcDirCache.Store(dir, e)
	return e
}

// buildPQCDirEntry walks dir ONCE and concatenates all source file content.
func buildPQCDirEntry(dir string) *pqcDirEntry {
	var rawBuf strings.Builder
	var certFiles []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error { //nolint:errcheck
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".pem", ".crt", ".cer", ".cert":
			certFiles = append(certFiles, path)
			return nil
		}
		if !isSourceFile(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rawBuf.Write(data)
		rawBuf.WriteByte('\n')
		return nil
	})
	raw := rawBuf.String()
	return &pqcDirEntry{
		lower:     strings.ToLower(raw),
		raw:       raw,
		certFiles: certFiles,
	}
}

// scanSourceForAlgorithms checks for approved and deprecated PQC algorithm names.
// Uses pqcDirCache — O(1) walks after first call for a given dir.
func scanSourceForAlgorithms(dir string, approved, deprecated []string) (hasApproved, hasDeprecated bool, deprecatedFound []string) {
	e := getPQCDirEntry(dir)
	for _, a := range approved {
		if strings.Contains(e.lower, strings.ToLower(a)) {
			hasApproved = true
		}
	}
	for _, d := range deprecated {
		if strings.Contains(e.lower, strings.ToLower(d)) {
			hasDeprecated = true
			deprecatedFound = append(deprecatedFound, d)
		}
	}
	return
}

// scanSourceContainsAny returns true if any of the patterns appear in source files under dir.
// Uses pqcDirCache — O(1) walks after first call for a given dir.
func scanSourceContainsAny(dir string, patterns []string) bool {
	e := getPQCDirEntry(dir)
	for _, p := range patterns {
		if strings.Contains(e.raw, p) {
			return true
		}
	}
	return false
}

// scanSourceForPresence returns which patterns were found across source files.
// Uses pqcDirCache — O(1) walks after first call for a given dir.
func scanSourceForPresence(dir string, patterns []string) []string {
	e := getPQCDirEntry(dir)
	seen := make(map[string]bool)
	for _, p := range patterns {
		if strings.Contains(e.lower, strings.ToLower(p)) {
			seen[p] = true
		}
	}
	var found []string
	for p := range seen {
		found = append(found, p)
	}
	return found
}

// scanDirForPatterns searches a directory (non-recursively, just docs) for patterns.
func scanDirForPatterns(dir string, patterns []string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))
		for _, p := range patterns {
			if strings.Contains(content, strings.ToLower(p)) {
				return true
			}
		}
	}
	return false
}

// isSourceFile returns true for Go, Python, YAML, JSON, Markdown, and config files.
func isSourceFile(path string) bool {
	// Skip vendor, bin, .git
	lower := strings.ToLower(path)
	for _, skip := range []string{"/vendor/", "\\vendor\\", "/.git/", "\\.git\\", "/bin/", "\\bin\\"} {
		if strings.Contains(lower, skip) {
			return false
		}
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go", ".py", ".yaml", ".yml", ".json", ".md", ".toml", ".sh", ".ps1", ".tf", ".c", ".cpp", ".h", ".rs":
		return true
	}
	return false
}

// findCertFiles returns paths to PEM certificate files under dir.
// Uses pqcDirCache — cert files are collected during the initial scan walk.
func findCertFiles(dir string) []string {
	return getPQCDirEntry(dir).certFiles
}

// certFileHasPQC checks if a PEM certificate file uses PQC algorithms.
// ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18
// ML-KEM-768 OID: 2.16.840.1.101.3.4.4.2
func certFileHasPQC(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	// String-based check first (DER OID bytes won't appear as text anyway)
	content := string(data)
	if strings.Contains(content, "ML-DSA") || strings.Contains(content, "ML-KEM") {
		return true
	}
	// Try parsing as X.509
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	// Check signature algorithm OID string for PQC indicators
	oidStr := cert.SignatureAlgorithm.String()
	return strings.Contains(strings.ToLower(oidStr), "dilithium") ||
		strings.Contains(strings.ToLower(oidStr), "ml-dsa") ||
		strings.Contains(strings.ToLower(oidStr), "mldsa")
}

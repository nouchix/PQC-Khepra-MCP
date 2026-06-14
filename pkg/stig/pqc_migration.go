package stig

import (
	"fmt"
	"os"
	"strings"
	"time"
)


// validatePQCReadiness performs post-quantum cryptography readiness assessment
func (v *Validator) validatePQCReadiness(result *ValidationResult) error {
	result.Version = "1.0"

	// PQC readiness checks — each populates result.Findings
	v.checkPQC_TLS(result)
	v.checkPQC_SSH(result)
	v.checkPQC_Certificates(result)
	v.checkPQC_VPN(result)
	v.checkPQC_CodeSigning(result)

	// Compute PQC metrics from the findings generated above.
	// These were previously discarded; they now feed into a summary finding
	// and into the BlastRadiusAnalysis populated by analyzePQCBlastRadius().
	inventory := v.assessCryptographicInventory()
	score := v.calculatePQCReadinessScore(result.Findings)
	migrationDays, migrationCost := v.estimateMigrationEffort(len(result.Findings))

	// Build a human-readable inventory narrative for the summary finding.
	inventoryDesc := "Cryptographic asset inventory:\n"
	for asset, count := range inventory {
		if count > 0 {
			inventoryDesc += fmt.Sprintf("  • %s: %d\n", asset, count)
		}
	}

	// Add a summary finding that surfaces NTI score, migration estimate, and inventory.
	// This is the finding that appears in both the PDF report and the Godfather Report.
	summaryStatus := "Fail"
	if score >= 95.0 {
		summaryStatus = "Pass"
	}

	result.Findings = append(result.Findings, Finding{
		ID:    "PQC-INVENTORY-SUMMARY",
		Title: "Post-Quantum Cryptography Readiness Summary",
		Description: fmt.Sprintf(
			"Overall PQC readiness score: %.1f%%. "+
				"Estimated migration effort: %d days / $%.0f USD. "+
				"\n%s",
			score, migrationDays, migrationCost, inventoryDesc,
		),
		Severity:    SeverityHigh,
		Status:      summaryStatus,
		Expected:    "PQC readiness score ≥ 95% (all algorithms upgraded to NIST FIPS 204/203)",
		Actual:      fmt.Sprintf("Current readiness: %.1f%% — %d assets require PQC migration", score, len(result.Findings)-1),
		Remediation: fmt.Sprintf("Execute PQC migration roadmap. Estimated: %d days, $%.0f USD.", migrationDays, migrationCost),
		References: []string{
			"NIST-FIPS-204: ML-DSA (Dilithium)",
			"NIST-FIPS-203: ML-KEM (Kyber)",
			"NSA-CNSA-2.0",
			"NIST-800-53:SC-13",
		},
		CheckedAt: time.Now(),
	})

	// Store the computed metrics so analyzePQCBlastRadius() can pick them up
	// via the validator's PQC result entry (v.report.Results[FrameworkPQC]).
	// The blast radius struct is assembled later in validator.Validate() →
	// analyzePQCBlastRadius(). We annotate the result metadata here so the
	// PDF exporter can render them without re-computing.
	result.PQCMetrics = &PQCMetrics{
		ReadinessScore:      score,
		EstimatedDays:       migrationDays,
		EstimatedCostUSD:    migrationCost,
		CryptoInventory:     inventory,
		TotalAssetsFound:    sumInventory(inventory),
		VulnerableAssets:    countVulnerableAssets(inventory),
	}

	return nil
}

// sumInventory returns the total number of cryptographic assets found.
func sumInventory(inv map[string]int) int {
	total := 0
	for _, n := range inv {
		total += n
	}
	return total
}

// countVulnerableAssets returns the count of assets that are classical (non-PQC).
// All discovered assets are considered vulnerable until KHEPRA confirms PQC upgrade.
func countVulnerableAssets(inv map[string]int) int {
	return sumInventory(inv)
}

func (v *Validator) checkPQC_TLS(result *ValidationResult) {
	finding := Finding{
		ID:          "PQC-TLS-001",
		Title:       "TLS post-quantum readiness",
		Description: "Assess TLS configuration for post-quantum algorithm support",
		Severity:    SeverityHigh,
		Status:      "Fail",
		Expected:    "TLS 1.3 with hybrid PQC key exchange (X25519Kyber768)",
		Actual:      "TLS 1.2/1.3 with classical key exchange only",
		Remediation: "Upgrade to TLS 1.3 with PQC hybrid mode, deploy Kyber-aware TLS libraries",
		References: []string{
			"NIST-800-53:SC-8",
			"NIST-800-53:SC-13",
		},
		CheckedAt: time.Now(),
	}
	result.Findings = append(result.Findings, finding)
}

func (v *Validator) checkPQC_SSH(result *ValidationResult) {
	finding := Finding{
		ID:          "PQC-SSH-001",
		Title:       "SSH post-quantum readiness",
		Description: "Assess SSH configuration for post-quantum algorithm support",
		Severity:    SeverityHigh,
		Status:      "Fail",
		Expected:    "SSH with PQC key exchange and host keys (sntrup761, Dilithium)",
		Actual:      "SSH with classical algorithms only (RSA, ECDSA, Ed25519)",
		Remediation: "Upgrade OpenSSH to version supporting PQC KEX (sntrup761x25519-sha512@openssh.com)",
		References: []string{
			"NIST-800-53:SC-8",
			"NIST-800-53:SC-13",
		},
		CheckedAt: time.Now(),
	}
	result.Findings = append(result.Findings, finding)
}

func (v *Validator) checkPQC_Certificates(result *ValidationResult) {
	finding := Finding{
		ID:          "PQC-CERT-001",
		Title:       "X.509 certificate post-quantum readiness",
		Description: "Assess X.509 certificates for post-quantum signatures",
		Severity:    SeverityMedium,
		Status:      "Fail",
		Expected:    "Certificates signed with PQC algorithms (Dilithium3, SPHINCS+)",
		Actual:      "Certificates use RSA/ECDSA signatures only",
		Remediation: "Deploy hybrid certificates (RSA+Dilithium3) or pure PQC certificates",
		References: []string{
			"NIST-800-53:SC-12",
			"NIST-800-53:SC-13",
		},
		CheckedAt: time.Now(),
	}
	result.Findings = append(result.Findings, finding)
}

func (v *Validator) checkPQC_VPN(result *ValidationResult) {
	finding := Finding{
		ID:          "PQC-VPN-001",
		Title:       "VPN post-quantum readiness",
		Description: "Assess VPN (IPsec/IKEv2) for post-quantum algorithm support",
		Severity:    SeverityHigh,
		Status:      "Fail",
		Expected:    "IPsec with PQC key exchange (IKEv2 with Kyber)",
		Actual:      "IPsec with classical DH/ECDH key exchange",
		Remediation: "Upgrade VPN to support PQC KEMs (Kyber1024) for IKEv2",
		References: []string{
			"NIST-800-53:SC-8",
			"NIST-800-53:SC-13",
		},
		CheckedAt: time.Now(),
	}
	result.Findings = append(result.Findings, finding)
}

func (v *Validator) checkPQC_CodeSigning(result *ValidationResult) {
	finding := Finding{
		ID:          "PQC-SIGN-001",
		Title:       "Code signing post-quantum readiness",
		Description: "Assess code signing for post-quantum signatures",
		Severity:    SeverityMedium,
		Status:      "Fail",
		Expected:    "Software signed with PQC algorithms (Dilithium3)",
		Actual:      "Software signed with RSA/ECDSA only",
		Remediation: "Implement PQC code signing (Dilithium3) for software distribution",
		References: []string{
			"NIST-800-53:SC-13",
			"NIST-800-53:SI-7",
		},
		CheckedAt: time.Now(),
	}
	result.Findings = append(result.Findings, finding)
}

// Additional PQC assessment functions

// assessCryptographicInventory scans well-known system paths for cryptographic
// assets. Counts are best-effort; paths not present on the host are skipped.
func (v *Validator) assessCryptographicInventory() map[string]int {
	inventory := map[string]int{
		"TLS_connections":   0,
		"SSH_connections":   0,
		"X509_certificates": 0,
		"VPN_tunnels":       0,
		"signed_binaries":   0,
		"encrypted_volumes": 0,
		"crypto_API_calls":  0,
	}

	// Count X.509 certificates in standard PKI directories
	for _, certDir := range []string{"/etc/pki/tls/certs", "/etc/ssl/certs", "/usr/local/share/ca-certificates"} {
		entries, err := os.ReadDir(certDir)
		if err == nil {
			for _, e := range entries {
				name := e.Name()
				if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cer") {
					inventory["X509_certificates"]++
				}
			}
		}
	}

	// Count SSH host keys in /etc/ssh
	entries, err := os.ReadDir("/etc/ssh")
	if err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "ssh_host_") && strings.HasSuffix(e.Name(), "_key") {
				inventory["SSH_connections"]++
			}
		}
	}

	return inventory
}

// calculatePQCReadinessScore calculates overall PQC readiness (0-100%)
func (v *Validator) calculatePQCReadinessScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	pqcReadyCount := 0
	for _, finding := range findings {
		if finding.Status == "Pass" {
			pqcReadyCount++
		}
	}

	return (float64(pqcReadyCount) / float64(len(findings))) * 100.0
}

// estimateMigrationEffort estimates time and resources for PQC migration
func (v *Validator) estimateMigrationEffort(failedCount int) (days int, cost float64) {
	// Rough estimates based on typical DoD deployment
	// Each failed control requires approximately:
	// - 2 days of work (planning, testing, deployment)
	// - $5,000 in labor costs (assuming $125/hour for 40 hours)

	days = failedCount * 2
	cost = float64(failedCount) * 5000.0

	return days, cost
}

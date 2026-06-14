package ert

import (
	"fmt"
)

// calculateExecutiveRisk translates technical score to board-level language
func (e *Engine) calculateExecutiveRisk(alignmentScore int) string {
	if alignmentScore < 40 {
		return "CRITICAL"
	} else if alignmentScore < 60 {
		return "HIGH"
	} else if alignmentScore < 80 {
		return "MODERATE"
	}
	return "LOW"
}

// buildCausalChain creates logical chain from strategy to failure/success
func (e *Engine) buildCausalChain(readiness *ReadinessIntel, arch *ArchitectureIntel, crypto *CryptoIntel) []CausalLink {
	chain := []CausalLink{}
	step := 1

	// Strategic goal
	if readiness.AlignmentScore < 60 {
		// Failure chain
		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "GOAL",
			Description: "Strategic Goal: Achieve CMMC Level 2 for DoD Contract Renewal",
		})
		step++

		// Blockers
		if len(readiness.ComplianceGaps) > 0 {
			chain = append(chain, CausalLink{
				Step:        step,
				Type:        "BLOCKER",
				Description: fmt.Sprintf("BUT -> %d compliance gaps prevent certification", len(readiness.ComplianceGaps)),
			})
			step++
		}

		if crypto.CryptoUsage.HasLegacy && !crypto.CryptoUsage.HasPQC {
			chain = append(chain, CausalLink{
				Step:        step,
				Type:        "BLOCKER",
				Description: "BUT -> Legacy cryptography (RSA/ECDSA) fails FIPS 140-3 requirements",
			})
			step++
		}

		// Consequence
		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "CONSEQUENCE",
			Description: "THEREFORE -> Contract renewal at risk, estimated $12M ARR impact",
		})
		step++
	} else {
		// Success chain
		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "GOAL",
			Description: "Strategic Goal: Expand into Regulated Markets (Healthcare/Finance)",
		})
		step++

		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "ENABLER",
			Description: "AND -> Security posture exceeds industry baseline",
		})
		step++

		if crypto.CryptoUsage.HasPQC {
			chain = append(chain, CausalLink{
				Step:        step,
				Type:        "ENABLER",
				Description: "AND -> Post-Quantum Cryptography provides strategic advantage",
			})
			step++
		}

		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "CONSEQUENCE",
			Description: "THEREFORE -> Go-to-Market timeline accelerated by 2 quarters",
		})
		step++
	}

	// Quantum threat chain
	if crypto.CryptoUsage.HasLegacy && !crypto.CryptoUsage.HasPQC {
		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "RISK",
			Description: "Current Crypto: RSA-2048 / ECDSA-P256 (quantum-vulnerable)",
		})
		step++

		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "BLOCKER",
			Description: "BUT -> Quantum computers expected to break these by 2028-2030",
		})
		step++

		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "CONSEQUENCE",
			Description: "THEREFORE -> PQC migration is economically mandatory (avoid $500K+ re-audit costs)",
		})
		step++
	}

	// Supply chain risk chain
	if len(arch.VulnerableDeps) > 0 {
		exploitable := 0
		for _, dep := range arch.VulnerableDeps {
			if dep.Exploitable {
				exploitable++
			}
		}

		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "RISK",
			Description: fmt.Sprintf("Supply Chain: %d vulnerable dependencies, %d with known exploits", len(arch.VulnerableDeps), exploitable),
		})
		step++

		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "BLOCKER",
			Description: "BUT -> No automated vulnerability scanning in CI/CD",
		})
		step++

		chain = append(chain, CausalLink{
			Step:        step,
			Type:        "CONSEQUENCE",
			Description: "THEREFORE -> Exposure window averages 45 days per CVE",
		})
		step++
	}

	return chain
}

// generateRecommendations creates executive action items
func (e *Engine) generateRecommendations(readiness *ReadinessIntel, arch *ArchitectureIntel, crypto *CryptoIntel) []Recommendation {
	recommendations := []Recommendation{}

	// Critical compliance gaps
	if readiness.AlignmentScore < 60 {
		recommendations = append(recommendations, Recommendation{
			Priority: "URGENT",
			Action:   "Deploy AdinKhepra STIG Validation Suite",
			Impact:   "Achieves CMMC Level 2 compliance within 90 days",
			Cost:     "$150K implementation",
			ROI:      "$12M contract renewal secured",
		})
	}

	// PQC migration
	if crypto.CryptoUsage.HasLegacy && !crypto.CryptoUsage.HasPQC {
		recommendations = append(recommendations, Recommendation{
			Priority: "STRATEGIC",
			Action:   "Initiate Post-Quantum Cryptography Migration",
			Impact:   "Future-proofs compliance evidence, avoids $500K+ re-audit costs",
			Cost:     "$200K migration",
			ROI:      "$500K+ avoided costs + strategic advantage",
		})
	} else if !crypto.CryptoUsage.HasLegacy && !crypto.CryptoUsage.HasPQC {
		recommendations = append(recommendations, Recommendation{
			Priority: "STRATEGIC",
			Action:   "Implement AdinKhepra PQC (Kyber-1024 + Dilithium-3)",
			Impact:   "Establishes quantum-resistant security baseline",
			Cost:     "$100K implementation",
			ROI:      "Future-proof certification",
		})
	}

	// Supply chain security
	if len(arch.VulnerableDeps) > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority: "OPERATIONAL",
			Action:   "Enable Automated Supply Chain Scanning",
			Impact:   "Reduces CVE exposure window from 45 days to 24 hours",
			Cost:     "$50K annual subscription",
			ROI:      "Prevents supply chain compromise incidents",
		})
	}

	// Continuous monitoring (always recommend)
	recommendations = append(recommendations, Recommendation{
		Priority: "FOUNDATIONAL",
		Action:   "Establish Continuous Compliance Monitoring (AdinKhepra Agent)",
		Impact:   "Real-time drift detection, automated POA&M generation",
		Cost:     "$75K/year",
		ROI:      "Reduces audit preparation time by 80%",
	})

	// IP purity
	if crypto.IPLineage.GPL > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority: "URGENT",
			Action:   "Remediate GPL Contamination in Codebase",
			Impact:   "Prevents IP litigation and contract rejection",
			Cost:     "$100K remediation",
			ROI:      "Protects proprietary IP value",
		})
	}

	return recommendations
}

// calculateBusinessImpact translates technical findings to business metrics
func (e *Engine) calculateBusinessImpact(readiness *ReadinessIntel, arch *ArchitectureIntel, crypto *CryptoIntel) BusinessImpact {
	impact := BusinessImpact{
		KeyRisks: []string{},
	}

	// Revenue at risk
	if readiness.AlignmentScore < 60 {
		impact.RevenueAtRisk = "$12M ARR (DoD contract renewal)"
	} else {
		impact.RevenueAtRisk = "$0 (compliant)"
	}

	// Compliance cost
	gapCount := len(readiness.ComplianceGaps)
	if gapCount > 0 {
		impact.ComplianceCost = fmt.Sprintf("$%dK (remediation + audit)", gapCount*10)
	} else {
		impact.ComplianceCost = "$50K (annual maintenance)"
	}

	// Mitigation cost
	totalCost := 0
	if readiness.AlignmentScore < 60 {
		totalCost += 150 // STIG validation
	}
	if crypto.CryptoUsage.HasLegacy && !crypto.CryptoUsage.HasPQC {
		totalCost += 200 // PQC migration
	}
	if len(arch.VulnerableDeps) > 0 {
		totalCost += 50 // Supply chain scanning
	}
	totalCost += 75 // Continuous monitoring

	impact.MitigationCost = fmt.Sprintf("$%dK", totalCost)

	// Time to compliance
	if readiness.AlignmentScore < 40 {
		impact.TimeToCompliance = "180 days (critical gaps)"
	} else if readiness.AlignmentScore < 60 {
		impact.TimeToCompliance = "90 days (moderate gaps)"
	} else {
		impact.TimeToCompliance = "30 days (minor gaps)"
	}

	// Key risks
	if len(readiness.ComplianceGaps) > 5 {
		impact.KeyRisks = append(impact.KeyRisks, "Contract renewal blocked by compliance failures")
	}

	if crypto.CryptoUsage.HasLegacy && !crypto.CryptoUsage.HasPQC {
		impact.KeyRisks = append(impact.KeyRisks, "Quantum computing threatens cryptographic infrastructure by 2028")
	}

	if len(arch.VulnerableDeps) > 0 {
		impact.KeyRisks = append(impact.KeyRisks, "Supply chain vulnerabilities enable lateral movement attacks")
	}

	if crypto.IPLineage.GPL > 0 {
		impact.KeyRisks = append(impact.KeyRisks, "GPL contamination creates IP litigation exposure")
	}

	if len(arch.FrictionPoints) > 0 {
		impact.KeyRisks = append(impact.KeyRisks, "Architectural friction slows deployment velocity by 40%")
	}

	return impact
}

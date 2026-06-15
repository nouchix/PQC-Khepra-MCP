// Package ea — ERT Integration Bridge
//
// This file bridges the ERT pipeline's EnrichedFindings into the EA engine's
// fitness function. The EA genome evolution now incorporates live threat
// intelligence data from the SCA pipeline (EPSS scores, CISA KEV, CVSS,
// compliance gaps) to evolve optimal defense configurations.
//
// Integration Model:
//   KernelRouter.RouteWithFindings() accepts EnrichedFindings from the ERT pipeline
//   and feeds them into the EA evolution as a multi-objective threat signal.
//
//   Fitness = 0.35 × BaseAttackResistance
//           + 0.30 × ThreatAwareness(findings)
//           + 0.20 × ComplianceCoverage(findings)
//           + 0.15 × PQCReadiness(genome)

package ea

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sca"
)

// ──────────────────────────────────────────────────────────────────────────────
// ERT Route Input / Output
// ──────────────────────────────────────────────────────────────────────────────

// ERTRouteInput carries enriched SCA findings + constraints into the EA router.
type ERTRouteInput struct {
	Findings    []sca.EnrichedFinding  `json:"findings"`
	Context     map[string]interface{} `json:"context,omitempty"`    // compliance score, crypto inventory
	Constraints EAConstraints          `json:"constraints,omitempty"`
}

// EAConstraints defines the boundaries for EA evolution based on threat context.
type EAConstraints struct {
	MinSecurityBits int    `json:"min_security_bits"` // e.g. 128, 192, 256
	QuantumTimeline string `json:"quantum_timeline"`  // "CNSA-2.0", "CNSA-1.0", "pre-quantum"
	MaxRiskScore    float64 `json:"max_risk_score"`   // acceptable risk threshold (0–10)
	EvolutionCycles int    `json:"evolution_cycles"`  // how many EA generations to run
}

// DefaultEAConstraints returns production-safe constraint defaults.
func DefaultEAConstraints() EAConstraints {
	return EAConstraints{
		MinSecurityBits: 128,
		QuantumTimeline: "CNSA-2.0",
		MaxRiskScore:    7.0,
		EvolutionCycles: 10,
	}
}

// ERTEvolutionResult carries the EA engine's output after processing ERT findings.
type ERTEvolutionResult struct {
	BestGenome      *AdinkraGenome `json:"best_genome"`
	ThreatScore     float64        `json:"threat_score"`       // 0.0–1.0 aggregate threat level
	ComplianceGap   float64        `json:"compliance_gap"`     // 0.0–1.0 (0 = fully compliant)
	RiskSummary     RiskSummary    `json:"risk_summary"`
	Recommendations []string       `json:"recommendations"`
	DAGNodeID       string         `json:"dag_node_id,omitempty"`
	EvolvedAt       time.Time      `json:"evolved_at"`
}

// RiskSummary aggregates finding-level risk data for the EA engine.
type RiskSummary struct {
	TotalFindings    int     `json:"total_findings"`
	CriticalCount    int     `json:"critical_count"`
	HighCount        int     `json:"high_count"`
	MediumCount      int     `json:"medium_count"`
	LowCount         int     `json:"low_count"`
	KEVCount         int     `json:"kev_count"`
	ExploitedCount   int     `json:"exploited_count"`
	AvgEPSS          float64 `json:"avg_epss"`
	MaxEPSS          float64 `json:"max_epss"`
	AvgCVSS          float64 `json:"avg_cvss"`
	MaxCVSS          float64 `json:"max_cvss"`
	HighRiskCount    int     `json:"high_risk_count"` // findings that pass IsHighRisk()
	ComplianceImpact int     `json:"compliance_impact"` // findings with NIST mappings
}

// ──────────────────────────────────────────────────────────────────────────────
// Threat Score Calculation
// ──────────────────────────────────────────────────────────────────────────────

// CalculateThreatScore computes an aggregate threat score (0.0–1.0) from
// enriched findings. This is the primary input to the EA fitness function's
// threat awareness component.
//
// Scoring Methodology:
//   1. EPSS-weighted average: each finding's contribution is scaled by its EPSS
//   2. KEV bonus: CISA KEV presence adds significant weight
//   3. Severity ladder: CRITICAL/HIGH findings contribute more than MEDIUM/LOW
//   4. InTheWild multiplier: active exploitation is a 1.5× amplifier
func CalculateThreatScore(findings []sca.EnrichedFinding) float64 {
	if len(findings) == 0 {
		return 0
	}

	var (
		totalScore  float64
		totalWeight float64
	)

	for _, f := range findings {
		weight := severityWeight(f.Severity)

		// EPSS component: probability of exploitation × weight
		epssContrib := f.EPSSScore * weight

		// CVSS component: base score normalized to [0,1] × weight
		cvssContrib := (f.CVSSv3Score / 10.0) * weight

		// KEV bonus: confirmed exploitation is strongest signal
		var kevBonus float64
		if f.InCISAKEV {
			kevBonus = 0.5 * weight
		}

		// InTheWild amplifier
		var wildMult float64 = 1.0
		if f.InTheWild {
			wildMult = 1.5
		}

		// PoC available adds minor signal
		var pocBonus float64
		if f.PoCAvailable {
			pocBonus = 0.1 * weight
		}

		findingScore := (0.4*epssContrib + 0.4*cvssContrib + kevBonus + pocBonus) * wildMult
		totalScore += findingScore
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0
	}

	// Normalize to [0, 1]
	normalized := totalScore / totalWeight
	return math.Min(1.0, math.Max(0.0, normalized))
}

// CalculateComplianceGap computes the compliance coverage gap (0.0–1.0)
// based on how many findings have missing or incomplete NIST/CMMC mappings.
// 0.0 = fully mapped and covered, 1.0 = completely unmapped.
func CalculateComplianceGap(findings []sca.EnrichedFinding) float64 {
	if len(findings) == 0 {
		return 0
	}

	unmapped := 0
	for _, f := range findings {
		// A finding is "unmapped" if it has no NIST 800-53 controls
		if len(f.NIST53Controls) == 0 {
			unmapped++
		}
	}

	return float64(unmapped) / float64(len(findings))
}

// BuildRiskSummary aggregates risk metrics from enriched findings.
func BuildRiskSummary(findings []sca.EnrichedFinding) RiskSummary {
	rs := RiskSummary{TotalFindings: len(findings)}

	var totalEPSS, totalCVSS float64

	for _, f := range findings {
		// Severity counts
		switch sca.Severity(f.Severity) {
		case sca.SeverityCritical:
			rs.CriticalCount++
		case sca.SeverityHigh:
			rs.HighCount++
		case sca.SeverityMedium:
			rs.MediumCount++
		case sca.SeverityLow:
			rs.LowCount++
		}

		// KEV / exploitation
		if f.InCISAKEV {
			rs.KEVCount++
		}
		if f.InTheWild {
			rs.ExploitedCount++
		}

		// EPSS aggregation
		totalEPSS += f.EPSSScore
		if f.EPSSScore > rs.MaxEPSS {
			rs.MaxEPSS = f.EPSSScore
		}

		// CVSS aggregation
		totalCVSS += f.CVSSv3Score
		if f.CVSSv3Score > rs.MaxCVSS {
			rs.MaxCVSS = f.CVSSv3Score
		}

		// High risk
		if f.IsHighRisk() {
			rs.HighRiskCount++
		}

		// Compliance impact
		if len(f.NIST53Controls) > 0 {
			rs.ComplianceImpact++
		}
	}

	if rs.TotalFindings > 0 {
		rs.AvgEPSS = totalEPSS / float64(rs.TotalFindings)
		rs.AvgCVSS = totalCVSS / float64(rs.TotalFindings)
	}

	return rs
}

// severityWeight returns the EA-compatible weight for a severity string.
func severityWeight(sev string) float64 {
	switch sca.Severity(sev) {
	case sca.SeverityCritical:
		return 4.0
	case sca.SeverityHigh:
		return 3.0
	case sca.SeverityMedium:
		return 2.0
	case sca.SeverityLow:
		return 1.0
	default:
		return 0.5
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Threat-Aware Fitness Function
// ──────────────────────────────────────────────────────────────────────────────

// ThreatAwareFitnessFunc returns a FitnessFunc that incorporates live threat
// intelligence from ERT findings into the Adinkra genome evolution.
//
// The multi-objective fitness landscape:
//   0.35 × BaseAttackResistance (existing Adinkra fitness)
//   0.30 × ThreatAwareness (EPSS-weighted, KEV, InTheWild)
//   0.20 × ComplianceCoverage (NIST mapping completeness)
//   0.15 × PQCReadiness (quantum resistance from genome params)
func ThreatAwareFitnessFunc(findings []sca.EnrichedFinding) FitnessFunc {
	baseFitness := AdinkraFitnessFunc()
	threatScore := CalculateThreatScore(findings)
	complianceGap := CalculateComplianceGap(findings)

	return func(ind *Individual) (float64, error) {
		// Component 1: Base attack resistance (existing Adinkra fitness)
		base, err := baseFitness(ind)
		if err != nil {
			return 0.001, nil
		}

		// Component 2: Threat awareness — genomes that defend against
		// the current threat landscape are rewarded
		// Higher threat score → more pressure to evolve stronger params
		threatAwareness := 1.0 - threatScore // Invert: high threat → low score → pressure to evolve

		// Component 3: Compliance coverage (inverted gap)
		complianceCoverage := 1.0 - complianceGap

		// Component 4: PQC readiness from genome parameters
		pqcReadiness := pqcReadinessFromGenome(ind.Genome)

		// Multi-objective weighted sum
		fitness := 0.35*base +
			0.30*threatAwareness +
			0.20*complianceCoverage +
			0.15*pqcReadiness

		// Clamp to [0, 1]
		return math.Min(1.0, math.Max(0.0, fitness)), nil
	}
}

// pqcReadinessFromGenome evaluates the genome's PQC parameters.
// Returns [0, 1] where 1.0 = maximum quantum resistance.
func pqcReadinessFromGenome(genome []byte) float64 {
	g, err := decodeAdinkraGenome(genome)
	if err != nil {
		return 0.1 // Undecodable genome → poor readiness
	}

	var totalBits int
	var count int
	for _, p := range g.SymbolMappings {
		totalBits += p.SecurityBits
		count++
	}

	if count == 0 {
		return 0.1
	}

	avgBits := float64(totalBits) / float64(count)
	// 256 bits is CNSA-2.0 target, 128 is minimum
	readiness := (avgBits - 128) / (256 - 128)
	return math.Min(1.0, math.Max(0.0, readiness))
}

// ──────────────────────────────────────────────────────────────────────────────
// KernelRouter ERT Extension
// ──────────────────────────────────────────────────────────────────────────────

// RouteWithFindings extends the KernelRouter to accept ERT enriched findings,
// evolve the EA genome against the current threat landscape, and return an
// ERTEvolutionResult with recommendations.
//
// This is the bridge between:
//   - ERT Pipeline (Syft→Grype→Enricher→Compliance) producing EnrichedFindings
//   - EA Engine (Adinkra evolution) consuming threat signals
func (r *KernelRouter) RouteWithFindings(ctx context.Context, input ERTRouteInput) (*ERTEvolutionResult, error) {
	if len(input.Findings) == 0 {
		return nil, fmt.Errorf("ea: RouteWithFindings: no findings provided")
	}

	constraints := input.Constraints
	if constraints.EvolutionCycles <= 0 {
		constraints = DefaultEAConstraints()
	}

	// Build risk summary
	summary := BuildRiskSummary(input.Findings)

	// Create a SecurityContext from findings for agent routing
	sec := r.securityContextFromFindings(input.Findings, input.Context)

	// If EA engine is attached, run threat-aware evolution
	var bestGenome *AdinkraGenome
	r.mu.RLock()
	eng := r.eaEngine
	r.mu.RUnlock()

	if eng != nil {
		// Swap in the threat-aware fitness function for this evolution cycle
		threatFitness := ThreatAwareFitnessFunc(input.Findings)
		eng.mu.Lock()
		originalFitness := eng.fitnessFunc
		eng.fitnessFunc = threatFitness
		eng.mu.Unlock()

		// Evolve for the specified number of cycles
		for i := 0; i < constraints.EvolutionCycles; i++ {
			if _, err := eng.Evolve(); err != nil {
				// Restore and return partial result
				eng.mu.Lock()
				eng.fitnessFunc = originalFitness
				eng.mu.Unlock()
				return nil, fmt.Errorf("ea: evolution cycle %d failed: %w", i, err)
			}
		}

		// Restore original fitness function
		eng.mu.Lock()
		eng.fitnessFunc = originalFitness
		eng.mu.Unlock()

		// Extract best genome
		best := eng.BestIndividual()
		if best != nil {
			g, err := decodeAdinkraGenome(best.Genome)
			if err == nil {
				g.Generation = best.Generation
				g.Fitness = best.Fitness
				bestGenome = g
			}
		}

		// Update routing weights from best genome
		if best != nil {
			r.UpdateWeightsFromGenome(best.Genome)
		}
	}

	// Calculate scores
	threatScore := CalculateThreatScore(input.Findings)
	complianceGap := CalculateComplianceGap(input.Findings)

	// Generate recommendations based on findings + evolution
	recommendations := generateRecommendations(input.Findings, summary, constraints)

	result := &ERTEvolutionResult{
		BestGenome:      bestGenome,
		ThreatScore:     threatScore,
		ComplianceGap:   complianceGap,
		RiskSummary:     summary,
		Recommendations: recommendations,
		EvolvedAt:       time.Now().UTC(),
	}

	// Record to DAG
	if err := r.recordERTResult(sec, result); err != nil {
		fmt.Printf("[EA-ROUTER] WARN: DAG record failed for ERT evolution: %v\n", err)
	}

	return result, nil
}

// securityContextFromFindings constructs a SecurityContext from ERT findings.
func (r *KernelRouter) securityContextFromFindings(findings []sca.EnrichedFinding, meta map[string]interface{}) *SecurityContext {
	sec := NewSecurityContext("ert-pipeline")
	sec.UnpatchedCVEs = len(findings)

	// Check for legacy crypto signals
	for _, f := range findings {
		if f.Ecosystem == "crypto" || f.Component == "openssl" {
			sec.LegacyCryptoFound = true
		}
	}

	// Check for compliance frameworks from findings
	for _, f := range findings {
		if len(f.NIST53Controls) > 0 {
			sec.Frameworks = ertAppendUnique(sec.Frameworks, "nist-800-53")
		}
		if len(f.NIST171Controls) > 0 {
			sec.Frameworks = ertAppendUnique(sec.Frameworks, "cmmc")
		}
	}

	// Copy context metadata if provided
	if hasCUI, ok := meta["has_cui"].(bool); ok {
		sec.HasCUI = hasCUI
	}

	return sec
}

// ertAppendUnique adds a string to a slice if not already present.
// Named with ert prefix to avoid collision with kernel_router.go's containsAny.
func ertAppendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// recordERTResult writes the evolution result to the DAG.
func (r *KernelRouter) recordERTResult(sec *SecurityContext, result *ERTEvolutionResult) error {
	payload, err := json.Marshal(map[string]interface{}{
		"request_id":      sec.RequestID,
		"threat_score":    result.ThreatScore,
		"compliance_gap":  result.ComplianceGap,
		"total_findings":  result.RiskSummary.TotalFindings,
		"critical_count":  result.RiskSummary.CriticalCount,
		"high_risk_count": result.RiskSummary.HighRiskCount,
		"kev_count":       result.RiskSummary.KEVCount,
		"avg_epss":        result.RiskSummary.AvgEPSS,
		"recommendations": len(result.Recommendations),
	})
	if err != nil {
		return err
	}

	n := &dag.Node{
		Action: "ert_evolution",
		Symbol: "Nkyinkyim", // "twists and turns" — representing the evolutionary path
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		PQC:    map[string]string{"payload": string(payload)},
	}

	if err := r.dag.Add(n, nil); err != nil {
		return err
	}
	result.DAGNodeID = n.ID
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Recommendation Engine
// ──────────────────────────────────────────────────────────────────────────────

// generateRecommendations produces actionable recommendations based on
// the enriched findings and EA evolution constraints.
func generateRecommendations(findings []sca.EnrichedFinding, summary RiskSummary, constraints EAConstraints) []string {
	var recs []string

	// CISA KEV findings demand immediate remediation
	if summary.KEVCount > 0 {
		recs = append(recs, fmt.Sprintf(
			"IMMEDIATE: %d findings are in the CISA KEV catalog — these are confirmed actively exploited. Patch within 48 hours per BOD 22-01.",
			summary.KEVCount))
	}

	// Critical severity findings
	if summary.CriticalCount > 0 {
		recs = append(recs, fmt.Sprintf(
			"CRITICAL: %d findings rated CRITICAL severity (CVSS ≥ 9.0). Prioritize remediation in current sprint.",
			summary.CriticalCount))
	}

	// High EPSS findings
	highEPSSCount := 0
	for _, f := range findings {
		if f.EPSSScore >= 0.40 {
			highEPSSCount++
		}
	}
	if highEPSSCount > 0 {
		recs = append(recs, fmt.Sprintf(
			"EXPLOIT RISK: %d findings have EPSS ≥ 0.40 — high probability of exploitation within 30 days.",
			highEPSSCount))
	}

	// Compliance gaps
	gapPercent := CalculateComplianceGap(findings) * 100
	if gapPercent > 20 {
		recs = append(recs, fmt.Sprintf(
			"COMPLIANCE: %.0f%% of findings lack NIST 800-53 control mapping. Run compliance mapper to close audit gaps.",
			gapPercent))
	}

	// PQC readiness
	if constraints.MinSecurityBits >= 256 && constraints.QuantumTimeline == "CNSA-2.0" {
		recs = append(recs, "PQC: CNSA-2.0 timeline active — ensure all cryptographic operations use ML-DSA-65/ML-KEM-1024 minimum.")
	}

	// Default recommendation if nothing alarming
	if len(recs) == 0 {
		recs = append(recs, "NOMINAL: All findings within acceptable risk thresholds. Continue monitoring.")
	}

	return recs
}

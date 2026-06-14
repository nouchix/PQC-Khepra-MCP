package ea

import (
	"context"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sca"
)

// ──────────────────────────────────────────────────────────────────────────────
// Threat Score Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestCalculateThreatScore_Empty(t *testing.T) {
	score := CalculateThreatScore(nil)
	if score != 0 {
		t.Errorf("expected 0 for empty findings, got %f", score)
	}
}

func TestCalculateThreatScore_CriticalKEV(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{
			CVEID:       "CVE-2021-44228",
			Severity:    "CRITICAL",
			CVSSv3Score: 10.0,
			EPSSScore:   0.975,
			InCISAKEV:   true,
			InTheWild:   true,
		},
	}
	score := CalculateThreatScore(findings)
	if score < 0.5 {
		t.Errorf("expected high threat score for critical KEV finding, got %f", score)
	}
	if score > 1.0 {
		t.Errorf("threat score should be clamped to 1.0, got %f", score)
	}
}

func TestCalculateThreatScore_LowSeverity(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{
			CVEID:       "CVE-2024-99999",
			Severity:    "LOW",
			CVSSv3Score: 2.0,
			EPSSScore:   0.01,
		},
	}
	score := CalculateThreatScore(findings)
	if score >= 0.5 {
		t.Errorf("expected low threat score for LOW finding, got %f", score)
	}
}

func TestCalculateThreatScore_MixedFindings(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{CVEID: "CVE-2021-44228", Severity: "CRITICAL", CVSSv3Score: 10.0, EPSSScore: 0.97, InCISAKEV: true},
		{CVEID: "CVE-2024-12345", Severity: "LOW", CVSSv3Score: 2.0, EPSSScore: 0.01},
	}
	score := CalculateThreatScore(findings)
	// Should be elevated due to the critical finding dominating the weighted average
	// (weight 4.0 vs LOW weight 1.0), so aggregate stays high
	if score < 0.5 || score > 1.0 {
		t.Errorf("expected elevated threat score for mixed findings, got %f", score)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Compliance Gap Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestCalculateComplianceGap_AllMapped(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{CVEID: "CVE-1", NIST53Controls: []string{"RA-5"}},
		{CVEID: "CVE-2", NIST53Controls: []string{"SI-2"}},
	}
	gap := CalculateComplianceGap(findings)
	if gap != 0 {
		t.Errorf("expected 0 gap for fully mapped, got %f", gap)
	}
}

func TestCalculateComplianceGap_NoneMapper(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{CVEID: "CVE-1"},
		{CVEID: "CVE-2"},
	}
	gap := CalculateComplianceGap(findings)
	if gap != 1.0 {
		t.Errorf("expected 1.0 gap for unmapped, got %f", gap)
	}
}

func TestCalculateComplianceGap_Partial(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{CVEID: "CVE-1", NIST53Controls: []string{"RA-5"}},
		{CVEID: "CVE-2"}, // unmapped
	}
	gap := CalculateComplianceGap(findings)
	if gap != 0.5 {
		t.Errorf("expected 0.5 gap for half-mapped, got %f", gap)
	}
}

func TestCalculateComplianceGap_Empty(t *testing.T) {
	gap := CalculateComplianceGap(nil)
	if gap != 0 {
		t.Errorf("expected 0 for empty findings, got %f", gap)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Risk Summary Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestBuildRiskSummary(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{
			CVEID: "CVE-2021-44228", Severity: "CRITICAL",
			CVSSv3Score: 10.0, EPSSScore: 0.975,
			InCISAKEV: true, InTheWild: true,
			NIST53Controls: []string{"RA-5", "SI-2"},
		},
		{
			CVEID: "CVE-2022-32149", Severity: "HIGH",
			CVSSv3Score: 7.5, EPSSScore: 0.005,
		},
		{
			CVEID: "CVE-2024-00001", Severity: "MEDIUM",
			CVSSv3Score: 5.0,
		},
		{
			CVEID: "CVE-2024-00002", Severity: "LOW",
			CVSSv3Score: 2.0,
		},
	}

	rs := BuildRiskSummary(findings)

	if rs.TotalFindings != 4 {
		t.Errorf("TotalFindings: got %d, want 4", rs.TotalFindings)
	}
	if rs.CriticalCount != 1 {
		t.Errorf("CriticalCount: got %d, want 1", rs.CriticalCount)
	}
	if rs.HighCount != 1 {
		t.Errorf("HighCount: got %d, want 1", rs.HighCount)
	}
	if rs.MediumCount != 1 {
		t.Errorf("MediumCount: got %d, want 1", rs.MediumCount)
	}
	if rs.LowCount != 1 {
		t.Errorf("LowCount: got %d, want 1", rs.LowCount)
	}
	if rs.KEVCount != 1 {
		t.Errorf("KEVCount: got %d, want 1", rs.KEVCount)
	}
	if rs.ExploitedCount != 1 {
		t.Errorf("ExploitedCount: got %d, want 1", rs.ExploitedCount)
	}
	if rs.MaxCVSS != 10.0 {
		t.Errorf("MaxCVSS: got %f, want 10.0", rs.MaxCVSS)
	}
	if rs.MaxEPSS != 0.975 {
		t.Errorf("MaxEPSS: got %f, want 0.975", rs.MaxEPSS)
	}
	if rs.HighRiskCount < 1 {
		t.Errorf("HighRiskCount: got %d, want ≥1", rs.HighRiskCount)
	}
	if rs.ComplianceImpact != 1 {
		t.Errorf("ComplianceImpact: got %d, want 1", rs.ComplianceImpact)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Severity Weight Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		sev  string
		want float64
	}{
		{"CRITICAL", 4.0},
		{"HIGH", 3.0},
		{"MEDIUM", 2.0},
		{"LOW", 1.0},
		{"UNKNOWN", 0.5},
		{"", 0.5},
	}
	for _, tt := range tests {
		got := severityWeight(tt.sev)
		if got != tt.want {
			t.Errorf("severityWeight(%q) = %f, want %f", tt.sev, got, tt.want)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// PQC Readiness Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestPQCReadinessFromGenome(t *testing.T) {
	// Create a NIST-compliant genome
	g := newAdinkraGenome()
	genome, _ := EncodeAdinkraGenome(g)
	readiness := pqcReadinessFromGenome(genome)

	if readiness < 0.3 {
		t.Errorf("NIST-compliant genome should have good PQC readiness, got %f", readiness)
	}
	if readiness > 1.0 {
		t.Errorf("PQC readiness should be ≤ 1.0, got %f", readiness)
	}
}

func TestPQCReadinessFromGenome_Short(t *testing.T) {
	// Too-short genome → low readiness
	readiness := pqcReadinessFromGenome([]byte{1, 2, 3})
	if readiness != 0.1 {
		t.Errorf("short genome should have 0.1 readiness, got %f", readiness)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Threat-Aware Fitness Function Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestThreatAwareFitnessFunc(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{CVEID: "CVE-2021-44228", Severity: "CRITICAL", CVSSv3Score: 10.0, EPSSScore: 0.97, InCISAKEV: true},
	}

	fitnessFunc := ThreatAwareFitnessFunc(findings)

	// Create a NIST-compliant genome
	g := newAdinkraGenome()
	genome, _ := EncodeAdinkraGenome(g)
	ind := &Individual{Genome: genome}

	fitness, err := fitnessFunc(ind)
	if err != nil {
		t.Fatalf("fitness evaluation failed: %v", err)
	}

	if fitness < 0 || fitness > 1.0 {
		t.Errorf("fitness should be in [0, 1], got %f", fitness)
	}

	// With high threat score, base component should be partially offset
	t.Logf("Threat-aware fitness for NIST-compliant genome with critical KEV: %f", fitness)
}

func TestThreatAwareFitnessFunc_NoFindings(t *testing.T) {
	fitnessFunc := ThreatAwareFitnessFunc(nil)

	g := newAdinkraGenome()
	genome, _ := EncodeAdinkraGenome(g)
	ind := &Individual{Genome: genome}

	fitness, err := fitnessFunc(ind)
	if err != nil {
		t.Fatalf("fitness evaluation failed: %v", err)
	}

	// With no findings, threat awareness = 1.0, compliance gap = 0.0
	// Fitness should be high for a good genome
	if fitness < 0.5 {
		t.Errorf("no-threat fitness should be ≥ 0.5 for compliant genome, got %f", fitness)
	}
	t.Logf("No-threat fitness: %f", fitness)
}

// ──────────────────────────────────────────────────────────────────────────────
// Recommendation Engine Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestGenerateRecommendations_KEV(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{CVEID: "CVE-2021-44228", InCISAKEV: true, Severity: "CRITICAL", CVSSv3Score: 10.0},
	}
	summary := BuildRiskSummary(findings)
	recs := generateRecommendations(findings, summary, DefaultEAConstraints())

	found := false
	for _, r := range recs {
		if contains(r, "CISA KEV") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected KEV recommendation, got: %v", recs)
	}
}

func TestGenerateRecommendations_Nominal(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{CVEID: "CVE-2024-99999", Severity: "LOW", CVSSv3Score: 2.0, NIST53Controls: []string{"RA-5"}},
	}
	summary := BuildRiskSummary(findings)
	constraints := DefaultEAConstraints()
	constraints.MinSecurityBits = 128
	constraints.QuantumTimeline = "pre-quantum"
	recs := generateRecommendations(findings, summary, constraints)

	found := false
	for _, r := range recs {
		if contains(r, "NOMINAL") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected NOMINAL recommendation for low-risk findings, got: %v", recs)
	}
}

func TestGenerateRecommendations_HighEPSS(t *testing.T) {
	findings := []sca.EnrichedFinding{
		{CVEID: "CVE-2024-12345", Severity: "HIGH", CVSSv3Score: 8.0, EPSSScore: 0.65},
	}
	summary := BuildRiskSummary(findings)
	recs := generateRecommendations(findings, summary, DefaultEAConstraints())

	found := false
	for _, r := range recs {
		if contains(r, "EXPLOIT RISK") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected EXPLOIT RISK recommendation for high EPSS, got: %v", recs)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// RouteWithFindings Integration Test
// ──────────────────────────────────────────────────────────────────────────────

func TestRouteWithFindings_NilFindings(t *testing.T) {
	router := NewKernelRouter(dag.NewMemory())
	_, err := router.RouteWithFindings(context.Background(), ERTRouteInput{})
	if err == nil {
		t.Error("expected error for empty findings")
	}
}

func TestRouteWithFindings_WithoutEA(t *testing.T) {
	router := NewKernelRouter(dag.NewMemory())

	input := ERTRouteInput{
		Findings: []sca.EnrichedFinding{
			{
				CVEID:          "CVE-2021-44228",
				Severity:       "CRITICAL",
				CVSSv3Score:    10.0,
				EPSSScore:      0.975,
				InCISAKEV:      true,
				InTheWild:      true,
				NIST53Controls: []string{"RA-5", "SI-2"},
				DetectedAt:     time.Now(),
			},
			{
				CVEID:       "CVE-2022-32149",
				Severity:    "HIGH",
				CVSSv3Score: 7.5,
				EPSSScore:   0.005,
				DetectedAt:  time.Now(),
			},
		},
		Constraints: DefaultEAConstraints(),
	}

	result, err := router.RouteWithFindings(context.Background(), input)
	if err != nil {
		t.Fatalf("RouteWithFindings failed: %v", err)
	}

	// Without EA engine, genome should be nil
	if result.BestGenome != nil {
		t.Error("expected nil genome without EA engine")
	}

	// Threat score should be elevated
	if result.ThreatScore < 0.3 {
		t.Errorf("expected elevated threat score, got %f", result.ThreatScore)
	}

	// Compliance gap should reflect partial mapping
	if result.ComplianceGap < 0.3 || result.ComplianceGap > 0.7 {
		t.Errorf("expected partial compliance gap (~0.5), got %f", result.ComplianceGap)
	}

	// Recommendations should include KEV
	if len(result.Recommendations) == 0 {
		t.Error("expected at least one recommendation")
	}

	// DAG node should be recorded
	if result.DAGNodeID == "" {
		t.Error("expected DAG node to be recorded")
	}

	// Risk summary checks
	if result.RiskSummary.TotalFindings != 2 {
		t.Errorf("total findings: got %d, want 2", result.RiskSummary.TotalFindings)
	}
	if result.RiskSummary.CriticalCount != 1 {
		t.Errorf("critical count: got %d, want 1", result.RiskSummary.CriticalCount)
	}

	t.Logf("ERT Evolution Result (no EA):")
	t.Logf("  ThreatScore:   %.3f", result.ThreatScore)
	t.Logf("  ComplianceGap: %.3f", result.ComplianceGap)
	t.Logf("  Recommendations: %v", result.Recommendations)
	t.Logf("  DAG Node: %s", result.DAGNodeID)
}

func TestRouteWithFindings_WithEA(t *testing.T) {
	dagStore := dag.NewMemory()
	router := NewKernelRouter(dagStore)

	// Create and attach EA engine
	eng, err := NewAdinkraEAEngine(dagStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create EA engine: %v", err)
	}
	router.AttachEA(eng.EAEngine)

	input := ERTRouteInput{
		Findings: []sca.EnrichedFinding{
			{
				CVEID:          "CVE-2021-44228",
				Severity:       "CRITICAL",
				CVSSv3Score:    10.0,
				EPSSScore:      0.975,
				InCISAKEV:      true,
				NIST53Controls: []string{"RA-5"},
				DetectedAt:     time.Now(),
			},
		},
		Constraints: EAConstraints{
			MinSecurityBits: 256,
			QuantumTimeline: "CNSA-2.0",
			EvolutionCycles: 3, // Small for test speed
		},
	}

	result, err := router.RouteWithFindings(context.Background(), input)
	if err != nil {
		t.Fatalf("RouteWithFindings with EA failed: %v", err)
	}

	// With EA engine, genome should be populated
	if result.BestGenome == nil {
		t.Error("expected non-nil genome with EA engine attached")
	} else {
		t.Logf("  Best genome fitness: %.4f", result.BestGenome.Fitness)
		t.Logf("  Best genome generation: %d", result.BestGenome.Generation)
	}

	t.Logf("ERT Evolution Result (with EA, 3 cycles):")
	t.Logf("  ThreatScore:   %.3f", result.ThreatScore)
	t.Logf("  ComplianceGap: %.3f", result.ComplianceGap)
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

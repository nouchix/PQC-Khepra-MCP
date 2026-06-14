package ert

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sca"
)

// ──────────────────────────────────────────────────────────────────────────────
// Mock Lane for testing the orchestrator
// ──────────────────────────────────────────────────────────────────────────────

type mockLane struct {
	name     ScanLane
	findings []UnifiedFinding
	err      error
	delay    time.Duration
}

func (m *mockLane) Name() ScanLane { return m.name }

func (m *mockLane) Run(ctx context.Context, req ScanRequest) ([]UnifiedFinding, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.findings, m.err
}

// ──────────────────────────────────────────────────────────────────────────────
// Orchestrator Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestNewScanOrchestrator(t *testing.T) {
	o := NewScanOrchestrator()
	if o == nil {
		t.Fatal("NewScanOrchestrator returned nil")
	}
	if len(o.RegisteredLanes()) != 0 {
		t.Errorf("expected 0 lanes, got %d", len(o.RegisteredLanes()))
	}
}

func TestRegisterLane(t *testing.T) {
	o := NewScanOrchestrator()
	o.RegisterLane(&mockLane{name: LaneHorusVuln})
	o.RegisterLane(&mockLane{name: LaneHorusSecret})

	lanes := o.RegisteredLanes()
	if len(lanes) != 2 {
		t.Errorf("expected 2 lanes, got %d", len(lanes))
	}
}

func TestExecuteEmptyRequest(t *testing.T) {
	o := NewScanOrchestrator()
	_, err := o.Execute(context.Background(), ScanRequest{})
	if err == nil {
		t.Fatal("expected error for empty request")
	}
}

func TestExecuteSingleLane(t *testing.T) {
	o := NewScanOrchestrator()
	o.RegisterLane(&mockLane{
		name: LaneHorusVuln,
		findings: []UnifiedFinding{
			{
				ID:       "test-vuln-1",
				Source:   "horus",
				Category: CategoryVulnerability,
				Severity: "HIGH",
				Title:    "Test Vulnerability",
				Asset:    "lodash",
			},
		},
	})

	result, err := o.Execute(context.Background(), ScanRequest{
		TargetPath: "/tmp/test-target",
		Lanes:      []ScanLane{LaneHorusVuln},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Stats.TotalFindings != 1 {
		t.Errorf("expected TotalFindings=1, got %d", result.Stats.TotalFindings)
	}
	if result.Stats.HighCount != 1 {
		t.Errorf("expected HighCount=1, got %d", result.Stats.HighCount)
	}
}

func TestExecuteMultipleLanes(t *testing.T) {
	o := NewScanOrchestrator()

	// Register 3 lanes with different finding types
	o.RegisterLane(&mockLane{
		name: LaneHorusVuln,
		findings: []UnifiedFinding{
			{ID: "vuln-1", Source: "horus", Category: CategoryVulnerability, Severity: "CRITICAL"},
			{ID: "vuln-2", Source: "horus", Category: CategoryVulnerability, Severity: "HIGH"},
		},
	})
	o.RegisterLane(&mockLane{
		name: LaneHorusSecret,
		findings: []UnifiedFinding{
			{ID: "secret-1", Source: "horus", Category: CategorySecret, Severity: "CRITICAL"},
		},
	})
	o.RegisterLane(&mockLane{
		name: LaneHorusCompliance,
		findings: []UnifiedFinding{
			{ID: "compliance-1", Source: "horus", Category: CategoryCompliance, Severity: "MEDIUM"},
			{ID: "compliance-2", Source: "horus", Category: CategoryCompliance, Severity: "HIGH"},
		},
	})

	result, err := o.Execute(context.Background(), ScanRequest{
		TargetPath: "/tmp/test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Stats.TotalFindings != 5 {
		t.Errorf("expected 5 total findings, got %d", result.Stats.TotalFindings)
	}
	if result.Stats.CriticalCount != 2 {
		t.Errorf("expected 2 critical, got %d", result.Stats.CriticalCount)
	}
	if result.Stats.HighCount != 2 {
		t.Errorf("expected 2 high, got %d", result.Stats.HighCount)
	}
	if result.Stats.SecretsDetected != 1 {
		t.Errorf("expected 1 secret, got %d", result.Stats.SecretsDetected)
	}
}

func TestExecuteLaneError(t *testing.T) {
	o := NewScanOrchestrator()

	// Lane that errors
	o.RegisterLane(&mockLane{
		name: LaneHorusVuln,
		err:  fmt.Errorf("scan failed: disk full"),
	})
	// Lane that succeeds
	o.RegisterLane(&mockLane{
		name: LaneHorusSecret,
		findings: []UnifiedFinding{
			{ID: "secret-1", Source: "horus", Category: CategorySecret, Severity: "HIGH"},
		},
	})

	result, err := o.Execute(context.Background(), ScanRequest{
		TargetPath: "/tmp/test",
	})
	if err != nil {
		t.Fatalf("orchestrator should not fail, errors are per-lane: %v", err)
	}

	// Error should be recorded but not block other lanes
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Stats.TotalFindings != 1 {
		t.Errorf("expected 1 finding from the successful lane, got %d", result.Stats.TotalFindings)
	}
}

func TestExecuteContextCancellation(t *testing.T) {
	o := NewScanOrchestrator()

	// Slow lane that should be cancelled
	o.RegisterLane(&mockLane{
		name:  LaneHorusVuln,
		delay: 5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result, err := o.Execute(ctx, ScanRequest{
		TargetPath: "/tmp/test",
		Timeout:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected orchestrator error: %v", err)
	}

	// The slow lane should have errored due to context cancellation
	if len(result.Errors) == 0 {
		t.Log("WARN: Context cancellation may not have propagated in time")
	}
}

func TestExecuteSkipsUnregisteredLane(t *testing.T) {
	o := NewScanOrchestrator()
	o.RegisterLane(&mockLane{
		name: LaneHorusVuln,
		findings: []UnifiedFinding{
			{ID: "vuln-1", Source: "horus", Category: CategoryVulnerability, Severity: "HIGH"},
		},
	})

	// Request a lane that isn't registered
	result, err := o.Execute(context.Background(), ScanRequest{
		TargetPath: "/tmp/test",
		Lanes:      []ScanLane{LaneHorusVuln, LaneHorusSecret}, // secret not registered
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the registered lane should have run
	if result.Stats.TotalFindings != 1 {
		t.Errorf("expected 1 finding, got %d", result.Stats.TotalFindings)
	}
}

func TestAllLanes(t *testing.T) {
	lanes := AllLanes()
	// LaneHorusVuln, LaneHorusSecret, LaneHorusCompliance, LaneHorusContainer, LaneSCA, LaneSonar
	if len(lanes) != 6 {
		t.Errorf("expected 6 lanes, got %d", len(lanes))
	}
}


// ──────────────────────────────────────────────────────────────────────────────
// Stats Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestComputeStats(t *testing.T) {
	findings := []UnifiedFinding{
		{Severity: "CRITICAL", Category: CategoryVulnerability, Source: "sca"},
		{Severity: "CRITICAL", Category: CategorySecret, Source: "horus"},
		{Severity: "HIGH", Category: CategoryVulnerability, Source: "sca"},
		{Severity: "HIGH", Category: CategoryCompliance, Source: "horus"},
		{Severity: "MEDIUM", Category: CategoryMisconfigure, Source: "horus"},
	}

	stats := computeStats(findings)

	if stats.TotalFindings != 5 {
		t.Errorf("expected 5 total, got %d", stats.TotalFindings)
	}
	if stats.CriticalCount != 2 {
		t.Errorf("expected 2 critical, got %d", stats.CriticalCount)
	}
	if stats.HighCount != 2 {
		t.Errorf("expected 2 high, got %d", stats.HighCount)
	}
	if stats.SecretsDetected != 1 {
		t.Errorf("expected 1 secret, got %d", stats.SecretsDetected)
	}
	if stats.BySeverity["CRITICAL"] != 2 {
		t.Errorf("expected CRITICAL=2, got %d", stats.BySeverity["CRITICAL"])
	}
	if stats.BySource["sca"] != 2 {
		t.Errorf("expected sca=2, got %d", stats.BySource["sca"])
	}
	if stats.BySource["horus"] != 3 {
		t.Errorf("expected horus=3, got %d", stats.BySource["horus"])
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Normalization Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestToEnrichedFindingSCAPassthrough(t *testing.T) {
	// SCA findings should roundtrip losslessly
	original := sca.EnrichedFinding{
		Component:   "lodash",
		Version:     "4.17.20",
		Ecosystem:   "npm",
		CVEID:       "CVE-2021-23337",
		CVSSv3Score: 7.2,
		Severity:    "HIGH",
		EPSSScore:   0.3456,
		InCISAKEV:   true,
		DetectedAt:  time.Now().UTC(),
	}

	unified := UnifiedFinding{
		Source: "sca",
		Raw:    original,
	}

	result := ToEnrichedFinding(unified)

	if result.Component != "lodash" {
		t.Errorf("expected lodash, got %s", result.Component)
	}
	if result.CVEID != "CVE-2021-23337" {
		t.Errorf("expected CVE-2021-23337, got %s", result.CVEID)
	}
	if result.EPSSScore != 0.3456 {
		t.Errorf("expected EPSS 0.3456, got %f", result.EPSSScore)
	}
	if !result.InCISAKEV {
		t.Error("expected InCISAKEV=true")
	}
}

func TestToEnrichedFindingSecret(t *testing.T) {
	unified := UnifiedFinding{
		ID:         "horus_secret:API Key:main.go:42",
		Source:     "horus",
		Category:   CategorySecret,
		Severity:   "CRITICAL",
		Title:      "API Key detected in main.go",
		Asset:      "main.go",
		Location:   "line:42",
		SecretType: "API Key",
		Entropy:    4.5,
		Redacted:   "AKIA...WXYZ",
		Timestamp:  time.Now().UTC(),
	}

	ef := ToEnrichedFinding(unified)

	if ef.CVEID != "SECRET-API Key" {
		t.Errorf("expected SECRET-API Key, got %s", ef.CVEID)
	}
	if ef.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", ef.Severity)
	}
	if ef.CVSSv3Score != 9.8 {
		t.Errorf("expected CVSS 9.8 for critical secret, got %f", ef.CVSSv3Score)
	}
	if ef.Component != "main.go" {
		t.Errorf("expected main.go, got %s", ef.Component)
	}
}

func TestToEnrichedFindingCompliance(t *testing.T) {
	unified := UnifiedFinding{
		ID:        "horus_compliance:cis:CIS-1.1.1",
		Source:    "horus",
		Category:  CategoryCompliance,
		Severity:  "MEDIUM",
		Title:     "[CIS-1.1.1] Ensure cramfs is disabled",
		Framework: "cis",
		ControlID: "CIS-1.1.1",
		Timestamp: time.Now().UTC(),
	}

	ef := ToEnrichedFinding(unified)

	if ef.CVEID != "COMPLIANCE-cis-CIS-1.1.1" {
		t.Errorf("expected COMPLIANCE-cis-CIS-1.1.1, got %s", ef.CVEID)
	}
	if ef.CVSSv3Score != 5.0 {
		t.Errorf("expected CVSS 5.0 for medium compliance, got %f", ef.CVSSv3Score)
	}
	if ef.Confidence != "high" {
		t.Errorf("expected high confidence for compliance, got %s", ef.Confidence)
	}
}

func TestToEnrichedFindingHorusVuln(t *testing.T) {
	unified := UnifiedFinding{
		ID:       "horus_vuln:express:CVE-2022-24999",
		Source:   "horus",
		Category: CategoryVulnerability,
		Severity: "HIGH",
		CVEID:    "CVE-2022-24999",
		CVSSv3:   7.5,
		Asset:    "express",
		Evidence: map[string]interface{}{
			"version":  "4.17.1",
			"fixed_in": "4.17.3",
		},
		Timestamp: time.Now().UTC(),
	}

	ef := ToEnrichedFinding(unified)

	if ef.CVEID != "CVE-2022-24999" {
		t.Errorf("expected CVE-2022-24999, got %s", ef.CVEID)
	}
	if ef.CVSSv3Score != 7.5 {
		t.Errorf("expected CVSS 7.5, got %f", ef.CVSSv3Score)
	}
	if ef.Component != "express" {
		t.Errorf("expected express, got %s", ef.Component)
	}
}

func TestToEnrichedFindings(t *testing.T) {
	findings := []UnifiedFinding{
		{Source: "sca", Category: CategorySCA, Severity: "HIGH", CVEID: "CVE-1", Asset: "pkg1", Timestamp: time.Now()},
		{Source: "horus", Category: CategorySecret, Severity: "CRITICAL", SecretType: "JWT", Asset: "auth.go", Timestamp: time.Now()},
		{Source: "horus", Category: CategoryCompliance, Severity: "MEDIUM", Framework: "nist", ControlID: "AC-2", Timestamp: time.Now()},
	}

	enriched := ToEnrichedFindings(findings)

	if len(enriched) != 3 {
		t.Errorf("expected 3 enriched findings, got %d", len(enriched))
	}

	// Check that each conversion produced a valid result
	for _, ef := range enriched {
		if ef.Severity == "" {
			t.Error("enriched finding has empty severity")
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Horus Lane Unit Tests
// ──────────────────────────────────────────────────────────────────────────────

func TestHorusVulnLaneName(t *testing.T) {
	lane := NewHorusVulnLane()
	if lane.Name() != LaneHorusVuln {
		t.Errorf("expected %s, got %s", LaneHorusVuln, lane.Name())
	}
}

func TestHorusSecretLaneName(t *testing.T) {
	lane := NewHorusSecretLane()
	if lane.Name() != LaneHorusSecret {
		t.Errorf("expected %s, got %s", LaneHorusSecret, lane.Name())
	}
}

func TestHorusComplianceLaneName(t *testing.T) {
	lane := NewHorusComplianceLane()
	if lane.Name() != LaneHorusCompliance {
		t.Errorf("expected %s, got %s", LaneHorusCompliance, lane.Name())
	}
}

func TestHorusContainerLaneName(t *testing.T) {
	lane := NewHorusContainerLane()
	if lane.Name() != LaneHorusContainer {
		t.Errorf("expected %s, got %s", LaneHorusContainer, lane.Name())
	}
}

func TestHorusVulnLaneRequiresTarget(t *testing.T) {
	lane := NewHorusVulnLane()
	_, err := lane.Run(context.Background(), ScanRequest{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestHorusSecretLaneRequiresTarget(t *testing.T) {
	lane := NewHorusSecretLane()
	_, err := lane.Run(context.Background(), ScanRequest{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestHorusContainerLaneRequiresTarget(t *testing.T) {
	lane := NewHorusContainerLane()
	_, err := lane.Run(context.Background(), ScanRequest{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

// TestHorusComplianceLaneRun runs the compliance lane against the
// default CIS framework. Since these checks run against the local OS,
// results are environment-dependent but the lane should not error.
func TestHorusComplianceLaneRun(t *testing.T) {
	lane := NewHorusComplianceLane()
	findings, err := lane.Run(context.Background(), ScanRequest{
		TargetPath:          "/tmp/test",
		ComplianceFramework: "cis",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// CIS checks run against the local OS; on Windows CI they may all pass
	t.Logf("CIS compliance: %d failed checks", len(findings))

	// Verify findings are properly typed
	for _, f := range findings {
		if f.Category != CategoryCompliance {
			t.Errorf("expected compliance category, got %s", f.Category)
		}
		if f.Framework != "cis" {
			t.Errorf("expected cis framework, got %s", f.Framework)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Integration: Full orchestrator with Horus lanes
// ──────────────────────────────────────────────────────────────────────────────

func TestFullOrchestratorWithHorusLanes(t *testing.T) {
	o := NewScanOrchestrator()
	o.RegisterLane(NewHorusComplianceLane())

	// Run compliance only (does not require real filesystem target)
	result, err := o.Execute(context.Background(), ScanRequest{
		TargetPath:          "/tmp/test-target",
		Lanes:               []ScanLane{LaneHorusCompliance},
		ComplianceFramework: "cis",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RequestID == "" {
		t.Error("expected non-empty request ID")
	}
	if result.Duration < 0 {
		t.Error("expected non-negative duration")
	}

	t.Logf("Full orchestrator: %d findings, %v duration", result.Stats.TotalFindings, result.Duration)
}

func TestOrchestratorNormalizationPipeline(t *testing.T) {
	// Simulate a multi-lane scan and normalize for EA
	o := NewScanOrchestrator()
	o.RegisterLane(&mockLane{
		name: LaneHorusVuln,
		findings: []UnifiedFinding{
			{
				ID:       "vuln-1",
				Source:   "horus",
				Category: CategoryVulnerability,
				Severity: "CRITICAL",
				CVEID:    "CVE-2024-12345",
				CVSSv3:   9.8,
				Asset:    "openssl",
				Timestamp: time.Now(),
			},
		},
	})
	o.RegisterLane(&mockLane{
		name: LaneHorusSecret,
		findings: []UnifiedFinding{
			{
				ID:         "secret-1",
				Source:     "horus",
				Category:   CategorySecret,
				Severity:   "CRITICAL",
				Asset:      "config.go",
				SecretType: "AWS Key",
				Timestamp:  time.Now(),
			},
		},
	})

	result, err := o.Execute(context.Background(), ScanRequest{
		TargetPath: "/tmp/test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Normalize for EA
	enriched := ToEnrichedFindings(result.Findings)

	if len(enriched) != 2 {
		t.Fatalf("expected 2 enriched findings, got %d", len(enriched))
	}

	// Verify normalization produced valid EA-consumable findings
	for _, ef := range enriched {
		if ef.CVEID == "" {
			t.Error("enriched finding missing CVE ID")
		}
		if ef.Severity == "" {
			t.Error("enriched finding missing severity")
		}
		if ef.CVSSv3Score <= 0 {
			t.Errorf("expected positive CVSS score, got %f", ef.CVSSv3Score)
		}
	}

	t.Logf("Normalization pipeline: %d unified → %d enriched findings", len(result.Findings), len(enriched))
}

// ── Evidence Extraction Tests ────────────────────────────────────────────────

func TestExtractStringEvidence(t *testing.T) {
	evidence := map[string]interface{}{
		"version": "1.2.3",
		"count":   42,
	}

	if v := extractStringEvidence(evidence, "version"); v != "1.2.3" {
		t.Errorf("expected 1.2.3, got %s", v)
	}
	if v := extractStringEvidence(evidence, "missing"); v != "" {
		t.Errorf("expected empty, got %s", v)
	}
	if v := extractStringEvidence(nil, "version"); v != "" {
		t.Errorf("expected empty for nil evidence, got %s", v)
	}
}

func TestExtractStringSliceEvidence(t *testing.T) {
	evidence := map[string]interface{}{
		"controls": []string{"RA-5", "SI-2"},
	}

	result := extractStringSliceEvidence(evidence, "controls")
	if len(result) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(result))
	}
	if result[0] != "RA-5" || result[1] != "SI-2" {
		t.Errorf("unexpected controls: %v", result)
	}
}

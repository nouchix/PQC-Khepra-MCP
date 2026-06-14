// Package sca — Integration Tests
//
// These tests validate the full SCA pipeline end-to-end:
//   Syft (SBOM) → Grype (vuln matching) → Enricher (threat intel) → Compliance (CMMC/CCI/STIG)
//
// Prerequisites: `syft` and `grype` binaries must be in PATH.
// Tests are skipped automatically if binaries are not available.

package sca

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIntegration_FullPipeline runs the complete SCA pipeline against a real project.
func TestIntegration_FullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check binary prerequisites
	requireBinary(t, "syft")
	requireBinary(t, "grype")

	// Use a small test fixture to avoid timeouts
	projectRoot := findProjectRoot(t)
	targetPath := filepath.Join(projectRoot, "pkg", "sca", "testdata", "tiny-project")
	if _, err := os.Stat(targetPath); err != nil {
		t.Fatalf("Test fixture not found: %s", targetPath)
	}
	t.Logf("Scanning project: %s", targetPath)

	// Create pipeline with nil feed manager (no live API calls in tests)
	pipeline := NewPipeline(nil)

	// Load compliance data from docs/
	docsDir := filepath.Join(projectRoot, "docs")
	pipeline.LoadComplianceData(docsDir)
	t.Log("Compliance data loaded")

	// Run the full pipeline
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	start := time.Now()
	result, err := pipeline.ScanAndEnrich(ctx, targetPath)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ScanAndEnrich failed: %v", err)
	}

	// ── Validate results ─────────────────────────────────────────────────
	t.Logf("Pipeline completed in %s", elapsed.Round(time.Millisecond))
	t.Logf("Total findings:    %d", result.TotalCount)
	t.Logf("High-risk findings: %d", result.HighRiskCount)
	t.Logf("SBOM components:   %d", result.SBOMComponentCount)
	t.Logf("Scanner meta:      Syft=%s Grype=%s DB=%s",
		result.ScannerMeta.SyftVersion,
		result.ScannerMeta.GrypeVersion,
		result.ScannerMeta.GrypeDBVersion)

	// We should have found at least some components in the SBOM
	if result.SBOMComponentCount == 0 {
		t.Error("Expected non-zero SBOM component count")
	}

	// Validate scanner metadata was captured
	if result.ScannerMeta.ScannedAt.IsZero() {
		t.Error("ScannerMeta.ScannedAt should be set")
	}

	// ── Validate individual findings ─────────────────────────────────────
	for i, f := range result.Findings {
		// Every finding must have core identity fields
		if f.CVEID == "" {
			t.Errorf("Finding[%d]: missing CVE ID", i)
		}
		if f.Component == "" {
			t.Errorf("Finding[%d] (%s): missing component name", i, f.CVEID)
		}
		if f.Severity == "" {
			t.Errorf("Finding[%d] (%s): missing severity", i, f.CVEID)
		}

		// Compliance fields should always be initialized (never nil)
		if f.NIST53Controls == nil {
			t.Errorf("Finding[%d] (%s): NIST53Controls should not be nil", i, f.CVEID)
		}
		if f.NIST171Controls == nil {
			t.Errorf("Finding[%d] (%s): NIST171Controls should not be nil", i, f.CVEID)
		}
		if f.NIST172Controls == nil {
			t.Errorf("Finding[%d] (%s): NIST172Controls should not be nil", i, f.CVEID)
		}
		if f.CCIReferences == nil {
			t.Errorf("Finding[%d] (%s): CCIReferences should not be nil", i, f.CVEID)
		}
		if f.STIGFindings == nil {
			t.Errorf("Finding[%d] (%s): STIGFindings should not be nil", i, f.CVEID)
		}

		// Every SCA finding should have at least RA-5 and SI-2
		if len(f.NIST53Controls) < 2 {
			t.Errorf("Finding[%d] (%s): expected at least RA-5 + SI-2, got %v", i, f.CVEID, f.NIST53Controls)
		}

		// VEX status should be set
		if f.VEXStatus == "" {
			t.Errorf("Finding[%d] (%s): VEXStatus should be set", i, f.CVEID)
		}

		// Confidence should be calculated
		if f.Confidence == "" {
			t.Errorf("Finding[%d] (%s): Confidence should be set", i, f.CVEID)
		}

		// RiskScore should be computable
		_ = f.RiskScore()
	}

	// ── Print sample findings for review ─────────────────────────────────
	sampleCount := 3
	if len(result.Findings) < sampleCount {
		sampleCount = len(result.Findings)
	}

	for i := 0; i < sampleCount; i++ {
		f := result.Findings[i]
		t.Logf("\n=== Finding %d/%d ===", i+1, result.TotalCount)
		t.Logf("  CVE:        %s", f.CVEID)
		t.Logf("  Component:  %s@%s (%s)", f.Component, f.Version, f.Ecosystem)
		t.Logf("  Severity:   %s (CVSS %.1f)", f.Severity, f.CVSSv3Score)
		t.Logf("  RiskScore:  %.2f", f.RiskScore())
		t.Logf("  Confidence: %s", f.Confidence)
		t.Logf("  NIST 53:    %v", f.NIST53Controls)
		t.Logf("  NIST 171:   %v", f.NIST171Controls)
		t.Logf("  NIST 172:   %v", f.NIST172Controls)
		t.Logf("  CCIs:       %v", f.CCIReferences)
		t.Logf("  STIGs:      %d entries", len(f.STIGFindings))
		t.Logf("  CMMC:       %s", f.CMMCDomain)
		t.Logf("  HighRisk:   %v", f.IsHighRisk())
		t.Logf("  CISA KEV:   %v", f.InCISAKEV)
		t.Logf("  EPSS:       %.4f (p%.0f)", f.EPSSScore, f.EPSSPercentile*100)
		t.Logf("  Sources:    %v", f.Sources)
	}

	// ── JSON serialization round-trip ────────────────────────────────────
	if len(result.Findings) > 0 {
		data, err := json.MarshalIndent(result.Findings[0], "", "  ")
		if err != nil {
			t.Errorf("JSON marshal failed: %v", err)
		} else {
			t.Logf("\n=== Sample JSON Output ===\n%s", string(data))

			// Verify round-trip
			var roundTrip EnrichedFinding
			if err := json.Unmarshal(data, &roundTrip); err != nil {
				t.Errorf("JSON round-trip unmarshal failed: %v", err)
			}
			if roundTrip.CVEID != result.Findings[0].CVEID {
				t.Errorf("JSON round-trip: CVE mismatch: %s vs %s", roundTrip.CVEID, result.Findings[0].CVEID)
			}
		}
	}
}

// TestIntegration_ComplianceMapperCSVLoad validates CCI CSV parsing at scale.
func TestIntegration_ComplianceMapperCSVLoad(t *testing.T) {
	projectRoot := findProjectRoot(t)
	docsDir := filepath.Join(projectRoot, "docs")

	cm := NewComplianceMapper()

	// Load NIST 53 → 171
	nist171Path := filepath.Join(docsDir, "NIST53_to_171.csv")
	if _, err := os.Stat(nist171Path); err == nil {
		if err := cm.LoadCSV(nist171Path); err != nil {
			t.Fatalf("LoadCSV(NIST53_to_171) failed: %v", err)
		}
		t.Log("NIST53_to_171.csv loaded successfully")
	} else {
		t.Skip("NIST53_to_171.csv not found")
	}

	// Load NIST 53 → 172
	nist172Path := filepath.Join(docsDir, "NIST53_to_172.csv")
	if _, err := os.Stat(nist172Path); err == nil {
		if err := cm.LoadCSV172(nist172Path); err != nil {
			t.Fatalf("LoadCSV172(NIST53_to_172) failed: %v", err)
		}
		t.Log("NIST53_to_172.csv loaded successfully")
	}

	// Load CCI → NIST 53 (the big one: 7,434 rows)
	cciPath := filepath.Join(docsDir, "CCI_to_NIST53.csv")
	if _, err := os.Stat(cciPath); err == nil {
		start := time.Now()
		if err := cm.LoadCCICSV(cciPath); err != nil {
			t.Fatalf("LoadCCICSV failed: %v", err)
		}
		elapsed := time.Since(start)
		t.Logf("CCI_to_NIST53.csv loaded in %s", elapsed)

		// Verify we got data
		cm.mu.RLock()
		cciCount := 0
		for _, entries := range cm.nist53toCCI {
			cciCount += len(entries)
		}
		controlCount := len(cm.nist53toCCI)
		cm.mu.RUnlock()

		t.Logf("CCI entries loaded: %d across %d NIST 800-53 controls", cciCount, controlCount)

		if cciCount < 1000 {
			t.Errorf("Expected at least 1000 CCI entries, got %d", cciCount)
		}
	} else {
		t.Skip("CCI_to_NIST53.csv not found")
	}

	// Test a known mapping: RA-5 should map to something
	testFinding := &EnrichedFinding{
		CVEID:     "CVE-2024-0001",
		Component: "test-component",
		Severity:  "HIGH",
		Sources:   []string{"grype"},
	}

	cm.MapFinding(testFinding)

	if len(testFinding.NIST53Controls) == 0 {
		t.Error("Expected NIST 53 controls to be mapped")
	}
	if len(testFinding.NIST171Controls) == 0 {
		t.Error("Expected NIST 171 controls to be mapped")
	}
	if testFinding.CMMCDomain == "" {
		t.Error("Expected CMMC domain to be set")
	}

	t.Logf("Test finding mapped:")
	t.Logf("  NIST 53:  %v", testFinding.NIST53Controls)
	t.Logf("  NIST 171: %v", testFinding.NIST171Controls)
	t.Logf("  NIST 172: %v", testFinding.NIST172Controls)
	t.Logf("  CCIs:     %v", testFinding.CCIReferences)
	t.Logf("  STIGs:    %d findings", len(testFinding.STIGFindings))
	t.Logf("  CMMC:     %s", testFinding.CMMCDomain)
}

// TestIntegration_SyftOnly validates Syft adapter in isolation.
func TestIntegration_SyftOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	requireBinary(t, "syft")

	projectRoot := findProjectRoot(t)
	targetPath := filepath.Join(projectRoot, "pkg", "sca", "testdata", "tiny-project")
	adapter := NewSyftAdapter()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	bom, meta, err := adapter.GenerateSBOM(ctx, targetPath)
	if err != nil {
		t.Fatalf("Syft SBOM generation failed: %v", err)
	}

	t.Logf("SBOM generated: %d components", len(bom.Components))
	t.Logf("Syft version: %s", meta.SyftVersion)

	if len(bom.Components) == 0 {
		t.Error("Expected non-zero components in SBOM")
	}

	// Validate component structure
	for i, c := range bom.Components {
		if c.Name == "" {
			t.Errorf("Component[%d]: missing name", i)
		}
		if i < 5 {
			t.Logf("  Component: %s@%s (type=%s, purl=%s)", c.Name, c.Version, c.Type, c.PURL)
		}
	}
}

// TestIntegration_GrypeOnly validates Grype adapter in isolation.
func TestIntegration_GrypeOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	requireBinary(t, "grype")

	projectRoot := findProjectRoot(t)
	targetPath := filepath.Join(projectRoot, "pkg", "sca", "testdata", "tiny-project")
	adapter := NewGrypeAdapter()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	findings, meta, err := adapter.MatchVulnerabilities(ctx, targetPath)
	if err != nil {
		t.Fatalf("Grype matching failed: %v", err)
	}

	t.Logf("Grype findings: %d", len(findings))
	t.Logf("Grype version: %s, DB: %s", meta.GrypeVersion, meta.GrypeDBVersion)

	// Print first few findings
	for i, f := range findings {
		if i >= 5 {
			break
		}
		t.Logf("  %s: %s@%s (%s, CVSS %.1f)", f.CVEID, f.Component, f.Version, f.Severity, f.CVSSv3Score)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("Skipping: %s binary not found in PATH", name)
	}
}

func findProjectRoot(t *testing.T) string {
	t.Helper()

	// Walk up from current dir looking for go.mod
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Cannot get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Fallback: try common project paths
	candidates := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "blackbox", "khepra protocol"),
		".",
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "go.mod")); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}

	t.Fatal("Cannot find project root (no go.mod found)")
	return ""
}

// TestUnit_NormalizeNIST53Ref validates the NIST 800-53 reference normalizer.
func TestUnit_NormalizeNIST53Ref(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"RA-5", "RA-5"},
		{"RA-5(2)", "RA-5(2)"},
		{"RA-5 a", "RA-5"},
		{"RA-5.1 (ii)", "RA-5"},
		{"SI-2", "SI-2"},
		{"CM-8(1)", "CM-8(1)"},
		{"  RA-5  ", "RA-5"},
		{"AC-1 a.1 (a)", "AC-1"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q->%q", tt.input, tt.want), func(t *testing.T) {
			got := normalizeNIST53Ref(tt.input)
			if got != tt.want {
				t.Errorf("normalizeNIST53Ref(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestUnit_ConfidenceScoring validates confidence calculation logic.
func TestUnit_ConfidenceScoring(t *testing.T) {
	tests := []struct {
		name string
		f    EnrichedFinding
		want string
	}{
		{
			name: "all signals = high",
			f: EnrichedFinding{
				InCISAKEV:       true,
				EPSSScore:       0.95,
				InTheWild:       true,
				MITRETechniques: []string{"T1190"},
			},
			want: string(ConfidenceHigh),
		},
		{
			name: "KEV + EPSS = medium (65 pts, need 70 for high)",
			f: EnrichedFinding{
				InCISAKEV: true,
				EPSSScore: 0.5,
			},
			want: string(ConfidenceMedium),
		},
		{
			name: "EPSS only = low (25 pts, need 40 for medium)",
			f: EnrichedFinding{
				EPSSScore: 0.3,
			},
			want: string(ConfidenceLow),
		},
		{
			name: "no signals = low",
			f:    EnrichedFinding{},
			want: string(ConfidenceLow),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateConfidence(&tt.f)
			if got != tt.want {
				t.Errorf("calculateConfidence() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestUnit_RiskScore validates the risk scoring formula.
func TestUnit_RiskScore(t *testing.T) {
	f := EnrichedFinding{
		CVSSv3Score: 9.8,
		InCISAKEV:  true,
		InTheWild:  true,
		EPSSScore:  0.9,
	}

	score := f.RiskScore()
	if score <= 0 {
		t.Errorf("RiskScore should be positive for critical vuln, got %.2f", score)
	}

	// A critical KEV + InTheWild should have a high score
	basic := EnrichedFinding{CVSSv3Score: 5.0}
	if basic.RiskScore() >= score {
		t.Errorf("Critical KEV vuln should score higher than basic medium: %.2f vs %.2f", score, basic.RiskScore())
	}
}

// TestUnit_AppendIfNew validates the deduplication helper.
func TestUnit_AppendIfNew(t *testing.T) {
	s := []string{"a", "b"}
	s = appendIfNew(s, "b") // should not add
	if len(s) != 2 {
		t.Errorf("appendIfNew should not duplicate: got %v", s)
	}
	s = appendIfNew(s, "c") // should add
	if len(s) != 3 || s[2] != "c" {
		t.Errorf("appendIfNew should add new: got %v", s)
	}
}

// TestUnit_JSONMarshalNilSafety ensures nil slices serialize as [] not null.
func TestUnit_JSONMarshalNilSafety(t *testing.T) {
	f := EnrichedFinding{
		CVEID:     "CVE-2024-0001",
		Component: "test",
	}
	// All slice fields are nil

	data, err := json.Marshal(&f)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	s := string(data)
	nilFields := []string{
		"nist_53_controls", "nist_171_controls", "nist_172_controls",
		"cci_references", "stig_findings", "sources",
	}
	for _, field := range nilFields {
		needle := fmt.Sprintf(`"%s":null`, field)
		if strings.Contains(s, needle) {
			t.Errorf("Field %q serialized as null — should be []: %s", field, s)
		}
	}
}

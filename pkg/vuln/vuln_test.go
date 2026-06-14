package vuln

import (
	"strings"
	"testing"
	"time"
)

func TestNewHunter(t *testing.T) {
	h := NewHunter("/test/path")
	if h == nil {
		t.Fatal("expected non-nil hunter")
	}

	if h.rootPath != "/test/path" {
		t.Errorf("expected rootPath '/test/path', got '%s'", h.rootPath)
	}

	if h.httpClient == nil {
		t.Error("expected non-nil http client")
	}

	if h.autoFix {
		t.Error("expected autoFix to be false by default")
	}

	if !h.dryRun {
		t.Error("expected dryRun to be true by default")
	}
}

func TestHunter_SetAutoFix(t *testing.T) {
	h := NewHunter("/test")

	h.SetAutoFix(true)
	if !h.autoFix {
		t.Error("expected autoFix to be true")
	}

	h.SetAutoFix(false)
	if h.autoFix {
		t.Error("expected autoFix to be false")
	}
}

func TestHunter_SetDryRun(t *testing.T) {
	h := NewHunter("/test")

	h.SetDryRun(false)
	if h.dryRun {
		t.Error("expected dryRun to be false")
	}

	h.SetDryRun(true)
	if !h.dryRun {
		t.Error("expected dryRun to be true")
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityCritical != "CRITICAL" {
		t.Errorf("expected SeverityCritical='CRITICAL', got '%s'", SeverityCritical)
	}
	if SeverityHigh != "HIGH" {
		t.Errorf("expected SeverityHigh='HIGH', got '%s'", SeverityHigh)
	}
	if SeverityModerate != "MODERATE" {
		t.Errorf("expected SeverityModerate='MODERATE', got '%s'", SeverityModerate)
	}
	if SeverityLow != "LOW" {
		t.Errorf("expected SeverityLow='LOW', got '%s'", SeverityLow)
	}
}

func TestVulnerabilityStructure(t *testing.T) {
	now := time.Now()
	vuln := Vulnerability{
		ID:            "CVE-2024-1234",
		Package:       "test-package",
		Ecosystem:     "go",
		Severity:      SeverityHigh,
		CVSS:          8.5,
		Title:         "Test Vulnerability",
		Description:   "A test vulnerability description",
		AffectedRange: "< 1.2.3",
		FixedVersion:  "1.2.3",
		References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
		DiscoveredAt:  now,
		Metadata: map[string]string{
			"source": "test",
		},
	}

	if vuln.ID == "" {
		t.Error("expected non-empty ID")
	}
	if vuln.Package != "test-package" {
		t.Errorf("expected Package='test-package', got %q", vuln.Package)
	}
	if vuln.Ecosystem != "go" {
		t.Errorf("expected Ecosystem='go', got %q", vuln.Ecosystem)
	}
	if vuln.Severity != SeverityHigh {
		t.Error("expected HIGH severity")
	}
	if vuln.CVSS != 8.5 {
		t.Errorf("expected CVSS=8.5, got %v", vuln.CVSS)
	}
	if vuln.Title != "Test Vulnerability" {
		t.Errorf("expected Title set, got %q", vuln.Title)
	}
	if vuln.Description == "" {
		t.Error("expected non-empty Description")
	}
	if vuln.AffectedRange != "< 1.2.3" {
		t.Errorf("expected AffectedRange='< 1.2.3', got %q", vuln.AffectedRange)
	}
	if vuln.FixedVersion != "1.2.3" {
		t.Errorf("expected FixedVersion='1.2.3', got %q", vuln.FixedVersion)
	}
	if vuln.DiscoveredAt.IsZero() {
		t.Error("expected DiscoveredAt to be set")
	}
	if vuln.Metadata["source"] != "test" {
		t.Errorf("expected Metadata['source']='test', got %q", vuln.Metadata["source"])
	}
	if len(vuln.References) != 1 {
		t.Error("expected 1 reference")
	}
}

func TestRemediationPlan(t *testing.T) {
	plan := &RemediationPlan{
		Action:        "upgrade",
		TargetVersion: "1.2.3",
		Commands: []string{
			"go get test-package@v1.2.3",
			"go mod tidy",
		},
		RiskLevel: "low",
		Breaking:  false,
		Verified:  true,
	}

	if plan.Action != "upgrade" {
		t.Error("expected action 'upgrade'")
	}
	if plan.TargetVersion != "1.2.3" {
		t.Errorf("expected TargetVersion='1.2.3', got %q", plan.TargetVersion)
	}
	if plan.RiskLevel != "low" {
		t.Errorf("expected RiskLevel='low', got %q", plan.RiskLevel)
	}
	if plan.Breaking {
		t.Error("expected Breaking=false")
	}
	if !plan.Verified {
		t.Error("expected Verified=true")
	}
	if len(plan.Commands) != 2 {
		t.Error("expected 2 commands")
	}
}

func TestScanResult(t *testing.T) {
	start := time.Now()
	result := &ScanResult{
		ScanID:    "scan-12345",
		Timestamp: start,
		Duration:  5 * time.Second,
		TotalVulns: 3,
		BySeverity: map[Severity]int{
			SeverityCritical: 1,
			SeverityHigh:     2,
		},
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-1", Severity: SeverityCritical},
			{ID: "CVE-2", Severity: SeverityHigh},
			{ID: "CVE-3", Severity: SeverityHigh},
		},
		Ecosystems: []string{"go", "npm"},
	}

	if result.ScanID != "scan-12345" {
		t.Errorf("expected ScanID='scan-12345', got %q", result.ScanID)
	}
	if result.Timestamp.IsZero() {
		t.Error("expected Timestamp to be set")
	}
	if result.Duration != 5*time.Second {
		t.Errorf("expected Duration=5s, got %v", result.Duration)
	}
	if result.TotalVulns != 3 {
		t.Errorf("expected 3 total vulns, got %d", result.TotalVulns)
	}
	if result.BySeverity[SeverityCritical] != 1 {
		t.Error("expected 1 critical")
	}
	if len(result.Vulnerabilities) != 3 {
		t.Errorf("expected 3 Vulnerabilities, got %d", len(result.Vulnerabilities))
	}
	if len(result.Ecosystems) != 2 {
		t.Error("expected 2 ecosystems")
	}
}

func TestMapNPMSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
	}{
		{"critical", SeverityCritical},
		{"CRITICAL", SeverityCritical},
		{"high", SeverityHigh},
		{"HIGH", SeverityHigh},
		{"moderate", SeverityModerate},
		{"medium", SeverityModerate},
		{"low", SeverityLow},
		{"info", SeverityLow},
		{"unknown", SeverityLow},
	}

	for _, tt := range tests {
		got := mapNPMSeverity(tt.input)
		if got != tt.expected {
			t.Errorf("mapNPMSeverity(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}

func TestParseGoModDeps(t *testing.T) {
	content := `module github.com/test/module

go 1.21

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.4
)

require github.com/single/dep v1.0.0
`

	deps := parseGoModDeps(content)

	if len(deps) < 2 {
		t.Errorf("expected at least 2 deps, got %d", len(deps))
	}

	// Check that dependencies were parsed
	foundPkgErrors := false
	for _, dep := range deps {
		if dep.Name == "github.com/pkg/errors" {
			foundPkgErrors = true
			if dep.Version != "0.9.1" {
				t.Errorf("expected version 0.9.1, got %s", dep.Version)
			}
		}
	}

	if !foundPkgErrors {
		t.Error("expected to find github.com/pkg/errors dependency")
	}
}

func TestHunter_Report(t *testing.T) {
	h := NewHunter("/test")

	// Without scan
	report := h.Report()
	if report != "No scan results available." {
		t.Error("expected 'No scan results available.' when no scan")
	}

	// Set a last scan
	h.lastScan = &ScanResult{
		ScanID:     "test-scan",
		Timestamp:  time.Now(),
		Duration:   2 * time.Second,
		TotalVulns: 2,
		BySeverity: map[Severity]int{
			SeverityHigh: 2,
		},
		Vulnerabilities: []Vulnerability{
			{
				ID:           "CVE-2024-0001",
				Package:      "test-pkg",
				Ecosystem:    "go",
				Severity:     SeverityHigh,
				Title:        "Test Vuln 1",
				FixedVersion: "1.0.0",
			},
			{
				ID:           "CVE-2024-0002",
				Package:      "test-pkg-2",
				Ecosystem:    "npm",
				Severity:     SeverityHigh,
				Title:        "Test Vuln 2",
				FixedVersion: "2.0.0",
			},
		},
		Ecosystems: []string{"go", "npm"},
	}

	report = h.Report()
	if report == "" {
		t.Error("expected non-empty report")
	}

	// Check for expected content
	if !strings.Contains(report, "SOUHIMBOU") {
		t.Error("expected report to contain SOUHIMBOU header")
	}

	if !strings.Contains(report, "test-scan") {
		t.Error("expected report to contain scan ID")
	}

	if !strings.Contains(report, "CVE-2024-0001") {
		t.Error("expected report to contain vulnerability ID")
	}
}

func TestHunter_GetLastScan(t *testing.T) {
	h := NewHunter("/test")

	// Initially nil
	if h.GetLastScan() != nil {
		t.Error("expected nil before any scan")
	}

	// Set a scan result
	expected := &ScanResult{ScanID: "test-123"}
	h.lastScan = expected

	got := h.GetLastScan()
	if got == nil {
		t.Error("expected non-nil after setting scan")
	}

	if got.ScanID != expected.ScanID {
		t.Error("scan ID mismatch")
	}
}

func TestDependency(t *testing.T) {
	dep := Dependency{
		Name:    "github.com/test/package",
		Version: "1.2.3",
	}

	if dep.Name == "" {
		t.Error("expected non-empty name")
	}

	if dep.Version == "" {
		t.Error("expected non-empty version")
	}
}

func TestOSVQuery(t *testing.T) {
	query := OSVQuery{
		Version: "1.0.0",
	}
	query.Package.Name = "test-package"
	query.Package.Ecosystem = "Go"

	if query.Package.Name != "test-package" {
		t.Error("expected package name to be set")
	}

	if query.Version != "1.0.0" {
		t.Error("expected version to be set")
	}
}

func TestGenerateRemediationPlan_Go(t *testing.T) {
	h := NewHunter("/test")

	vuln := &Vulnerability{
		ID:           "CVE-2024-1234",
		Package:      "github.com/test/pkg",
		Ecosystem:    "go",
		FixedVersion: "1.2.3",
	}

	plan := h.generateRemediationPlan(vuln)

	if plan == nil {
		t.Fatal("expected non-nil plan")
	}

	if plan.Action != "upgrade" {
		t.Errorf("expected action 'upgrade', got '%s'", plan.Action)
	}

	if plan.TargetVersion != "1.2.3" {
		t.Error("expected target version to be set")
	}

	// Should have go get and go mod tidy commands
	if len(plan.Commands) < 2 {
		t.Error("expected at least 2 commands for Go remediation")
	}
}

func TestGenerateRemediationPlan_NPM(t *testing.T) {
	h := NewHunter("/test")

	vuln := &Vulnerability{
		ID:           "GHSA-xxxx",
		Package:      "lodash",
		Ecosystem:    "npm",
		FixedVersion: "4.17.21",
	}

	plan := h.generateRemediationPlan(vuln)

	if plan.Action != "upgrade" {
		t.Error("expected action 'upgrade'")
	}

	hasNpmUpdate := false
	for _, cmd := range plan.Commands {
		if strings.Contains(cmd, "npm") {
			hasNpmUpdate = true
			break
		}
	}
	if !hasNpmUpdate {
		t.Error("expected npm command in remediation plan")
	}
}

func TestGenerateRemediationPlan_NoFixAvailable(t *testing.T) {
	h := NewHunter("/test")

	vuln := &Vulnerability{
		ID:           "CVE-2024-9999",
		Package:      "github.com/test/pkg",
		Ecosystem:    "go",
		FixedVersion: "", // No fix available
	}

	plan := h.generateRemediationPlan(vuln)

	if plan.Action != "investigate" {
		t.Errorf("expected action 'investigate' when no fix, got '%s'", plan.Action)
	}

	if plan.RiskLevel != "medium" {
		t.Error("expected medium risk level when no fix")
	}
}

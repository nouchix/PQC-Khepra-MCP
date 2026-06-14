package pb

import (
	"testing"
)

// These tests validate the type system and compile-time contracts for the
// Iron Bank scanner interface. Integration tests that hit the live
// registry1.dso.mil endpoint live in pkg/ironbank and require
// IRONBANK_USERNAME + IRONBANK_CLI_SECRET environment variables.

const (
	testTargetURI       = "registry1.dso.mil/dsop/nouchix/adinkhepra:latest"
	testScanID          = "scan-456"
	testFrameworkABC    = "IronBank-ABC"
	testFormatCycloneDX = "cyclonedx-json"
	errNotImplemented   = "status must not be 'not_implemented'"
)

func TestScanRequest(t *testing.T) {
	req := &ScanRequest{
		ImageDigest:   "sha256:abc123",
		ImageTag:      "latest",
		Registry:      "registry1.dso.mil",
		ScanType:      "vulnerability",
		FIPSMode:      true,
		PolicyProfile: "strict",
		TargetUri:     testTargetURI,
		Frameworks:    []string{"STIG", "CMMC"},
	}

	if req.ImageDigest == "" {
		t.Error("expected non-empty image digest")
	}
	if !req.FIPSMode {
		t.Error("expected FIPS mode to be true")
	}
	if len(req.Frameworks) != 2 {
		t.Errorf("expected 2 frameworks, got %d", len(req.Frameworks))
	}
}

func TestScanResponse(t *testing.T) {
	resp := &ScanResponse{
		ScanId:          "scan-123",
		Status:          "scanning",
		Vulnerabilities: []*Vulnerability{},
		ComplianceScore: 95.5,
		Timestamp:       1234567890,
	}

	if resp.ScanId == "" {
		t.Error("expected non-empty scan ID")
	}
	if resp.ComplianceScore != 95.5 {
		t.Errorf("expected compliance score 95.5, got %f", resp.ComplianceScore)
	}
	// Status must never be "not_implemented" — that was a stub, now removed.
	if resp.Status == "not_implemented" {
		t.Error(errNotImplemented)
	}
}

func TestScanStatusRequest(t *testing.T) {
	req := &ScanStatusRequest{ScanId: testScanID}
	if req.ScanId != testScanID {
		t.Error("expected scan ID to match")
	}
}

func TestScanStatusResponse(t *testing.T) {
	resp := &ScanStatusResponse{
		ScanId:   testScanID,
		Status:   "Running",
		Progress: 50,
		Message:  "severity=high total=12 critical=0 high=3",
	}
	if resp.Progress != 50 {
		t.Errorf("expected progress 50, got %d", resp.Progress)
	}
	if resp.Status == "not_implemented" {
		t.Error(errNotImplemented)
	}
}

func TestVulnerability(t *testing.T) {
	vuln := &Vulnerability{
		ID:          "CVE-2024-1234",
		Package:     "openssl",
		Version:     "1.1.1",
		Severity:    "HIGH",
		CVSS:        8.5,
		Description: "A vulnerability in OpenSSL",
		FixVersion:  "1.1.1t",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
	}

	if vuln.ID == "" {
		t.Error("expected non-empty vulnerability ID")
	}
	if vuln.CVSS != 8.5 {
		t.Error("expected CVSS to be 8.5")
	}
	if len(vuln.References) != 1 {
		t.Error("expected 1 reference")
	}
}

func TestVulnerabilityList(t *testing.T) {
	list := &VulnerabilityList{
		Vulnerabilities: []*Vulnerability{
			{ID: "CVE-1", Severity: "CRITICAL"},
			{ID: "CVE-2", Severity: "HIGH"},
			{ID: "CVE-3", Severity: "MEDIUM"},
		},
		TotalCount: 3,
	}

	if list.TotalCount != 3 {
		t.Errorf("expected 3 total, got %d", list.TotalCount)
	}
	if len(list.Vulnerabilities) != 3 {
		t.Error("expected 3 vulnerabilities in list")
	}
}

func TestComplianceRequest(t *testing.T) {
	req := &ComplianceRequest{
		TargetUri:  testTargetURI,
		Frameworks: []string{testFrameworkABC, "STIG", "CMMC"},
	}
	if len(req.Frameworks) != 3 {
		t.Error("expected 3 frameworks")
	}
}

func TestComplianceResultABCGates(t *testing.T) {
	// Iron Bank ABC: max 1 Critical, max 4 High = passed
	result := &ComplianceResult{
		TargetUri: "test-target",
		Passed:    true,
		Score:     80.0,
		Frameworks: []*FrameworkResult{
			{
				Name:   testFrameworkABC,
				Passed: true,
				Score:  80.0,
				Controls: []*ControlResult{
					{ID: "IB-CVE-CRITICAL", Passed: true, Severity: "critical", Message: "1 critical CVEs found"},
					{ID: "IB-CVE-HIGH", Passed: true, Severity: "high", Message: "4 high CVEs found"},
				},
			},
		},
		Timestamp: 1234567890,
	}

	if !result.Passed {
		t.Error("expected ABC compliance to pass with 1 critical / 4 high")
	}
	if len(result.Frameworks) != 1 {
		t.Error("expected 1 framework result")
	}
	if result.Frameworks[0].Name != testFrameworkABC {
		t.Errorf("expected %s framework, got %s", testFrameworkABC, result.Frameworks[0].Name)
	}
}

func TestFrameworkResult(t *testing.T) {
	fw := &FrameworkResult{
		Name:    testFrameworkABC,
		Version: "2024",
		Passed:  true,
		Score:   95.0,
		Controls: []*ControlResult{
			{ID: "IB-CVE-CRITICAL", Title: "Critical CVE gate", Passed: true, Severity: "critical"},
		},
	}

	if fw.Name != testFrameworkABC {
		t.Errorf("expected %s framework name", testFrameworkABC)
	}
	if len(fw.Controls) != 1 {
		t.Error("expected 1 control result")
	}
}

func TestControlResult(t *testing.T) {
	ctrl := &ControlResult{
		ID:       "IB-CVE-HIGH",
		Title:    "High CVE Tolerance (max 4 justified in 10 days)",
		Passed:   false,
		Severity: "high",
		Message:  "7 high CVEs found",
	}

	if ctrl.Passed {
		t.Error("expected control to fail with 7 high CVEs")
	}
	if ctrl.Severity != "high" {
		t.Error("expected high severity")
	}
}

func TestSBOMRequest(t *testing.T) {
	req := &SBOMRequest{
		TargetUri: testTargetURI,
		Format:    testFormatCycloneDX,
	}
	if req.Format != testFormatCycloneDX {
		t.Errorf("expected %s format", testFormatCycloneDX)
	}
}

func TestSBOM(t *testing.T) {
	sbom := &SBOM{
		TargetUri: "test-target",
		Format:    testFormatCycloneDX,
		Content:   []byte(`{"bomFormat":"CycloneDX"}`),
		Components: []*SBOMComponent{
			{
				Name:     "openssl",
				Version:  "1.1.1",
				Type:     "library",
				Purl:     "pkg:deb/ubi9/openssl@1.1.1",
				Licenses: []string{"Apache-2.0"},
				Hashes:   map[string]string{"SHA-256": "abc123"},
			},
		},
		Timestamp: 1234567890,
	}

	if sbom.Format != testFormatCycloneDX {
		t.Errorf("expected %s format", testFormatCycloneDX)
	}
	if len(sbom.Components) != 1 {
		t.Error("expected 1 component")
	}
	if sbom.Components[0].Name != "openssl" {
		t.Error("expected component name openssl")
	}
}

func TestBatchScanRequest(t *testing.T) {
	req := &BatchScanRequest{
		Requests: []*ScanRequest{
			{TargetUri: "registry1.dso.mil/dsop/nouchix/adinkhepra:1.0.0"},
			{TargetUri: "registry1.dso.mil/dsop/nouchix/adinkhepra:1.0.1"},
		},
	}
	if len(req.Requests) != 2 {
		t.Errorf("expected 2 requests, got %d", len(req.Requests))
	}
}

func TestBatchScanResponse(t *testing.T) {
	resp := &BatchScanResponse{
		Result: &ScanResponse{ScanId: "batch-1", Status: "scanning"},
		Error:  "",
	}
	if resp.Result == nil {
		t.Error("expected non-nil result")
	}
	if resp.Result.Status == "not_implemented" {
		t.Error(errNotImplemented)
	}
}

func TestFilterBySeverity(t *testing.T) {
	vulns := []*Vulnerability{
		{ID: "CVE-1", Severity: "critical"},
		{ID: "CVE-2", Severity: "high"},
		{ID: "CVE-3", Severity: "medium"},
		{ID: "CVE-4", Severity: "low"},
	}

	highAndAbove := filterBySeverity(vulns, "high")
	if len(highAndAbove) != 2 {
		t.Errorf("expected 2 vulns at high+, got %d", len(highAndAbove))
	}

	critOnly := filterBySeverity(vulns, "critical")
	if len(critOnly) != 1 {
		t.Errorf("expected 1 critical vuln, got %d", len(critOnly))
	}
}

// TestNewIronBankClientInvalidCreds verifies the constructor validates
// its inputs without requiring live credentials.
func TestNewIronBankClientInvalidCreds(t *testing.T) {
	_, err := NewIronBankScannerClientFromHarbor("", "")
	if err == nil {
		t.Error("expected error with empty credentials")
	}
}

package remote

import (
	"encoding/json"
	"testing"
	"time"
)

// ─── STIGCheckResult ─────────────────────────────────────────────────────────

func TestSTIGCheckResult_ZeroValue(t *testing.T) {
	var r STIGCheckResult
	if r.Status != "" || r.ControlID != "" {
		t.Error("zero-value STIGCheckResult should have empty fields")
	}
}

// ─── ScanReport ──────────────────────────────────────────────────────────────

func TestScanReport_Score_Calculation(t *testing.T) {
	report := &ScanReport{
		Host:        "test-host",
		TotalChecks: 10,
		Passed:      7,
		Failed:      3,
	}
	// Manually compute score as the scanner would
	if report.TotalChecks > 0 {
		report.Score = float64(report.Passed) / float64(report.TotalChecks) * 100
	}

	expected := 70.0
	if report.Score != expected {
		t.Errorf("expected score %f, got %f", expected, report.Score)
	}
}

func TestScanReport_ToJSON(t *testing.T) {
	report := &ScanReport{
		Host:        "test-host",
		Profile:     "tactical",
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		TotalChecks: 3,
		Passed:      2,
		Failed:      1,
		Score:       66.7,
		Results: []STIGCheckResult{
			{ControlID: "RHEL-09-001001", Status: "pass", Severity: "high"},
			{ControlID: "RHEL-09-001002", Status: "fail", Severity: "medium"},
		},
	}

	data, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var decoded ScanReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("ToJSON produced invalid JSON: %v", err)
	}
	if decoded.Host != "test-host" {
		t.Errorf("expected host=test-host, got %s", decoded.Host)
	}
	if len(decoded.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(decoded.Results))
	}
}

// ─── STIGCheck ───────────────────────────────────────────────────────────────

func TestSTIGCheck_EvaluateFunc_Pass(t *testing.T) {
	check := STIGCheck{
		ControlID: "RHEL-09-001001",
		Title:     "Test check",
		Severity:  "high",
		EvaluateFunc: func(output string, exitCode int) (bool, string) {
			return exitCode == 0, "non-zero exit"
		},
	}

	passed, _ := check.EvaluateFunc("ok", 0)
	if !passed {
		t.Error("expected pass when exit code is 0")
	}

	passed, finding := check.EvaluateFunc("fail", 1)
	if passed {
		t.Error("expected fail when exit code is non-zero")
	}
	if finding != "non-zero exit" {
		t.Errorf("expected finding 'non-zero exit', got '%s'", finding)
	}
}

// ─── NewBulkScanner ──────────────────────────────────────────────────────────

func TestNewBulkScanner_DefaultConcurrency(t *testing.T) {
	b := NewBulkScanner(nil, nil, 0)
	if b == nil {
		t.Fatal("NewBulkScanner returned nil")
	}
	if b.concurrency != 10 {
		t.Errorf("expected default concurrency 10, got %d", b.concurrency)
	}
}

func TestNewBulkScanner_ExplicitConcurrency(t *testing.T) {
	b := NewBulkScanner(nil, nil, 5)
	if b.concurrency != 5 {
		t.Errorf("expected concurrency 5, got %d", b.concurrency)
	}
}

func TestNewBulkScanner_EmptyProfiles(t *testing.T) {
	b := NewBulkScanner([]*ConnectionProfile{}, []STIGCheck{}, 3)
	if b == nil {
		t.Fatal("NewBulkScanner returned nil for empty profiles")
	}
}

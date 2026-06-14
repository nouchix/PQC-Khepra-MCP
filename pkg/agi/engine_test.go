package agi

import (
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

func TestNewEngine(t *testing.T) {
	mem := dag.NewMemory()
	e := NewEngine(mem)

	if e.Status != "Initialized" {
		t.Errorf("Expected status Initialized, got %s", e.Status)
	}

	if e.Objective != ObjectiveAuditor {
		t.Errorf("Expected objective %s, got %s", ObjectiveAuditor, e.Objective)
	}

	if len(e.pubKey) == 0 || len(e.privKey) == 0 {
		t.Error("Expected keys to be generated")
	}
}

func TestGetState(t *testing.T) {
	mem := dag.NewMemory()
	e := NewEngine(mem)

	state := e.GetState()
	if state["mode"] != "KASA-Hybrid-v2" {
		t.Errorf("Expected mode KASA-Hybrid-v2, got %s", state["mode"])
	}
}

func TestPentestIntentDetection(t *testing.T) {
	mem := dag.NewMemory()
	e := NewEngine(mem)

	testCases := []struct {
		input    string
		contains string
	}{
		{"run pentest on 127.0.0.1", "INITIATING INTERNAL PENETRATION TEST"},
		{"penetration test localhost", "INITIATING INTERNAL PENETRATION TEST"},
		{"internal pentest on 192.168.1.1", "INITIATING INTERNAL PENETRATION TEST"},
		{"run attack simulation", "INITIATING INTERNAL PENETRATION TEST"},
	}

	for _, tc := range testCases {
		response := e.Chat(tc.input)
		if !contains(response, tc.contains) {
			t.Errorf("Input '%s': expected response to contain '%s', got '%s'", tc.input, tc.contains, response)
		}
	}
}

func TestPentestTargetExtraction(t *testing.T) {
	mem := dag.NewMemory()
	e := NewEngine(mem)

	testCases := []struct {
		input          string
		expectedTarget string
	}{
		{"run pentest on 192.168.1.100", "192.168.1.100"},
		{"penetration test 10.0.0.1", "10.0.0.1"},
		{"pentest on localhost", "localhost"},
		{"internal pentest", "127.0.0.1"}, // Default target
	}

	for _, tc := range testCases {
		response := e.Chat(tc.input)
		if !contains(response, tc.expectedTarget) {
			t.Errorf("Input '%s': expected target '%s' in response, got '%s'", tc.input, tc.expectedTarget, response)
		}
	}
}

func TestPentestIntervalConfiguration(t *testing.T) {
	mem := dag.NewMemory()
	e := NewEngine(mem)

	// Verify pentest interval is set (24 hours for NIST 800-53 CA-8 compliance)
	if e.PentestInterval.Hours() != 24 {
		t.Errorf("Expected pentest interval of 24 hours, got %v", e.PentestInterval)
	}
}

func TestArsenalInitialization(t *testing.T) {
	mem := dag.NewMemory()
	e := NewEngine(mem)

	if e.arsenal == nil {
		t.Error("Expected arsenal to be initialized")
	}

	// Arsenal should have standard tools defined
	gapReport := e.arsenal.ReportGaps()
	if gapReport == "" {
		t.Error("Expected arsenal gap report to be non-empty")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

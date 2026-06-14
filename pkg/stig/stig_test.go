package stig

import (
	"testing"
)

func TestValidator(t *testing.T) {
	// Basic test to ensure Validator can be instantiated
	// and essential methods don't panic.
	// We might not be able to run full validation without root/mocking,
	// but we can test struct initialization.

	checker := NewSystemChecker()
	if checker == nil {
		t.Error("NewSystemChecker() returned nil")
	}

	// Test a safe method that doesn't require root
	if runtimeOS, _ := checker.GetOSVersion(); runtimeOS == "" {
		// It might return empty string on error, but let's just check it doesn't crash
	}
}

func TestFindingStruct(t *testing.T) {
	f := Finding{
		ID:     "TEST-001",
		Status: "Fail",
	}
	if f.ID != "TEST-001" {
		t.Error("Finding struct ID not initialized correctly")
	}
	if f.Status != "Fail" {
		t.Error("Finding struct Status not initialized correctly")
	}
}

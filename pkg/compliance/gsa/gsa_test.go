package gsa

import (
	"testing"
)

func TestGSAValidator(t *testing.T) {
	v := NewGSAValidator()
	if v == nil {
		t.Fatal("expected non-nil GSAValidator")
	}

	// Initially, requirements should be empty before RunReadinessCheck
	if len(v.Requirements) != 0 {
		t.Errorf("expected 0 requirements, got %d", len(v.Requirements))
	}

	result := v.RunReadinessCheck()
	
	// The current implementation mocks 3 requirements (SAM, CAGE, NIST)
	// SAM is met, CAGE is not, NIST is met. Total = 3.
	if len(v.Requirements) != 3 {
		t.Errorf("expected 3 requirements after check, got %d", len(v.Requirements))
	}

	// Since metCount = 2 and len = 3, it should be "PARTIAL"
	if result != "PARTIAL" {
		t.Errorf("expected result PARTIAL, got %s", result)
	}

	// Verify specific requirement
	sam, ok := v.Requirements[ReqSAMRegistration]
	if !ok || !sam.Met {
		t.Error("expected SAM registration to be met")
	}

	cage, ok := v.Requirements[ReqCAGECode]
	if !ok || cage.Met {
		t.Error("expected CAGE code to be NOT met")
	}
}

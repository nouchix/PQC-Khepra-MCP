package nist80171

import (
	"testing"
)

func TestValidatorValidateACFamily(t *testing.T) {
	v := &Validator{}
	results := v.ValidateACFamily()

	// Should have at least 10 results based on ValidateACFamily implementation
	if len(results) < 10 {
		t.Errorf("expected at least 10 results, got %d", len(results))
	}

	// Verify some specific controls
	found311 := false
	found318 := false
	for _, res := range results {
		if res.ControlID == "3.1.1" {
			found311 = true
			if res.Status != "PASS" {
				t.Errorf("control 3.1.1 should PASS, got %s", res.Status)
			}
		}
		if res.ControlID == "3.1.8" {
			found318 = true
			if res.Status != "PASS" {
				t.Errorf("control 3.1.8 should PASS, got %s", res.Status)
			}
		}
	}

	if !found311 {
		t.Error("control 3.1.1 not found in results")
	}
	if !found318 {
		t.Error("control 3.1.8 not found in results")
	}
}

func TestValidatorRequiresManualReview(t *testing.T) {
	v := &Validator{}
	res := v.requiresManualReview("test-id", FamilyAC,
		"Test description for manual review.",
		"Requires test evidence documentation.")

	if res.ControlID != "test-id" {
		t.Errorf("expected ID test-id, got %s", res.ControlID)
	}
	if res.Status != "MANUAL_REVIEW" {
		t.Errorf("expected status MANUAL_REVIEW, got %s", res.Status)
	}
	if res.Family != FamilyAC {
		t.Errorf("expected family %s, got %s", FamilyAC, res.Family)
	}
}

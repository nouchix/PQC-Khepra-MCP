package nist80172

import (
	"testing"
)

func TestEnhancedValidatorValidateACFamily(t *testing.T) {
	v := NewEnhancedValidator()
	results := v.ValidateACFamily()

	// Should have 3 results based on ValidateACFamily implementation
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	// Verify specific control
	found312e := false
	for _, res := range results {
		if res.ControlID == "3.1.2e" {
			found312e = true
			if res.Status != "PASS" {
				t.Errorf("control 3.1.2e should PASS, got %s", res.Status)
			}
		}
	}

	if !found312e {
		t.Error("control 3.1.2e not found in results")
	}
}

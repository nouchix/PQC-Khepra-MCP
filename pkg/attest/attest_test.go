package attest

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAssertion_Marshal(t *testing.T) {
	a := Assertion{
		Schema: "1.0",
		Symbol: "TEST",
		Semantics: Semantics{
			Boundary:       "global",
			Purpose:        "testing",
			LeastPrivilege: true,
		},
		Lifecycle: Lifecycle{
			Journey:         "dev",
			CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			RotationAfterND: 90,
		},
		Binding: Binding{
			OpenSSHPubSHA256: "sha256:test",
			Comment:          "test key",
		},
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Basic check
	if len(data) == 0 {
		t.Fatal("Empty JSON output")
	}

	var parsed Assertion
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if parsed.Binding.Comment != "test key" {
		t.Errorf("Expected comment 'test key', got '%s'", parsed.Binding.Comment)
	}
}

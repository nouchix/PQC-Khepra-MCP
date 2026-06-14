package maat

import (
	"testing"
)

// ─── AnubisWeigher ──────────────────────────────────────────────────────────

func TestNewAnubisWeigher(t *testing.T) {
	w := NewAnubisWeigher()
	if w == nil {
		t.Fatal("NewAnubisWeigher returned nil")
	}
	if w.Feather == nil {
		t.Fatal("Feather is nil")
	}
	if w.Feather.Weight != 1.0 {
		t.Errorf("expected feather weight 1.0, got %f", w.Feather.Weight)
	}
}

func TestWeighHeart_Catastrophic(t *testing.T) {
	w := NewAnubisWeigher()
	isfet := Isfet{ID: "test-1", Severity: SeverityCatastrophic, Certainty: 1.0}
	options := w.WeighHeart(isfet)

	if len(options) == 0 {
		t.Fatal("expected options for catastrophic severity")
	}

	// Must include ActionSeal for catastrophic events
	hasSeal := false
	for _, o := range options {
		if o.Action == ActionSeal {
			hasSeal = true
		}
		// Potency must be in [0,1]
		if o.Potency < 0 || o.Potency > 1 {
			t.Errorf("option %s potency %f out of [0,1]", o.Action, o.Potency)
		}
	}
	if !hasSeal {
		t.Error("catastrophic severity should include ActionSeal option")
	}
}

func TestWeighHeart_Severe(t *testing.T) {
	w := NewAnubisWeigher()
	isfet := Isfet{ID: "test-2", Severity: SeveritySevere, Certainty: 0.9}
	options := w.WeighHeart(isfet)

	if len(options) == 0 {
		t.Fatal("expected options for severe severity")
	}

	// Banish should appear for severe events (cheap, reversible)
	hasBanish := false
	for _, o := range options {
		if o.Action == ActionBanish {
			hasBanish = true
		}
	}
	if !hasBanish {
		t.Error("severe severity should include ActionBanish option")
	}
}

func TestWeighHeart_Moderate(t *testing.T) {
	w := NewAnubisWeigher()
	isfet := Isfet{ID: "test-3", Severity: SeverityModerate, Certainty: 0.75}
	options := w.WeighHeart(isfet)

	if len(options) == 0 {
		t.Fatal("expected options for moderate severity")
	}

	// Observe should appear as safe fallback for moderate events
	hasObserve := false
	for _, o := range options {
		if o.Action == ActionObserve {
			hasObserve = true
		}
	}
	if !hasObserve {
		t.Error("moderate severity should include ActionObserve option")
	}
}

func TestWeighHeart_Minor(t *testing.T) {
	w := NewAnubisWeigher()
	isfet := Isfet{ID: "test-4", Severity: SeverityMinor, Certainty: 0.5}
	options := w.WeighHeart(isfet)

	if len(options) == 0 {
		t.Fatal("expected options for minor severity")
	}

	// Minor events lead with observation
	hasObserve := false
	for _, o := range options {
		if o.Action == ActionObserve {
			hasObserve = true
			// Observe should have zero operational burden
			if o.OperationalBurden != 0.0 {
				t.Errorf("ActionObserve should have 0 burden, got %f", o.OperationalBurden)
			}
		}
	}
	if !hasObserve {
		t.Error("minor severity should include ActionObserve")
	}
}

func TestWeighHeart_PotencyInRange(t *testing.T) {
	w := NewAnubisWeigher()
	severities := []Severity{SeverityMinor, SeverityModerate, SeveritySevere, SeverityCatastrophic}

	for _, sev := range severities {
		isfet := Isfet{ID: "range-test", Severity: sev, Certainty: 1.0}
		options := w.WeighHeart(isfet)
		for _, o := range options {
			if o.Potency < 0 || o.Potency > 1 {
				t.Errorf("severity=%s action=%s potency=%f out of [0,1]", sev, o.Action, o.Potency)
			}
		}
	}
}

// ─── Severity Constants ─────────────────────────────────────────────────────

func TestSeverityConstants(t *testing.T) {
	if SeverityMinor == SeverityModerate {
		t.Error("SeverityMinor and SeverityModerate must be distinct")
	}
	if SeverityModerate == SeveritySevere {
		t.Error("SeverityModerate and SeveritySevere must be distinct")
	}
	if SeveritySevere == SeverityCatastrophic {
		t.Error("SeveritySevere and SeverityCatastrophic must be distinct")
	}
}

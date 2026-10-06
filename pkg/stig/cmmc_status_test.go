package stig

import "testing"

// With no other framework run, nothing can be Met.
func TestCMMCZeroChecksYieldsZeroMet(t *testing.T) {
	v := NewValidator(".")
	result := &ValidationResult{Framework: FrameworkCMMC}
	if err := v.validateCMMC(result); err != nil {
		t.Fatalf("validateCMMC: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected CMMC practices in the result")
	}
	for _, f := range result.Findings {
		if f.Status == "Pass" {
			t.Fatalf("%s is Pass with zero checks executed", f.ID)
		}
		if f.Status != StatusNotAssessed {
			t.Fatalf("%s: want %q with zero checks, got %q", f.ID, StatusNotAssessed, f.Status)
		}
	}
}

func TestCMMCPracticeStatus(t *testing.T) {
	refs := []string{"AC-2", "AC-3"}
	cases := []struct {
		name string
		ev   map[string]*controlEvidence
		want string
	}{
		{"no evidence", map[string]*controlEvidence{}, StatusNotAssessed},
		{"partial coverage", map[string]*controlEvidence{"AC-2": {passed: 3}}, StatusNotAssessed},
		{"pending manual review", map[string]*controlEvidence{"AC-2": {passed: 1}, "AC-3": {passed: 1, pending: 1}}, StatusNotAssessed},
		{"all covered and passing", map[string]*controlEvidence{"AC-2": {passed: 1}, "AC-3": {passed: 2}}, "Pass"},
		{"any failure", map[string]*controlEvidence{"AC-2": {passed: 4}, "AC-3": {failed: 1, failReason: "x"}}, "Fail"},
	}
	for _, c := range cases {
		if got, _ := cmmcPracticeStatus(refs, c.ev); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if got, _ := cmmcPracticeStatus(nil, map[string]*controlEvidence{}); got != StatusNotAssessed {
		t.Errorf("practice with no mapped controls: got %q, want %q", got, StatusNotAssessed)
	}
}

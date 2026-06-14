package sca

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEnrichedFinding_JSONRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	original := EnrichedFinding{
		Component:       "golang.org/x/crypto",
		Version:         "0.17.0",
		Ecosystem:       "go",
		PackageURL:      "pkg:golang/golang.org/x/crypto@v0.17.0",
		CPE:             "cpe:2.3:a:golang:x_crypto:0.17.0:*:*:*:*:*:*:*",
		CVEID:           "CVE-2024-45337",
		CVSSv3Score:     9.1,
		CVSSv3Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		Severity:        "CRITICAL",
		Sources:         []string{"grype", "nvd"},
		InCISAKEV:       true,
		KEVDateAdded:    "2024-12-19",
		InTheWild:       true,
		ExploitDBID:     "51234",
		PoCAvailable:    true,
		EPSSScore:       0.87,
		EPSSPercentile:  0.98,
		MITRETactics:    []string{"TA0001"},
		MITRETechniques: []string{"T1190"},
		VEXStatus:       "affected",
		Confidence:      "high",
		DetectedAt:      now,
		ScannerMeta: ScannerMetadata{
			SyftVersion:    "1.4.1",
			GrypeVersion:   "0.79.0",
			GrypeDBVersion: "v5-2024.12.19",
			ScannedAt:      now,
		},
	}

	data, err := json.Marshal(&original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("Marshal produced invalid JSON")
	}

	var rt EnrichedFinding
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if rt.Component != original.Component {
		t.Errorf("Component mismatch: %q vs %q", rt.Component, original.Component)
	}
	if rt.CVEID != original.CVEID {
		t.Errorf("CVEID mismatch: %q vs %q", rt.CVEID, original.CVEID)
	}
	if rt.CVSSv3Score != original.CVSSv3Score {
		t.Errorf("CVSSv3Score mismatch: %f vs %f", rt.CVSSv3Score, original.CVSSv3Score)
	}
	if rt.InCISAKEV != original.InCISAKEV {
		t.Errorf("InCISAKEV mismatch")
	}
	if len(rt.Sources) != len(original.Sources) {
		t.Errorf("Sources length mismatch")
	}
}

func TestEnrichedFinding_NilSlicesSerializeAsEmptyArray(t *testing.T) {
	f := EnrichedFinding{Component: "test", CVEID: "CVE-2024-00001"}
	data, err := json.Marshal(&f)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	s := string(data)
	for _, field := range []string{"sources", "mitre_tactics", "mitre_techniques"} {
		if strings.Contains(s, `"`+field+`":null`) {
			t.Errorf("%s serialized as null, expected empty array", field)
		}
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	tests := []struct {
		score float64
		want  Severity
	}{
		{10.0, SeverityCritical}, {9.0, SeverityCritical},
		{8.9, SeverityHigh}, {7.0, SeverityHigh},
		{6.9, SeverityMedium}, {4.0, SeverityMedium},
		{3.9, SeverityLow}, {0.1, SeverityLow},
		{0.0, SeverityNone},
	}
	for _, tt := range tests {
		if got := SeverityFromCVSS(tt.score); got != tt.want {
			t.Errorf("SeverityFromCVSS(%f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestEnrichedFinding_IsHighRisk(t *testing.T) {
	tests := []struct {
		name string
		f    EnrichedFinding
		want bool
	}{
		{"CRITICAL always", EnrichedFinding{Severity: "CRITICAL"}, true},
		{"CISA KEV always", EnrichedFinding{Severity: "MEDIUM", InCISAKEV: true}, true},
		{"In the wild always", EnrichedFinding{Severity: "LOW", InTheWild: true}, true},
		{"HIGH+EPSS>0.1", EnrichedFinding{Severity: "HIGH", EPSSScore: 0.5}, true},
		{"HIGH+PoC", EnrichedFinding{Severity: "HIGH", PoCAvailable: true}, true},
		{"HIGH+low EPSS no", EnrichedFinding{Severity: "HIGH", EPSSScore: 0.05}, false},
		{"MEDIUM no signals", EnrichedFinding{Severity: "MEDIUM"}, false},
		{"Zero value", EnrichedFinding{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.IsHighRisk(); got != tt.want {
				t.Errorf("IsHighRisk() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnrichedFinding_RiskScore(t *testing.T) {
	f := EnrichedFinding{CVSSv3Score: 9.8, EPSSScore: 0.99, InCISAKEV: true, InTheWild: true, PoCAvailable: true}
	if s := f.RiskScore(); s != 10.0 {
		t.Errorf("maxed signals: got %f, want 10.0", s)
	}
	f = EnrichedFinding{}
	if s := f.RiskScore(); s != 0.0 {
		t.Errorf("zero finding: got %f, want 0.0", s)
	}
}

func TestEnrichedFinding_EPSSRank(t *testing.T) {
	tests := []struct {
		p    float64
		want string
	}{
		{0.99, "top-5%"}, {0.95, "top-5%"},
		{0.94, "top-10%"}, {0.90, "top-10%"},
		{0.75, "top-25%"}, {0.50, "top-50%"},
		{0.49, "below-50%"}, {0.0, "below-50%"},
	}
	for _, tt := range tests {
		f := EnrichedFinding{EPSSPercentile: tt.p}
		if got := f.EPSSRank(); got != tt.want {
			t.Errorf("EPSSRank(%f) = %q, want %q", tt.p, got, tt.want)
		}
	}
}

func TestEnrichedFinding_String(t *testing.T) {
	f := EnrichedFinding{Severity: "CRITICAL", CVEID: "CVE-2024-45337", Component: "x/crypto", Version: "0.17.0", CVSSv3Score: 9.1, EPSSScore: 0.87, InCISAKEV: true}
	s := f.String()
	if !strings.Contains(s, "CRITICAL") || !strings.Contains(s, "CVE-2024-45337") || !strings.Contains(s, "HIGH-RISK") {
		t.Errorf("String() missing expected content: %s", s)
	}
}

func TestEnrichedFinding_ZeroValueDefaults(t *testing.T) {
	var f EnrichedFinding
	if f.IsHighRisk() {
		t.Error("zero finding should not be high risk")
	}
	f.ClassifySeverity()
	if f.Severity != "NONE" {
		t.Errorf("zero finding severity = %q, want NONE", f.Severity)
	}
}

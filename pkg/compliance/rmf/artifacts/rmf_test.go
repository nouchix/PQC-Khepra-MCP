package artifacts

import (
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/compliance/nist80171"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/compliance/nist80172"
)

func TestSSPGenerator(t *testing.T) {
	g := &SSPGenerator{
		AppName:      "Khepra Shield",
		Organization: "NouchiX",
		Version:      "2.0",
	}

	results171 := []nist80171.ControlResult{
		{ControlID: "3.1.1", Title: "Access Control", Status: "PASS"},
		{ControlID: "3.1.10", Title: "Privilege Control", Status: "FAIL", Description: "Missing audit", Remediation: "Add audit logs"},
	}
	results172 := []nist80172.EnhancedResult{
		{ControlID: "3.1.1e", Title: "Enhanced AC", Status: "PASS"},
	}

	// Test GenerateSSP
	ssp, err := g.GenerateSSP(results171, results172)
	if err != nil {
		t.Fatalf("GenerateSSP failed: %v", err)
	}
	if ssp == "" {
		t.Fatal("expected non-empty SSP")
	}

	// Test GeneratePOAM
	poam, err := g.GeneratePOAM(results171)
	if err != nil {
		t.Fatalf("GeneratePOAM failed: %v", err)
	}
	if poam == "" {
		t.Fatal("expected non-empty POAM")
	}
}

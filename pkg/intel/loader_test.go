package intel

import (
	"os"
	"testing"
)

func TestLoadCisaKEV(t *testing.T) {
	jsonContent := `{
		"title": "CISA KEV Catalog",
		"vulnerabilities": [
			{
				"cveID": "CVE-2023-1234",
				"vulnerabilityName": "Test Vuln",
				"shortDescription": "A test vulnerability"
			}
		]
	}`

	tmpfile, err := os.CreateTemp("", "test_kev_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(jsonContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	kb := NewKnowledgeBase()
	if err := kb.LoadCisaKEV(tmpfile.Name()); err != nil {
		t.Fatalf("LoadCisaKEV failed: %v", err)
	}

	if len(kb.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vuln, got %d", len(kb.Vulnerabilities))
	}

	if _, ok := kb.Vulnerabilities["CVE-2023-1234"]; !ok {
		t.Error("Expected to find CVE-2023-1234")
	}
}

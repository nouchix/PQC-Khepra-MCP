package arsenal

import (
	"os"
	"testing"
)

func TestParseGitleaks(t *testing.T) {
	content := `[
		{
			"Description": "AWS Access Key",
			"StartLine": 10,
			"File": "config.js",
			"Secret": "AKIA1234567890",
			"Author": "dev@example.com"
		}
	]`
	tmp := "test_gitleaks.json"
	os.WriteFile(tmp, []byte(content), 0644)
	defer os.Remove(tmp)

	findings, err := ParseGitleaks(tmp)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
	if findings[0].File != "config.js" {
		t.Errorf("File mismatch: %s", findings[0].File)
	}
}

func TestParseTruffleHog(t *testing.T) {
	// JSONL Format
	content := `{"DetectorName": "PrivateKey", "Verified": true, "SourceMetadata": {"Data": {"Filesystem": {"file": "id_rsa"}}}}
{"DetectorName": "AWS", "Verified": false, "SourceMetadata": {"Data": {"Filesystem": {"file": ".env"}}}}`

	tmp := "test_trufflehog.json"
	os.WriteFile(tmp, []byte(content), 0644)
	defer os.Remove(tmp)

	findings, err := ParseTruffleHog(tmp)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}

	if findings[0].DetectorName != "PrivateKey" {
		t.Errorf("Detector mismatch: %s", findings[0].DetectorName)
	}
	if !findings[0].Verified {
		t.Error("Verification status mismatch")
	}
}

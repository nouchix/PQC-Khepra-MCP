package connectors

import (
	"os"
	"testing"
)

func TestParseCKL(t *testing.T) {
	// Create a dummy CKL file
	xmlContent := `
<CHECKLIST>
	<STIGS>
		<iD>
			<STIG_TITLE>Test STIG</STIG_TITLE>
			<VULN>
				<STATUS>Open</STATUS>
				<FINDING_ID>V-12345</FINDING_ID>
				<COMMENTS>Test Comment</COMMENTS>
			</VULN>
			<VULN>
				<STATUS>NotAFinding</STATUS>
				<FINDING_ID>V-67890</FINDING_ID>
			</VULN>
		</iD>
	</STIGS>
</CHECKLIST>`

	tmpfile, err := os.CreateTemp("", "test_ckl_*.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(xmlContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	vulns, err := ParseCKL(tmpfile.Name())
	if err != nil {
		t.Fatalf("ParseCKL failed: %v", err)
	}

	if len(vulns) != 1 {
		t.Errorf("Expected 1 open vuln, got %d", len(vulns))
	}
	if vulns[0].FindingID != "V-12345" {
		t.Errorf("Expected finding ID V-12345, got %s", vulns[0].FindingID)
	}
}

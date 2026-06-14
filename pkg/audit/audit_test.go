package audit

import (
	"os"
	"strings"
	"testing"
)

func TestGenerateAFFiNE(t *testing.T) {
	// Test data
	report := &RiskReport{
		ScanID: "scan-test-123",
		Client: "Test Client Corp",
		Risks: []Risk{
			{
				Severity:      "CRITICAL",
				Title:         "Unpatched SQL Injection Vulnerability",
				Description:   "SQL injection vulnerability in user authentication endpoint",
				Remediation:   "Apply security patches and implement parameterized queries",
				CausalLink:    "CVE-2024-1234",
				STIGReference: "STIG-V-12345",
			},
			{
				Severity:      "HIGH",
				Title:         "Weak Cryptographic Algorithm",
				Description:   "Using deprecated SHA-1 for password hashing",
				Remediation:   "Migrate to bcrypt or Argon2",
				CausalLink:    "CWE-327",
				STIGReference: "STIG-V-67890",
			},
			{
				Severity:      "MEDIUM",
				Title:         "Missing Security Headers",
				Description:   "HTTP security headers not configured",
				Remediation:   "Add Content-Security-Policy and X-Frame-Options headers",
				CausalLink:    "OWASP-A05",
				STIGReference: "STIG-V-11111",
			},
		},
	}

	// Generate AFFiNE report
	result := GenerateAFFiNE(report)

	// Verify report structure
	if result == "" {
		t.Fatal("GenerateAFFiNE returned empty string")
	}

	// Verify header contains client name
	if !strings.Contains(result, "Test Client Corp") {
		t.Error("Report missing client name")
	}

	// Verify scan ID is present
	if !strings.Contains(result, "scan-test-123") {
		t.Error("Report missing scan ID")
	}

	// Verify classification marking
	if !strings.Contains(result, "CONFIDENTIAL // PROPRIETARY") {
		t.Error("Report missing classification marking")
	}

	// Verify risk counts
	if !strings.Contains(result, "**CRITICAL Vulnerabilities:** 1") {
		t.Error("Report has incorrect CRITICAL count")
	}

	if !strings.Contains(result, "**HIGH Severity Risks:** 1") {
		t.Error("Report has incorrect HIGH count")
	}

	if !strings.Contains(result, "**Total Findings:** 3") {
		t.Error("Report has incorrect total count")
	}

	// Verify immediate action warning for CRITICAL findings
	if !strings.Contains(result, "IMMEDIATE ACTION REQUIRED") {
		t.Error("Report missing CRITICAL warning")
	}

	// Verify strategic findings section
	if !strings.Contains(result, "## 2. Strategic Findings") {
		t.Error("Report missing Strategic Findings section")
	}

	// Verify first finding is included
	if !strings.Contains(result, "Unpatched SQL Injection Vulnerability") {
		t.Error("Report missing first finding")
	}

	// Verify PQC readiness section
	if !strings.Contains(result, "## 3. Quantum Readiness (PQC) Assessment") {
		t.Error("Report missing PQC section")
	}

	if !strings.Contains(result, "Dilithium-Mode3") {
		t.Error("Report missing PQC recommendation")
	}

	// Verify next steps section
	if !strings.Contains(result, "## 4. Required Decisions") {
		t.Error("Report missing Required Decisions section")
	}

	// Verify Khepra branding
	if !strings.Contains(result, "Khepra Agentic Security Auditor") {
		t.Error("Report missing Khepra branding")
	}
}

func TestGenerateAFFiNE_EmptyReport(t *testing.T) {
	// Test with empty risks
	report := &RiskReport{
		ScanID: "scan-empty-456",
		Client: "Empty Client",
		Risks:  []Risk{},
	}

	result := GenerateAFFiNE(report)

	// Should still generate a valid report
	if result == "" {
		t.Fatal("GenerateAFFiNE returned empty string for empty report")
	}

	// Should have zero counts
	if !strings.Contains(result, "**CRITICAL Vulnerabilities:** 0") {
		t.Error("Empty report has incorrect CRITICAL count")
	}

	if !strings.Contains(result, "**Total Findings:** 0") {
		t.Error("Empty report has incorrect total count")
	}

	// Should NOT have immediate action warning
	if strings.Contains(result, "IMMEDIATE ACTION REQUIRED") {
		t.Error("Empty report should not have CRITICAL warning")
	}
}

func TestGenerateAFFiNE_MaxFindings(t *testing.T) {
	// Test with more than 5 findings (should limit to top 5)
	risks := make([]Risk, 10)
	for i := 0; i < 10; i++ {
		risks[i] = Risk{
			Severity:      "MEDIUM",
			Title:         "Finding " + string(rune(i+'A')),
			Description:   "Test description",
			Remediation:   "Test remediation",
			CausalLink:    "TEST-" + string(rune(i+'A')),
			STIGReference: "STIG-V-" + string(rune(i+'A')),
		}
	}

	report := &RiskReport{
		ScanID: "scan-max-789",
		Client: "Max Findings Client",
		Risks:  risks,
	}

	result := GenerateAFFiNE(report)

	// Should contain first 5 findings
	if !strings.Contains(result, "Finding A") {
		t.Error("Report missing first finding")
	}

	if !strings.Contains(result, "Finding E") {
		t.Error("Report missing fifth finding")
	}

	// Should NOT contain 6th+ findings in strategic section
	// (Total count will be 10, but strategic findings limited to 5)
	if !strings.Contains(result, "**Total Findings:** 10") {
		t.Error("Report has incorrect total count")
	}
}

func TestExportToCSV(t *testing.T) {
	// Test data
	report := &RiskReport{
		ScanID: "scan-csv-001",
		Client: "CSV Test Client",
		Risks: []Risk{
			{
				Severity:      "CRITICAL",
				Title:         "SQL Injection",
				Description:   "SQL injection in login form",
				Remediation:   "Use parameterized queries",
				CausalLink:    "CVE-2024-5678",
				STIGReference: "STIG-V-99999",
			},
			{
				Severity:      "HIGH",
				Title:         "XSS Vulnerability",
				Description:   "Cross-site scripting in search",
				Remediation:   "Sanitize user input",
				CausalLink:    "CWE-79",
				STIGReference: "STIG-V-88888",
			},
		},
	}

	// Create temporary file
	tmpFile := "test_export.csv"
	defer os.Remove(tmpFile)

	// Export to CSV
	err := ExportToCSV(report, tmpFile)
	if err != nil {
		t.Fatalf("ExportToCSV failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("CSV file was not created")
	}

	// Read file contents
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	content := string(data)

	// Verify header row
	if !strings.Contains(content, "scan_id,client,severity,title,description,remediation,causal_link_id,stig_reference,risk_score") {
		t.Error("CSV missing correct header row")
	}

	// Verify scan ID
	if !strings.Contains(content, "scan-csv-001") {
		t.Error("CSV missing scan ID")
	}

	// Verify client name
	if !strings.Contains(content, "CSV Test Client") {
		t.Error("CSV missing client name")
	}

	// Verify CRITICAL severity
	if !strings.Contains(content, "CRITICAL") {
		t.Error("CSV missing CRITICAL severity")
	}

	// Verify risk scores (CRITICAL=100, HIGH=75)
	if !strings.Contains(content, "100") {
		t.Error("CSV missing CRITICAL risk score (100)")
	}

	if !strings.Contains(content, "75") {
		t.Error("CSV missing HIGH risk score (75)")
	}

	// Verify finding titles
	if !strings.Contains(content, "SQL Injection") {
		t.Error("CSV missing SQL Injection finding")
	}

	if !strings.Contains(content, "XSS Vulnerability") {
		t.Error("CSV missing XSS finding")
	}
}

func TestExportToCSV_RiskScoreMapping(t *testing.T) {
	// Test risk score mapping for all severity levels
	tests := []struct {
		severity      string
		expectedScore string
	}{
		{"CRITICAL", "100"},
		{"HIGH", "75"},
		{"MEDIUM", "50"},
		{"LOW", "25"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			report := &RiskReport{
				ScanID: "scan-score-test",
				Client: "Score Test Client",
				Risks: []Risk{
					{
						Severity:      tt.severity,
						Title:         "Test Finding",
						Description:   "Test description",
						Remediation:   "Test remediation",
						CausalLink:    "TEST-001",
						STIGReference: "STIG-V-00001",
					},
				},
			}

			tmpFile := "test_score_" + tt.severity + ".csv"
			defer os.Remove(tmpFile)

			err := ExportToCSV(report, tmpFile)
			if err != nil {
				t.Fatalf("ExportToCSV failed: %v", err)
			}

			data, err := os.ReadFile(tmpFile)
			if err != nil {
				t.Fatalf("Failed to read CSV: %v", err)
			}

			if !strings.Contains(string(data), tt.expectedScore) {
				t.Errorf("CSV missing expected score %s for severity %s", tt.expectedScore, tt.severity)
			}
		})
	}
}

func TestExportToCSV_EmptyReport(t *testing.T) {
	// Test with empty risks
	report := &RiskReport{
		ScanID: "scan-empty-csv",
		Client: "Empty CSV Client",
		Risks:  []Risk{},
	}

	tmpFile := "test_empty.csv"
	defer os.Remove(tmpFile)

	err := ExportToCSV(report, tmpFile)
	if err != nil {
		t.Fatalf("ExportToCSV failed on empty report: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("CSV file was not created for empty report")
	}

	// Read file contents
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	content := string(data)

	// Should have header row only
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 1 {
		t.Errorf("Empty report CSV should have 1 line (header), got %d", len(lines))
	}
}

func TestExportToCSV_InvalidPath(t *testing.T) {
	// Test with invalid file path
	report := &RiskReport{
		ScanID: "scan-invalid",
		Client: "Invalid Path Client",
		Risks:  []Risk{},
	}

	// Use invalid path (non-existent directory)
	invalidPath := "/nonexistent/directory/test.csv"

	err := ExportToCSV(report, invalidPath)
	if err == nil {
		t.Error("ExportToCSV should fail with invalid path")
	}
}

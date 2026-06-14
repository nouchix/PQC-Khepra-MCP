package stig

import (
	"fmt"
	"time"
)

// validateRHEL09STIG validates against RHEL-09-STIG-V1R3
// Reference: https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/
func (v *Validator) validateRHEL09STIG(result *ValidationResult) error {
	result.Version = "V1R3"

	// Initialize system checker
	checker := NewSystemChecker()

	// Load compliance database for cross-references
	db, err := GetDatabase()
	if err != nil {
		return fmt.Errorf("failed to load compliance database: %w", err)
	}

	// Execute all RHEL-09 STIG checks
	v.checkRHEL09_291015(result, checker, db) // DoD Banner
	v.checkRHEL09_291020(result, checker, db) // SCAP Security Guide
	v.checkRHEL09_291025(result, checker, db) // Firewalld
	v.checkRHEL09_431010(result, checker, db) // SELinux
	v.checkRHEL09_611010(result, checker, db) // FIPS mode

	// Additional critical STIG checks
	v.checkRHEL09_211010(result, checker, db) // Account lockout
	v.checkRHEL09_212010(result, checker, db) // Password complexity
	v.checkRHEL09_231010(result, checker, db) // Audit configuration
	v.checkRHEL09_255010(result, checker, db) // SSH configuration

	return nil
}

// checkRHEL09_291015: DoD Notice and Consent Banner
func (v *Validator) checkRHEL09_291015(result *ValidationResult, checker *SystemChecker, db *ComplianceDatabase) {
	stigID := "SV-257777r925318_rule"

	finding := Finding{
		ID:          stigID,
		Title:       db.GetSTIGTitle(stigID),
		Description: "System must display DoD banner before granting access",
		Severity:    Severity(db.GetSTIGSeverity(stigID)),
		CheckedAt:   time.Now(),
	}

	// Check /etc/issue for DoD banner
	expectedBanner := "You are accessing a U.S. Government"
	bannerPath := "/etc/issue"

	exists, _ := checker.CheckFileExists(bannerPath)
	if !exists {
		finding.Status = "Fail"
		finding.Actual = fmt.Sprintf("File not found: %s", bannerPath)
		finding.Expected = "DoD banner present in " + bannerPath
		finding.Remediation = "Create /etc/issue with Standard Mandatory DoD Notice"
	} else {
		// Check if banner contains required text
		contains, _ := checker.CheckFileContains(bannerPath, expectedBanner)
		if contains {
			finding.Status = "Pass"
			finding.Actual = "DoD banner present with required text"
			finding.Expected = "DoD banner with text: " + expectedBanner
			finding.Remediation = "N/A"
		} else {
			finding.Status = "Fail"
			finding.Actual = "Banner file exists but missing required text"
			finding.Expected = "DoD banner with text: " + expectedBanner
			finding.Remediation = "Add Standard Mandatory DoD Notice to /etc/issue"
		}
	}

	// Get cross-references from database
	refs, _ := db.GetCrossReferences(stigID)
	finding.References = refs

	result.Findings = append(result.Findings, finding)
}

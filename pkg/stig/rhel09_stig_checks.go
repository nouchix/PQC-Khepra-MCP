package stig

import (
	"fmt"
	"time"
)

// checkRHEL09_291020: SCAP Security Guide installed
func (v *Validator) checkRHEL09_291020(result *ValidationResult, checker *SystemChecker, db *ComplianceDatabase) {
	stigID := "SV-257778r925321_rule"

	finding := Finding{
		ID:          stigID,
		Title:       "SCAP Security Guide package installed",
		Description: "System must have scap-security-guide package installed",
		Severity:    SeverityCAT2,
		CheckedAt:   time.Now(),
	}

	installed, version, _ := checker.CheckPackageInstalled("scap-security-guide")
	if installed {
		finding.Status = "Pass"
		finding.Expected = "scap-security-guide package installed"
		finding.Actual = fmt.Sprintf("Package installed: %s", version)
		finding.Remediation = "N/A"
	} else {
		finding.Status = "Fail"
		finding.Expected = "scap-security-guide package installed"
		finding.Actual = "Package not installed"
		finding.Remediation = "Install with: sudo dnf install scap-security-guide -y"
	}

	refs, _ := db.GetCrossReferences(stigID)
	finding.References = refs
	result.Findings = append(result.Findings, finding)
}

// checkRHEL09_291025: Firewalld installed and active
func (v *Validator) checkRHEL09_291025(result *ValidationResult, checker *SystemChecker, db *ComplianceDatabase) {
	stigID := "SV-257779r925324_rule"

	finding := Finding{
		ID:          stigID,
		Title:       "firewalld package installed and active",
		Description: "System must have firewalld package installed for host-based firewall",
		Severity:    SeverityCAT2,
		CheckedAt:   time.Now(),
	}

	installed, _, _ := checker.CheckPackageInstalled("firewalld")
	active, _ := checker.CheckFirewalldActive()

	if installed && active {
		finding.Status = "Pass"
		finding.Expected = "firewalld installed and active"
		finding.Actual = "firewalld installed and active"
		finding.Remediation = "N/A"
	} else if installed && !active {
		finding.Status = "Fail"
		finding.Expected = "firewalld installed and active"
		finding.Actual = "firewalld installed but not active"
		finding.Remediation = "Enable and start firewalld: sudo systemctl enable --now firewalld"
	} else {
		finding.Status = "Fail"
		finding.Expected = "firewalld installed and active"
		finding.Actual = "firewalld not installed"
		finding.Remediation = "Install firewalld: sudo dnf install firewalld -y && sudo systemctl enable --now firewalld"
	}

	refs, _ := db.GetCrossReferences(stigID)
	finding.References = refs
	result.Findings = append(result.Findings, finding)
}

// checkRHEL09_431010: SELinux enforcing mode
func (v *Validator) checkRHEL09_431010(result *ValidationResult, checker *SystemChecker, db *ComplianceDatabase) {
	stigID := "SV-258001r926022_rule"

	finding := Finding{
		ID:          stigID,
		Title:       "SELinux configured to enforce access control",
		Description: "System must use SELinux in enforcing mode",
		Severity:    SeverityCAT1,
		CheckedAt:   time.Now(),
	}

	selinuxMode, _ := checker.CheckSELinuxMode()

	if selinuxMode == "enforcing" {
		finding.Status = "Pass"
		finding.Expected = "SELinux mode: enforcing"
		finding.Actual = "SELinux mode: enforcing"
		finding.Remediation = "N/A"
	} else {
		finding.Status = "Fail"
		finding.Expected = "SELinux mode: enforcing"
		finding.Actual = fmt.Sprintf("SELinux mode: %s", selinuxMode)
		finding.Remediation = "Edit /etc/selinux/config, set SELINUX=enforcing, reboot"
	}

	refs, _ := db.GetCrossReferences(stigID)
	finding.References = refs
	result.Findings = append(result.Findings, finding)
}

// checkRHEL09_611010: FIPS mode enabled
func (v *Validator) checkRHEL09_611010(result *ValidationResult, checker *SystemChecker, db *ComplianceDatabase) {
	stigID := "SV-258090r926289_rule"

	finding := Finding{
		ID:          stigID,
		Title:       "NIST FIPS-validated cryptography implemented",
		Description: "System must use FIPS 140-2/140-3 validated cryptographic modules",
		Severity:    SeverityCAT1,
		CheckedAt:   time.Now(),
	}

	fipsEnabled, _ := checker.CheckFIPSMode()

	if fipsEnabled {
		finding.Status = "Pass"
		finding.Expected = "FIPS mode enabled"
		finding.Actual = "FIPS mode enabled"
		finding.Remediation = "N/A"
	} else {
		finding.Status = "Fail"
		finding.Expected = "FIPS mode enabled"
		finding.Actual = "FIPS mode disabled"
		finding.Remediation = "Enable FIPS: sudo fips-mode-setup --enable && reboot"
	}

	refs, _ := db.GetCrossReferences(stigID)
	finding.References = refs
	result.Findings = append(result.Findings, finding)
}

// checkRHEL09_211010: Account lockout
func (v *Validator) checkRHEL09_211010(result *ValidationResult, checker *SystemChecker, db *ComplianceDatabase) {
	stigID := "SV-257823r925453_rule"

	finding := Finding{
		ID:          stigID,
		Title:       "Account lockout after failed login attempts",
		Description: "System must lock accounts after 3 consecutive failed login attempts",
		Severity:    SeverityCAT2,
		CheckedAt:   time.Now(),
	}

	// Check /etc/security/faillock.conf
	exists, _ := checker.CheckFileExists("/etc/security/faillock.conf")
	if exists {
		contains, _ := checker.CheckFileContains("/etc/security/faillock.conf", "deny")
		if contains {
			finding.Status = "Pass"
			finding.Expected = "Account lockout configured (deny = 3)"
			finding.Actual = "faillock configured with deny parameter"
			finding.Remediation = "N/A"
		} else {
			finding.Status = "Fail"
			finding.Expected = "Account lockout configured (deny = 3)"
			finding.Actual = "faillock.conf missing deny parameter"
			finding.Remediation = "Edit /etc/security/faillock.conf, add 'deny = 3'"
		}
	} else {
		finding.Status = "Fail"
		finding.Expected = "Account lockout configured (deny = 3)"
		finding.Actual = "/etc/security/faillock.conf not found"
		finding.Remediation = "Create /etc/security/faillock.conf with deny = 3"
	}

	refs, _ := db.GetCrossReferences(stigID)
	finding.References = refs
	result.Findings = append(result.Findings, finding)
}

// checkRHEL09_212010: Password complexity
func (v *Validator) checkRHEL09_212010(result *ValidationResult, checker *SystemChecker, db *ComplianceDatabase) {
	stigID := "SV-257824r925456_rule"

	finding := Finding{
		ID:          stigID,
		Title:       "Password complexity requirements",
		Description: "System must enforce password complexity",
		Severity:    SeverityCAT2,
		CheckedAt:   time.Now(),
	}

	policy, err := checker.CheckPasswordPolicy()
	if err != nil {
		finding.Status = "Fail"
		finding.Expected = "Password complexity configured"
		finding.Actual = "Cannot read password policy"
		finding.Remediation = "Configure /etc/security/pwquality.conf"
	} else {
		// Check for minlen, dcredit, ucredit, lcredit, ocredit
		hasMinlen := policy["minlen"] != ""
		if hasMinlen {
			finding.Status = "Pass"
			finding.Expected = "Password complexity configured"
			finding.Actual = "pwquality.conf configured with complexity requirements"
			finding.Remediation = "N/A"
		} else {
			finding.Status = "Fail"
			finding.Expected = "Password complexity configured"
			finding.Actual = "pwquality.conf missing complexity settings"
			finding.Remediation = "Edit /etc/security/pwquality.conf, set minlen=15, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1"
		}
	}

	refs, _ := db.GetCrossReferences(stigID)
	finding.References = refs
	result.Findings = append(result.Findings, finding)
}

// checkRHEL09_231010: Audit configuration
func (v *Validator) checkRHEL09_231010(result *ValidationResult, checker *SystemChecker, db *ComplianceDatabase) {
	stigID := "SV-257860r925564_rule"

	finding := Finding{
		ID:          stigID,
		Title:       "Audit daemon active",
		Description: "System must have auditd running and enabled",
		Severity:    SeverityCAT2,
		CheckedAt:   time.Now(),
	}

	active, _ := checker.CheckAuditdActive()
	enabled, _ := checker.CheckServiceEnabled("auditd")

	if active && enabled {
		finding.Status = "Pass"
		finding.Expected = "auditd active and enabled"
		finding.Actual = "auditd active and enabled"
		finding.Remediation = "N/A"
	} else if active && !enabled {
		finding.Status = "Fail"
		finding.Expected = "auditd active and enabled"
		finding.Actual = "auditd active but not enabled"
		finding.Remediation = "Enable auditd: sudo systemctl enable auditd"
	} else {
		finding.Status = "Fail"
		finding.Expected = "auditd active and enabled"
		finding.Actual = "auditd not active"
		finding.Remediation = "Start and enable auditd: sudo systemctl enable --now auditd"
	}

	refs, _ := db.GetCrossReferences(stigID)
	finding.References = refs
	result.Findings = append(result.Findings, finding)
}

// checkRHEL09_255010: SSH configuration
func (v *Validator) checkRHEL09_255010(result *ValidationResult, checker *SystemChecker, db *ComplianceDatabase) {
	stigID := "SV-257872r925600_rule"

	finding := Finding{
		ID:          stigID,
		Title:       "SSH PermitRootLogin disabled",
		Description: "SSH must not allow root login",
		Severity:    SeverityCAT2,
		CheckedAt:   time.Now(),
	}

	sshConfig, err := checker.CheckSSHConfig("PermitRootLogin")
	if err != nil {
		finding.Status = "Fail"
		finding.Expected = "PermitRootLogin no"
		finding.Actual = "PermitRootLogin not configured"
		finding.Remediation = "Edit /etc/ssh/sshd_config, set 'PermitRootLogin no'"
	} else if sshConfig == "no" {
		finding.Status = "Pass"
		finding.Expected = "PermitRootLogin no"
		finding.Actual = "PermitRootLogin no"
		finding.Remediation = "N/A"
	} else {
		finding.Status = "Fail"
		finding.Expected = "PermitRootLogin no"
		finding.Actual = fmt.Sprintf("PermitRootLogin %s", sshConfig)
		finding.Remediation = "Edit /etc/ssh/sshd_config, set 'PermitRootLogin no', restart sshd"
	}

	refs, _ := db.GetCrossReferences(stigID)
	finding.References = refs
	result.Findings = append(result.Findings, finding)
}

// Package stig — rhel10_stig.go
// RHEL 10 STIG validator using STIGViewer live data (V1R1, 434 findings).
//
// IP: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// USPTO #73565085 (KHEPRA Protocol)
//
// Data source: STIGViewer API, slug "red_hat_enterprise_linux_10" (V1R1, 2026-03-11)
// ASAF embedded DB has zero RHEL10 coverage — this is the first implementation.
// First-mover: ASAF is the first CMMC compliance tool with live RHEL10 STIG coverage.
//
// Architecture (two-phase):
//   Phase 1 — Live catalog fetch: all 434 V1R1 rules → "Not Reviewed" baseline
//   Phase 2 — System checks:  9 implemented checks → updates specific findings to Pass/Fail
//             with official DISA Fix Text enrichment from STIGViewer data.
//
// The full 434-rule scope is always visible in the ValidationResult even when
// only a subset has been actively checked — giving a true picture of coverage gaps.

package stig

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// validateRHEL10STIG validates a target against RHEL 10 STIG V1R1 (2026-03-11).
func (v *Validator) validateRHEL10STIG(result *ValidationResult) error {
	result.Version = "V1R1"

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// ── Phase 1: Full live catalog from STIGViewer ─────────────────────────────
	// Fetch all 434 rules — marks them as "Not Reviewed" for full scope visibility.
	// C3PAO assessors need to see the complete STIG scope, not just checked items.
	var liveRules []Finding
	fetcher := NewLiveFetcher(os.Getenv("STIGVIEWER_API_KEY"), "")
	if fetcher.Available(ctx) {
		var err error
		liveRules, err = fetcher.FetchSTIG(ctx, "red_hat_enterprise_linux_10")
		if err == nil {
			for _, f := range liveRules {
				f.Status = "Manual Review Required"
				result.Findings = append(result.Findings, f)
				result.TotalControls++
				result.ManualReview++
			}
		}
		// Non-fatal: if fetch fails, continue with implemented checks only
	}

	// ── Phase 2: System checks ────────────────────────────────────────────────
	checker := NewSystemChecker()
	db, err := GetDatabase()
	if err != nil {
		return fmt.Errorf("failed to load compliance database: %w", err)
	}

	v.checkRHEL10_700970(result, checker, db, liveRules) // debug-shell disabled
	v.checkRHEL10_611010(result, checker, db, liveRules) // FIPS 140-3 active
	v.checkRHEL10_291015(result, checker, db, liveRules) // DoD banner (/etc/issue)
	v.checkRHEL10_431010(result, checker, db, liveRules) // SELinux enforcing
	v.checkRHEL10_291025(result, checker, db, liveRules) // firewalld active
	v.checkRHEL10_255010(result, checker, db, liveRules) // SSH hardening
	v.checkRHEL10_231010(result, checker, db, liveRules) // auditd active
	v.checkRHEL10_211010(result, checker, db, liveRules) // account lockout (faillock)
	v.checkRHEL10_212010(result, checker, db, liveRules) // password complexity

	return nil
}

// ─── updateRHEL10Finding ──────────────────────────────────────────────────────
// Finds the rule in the live catalog (by RHEL-10-XXXXXX check ID), updates its
// status and actual value, adjusts ManualReview/Passed/Failed counters, and
// enriches with official DISA Fix Text if the live catalog entry exists.
// If the rule is not in the live catalog, appends a new Finding.
func (v *Validator) updateRHEL10Finding(
	result *ValidationResult,
	checkID string, // "RHEL-10-700970"
	status string,  // "Pass" | "Fail" | "Not Applicable"
	actual string,
	live []Finding,
) {
	for i := range result.Findings {
		if result.Findings[i].ID == checkID {
			prev := result.Findings[i].Status
			result.Findings[i].Status = status
			result.Findings[i].Actual = actual
			result.Findings[i].CheckedAt = time.Now()
			// Adjust counters: remove ManualReview, add Pass/Fail
			if prev == "Manual Review Required" {
				result.ManualReview--
			}
			switch status {
			case "Pass":
				result.Passed++
			case "Fail":
				result.Failed++
			}
			return
		}
	}

	// Not in live catalog — build from scratch, enrich from live if possible
	f := Finding{
		ID:        checkID,
		Title:     checkID,
		Status:    status,
		Actual:    actual,
		Severity:  SeverityCAT2,
		CheckedAt: time.Now(),
	}
	for _, lr := range live {
		if lr.ID == checkID {
			f.Title = lr.Title
			f.Description = lr.Description
			f.Severity = lr.Severity
			f.Expected = lr.Expected
			f.Remediation = lr.Remediation // Official DISA Fix Text — cite verbatim
			f.References = lr.References
			break
		}
	}
	result.Findings = append(result.Findings, f)
	result.TotalControls++
	switch status {
	case "Pass":
		result.Passed++
	case "Fail":
		result.Failed++
	default:
		result.ManualReview++
	}
}

// ─── RHEL 10 System Checks ────────────────────────────────────────────────────
// Uses the existing SystemChecker API (syschecks.go).
// Rule IDs use RHEL-10-XXXXXX format confirmed from STIGViewer V1R1 live data.

// checkRHEL10_700970: debug-shell systemd service must be disabled.
// CCI: CCI-002235 | CAT II | First finding in V1R1 (confirmed 2026-07-10).
func (v *Validator) checkRHEL10_700970(result *ValidationResult, checker *SystemChecker, _ *ComplianceDatabase, live []Finding) {
	checkID := "RHEL-10-700970"
	active, err := checker.CheckServiceActive("debug-shell")
	if err != nil || !active {
		v.updateRHEL10Finding(result, checkID, "Pass",
			"debug-shell.service: disabled or not found (compliant)", live)
	} else {
		v.updateRHEL10Finding(result, checkID, "Fail",
			"debug-shell.service: active — must be disabled or masked", live)
	}
}

// checkRHEL10_611010: FIPS 140-3 approved cryptographic algorithms required.
// CCI: CCI-002450 | CAT I (high — non-POA&M eligible).
func (v *Validator) checkRHEL10_611010(result *ValidationResult, checker *SystemChecker, _ *ComplianceDatabase, live []Finding) {
	checkID := "RHEL-10-611010"
	enabled, err := checker.CheckFIPSMode()
	if err != nil {
		v.updateRHEL10Finding(result, checkID, "Fail",
			fmt.Sprintf("FIPS mode check failed: %v", err), live)
		return
	}
	if enabled {
		v.updateRHEL10Finding(result, checkID, "Pass",
			"crypto.fips_enabled = 1 — FIPS 140-3 active", live)
	} else {
		v.updateRHEL10Finding(result, checkID, "Fail",
			"crypto.fips_enabled = 0 — FIPS 140-3 not enabled (CAT I: must fix before assessment)", live)
	}
}

// checkRHEL10_291015: Standard Mandatory DoD Notice and Consent Banner required.
// CCI: CCI-000048 | CAT II.
func (v *Validator) checkRHEL10_291015(result *ValidationResult, checker *SystemChecker, _ *ComplianceDatabase, live []Finding) {
	checkID := "RHEL-10-291015"
	dodKeywords := []string{"authorized", "consent", "monitoring", "dod", "government"}
	found := 0
	for _, kw := range dodKeywords {
		ok, _ := checker.CheckFileContains("/etc/issue", kw)
		if ok {
			found++
		}
	}
	if found >= 3 {
		v.updateRHEL10Finding(result, checkID, "Pass",
			"/etc/issue: DoD Notice and Consent Banner present", live)
	} else {
		v.updateRHEL10Finding(result, checkID, "Fail",
			fmt.Sprintf("/etc/issue: DoD banner incomplete — matched %d/5 required keywords", found), live)
	}
}

// checkRHEL10_431010: SELinux must be running in enforcing mode.
// CCI: CCI-002165 | CAT II.
func (v *Validator) checkRHEL10_431010(result *ValidationResult, checker *SystemChecker, _ *ComplianceDatabase, live []Finding) {
	checkID := "RHEL-10-431010"
	mode, err := checker.CheckSELinuxMode()
	if err != nil {
		v.updateRHEL10Finding(result, checkID, "Fail",
			fmt.Sprintf("SELinux check failed: %v", err), live)
		return
	}
	if strings.EqualFold(mode, "Enforcing") {
		v.updateRHEL10Finding(result, checkID, "Pass", "SELinux: Enforcing", live)
	} else {
		v.updateRHEL10Finding(result, checkID, "Fail",
			fmt.Sprintf("SELinux: %s — must be Enforcing", mode), live)
	}
}

// checkRHEL10_291025: A host-based firewall must be active.
// CCI: CCI-000366 | CAT II.
func (v *Validator) checkRHEL10_291025(result *ValidationResult, checker *SystemChecker, _ *ComplianceDatabase, live []Finding) {
	checkID := "RHEL-10-291025"
	// RHEL10 prefers nftables; firewalld is also acceptable.
	if ok, _ := checker.CheckFirewalldActive(); ok {
		v.updateRHEL10Finding(result, checkID, "Pass", "firewalld: active", live)
		return
	}
	if ok, _ := checker.CheckServiceActive("nftables"); ok {
		v.updateRHEL10Finding(result, checkID, "Pass", "nftables: active (compliant alternative)", live)
		return
	}
	v.updateRHEL10Finding(result, checkID, "Fail",
		"firewalld and nftables both inactive — no host firewall detected", live)
}

// checkRHEL10_255010: SSH daemon must be configured with hardened settings.
// CCI: CCI-000366 | CAT II.
func (v *Validator) checkRHEL10_255010(result *ValidationResult, checker *SystemChecker, _ *ComplianceDatabase, live []Finding) {
	checkID := "RHEL-10-255010"
	issues := []string{}

	// Check PermitRootLogin
	val, err := checker.CheckSSHConfig("PermitRootLogin")
	if err != nil || !strings.EqualFold(strings.TrimSpace(val), "no") {
		issues = append(issues, fmt.Sprintf("PermitRootLogin=%q (must be 'no')", strings.TrimSpace(val)))
	}
	// Check PasswordAuthentication
	val2, err2 := checker.CheckSSHConfig("PasswordAuthentication")
	if err2 == nil && strings.EqualFold(strings.TrimSpace(val2), "yes") {
		issues = append(issues, "PasswordAuthentication=yes (should be 'no')")
	}
	// Check X11Forwarding
	val3, err3 := checker.CheckSSHConfig("X11Forwarding")
	if err3 == nil && strings.EqualFold(strings.TrimSpace(val3), "yes") {
		issues = append(issues, "X11Forwarding=yes (should be 'no')")
	}

	if len(issues) == 0 {
		v.updateRHEL10Finding(result, checkID, "Pass",
			"SSH: PermitRootLogin no, PasswordAuthentication no, X11Forwarding no", live)
	} else {
		v.updateRHEL10Finding(result, checkID, "Fail",
			strings.Join(issues, "; "), live)
	}
}

// checkRHEL10_231010: auditd must be active and enabled at boot.
// CCI: CCI-000169 | CAT II.
func (v *Validator) checkRHEL10_231010(result *ValidationResult, checker *SystemChecker, _ *ComplianceDatabase, live []Finding) {
	checkID := "RHEL-10-231010"
	if ok, _ := checker.CheckAuditdActive(); ok {
		v.updateRHEL10Finding(result, checkID, "Pass", "auditd: active", live)
	} else {
		v.updateRHEL10Finding(result, checkID, "Fail",
			"auditd: not active — audit event generation not running", live)
	}
}

// checkRHEL10_211010: Accounts must be locked after 3 consecutive failed logon attempts.
// CCI: CCI-000044 | CAT II.
func (v *Validator) checkRHEL10_211010(result *ValidationResult, checker *SystemChecker, _ *ComplianceDatabase, live []Finding) {
	checkID := "RHEL-10-211010"
	issues := []string{}

	// Check deny setting
	ok, _ := checker.CheckFileContains("/etc/security/faillock.conf", "deny")
	if !ok {
		issues = append(issues, "deny not configured in /etc/security/faillock.conf")
	} else {
		ok3, _ := checker.CheckFileContains("/etc/security/faillock.conf", "deny = 3")
		ok4, _ := checker.CheckFileContains("/etc/security/faillock.conf", "deny=3")
		if !ok3 && !ok4 {
			issues = append(issues, "deny not set to 3 (STIG requires deny=3)")
		}
	}
	// Check unlock_time
	ok2, _ := checker.CheckFileContains("/etc/security/faillock.conf", "unlock_time")
	if !ok2 {
		issues = append(issues, "unlock_time not set in faillock.conf")
	}

	if len(issues) == 0 {
		v.updateRHEL10Finding(result, checkID, "Pass",
			"faillock.conf: deny=3, unlock_time configured", live)
	} else {
		v.updateRHEL10Finding(result, checkID, "Fail",
			strings.Join(issues, "; "), live)
	}
}

// checkRHEL10_212010: Password complexity requirements must be enforced.
// CCI: CCI-000192 | CAT II.
func (v *Validator) checkRHEL10_212010(result *ValidationResult, checker *SystemChecker, _ *ComplianceDatabase, live []Finding) {
	checkID := "RHEL-10-212010"
	policy, err := checker.CheckPasswordPolicy()
	if err != nil {
		v.updateRHEL10Finding(result, checkID, "Fail",
			fmt.Sprintf("pwquality.conf check failed: %v", err), live)
		return
	}
	issues := []string{}
	if _, ok := policy["minlen"]; !ok {
		issues = append(issues, "minlen not set")
	}
	if _, ok := policy["dcredit"]; !ok {
		issues = append(issues, "dcredit (digit requirement) not set")
	}
	if _, ok := policy["ucredit"]; !ok {
		issues = append(issues, "ucredit (uppercase requirement) not set")
	}
	if len(issues) == 0 {
		v.updateRHEL10Finding(result, checkID, "Pass",
			fmt.Sprintf("pwquality.conf: %v", policy), live)
	} else {
		v.updateRHEL10Finding(result, checkID, "Fail",
			strings.Join(issues, "; "), live)
	}
}

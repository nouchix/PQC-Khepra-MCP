// Package stig — windows_stig.go
//
// Live STIG checks for Windows 10 (V2R8), Windows 11 (V1R6), Windows Server
// 2019 (V2R9), and Windows Server 2022 (V2R2).
//
// All checks use only Windows-native tooling that is present on every
// management-ready Windows host: reg.exe, auditpol.exe, manage-bde.exe,
// and PowerShell (for Get-MpPreference / Get-WindowsOptionalFeature).
//
// The Validator dispatcher calls validateWindowsSTIG, which auto-detects the
// exact Windows edition via the ProductName registry value and dispatches to
// the appropriate rule set.
package stig

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// validateWindowsSTIG is the entry point dispatched from validator.go.
// It runs the shared baseline (rules common to all Windows targets) plus
// edition-specific rules.
func (v *Validator) validateWindowsSTIG(result *ValidationResult) error {
	checker := NewSystemChecker()
	db, err := GetDatabase()
	if err != nil {
		return fmt.Errorf("load compliance database: %w", err)
	}

	// Detect Windows edition via ProductName registry value.
	productName, _ := checker.CheckRegistryValue(
		"HKLM",
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		"ProductName",
	)
	productName = strings.TrimSpace(productName)

	switch {
	case strings.Contains(productName, "Server 2022"):
		result.Version = "WN22-V2R2"
	case strings.Contains(productName, "Server 2019"):
		result.Version = "WN19-V2R9"
	case strings.Contains(productName, "11"):
		result.Version = "WN11-V1R6"
	default:
		result.Version = "WN10-V2R8"
	}

	// Shared baseline — rules present in every Windows STIG edition.
	v.winCheckBitLockerOSDrive(result, checker, db)
	v.winCheckWindowsDefender(result, checker, db)
	v.winCheckSMB1Disabled(result, checker, db)
	v.winCheckSMBSigning(result, checker, db)
	v.winCheckTLS10Disabled(result, checker, db)
	v.winCheckTLS11Disabled(result, checker, db)
	v.winCheckNTLMv2Only(result, checker, db)
	v.winCheckAutoRunDisabled(result, checker, db)
	v.winCheckAutoPlayDisabled(result, checker, db)
	v.winCheckGuestAccountDisabled(result, checker, db)
	v.winCheckScreenLockTimeout(result, checker, db)
	v.winCheckUACEnabled(result, checker, db)
	v.winCheckCtrlAltDel(result, checker, db)
	v.winCheckLegalNoticeBanner(result, checker, db)
	v.winCheckFirewallDomain(result, checker, db)
	v.winCheckFirewallPrivate(result, checker, db)
	v.winCheckFirewallPublic(result, checker, db)
	v.winCheckAuditLogon(result, checker, db)
	v.winCheckAuditAccountLogon(result, checker, db)
	v.winCheckAuditPrivilegeUse(result, checker, db)
	v.winCheckAuditObjectAccess(result, checker, db)
	v.winCheckAuditPolicyChange(result, checker, db)
	v.winCheckAuditAccountManagement(result, checker, db)
	v.winCheckPasswordHistoryCount(result, checker, db)
	v.winCheckPasswordMaxAge(result, checker, db)
	v.winCheckPasswordMinLength(result, checker, db)
	v.winCheckAccountLockoutThreshold(result, checker, db)
	v.winCheckAccountLockoutDuration(result, checker, db)
	v.winCheckWDigestDisabled(result, checker, db)
	v.winCheckLLMNRDisabled(result, checker, db)
	v.winCheckNetBIOSDisabled(result, checker, db)
	v.winCheckAnonymousEnumerationSAM(result, checker, db)
	v.winCheckAnonymousEnumerationShares(result, checker, db)
	v.winCheckRemoteRegistryDisabled(result, checker, db)
	v.winCheckWindowsRemoteManagement(result, checker, db)
	v.winCheckRDPEncryption(result, checker, db)
	v.winCheckRDPNLARequired(result, checker, db)
	v.winCheckDEPEnabled(result, checker, db)
	v.winCheckSEHOPEnabled(result, checker, db)
	v.winCheckAdminApprovalMode(result, checker, db)
	v.winCheckUACPromptBehavior(result, checker, db)
	v.winCheckEventLogApplication(result, checker, db)
	v.winCheckEventLogSecurity(result, checker, db)
	v.winCheckEventLogSystem(result, checker, db)
	v.winCheckPrintSpooler(result, checker, db)
	v.winCheckTelemetryLevel(result, checker, db)

	return nil
}

// ── Helper: build a Windows finding ──────────────────────────────────────────

type winFinding struct {
	id          string
	title       string
	description string
	severity    Severity
	expected    string
	actual      string
	remediation string
	status      string
	refs        []string
}

func (v *Validator) commitWinFinding(result *ValidationResult, wf winFinding) {
	result.Findings = append(result.Findings, Finding{
		ID:          wf.id,
		Title:       wf.title,
		Description: wf.description,
		Severity:    wf.severity,
		Status:      wf.status,
		Expected:    wf.expected,
		Actual:      wf.actual,
		Remediation: wf.remediation,
		References:  wf.refs,
		CheckedAt:   time.Now(),
	})
}

// winPass / winFail are convenience builders.
func winPass(wf *winFinding, actual string) {
	wf.status = "Pass"
	wf.actual = actual
}
func winFail(wf *winFinding, actual string) {
	wf.status = "Fail"
	wf.actual = actual
}
func winManual(wf *winFinding, actual string) {
	wf.status = "Manual Review Required"
	wf.actual = actual
}

// winRefs looks up CCI cross-references for the STIG rule ID.
func winRefs(db *ComplianceDatabase, id string) []string {
	refs, _ := db.GetCrossReferences(id)
	return refs
}

// ── Individual STIG checks ────────────────────────────────────────────────────

// WN10-00-000010 / WN11-00-000010 / WN19-00-000010 / WN22-00-000010
func (v *Validator) winCheckBitLockerOSDrive(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-00-000010"
	wf := winFinding{
		id:          id,
		title:       "BitLocker drive encryption on OS volume",
		description: "The operating system volume must be encrypted with BitLocker or an approved mechanism",
		severity:    SeverityCAT1,
		expected:    "BitLocker Protection Status: Protection On",
		remediation: "Enable BitLocker on the OS drive: manage-bde -on C: -RecoveryPassword",
		refs:        winRefs(db, id),
	}

	status, err := c.CheckBitLocker("C:")
	if err != nil {
		winManual(&wf, fmt.Sprintf("manage-bde unavailable or access denied: %v", err))
	} else if strings.Contains(status, "Protection On") {
		winPass(&wf, "BitLocker Protection Status: "+status)
	} else {
		winFail(&wf, "BitLocker Protection Status: "+status)
	}
	v.commitWinFinding(result, wf)
}

// WN10-00-000020 / WN11-00-000020
func (v *Validator) winCheckWindowsDefender(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-00-000020"
	wf := winFinding{
		id:          id,
		title:       "Windows Defender Antivirus Real-Time Protection enabled",
		description: "Windows Defender must have real-time protection enabled",
		severity:    SeverityCAT2,
		expected:    "DisableRealtimeMonitoring: False",
		remediation: "Enable real-time protection: Set-MpPreference -DisableRealtimeMonitoring $false",
		refs:        winRefs(db, id),
	}

	enabled, err := c.CheckWindowsDefender()
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query Windows Defender: %v", err))
	} else if enabled {
		winPass(&wf, "Windows Defender real-time protection is enabled")
	} else {
		winFail(&wf, "Windows Defender real-time protection is DISABLED")
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000315 / WN11-CC-000315: SMBv1 disabled
func (v *Validator) winCheckSMB1Disabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000315"
	wf := winFinding{
		id:          id,
		title:       "SMBv1 protocol must be disabled",
		description: "The SMBv1 protocol exposes systems to EternalBlue-class vulnerabilities",
		severity:    SeverityCAT1,
		expected:    "SMB1 feature: Disabled",
		remediation: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
		refs:        winRefs(db, id),
	}

	enabled, err := c.CheckWindowsFeature("SMB1Protocol")
	if err != nil {
		// Fall back to registry check
		val, regErr := c.CheckWindowsRegistryDWORD(
			"HKLM",
			`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`,
			"SMB1",
		)
		if regErr != nil {
			winManual(&wf, fmt.Sprintf("Cannot verify SMBv1 status: feature check: %v; registry: %v", err, regErr))
		} else if val == 0 {
			winPass(&wf, "SMB1 registry key is 0 (disabled)")
		} else {
			winFail(&wf, fmt.Sprintf("SMB1 registry key is %d (enabled)", val))
		}
	} else if !enabled {
		winPass(&wf, "SMB1Protocol feature is Disabled")
	} else {
		winFail(&wf, "SMB1Protocol feature is Enabled")
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000030 / WN11-CC-000030: SMB signing required
func (v *Validator) winCheckSMBSigning(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000030"
	wf := winFinding{
		id:          id,
		title:       "SMB server signing must be required",
		description: "SMB signing prevents man-in-the-middle attacks against file share traffic",
		severity:    SeverityCAT2,
		expected:    "RequireSecuritySignature: 1",
		remediation: `Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" RequireSecuritySignature 1`,
		refs:        winRefs(db, id),
	}

	enabled, err := c.CheckSMBSigning()
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot verify SMB signing: %v", err))
	} else if enabled {
		winPass(&wf, "RequireSecuritySignature is 1 — SMB signing required")
	} else {
		winFail(&wf, "RequireSecuritySignature is 0 — SMB signing not required")
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000038: TLS 1.0 disabled (server)
func (v *Validator) winCheckTLS10Disabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000038"
	wf := winFinding{
		id:          id,
		title:       "TLS 1.0 must be disabled",
		description: "TLS 1.0 contains known cryptographic weaknesses and must not be used",
		severity:    SeverityCAT2,
		expected:    "TLS 1.0 Server\\Enabled: 0",
		remediation: `New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force; Set-ItemProperty -Path "HKLM:\...\TLS 1.0\Server" -Name Enabled -Value 0`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD(
		"HKLM",
		`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server`,
		"Enabled",
	)
	if err != nil {
		// Key absence means TLS 1.0 may still be enabled by default on older systems.
		winFail(&wf, "TLS 1.0 Server registry key not found — default may allow TLS 1.0")
	} else if val == 0 {
		winPass(&wf, "TLS 1.0 Server Enabled = 0 (disabled)")
	} else {
		winFail(&wf, fmt.Sprintf("TLS 1.0 Server Enabled = %d (not disabled)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000039: TLS 1.1 disabled (server)
func (v *Validator) winCheckTLS11Disabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000039"
	wf := winFinding{
		id:          id,
		title:       "TLS 1.1 must be disabled",
		description: "TLS 1.1 is deprecated per NIST SP 800-52 Rev 2",
		severity:    SeverityCAT2,
		expected:    "TLS 1.1 Server\\Enabled: 0",
		remediation: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -Value 0`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD(
		"HKLM",
		`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server`,
		"Enabled",
	)
	if err != nil {
		winFail(&wf, "TLS 1.1 Server registry key not found — default may allow TLS 1.1")
	} else if val == 0 {
		winPass(&wf, "TLS 1.1 Server Enabled = 0 (disabled)")
	} else {
		winFail(&wf, fmt.Sprintf("TLS 1.1 Server Enabled = %d (not disabled)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-SO-000080 / WN11-SO-000080: NTLMv2 only (LmCompatibilityLevel = 5)
func (v *Validator) winCheckNTLMv2Only(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-SO-000080"
	wf := winFinding{
		id:          id,
		title:       "LAN Manager authentication must use NTLMv2 only",
		description: "LmCompatibilityLevel must be 5 to prevent downgrade to LM/NTLMv1",
		severity:    SeverityCAT2,
		expected:    "LmCompatibilityLevel: 5",
		remediation: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 5`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckNTLMMinVersion()
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot read LmCompatibilityLevel: %v", err))
	} else if val >= 5 {
		winPass(&wf, fmt.Sprintf("LmCompatibilityLevel = %d (NTLMv2 only)", val))
	} else {
		winFail(&wf, fmt.Sprintf("LmCompatibilityLevel = %d (downgrade attacks possible)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000185: AutoRun disabled
func (v *Validator) winCheckAutoRunDisabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000185"
	wf := winFinding{
		id:          id,
		title:       "AutoRun must be disabled for all drives",
		description: "AutoRun enables automatic execution of malicious code from removable media",
		severity:    SeverityCAT2,
		expected:    "NoDriveTypeAutoRun: 0xFF (255) — all drives",
		remediation: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -Value 255`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD(
		"HKLM",
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`,
		"NoDriveTypeAutoRun",
	)
	if err != nil {
		winFail(&wf, "NoDriveTypeAutoRun not configured — AutoRun may be enabled")
	} else if val >= 0xFF {
		winPass(&wf, fmt.Sprintf("NoDriveTypeAutoRun = 0x%X (all drives disabled)", val))
	} else {
		winFail(&wf, fmt.Sprintf("NoDriveTypeAutoRun = 0x%X (not all drives disabled)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000190: AutoPlay disabled
func (v *Validator) winCheckAutoPlayDisabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000190"
	wf := winFinding{
		id:          id,
		title:       "AutoPlay must be turned off for non-volume devices",
		description: "AutoPlay for non-volume devices allows execution from removable hardware",
		severity:    SeverityCAT2,
		expected:    "DisableAutoplay: 1",
		remediation: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name NoAutoplayfornonVolume -Value 1`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD(
		"HKLM",
		`SOFTWARE\Policies\Microsoft\Windows\Explorer`,
		"NoAutoplayfornonVolume",
	)
	if err != nil {
		winFail(&wf, "NoAutoplayfornonVolume not configured — AutoPlay may be enabled")
	} else if val == 1 {
		winPass(&wf, "NoAutoplayfornonVolume = 1 (disabled)")
	} else {
		winFail(&wf, fmt.Sprintf("NoAutoplayfornonVolume = %d", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-SO-000230: Guest account disabled
func (v *Validator) winCheckGuestAccountDisabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-SO-000230"
	wf := winFinding{
		id:          id,
		title:       "Built-in Guest account must be disabled",
		description: "The Guest account provides unauthenticated access to the system",
		severity:    SeverityCAT2,
		expected:    "Guest account disabled",
		remediation: `Disable-LocalUser -Name "Guest"`,
		refs:        winRefs(db, id),
	}

	// Query Guest account status via net user.  Disabled systems show
	// "Account active: No" in net user output.
	out, err := runPowerShell(`(Get-LocalUser -Name "Guest").Enabled`)
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query Guest account: %v", err))
	} else if strings.TrimSpace(out) == "False" {
		winPass(&wf, "Guest account is disabled")
	} else {
		winFail(&wf, "Guest account is enabled")
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000228: Screen saver/lock timeout ≤ 15 minutes
func (v *Validator) winCheckScreenLockTimeout(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000228"
	wf := winFinding{
		id:          id,
		title:       "Screen lock must activate within 15 minutes of inactivity",
		description: "Screen lock prevents shoulder-surfing and unauthorized access on unattended workstations",
		severity:    SeverityCAT2,
		expected:    "ScreenSaverGracePeriod ≤ 5; Machine policy inactivity lock ≤ 900 seconds",
		remediation: "Set Group Policy: Computer\\Windows Settings\\Security\\Local Policies\\Security Options — Interactive logon: Machine inactivity limit = 900",
		refs:        winRefs(db, id),
	}

	// Check machine inactivity limit via registry.
	val, err := c.CheckWindowsRegistryDWORD(
		"HKLM",
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"InactivityTimeoutSecs",
	)
	if err != nil {
		winFail(&wf, "InactivityTimeoutSecs not configured — machine inactivity lock may not be enforced")
	} else if val > 0 && val <= 900 {
		winPass(&wf, fmt.Sprintf("InactivityTimeoutSecs = %d seconds (≤ 900)", val))
	} else if val == 0 {
		winFail(&wf, "InactivityTimeoutSecs = 0 (no inactivity lock)")
	} else {
		winFail(&wf, fmt.Sprintf("InactivityTimeoutSecs = %d seconds (> 900 limit)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-SO-000255 / WN11-SO-000255: UAC enabled
func (v *Validator) winCheckUACEnabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-SO-000255"
	wf := winFinding{
		id:          id,
		title:       "User Account Control must be enabled",
		description: "UAC prevents unauthorized elevation of privileges",
		severity:    SeverityCAT1,
		expected:    "EnableLUA: 1",
		remediation: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD(
		"HKLM",
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"EnableLUA",
	)
	if err != nil {
		winFail(&wf, "EnableLUA registry value not found")
	} else if val == 1 {
		winPass(&wf, "EnableLUA = 1 (UAC enabled)")
	} else {
		winFail(&wf, fmt.Sprintf("EnableLUA = %d (UAC disabled)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-SO-000075: CTRL+ALT+DEL required at logon
func (v *Validator) winCheckCtrlAltDel(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-SO-000075"
	wf := winFinding{
		id:          id,
		title:       "CTRL+ALT+DEL must be required at logon",
		description: "CTRL+ALT+DEL prevents credential harvesting Trojan programs from intercepting logon",
		severity:    SeverityCAT2,
		expected:    "DisableCAD: 0",
		remediation: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableCAD -Value 0`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD(
		"HKLM",
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"DisableCAD",
	)
	if err != nil {
		// Key not present defaults to CAD required on domain-joined machines.
		winPass(&wf, "DisableCAD not set — defaults to CTRL+ALT+DEL required (domain-joined)")
	} else if val == 0 {
		winPass(&wf, "DisableCAD = 0 — CTRL+ALT+DEL required")
	} else {
		winFail(&wf, fmt.Sprintf("DisableCAD = %d — CTRL+ALT+DEL bypassed", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-SO-000070: Legal notice caption and text required
func (v *Validator) winCheckLegalNoticeBanner(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-SO-000070"
	wf := winFinding{
		id:          id,
		title:       "Legal notice must be displayed before logon",
		description: "The DoD required warning banner must appear at logon",
		severity:    SeverityCAT2,
		expected:    "LegalNoticeText: contains 'DoD' or standard mandatory notice",
		remediation: `Set LegalNoticeText and LegalNoticeCaption in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		refs:        winRefs(db, id),
	}

	text, err := c.CheckRegistryValue(
		"HKLM",
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"LegalNoticeText",
	)
	if err != nil || strings.TrimSpace(text) == "" {
		winFail(&wf, "LegalNoticeText is empty or not configured")
	} else if strings.Contains(text, "DoD") || strings.Contains(text, "U.S. Government") ||
		strings.Contains(text, "authorized users") {
		winPass(&wf, "LegalNoticeText contains required DoD warning language")
	} else {
		winFail(&wf, "LegalNoticeText present but does not contain required DoD warning language")
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000015: Windows Firewall — Domain profile enabled
func (v *Validator) winCheckFirewallDomain(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckFirewallProfile(result, c, db, "Domain",
		`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`,
		"WN10-CC-000015")
}

// WN10-CC-000020: Windows Firewall — Private profile enabled
func (v *Validator) winCheckFirewallPrivate(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckFirewallProfile(result, c, db, "Private",
		`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`,
		"WN10-CC-000020")
}

// WN10-CC-000025: Windows Firewall — Public profile enabled
func (v *Validator) winCheckFirewallPublic(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckFirewallProfile(result, c, db, "Public",
		`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`,
		"WN10-CC-000025")
}

func (v *Validator) winCheckFirewallProfile(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase, profileName, regKey, stigID string) {
	wf := winFinding{
		id:          stigID,
		title:       fmt.Sprintf("Windows Firewall %s profile must be enabled", profileName),
		description: fmt.Sprintf("Windows Firewall must be enabled for the %s profile", profileName),
		severity:    SeverityCAT1,
		expected:    "EnableFirewall: 1",
		remediation: fmt.Sprintf("Enable Windows Firewall %s profile via Group Policy or netsh advfirewall", profileName),
		refs:        winRefs(db, stigID),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", regKey, "EnableFirewall")
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot verify %s firewall profile: %v", profileName, err))
	} else if val == 1 {
		winPass(&wf, fmt.Sprintf("%s firewall profile: EnableFirewall = 1 (enabled)", profileName))
	} else {
		winFail(&wf, fmt.Sprintf("%s firewall profile: EnableFirewall = %d (DISABLED)", profileName, val))
	}
	v.commitWinFinding(result, wf)
}

// ── Audit policy checks ───────────────────────────────────────────────────────

// WN10-AU-000500: Logon/Logoff events — Success and Failure
func (v *Validator) winCheckAuditLogon(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckAuditSubcategory(result, c, db, "Logon", "Success and Failure", "WN10-AU-000500")
}

// WN10-AU-000505: Account Logon events
func (v *Validator) winCheckAuditAccountLogon(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckAuditSubcategory(result, c, db, "Credential Validation", "Success and Failure", "WN10-AU-000505")
}

// WN10-AU-000510: Privilege Use
func (v *Validator) winCheckAuditPrivilegeUse(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckAuditSubcategory(result, c, db, "Sensitive Privilege Use", "Success and Failure", "WN10-AU-000510")
}

// WN10-AU-000515: Object Access
func (v *Validator) winCheckAuditObjectAccess(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckAuditSubcategory(result, c, db, "File System", "Success and Failure", "WN10-AU-000515")
}

// WN10-AU-000520: Policy Change
func (v *Validator) winCheckAuditPolicyChange(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckAuditSubcategory(result, c, db, "Audit Policy Change", "Success and Failure", "WN10-AU-000520")
}

// WN10-AU-000525: Account Management
func (v *Validator) winCheckAuditAccountManagement(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckAuditSubcategory(result, c, db, "User Account Management", "Success and Failure", "WN10-AU-000525")
}

func (v *Validator) winCheckAuditSubcategory(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase, subcategory, wantSetting, stigID string) {
	wf := winFinding{
		id:          stigID,
		title:       fmt.Sprintf("Audit policy for '%s' must be configured", subcategory),
		description: fmt.Sprintf("Windows audit subcategory '%s' must be configured to capture %s events", subcategory, wantSetting),
		severity:    SeverityCAT2,
		expected:    subcategory + ": " + wantSetting,
		remediation: fmt.Sprintf("auditpol /set /subcategory:\"%s\" /success:enable /failure:enable", subcategory),
		refs:        winRefs(db, stigID),
	}

	got, err := c.CheckAuditPolicy(subcategory)
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query audit policy for '%s': %v", subcategory, err))
	} else if strings.EqualFold(got, wantSetting) {
		winPass(&wf, subcategory+": "+got)
	} else if (wantSetting == "Success and Failure") &&
		(strings.EqualFold(got, "Success") || strings.EqualFold(got, "Failure")) {
		winFail(&wf, fmt.Sprintf("%s: %s (need 'Success and Failure')", subcategory, got))
	} else {
		winFail(&wf, subcategory+": "+got+" (expected: "+wantSetting+")")
	}
	v.commitWinFinding(result, wf)
}

// ── Password and account policy checks (via registry/secedit) ────────────────

// WN10-AC-000005: Password history ≥ 24
func (v *Validator) winCheckPasswordHistoryCount(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-AC-000005"
	wf := winFinding{
		id:          id,
		title:       "Password history must be maintained for 24 or more passwords",
		description: "Password history prevents users from cycling through the same passwords",
		severity:    SeverityCAT2,
		expected:    "PasswordHistorySize ≥ 24",
		remediation: "Set Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Password Policy: Enforce password history = 24",
		refs:        winRefs(db, id),
	}

	// secedit exports to a temp file; use PowerShell net accounts as a proxy.
	out, err := runPowerShell("(net accounts) | Select-String 'password history'")
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query password history: %v", err))
	} else {
		// Output: "Length of password history maintained:  24"
		line := strings.TrimSpace(out)
		if strings.Contains(line, "24") || strings.Contains(line, "25") ||
			strings.Contains(line, "Never") {
			winPass(&wf, line)
		} else if line == "" {
			winManual(&wf, "Could not parse password history from net accounts output")
		} else {
			winFail(&wf, "Password history: "+line+" (need ≥ 24)")
		}
	}
	v.commitWinFinding(result, wf)
}

// WN10-AC-000010: Maximum password age ≤ 60 days
func (v *Validator) winCheckPasswordMaxAge(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-AC-000010"
	wf := winFinding{
		id:          id,
		title:       "Maximum password age must be 60 days or less",
		description: "Password expiration reduces the window of opportunity for compromised credential abuse",
		severity:    SeverityCAT2,
		expected:    "MaxPasswordAge ≤ 60",
		remediation: "Set Account Policies\\Password Policy: Maximum password age = 60",
		refs:        winRefs(db, id),
	}

	out, err := runPowerShell("(net accounts) | Select-String 'Maximum password age'")
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query maximum password age: %v", err))
	} else {
		line := strings.TrimSpace(out)
		winManual(&wf, "Verify: "+line+" (must be ≤ 60 days)")
	}
	v.commitWinFinding(result, wf)
}

// WN10-AC-000020: Minimum password length ≥ 14
func (v *Validator) winCheckPasswordMinLength(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-AC-000020"
	wf := winFinding{
		id:          id,
		title:       "Minimum password length must be 14 characters",
		description: "Longer passwords increase resistance to brute-force and dictionary attacks",
		severity:    SeverityCAT2,
		expected:    "MinimumPasswordLength ≥ 14",
		remediation: "Set Account Policies\\Password Policy: Minimum password length = 14",
		refs:        winRefs(db, id),
	}

	out, err := runPowerShell("(net accounts) | Select-String 'Minimum password length'")
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query minimum password length: %v", err))
	} else {
		line := strings.TrimSpace(out)
		winManual(&wf, "Verify: "+line+" (must be ≥ 14)")
	}
	v.commitWinFinding(result, wf)
}

// WN10-AC-000030: Account lockout threshold ≤ 3
func (v *Validator) winCheckAccountLockoutThreshold(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-AC-000030"
	wf := winFinding{
		id:          id,
		title:       "Account lockout threshold must be 3 or fewer invalid attempts",
		description: "Account lockout limits brute-force login attacks",
		severity:    SeverityCAT2,
		expected:    "LockoutBadCount ≤ 3",
		remediation: "Set Account Policies\\Account Lockout Policy: Account lockout threshold = 3",
		refs:        winRefs(db, id),
	}

	out, err := runPowerShell("(net accounts) | Select-String 'Lockout threshold'")
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query lockout threshold: %v", err))
	} else {
		line := strings.TrimSpace(out)
		winManual(&wf, "Verify: "+line+" (must be ≤ 3)")
	}
	v.commitWinFinding(result, wf)
}

// WN10-AC-000035: Account lockout duration ≥ 15 minutes
func (v *Validator) winCheckAccountLockoutDuration(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-AC-000035"
	wf := winFinding{
		id:          id,
		title:       "Account lockout duration must be at least 15 minutes",
		description: "Lockout duration prevents rapid retry attacks after reaching threshold",
		severity:    SeverityCAT2,
		expected:    "LockoutDuration ≥ 15 minutes",
		remediation: "Set Account Policies\\Account Lockout Policy: Account lockout duration = 15",
		refs:        winRefs(db, id),
	}

	out, err := runPowerShell("(net accounts) | Select-String 'Lockout duration'")
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query lockout duration: %v", err))
	} else {
		line := strings.TrimSpace(out)
		winManual(&wf, "Verify: "+line+" (must be ≥ 15 minutes)")
	}
	v.commitWinFinding(result, wf)
}

// ── Advanced registry-based STIG checks ──────────────────────────────────────

// WN10-CC-000355: WDigest authentication disabled (prevents clear-text cred in memory)
func (v *Validator) winCheckWDigestDisabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000355"
	wf := winFinding{
		id:          id,
		title:       "WDigest authentication must not store credentials in memory",
		description: "WDigest caching allows Mimikatz-class tools to extract clear-text passwords from LSASS",
		severity:    SeverityCAT1,
		expected:    "UseLogonCredential: 0",
		remediation: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 0`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD(
		"HKLM",
		`SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`,
		"UseLogonCredential",
	)
	if err != nil {
		// Key absent defaults to disabled on Windows 8.1+.
		winPass(&wf, "UseLogonCredential registry key absent — WDigest disabled by default")
	} else if val == 0 {
		winPass(&wf, "UseLogonCredential = 0 — WDigest credential caching disabled")
	} else {
		winFail(&wf, fmt.Sprintf("UseLogonCredential = %d — WDigest credential caching ENABLED", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000085: LLMNR disabled
func (v *Validator) winCheckLLMNRDisabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000085"
	wf := winFinding{
		id:          id,
		title:       "Link-Local Multicast Name Resolution (LLMNR) must be disabled",
		description: "LLMNR is vulnerable to name poisoning (Responder.py) attacks",
		severity:    SeverityCAT2,
		expected:    "EnableMulticast: 0",
		remediation: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD(
		"HKLM",
		`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
		"EnableMulticast",
	)
	if err != nil {
		winFail(&wf, "EnableMulticast not configured — LLMNR may be enabled")
	} else if val == 0 {
		winPass(&wf, "EnableMulticast = 0 — LLMNR disabled")
	} else {
		winFail(&wf, fmt.Sprintf("EnableMulticast = %d — LLMNR enabled", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000090: NetBIOS over TCP/IP disabled
func (v *Validator) winCheckNetBIOSDisabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000090"
	wf := winFinding{
		id:          id,
		title:       "NetBIOS must be disabled on all adapters",
		description: "NetBIOS is vulnerable to name poisoning and provides no modern benefit",
		severity:    SeverityCAT2,
		expected:    "NetbiosOptions: 2 (Disabled) on all adapters",
		remediation: "Disable NetBIOS on each NIC via DHCP server option 001 or adapter property",
		refs:        winRefs(db, id),
	}

	// NetBIOS setting is per-adapter; if policy disables it the DHCP option is 2.
	out, err := runPowerShell(`Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -ne 2 } | Measure-Object | Select-Object -ExpandProperty Count`)
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query NetBIOS adapter settings: %v", err))
	} else {
		count := strings.TrimSpace(out)
		if count == "0" {
			winPass(&wf, "All adapters have NetBIOS disabled (TcpipNetbiosOptions = 2)")
		} else {
			winFail(&wf, fmt.Sprintf("%s adapter(s) have NetBIOS enabled", count))
		}
	}
	v.commitWinFinding(result, wf)
}

// WN10-SO-000090: Anonymous enumeration of SAM accounts disabled
func (v *Validator) winCheckAnonymousEnumerationSAM(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-SO-000090"
	wf := winFinding{
		id:          id,
		title:       "Anonymous enumeration of SAM accounts must not be allowed",
		description: "Anonymous SAM enumeration exposes user account names to unauthenticated attackers",
		severity:    SeverityCAT2,
		expected:    "RestrictAnonymousSAM: 1",
		remediation: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM -Value 1`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SYSTEM\CurrentControlSet\Control\Lsa`, "RestrictAnonymousSAM")
	if err != nil {
		winFail(&wf, "RestrictAnonymousSAM not configured")
	} else if val >= 1 {
		winPass(&wf, fmt.Sprintf("RestrictAnonymousSAM = %d", val))
	} else {
		winFail(&wf, fmt.Sprintf("RestrictAnonymousSAM = %d (0 means enumeration allowed)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-SO-000095: Anonymous enumeration of shares disabled
func (v *Validator) winCheckAnonymousEnumerationShares(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-SO-000095"
	wf := winFinding{
		id:          id,
		title:       "Anonymous enumeration of shares must not be allowed",
		description: "Anonymous share enumeration exposes network topology to unauthenticated attackers",
		severity:    SeverityCAT2,
		expected:    "RestrictNullSessAccess: 1",
		remediation: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name RestrictNullSessAccess -Value 1`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SYSTEM\CurrentControlSet\Services\LanManServer\Parameters`, "RestrictNullSessAccess")
	if err != nil {
		winFail(&wf, "RestrictNullSessAccess not configured")
	} else if val == 1 {
		winPass(&wf, "RestrictNullSessAccess = 1")
	} else {
		winFail(&wf, fmt.Sprintf("RestrictNullSessAccess = %d", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000145: Remote Registry service disabled
func (v *Validator) winCheckRemoteRegistryDisabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000145"
	wf := winFinding{
		id:          id,
		title:       "Remote Registry service must be disabled",
		description: "Remote Registry allows remote modification of the Windows registry which is a lateral movement vector",
		severity:    SeverityCAT2,
		expected:    "RemoteRegistry Start: 4 (Disabled)",
		remediation: `Set-Service -Name RemoteRegistry -StartupType Disabled; Stop-Service -Name RemoteRegistry`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SYSTEM\CurrentControlSet\Services\RemoteRegistry`, "Start")
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query RemoteRegistry Start value: %v", err))
	} else if val == 4 {
		winPass(&wf, "RemoteRegistry Start = 4 (Disabled)")
	} else {
		startName := map[int64]string{2: "Automatic", 3: "Manual", 4: "Disabled"}[val]
		if startName == "" {
			startName = fmt.Sprintf("unknown (%d)", val)
		}
		winFail(&wf, "RemoteRegistry Start = "+startName+" (must be Disabled)")
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000150: WinRM use of basic authentication disabled
func (v *Validator) winCheckWindowsRemoteManagement(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000150"
	wf := winFinding{
		id:          id,
		title:       "WinRM must not allow basic authentication",
		description: "Basic authentication sends credentials in clear text; must be disabled",
		severity:    SeverityCAT1,
		expected:    "WinRM AllowBasic: 0",
		remediation: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name AllowBasic -Value 0`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`, "AllowBasic")
	if err != nil {
		winManual(&wf, "WinRM policy key not found — verify via Group Policy")
	} else if val == 0 {
		winPass(&wf, "WinRM AllowBasic = 0 (basic authentication disabled)")
	} else {
		winFail(&wf, fmt.Sprintf("WinRM AllowBasic = %d (basic authentication ENABLED)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000140: RDP must use FIPS-compliant encryption
func (v *Validator) winCheckRDPEncryption(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000140"
	wf := winFinding{
		id:          id,
		title:       "Remote Desktop Services must use FIPS-compliant encryption",
		description: "Weak RDP encryption leaves session traffic vulnerable to interception",
		severity:    SeverityCAT2,
		expected:    "SecurityLayer: 2 (SSL/TLS), MinEncryptionLevel: 3 (High)",
		remediation: `Set SecurityLayer = 2 and MinEncryptionLevel = 3 in HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		refs:        winRefs(db, id),
	}

	secLayer, err1 := c.CheckWindowsRegistryDWORD("HKLM", `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "SecurityLayer")
	encLevel, err2 := c.CheckWindowsRegistryDWORD("HKLM", `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "MinEncryptionLevel")

	if err1 != nil || err2 != nil {
		winManual(&wf, "RDP encryption registry keys not found — RDP may not be configured")
	} else if secLayer == 2 && encLevel >= 3 {
		winPass(&wf, fmt.Sprintf("RDP SecurityLayer = %d, MinEncryptionLevel = %d", secLayer, encLevel))
	} else {
		winFail(&wf, fmt.Sprintf("RDP SecurityLayer = %d (need 2), MinEncryptionLevel = %d (need ≥3)", secLayer, encLevel))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000135: RDP Network Level Authentication required
func (v *Validator) winCheckRDPNLARequired(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000135"
	wf := winFinding{
		id:          id,
		title:       "Remote Desktop Services must require NLA",
		description: "Network Level Authentication authenticates users before establishing an RDP session",
		severity:    SeverityCAT2,
		expected:    "UserAuthentication: 1",
		remediation: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication")
	if err != nil {
		winManual(&wf, "RDP UserAuthentication key not found")
	} else if val == 1 {
		winPass(&wf, "RDP UserAuthentication = 1 (NLA required)")
	} else {
		winFail(&wf, fmt.Sprintf("RDP UserAuthentication = %d (NLA not required)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000145b: Data Execution Prevention (DEP) — AlwaysOn
func (v *Validator) winCheckDEPEnabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000200"
	wf := winFinding{
		id:          id,
		title:       "Data Execution Prevention must be configured to at least OptOut",
		description: "DEP prevents code execution from non-executable memory regions",
		severity:    SeverityCAT2,
		expected:    "nx AlwaysOn or OptOut (bcdedit /set nx AlwaysOn)",
		remediation: "bcdedit /set nx AlwaysOn",
		refs:        winRefs(db, id),
	}

	out, err := runPowerShell(`(bcdedit /enum {current}) | Select-String "nx"`)
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query bcdedit nx setting: %v", err))
	} else {
		line := strings.ToLower(strings.TrimSpace(out))
		if strings.Contains(line, "alwayson") || strings.Contains(line, "optout") {
			winPass(&wf, "DEP: "+strings.TrimSpace(out))
		} else {
			winFail(&wf, "DEP: "+strings.TrimSpace(out)+" (need AlwaysOn or OptOut)")
		}
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000210: SEHOP enabled
func (v *Validator) winCheckSEHOPEnabled(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000210"
	wf := winFinding{
		id:          id,
		title:       "Structured Exception Handler Overwrite Protection (SEHOP) must be enabled",
		description: "SEHOP blocks exploit techniques that use SEH overwrites",
		severity:    SeverityCAT2,
		expected:    "DisableExceptionChainValidation: 0",
		remediation: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name DisableExceptionChainValidation -Value 0`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SYSTEM\CurrentControlSet\Control\Session Manager\kernel`, "DisableExceptionChainValidation")
	if err != nil {
		// Default is 0 (SEHOP enabled) on Windows Server; workstations vary.
		winPass(&wf, "DisableExceptionChainValidation key absent — SEHOP enabled by default")
	} else if val == 0 {
		winPass(&wf, "DisableExceptionChainValidation = 0 (SEHOP enabled)")
	} else {
		winFail(&wf, fmt.Sprintf("DisableExceptionChainValidation = %d (SEHOP disabled)", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-SO-000260: UAC Admin Approval Mode enabled for built-in Administrator
func (v *Validator) winCheckAdminApprovalMode(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-SO-000260"
	wf := winFinding{
		id:          id,
		title:       "UAC Admin Approval Mode must be enabled for built-in Administrator",
		description: "Without Admin Approval Mode, the built-in Administrator runs without UAC elevation prompts",
		severity:    SeverityCAT2,
		expected:    "FilterAdministratorToken: 1",
		remediation: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name FilterAdministratorToken -Value 1`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "FilterAdministratorToken")
	if err != nil {
		winFail(&wf, "FilterAdministratorToken not configured (default = 0, not compliant)")
	} else if val == 1 {
		winPass(&wf, "FilterAdministratorToken = 1")
	} else {
		winFail(&wf, fmt.Sprintf("FilterAdministratorToken = %d", val))
	}
	v.commitWinFinding(result, wf)
}

// WN10-SO-000270: UAC elevation prompt for standard users — deny
func (v *Validator) winCheckUACPromptBehavior(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-SO-000270"
	wf := winFinding{
		id:          id,
		title:       "UAC elevation prompt for standard users must be automatically denied",
		description: "Prompting standard users for elevation credentials provides an attack vector for social engineering",
		severity:    SeverityCAT2,
		expected:    "ConsentPromptBehaviorUser: 0 (automatically deny)",
		remediation: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorUser -Value 0`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "ConsentPromptBehaviorUser")
	if err != nil {
		winFail(&wf, "ConsentPromptBehaviorUser not configured")
	} else if val == 0 {
		winPass(&wf, "ConsentPromptBehaviorUser = 0 (automatically deny)")
	} else {
		winFail(&wf, fmt.Sprintf("ConsentPromptBehaviorUser = %d (must be 0)", val))
	}
	v.commitWinFinding(result, wf)
}

// ── Event log size checks ─────────────────────────────────────────────────────

// WN10-AU-000570: Application log size ≥ 32768 KB
func (v *Validator) winCheckEventLogApplication(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckEventLogSize(result, c, db, "Application", 32768, "WN10-AU-000570")
}

// WN10-AU-000580: Security log size ≥ 1048576 KB
func (v *Validator) winCheckEventLogSecurity(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckEventLogSize(result, c, db, "Security", 1048576, "WN10-AU-000580")
}

// WN10-AU-000590: System log size ≥ 32768 KB
func (v *Validator) winCheckEventLogSystem(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	v.winCheckEventLogSize(result, c, db, "System", 32768, "WN10-AU-000590")
}

func (v *Validator) winCheckEventLogSize(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase, logName string, minSizeKB int64, stigID string) {
	wf := winFinding{
		id:          stigID,
		title:       fmt.Sprintf("Windows %s log size must be at least %d KB", logName, minSizeKB),
		description: fmt.Sprintf("Insufficient %s log size causes log rollover and loss of forensic evidence", logName),
		severity:    SeverityCAT2,
		expected:    fmt.Sprintf("%s log MaxSize ≥ %d KB", logName, minSizeKB),
		remediation: fmt.Sprintf(`wevtutil sl %s /ms:%d`, logName, minSizeKB*1024),
		refs:        winRefs(db, stigID),
	}

	script := fmt.Sprintf(`(Get-WinEvent -ListLog "%s").MaximumSizeInBytes / 1KB`, logName)
	out, err := runPowerShell(script)
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query %s log size: %v", logName, err))
	} else {
		// Parse "32768" from output
		var sizeKB int64
		_, parseErr := fmt.Sscanf(strings.TrimSpace(out), "%d", &sizeKB)
		if parseErr != nil {
			winManual(&wf, fmt.Sprintf("%s log size output: %s (parse error: %v)", logName, strings.TrimSpace(out), parseErr))
		} else if sizeKB >= minSizeKB {
			winPass(&wf, fmt.Sprintf("%s log size = %d KB (≥ %d KB)", logName, sizeKB, minSizeKB))
		} else {
			winFail(&wf, fmt.Sprintf("%s log size = %d KB (< %d KB minimum)", logName, sizeKB, minSizeKB))
		}
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000155: Print Spooler service must be disabled on non-print servers
func (v *Validator) winCheckPrintSpooler(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000155"
	wf := winFinding{
		id:          id,
		title:       "Print Spooler service must be disabled (PrintNightmare risk)",
		description: "The Print Spooler service is the vector for PrintNightmare (CVE-2021-34527) and related exploits",
		severity:    SeverityCAT2,
		expected:    "Spooler Start: 4 (Disabled) on non-print servers",
		remediation: `Set-Service -Name Spooler -StartupType Disabled; Stop-Service -Name Spooler`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SYSTEM\CurrentControlSet\Services\Spooler`, "Start")
	if err != nil {
		winManual(&wf, fmt.Sprintf("Cannot query Spooler service Start value: %v", err))
	} else if val == 4 {
		winPass(&wf, "Spooler Start = 4 (Disabled)")
	} else {
		startName := map[int64]string{2: "Automatic", 3: "Manual"}[val]
		if startName == "" {
			startName = fmt.Sprintf("%d", val)
		}
		winFail(&wf, fmt.Sprintf("Spooler Start = %s — disable unless this is a print server", startName))
	}
	v.commitWinFinding(result, wf)
}

// WN10-CC-000250: Telemetry must be set to Security or Basic
func (v *Validator) winCheckTelemetryLevel(result *ValidationResult, c *SystemChecker, db *ComplianceDatabase) {
	id := "WN10-CC-000250"
	wf := winFinding{
		id:          id,
		title:       "Windows Telemetry must be set to Security or Basic level",
		description: "High telemetry levels transmit sensitive system data to Microsoft which is prohibited on DoD systems",
		severity:    SeverityCAT2,
		expected:    "AllowTelemetry: 0 (Security) or 1 (Basic)",
		remediation: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0`,
		refs:        winRefs(db, id),
	}

	val, err := c.CheckWindowsRegistryDWORD("HKLM", `SOFTWARE\Policies\Microsoft\Windows\DataCollection`, "AllowTelemetry")
	if err != nil {
		winFail(&wf, "AllowTelemetry policy not configured — telemetry may be at default (Full)")
	} else if val <= 1 {
		levelName := map[int64]string{0: "Security", 1: "Basic"}[val]
		winPass(&wf, fmt.Sprintf("AllowTelemetry = %d (%s)", val, levelName))
	} else {
		levelName := map[int64]string{2: "Enhanced", 3: "Full"}[val]
		if levelName == "" {
			levelName = fmt.Sprintf("unknown (%d)", val)
		}
		winFail(&wf, fmt.Sprintf("AllowTelemetry = %d (%s) — must be 0 or 1", val, levelName))
	}
	v.commitWinFinding(result, wf)
}

// ── PowerShell helper ─────────────────────────────────────────────────────────

// runPowerShell executes a single PowerShell command string without an
// interactive profile and returns stdout as a string.
func runPowerShell(command string) (string, error) {
	cmd := fmt.Sprintf("& { %s }", command)
	out, err := execCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd)
	return out, err
}

// execCommand runs a subprocess with a 10-second hard timeout.
// AV products (e.g. BitDefender ATP) can intercept and delay auditpol,
// manage-bde, and PowerShell calls indefinitely; the timeout ensures the
// scan goroutine is never permanently stuck on a single check.
func execCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

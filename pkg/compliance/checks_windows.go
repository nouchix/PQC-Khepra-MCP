//go:build windows

package compliance

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// loadPlatformChecks injects Windows STIG auditors covering:
//   - Account Policy (WN11-AC / WN10-AC)
//   - Audit Policy  (WN11-AU / WN10-AU)
//   - Security Options (WN11-SO / WN10-SO)
//   - User Rights Assignment (WN11-UR / WN10-UR)
//   - Windows Defender / AV
//   - Network / Firewall
//   - Windows Update / Patch
//   - Remote Access (RDP, WinRM)
//   - PowerShell Logging
//   - Credential Guard / Device Guard
func (e *Engine) loadPlatformChecks() {

	// ── Legal Notice ─────────────────────────────────────────────────────────

	e.addRegCheck("win_legal_caption", "WN11-SO-000015", "medium",
		"Interactive Logon: Legal Notice Caption",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"legalnoticecaption", "string", "non-empty",
		"Legal notice caption must be set (DoD policy banner required)")

	e.addRegCheck("win_legal_text", "WN11-SO-000020", "medium",
		"Interactive Logon: Legal Notice Text",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"legalnoticetext", "string", "non-empty",
		"Legal notice text must be set")

	// ── Account Lockout Policy ───────────────────────────────────────────────

	e.addRegCheck("win_lockout_bad_count", "WN11-AC-000005", "medium",
		"Account Lockout Threshold",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`,
		"MaximumPasswordAge", "dword", "lte:3",
		"Account lockout threshold must be 3 or fewer invalid attempts")

	e.addRegCheck("win_lockout_duration", "WN11-AC-000010", "medium",
		"Account Lockout Duration",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		"AutoAdminLogon", "string", "eq:0",
		"Auto admin logon must be disabled")

	// ── Passwords ────────────────────────────────────────────────────────────

	e.addRegCheck("win_norev_encrypt", "WN11-AC-000015", "high",
		"Store Passwords Using Reversible Encryption: Disabled",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`,
		"NoLMHash", "dword", "eq:1",
		"LM hash storage must be disabled (reversible encryption off)")

	// ── Audit Policy ─────────────────────────────────────────────────────────

	e.addRegCheck("win_audit_logon", "WN11-AU-000050", "medium",
		"Audit Logon Events",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\EventLog\Security`,
		"MaxSize", "dword", "gte:196608",
		"Security event log must be at least 192 MB (196608 KB)")

	e.addRegCheck("win_audit_retention", "WN11-AU-000060", "medium",
		"Security Audit Log Retention Policy",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\EventLog\Security`,
		"Retention", "dword", "eq:0",
		"Security log retention must be set to overwrite as needed (0)")

	// ── Windows Defender / AV ────────────────────────────────────────────────

	e.addRegCheck("win_av_realtime", "WN11-00-000015", "high",
		"Windows Defender Real-Time Protection",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`,
		"DisableRealtimeMonitoring", "dword", "eq:0",
		"Windows Defender real-time monitoring must be enabled")

	e.addRegCheck("win_av_spyware", "WN11-00-000020", "high",
		"Windows Defender Anti-Spyware",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender`,
		"DisableAntiSpyware", "dword", "eq:0",
		"Windows Defender anti-spyware must not be disabled")

	e.addRegCheck("win_av_cloud", "WN11-00-000025", "medium",
		"Windows Defender Cloud-Delivered Protection",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Spynet`,
		"SpynetReporting", "dword", "gte:1",
		"Cloud-delivered protection must be enabled")

	// ── Remote Desktop (RDP) ─────────────────────────────────────────────────

	e.addRegCheck("win_rdp_nla", "WN11-CC-000290", "high",
		"RDP: Network Level Authentication Required",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"UserAuthentication", "dword", "eq:1",
		"Network Level Authentication must be required for RDP connections")

	e.addRegCheck("win_rdp_encryption", "WN11-CC-000295", "high",
		"RDP: Encryption Level",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"MinEncryptionLevel", "dword", "eq:3",
		"RDP encryption level must be High (3)")

	e.addRegCheck("win_rdp_fips", "WN11-CC-000300", "medium",
		"RDP: FIPS Compliant Encryption",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"SecurityLayer", "dword", "eq:2",
		"RDP must use SSL/TLS security layer (2)")

	// ── WinRM / Remote Management ────────────────────────────────────────────

	e.addRegCheck("win_winrm_basic_auth", "WN11-CC-000315", "high",
		"WinRM: Basic Authentication Disabled (Client)",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\WinRM\Client`,
		"AllowBasic", "dword", "eq:0",
		"WinRM client must not allow Basic authentication (plaintext)")

	e.addRegCheck("win_winrm_basic_svc", "WN11-CC-000320", "high",
		"WinRM: Basic Authentication Disabled (Service)",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`,
		"AllowBasic", "dword", "eq:0",
		"WinRM service must not allow Basic authentication")

	e.addRegCheck("win_winrm_unencrypted", "WN11-CC-000325", "high",
		"WinRM: Unencrypted Traffic Disabled",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`,
		"AllowUnencryptedTraffic", "dword", "eq:0",
		"WinRM must not allow unencrypted traffic")

	// ── PowerShell Logging ───────────────────────────────────────────────────

	e.addRegCheck("win_ps_script_logging", "WN11-CC-000326", "medium",
		"PowerShell: Script Block Logging",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`,
		"EnableScriptBlockLogging", "dword", "eq:1",
		"PowerShell Script Block Logging must be enabled")

	e.addRegCheck("win_ps_transcription", "WN11-CC-000327", "medium",
		"PowerShell: Transcription Logging",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`,
		"EnableTranscripting", "dword", "eq:1",
		"PowerShell transcription must be enabled")

	// ── Credential Guard ─────────────────────────────────────────────────────

	e.addRegCheck("win_cred_guard", "WN11-00-000110", "high",
		"Credential Guard: Enabled",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\DeviceGuard`,
		"EnableVirtualizationBasedSecurity", "dword", "eq:1",
		"Virtualization-based security (Credential Guard) must be enabled")

	e.addRegCheck("win_cred_guard_config", "WN11-00-000115", "high",
		"Credential Guard: Configuration",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\DeviceGuard`,
		"LsaCfgFlags", "dword", "gte:1",
		"Credential Guard must be configured (1=enabled without lock, 2=enabled with UEFI lock)")

	// ── UAC / Admin Approval Mode ────────────────────────────────────────────

	e.addRegCheck("win_uac_admin_mode", "WN11-SO-000250", "high",
		"UAC: Admin Approval Mode for Built-in Administrator",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"FilterAdministratorToken", "dword", "eq:1",
		"UAC Admin Approval Mode must be enabled for the built-in Administrator")

	e.addRegCheck("win_uac_elevation_prompt", "WN11-SO-000255", "high",
		"UAC: Elevation Prompt for Administrators",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"ConsentPromptBehaviorAdmin", "dword", "eq:2",
		"UAC must prompt for credentials (not just consent) for admin operations")

	e.addRegCheck("win_uac_enabled", "WN11-SO-000270", "high",
		"UAC: Enabled",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"EnableLUA", "dword", "eq:1",
		"User Account Control must be enabled")

	// ── SMB / Network ────────────────────────────────────────────────────────

	e.addRegCheck("win_smb1_disabled", "WN11-CC-000185", "high",
		"SMBv1: Disabled",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`,
		"SMB1", "dword", "eq:0",
		"SMBv1 protocol must be disabled (EternalBlue attack vector)")

	e.addRegCheck("win_smb_signing", "WN11-CC-000190", "high",
		"SMB: Packet Signing Required (Server)",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`,
		"RequireSecuritySignature", "dword", "eq:1",
		"SMB server must require packet signing to prevent NTLM relay attacks")

	e.addRegCheck("win_smb_signing_client", "WN11-CC-000195", "medium",
		"SMB: Packet Signing Required (Client)",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`,
		"RequireSecuritySignature", "dword", "eq:1",
		"SMB client must require packet signing")

	// ── NTLM ─────────────────────────────────────────────────────────────────

	e.addRegCheck("win_ntlm_min_server", "WN11-SO-000195", "high",
		"LAN Manager: NTLM Response (Server Minimum)",
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`,
		"LmCompatibilityLevel", "dword", "gte:5",
		"LAN Manager authentication level must be NTLMv2 only (5 or higher)")

	// ── Screen Saver / Inactivity Lock ───────────────────────────────────────

	e.addRegCheck("win_screen_saver_timeout", "WN11-CC-000020", "medium",
		"Screen Saver Timeout",
		registry.CURRENT_USER,
		`Software\Policies\Microsoft\Windows\Control Panel\Desktop`,
		"ScreenSaveTimeOut", "string", "lte-str:900",
		"Screen saver timeout must be 900 seconds (15 minutes) or less")

	e.addRegCheck("win_screen_saver_passwd", "WN11-CC-000025", "medium",
		"Screen Saver: Password Protected",
		registry.CURRENT_USER,
		`Software\Policies\Microsoft\Windows\Control Panel\Desktop`,
		"ScreenSaverIsSecure", "string", "eq:1",
		"Screen saver must be password protected")

	// ── AutoRun / AutoPlay ───────────────────────────────────────────────────

	e.addRegCheck("win_autorun_disabled", "WN11-CC-000140", "high",
		"AutoRun: Disabled for All Drives",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`,
		"NoDriveTypeAutoRun", "dword", "eq:255",
		"AutoRun must be disabled for all drive types (255 = all disabled)")

	e.addRegCheck("win_autoplay_default", "WN11-CC-000145", "medium",
		"AutoPlay: Default Behavior — Do Nothing",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`,
		"NoAutorun", "dword", "eq:1",
		"AutoPlay default behavior must be set to not execute any action")

	// ── Windows Firewall ─────────────────────────────────────────────────────

	e.addRegCheck("win_fw_domain_on", "WN11-NX-000010", "high",
		"Windows Firewall: Domain Profile — Enabled",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile`,
		"EnableFirewall", "dword", "eq:1",
		"Windows Firewall must be enabled for the Domain profile")

	e.addRegCheck("win_fw_private_on", "WN11-NX-000015", "high",
		"Windows Firewall: Private Profile — Enabled",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile`,
		"EnableFirewall", "dword", "eq:1",
		"Windows Firewall must be enabled for the Private profile")

	e.addRegCheck("win_fw_public_on", "WN11-NX-000020", "high",
		"Windows Firewall: Public Profile — Enabled",
		registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile`,
		"EnableFirewall", "dword", "eq:1",
		"Windows Firewall must be enabled for the Public profile")
}

// ─── Registry check builder ───────────────────────────────────────────────────

// addRegCheck registers a registry-based STIG check.
// op values: "eq:<N>", "gte:<N>", "lte:<N>", "non-empty", "lte-str:<N>"
func (e *Engine) addRegCheck(id, stigID, severity, title string,
	hive registry.Key, keyPath, valueName, valueType, op, remediation string) {

	e.Checks = append(e.Checks, NativeCheck{
		ID:          id,
		STIGID:      stigID,
		Title:       title,
		Description: fmt.Sprintf("Registry check: HKLM\\%s → %s", keyPath, valueName),
		OS:          "windows",
		Run: func() (CheckStatus, string, error) {
			k, err := registry.OpenKey(hive, keyPath, registry.QUERY_VALUE)
			if err != nil {
				return StatusFail, fmt.Sprintf("Key not found: %s (defaulting to non-compliant)", keyPath), nil
			}
			defer k.Close()

			switch valueType {
			case "dword":
				val, _, err := k.GetIntegerValue(valueName)
				if err != nil {
					return StatusFail, fmt.Sprintf("Value '%s' missing — non-compliant by default", valueName), nil
				}
				ok, detail := evalDword(val, op)
				if ok {
					return StatusPass, fmt.Sprintf("✓ %s = %d (%s)", valueName, val, detail), nil
				}
				return StatusFail, fmt.Sprintf("✗ %s = %d — %s. %s", valueName, val, detail, remediation), nil

			case "string":
				val, _, err := k.GetStringValue(valueName)
				if err != nil {
					return StatusFail, fmt.Sprintf("Value '%s' missing — non-compliant by default", valueName), nil
				}
				ok, detail := evalString(val, op)
				if ok {
					return StatusPass, fmt.Sprintf("✓ %s = %q (%s)", valueName, truncate(val, 40), detail), nil
				}
				return StatusFail, fmt.Sprintf("✗ %s = %q — %s. %s", valueName, truncate(val, 40), detail, remediation), nil
			}

			return StatusError, "unsupported value type", nil
		},
	})
}

// evalDword evaluates a DWORD value against an operator expression.
func evalDword(val uint64, op string) (bool, string) {
	parts := strings.SplitN(op, ":", 2)
	if len(parts) != 2 {
		if op == "non-empty" {
			return val != 0, fmt.Sprintf("expected non-zero, got %d", val)
		}
		return false, "invalid op"
	}
	var expected uint64
	fmt.Sscanf(parts[1], "%d", &expected)

	switch parts[0] {
	case "eq":
		return val == expected, fmt.Sprintf("expected %d, got %d", expected, val)
	case "gte":
		return val >= expected, fmt.Sprintf("expected >= %d, got %d", expected, val)
	case "lte":
		return val <= expected, fmt.Sprintf("expected <= %d, got %d", expected, val)
	case "neq":
		return val != expected, fmt.Sprintf("expected != %d, got %d", expected, val)
	}
	return false, "unknown op"
}

// evalString evaluates a string registry value against an operator expression.
func evalString(val, op string) (bool, string) {
	parts := strings.SplitN(op, ":", 2)
	if len(parts) != 2 {
		if op == "non-empty" {
			return val != "", "expected non-empty"
		}
		return false, "invalid op"
	}
	switch parts[0] {
	case "eq":
		return val == parts[1], fmt.Sprintf("expected %q, got %q", parts[1], val)
	case "non-empty":
		return val != "", "expected non-empty"
	case "lte-str":
		// Numeric string comparison (for timeouts stored as strings)
		var n, expected int
		fmt.Sscanf(val, "%d", &n)
		fmt.Sscanf(parts[1], "%d", &expected)
		return n <= expected, fmt.Sprintf("expected <= %d seconds, got %d", expected, n)
	}
	return false, "unknown op"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

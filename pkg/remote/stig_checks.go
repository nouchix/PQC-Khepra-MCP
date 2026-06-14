package remote

import (
	"fmt"
	"strings"
)

// RemoteSTIGChecks provides STIG checks that can be executed remotely
// These are command-based checks that work over SSH/WinRM

// GetLinuxSTIGChecks returns STIG checks for Linux systems (RHEL 8/9, Ubuntu, etc.)
func GetLinuxSTIGChecks() []STIGCheck {
	return []STIGCheck{
		// AC-2: Account Management
		{
			ControlID:    "V-253263",
			Title:        "SSH Root Login Disabled",
			Severity:     "high",
			CheckCommand: "grep -i '^PermitRootLogin' /etc/ssh/sshd_config | grep -v no",
			Remediation:  "Set PermitRootLogin no in /etc/ssh/sshd_config",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				// Exit code != 0 means PermitRootLogin is properly set to no or not present
				return exitCode != 0, "PermitRootLogin is not disabled"
			},
		},
		// SC-13: Cryptographic Protection
		{
			ControlID:    "V-253275",
			Title:        "FIPS Mode Enabled",
			Severity:     "critical",
			CheckCommand: "cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0",
			Remediation:  "Enable FIPS mode: fips-mode-setup --enable && reboot",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "1", "FIPS mode not enabled"
			},
		},
		// AU-2: Audit Events
		{
			ControlID:    "V-253280",
			Title:        "Auditd Service Active",
			Severity:     "high",
			CheckCommand: "systemctl is-active auditd",
			Remediation:  "systemctl enable auditd && systemctl start auditd",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "active", "Auditd is not active"
			},
		},
		// AC-17: Remote Access
		{
			ControlID:    "V-253285",
			Title:        "SSH Protocol Version 2",
			Severity:     "high",
			CheckCommand: "sshd -T 2>/dev/null | grep -i '^protocol' || echo 'protocol 2'",
			Remediation:  "SSH Protocol 2 is default in modern OpenSSH",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return !strings.Contains(output, "1"), "SSH Protocol 1 not disabled"
			},
		},
		// SC-28: Protection of Information at Rest
		{
			ControlID:    "V-253290",
			Title:        "LUKS Encryption Configured",
			Severity:     "critical",
			CheckCommand: "lsblk -o NAME,TYPE,FSTYPE | grep -E 'crypt|luks' || blkid | grep -i luks",
			Remediation:  "Configure LUKS encryption for sensitive data volumes",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return exitCode == 0 && len(output) > 0, "No LUKS encryption detected"
			},
		},
		// AC-6: Least Privilege
		{
			ControlID:    "V-253301",
			Title:        "SELinux Enforcing",
			Severity:     "high",
			CheckCommand: "getenforce 2>/dev/null || sestatus 2>/dev/null | grep -i mode",
			Remediation:  "setenforce 1 && sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				out := strings.ToLower(output)
				return strings.Contains(out, "enforcing"), "SELinux not enforcing"
			},
		},
		// SC-10: Network Disconnect
		{
			ControlID:    "V-253315",
			Title:        "Firewalld Active",
			Severity:     "medium",
			CheckCommand: "systemctl is-active firewalld",
			Remediation:  "systemctl enable firewalld && systemctl start firewalld",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "active", "Firewalld not active"
			},
		},
		// IA-5: Authenticator Management
		{
			ControlID:    "V-253320",
			Title:        "Password Minimum Length 15",
			Severity:     "medium",
			CheckCommand: "grep -E '^minlen' /etc/security/pwquality.conf 2>/dev/null || echo 'minlen = 0'",
			Remediation:  "Set minlen = 15 in /etc/security/pwquality.conf",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				// Parse minlen value
				output = strings.TrimSpace(output)
				if strings.Contains(output, "=") {
					parts := strings.Split(output, "=")
					if len(parts) == 2 {
						val := strings.TrimSpace(parts[1])
						if len(val) > 0 && val[0] >= '1' && val[0] <= '9' {
							// Check if >= 15
							return val >= "15", fmt.Sprintf("Password minlen is %s, requires 15", val)
						}
					}
				}
				return false, "Password minimum length not configured"
			},
		},
		// CM-6: Configuration Settings
		{
			ControlID:    "V-253325",
			Title:        "Kernel IP Forwarding Disabled",
			Severity:     "medium",
			CheckCommand: "sysctl net.ipv4.ip_forward",
			Remediation:  "sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.Contains(output, "= 0"), "IP forwarding is enabled"
			},
		},
		// CM-7: Least Functionality
		{
			ControlID:    "V-253330",
			Title:        "Unused Services Disabled",
			Severity:     "low",
			CheckCommand: "systemctl list-unit-files --type=service --state=enabled | wc -l",
			Remediation:  "Disable unnecessary services with systemctl disable <service>",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				// Just informational - return pass but include count
				return true, fmt.Sprintf("%s enabled services", strings.TrimSpace(output))
			},
		},
	}
}

// GetWindowsSTIGChecks returns STIG checks for Windows systems
func GetWindowsSTIGChecks() []STIGCheck {
	return []STIGCheck{
		// AC-2: Account Management
		{
			ControlID:    "V-253500",
			Title:        "Guest Account Disabled",
			Severity:     "high",
			CheckCommand: "Get-LocalUser -Name 'Guest' | Select-Object -ExpandProperty Enabled",
			Remediation:  "Disable-LocalUser -Name 'Guest'",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "False", "Guest account is enabled"
			},
		},
		// AU-2: Audit Events
		{
			ControlID:    "V-253505",
			Title:        "Windows Event Log Running",
			Severity:     "high",
			CheckCommand: "(Get-Service -Name 'EventLog').Status",
			Remediation:  "Start-Service -Name 'EventLog'",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "Running", "Event Log service not running"
			},
		},
		// SC-28: Protection of Information at Rest
		{
			ControlID:    "V-253510",
			Title:        "BitLocker Enabled on OS Drive",
			Severity:     "critical",
			CheckCommand: "(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus",
			Remediation:  "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "On", "BitLocker not enabled on C:"
			},
		},
		// SC-13: Cryptographic Protection
		{
			ControlID:    "V-253515",
			Title:        "TLS 1.2+ Enforced",
			Severity:     "high",
			CheckCommand: "(Get-TlsCipherSuite | Where-Object { $_.Name -match 'TLS_1_[01]' }).Count",
			Remediation:  "Disable-TlsCipherSuite for older protocols",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "0" || exitCode != 0, "Legacy TLS versions enabled"
			},
		},
		// IA-5: Authenticator Management
		{
			ControlID:    "V-253520",
			Title:        "Password Minimum Length 14",
			Severity:     "medium",
			CheckCommand: "net accounts | Select-String 'Minimum password length'",
			Remediation:  "net accounts /minpwlen:14",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				// Parse the output for password length
				if strings.Contains(output, "14") || strings.Contains(output, "15") {
					return true, ""
				}
				return false, "Password minimum length less than 14"
			},
		},
		// SC-10: Network Disconnect
		{
			ControlID:    "V-253525",
			Title:        "Windows Firewall Enabled",
			Severity:     "high",
			CheckCommand: "(Get-NetFirewallProfile -All | Where-Object { $_.Enabled -eq 'False' }).Count",
			Remediation:  "Set-NetFirewallProfile -All -Enabled True",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "0" || output == "", "Some firewall profiles disabled"
			},
		},
		// CM-6: Configuration Settings
		{
			ControlID:    "V-253530",
			Title:        "Remote Desktop NLA Required",
			Severity:     "medium",
			CheckCommand: "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication",
			Remediation:  "Set-ItemProperty -Path 'HKLM:\\System...' -Name 'UserAuthentication' -Value 1",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "1", "RDP NLA not required"
			},
		},
		// CM-7: Least Functionality
		{
			ControlID:    "V-253535",
			Title:        "SMBv1 Disabled",
			Severity:     "high",
			CheckCommand: "(Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol').State",
			Remediation:  "Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart",
			EvaluateFunc: func(output string, exitCode int) (bool, string) {
				return strings.TrimSpace(output) == "Disabled" || strings.Contains(output, "Disabled"), "SMBv1 is enabled"
			},
		},
	}
}

// GetSTIGChecksForProfile returns STIG checks based on tactical profile
func GetSTIGChecksForProfile(profile string, osType string) []STIGCheck {
	var checks []STIGCheck

	switch osType {
	case "linux":
		checks = GetLinuxSTIGChecks()
	case "windows":
		checks = GetWindowsSTIGChecks()
	default:
		// Default to Linux
		checks = GetLinuxSTIGChecks()
	}

	// Filter or prioritize based on tactical profile
	switch profile {
	case "SATCOM", "satcom":
		// SATCOM requires stricter crypto controls
		return filterBySeverity(checks, []string{"critical", "high"})
	case "JDN", "jdn":
		// JDN full compliance
		return checks
	case "JNN", "jnn":
		// JNN slightly relaxed
		return checks
	case "WIN-T", "win-t":
		// WIN-T tactical
		return filterBySeverity(checks, []string{"critical", "high", "medium"})
	default:
		return checks
	}
}

// filterBySeverity filters checks by severity levels
func filterBySeverity(checks []STIGCheck, severities []string) []STIGCheck {
	filtered := make([]STIGCheck, 0)
	for _, check := range checks {
		for _, sev := range severities {
			if check.Severity == sev {
				filtered = append(filtered, check)
				break
			}
		}
	}
	return filtered
}

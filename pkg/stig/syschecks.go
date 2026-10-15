package stig

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SystemChecker provides real system validation checks
type SystemChecker struct{}

// NewSystemChecker creates a new system checker
func NewSystemChecker() *SystemChecker {
	return &SystemChecker{}
}

// CheckFileExists checks if a file exists
func (s *SystemChecker) CheckFileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// CheckFileContains checks if a file contains a specific string
func (s *SystemChecker) CheckFileContains(path, needle string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), needle) {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// CheckFilePermissions checks file/directory permissions
func (s *SystemChecker) CheckFilePermissions(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Mode().Perm(), nil
}

// CheckFileOwnership checks file/directory ownership (Unix only)
func (s *SystemChecker) CheckFileOwnership(path string) (uid, gid int, err error) {
	// File ownership (UID/GID) requires syscall.Stat_t which is Linux-only.
	// This function is intentionally a no-op on Windows to keep cross-platform builds clean.
	// Add a Linux build-tag variant using os.Stat + syscall.Stat_t if per-OS coverage is needed.
	return 0, 0, fmt.Errorf("ownership validation requires a Linux build (syscall.Stat_t unavailable on %s)", runtime.GOOS)
}

// CheckPackageInstalled checks if an RPM/DEB package is installed.
// Returns false (not an error) on Windows where these tools don't exist.
func (s *SystemChecker) CheckPackageInstalled(packageName string) (bool, string, error) {
	if runtime.GOOS == "windows" {
		return false, "not applicable on Windows", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try RPM first (RHEL/CentOS/Fedora)
	cmd := exec.CommandContext(ctx, "rpm", "-q", packageName)
	output, err := cmd.Output()
	if err == nil {
		return true, strings.TrimSpace(string(output)), nil
	}

	// Try dpkg (Debian/Ubuntu)
	cmd = exec.CommandContext(ctx, "dpkg", "-l", packageName)
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ii") && strings.Contains(line, packageName) {
				return true, strings.TrimSpace(line), nil
			}
		}
	}

	return false, "not installed", nil
}

// CheckServiceEnabled checks if a systemd service is enabled.
// Returns false (not an error) on Windows where systemctl does not exist.
func (s *SystemChecker) CheckServiceEnabled(serviceName string) (bool, error) {
	if runtime.GOOS == "windows" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-enabled", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false, nil // Not enabled
	}
	return strings.TrimSpace(string(output)) == "enabled", nil
}

// CheckServiceActive checks if a systemd service is active.
// Returns false (not an error) on Windows where systemctl does not exist.
func (s *SystemChecker) CheckServiceActive(serviceName string) (bool, error) {
	if runtime.GOOS == "windows" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false, nil // Not active
	}
	return strings.TrimSpace(string(output)) == "active", nil
}

// CheckSELinuxMode checks SELinux mode (enforcing, permissive, disabled).
// Returns "disabled" on Windows where SELinux does not apply.
func (s *SystemChecker) CheckSELinuxMode() (string, error) {
	if runtime.GOOS == "windows" {
		return "disabled", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "getenforce")
	output, err := cmd.Output()
	if err == nil {
		return strings.ToLower(strings.TrimSpace(string(output))), nil
	}

	// Try reading /sys/fs/selinux/enforce
	content, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return "disabled", nil // SELinux not available
	}
	if strings.TrimSpace(string(content)) == "1" {
		return "enforcing", nil
	}
	return "permissive", nil
}

// CheckFIPSMode checks if FIPS mode is enabled
func (s *SystemChecker) CheckFIPSMode() (bool, error) {
	// Check /proc/sys/crypto/fips_enabled
	content, err := os.ReadFile("/proc/sys/crypto/fips_enabled")
	if err != nil {
		return false, nil // FIPS not available
	}

	enabled := strings.TrimSpace(string(content))
	return enabled == "1", nil
}

// CheckSysctlValue reads a sysctl parameter value.
// Returns an error on Windows where sysctl does not exist.
func (s *SystemChecker) CheckSysctlValue(param string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("sysctl not available on Windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sysctl", "-n", param).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// CheckKernelParameter checks if a kernel parameter is set
func (s *SystemChecker) CheckKernelParameter(param, expectedValue string) (bool, string, error) {
	// Check /proc/cmdline
	content, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false, "", err
	}

	cmdline := string(content)
	params := strings.Fields(cmdline)

	for _, p := range params {
		if strings.HasPrefix(p, param+"=") {
			value := strings.TrimPrefix(p, param+"=")
			return value == expectedValue, value, nil
		} else if p == param {
			// Parameter present without value
			return expectedValue == "", "", nil
		}
	}

	return false, "", nil
}

// CheckAuditdActive checks if auditd is running
func (s *SystemChecker) CheckAuditdActive() (bool, error) {
	return s.CheckServiceActive("auditd")
}

// CheckFirewalldActive checks if firewalld is running
func (s *SystemChecker) CheckFirewalldActive() (bool, error) {
	return s.CheckServiceActive("firewalld")
}

// CheckPasswordPolicy checks PAM password policy settings
func (s *SystemChecker) CheckPasswordPolicy() (map[string]string, error) {
	policy := make(map[string]string)

	// Check /etc/security/pwquality.conf
	if exists, _ := s.CheckFileExists("/etc/security/pwquality.conf"); exists {
		file, err := os.Open("/etc/security/pwquality.conf")
		if err != nil {
			return nil, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 3 && parts[1] == "=" {
				policy[parts[0]] = parts[2]
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	return policy, nil
}

// GetOSVersion gets operating system version.
func (s *SystemChecker) GetOSVersion() (string, error) {
	if runtime.GOOS == "windows" {
		// Use reg.exe to read the Windows version string — no subprocess hang risk.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "reg", "query",
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "ProductName").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "ProductName") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						return strings.Join(fields[2:], " "), nil
					}
				}
			}
		}
		return "Windows (version unknown)", nil
	}

	// Try /etc/os-release first (most modern Linux systems)
	if exists, _ := s.CheckFileExists("/etc/os-release"); exists {
		file, err := os.Open("/etc/os-release")
		if err != nil {
			return "", err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				name := strings.TrimPrefix(line, "PRETTY_NAME=")
				name = strings.Trim(name, "\"")
				return name, nil
			}
		}
		if err := scanner.Err(); err != nil {
			return "", err
		}
	}

	// Fallback to uname (Linux/macOS only — never called on Windows)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "uname", "-a").Output()
	if err != nil {
		return "Unknown", nil
	}
	return strings.TrimSpace(string(output)), nil
}

// GetKernelVersion gets kernel version.
// On Windows returns the NT version string via registry; on Linux uses uname.
func (s *SystemChecker) GetKernelVersion() (string, error) {
	if runtime.GOOS == "windows" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "reg", "query",
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "CurrentBuildNumber").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "CurrentBuildNumber") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						return "NT build " + fields[len(fields)-1], nil
					}
				}
			}
		}
		return "Windows (build unknown)", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "uname", "-r").Output()
	if err != nil {
		return "Unknown", nil
	}
	return strings.TrimSpace(string(output)), nil
}

// CheckSSHConfig checks SSH server configuration
func (s *SystemChecker) CheckSSHConfig(param string) (string, error) {
	sshConfigPath := "/etc/ssh/sshd_config"

	file, err := os.Open(sshConfigPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue // Skip comments
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], param) {
			return strings.Join(fields[1:], " "), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("parameter not found: %s", param)
}

// CheckUserAccounts lists all user accounts
func (s *SystemChecker) CheckUserAccounts() ([]string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	users := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			username := fields[0]
			uidStr := fields[2]

			// Parse UID
			uid, err := strconv.Atoi(uidStr)
			if err != nil {
				continue
			}

			// Only include human users (UID >= 1000) and root (UID = 0)
			if uid >= 1000 || uid == 0 {
				users = append(users, username)
			}
		}
	}

	return users, scanner.Err()
}

// CheckCryptoModules checks loaded crypto kernel modules
func (s *SystemChecker) CheckCryptoModules() ([]string, error) {
	file, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cryptoModules := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 {
			moduleName := fields[0]
			// Check for crypto-related modules
			if strings.Contains(moduleName, "crypto") ||
				strings.Contains(moduleName, "aes") ||
				strings.Contains(moduleName, "sha") ||
				strings.Contains(moduleName, "rsa") {
				cryptoModules = append(cryptoModules, moduleName)
			}
		}
	}

	return cryptoModules, scanner.Err()
}

// CheckListeningPorts checks for listening network ports.
// On Windows, uses netstat (ss is not available); on Linux prefers ss with netstat fallback.
func (s *SystemChecker) CheckListeningPorts() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var output []byte
	var err error
	if runtime.GOOS == "windows" {
		output, err = exec.CommandContext(ctx, "netstat", "-ano").Output()
	} else {
		output, err = exec.CommandContext(ctx, "ss", "-lntu").Output()
		if err != nil {
			output, err = exec.CommandContext(ctx, "netstat", "-lntu").Output()
		}
	}
	if err != nil {
		return nil, err
	}

	ports := []string{}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "LISTEN") || strings.Contains(line, "LISTENING") {
			ports = append(ports, line)
		}
	}
	return ports, nil
}

// ── Windows-specific primitives ───────────────────────────────────────────────

// CheckRegistryValue reads a Windows registry value using reg.exe (native) or
// PowerShell as fallback.  hive is the registry hive abbreviation (HKLM, HKCU,
// HKEY_LOCAL_MACHINE, etc.), keyPath is the subkey path, valueName is the
// value name to query.  Returns the string representation of the value.
//
// Only meaningful on Windows (runtime.GOOS == "windows"); returns an error on
// other platforms.
func (s *SystemChecker) CheckRegistryValue(hive, keyPath, valueName string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("registry checks require Windows (current OS: %s)", runtime.GOOS)
	}

	// Normalise hive abbreviations to full names for reg.exe
	hiveMap := map[string]string{
		"HKLM": "HKEY_LOCAL_MACHINE",
		"HKCU": "HKEY_CURRENT_USER",
		"HKCR": "HKEY_CLASSES_ROOT",
		"HKU":  "HKEY_USERS",
		"HKCC": "HKEY_CURRENT_CONFIG",
	}
	if full, ok := hiveMap[strings.ToUpper(hive)]; ok {
		hive = full
	}

	fullKey := hive + `\` + keyPath

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "reg", "query", fullKey, "/v", valueName).Output()
	if err != nil {
		return "", fmt.Errorf("reg query %s /v %s: %w", fullKey, valueName, err)
	}

	// Parse reg.exe output:
	//   HKEY_LOCAL_MACHINE\...\key
	//       ValueName    REG_DWORD    0x1
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(valueName)) {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[len(fields)-1], nil
			}
		}
	}

	return "", fmt.Errorf("value %s not found in %s", valueName, fullKey)
}

// CheckAuditPolicy queries Windows audit policy for a specific subcategory via
// auditpol.exe and returns the configured setting ("Success and Failure",
// "Success", "Failure", "No Auditing").
func (s *SystemChecker) CheckAuditPolicy(subcategory string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("audit policy checks require Windows (current OS: %s)", runtime.GOOS)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "auditpol", "/get", "/subcategory:"+subcategory).Output()
	if err != nil {
		return "", fmt.Errorf("auditpol /get /subcategory:%s: %w", subcategory, err)
	}

	// auditpol output format:
	//   System audit policy
	//   Category/Subcategory                      Setting
	//     Logon/Logoff                            -
	//       Logon                                  Success and Failure
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "System audit") || strings.HasPrefix(trimmed, "Category") {
			continue
		}
		// The setting is at the end after the subcategory name.
		// Example: "  Logon                                  Success and Failure"
		idx := strings.LastIndexAny(trimmed, "  ")
		if idx > 0 {
			possible := strings.TrimSpace(trimmed[idx:])
			if possible == "Success and Failure" || possible == "Success" ||
				possible == "Failure" || possible == "No Auditing" {
				return possible, nil
			}
		}
	}

	return "", fmt.Errorf("could not parse auditpol output for subcategory: %s", subcategory)
}

// CheckWindowsFeature checks whether a Windows optional feature is enabled.
// Returns true if the feature is present and enabled.
func (s *SystemChecker) CheckWindowsFeature(featureName string) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("Windows feature checks require Windows (current OS: %s)", runtime.GOOS)
	}

	script := fmt.Sprintf(
		"(Get-WindowsOptionalFeature -Online -FeatureName '%s').State",
		featureName,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return false, fmt.Errorf("Get-WindowsOptionalFeature %s: %w", featureName, err)
	}
	return strings.TrimSpace(string(out)) == "Enabled", nil
}

// CheckBitLocker returns the BitLocker protection status string for the given
// drive letter (e.g. "C:").  Typical return values: "Protection On",
// "Protection Off", "Protection Unknown".
func (s *SystemChecker) CheckBitLocker(drive string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("BitLocker checks require Windows (current OS: %s)", runtime.GOOS)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "manage-bde", "-status", drive).Output()
	if err != nil {
		return "", fmt.Errorf("manage-bde -status %s: %w", drive, err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Protection Status:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", fmt.Errorf("BitLocker status not found for drive %s", drive)
}

// CheckWindowsDefender returns the Windows Defender real-time protection state
// via PowerShell Get-MpPreference.
func (s *SystemChecker) CheckWindowsDefender() (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("Windows Defender check requires Windows (current OS: %s)", runtime.GOOS)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive",
		"-Command", "(Get-MpPreference).DisableRealtimeMonitoring").Output()
	if err != nil {
		return false, fmt.Errorf("Get-MpPreference: %w", err)
	}

	// "False" means Defender IS enabled (NOT disabled)
	val := strings.TrimSpace(string(out))
	return strings.EqualFold(val, "False"), nil
}

// CheckWindowsRegistryDWORD is a convenience wrapper that reads a REG_DWORD
// value and converts it to an integer.  Returns -1 on parse failure.
func (s *SystemChecker) CheckWindowsRegistryDWORD(hive, keyPath, valueName string) (int64, error) {
	raw, err := s.CheckRegistryValue(hive, keyPath, valueName)
	if err != nil {
		return -1, err
	}
	// reg.exe returns DWORD in hex: 0x1, 0x0, etc.
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		v, err := strconv.ParseInt(raw[2:], 16, 64)
		return v, err
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	return v, err
}

// CheckSMBSigning verifies that SMB signing is required on the local machine
// via the registry.
func (s *SystemChecker) CheckSMBSigning() (bool, error) {
	if runtime.GOOS != "windows" {
		return false, fmt.Errorf("SMB signing check requires Windows (current OS: %s)", runtime.GOOS)
	}

	// RequireSecuritySignature=1 means signing is mandatory for SMB server.
	v, err := s.CheckWindowsRegistryDWORD(
		"HKLM",
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`,
		"RequireSecuritySignature",
	)
	if err != nil {
		return false, err
	}
	return v == 1, nil
}

// CheckNTLMMinVersion returns the LmCompatibilityLevel registry value which
// controls NTLM authentication version.  Value of 5 means NTLMv2 only.
func (s *SystemChecker) CheckNTLMMinVersion() (int64, error) {
	if runtime.GOOS != "windows" {
		return -1, fmt.Errorf("NTLM check requires Windows (current OS: %s)", runtime.GOOS)
	}

	return s.CheckWindowsRegistryDWORD(
		"HKLM",
		`SYSTEM\CurrentControlSet\Control\Lsa`,
		"LmCompatibilityLevel",
	)
}

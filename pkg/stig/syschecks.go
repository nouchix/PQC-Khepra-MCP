package stig

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
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

// CheckPackageInstalled checks if an RPM/DEB package is installed
func (s *SystemChecker) CheckPackageInstalled(packageName string) (bool, string, error) {
	// Try RPM first (RHEL/CentOS/Fedora)
	cmd := exec.Command("rpm", "-q", packageName)
	output, err := cmd.Output()
	if err == nil {
		return true, strings.TrimSpace(string(output)), nil
	}

	// Try dpkg (Debian/Ubuntu)
	cmd = exec.Command("dpkg", "-l", packageName)
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

// CheckServiceEnabled checks if a systemd service is enabled
func (s *SystemChecker) CheckServiceEnabled(serviceName string) (bool, error) {
	cmd := exec.Command("systemctl", "is-enabled", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false, nil // Not enabled
	}

	status := strings.TrimSpace(string(output))
	return status == "enabled", nil
}

// CheckServiceActive checks if a systemd service is active
func (s *SystemChecker) CheckServiceActive(serviceName string) (bool, error) {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false, nil // Not active
	}

	status := strings.TrimSpace(string(output))
	return status == "active", nil
}

// CheckSELinuxMode checks SELinux mode (enforcing, permissive, disabled)
func (s *SystemChecker) CheckSELinuxMode() (string, error) {
	// Try getenforce command
	cmd := exec.Command("getenforce")
	output, err := cmd.Output()
	if err == nil {
		return strings.ToLower(strings.TrimSpace(string(output))), nil
	}

	// Try reading /sys/fs/selinux/enforce
	content, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return "disabled", nil // SELinux not available
	}

	enforce := strings.TrimSpace(string(content))
	if enforce == "1" {
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

// CheckSysctlValue reads a sysctl parameter value
func (s *SystemChecker) CheckSysctlValue(param string) (string, error) {
	cmd := exec.Command("sysctl", "-n", param)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
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

// GetOSVersion gets operating system version
func (s *SystemChecker) GetOSVersion() (string, error) {
	// Try /etc/os-release first (most modern systems)
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

	// Fallback to uname
	cmd := exec.Command("uname", "-a")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown", nil
	}

	return strings.TrimSpace(string(output)), nil
}

// GetKernelVersion gets kernel version
func (s *SystemChecker) GetKernelVersion() (string, error) {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
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

// CheckListeningPorts checks for listening network ports
func (s *SystemChecker) CheckListeningPorts() ([]string, error) {
	cmd := exec.Command("ss", "-lntu")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		cmd = exec.Command("netstat", "-lntu")
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}

	ports := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "LISTEN") {
			ports = append(ports, line)
		}
	}

	return ports, nil
}

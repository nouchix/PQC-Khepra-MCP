package stig

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ExecutionLink defines the interface for running commands across the DEMARC
type ExecutionLink interface {
	Execute(command string, args []string) (string, error)
	GetContext() string // "local", "agent:<machine_id>"
}

// LocalLink implements direct execution on the current machine
type LocalLink struct{}

func (l *LocalLink) Execute(command string, args []string) (string, error) {
	cmd := exec.Command(command, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (l *LocalLink) GetContext() string { return "local" }

// DEMARCLink implements command execution via the Khepra Secure Gateway (DEMARC)
type DEMARCLink struct {
	MachineID string
	Manager   interface {
		ExecuteOnAgent(machineID string, command string, args []string) (string, error)
	}
}

func (d *DEMARCLink) Execute(command string, args []string) (string, error) {
	return d.Manager.ExecuteOnAgent(d.MachineID, command, args)
}

func (d *DEMARCLink) GetContext() string { return "agent:" + d.MachineID }

// Remediator orchestrates automated security fixes with Failsafe protection
type Remediator struct {
	checker *SystemChecker
	link    ExecutionLink
	backups string
}

// NewRemediator creates a new remediator instance
func NewRemediator(checker *SystemChecker) *Remediator {
	backupPath := "/var/khepra/backups"
	if os.Getenv("OS") == "Windows_NT" {
		backupPath = filepath.Join(os.Getenv("APPDATA"), "khepra", "backups")
	}
	os.MkdirAll(backupPath, 0700)

	return &Remediator{
		checker: checker,
		link:    &LocalLink{}, // Default to local, can be swapped for DEMARCLink
		backups: backupPath,
	}
}

// SetLink swaps the execution link (e.g. to a remote Agent via DEMARC)
func (r *Remediator) SetLink(link ExecutionLink) {
	r.link = link
}

// Remediate executes the remediation for a specific finding
func (r *Remediator) Remediate(findingID string) (*RemediationResult, error) {
	result := &RemediationResult{
		FindingID:    findingID,
		RemediatedAt: time.Now(),
		Status:       "Failed",
	}

	// Dispatch to control-specific remediation logic
	switch findingID {
	case "SV-257778r925321_rule": // SCAP Security Guide
		return r.RemediatePackageInstall("scap-security-guide")
	case "SV-257779r925324_rule": // Firewalld
		return r.RemediateFirewalld()
	case "SV-258090r926289_rule": // FIPS Mode
		return r.RemediateFIPSMode()
	case "SV-257860r925564_rule": // Auditd
		return r.RemediateServiceEnable("auditd")
	case "SV-257872r925600_rule": // SSH PermitRootLogin
		return r.RemediateSSHConfig("PermitRootLogin", "no")
	default:
		result.Status = "Requires Manual Intervention"
		result.Output = fmt.Sprintf("No automated remediation script available for %s", findingID)
		return result, nil
	}
}

// RemediatePackageInstall installs a missing package
func (r *Remediator) RemediatePackageInstall(packageName string) (*RemediationResult, error) {
	res := &RemediationResult{FindingID: packageName, Command: "dnf install -y " + packageName, RemediatedAt: time.Now()}

	out, err := r.link.Execute("sudo", []string{"dnf", "install", "-y", packageName})
	res.Output = out

	if err != nil {
		res.Status = "Failed"
		return res, fmt.Errorf("failed to install package %s: %w", packageName, err)
	}

	res.Status = "Success"
	return res, nil
}

// RemediateServiceEnable enables and starts a systemd service
func (r *Remediator) RemediateServiceEnable(serviceName string) (*RemediationResult, error) {
	res := &RemediationResult{FindingID: serviceName, Command: "systemctl enable --now " + serviceName, RemediatedAt: time.Now()}

	out, err := r.link.Execute("sudo", []string{"systemctl", "enable", "--now", serviceName})
	res.Output = out

	if err != nil {
		res.Status = "Failed"
		return res, fmt.Errorf("failed to enable service %s: %w", serviceName, err)
	}

	res.Status = "Success"
	return res, nil
}

// RemediateFirewalld handles firewalld specific fix
func (r *Remediator) RemediateFirewalld() (*RemediationResult, error) {
	// First ensure it is installed
	installRes, err := r.RemediatePackageInstall("firewalld")
	if err != nil {
		return installRes, err
	}

	// Then enable it
	return r.RemediateServiceEnable("firewalld")
}

// RemediateFIPSMode enables FIPS mode
func (r *Remediator) RemediateFIPSMode() (*RemediationResult, error) {
	res := &RemediationResult{FindingID: "fips", Command: "fips-mode-setup --enable", RemediatedAt: time.Now()}

	out, err := r.link.Execute("sudo", []string{"fips-mode-setup", "--enable"})
	res.Output = out

	if err != nil {
		res.Status = "Failed"
		return res, fmt.Errorf("failed to enable FIPS: %w", err)
	}

	res.Status = "Success"
	res.Output += " [REBOOT REQUIRED]"
	return res, nil
}

// RemediateSSHConfig updates sshd_config with Augean Failsafe
func (r *Remediator) RemediateSSHConfig(param, value string) (*RemediationResult, error) {
	configPath := "/etc/ssh/sshd_config"
	res := &RemediationResult{FindingID: "ssh_" + param, Command: "failsafe_update_sshd_config", RemediatedAt: time.Now()}

	// 1. Snapshot (Failsafe)
	backup, err := r.snapshotFile(configPath)
	if err != nil {
		res.Status = "Failed"
		res.Output = "Failsafe Error: Could not create backup before fix."
		return res, err
	}

	// 2. Perform Update
	script := fmt.Sprintf("grep -q '^%s' %s && sed -i 's/^%s.*/%s %s/' %s || echo '%s %s' >> %s",
		param, configPath, param, param, value, configPath, param, value, configPath)

	out, err := r.link.Execute("sudo", []string{"bash", "-c", script})
	res.Output = out

	if err != nil {
		res.Status = "Failed"
		// 3. Auto-Rollback if script fails
		r.rollbackFile(configPath, backup)
		return res, err
	}

	// 4. Verify & Restart
	_, err = r.link.Execute("sudo", []string{"systemctl", "reload", "sshd"})
	if err != nil {
		res.Status = "Failed"
		res.Output += " [RELOAD FAILED - ROLLING BACK]"
		r.rollbackFile(configPath, backup)
		return res, err
	}

	res.Status = "Success"
	return res, nil
}

// snapshotFile creates a timestamped backup of a configuration file
func (r *Remediator) snapshotFile(path string) (string, error) {
	if r.link.GetContext() != "local" {
		// Remote snapshots would be handled by the Agent locally
		return "remote_agent_snapshot", nil
	}

	backupName := fmt.Sprintf("%s.%d.bak", filepath.Base(path), time.Now().Unix())
	target := filepath.Join(r.backups, backupName)

	sourceFile, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(target)
	if err != nil {
		return "", err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return target, err
}

// rollbackFile restores a file from a snapshot
func (r *Remediator) rollbackFile(path, backup string) error {
	if r.link.GetContext() != "local" {
		return nil // Agent handles its own rollback
	}

	// cp is used for rollback to preserve file permissions and avoid
	// cross-device rename failures that mv can produce on remote mounts.
	cmd := exec.Command("sudo", "cp", backup, path)
	return cmd.Run()
}

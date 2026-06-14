//go:build linux || darwin

package compliance

import (
	"os"
	"strings"
)

// loadPlatformChecks injects Linux-specific STIG auditors.
func (e *Engine) loadPlatformChecks() {

	// STIG: SSH Root Login Disabled
	e.Checks = append(e.Checks, NativeCheck{
		ID:          "nix_ssh_root",
		STIGID:      "RHEL-08-010550",
		Title:       "Disable SSH Root Login",
		Description: "Verify PermitRootLogin is no in sshd_config",
		OS:          "linux",
		Run: func() (CheckStatus, string, error) {
			content, err := os.ReadFile("/etc/ssh/sshd_config")
			if err != nil {
				return StatusError, "Could not check sshd_config", err
			}

			// Simple parser (robust implementation would parse valid lines)
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "PermitRootLogin") {
					parts := strings.Fields(line)
					if len(parts) >= 2 && parts[1] == "no" {
						return StatusPass, "PermitRootLogin no found", nil
					}
					if len(parts) >= 2 && parts[1] == "yes" {
						return StatusFail, "PermitRootLogin is set to YES", nil
					}
				}
			}
			// Default logic if not found? OpenSSH defaults usually 'prohibit-password' or 'no' in modern.
			// Conservatively fail or warn
			return StatusFail, "Configuration not explicitly set", nil
		},
	})
}

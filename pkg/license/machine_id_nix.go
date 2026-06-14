//go:build !windows

package license

import (
	"os"
	"strings"
)

// getMachineUUID retrieves system-level machine UUID
func getMachineUUID() string {
	// Linux: /etc/machine-id or /var/lib/dbus/machine-id
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		return strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		return strings.TrimSpace(string(data))
	}

	// Fallback to hostname
	hostname, _ := os.Hostname()
	return "fallback-" + hostname
}

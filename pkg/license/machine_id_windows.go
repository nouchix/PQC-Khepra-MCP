//go:build windows

package license

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

// getMachineUUID retrieves system-level machine UUID
func getMachineUUID() string {
	// Windows: MachineGuid from registry
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		guid, _, err := k.GetStringValue("MachineGuid")
		if err == nil {
			return guid
		}
	}

	// Fallback to hostname
	hostname, _ := os.Hostname()
	return "fallback-" + hostname
}

package license

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// GenerateMachineID creates a stable identifier based on hardware
// This binds licenses to specific machines/VMs
func GenerateMachineID() string {
	var components []string

	// Component 1: Hostname
	hostname, _ := os.Hostname()
	components = append(components, hostname)

	// Component 2: Primary MAC address
	mac := getPrimaryMAC()
	components = append(components, mac)

	// Component 3: Platform (os/arch)
	platform := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	components = append(components, platform)

	// Component 4: Machine UUID (from /etc/machine-id or registry)
	machineUUID := getMachineUUID()
	components = append(components, machineUUID)

	// Hash all components with salt
	salt := "khepra-license-v1-2026"
	data := strings.Join(components, ":") + ":" + salt
	hash := sha256.Sum256([]byte(data))

	return "khepra-" + hex.EncodeToString(hash[:16])
}

// getPrimaryMAC gets first non-loopback MAC address
func getPrimaryMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		if len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr.String()
		}
	}

	return "unknown"
}

package audit

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/scanner"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/types"
)

const Localhost = "127.0.0.1"

// NewSnapshot captures the current system state for baseline or audit purposes.
func NewSnapshot() (*types.AuditSnapshot, error) {
	// 1. Host Info
	hostname, _ := os.Hostname()

	host := types.InfoHost{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		PublicIP: fetchPublicIP(),
	}

	// 2. Network Ports
	// Use the native scanner we built in Phase 2
	s := scanner.New()
	s.Concurrency = 500 // Be gentle on localhost
	results, err := s.Run(Localhost)

	var netPorts []types.NetworkPort
	if err == nil {
		for _, r := range results {
			if r.Status == "OPEN" {
				netPorts = append(netPorts, types.NetworkPort{
					Port:     r.Port,
					Protocol: "tcp",
					State:    "LISTENING",
					BindAddr: "0.0.0.0",
				})
			}
		}
	} else {
		// Log error but continue?
		// For MVP we just return empty list if scan fails
		fmt.Printf("[WARN] Port scan failed: %v\n", err)
	}

	// 3. Processes — collect live process list via os/exec (best-effort).
	procs := collectProcesses()

	// 4. File manifests — hash the running executable for integrity attestation.
	exePath, _ := os.Executable()
	manifests := []types.FileManifest{}
	if exePath != "" {
		checksum := hashFile(exePath)
		manifests = append(manifests, types.FileManifest{Path: exePath, Type: "binary", Checksum: checksum})
	}

	snap := &types.AuditSnapshot{
		SchemaVersion: "1.0",
		ScanID:        fmt.Sprintf("snap-%d", time.Now().Unix()),
		Timestamp:     time.Now(),
		Host:          host,
		Network:       types.NetworkIntelligence{Ports: netPorts},
		System:        types.SystemIntelligence{Processes: procs},
		Manifests:     manifests,
		Tags:          []string{"agent-generated"},
	}

	// Populate backwards-compatible fields
	snap.NetworkList = netPorts
	snap.Processes = procs
	// PublicKey left empty until snapshot is sealed with PQC; kept for compatibility
	snap.PublicKey = ""

	return snap, nil
}

func fetchPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return Localhost
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return Localhost
	}
	return string(ip)
}

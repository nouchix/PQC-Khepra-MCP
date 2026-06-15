package sonar

import (
	"context"
	"log"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/scanner/network"
)

// SonarRuntime manages the lifecycle of the active scan.
//
// OSINT (Shodan/Censys) has been removed by design — no external calls,
// no telemetry, no third-party data egress. All scanning is 100% local.
type SonarRuntime struct{}

// NewOrchestrator initialises the sonar runtime.
// The secrets parameter is accepted for API compatibility but is ignored;
// OSINT keys are no longer used.
func NewOrchestrator(_ interface{}) *SonarRuntime {
	return &SonarRuntime{}
}

// ActiveScanResult holds the combined local scan intelligence.
type ActiveScanResult struct {
	Target      string
	PortResults []network.PortResult
	Error       string
}

// RunActiveScan executes a pure-local port scan against targetIP.
// No external network calls are made beyond the target itself.
func (r *SonarRuntime) RunActiveScan(targetIP string) ActiveScanResult {
	result := ActiveScanResult{Target: targetIP}
	log.Printf("[SONAR] Mission Start: Active scan engaged for %s", targetIP)

	scanner := network.NewScanner(targetIP, nil)
	result.PortResults = scanner.Scan(context.Background())
	if result.PortResults == nil {
		result.PortResults = []network.PortResult{}
	}
	log.Printf("[SONAR] Network Scan Complete. Open Ports: %d", len(result.PortResults))
	log.Println("[SONAR] Stealth Mode: OSINT permanently disabled (privacy policy).")

	return result
}

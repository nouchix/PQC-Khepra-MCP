package intel

import (
	"fmt"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/attest"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/audit"
)

// GenerateRiskAttestation transforms a raw AuditSnapshot into a causal risk report.
func GenerateRiskAttestation(snapshot *audit.AuditSnapshot) *attest.RiskAttestation {
	attestation := &attest.RiskAttestation{
		Target:     snapshot.Host.Hostname, // Or PublicIP
		SnapshotID: snapshot.ScanID,
		Timestamp:  time.Now().UTC(),
		Findings:   []attest.RiskFinding{},
	}

	totalScore := 100

	// Rule 1: Open Ports Analysis
	for _, port := range snapshot.Network.Ports {
		if port.State == "open" {
			finding := attest.RiskFinding{
				ID:       fmt.Sprintf("NET-OPEN-%d", port.Port),
				Title:    fmt.Sprintf("Open Port Detected: %d/%s", port.Port, port.Protocol),
				Severity: "MEDIUM",
				Evidence: []string{
					fmt.Sprintf("Port %d is accepting connections.", port.Port),
					fmt.Sprintf("Service Banner: %s", port.BindAddr),
				},
				Remediation: "Verify business need for this port. firewall it if unnecessary.",
			}

			// Contextual Risk Elevation
			if port.Port == 22 || port.Port == 3389 {
				finding.Severity = "HIGH"
				finding.Evidence = append(finding.Evidence, "Administrative interface exposed to internet.")
				totalScore -= 10
			} else {
				totalScore -= 2
			}
			attestation.Findings = append(attestation.Findings, finding)
		}
	}

	// Rule 2: Shodan Intelligence Correlation
	if snapshot.Intelligence.Shodan != nil {
		if len(snapshot.Intelligence.Shodan.Vulns) > 0 {
			finding := attest.RiskFinding{
				ID:       "INTEL-SHODAN-VULN",
				Title:    "Known Vulnerabilities (Shodan)",
				Severity: "CRITICAL",
				Evidence: []string{
					fmt.Sprintf("Shodan reports %d CVEs associated with this IP.", len(snapshot.Intelligence.Shodan.Vulns)),
					fmt.Sprintf("ISP: %s", snapshot.Intelligence.Shodan.ISP),
				},
				Remediation: "Immediate patching required. IP is flagged by global sensors.",
			}
			totalScore -= 30
			attestation.Findings = append(attestation.Findings, finding)
		}
	}

	// Rule 3: Censys Intelligence
	if snapshot.Intelligence.Censys != nil {
		// Just being on Censys isn't a risk, but having many services is exposure.
		if len(snapshot.Intelligence.Censys.Services) > 5 {
			finding := attest.RiskFinding{
				ID:       "INTEL-CENSYS-EXPOSURE",
				Title:    "High Attack Surface (Censys)",
				Severity: "HIGH",
				Evidence: []string{
					fmt.Sprintf("Censys indexed %d exposed services.", len(snapshot.Intelligence.Censys.Services)),
				},
				Remediation: "Reduce public footprint. Use VPN/Zero Trust.",
			}
			totalScore -= 15
			attestation.Findings = append(attestation.Findings, finding)
		}
	}

	// Score Normalization
	if totalScore < 0 {
		totalScore = 0
	}
	attestation.Score = totalScore

	// Narrative: deterministic format string over risk findings.
	// LLM-driven narrative generation can be enabled by wiring pkg/llm to this engine.
	attestation.Narrative = fmt.Sprintf(
		"Diagnostic completed on %s. Found %d active risks. Risk Score: %d/100. "+
			"Critical attention needed for %d issues.",
		attestation.Timestamp.Format(time.RFC3339),
		len(attestation.Findings),
		attestation.Score,
		countSeverity(attestation.Findings, "CRITICAL"),
	)

	return attestation
}

func countSeverity(findings []attest.RiskFinding, level string) int {
	c := 0
	for _, f := range findings {
		if f.Severity == level {
			c++
		}
	}
	return c
}

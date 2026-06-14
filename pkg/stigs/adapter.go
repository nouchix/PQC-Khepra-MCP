package stigs

import "strings"

// Evidence represents a generic finding from any tool that maps to a STIG.
type Evidence struct {
	Tool        string
	ToolID      string // PluginID, RuleID, etc.
	Description string
	Location    string
	Context     map[string]string
}

// MapToSTIG returns the STIG ID and CCI associated with a given tool finding.
// This acts as the central Rosetta Stone for the Khepra Ingestion Engine.
func MapToSTIG(tool, toolID string) (stigID, cci string) {
	// Normalize
	tool = strings.ToLower(tool)

	switch tool {
	case "gitleaks", "trufflehog", "detect-secrets":
		// Secrets Management
		return "IA-5", "CCI-000162" // IA-5 (1) Authenticator Management

	case "zap":
		// DAST / Web
		return "RA-5", "CCI-001054" // RA-5 Vulnerability Scanning

	case "retirejs", "dependabot":
		// Supply Chain
		return "SA-22", "CCI-003194" // SA-22 Unsupported System Software

	case "zscan", "nmap":
		// Ports / Services
		if toolID == "port-22" {
			return "SC-000000", "CCI-001436" // OpenSSH config usually
		}
		return "CM-7", "CCI-000381" // CM-7 Least Functionality

	case "sarif":
		// SAST
		return "SA-11", "CCI-003217" // SA-11 Developer Security Testing

	default:
		return "GEN-000000", "CCI-000000"
	}
}

// StigControlNode represents a vertex in the Trust Constellation
type StigControlNode struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Verdicts []Evidence `json:"evidence"`
	Status   string     `json:"status"` // COMPLIANT, NON_COMPLIANT, OPEN
}

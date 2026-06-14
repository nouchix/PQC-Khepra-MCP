package artifacts

import (
	"fmt"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/compliance/nist80171"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/compliance/nist80172"
)

// SSPGenerator orchestrates the creation of formal compliance documents
type SSPGenerator struct {
	AppName      string
	Organization string
	Version      string
}

// SecurityPackage represents a full set of RMF artifacts
type SecurityPackage struct {
	SSP  string // System Security Plan
	POAM string // Plan of Action & Milestones
	SAR  string // Security Assessment Report
}

// GenerateSSP generates a structured SSP based on NIST 800-171 and 800-172 results
func (g *SSPGenerator) GenerateSSP(results171 []nist80171.ControlResult, results172 []nist80172.EnhancedResult) (string, error) {
	ssp := "# System Security Plan (SSP)\n"
	ssp += fmt.Sprintf("System: %s\n", g.AppName)
	ssp += fmt.Sprintf("Organization: %s\n", g.Organization)
	ssp += fmt.Sprintf("Date Generated: %s\n", time.Now().Format(time.RFC1123))
	ssp += "Compliance Baseline: NIST 800-171 Rev 2 + NIST 800-172 (Enhanced)\n\n"

	ssp += "## NIST 800-171 Control Implementation Details\n\n"

	for _, res := range results171 {
		ssp += fmt.Sprintf("### Control %s: %s\n", res.ControlID, res.Title)
		ssp += fmt.Sprintf("- **Status**: %s\n", res.Status)
		ssp += fmt.Sprintf("- **Family**: %s\n", res.Family)
		ssp += fmt.Sprintf("- **Finding**: %s\n", res.Finding)
		ssp += "\n"
	}

	if len(results172) > 0 {
		ssp += "## NIST 800-172 Enhanced Requirement Details\n\n"
		for _, res := range results172 {
			ssp += fmt.Sprintf("### Enhanced Requirement %s: %s\n", res.ControlID, res.Title)
			ssp += fmt.Sprintf("- **Status**: %s\n", res.Status)
			ssp += fmt.Sprintf("- **Family**: %s\n", res.Family)
			ssp += fmt.Sprintf("- **Finding**: %s\n", res.Finding)
			ssp += "\n"
		}
	}

	return ssp, nil
}

// GeneratePOAM identifies failed controls and creates a POA&M
func (g *SSPGenerator) GeneratePOAM(results []nist80171.ControlResult) (string, error) {
	poam := "# Plan of Action & Milestones (POA&M)\n\n"
	poam += "| Control ID | Weakness | Remediation Plan | Scheduled Completion | Status |\n"
	poam += "|------------|----------|------------------|----------------------|--------|\n"

	for _, res := range results {
		if res.Status == "FAIL" || res.Status == "MANUAL_REVIEW" {
			poam += fmt.Sprintf("| %s | %s | %s | %s | OPEN |\n",
				res.ControlID,
				res.Description,
				res.Remediation,
				time.Now().AddDate(0, 1, 0).Format("2006-01-02"), // 30 day target
			)
		}
	}

	return poam, nil
}

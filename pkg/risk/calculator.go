package risk

import (
	"fmt"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/intel"
)

// AssetCriticality represents the business impact multiplier for different asset types
type AssetCriticality int

const (
	WorkstationCriticality AssetCriticality = 1
	WebServerCriticality   AssetCriticality = 2
	AppServerCriticality   AssetCriticality = 3
	DatabaseCriticality    AssetCriticality = 5
	DomainControllerCriticality AssetCriticality = 8
)

// IBM Cost of Data Breach Report 2024: $500K per compromised endpoint baseline
// Source: https://www.ibm.com/reports/data-breach
const BreachCostPerHost = 500000.0

// FinancialRisk represents aggregated financial exposure by severity
type FinancialRisk struct {
	Severity    string
	Count       int
	ImpactUSD   float64
	CVEExamples []string // Sample CVE IDs for this severity level
}

// RiskSummary provides the complete financial risk assessment
type RiskSummary struct {
	RisksBySeverity map[string]*FinancialRisk
	TotalExposure   float64
	AssetType       string
	Methodology     string
}

// CalculateFinancialExposure computes financial risk using the formula:
//
// Financial Risk = Σ(CVSS Score × Asset Criticality × Breach Cost Per Host)
//
// Data Sources:
// - CVSS Scores: NIST National Vulnerability Database (NVD) / MITRE
// - Asset Criticality: Heuristic-based (port analysis)
// - Breach Costs: IBM Cost of Data Breach Report 2024 ($500K/host baseline)
func CalculateFinancialExposure(
	snapshot *audit.AuditSnapshot,
	kb *intel.KnowledgeBase,
) *RiskSummary {
	summary := &RiskSummary{
		RisksBySeverity: map[string]*FinancialRisk{
			"CRITICAL": {Severity: "CRITICAL", Count: 0, ImpactUSD: 0, CVEExamples: []string{}},
			"HIGH":     {Severity: "HIGH", Count: 0, ImpactUSD: 0, CVEExamples: []string{}},
			"MEDIUM":   {Severity: "MEDIUM", Count: 0, ImpactUSD: 0, CVEExamples: []string{}},
			"LOW":      {Severity: "LOW", Count: 0, ImpactUSD: 0, CVEExamples: []string{}},
		},
	}

	// Determine asset criticality based on network ports and services
	assetCrit, assetType := DetermineAssetCriticality(snapshot)
	summary.AssetType = assetType

	// Track unique CVEs to avoid double-counting
	seenCVEs := make(map[string]bool)

	// Correlate vulnerabilities from Shodan intelligence
	if snapshot.Intelligence.Shodan != nil {
		for _, cveID := range snapshot.Intelligence.Shodan.Vulns {
			if seenCVEs[cveID] {
				continue
			}
			seenCVEs[cveID] = true

			// Look up CVE in knowledge base
			vuln := kb.SearchVuln(cveID)
			if vuln == nil || vuln.CVSS == 0 {
				// CVE not in database or no CVSS score - use conservative estimate
				summary.RisksBySeverity["MEDIUM"].Count++
				summary.RisksBySeverity["MEDIUM"].ImpactUSD += (0.5 * float64(assetCrit) * BreachCostPerHost)
				continue
			}

			// Calculate impact: (CVSS / 10) × Criticality × Breach Cost
			// Normalize CVSS to 0-1 range (divide by 10)
			normalizedScore := vuln.CVSS / 10.0
			impact := normalizedScore * float64(assetCrit) * BreachCostPerHost

			// Map to severity
			severity := vuln.Severity
			if severity == "" {
				severity = intel.MapCVSSToSeverity(vuln.CVSS)
			}

			risk := summary.RisksBySeverity[severity]
			risk.Count++
			risk.ImpactUSD += impact
			if len(risk.CVEExamples) < 3 {
				risk.CVEExamples = append(risk.CVEExamples, cveID)
			}
		}
	}

	// Correlate vulnerabilities from Censys intelligence
	if snapshot.Intelligence.Censys != nil {
		// Censys doesn't provide CVE IDs directly, but high service count = high attack surface
		serviceCount := len(snapshot.Intelligence.Censys.Services)
		if serviceCount > 5 {
			// Heuristic: Each excessive service adds $100K risk
			excessServices := serviceCount - 5
			additionalRisk := float64(excessServices) * 100000.0
			summary.RisksBySeverity["HIGH"].Count += excessServices
			summary.RisksBySeverity["HIGH"].ImpactUSD += additionalRisk
		}
	}

	// Calculate total exposure
	for _, risk := range summary.RisksBySeverity {
		summary.TotalExposure += risk.ImpactUSD
	}

	// Generate methodology documentation
	summary.Methodology = generateMethodologyDoc(assetCrit, assetType)

	return summary
}

// DetermineAssetCriticality analyzes the snapshot to determine asset type and criticality multiplier
func DetermineAssetCriticality(snapshot *audit.AuditSnapshot) (AssetCriticality, string) {
	// Check for domain controller (LDAP/Kerberos/SMB)
	for _, port := range snapshot.Network.Ports {
		if port.Port == 389 || port.Port == 636 || port.Port == 88 {
			return DomainControllerCriticality, "Domain Controller"
		}
	}

	// Check for database servers
	for _, port := range snapshot.Network.Ports {
		switch port.Port {
		case 3306: // MySQL
			return DatabaseCriticality, "MySQL Database Server"
		case 5432: // PostgreSQL
			return DatabaseCriticality, "PostgreSQL Database Server"
		case 1433: // MS SQL Server
			return DatabaseCriticality, "MS SQL Database Server"
		case 27017: // MongoDB
			return DatabaseCriticality, "MongoDB Database Server"
		case 6379: // Redis
			return DatabaseCriticality, "Redis Database Server"
		}
	}

	// Check for application servers
	for _, port := range snapshot.Network.Ports {
		if port.Port == 8080 || port.Port == 8443 || port.Port == 9000 {
			return AppServerCriticality, "Application Server"
		}
	}

	// Check for web servers
	for _, port := range snapshot.Network.Ports {
		if port.Port == 80 || port.Port == 443 {
			return WebServerCriticality, "Web Server"
		}
	}

	// Default: Workstation
	return WorkstationCriticality, "Workstation"
}

// generateMethodologyDoc creates the citation and methodology explanation
func generateMethodologyDoc(criticality AssetCriticality, assetType string) string {
	return fmt.Sprintf(`
## Financial Risk Methodology

**Calculation Formula:**
` + "```" + `
Financial Risk = Σ(CVSS Score × Asset Criticality × Breach Cost Per Host)
` + "```" + `

**Data Sources:**
- **CVSS Scores:** NIST National Vulnerability Database (NVD) + MITRE CVE Database (CVE 5.1 format)
- **Asset Classification:** Port-based heuristic analysis
  - Domain Controllers: 8x multiplier (critical infrastructure)
  - Database Servers: 5x multiplier (data sovereignty risk)
  - Application Servers: 3x multiplier (business logic exposure)
  - Web Servers: 2x multiplier (public-facing)
  - Workstations: 1x multiplier (baseline)
- **Breach Costs:** IBM Cost of Data Breach Report 2024
  - Baseline: $500,000 per compromised endpoint
  - Average total breach cost: $4.88M
  - Healthcare sector average: $11.0M
  - Financial sector average: $6.08M

**Current Asset Assessment:**
- **Type:** %s
- **Criticality Multiplier:** %dx
- **Baseline Risk:** $%.2fM per critical vulnerability

**Example Calculation:**
- CVE-2021-44228 (Log4Shell): CVSS 10.0
- Detected on %s (%dx criticality)
- Impact: (10.0 / 10) × %d × $500K = **$%.1fM potential loss**

**Limitations:**
- Port-based asset classification (heuristic, not asset inventory)
- Does not account for compensating controls (WAF, IDS, segmentation)
- Assumes internet-facing exposure (actual risk may be lower with proper network segmentation)

**References:**
- IBM Security: Cost of a Data Breach Report 2024
  https://www.ibm.com/reports/data-breach
- NIST National Vulnerability Database
  https://nvd.nist.gov/
- FIRST CVSS v3.1 Specification
  https://www.first.org/cvss/v3.1/specification-document
`,
		assetType,
		criticality,
		(float64(criticality) * BreachCostPerHost) / 1e6,
		assetType,
		criticality,
		criticality,
		(float64(criticality) * BreachCostPerHost) / 1e6,
	)
}

// FormatRiskSummary generates a markdown table for reports
func FormatRiskSummary(summary *RiskSummary) string {
	table := `
| Severity | Count | Business Impact | Example CVEs |
|----------|-------|----------------|--------------|
`
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		risk := summary.RisksBySeverity[severity]
		impactStr := fmt.Sprintf("$%.1fM potential loss", risk.ImpactUSD/1e6)
		if risk.ImpactUSD == 0 {
			impactStr = "Minimal"
		}
		exampleCVEs := "None"
		if len(risk.CVEExamples) > 0 {
			exampleCVEs = risk.CVEExamples[0]
			if len(risk.CVEExamples) > 1 {
				exampleCVEs += fmt.Sprintf(" (+%d more)", len(risk.CVEExamples)-1)
			}
		}
		table += fmt.Sprintf("| %s | %d | %s | %s |\n",
			severity, risk.Count, impactStr, exampleCVEs)
	}

	table += fmt.Sprintf("\n**Total Risk Exposure:** $%.1fM\n", summary.TotalExposure/1e6)
	table += fmt.Sprintf("**Asset Type:** %s\n", summary.AssetType)

	return table
}

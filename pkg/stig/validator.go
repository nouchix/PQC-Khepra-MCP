package stig

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	FrameworkRHEL09STIG = "RHEL-09-STIG-V1R3"
	FrameworkRHEL10STIG = "RHEL-10-STIG-V1R1"
	FrameworkCISL1      = "CIS-RHEL-9-L1"
	FrameworkCISL2      = "CIS-RHEL-9-L2"
	FrameworkNIST53     = "NIST-800-53-Rev5"
	FrameworkNIST171    = "NIST-800-171-Rev2"
	FrameworkCMMC       = "CMMC-3.0-L3"
	FrameworkPQC        = "PQC-Readiness"
	// FrameworkPQCStig is the World's First DoD PQC STIG baseline (NouchiX / AdinKhepra).
	// Fills the gap left by DISA, which has no PQC-specific STIGs as of mid-2026.
	// Aligned to NIST FIPS 203/204/205 and NSA CNSA 2.0.
	FrameworkPQCStig    = "PQC-01-STIG-V1R1"
)

// Validator performs comprehensive STIG validation
type Validator struct {
	targetPath        string
	enabledFrameworks []string
	report            *ComprehensiveReport
}

// NewValidator creates a new STIG validator
func NewValidator(targetPath string) *Validator {
	return &Validator{
		targetPath: targetPath,
		enabledFrameworks: []string{
			FrameworkRHEL09STIG,
			FrameworkRHEL10STIG,
			FrameworkCISL1,
			FrameworkCISL2,
			FrameworkNIST53,
			FrameworkNIST171,
			FrameworkCMMC,
			FrameworkPQC,
			FrameworkPQCStig, // World's First DoD PQC STIG
		},
		report: &ComprehensiveReport{
			Results:         make(map[string]*ValidationResult),
			CrossReferences: make(map[string][]string),
		},
	}
}

// EnableFramework enables a specific framework for validation
func (v *Validator) EnableFramework(framework string) {
	for _, f := range v.enabledFrameworks {
		if f == framework {
			return // Already enabled
		}
	}
	v.enabledFrameworks = append(v.enabledFrameworks, framework)
}

// DisableFramework disables a specific framework
func (v *Validator) DisableFramework(framework string) {
	filtered := []string{}
	for _, f := range v.enabledFrameworks {
		if f != framework {
			filtered = append(filtered, f)
		}
	}
	v.enabledFrameworks = filtered
}

// Validate performs comprehensive validation across all enabled frameworks
func (v *Validator) Validate() (*ComprehensiveReport, error) {
	startTime := time.Now()

	// Collect system information
	if err := v.collectSystemInfo(); err != nil {
		return nil, fmt.Errorf("failed to collect system info: %w", err)
	}

	// Run validation for each enabled framework
	for _, framework := range v.enabledFrameworks {
		if err := v.validateFramework(framework); err != nil {
			// Log error but continue with other frameworks
			fmt.Fprintf(os.Stderr, "Warning: framework %s validation failed: %v\n", framework, err)
		}
	}

	// Build cross-references (STIG → CCI → NIST 800-53 → NIST 800-171 → CMMC)
	v.buildCrossReferences()

	// Perform PQC blast radius analysis
	v.analyzePQCBlastRadius()

	// Generate POA&M items from failed findings
	v.generatePOAM()

	// Create executive summary
	v.generateExecutiveSummary()

	v.report.ScanDuration = time.Since(startTime)
	return v.report, nil
}

// ValidatePQCOnly runs ONLY the PQC-01-STIG-V1R1 framework — fast path.
//
// Compared to Validate(), this skips:
//   - collectSystemInfo() — avoids exec.Command("uname") WSL hang on Windows
//   - buildCrossReferences() — skips loading the 36,195-row compliance database
//   - analyzePQCBlastRadius() — skips full project blast-radius scan
//   - generatePOAM() / generateExecutiveSummary() — skips report assembly
//
// Use this from the pqc_stig MCP tool for a fast, focused PQC assessment.
// Returns in < 1 second for typical project directories.
func (v *Validator) ValidatePQCOnly() (*ComprehensiveReport, error) {
	startTime := time.Now()

	// Minimal system info — no exec.Command, no blocking calls
	v.report.Hostname = "static-analysis"
	v.report.OSVersion = runtime.GOOS + "/" + runtime.GOARCH
	v.report.KernelVersion = "n/a (static-analysis-mode)"
	v.report.ScanDate = startTime

	// Run only the PQC STIG framework
	if err := v.validateFramework(FrameworkPQCStig); err != nil {
		return nil, fmt.Errorf("pqc stig validation failed: %w", err)
	}

	v.report.ScanDuration = time.Since(startTime)
	return v.report, nil
}

// collectSystemInfo gathers system information
func (v *Validator) collectSystemInfo() error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	v.report.Hostname = hostname
	v.report.ScanDate = time.Now()

	// Attempt to read OS version from /etc/os-release
	v.report.OSVersion = runtime.GOOS + " " + runtime.GOARCH
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				v.report.OSVersion = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}

	// Get kernel version via uname -r
	cmd := exec.Command("uname", "-r")
	if out, err := cmd.Output(); err == nil {
		v.report.KernelVersion = strings.TrimSpace(string(out))
	} else {
		v.report.KernelVersion = "unknown"
	}

	return nil
}

// validateFramework runs validation for a specific framework
func (v *Validator) validateFramework(framework string) error {
	result := &ValidationResult{
		Framework: framework,
		StartTime: time.Now(),
		Findings:  []Finding{},
	}

	// Dispatch to framework-specific validator
	var err error
	switch framework {
	case FrameworkRHEL09STIG:
		err = v.validateRHEL09STIG(result)
	case FrameworkRHEL10STIG:
		err = v.validateRHEL10STIG(result)
	case FrameworkCISL1:
		err = v.validateCISBenchmarkL1(result)
	case FrameworkCISL2:
		err = v.validateCISBenchmarkL2(result)
	case FrameworkNIST53:
		err = v.validateNIST80053(result)
	case FrameworkNIST171:
		err = v.validateNIST800171(result)
	case FrameworkCMMC:
		err = v.validateCMMC(result)
	case FrameworkPQC:
		err = v.validatePQCReadiness(result)
	case FrameworkPQCStig:
		// World's First DoD PQC STIG — NouchiX PQC-01-STIG-V1R1
		err = v.validatePQCStig(result)
	default:
		return fmt.Errorf("unknown framework: %s", framework)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Calculate totals
	for _, finding := range result.Findings {
		switch finding.Status {
		case "Pass":
			result.Passed++
		case "Fail":
			result.Failed++
		case "Not Applicable":
			result.NotApplicable++
		case "Manual Review Required":
			result.ManualReview++
		}
	}
	result.TotalControls = len(result.Findings)

	v.report.Results[framework] = result
	return err
}

// buildCrossReferences maps controls across frameworks using the moat database
func (v *Validator) buildCrossReferences() {
	// Load the comprehensive 36,195-row compliance mapping database
	db, err := GetDatabase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load compliance database: %v\n", err)
		return
	}

	v.report.CrossReferences = make(map[string][]string)

	// Build cross-references for all findings across all frameworks
	for _, result := range v.report.Results {
		for _, finding := range result.Findings {
			// Get cross-references from database
			refs, err := db.GetCrossReferences(finding.ID)
			if err == nil && len(refs) > 0 {
				v.report.CrossReferences[finding.ID] = refs
			}
		}
	}
}

// analyzePQCBlastRadius performs post-quantum migration impact analysis
func (v *Validator) analyzePQCBlastRadius() {
	checker := NewSystemChecker()

	// Perform real cryptographic inventory
	cryptoModules, _ := checker.CheckCryptoModules()
	listeningPorts, _ := checker.CheckListeningPorts()

	totalOps := len(cryptoModules) + len(listeningPorts)
	legacyOps := totalOps // Assume all are legacy until proven otherwise
	pqcOps := 0

	// Check for PQC readiness indicators
	fipsEnabled, _ := checker.CheckFIPSMode()
	if fipsEnabled {
		// FIPS mode is a step toward PQC readiness
		pqcOps += 5
		legacyOps -= 5
	}

	// Calculate readiness score
	readinessScore := 0.0
	if totalOps > 0 {
		readinessScore = (float64(pqcOps) / float64(totalOps)) * 100.0
	}

	// Estimate migration effort
	estimatedDays := legacyOps * 2 // 2 days per crypto operation to migrate

	v.report.PQCBlastRadius = &BlastRadiusAnalysis{
		TotalCryptoOperations:  totalOps,
		LegacyCryptoOperations: legacyOps,
		PQCReadyOperations:     pqcOps,
		PQCReadinessScore:      readinessScore,
		EstimatedMigrationDays: estimatedDays,
		VulnerableProtocols: []string{
			"TLS 1.2 (upgrade to TLS 1.3 with hybrid PQC key exchange)",
			"SSH (deploy post-quantum key exchange: sntrup761x25519-sha512@openssh.com)",
			"IPsec (upgrade to IKEv2 with Kyber1024 KEM)",
			"X.509 Certificates (deploy hybrid RSA+Dilithium3 or pure Dilithium3)",
		},
		HighRiskSystems: v.identifyHighRiskSystems(checker),
		MediumRiskSystems: []string{
			"Internal web applications using TLS 1.2",
			"Database connections without PQC",
		},
		LowRiskSystems: []string{
			"Legacy systems scheduled for decommission",
		},
		ImmediateActions: []string{
			"Inventory all cryptographic operations (TLS, SSH, IPsec, certificates)",
			"Upgrade OpenSSH to version with PQC key exchange support",
			"Deploy TLS 1.3 with hybrid PQC ciphers (X25519Kyber768)",
			"Generate hybrid certificates (RSA-2048 + Dilithium3)",
		},
		ShortTermActions: []string{
			"Migrate VPN infrastructure to Kyber1024-based IKEv2",
			"Implement PQC code signing for software distribution",
			"Train security team on PQC migration best practices",
		},
		LongTermActions: []string{
			"Replace all legacy crypto with pure PQC algorithms",
			"Achieve CNSA 2.0 compliance (NSA Commercial National Security Algorithm Suite)",
			"Deploy quantum-resistant backup and recovery procedures",
		},
	}
}

// identifyHighRiskSystems identifies systems requiring immediate PQC migration
func (v *Validator) identifyHighRiskSystems(checker *SystemChecker) []string {
	highRisk := []string{}

	// Check for externally-facing services
	ports, _ := checker.CheckListeningPorts()
	for _, port := range ports {
		if strings.Contains(port, ":443") || strings.Contains(port, ":22") {
			highRisk = append(highRisk, "External-facing service on "+port)
		}
	}

	// Check for VPN services
	vpnPackages := []string{"openvpn", "strongswan", "libreswan"}
	for _, pkg := range vpnPackages {
		installed, _, _ := checker.CheckPackageInstalled(pkg)
		if installed {
			highRisk = append(highRisk, "VPN gateway ("+pkg+")")
		}
	}

	// Default high-risk systems
	if len(highRisk) == 0 {
		highRisk = []string{
			"External-facing web servers (assumed present)",
			"SSH servers accessible from internet",
		}
	}

	return highRisk
}

// generatePOAM creates Plan of Action & Milestones items with dollar-weighted priority sorting.
// Each non-compliant finding becomes a tracked POAM item with financial exposure,
// remediation effort estimate, and a priority score for sequencing.
func (v *Validator) generatePOAM() {
	v.report.POAMItems = []POAMItem{}
	counter := 1

	// Severity → days-to-remediate and financial weight constants.
	// Based on IBM Cost of Data Breach Report 2024 ($500K baseline) and
	// typical DoD remediation effort benchmarks.
	type severityConfig struct {
		days   int
		weight float64
		cost   float64 // USD per finding
	}
	severityMap := map[Severity]severityConfig{
		SeverityCAT1:     {days: 7, weight: 3.0, cost: 150000},
		SeverityCritical: {days: 7, weight: 3.0, cost: 150000},
		SeverityCAT2:     {days: 14, weight: 2.0, cost: 50000},
		SeverityHigh:     {days: 14, weight: 2.0, cost: 50000},
		SeverityCAT3:     {days: 30, weight: 1.0, cost: 10000},
		SeverityMedium:   {days: 30, weight: 1.0, cost: 10000},
		SeverityLow:      {days: 60, weight: 0.5, cost: 2500},
	}
	defaultConfig := severityConfig{days: 30, weight: 1.0, cost: 10000}

	// Generate POAM item for each failed finding across all frameworks.
	for _, result := range v.report.Results {
		for _, finding := range result.Findings {
			if finding.Status != "Fail" {
				continue
			}

			cfg, ok := severityMap[finding.Severity]
			if !ok {
				cfg = defaultConfig
			}

			priorityScore := 0.0
			if cfg.days > 0 {
				priorityScore = (cfg.cost / float64(cfg.days)) * cfg.weight
			}

			// Scheduled completion date: days from now based on severity.
			dueDate := time.Now().Add(time.Duration(cfg.days) * 24 * time.Hour)

			poam := POAMItem{
				ID:                  fmt.Sprintf("POAM-%d-%03d", time.Now().Year(), counter),
				ControlID:           finding.ID,
				Weakness:            finding.Description,
				Severity:            finding.Severity,
				Status:              "Open",
				PointOfContact:      "ISSM",
				EstimatedCost:       cfg.cost,
				ScheduledCompletion: dueDate,
				MilestoneActions:    []string{finding.Remediation},
				DollarImpact:        cfg.cost,
				SeverityWeight:      cfg.weight,
				PriorityScore:       priorityScore,
				EstimatedDays:       cfg.days,
			}
			v.report.POAMItems = append(v.report.POAMItems, poam)
			counter++
		}
	}

	// Sort POAM items highest priority first (highest PriorityScore = fix first).
	for i := 0; i < len(v.report.POAMItems); i++ {
		for j := i + 1; j < len(v.report.POAMItems); j++ {
			if v.report.POAMItems[j].PriorityScore > v.report.POAMItems[i].PriorityScore {
				v.report.POAMItems[i], v.report.POAMItems[j] = v.report.POAMItems[j], v.report.POAMItems[i]
			}
		}
	}
}


// generateExecutiveSummary creates high-level summary
func (v *Validator) generateExecutiveSummary() {
	summary := ExecutiveSummary{}

	v.calculateFrameworkCompliance(&summary)
	v.calculateOverallCompliance(&summary)
	v.countFindings(&summary)

	// Risk assessment
	summary.OverallRisk = RiskLevel(summary.CAT1Findings, summary.CAT2Findings, summary.CAT3Findings)

	v.updatePQCAndRisks(&summary)

	v.report.ExecutiveSummary = summary
}

func (v *Validator) calculateFrameworkCompliance(summary *ExecutiveSummary) {
	if stig, ok := v.report.Results[FrameworkRHEL09STIG]; ok {
		summary.STIGCompliance = stig.ComplianceScore()
	}
	if cis, ok := v.report.Results[FrameworkCISL2]; ok {
		summary.CISCompliance = cis.ComplianceScore()
	}
	if nist53, ok := v.report.Results[FrameworkNIST53]; ok {
		summary.NIST80053Compliance = nist53.ComplianceScore()
	}
	if nist171, ok := v.report.Results[FrameworkNIST171]; ok {
		summary.NIST800171Compliance = nist171.ComplianceScore()
	}
	if cmmc, ok := v.report.Results[FrameworkCMMC]; ok {
		summary.CMMCCompliance = cmmc.ComplianceScore()
	}
}

func (v *Validator) calculateOverallCompliance(summary *ExecutiveSummary) {
	total := 0.0
	count := 0
	for _, result := range v.report.Results {
		if result.TotalControls > 0 {
			total += result.ComplianceScore()
			count++
		}
	}
	if count > 0 {
		summary.OverallCompliance = total / float64(count)
	}
	summary.ComplianceGrade = ComplianceGrade(summary.OverallCompliance)
}

func (v *Validator) countFindings(summary *ExecutiveSummary) {
	for _, result := range v.report.Results {
		for _, finding := range result.Findings {
			if finding.Status == "Fail" {
				switch finding.Severity {
				case SeverityCAT1, SeverityCritical:
					summary.CAT1Findings++
				case SeverityCAT2, SeverityHigh:
					summary.CAT2Findings++
				case SeverityCAT3, SeverityMedium, SeverityLow:
					summary.CAT3Findings++
				}
			}
		}
	}
}

func (v *Validator) updatePQCAndRisks(summary *ExecutiveSummary) {
	if v.report.PQCBlastRadius != nil {
		summary.PQCReadinessGrade = ComplianceGrade(v.report.PQCBlastRadius.PQCReadinessScore)
		summary.PQCMigrationRequired = v.report.PQCBlastRadius.PQCReadinessScore < 95.0
	}

	summary.TopRisks = []string{
		fmt.Sprintf("%d CAT I/Critical findings requiring immediate remediation", summary.CAT1Findings),
		fmt.Sprintf("%d CAT II/High findings requiring attention", summary.CAT2Findings),
	}

	summary.ExecutiveRecommendations = []string{
		fmt.Sprintf("Address %d critical findings within 30 days", summary.CAT1Findings),
		fmt.Sprintf("Implement Plan of Action & Milestones for %d open items", len(v.report.POAMItems)),
	}

	if summary.PQCMigrationRequired {
		summary.TopRisks = append(summary.TopRisks, "Post-quantum cryptography migration required")
		summary.ExecutiveRecommendations = append(summary.ExecutiveRecommendations,
			"Initiate post-quantum cryptography migration planning")
	}
}

// GetReport returns the generated compliance report
func (v *Validator) GetReport() *ComprehensiveReport {
	return v.report
}

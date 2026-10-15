package stig

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	FrameworkRHEL09STIG = "RHEL-09-STIG-V1R3"
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

	// Additional live-scan framework identifiers for multi-OS Tier 1 coverage.
	FrameworkRHEL08STIG      = "RHEL-08-STIG"
	FrameworkRHEL07STIG      = "RHEL-07-STIG"
	FrameworkRHEL10STIG      = "RHEL-10-STIG-V1R2" // STIGViewer V1R2, 434 findings (2026-07-11)
	FrameworkOracleLinux8    = "Oracle-Linux-8-STIG"
	FrameworkUbuntu1804      = "CAN_Ubuntu_18-04-STIG"
	FrameworkUbuntu2204      = "CAN_Ubuntu_22-04-STIG"
	FrameworkUbuntu2404      = "CAN_Ubuntu_24-04-STIG"
	FrameworkAlmaLinux9      = "AlmaLinux-OS-9-STIG"
	FrameworkWindows10       = "Windows-10-STIG"
	FrameworkWindows11       = "Windows-11-STIG"
	FrameworkWinServer2016   = "Windows-Server-2016-STIG"
	FrameworkWinServer2019   = "Windows-Server-2019-STIG"
	FrameworkWinServer2022   = "Windows-Server-2022-STIG"
	FrameworkMacOS13         = "Apple-macOS-13-STIG"
	FrameworkMacOS14         = "Apple-macOS-14-STIG"
	FrameworkMacOS15         = "Apple-macOS-15-STIG"
	FrameworkKubernetes      = "Kubernetes-STIG"
)

// Validator performs comprehensive STIG validation
type Validator struct {
	targetPath        string
	enabledFrameworks []string
	report            *ComprehensiveReport
	// hostOS is set by collectSystemInfo() after OS detection.
	// Values: "rhel9", "rhel8", "rhel7", "ubuntu1804", "oracle8",
	//         "win10", "win11", "winsrv2016", "winsrv2019", "winsrv2022",
	//         "macos13", "macos14", "macos15", "unknown"
	hostOS string
}

// NewValidator creates a new STIG validator
func NewValidator(targetPath string) *Validator {
	return &Validator{
		targetPath: targetPath,
		enabledFrameworks: []string{
			FrameworkRHEL09STIG,
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

	// Run validation for each enabled framework in dependency order:
	// concrete technical OS STIG benchmarks and PQC run first, so composite
	// frameworks (NIST-800-53, NIST-800-171, CMMC) have the full findings pool.
	for _, framework := range orderFrameworks(v.enabledFrameworks) {
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
//   - buildCrossReferences() — skips loading the 25,185-row compliance database (deduplicated)
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

	// Read OS version from /etc/os-release (Linux) or runtime.GOOS (other platforms).
	v.report.OSVersion = runtime.GOOS + " " + runtime.GOARCH
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				v.report.OSVersion = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}

	// Get kernel version via uname -r (Linux/macOS only; no-op on Windows)
	if runtime.GOOS != "windows" {
		cmd := exec.Command("uname", "-r")
		if out, err := cmd.Output(); err == nil {
			v.report.KernelVersion = strings.TrimSpace(string(out))
		} else {
			v.report.KernelVersion = "unknown"
		}
	} else {
		v.report.KernelVersion = "n/a"
	}

	// Detect host OS and auto-select the matching STIG Tier 1 framework.
	v.autoSelectOSFramework()
	return nil
}

// autoSelectOSFramework detects the host OS, sets v.hostOS, and adds the matching
// OS-family STIG framework to v.enabledFrameworks if it is not already present.
// Frameworks for the wrong OS are removed so that scans stay relevant.
func (v *Validator) autoSelectOSFramework() {
	var fw string
	switch runtime.GOOS {
	case "windows":
		fw = detectWindowsSTIGFramework()
		v.hostOS = windowsFWtoHostOS(fw)
		// Windows scans don't need Linux-specific frameworks.
		v.removeFramework(FrameworkRHEL09STIG)
		v.removeFramework(FrameworkCISL1)
		v.removeFramework(FrameworkCISL2)
	case "darwin":
		fw = detectMacOSSTIGFramework()
		v.hostOS = macosFWtoHostOS(fw)
		v.removeFramework(FrameworkRHEL09STIG)
		v.removeFramework(FrameworkCISL1)
		v.removeFramework(FrameworkCISL2)
	default: // linux and other POSIX
		osID, versionID := readOSRelease()
		fw = detectLinuxSTIGFramework(osID, versionID)
		v.hostOS = linuxFWtoHostOS(fw)
		// Replace the default FrameworkRHEL09STIG with the detected one if different.
		if fw != FrameworkRHEL09STIG {
			v.removeFramework(FrameworkRHEL09STIG)
		}
	}
	if fw != "" {
		v.addFrameworkIfMissing(fw)
	}
}

// addFrameworkIfMissing appends fw to enabledFrameworks when not already present.
func (v *Validator) addFrameworkIfMissing(fw string) {
	for _, f := range v.enabledFrameworks {
		if f == fw {
			return
		}
	}
	v.enabledFrameworks = append(v.enabledFrameworks, fw)
}

// removeFramework removes all occurrences of fw from enabledFrameworks.
func (v *Validator) removeFramework(fw string) {
	out := v.enabledFrameworks[:0]
	for _, f := range v.enabledFrameworks {
		if f != fw {
			out = append(out, f)
		}
	}
	v.enabledFrameworks = out
}

// orderFrameworks ensures concrete technical STIG benchmarks and PQC run FIRST,
// so that composite frameworks (NIST-800-53, NIST-800-171, CMMC) have the full
// evidence pool available when they evaluate.
func orderFrameworks(frameworks []string) []string {
	var primary []string
	var composite []string
	for _, f := range frameworks {
		switch f {
		case FrameworkNIST53, FrameworkNIST171, FrameworkCMMC:
			composite = append(composite, f)
		default:
			primary = append(primary, f)
		}
	}
	return append(primary, composite...)
}

// readOSRelease parses /etc/os-release and returns the ID and VERSION_ID values.
func readOSRelease() (osID, versionID string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "ID="):
			osID = strings.ToLower(strings.Trim(strings.TrimPrefix(line, "ID="), "\""))
		case strings.HasPrefix(line, "VERSION_ID="):
			versionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}
	return osID, versionID
}

// detectLinuxSTIGFramework maps /etc/os-release ID + VERSION_ID to a STIG framework.
func detectLinuxSTIGFramework(osID, versionID string) string {
	switch osID {
	case "rhel", "redhat":
		switch {
		case strings.HasPrefix(versionID, "9"):
			return FrameworkRHEL09STIG
		case strings.HasPrefix(versionID, "8"):
			return FrameworkRHEL08STIG
		case strings.HasPrefix(versionID, "7"):
			return FrameworkRHEL07STIG
		}
	case "ol": // Oracle Linux
		if strings.HasPrefix(versionID, "8") {
			return FrameworkOracleLinux8
		}
	case "ubuntu":
		switch {
		case strings.HasPrefix(versionID, "18"):
			return FrameworkUbuntu1804
		// Ubuntu 20.04/22.04/24.04 tables were not downloaded from DISA CDN;
		// fall through to RHEL09 (best available general Linux baseline).
		}
	case "almalinux", "rocky":
		// AlmaLinux and Rocky Linux are RHEL-compatible; use closest RHEL STIG.
		if strings.HasPrefix(versionID, "9") {
			return FrameworkRHEL09STIG
		}
		return FrameworkRHEL08STIG
	}
	return FrameworkRHEL09STIG // default: best available Linux baseline
}

// detectWindowsSTIGFramework maps the Windows build number to a STIG framework.
// Falls back to Windows Server 2022 (most restrictive, appropriate for DIB targets).
func detectWindowsSTIGFramework() string {
	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err != nil {
		return FrameworkWinServer2022
	}
	build := parseWindowsBuild(string(out))
	switch {
	case build >= 22000:
		return FrameworkWindows11
	case build >= 20348:
		return FrameworkWinServer2022
	case build >= 17763:
		return FrameworkWinServer2019
	case build >= 14393:
		return FrameworkWinServer2016
	default:
		return FrameworkWindows10
	}
}

// parseWindowsBuild extracts the build number from a "ver" command output like
// "Microsoft Windows [Version 10.0.22631.4602]".
func parseWindowsBuild(verOutput string) int {
	// Find "10.0." or "6.x." and extract the third component.
	idx := strings.Index(verOutput, "10.0.")
	if idx < 0 {
		return 0
	}
	rest := verOutput[idx+5:]
	for i, c := range rest {
		if c == '.' || c == ']' || c == ' ' || c == '\n' || c == '\r' {
			build, _ := strconv.Atoi(rest[:i])
			return build
		}
	}
	return 0
}

// detectMacOSSTIGFramework maps the sw_vers product version to a STIG framework.
func detectMacOSSTIGFramework() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return FrameworkMacOS15
	}
	ver := strings.TrimSpace(string(out))
	switch {
	case strings.HasPrefix(ver, "15."):
		return FrameworkMacOS15
	case strings.HasPrefix(ver, "14."):
		return FrameworkMacOS14
	case strings.HasPrefix(ver, "13."):
		return FrameworkMacOS13
	default:
		return FrameworkMacOS15
	}
}

// ── hostOS string helpers ─────────────────────────────────────────────────────

func windowsFWtoHostOS(fw string) string {
	switch fw {
	case FrameworkWindows10:
		return "win10"
	case FrameworkWindows11:
		return "win11"
	case FrameworkWinServer2016:
		return "winsrv2016"
	case FrameworkWinServer2019:
		return "winsrv2019"
	case FrameworkWinServer2022:
		return "winsrv2022"
	}
	return "windows"
}

func macosFWtoHostOS(fw string) string {
	switch fw {
	case FrameworkMacOS13:
		return "macos13"
	case FrameworkMacOS14:
		return "macos14"
	case FrameworkMacOS15:
		return "macos15"
	}
	return "macos"
}

func linuxFWtoHostOS(fw string) string {
	switch fw {
	case FrameworkRHEL09STIG:
		return "rhel9"
	case FrameworkRHEL10STIG:
		return "rhel10"
	case FrameworkRHEL08STIG:
		return "rhel8"
	case FrameworkRHEL07STIG:
		return "rhel7"
	case FrameworkOracleLinux8:
		return "oracle8"
	case FrameworkUbuntu1804:
		return "ubuntu1804"
	}
	return "linux"
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
		// RHEL 10 V1R2 — live STIGViewer fetch, 434 findings. First ASAF RHEL10 coverage.
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
	case FrameworkRHEL08STIG:
		err = v.validateTableSTIG(result, "V2R7", rhel08STIG)
	case FrameworkRHEL07STIG:
		err = v.validateTableSTIG(result, "V3R15", rhel07STIG)
	case FrameworkOracleLinux8:
		err = v.validateTableSTIG(result, "V1R10", oracleLinux8STIG)
	case FrameworkUbuntu1804:
		err = v.validateTableSTIG(result, "V2R15", ubuntu1804STIG)
	case FrameworkWindows10:
		err = v.validateTableSTIG(result, "V2R9", win10STIG)
	case FrameworkWindows11:
		err = v.validateTableSTIG(result, "V1R6", win11STIG)
	case FrameworkWinServer2016:
		err = v.validateTableSTIG(result, "V2R10", winSrv2016STIG)
	case FrameworkWinServer2019:
		err = v.validateTableSTIG(result, "V2R9", winSrv2019STIG)
	case FrameworkWinServer2022:
		err = v.validateTableSTIG(result, "V1R5", winSrv2022STIG)
	case FrameworkMacOS13:
		err = v.validateTableSTIG(result, "V1R5", macos13STIG)
	case FrameworkMacOS14:
		err = v.validateTableSTIG(result, "V1R2", macos14STIG)
	case FrameworkMacOS15:
		err = v.validateTableSTIG(result, "V1R7", macos15STIG)
	case FrameworkKubernetes:
		err = v.validateTableSTIG(result, "V1R11", k8sStig)
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
		case StatusNotAssessed:
			result.NotAssessed++
		}
	}
	result.TotalControls = len(result.Findings)

	v.report.Results[framework] = result
	return err
}

// buildCrossReferences maps controls across frameworks using the moat database
func (v *Validator) buildCrossReferences() {
	// Load the comprehensive 25,185-row compliance mapping database (deduplicated)
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

// ImportCKL parses a STIG Viewer .ckl XML checklist file and returns a
// ComprehensiveReport.  Each iSTIG section in the file becomes a separate
// ValidationResult keyed by the STIG title.  No live OS checks are run.
func (v *Validator) ImportCKL(path string) (*ComprehensiveReport, error) {
	start := time.Now()

	results, err := ParseCKLFile(path)
	if err != nil {
		return nil, fmt.Errorf("import CKL %s: %w", path, err)
	}

	report := &ComprehensiveReport{
		Hostname:        v.report.Hostname,
		OSVersion:       v.report.OSVersion,
		ScanDate:        start,
		Results:         make(map[string]*ValidationResult),
		CrossReferences: make(map[string][]string),
	}

	for _, r := range results {
		frameworkKey := cklFrameworkKey(r.STIGTitle, r.STIGFile)
		vr := buildValidationResultFromFindings(frameworkKey, r.STIGFile, r.Findings, start)
		report.Results[frameworkKey] = vr
	}

	report.ScanDuration = time.Since(start)
	return report, nil
}

// ImportCKLB parses a STIG Viewer 2.x .cklb JSON checklist file and returns
// a ComprehensiveReport.  Handles both canonical and flat CKLB format variants.
func (v *Validator) ImportCKLB(path string) (*ComprehensiveReport, error) {
	start := time.Now()

	results, err := ParseCKLBFile(path)
	if err != nil {
		return nil, fmt.Errorf("import CKLB %s: %w", path, err)
	}

	report := &ComprehensiveReport{
		Hostname:        coalesce(results[0].Hostname, v.report.Hostname),
		OSVersion:       v.report.OSVersion,
		ScanDate:        start,
		Results:         make(map[string]*ValidationResult),
		CrossReferences: make(map[string][]string),
	}

	for _, r := range results {
		frameworkKey := cklFrameworkKey(r.STIGTitle, r.BenchmarkID)
		vr := buildValidationResultFromFindings(frameworkKey, r.Version, r.Findings, start)
		report.Results[frameworkKey] = vr
	}

	report.ScanDuration = time.Since(start)
	return report, nil
}

// cklFrameworkKey returns a stable map key for a ValidationResult from a CKL/CKLB import.
func cklFrameworkKey(title, fileOrBenchmark string) string {
	if title != "" {
		return title
	}
	if fileOrBenchmark != "" {
		return fileOrBenchmark
	}
	return "Imported-STIG"
}

// buildValidationResultFromFindings assembles a ValidationResult from a []Finding slice.
func buildValidationResultFromFindings(framework, version string, findings []Finding, start time.Time) *ValidationResult {
	end := time.Now()
	vr := &ValidationResult{
		Framework: framework,
		Version:   version,
		Findings:  findings,
		StartTime: start,
		EndTime:   end,
		Duration:  end.Sub(start),
	}
	for _, f := range findings {
		switch f.Status {
		case "Pass":
			vr.Passed++
		case "Fail":
			vr.Failed++
		case "Not Applicable":
			vr.NotApplicable++
		default:
			vr.ManualReview++
		}
	}
	vr.TotalControls = len(findings)
	return vr
}

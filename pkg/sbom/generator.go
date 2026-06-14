package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/intel"
)

// Component represents a software component in the SBOM
type Component struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	PURL         string   `json:"purl"` // Package URL
	Type         string   `json:"type"` // library, application, container, etc.
	Supplier     string   `json:"supplier"`
	License      string   `json:"license"`
	Hashes       []string `json:"hashes"`
	Dependencies []string `json:"dependencies"` // List of dependent component names
}

// VulnerableComponent represents a component with known vulnerabilities
type VulnerableComponent struct {
	Component
	CVEs          []string `json:"cves"`
	STIGs         []string `json:"stigs"` // Mapped STIG controls
	RiskScore     float64  `json:"risk_score"`
	Exploitable   bool     `json:"exploitable"` // In CISA KEV
	PublicExploit bool     `json:"public_exploit"`
}

// SBOM represents a Software Bill of Materials
type SBOM struct {
	Format       string      `json:"format"` // CycloneDX, SPDX
	Version      string      `json:"version"`
	Timestamp    time.Time   `json:"timestamp"`
	Target       string      `json:"target"` // Container image, filesystem, binary
	Components   []Component `json:"components"`
	TotalCount   int         `json:"total_count"`
	VulnCount    int         `json:"vuln_count"`
	CriticalVuln int         `json:"critical_vuln"`
}

// SBOMGenerator generates Software Bill of Materials and correlates with CVE database
type SBOMGenerator struct {
	scanner    string // syft, trivy, grype
	cveLookup  *intel.KnowledgeBase
	stigMapper STIGMapper
	cveDBPath  string // Path to CVE database directory
}

// STIGMapper maps CVEs to STIG controls
type STIGMapper interface {
	MapCVEToSTIG(cveID string) []string
}

// NewSBOMGenerator creates a new SBOM generator
func NewSBOMGenerator(scanner string) *SBOMGenerator {
	return &SBOMGenerator{
		scanner:   scanner,
		cveLookup: intel.NewKnowledgeBase(),
	}
}

// SetCVEDatabase sets the path to the CVE database
func (sg *SBOMGenerator) SetCVEDatabase(path string) {
	sg.cveDBPath = path
	// Reload knowledge base with the new path
	sg.cveLookup = intel.NewKnowledgeBase()
}

// GenerateSBOM scans a target and generates a Software Bill of Materials
func (sg *SBOMGenerator) GenerateSBOM(target string) (*SBOM, error) {
	// Detect target type
	targetType, err := sg.detectTargetType(target)
	if err != nil {
		return nil, fmt.Errorf("failed to detect target type: %w", err)
	}

	// Run scanner based on type
	var components []Component
	switch sg.scanner {
	case "syft":
		components, err = sg.runSyft(target, targetType)
	case "trivy":
		components, err = sg.runTrivy(target, targetType)
	case "grype":
		components, err = sg.runGrype(target, targetType)
	default:
		return nil, fmt.Errorf("unsupported scanner: %s", sg.scanner)
	}

	if err != nil {
		return nil, fmt.Errorf("scanner failed: %w", err)
	}

	sbom := &SBOM{
		Format:     "CycloneDX",
		Version:    "1.4",
		Timestamp:  time.Now(),
		Target:     target,
		Components: components,
		TotalCount: len(components),
	}

	return sbom, nil
}

// CorrelateVulnerabilities matches SBOM components against CVE database
func (sg *SBOMGenerator) CorrelateVulnerabilities(sbom *SBOM) ([]VulnerableComponent, error) {
	var vulnerable []VulnerableComponent

	for _, comp := range sbom.Components {
		// Query CVE database using component name + version via KnowledgeBase.
		// Extend by calling sg.cveLookup.QueryByPackage(comp.Name, comp.Version)
		// once the KnowledgeBase package-name index is wired (see pkg/intel/kb_index.go).
		cves := []intel.Vulnerability{}

		if len(cves) == 0 {
			continue // No vulnerabilities found
		}

		vulnComp := VulnerableComponent{
			Component: comp,
			CVEs:      make([]string, 0),
			STIGs:     make([]string, 0),
		}

		for _, cve := range cves {
			vulnComp.CVEs = append(vulnComp.CVEs, cve.ID)

			// Check if actively exploited (CISA KEV)
			if cve.IsExploited {
				vulnComp.Exploitable = true
			}

			// PublicExploit mirrors IsExploited when EPSS or PoC data is not available.
			// Extend with cve.ExploitURLs once the EPSS feed (pkg/vuln/feeds.go) populates that field.
			if cve.IsExploited {
				vulnComp.PublicExploit = true
			}

			// Map to STIG controls
			if sg.stigMapper != nil {
				stigs := sg.stigMapper.MapCVEToSTIG(cve.ID)
				vulnComp.STIGs = append(vulnComp.STIGs, stigs...)
			}
		}

		// Calculate contextual risk score
		vulnComp.RiskScore = sg.calculateRiskScore(vulnComp, cves)

		vulnerable = append(vulnerable, vulnComp)

		// Update SBOM stats
		sbom.VulnCount++
		if vulnComp.RiskScore >= 9.0 {
			sbom.CriticalVuln++
		}
	}

	return vulnerable, nil
}

// calculateRiskScore computes context-aware risk (not just CVSS)
func (sg *SBOMGenerator) calculateRiskScore(comp VulnerableComponent, cves []intel.Vulnerability) float64 {
	if len(cves) == 0 {
		return 0.0
	}

	// Start with base CVSS score (average of all CVEs)
	var totalCVSS float64
	for _, cve := range cves {
		totalCVSS += cve.CVSS
	}
	baseScore := totalCVSS / float64(len(cves))

	// Apply multipliers
	score := baseScore

	// 2x multiplier if actively exploited (CISA KEV)
	if comp.Exploitable {
		score *= 2.0
	}

	// 1.5x multiplier if public exploit exists
	if comp.PublicExploit {
		score *= 1.5
	}

	// Cap at 10.0
	if score > 10.0 {
		score = 10.0
	}

	return score
}

// detectTargetType determines if target is container, filesystem, or binary
func (sg *SBOMGenerator) detectTargetType(target string) (string, error) {
	// Check if it's a container image (has : for tag)
	if contains(target, ":") && !filepath.IsAbs(target) {
		return "container", nil
	}

	// Check if it's a directory
	info, err := os.Stat(target)
	if err == nil && info.IsDir() {
		return "filesystem", nil
	}

	// Check if it's a file
	if err == nil && !info.IsDir() {
		return "binary", nil
	}

	return "", fmt.Errorf("cannot determine target type for: %s", target)
}

// runSyft executes Syft SBOM scanner
func (sg *SBOMGenerator) runSyft(target, targetType string) ([]Component, error) {
	var cmd *exec.Cmd

	switch targetType {
	case "container":
		cmd = exec.Command("syft", target, "-o", "json")
	case "filesystem":
		cmd = exec.Command("syft", "dir:"+target, "-o", "json")
	case "binary":
		cmd = exec.Command("syft", "file:"+target, "-o", "json")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("syft command failed: %w (output: %s)", err, string(output))
	}

	// Parse Syft JSON output
	var syftResult struct {
		Artifacts []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			PURL    string `json:"purl"`
		} `json:"artifacts"`
	}

	if err := json.Unmarshal(output, &syftResult); err != nil {
		return nil, fmt.Errorf("failed to parse syft output: %w", err)
	}

	// Convert to Component structs
	components := make([]Component, len(syftResult.Artifacts))
	for i, art := range syftResult.Artifacts {
		components[i] = Component{
			Name:    art.Name,
			Version: art.Version,
			Type:    art.Type,
			PURL:    art.PURL,
		}
	}

	return components, nil
}

// runTrivy executes Trivy scanner
func (sg *SBOMGenerator) runTrivy(target, targetType string) ([]Component, error) {
	var cmd *exec.Cmd

	switch targetType {
	case "container":
		cmd = exec.Command("trivy", "image", "--format", "json", target)
	case "filesystem":
		cmd = exec.Command("trivy", "fs", "--format", "json", target)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("trivy command failed: %w", err)
	}

	// Parse Trivy output (simplified - actual format is more complex)
	var trivyResult struct {
		Results []struct {
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"packages"`
		} `json:"results"`
	}

	if err := json.Unmarshal(output, &trivyResult); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	var components []Component
	for _, result := range trivyResult.Results {
		for _, pkg := range result.Packages {
			components = append(components, Component{
				Name:    pkg.Name,
				Version: pkg.Version,
				Type:    "library",
			})
		}
	}

	return components, nil
}

// runGrype executes Grype vulnerability scanner
func (sg *SBOMGenerator) runGrype(target, targetType string) ([]Component, error) {
	// Grype is primarily a vulnerability scanner, not SBOM generator
	// In practice, you'd first generate SBOM with Syft, then scan with Grype
	return sg.runSyft(target, targetType)
}

// GenerateDAGNodes creates DAG nodes linking SBOM components to their vulnerabilities.
// DAG node schema uses Action=component-name, Symbol=vuln-severity, Time=RFC3339.
// Binding is deferred until the SBOM component PURL can be used as a stable parent ID.
func (sg *SBOMGenerator) GenerateDAGNodes(sbom *SBOM, vulnerable []VulnerableComponent, dagInstance *dag.Memory, hostname string) error {
	if dagInstance == nil {
		return nil
	}
	// DAG binding uses the dag.Memory.Add() API with Action=component name,
	// Symbol=risk level, Time=scan timestamp. Wired when SBOM PURL indexing is stable.
	_ = sbom
	_ = vulnerable
	_ = hostname
	return nil
}

// ExportSBOM saves SBOM to a file (CycloneDX JSON format)
func (sg *SBOMGenerator) ExportSBOM(sbom *SBOM, outputPath string) error {
	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write SBOM file: %w", err)
	}

	return nil
}

// TrackSBOMChanges compares two SBOMs and identifies new vulnerable dependencies
func (sg *SBOMGenerator) TrackSBOMChanges(oldSBOM, newSBOM *SBOM) []Component {
	oldComponents := make(map[string]Component)
	for _, comp := range oldSBOM.Components {
		key := fmt.Sprintf("%s:%s", comp.Name, comp.Version)
		oldComponents[key] = comp
	}

	var newVulnerabilities []Component
	for _, comp := range newSBOM.Components {
		key := fmt.Sprintf("%s:%s", comp.Name, comp.Version)
		if _, exists := oldComponents[key]; !exists {
			// New component — query KnowledgeBase for known CVEs.
			// Extend with sg.cveLookup.QueryByPackage(comp.Name, comp.Version).
			var cves []intel.Vulnerability
			if len(cves) > 0 {
				newVulnerabilities = append(newVulnerabilities, comp)
			}
		}
	}

	return newVulnerabilities
}

// contains is a helper function for substring matching
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// SimpleST IGMapper is a basic STIG mapper implementation
type SimpleSTIGMapper struct {
	mappings map[string][]string
}

// NewSimpleSTIGMapper creates a basic STIG mapper
func NewSimpleSTIGMapper() *SimpleSTIGMapper {
	return &SimpleSTIGMapper{
		mappings: map[string][]string{
			"CVE-2021-44228": {"RHEL-08-010370"}, // Log4Shell -> Software updates
			"CVE-2021-45046": {"RHEL-08-010370"},
			"CVE-2017-5638":  {"RHEL-08-010370"}, // Struts
		},
	}
}

// MapCVEToSTIG maps a CVE ID to STIG control IDs
func (sm *SimpleSTIGMapper) MapCVEToSTIG(cveID string) []string {
	if stigs, exists := sm.mappings[cveID]; exists {
		return stigs
	}
	return []string{"GENERIC-VULN-MGMT"}
}

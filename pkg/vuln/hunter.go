// Package vuln implements the Vulnerability Hunter - SouHimBou's ability to
// discover, analyze, and remediate dependency vulnerabilities autonomously.
//
// "The Scarab sees what the eye cannot - the rot beneath the surface."
package vuln

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityModerate Severity = "MODERATE"
	SeverityLow      Severity = "LOW"
)

// Vulnerability represents a discovered security vulnerability
type Vulnerability struct {
	ID              string            `json:"id"`               // CVE-XXXX-XXXXX or GHSA-XXXX
	Package         string            `json:"package"`          // Affected package name
	Ecosystem       string            `json:"ecosystem"`        // go, npm, pip, etc.
	Severity        Severity          `json:"severity"`         // CRITICAL, HIGH, MODERATE, LOW
	CVSS            float64           `json:"cvss,omitempty"`   // CVSS score if available
	Title           string            `json:"title"`            // Short description
	Description     string            `json:"description"`      // Full description
	AffectedRange   string            `json:"affected_range"`   // e.g., "< 1.2.3"
	FixedVersion    string            `json:"fixed_version"`    // Version that fixes it
	References      []string          `json:"references"`       // URLs for more info
	DiscoveredAt    time.Time         `json:"discovered_at"`    // When we found it
	RemediationPlan *RemediationPlan  `json:"remediation_plan"` // Auto-generated fix plan
	Metadata        map[string]string `json:"metadata"`         // Extra context
}

// RemediationPlan describes how to fix a vulnerability
type RemediationPlan struct {
	Action      string   `json:"action"`       // "upgrade", "replace", "remove", "patch"
	TargetVersion string `json:"target_version"`
	Commands    []string `json:"commands"`     // Shell commands to execute
	RiskLevel   string   `json:"risk_level"`   // Risk of the remediation itself
	Breaking    bool     `json:"breaking"`     // Might break existing code
	Verified    bool     `json:"verified"`     // Has been tested
}

// ScanResult contains the results of a vulnerability scan
type ScanResult struct {
	ScanID          string           `json:"scan_id"`
	Timestamp       time.Time        `json:"timestamp"`
	Duration        time.Duration    `json:"duration"`
	TotalVulns      int              `json:"total_vulns"`
	BySeverity      map[Severity]int `json:"by_severity"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
	Ecosystems      []string         `json:"ecosystems_scanned"`
	Errors          []string         `json:"errors,omitempty"`
}

// Hunter is the vulnerability discovery and remediation engine
type Hunter struct {
	rootPath    string
	httpClient  *http.Client
	mu          sync.Mutex
	lastScan    *ScanResult
	autoFix     bool
	dryRun      bool

	// Threat Intelligence
	intelManager *IntelFeedManager

	// Callbacks for AGI integration
	OnVulnDiscovered func(v Vulnerability)
	OnRemediationComplete func(v Vulnerability, success bool)
}

// NewHunter creates a new vulnerability hunter
func NewHunter(rootPath string) *Hunter {
	return &Hunter{
		rootPath: rootPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		autoFix:      false,
		dryRun:       true,
		intelManager: NewIntelFeedManager(),
	}
}

// RefreshIntelligence fetches latest threat intel from all feeds
func (h *Hunter) RefreshIntelligence(ctx context.Context) error {
	log.Println("[HUNTER] Refreshing threat intelligence from all feeds...")
	return h.intelManager.FetchAll(ctx)
}

// GetIntelStats returns threat intelligence statistics
func (h *Hunter) GetIntelStats() map[string]int {
	return h.intelManager.Stats()
}

// SetAutoFix enables autonomous remediation (USE WITH CAUTION)
func (h *Hunter) SetAutoFix(enabled bool) {
	h.autoFix = enabled
}

// SetDryRun controls whether commands are actually executed
func (h *Hunter) SetDryRun(dryRun bool) {
	h.dryRun = dryRun
}

// Scan performs a comprehensive vulnerability scan across all ecosystems
func (h *Hunter) Scan(ctx context.Context) (*ScanResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	start := time.Now()
	result := &ScanResult{
		ScanID:     fmt.Sprintf("scan-%d", time.Now().Unix()),
		Timestamp:  start,
		BySeverity: make(map[Severity]int),
		Ecosystems: []string{},
	}

	var allVulns []Vulnerability
	var errors []string

	// Scan Go dependencies
	if h.hasGoMod() {
		log.Println("[HUNTER] Scanning Go dependencies...")
		result.Ecosystems = append(result.Ecosystems, "go")
		vulns, err := h.scanGo(ctx)
		if err != nil {
			errors = append(errors, fmt.Sprintf("go: %v", err))
		} else {
			allVulns = append(allVulns, vulns...)
		}
	}

	// Scan NPM dependencies
	if h.hasPackageJSON() {
		log.Println("[HUNTER] Scanning NPM dependencies...")
		result.Ecosystems = append(result.Ecosystems, "npm")
		vulns, err := h.scanNPM(ctx)
		if err != nil {
			errors = append(errors, fmt.Sprintf("npm: %v", err))
		} else {
			allVulns = append(allVulns, vulns...)
		}
	}

	// Scan Python dependencies
	if h.hasPythonRequirements() {
		log.Println("[HUNTER] Scanning Python dependencies...")
		result.Ecosystems = append(result.Ecosystems, "pip")
		vulns, err := h.scanPython(ctx)
		if err != nil {
			errors = append(errors, fmt.Sprintf("pip: %v", err))
		} else {
			allVulns = append(allVulns, vulns...)
		}
	}

	// Enrich with threat intelligence and generate remediation plans
	for i := range allVulns {
		// Enrich with threat intel (CISA KEV, NVD, InTheWild, etc.)
		h.intelManager.EnrichVulnerability(&allVulns[i])

		// Generate remediation plan
		allVulns[i].RemediationPlan = h.generateRemediationPlan(&allVulns[i])
		result.BySeverity[allVulns[i].Severity]++

		// Callback for AGI integration
		if h.OnVulnDiscovered != nil {
			h.OnVulnDiscovered(allVulns[i])
		}
	}

	result.Vulnerabilities = allVulns
	result.TotalVulns = len(allVulns)
	result.Duration = time.Since(start)
	result.Errors = errors

	h.lastScan = result
	return result, nil
}

// hasGoMod checks if go.mod exists
func (h *Hunter) hasGoMod() bool {
	_, err := os.Stat(filepath.Join(h.rootPath, "go.mod"))
	return err == nil
}

// hasPackageJSON checks if package.json exists
func (h *Hunter) hasPackageJSON() bool {
	_, err := os.Stat(filepath.Join(h.rootPath, "package.json"))
	return err == nil
}

// hasPythonRequirements checks for requirements.txt or pyproject.toml
func (h *Hunter) hasPythonRequirements() bool {
	if _, err := os.Stat(filepath.Join(h.rootPath, "requirements.txt")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(h.rootPath, "pyproject.toml")); err == nil {
		return true
	}
	return false
}

// scanGo uses govulncheck to find Go vulnerabilities
func (h *Hunter) scanGo(ctx context.Context) ([]Vulnerability, error) {
	// First, try using govulncheck (official Go tool)
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = h.rootPath

	output, err := cmd.Output()
	if err != nil {
		// Fallback: parse go.mod and check against OSV database
		return h.scanGoOSV(ctx)
	}

	return h.parseGovulncheckOutput(output)
}

// scanGoOSV scans Go dependencies against the OSV database
func (h *Hunter) scanGoOSV(ctx context.Context) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Read go.mod
	goModPath := filepath.Join(h.rootPath, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	// Parse module dependencies
	deps := parseGoModDeps(string(data))

	// Query OSV API for each dependency
	for _, dep := range deps {
		osvVulns, err := h.queryOSV(ctx, "Go", dep.Name, dep.Version)
		if err != nil {
			log.Printf("[HUNTER] OSV query failed for %s: %v", dep.Name, err)
			continue
		}
		vulns = append(vulns, osvVulns...)
	}

	return vulns, nil
}

// Dependency represents a parsed dependency
type Dependency struct {
	Name    string
	Version string
}

// parseGoModDeps extracts dependencies from go.mod content
func parseGoModDeps(content string) []Dependency {
	var deps []Dependency
	scanner := bufio.NewScanner(strings.NewReader(content))
	inRequire := false

	// Regex for parsing dependency lines
	depRegex := regexp.MustCompile(`^\s*([^\s]+)\s+v?([^\s]+)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			// Single-line require
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				deps = append(deps, Dependency{
					Name:    parts[1],
					Version: strings.TrimPrefix(parts[2], "v"),
				})
			}
			continue
		}
		if inRequire {
			matches := depRegex.FindStringSubmatch(line)
			if len(matches) >= 3 {
				deps = append(deps, Dependency{
					Name:    matches[1],
					Version: strings.TrimPrefix(matches[2], "v"),
				})
			}
		}
	}

	return deps
}

// scanNPM uses npm audit to find vulnerabilities
func (h *Hunter) scanNPM(ctx context.Context) ([]Vulnerability, error) {
	cmd := exec.CommandContext(ctx, "npm", "audit", "--json")
	cmd.Dir = h.rootPath

	output, err := cmd.Output()
	// npm audit returns exit code 1 if vulnerabilities found, which is expected
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("npm audit failed: %w", err)
	}

	return h.parseNPMAuditOutput(output)
}

// parseNPMAuditOutput parses npm audit JSON output
func (h *Hunter) parseNPMAuditOutput(output []byte) ([]Vulnerability, error) {
	var auditResult struct {
		Vulnerabilities map[string]struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Via      []interface{} `json:"via"`
			Range    string `json:"range"`
			FixAvailable interface{} `json:"fixAvailable"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(output, &auditResult); err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	for name, v := range auditResult.Vulnerabilities {
		vuln := Vulnerability{
			ID:           fmt.Sprintf("NPM-%s", name),
			Package:      name,
			Ecosystem:    "npm",
			Severity:     mapNPMSeverity(v.Severity),
			AffectedRange: v.Range,
			DiscoveredAt: time.Now(),
			Metadata:     make(map[string]string),
		}

		// Extract CVE/GHSA from via array
		for _, via := range v.Via {
			if viaMap, ok := via.(map[string]interface{}); ok {
				if source, ok := viaMap["source"].(string); ok {
					vuln.ID = source
				}
				if title, ok := viaMap["title"].(string); ok {
					vuln.Title = title
				}
				if url, ok := viaMap["url"].(string); ok {
					vuln.References = append(vuln.References, url)
				}
			}
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// mapNPMSeverity maps npm severity strings to our Severity type
func mapNPMSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "moderate", "medium":
		return SeverityModerate
	default:
		return SeverityLow
	}
}

// scanPython uses pip-audit or safety to find vulnerabilities
func (h *Hunter) scanPython(ctx context.Context) ([]Vulnerability, error) {
	// Try pip-audit first
	cmd := exec.CommandContext(ctx, "pip-audit", "--format", "json")
	cmd.Dir = h.rootPath

	output, err := cmd.Output()
	if err != nil {
		// Fallback to safety
		return h.scanPythonSafety(ctx)
	}

	return h.parsePipAuditOutput(output)
}

// scanPythonSafety uses the safety tool as fallback
func (h *Hunter) scanPythonSafety(ctx context.Context) ([]Vulnerability, error) {
	cmd := exec.CommandContext(ctx, "safety", "check", "--json")
	cmd.Dir = h.rootPath

	output, err := cmd.Output()
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("python vulnerability scan failed: %w", err)
	}

	// Parse safety output
	var vulns []Vulnerability
	// Safety JSON parsing would go here
	return vulns, nil
}

// parsePipAuditOutput parses pip-audit JSON output
func (h *Hunter) parsePipAuditOutput(output []byte) ([]Vulnerability, error) {
	var auditResult []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vulns   []struct {
			ID          string   `json:"id"`
			Description string   `json:"description"`
			FixVersions []string `json:"fix_versions"`
		} `json:"vulns"`
	}

	if err := json.Unmarshal(output, &auditResult); err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	for _, pkg := range auditResult {
		for _, v := range pkg.Vulns {
			fixVersion := ""
			if len(v.FixVersions) > 0 {
				fixVersion = v.FixVersions[0]
			}

			vulns = append(vulns, Vulnerability{
				ID:           v.ID,
				Package:      pkg.Name,
				Ecosystem:    "pip",
				Severity:     SeverityModerate, // pip-audit doesn't always include severity
				Description:  v.Description,
				FixedVersion: fixVersion,
				DiscoveredAt: time.Now(),
			})
		}
	}

	return vulns, nil
}

// parseGovulncheckOutput parses govulncheck JSON output
func (h *Hunter) parseGovulncheckOutput(output []byte) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// govulncheck outputs newline-delimited JSON
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		var entry struct {
			OSV struct {
				ID      string `json:"id"`
				Summary string `json:"summary"`
				Details string `json:"details"`
			} `json:"osv"`
			Modules []struct {
				Path    string `json:"path"`
				Version string `json:"version"`
				FixedIn string `json:"fixed_in"`
			} `json:"modules"`
		}

		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		if entry.OSV.ID == "" {
			continue
		}

		for _, mod := range entry.Modules {
			vulns = append(vulns, Vulnerability{
				ID:           entry.OSV.ID,
				Package:      mod.Path,
				Ecosystem:    "go",
				Severity:     SeverityModerate, // Would need to query for actual severity
				Title:        entry.OSV.Summary,
				Description:  entry.OSV.Details,
				FixedVersion: mod.FixedIn,
				DiscoveredAt: time.Now(),
			})
		}
	}

	return vulns, nil
}

// OSVQuery represents a request to the OSV API
type OSVQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// queryOSV queries the Open Source Vulnerability database
func (h *Hunter) queryOSV(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error) {
	query := OSVQuery{Version: version}
	query.Package.Name = pkg
	query.Package.Ecosystem = ecosystem

	jsonData, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/query", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Details  string `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Affected []struct {
				Ranges []struct {
					Events []struct {
						Fixed string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		} `json:"vulns"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	for _, v := range result.Vulns {
		vuln := Vulnerability{
			ID:          v.ID,
			Package:     pkg,
			Ecosystem:   strings.ToLower(ecosystem),
			Title:       v.Summary,
			Description: v.Details,
			DiscoveredAt: time.Now(),
		}

		// Extract severity
		for _, sev := range v.Severity {
			if sev.Type == "CVSS_V3" {
				vuln.Metadata = map[string]string{"cvss": sev.Score}
			}
		}

		// Extract fixed version
		for _, affected := range v.Affected {
			for _, r := range affected.Ranges {
				for _, event := range r.Events {
					if event.Fixed != "" {
						vuln.FixedVersion = event.Fixed
						break
					}
				}
			}
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// generateRemediationPlan creates an automated fix plan for a vulnerability
func (h *Hunter) generateRemediationPlan(v *Vulnerability) *RemediationPlan {
	plan := &RemediationPlan{
		Action:    "upgrade",
		RiskLevel: "low",
		Breaking:  false,
		Verified:  false,
	}

	switch v.Ecosystem {
	case "go":
		if v.FixedVersion != "" {
			plan.TargetVersion = v.FixedVersion
			plan.Commands = []string{
				fmt.Sprintf("go get %s@v%s", v.Package, v.FixedVersion),
				"go mod tidy",
				"go mod vendor",
			}
		} else {
			plan.Action = "investigate"
			plan.RiskLevel = "medium"
			plan.Commands = []string{
				fmt.Sprintf("# No fixed version available for %s", v.Package),
				"# Consider finding an alternative package",
			}
		}

	case "npm":
		if v.FixedVersion != "" {
			plan.TargetVersion = v.FixedVersion
			plan.Commands = []string{
				fmt.Sprintf("npm update %s", v.Package),
				"npm audit fix",
			}
		} else {
			plan.Commands = []string{
				"npm audit fix --force",
			}
			plan.RiskLevel = "medium"
			plan.Breaking = true
		}

	case "pip":
		if v.FixedVersion != "" {
			plan.TargetVersion = v.FixedVersion
			plan.Commands = []string{
				fmt.Sprintf("pip install --upgrade %s>=%s", v.Package, v.FixedVersion),
				"pip freeze > requirements.txt",
			}
		}
	}

	return plan
}

// Remediate attempts to fix a vulnerability
func (h *Hunter) Remediate(ctx context.Context, v *Vulnerability) error {
	if v.RemediationPlan == nil {
		return fmt.Errorf("no remediation plan available")
	}

	log.Printf("[HUNTER] Remediating %s in %s (severity: %s)", v.ID, v.Package, v.Severity)

	for _, cmd := range v.RemediationPlan.Commands {
		if strings.HasPrefix(cmd, "#") {
			// Comment, skip
			continue
		}

		if h.dryRun {
			log.Printf("[HUNTER] DRY-RUN: %s", cmd)
			continue
		}

		// Execute the command
		parts := strings.Fields(cmd)
		if len(parts) == 0 {
			continue
		}

		execCmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
		execCmd.Dir = h.rootPath
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr

		if err := execCmd.Run(); err != nil {
			return fmt.Errorf("remediation command failed: %s: %w", cmd, err)
		}
	}

	// Callback
	if h.OnRemediationComplete != nil {
		h.OnRemediationComplete(*v, true)
	}

	return nil
}

// RemediateAll attempts to fix all vulnerabilities in the last scan
func (h *Hunter) RemediateAll(ctx context.Context) error {
	if h.lastScan == nil {
		return fmt.Errorf("no scan results available")
	}

	// Sort by severity - fix critical first
	criticalVulns := []Vulnerability{}
	highVulns := []Vulnerability{}
	otherVulns := []Vulnerability{}

	for _, v := range h.lastScan.Vulnerabilities {
		switch v.Severity {
		case SeverityCritical:
			criticalVulns = append(criticalVulns, v)
		case SeverityHigh:
			highVulns = append(highVulns, v)
		default:
			otherVulns = append(otherVulns, v)
		}
	}

	// Process in order
	allVulns := append(criticalVulns, highVulns...)
	allVulns = append(allVulns, otherVulns...)

	for i := range allVulns {
		if err := h.Remediate(ctx, &allVulns[i]); err != nil {
			log.Printf("[HUNTER] Remediation failed for %s: %v", allVulns[i].ID, err)
			// Continue with others
		}
	}

	return nil
}

// GetLastScan returns the results of the most recent scan
func (h *Hunter) GetLastScan() *ScanResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastScan
}

// Report generates a human-readable report of vulnerabilities
func (h *Hunter) Report() string {
	if h.lastScan == nil {
		return "No scan results available."
	}

	var sb strings.Builder
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("           SOUHIMBOU VULNERABILITY INTELLIGENCE REPORT\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("Scan ID:     %s\n", h.lastScan.ScanID))
	sb.WriteString(fmt.Sprintf("Timestamp:   %s\n", h.lastScan.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Duration:    %s\n", h.lastScan.Duration))
	sb.WriteString(fmt.Sprintf("Ecosystems:  %s\n\n", strings.Join(h.lastScan.Ecosystems, ", ")))

	sb.WriteString("SEVERITY BREAKDOWN:\n")
	sb.WriteString(fmt.Sprintf("  CRITICAL: %d\n", h.lastScan.BySeverity[SeverityCritical]))
	sb.WriteString(fmt.Sprintf("  HIGH:     %d\n", h.lastScan.BySeverity[SeverityHigh]))
	sb.WriteString(fmt.Sprintf("  MODERATE: %d\n", h.lastScan.BySeverity[SeverityModerate]))
	sb.WriteString(fmt.Sprintf("  LOW:      %d\n", h.lastScan.BySeverity[SeverityLow]))
	sb.WriteString(fmt.Sprintf("  TOTAL:    %d\n\n", h.lastScan.TotalVulns))

	if h.lastScan.TotalVulns > 0 {
		sb.WriteString("VULNERABILITIES:\n")
		sb.WriteString("───────────────────────────────────────────────────────────────\n")

		for _, v := range h.lastScan.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("\n[%s] %s\n", v.Severity, v.ID))
			sb.WriteString(fmt.Sprintf("  Package:  %s (%s)\n", v.Package, v.Ecosystem))
			if v.Title != "" {
				sb.WriteString(fmt.Sprintf("  Title:    %s\n", v.Title))
			}
			if v.FixedVersion != "" {
				sb.WriteString(fmt.Sprintf("  Fix:      Upgrade to %s\n", v.FixedVersion))
			}
			if v.RemediationPlan != nil {
				sb.WriteString(fmt.Sprintf("  Remediation: %s\n", v.RemediationPlan.Action))
			}
		}
	}

	sb.WriteString("\n═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

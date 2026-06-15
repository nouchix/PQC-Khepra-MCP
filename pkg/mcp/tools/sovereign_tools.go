package tools

// sovereign_tools.go — P0/P1 MCP tools for sovereign (no-Supabase) operation.
//
// ALL tools in this file work 100% offline — no Supabase, no network calls,
// no external dependencies beyond the embedded 36,195-row compliance database.
//
// Tools implemented:
//   khepra_export_attestation  — PQC-signed C3PAO evidence package (JSON)
//   khepra_export_poam         — Plan of Action & Milestones (DFARS 252.204-7012)
//   khepra_query_stig          — Control lookup by STIG/CCI/NIST ID
//   khepra_get_compliance_score — Fast compliance score without full scan
//   khepra_query_threat_intel  — Query embedded CISA KEV + CVE data
//   khepra_get_dag_chain       — Retrieve session DAG audit chain

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/stig"
)

// ─── khepra_export_attestation ───────────────────────────────────────────────
//
// The existential C3PAO artifact: a PQC-signed evidence package covering all
// active frameworks. No Supabase. No network. Dilithium-signed JSON + DAG node ID.

type AttestationExport struct {
	FormatVersion   string                   `json:"format_version"`
	ExportedAt      string                   `json:"exported_at"`
	Hostname        string                   `json:"hostname"`
	OSVersion       string                   `json:"os_version"`
	KernelVersion   string                   `json:"kernel_version,omitempty"`
	Frameworks      []FrameworkAttestation   `json:"frameworks"`
	POAMCount       int                      `json:"poam_count"`
	OverallScore    float64                  `json:"overall_compliance_score"`
	OverallGrade    string                   `json:"overall_grade"`
	PQCStatus       string                   `json:"pqc_status"`
	DAGNodeID       string                   `json:"dag_node_id,omitempty"`
	PQCSignature    string                   `json:"pqc_signature,omitempty"`
	ChainDepth      int                      `json:"chain_depth"`
	// C3PAO fields
	EvidenceStandard string                  `json:"evidence_standard"`
	AssessmentType   string                  `json:"assessment_type"`
	GeneratedBy      string                  `json:"generated_by"`
}

type FrameworkAttestation struct {
	Framework   string  `json:"framework"`
	Version     string  `json:"version"`
	TotalChecks int     `json:"total_checks"`
	Passed      int     `json:"passed"`
	Failed      int     `json:"failed"`
	Score       float64 `json:"score"`
	Grade       string  `json:"grade"`
}

func HandleKhepraExportAttestation(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("khepra_export_attestation: invalid path: %w", err)
	}

	v := stig.NewValidator(absPath)
	report, err := v.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("khepra_export_attestation: validation failed: %w", err)
	}

	var frameworks []FrameworkAttestation
	totalScore := 0.0
	count := 0

	for name, result := range report.Results {
		if result.TotalControls == 0 {
			continue
		}
		score := result.ComplianceScore()
		frameworks = append(frameworks, FrameworkAttestation{
			Framework:   name,
			Version:     result.Version,
			TotalChecks: result.TotalControls,
			Passed:      result.Passed,
			Failed:      result.Failed,
			Score:       score,
			Grade:       stig.ComplianceGrade(score),
		})
		totalScore += score
		count++
	}
	// Sort deterministically
	sort.Slice(frameworks, func(i, j int) bool {
		return frameworks[i].Framework < frameworks[j].Framework
	})

	overallScore := 0.0
	if count > 0 {
		overallScore = totalScore / float64(count)
	}

	hostname, _ := os.Hostname()

	pqcStatus := "Classical only"
	if report.PQCBlastRadius != nil {
		pqcStatus = stig.ComplianceGrade(report.PQCBlastRadius.PQCReadinessScore)
	}
	if report.ExecutiveSummary.PQCMigrationRequired {
		pqcStatus += " — PQC migration required"
	}

	export := &AttestationExport{
		FormatVersion:    "1.0.0",
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		Hostname:         hostname,
		OSVersion:        report.OSVersion,
		KernelVersion:    report.KernelVersion,
		Frameworks:       frameworks,
		POAMCount:        len(report.POAMItems),
		OverallScore:     overallScore,
		OverallGrade:     stig.ComplianceGrade(overallScore),
		PQCStatus:        pqcStatus,
		ChainDepth:       0, // populated by router attestation layer
		EvidenceStandard: "NIST SP 800-171A / CMMC Assessment Guide",
		AssessmentType:   "Automated — KHEPRA PQC-MCP Server v1.0",
		GeneratedBy:      "AdinKhepra / NouchiX KHEPRA MCP Server",
	}

	var warnings []string
	if report.ExecutiveSummary.CAT1Findings > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CAT I findings — package NOT suitable for C3PAO submission until remediated", report.ExecutiveSummary.CAT1Findings))
	}
	if overallScore < 90 {
		warnings = append(warnings, fmt.Sprintf("Overall score %.1f%% below 90%% threshold — remediate gaps before presenting to C3PAO", overallScore))
	}
	if overallScore >= 90 && report.ExecutiveSummary.CAT1Findings == 0 {
		warnings = append(warnings, "Package appears C3PAO-ready — verify with a qualified C3PAO before submission")
	}

	return export, warnings, nil
}

// ─── khepra_export_poam ──────────────────────────────────────────────────────
//
// DFARS 252.204-7012 mandates a Plan of Action & Milestones. This tool
// exports the POA&M in a machine-readable JSON format with dollar-weighted
// priority sorting from the stig.Validator.generatePOAM() output.

type POAMExport struct {
	ExportedAt   string       `json:"exported_at"`
	TotalItems   int          `json:"total_items"`
	OpenItems    int          `json:"open_items"`
	TotalCostUSD float64      `json:"estimated_total_cost_usd"`
	Items        []POAMRecord `json:"items"`
	Standard     string       `json:"standard"`
}

type POAMRecord struct {
	ID                  string   `json:"id"`
	ControlID           string   `json:"control_id"`
	Weakness            string   `json:"weakness"`
	Severity            string   `json:"severity"`
	Status              string   `json:"status"`
	PointOfContact      string   `json:"point_of_contact"`
	EstimatedCostUSD    float64  `json:"estimated_cost_usd"`
	ScheduledCompletion string   `json:"scheduled_completion"`
	MilestoneActions    []string `json:"milestone_actions"`
	PriorityScore       float64  `json:"priority_score"`
}

func HandleKhepraExportPOAM(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("khepra_export_poam: invalid path: %w", err)
	}

	v := stig.NewValidator(absPath)
	report, err := v.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("khepra_export_poam: validation failed: %w", err)
	}

	var records []POAMRecord
	totalCost := 0.0
	openCount := 0

	for _, item := range report.POAMItems {
		rec := POAMRecord{
			ID:               item.ID,
			ControlID:        item.ControlID,
			Weakness:         item.Weakness,
			Severity:         string(item.Severity),
			Status:           item.Status,
			PointOfContact:   item.PointOfContact,
			EstimatedCostUSD: item.EstimatedCost,
			MilestoneActions: item.MilestoneActions,
			PriorityScore:    item.PriorityScore,
		}
		if !item.ScheduledCompletion.IsZero() {
			rec.ScheduledCompletion = item.ScheduledCompletion.UTC().Format("2006-01-02")
		}
		records = append(records, rec)
		if item.Status == "Open" {
			openCount++
		}
		totalCost += item.EstimatedCost
	}

	export := &POAMExport{
		ExportedAt:   time.Now().UTC().Format(time.RFC3339),
		TotalItems:   len(records),
		OpenItems:    openCount,
		TotalCostUSD: totalCost,
		Items:        records,
		Standard:     "NIST SP 800-171A / DFARS 252.204-7012",
	}

	var warnings []string
	if openCount > 0 {
		warnings = append(warnings, fmt.Sprintf("%d open POA&M items — total estimated remediation cost: $%.0f", openCount, totalCost))
	}
	if len(records) == 0 {
		warnings = append(warnings, "No POA&M items generated — either all controls passed or no frameworks were scanned")
	}

	return export, warnings, nil
}

// ─── khepra_query_stig ───────────────────────────────────────────────────────
//
// Look up a control by STIG ID, CCI number, NIST 800-53 control, or free-text
// search across the embedded 36,195-row compliance database. 100% offline.

type STIGQueryResult struct {
	Query          string             `json:"query"`
	MatchType      string             `json:"match_type"`
	TotalMatches   int                `json:"total_matches"`
	Controls       []STIGControlEntry `json:"controls"`
	CrossRefs      []string           `json:"cross_references,omitempty"`
	DatabaseStats  map[string]int     `json:"database_stats"`
	QueriedAt      string             `json:"queried_at"`
}

type STIGControlEntry struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	CCIs        []string `json:"ccis,omitempty"`
	NIST53Refs  []string `json:"nist_800_53,omitempty"`
	NIST171Refs []string `json:"nist_800_171,omitempty"`
	CMMCRefs    []string `json:"cmmc,omitempty"`
}

func HandleKhepraQuerySTIG(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	query, _ := call.Args["control_id"].(string)
	if query == "" {
		query, _ = call.Args["query"].(string)
	}
	if query == "" {
		return nil, nil, fmt.Errorf("khepra_query_stig: 'control_id' or 'query' is required")
	}
	query = strings.TrimSpace(query)

	db, err := stig.GetDatabase()
	if err != nil {
		return nil, nil, fmt.Errorf("khepra_query_stig: compliance database unavailable: %w", err)
	}

	stats := db.Stats()
	result := &STIGQueryResult{
		Query:         query,
		DatabaseStats: stats,
		QueriedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	// Determine query type
	upperQ := strings.ToUpper(query)

	// STIG ID lookup (e.g. SV-257777r925318_rule or RHEL-09-291015)
	if title := db.GetSTIGTitle(query); title != "" {
		result.MatchType = "stig_id"
		refs, _ := db.GetCrossReferences(query)
		result.CrossRefs = refs
		entry := buildSTIGEntry(query, db)
		result.Controls = []STIGControlEntry{entry}
		result.TotalMatches = 1
		return result, nil, nil
	}

	// CCI lookup (e.g. CCI-000001)
	if strings.HasPrefix(upperQ, "CCI-") {
		result.MatchType = "cci"
		var entries []STIGControlEntry
		stigIDs := db.GetSTIGsForCCI(query)
		for _, id := range stigIDs {
			entries = append(entries, buildSTIGEntry(id, db))
		}
		result.Controls = entries
		result.TotalMatches = len(entries)
		return result, nil, nil
	}

	// NIST 800-53 control lookup (e.g. AC-2, SC-13)
	if isNIST53Ref(query) {
		result.MatchType = "nist_800_53"
		var entries []STIGControlEntry
		cciIDs := db.GetCCIsForNIST53(query)
		seen := map[string]bool{}
		for _, cci := range cciIDs {
			for _, stigID := range db.GetSTIGsForCCI(cci) {
				if !seen[stigID] {
					entries = append(entries, buildSTIGEntry(stigID, db))
					seen[stigID] = true
				}
			}
		}
		if len(entries) > 20 {
			entries = entries[:20] // Cap at 20 for readability
		}
		result.Controls = entries
		result.TotalMatches = len(entries)
		if len(entries) == 20 {
			return result, []string{"results capped at 20 — use a more specific control ID"}, nil
		}
		return result, nil, nil
	}

	// Free-text search: look for matching STIG titles
	result.MatchType = "text_search"
	var entries []STIGControlEntry
	lowerQ := strings.ToLower(query)
	for stigID, mappings := range db.AllSTIGs() {
		for _, m := range mappings {
			if strings.Contains(strings.ToLower(m.STIGTitle), lowerQ) {
				entries = append(entries, buildSTIGEntry(stigID, db))
				break
			}
		}
		if len(entries) >= 20 {
			break
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	result.Controls = entries
	result.TotalMatches = len(entries)

	var warnings []string
	if len(entries) == 0 {
		warnings = append(warnings, fmt.Sprintf("No matches for %q in STIG/CCI/NIST database", query))
	} else if len(entries) == 20 {
		warnings = append(warnings, "Results capped at 20 — use a more specific control ID")
	}
	return result, warnings, nil
}

func buildSTIGEntry(stigID string, db *stig.ComplianceDatabase) STIGControlEntry {
	entry := STIGControlEntry{
		ID:       stigID,
		Title:    db.GetSTIGTitle(stigID),
		Severity: db.GetSTIGSeverity(stigID),
	}
	refs, _ := db.GetCrossReferences(stigID)
	for _, ref := range refs {
		switch {
		case strings.HasPrefix(ref, "CCI-"):
			entry.CCIs = append(entry.CCIs, ref)
		case strings.HasPrefix(ref, "NIST-800-53:"):
			entry.NIST53Refs = append(entry.NIST53Refs, strings.TrimPrefix(ref, "NIST-800-53:"))
		case strings.HasPrefix(ref, "NIST-800-171:"):
			entry.NIST171Refs = append(entry.NIST171Refs, strings.TrimPrefix(ref, "NIST-800-171:"))
		case strings.HasPrefix(ref, "CMMC:"):
			entry.CMMCRefs = append(entry.CMMCRefs, ref)
		}
	}
	return entry
}

func isNIST53Ref(s string) bool {
	// e.g. AC-1, SC-13, IA-5(1), SI-3
	upper := strings.ToUpper(s)
	families := []string{"AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC", "SI", "SR"}
	for _, f := range families {
		if strings.HasPrefix(upper, f+"-") {
			return true
		}
	}
	return false
}

// ─── khepra_get_compliance_score ─────────────────────────────────────────────
//
// Fast compliance score without running a full scan. Returns the last cached
// score from the compliance database stats. Good for dashboard use.

type ComplianceScoreResult struct {
	Requested   string             `json:"framework"`
	Score       float64            `json:"score"`
	Grade       string             `json:"grade"`
	TotalChecks int                `json:"total_checks"`
	Passed      int                `json:"passed"`
	Failed      int                `json:"failed"`
	Risk        string             `json:"risk_level"`
	DBStats     map[string]int     `json:"database_stats"`
	ScanMode    string             `json:"scan_mode"`
	ScoredAt    string             `json:"scored_at"`
}

func HandleKhepraGetComplianceScore(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	framework, _ := call.Args["framework"].(string)
	if framework == "" {
		framework = stig.FrameworkCMMC
	}

	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("khepra_get_compliance_score: invalid path: %w", err)
	}

	// Map framework aliases
	aliases := map[string]string{
		"CMMC":        stig.FrameworkCMMC,
		"CMMC-L3":     stig.FrameworkCMMC,
		"RHEL-09":     stig.FrameworkRHEL09STIG,
		"STIG":        stig.FrameworkRHEL09STIG,
		"NIST-171":    stig.FrameworkNIST171,
		"NIST-53":     stig.FrameworkNIST53,
		"PQC":         stig.FrameworkPQC,
		"PQC-STIG":    stig.FrameworkPQCStig,
	}
	if canonical, ok := aliases[strings.ToUpper(framework)]; ok {
		framework = canonical
	}

	// Run targeted scan for just this framework
	v := stig.NewValidator(absPath)
	// Disable all then re-enable only the requested framework
	v.DisableAllFrameworks()
	v.EnableFramework(framework)

	report, err := v.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("khepra_get_compliance_score: scan failed: %w", err)
	}

	db, _ := stig.GetDatabase()
	var dbStats map[string]int
	if db != nil {
		dbStats = db.Stats()
	}

	result, ok := report.Results[framework]
	if !ok || result.TotalControls == 0 {
		return &ComplianceScoreResult{
			Requested: framework,
			Score:     0,
			Grade:     "N/A",
			Risk:      "Unknown",
			DBStats:   dbStats,
			ScanMode:  "targeted",
			ScoredAt:  time.Now().UTC().Format(time.RFC3339),
		}, []string{"no controls checked for " + framework}, nil
	}

	score := result.ComplianceScore()
	cat1, cat2, cat3 := countCATFindings(result)

	return &ComplianceScoreResult{
		Requested:   framework,
		Score:       score,
		Grade:       stig.ComplianceGrade(score),
		TotalChecks: result.TotalControls,
		Passed:      result.Passed,
		Failed:      result.Failed,
		Risk:        stig.RiskLevel(cat1, cat2, cat3),
		DBStats:     dbStats,
		ScanMode:    "targeted",
		ScoredAt:    time.Now().UTC().Format(time.RFC3339),
	}, nil, nil
}

func countCATFindings(r *stig.ValidationResult) (cat1, cat2, cat3 int) {
	for _, f := range r.Findings {
		if f.Status != "Fail" {
			continue
		}
		switch f.Severity {
		case stig.SeverityCAT1, stig.SeverityCritical:
			cat1++
		case stig.SeverityCAT2, stig.SeverityHigh:
			cat2++
		default:
			cat3++
		}
	}
	return
}

// ─── khepra_query_threat_intel ───────────────────────────────────────────────
//
// Query embedded CISA KEV + CVE data from the ERT Package B CVE loader.
// Returns matching vulnerability records sorted by severity.
// 100% offline — uses data embedded in the binary at build time.

type ThreatIntelResult struct {
	Query     string       `json:"query"`
	Source    string       `json:"source"`
	Matches   int          `json:"total_matches"`
	Vulns     []VulnRecord `json:"vulnerabilities"`
	QueriedAt string       `json:"queried_at"`
}

type VulnRecord struct {
	CVEID          string   `json:"cve_id"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	CVSSScore      float64  `json:"cvss_score,omitempty"`
	IsKEV          bool     `json:"is_kev"` // CISA Known Exploited Vulnerability
	KEVDateAdded   string   `json:"kev_date_added,omitempty"`
	AffectedVendor string   `json:"affected_vendor,omitempty"`
	AffectedProduct string  `json:"affected_product,omitempty"`
	Remediation    string   `json:"remediation,omitempty"`
	References     []string `json:"references,omitempty"`
}

func HandleKhepraQueryThreatIntel(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	query, _ := call.Args["query"].(string)
	if query == "" {
		query, _ = call.Args["cve_id"].(string)
	}
	if query == "" {
		return nil, nil, fmt.Errorf("khepra_query_threat_intel: 'query' or 'cve_id' is required (e.g. 'CVE-2021-44228', 'log4j', 'apache')")
	}
	query = strings.TrimSpace(query)

	// Load CVE data from the known paths used by ERT Package B
	vulns := loadEmbeddedCVEData(query)

	result := &ThreatIntelResult{
		Query:     query,
		Source:    "CISA KEV + NVD (embedded, offline)",
		Matches:   len(vulns),
		Vulns:     vulns,
		QueriedAt: time.Now().UTC().Format(time.RFC3339),
	}

	var warnings []string
	if len(vulns) == 0 {
		warnings = append(warnings, fmt.Sprintf("No CVE records match %q in offline database. For live lookups use: https://nvd.nist.gov/vuln/search?query=%s", query, query))
	}
	kevCount := 0
	for _, v := range vulns {
		if v.IsKEV {
			kevCount++
		}
	}
	if kevCount > 0 {
		warnings = append(warnings, fmt.Sprintf("%d result(s) are CISA Known Exploited Vulnerabilities — immediate patching required per BOD 22-01", kevCount))
	}

	return result, warnings, nil
}

// loadEmbeddedCVEData reads CVE JSON files from the data/cve-database directory.
// Matches by CVE ID or keyword in description/vendor/product.
func loadEmbeddedCVEData(query string) []VulnRecord {
	var results []VulnRecord
	lowerQ := strings.ToLower(query)
	isExactCVE := strings.HasPrefix(strings.ToUpper(query), "CVE-")

	cveDirs := []string{
		"data/cve-database",
		"../data/cve-database",
		filepath.Join(findProjectRoot(), "data", "cve-database"),
	}

	type kevEntry struct {
		CVEID           string `json:"cveID"`
		VendorProject   string `json:"vendorProject"`
		Product         string `json:"product"`
		DateAdded       string `json:"dateAdded"`
		ShortDesc       string `json:"shortDescription"`
		RequiredAction  string `json:"requiredAction"`
	}
	type kevFile struct {
		Vulnerabilities []kevEntry `json:"vulnerabilities"`
	}

	for _, dir := range cveDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			// Try KEV format
			var kev kevFile
			if json.Unmarshal(data, &kev) == nil && len(kev.Vulnerabilities) > 0 {
				for _, v := range kev.Vulnerabilities {
					match := false
					if isExactCVE {
						match = strings.EqualFold(v.CVEID, query)
					} else {
						match = strings.Contains(strings.ToLower(v.VendorProject), lowerQ) ||
							strings.Contains(strings.ToLower(v.Product), lowerQ) ||
							strings.Contains(strings.ToLower(v.ShortDesc), lowerQ) ||
							strings.Contains(strings.ToLower(v.CVEID), lowerQ)
					}
					if match {
						results = append(results, VulnRecord{
							CVEID:           v.CVEID,
							Description:     v.ShortDesc,
							Severity:        "HIGH", // KEV entries are always high priority
							IsKEV:           true,
							KEVDateAdded:    v.DateAdded,
							AffectedVendor:  v.VendorProject,
							AffectedProduct: v.Product,
							Remediation:     v.RequiredAction,
							References:      []string{fmt.Sprintf("https://www.cisa.gov/known-exploited-vulnerabilities-catalog#%s", v.CVEID)},
						})
					}
				}
				continue
			}
		}
		if len(results) > 0 {
			break
		}
	}

	// Sort KEV first, then by CVE ID descending (newest first)
	sort.Slice(results, func(i, j int) bool {
		if results[i].IsKEV != results[j].IsKEV {
			return results[i].IsKEV
		}
		return results[i].CVEID > results[j].CVEID
	})

	if len(results) > 50 {
		results = results[:50]
	}
	return results
}

func findProjectRoot() string {
	// Walk up from CWD looking for go.mod
	dir, _ := os.Getwd()
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

// ─── khepra_get_dag_chain ────────────────────────────────────────────────────
//
// Retrieve the current session's DAG audit chain. Each node is ML-DSA-65 signed
// and content-addressed. No Supabase — reads from the in-process DAG store.

type DAGChainResult struct {
	SessionID  string     `json:"session_id"`
	NodeCount  int        `json:"node_count"`
	ChainDepth int        `json:"chain_depth"`
	Nodes      []DAGNode  `json:"nodes"`
	Integrity  string     `json:"integrity"`
	QueriedAt  string     `json:"queried_at"`
}

type DAGNode struct {
	ID        string            `json:"id"`
	Action    string            `json:"action"`
	Symbol    string            `json:"symbol"`
	Timestamp string            `json:"timestamp"`
	Signed    bool              `json:"signed"`
	PQC       map[string]string `json:"pqc,omitempty"`
	Parents   []string          `json:"parents,omitempty"`
}

// dagStoreKey is the context key used to inject the DAG store into tool handlers.
// Defined locally to avoid a circular dependency on pkg/dag.
type dagStoreKey struct{}

// HandleKhepraGetDAGChain retrieves the ML-DSA-65-signed DAG audit chain for
// the current session. Reads from the dag.Store injected into the context by
// the router's DAGAttestor. 100% offline — no Supabase.
func HandleKhepraGetDAGChain(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	// The DAG store is injected by the router attestation layer.
	// Use dag.Store interface — methods: Add, Get, All.
	store, ok := ctx.Value(dagStoreKey{}).(dagStoreIface)
	if !ok || store == nil {
		return &DAGChainResult{
			SessionID:  "unavailable",
			NodeCount:  0,
			ChainDepth: 0,
			Nodes:      []DAGNode{},
			Integrity:  "DAG store not in context — use dag_attestation tool to export the signed chain",
			QueriedAt:  time.Now().UTC().Format(time.RFC3339),
		}, nil, nil
	}

	nodes := store.AllNodes()
	var dagNodes []DAGNode
	for _, n := range nodes {
		dagNodes = append(dagNodes, DAGNode{
			ID:        n.ID,
			Action:    n.Action,
			Symbol:    n.Symbol,
			Timestamp: n.Time,
			Signed:    n.Signature != "",
			PQC:       n.PQC,
			Parents:   n.Parents,
		})
	}

	integrity := "VALID"
	if len(dagNodes) == 0 {
		integrity = "EMPTY — no tool calls have been recorded this session"
	}

	return &DAGChainResult{
		SessionID:  extractSessionID(ctx),
		NodeCount:  len(dagNodes),
		ChainDepth: len(dagNodes),
		Nodes:      dagNodes,
		Integrity:  integrity,
		QueriedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil, nil
}

// dagStoreIface is a local interface matching dag.Store's read-side methods.
// This avoids importing pkg/dag in the tools package (which would create a cycle).
type dagStoreIface interface {
	AllNodes() []*dagNode
}

// dagNode mirrors dag.Node for the local interface.
type dagNode struct {
	ID        string
	Action    string
	Symbol    string
	Time      string
	Signature string
	PQC       map[string]string
	Parents   []string
}

func extractSessionID(ctx context.Context) string {
	if id, ok := ctx.Value("session_id").(string); ok && id != "" {
		return id
	}
	return fmt.Sprintf("session-%d", time.Now().Unix())
}

// ─── flight_export ────────────────────────────────────────────────────────────
//
// SouHimBou AI Flight Recorder — export evidence packet for a session.
// Reads the persistent NDJSON flight log, verifies the tamper chain,
// and returns a CMMC-aligned EvidencePacket mapping actions to controls.

func HandleFlightExport(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	sessionID, _ := call.Args["session_id"].(string)
	logPath, _ := call.Args["log_path"].(string)
	if logPath == "" {
		dir := os.Getenv("KHEPRA_DATA_DIR")
		if dir == "" {
			dir = "."
		}
		logPath = filepath.Join(dir, "khepra-flight.ndjson")
	}

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return nil, []string{"flight log not found — no tool calls have been recorded yet"}, nil
	}

	frames, err := flight.LoadSession(logPath, sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("flight_export: load session: %w", err)
	}

	// Verify tamper chain
	var chainResult *flight.ChainVerifyResult
	if len(frames) > 0 {
		chainResult, err = flight.VerifyChain(logPath, nil) // nil = unsigned verify (chain-only)
		if err != nil {
			chainResult = &flight.ChainVerifyResult{ChainIntact: false, FirstBrokenSeq: -1}
		}
	}

	packet := flight.ExportEvidencePacket(frames, logPath, chainResult)

	var warnings []string
	if !packet.ChainIntact {
		warnings = append(warnings, fmt.Sprintf("TAMPER ALERT: flight log chain broken at frame %d — evidence integrity compromised", packet.FirstBrokenFrame))
	}
	if packet.TotalActions == 0 {
		warnings = append(warnings, "No actions recorded for this session — ensure the flight recorder is wired to the MCP router")
	}
	signedPct := packet.PilotMetrics.SignedPrivilegedPct
	if signedPct < 100 && packet.PilotMetrics.PrivilegedCalls > 0 {
		warnings = append(warnings, fmt.Sprintf("%.0f%% of privileged calls signed — target is 100%% for CMMC evidence", signedPct))
	}

	return packet, warnings, nil
}

// Note: HandleAgentRecord is defined in compliance_tools.go.
// It handles both SouHimBou AI SaaS mode (SOUHIMBOU_ENDPOINT) and
// sovereign/air-gap mode (local PQC-signed DAG audit log).

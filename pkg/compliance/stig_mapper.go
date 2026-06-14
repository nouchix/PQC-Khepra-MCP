package compliance

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
)

// STIGRule represents a DISA STIG security control
type STIGRule struct {
	STIGID       string
	Title        string
	Severity     string
	CCIID        string
	STIGFile     string
	NIST53Ref    string   // From CCI mapping
	NIST171Refs  []string // From NIST 800-171 mapping
	CMMCControls []string // Derived from NIST 800-171
}

// ComplianceMapper holds the complete STIG→CCI→NIST 800-53→NIST 800-171→CMMC mapping chain
type ComplianceMapper struct {
	STIGRules       map[string]*STIGRule      // STIG_ID → Rule
	CCItoNIST53     map[string][]string       // CCI_ID → NIST 800-53 refs
	NIST53to171     map[string]string         // NIST 800-53 → NIST 800-171
	NIST171toCMMC   map[string]string         // NIST 800-171 → CMMC control
	ControlFamilies map[string]string         // NIST 800-171 → Family name
}

// NewComplianceMapper loads the full STIG-CMMC-NIST mapping chain
func NewComplianceMapper() *ComplianceMapper {
	cm := &ComplianceMapper{
		STIGRules:       make(map[string]*STIGRule),
		CCItoNIST53:     make(map[string][]string),
		NIST53to171:     make(map[string]string),
		NIST171toCMMC:   make(map[string]string),
		ControlFamilies: make(map[string]string),
	}

	// Load mapping files in sequence
	if err := cm.LoadSTIGCCIMap("docs/STIG_CCI_Map.csv"); err != nil {
		log.Printf("[COMPLIANCE] Failed to load STIG-CCI map: %v", err)
	}

	if err := cm.LoadCCItoNIST53("docs/CCI_to_NIST53.csv"); err != nil {
		log.Printf("[COMPLIANCE] Failed to load CCI-to-NIST53 map: %v", err)
	}

	if err := cm.LoadNIST53to171("docs/NIST53_to_171.csv"); err != nil {
		log.Printf("[COMPLIANCE] Failed to load NIST53-to-171 map: %v", err)
	}

	// Build NIST 800-171 to CMMC mapping (direct correspondence for Level 1-3)
	cm.buildNIST171toCMMCMap()

	log.Printf("[COMPLIANCE] Loaded %d STIG rules with full CMMC traceability", len(cm.STIGRules))

	return cm
}

// LoadSTIGCCIMap loads the STIG_CCI_Map.csv (28K+ STIG rules)
func (cm *ComplianceMapper) LoadSTIGCCIMap(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	// Skip header
	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) < 5 {
			continue
		}

		stigID := record[0]
		title := record[1]
		severity := record[2]
		cciID := record[3]
		stigFile := record[4]

		cm.STIGRules[stigID] = &STIGRule{
			STIGID:   stigID,
			Title:    title,
			Severity: severity,
			CCIID:    cciID,
			STIGFile: stigFile,
		}
	}

	return nil
}

// LoadCCItoNIST53 loads CCI_to_NIST53.csv mapping
func (cm *ComplianceMapper) LoadCCItoNIST53(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) < 2 {
			continue
		}

		cciID := record[0]
		nist53Ref := record[1]

		cm.CCItoNIST53[cciID] = append(cm.CCItoNIST53[cciID], nist53Ref)
	}

	return nil
}

// LoadNIST53to171 loads NIST53_to_171.csv mapping
func (cm *ComplianceMapper) LoadNIST53to171(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) < 3 {
			continue
		}

		nist171Ref := record[0]
		nist53Ref := record[1]
		family := record[2]

		cm.NIST53to171[nist53Ref] = nist171Ref
		cm.ControlFamilies[nist171Ref] = family
	}

	return nil
}

// =============================================================================
// CMMC 2.0 DOMAIN CODES
// Maps NIST 800-171 control family names to CMMC 2.0 domain abbreviations.
// =============================================================================
var CMMCDomainCode = map[string]string{
	"Access Control":                       "AC",
	"Awareness and Training":               "AT",
	"Audit and Accountability":             "AU",
	"Configuration Management":             "CM",
	"Identification and Authentication":    "IA",
	"Incident Response":                    "IR",
	"Maintenance":                          "MA",
	"Media Protection":                     "MP",
	"Personnel Security":                   "PS",
	"Physical Protection":                  "PE",
	"Risk Assessment":                      "RA",
	"Security Assessment":                  "CA",
	"System and Communications Protection": "SC",
	"System and Information Integrity":     "SI",
}

// CMMC Level 1 (17 practices) — the FCI-only subset of 800-171
var CMMCLevel1Practices = map[string]bool{
	"3.1.1": true, "3.1.2": true, "3.1.20": true, "3.1.22": true,
	"3.4.1": true, "3.4.2": true,
	"3.5.1": true, "3.5.2": true,
	"3.11.1": true, "3.11.2": true,
	"3.12.1": true, "3.12.2": true,
	"3.13.1": true, "3.13.2": true, "3.13.5": true,
	"3.14.1": true, "3.14.2": true, "3.14.6": true, "3.14.7": true,
}

// buildNIST171toCMMCMap creates NIST 800-171 → CMMC 2.0 practice mapping.
// Every 800-171 r2 control maps 1:1 to a CMMC Level 2 practice.
// Level 1 practices are a strict subset (17 of 110).
// Level 3 enhanced practices come from 800-172.
func (cm *ComplianceMapper) buildNIST171toCMMCMap() {
	// Map every 800-171 control to its CMMC L2 practice ID.
	// Format: "AC.L2-3.1.1" (domain.level-controlRef)
	for nist171, family := range cm.ControlFamilies {
		domain := CMMCDomainCode[family]
		if domain == "" {
			domain = "GEN"
		}

		// L1 practices get dual-mapped (they satisfy both L1 and L2)
		if CMMCLevel1Practices[nist171] {
			cm.NIST171toCMMC[nist171] = fmt.Sprintf("%s.L1-%s|%s.L2-%s", domain, nist171, domain, nist171)
		} else {
			cm.NIST171toCMMC[nist171] = fmt.Sprintf("%s.L2-%s", domain, nist171)
		}
	}
}

// MapSTIGtoCMMC traces a STIG finding through the entire compliance chain
func (cm *ComplianceMapper) MapSTIGtoCMMC(stigID string) (*STIGRule, error) {
	rule, ok := cm.STIGRules[stigID]
	if !ok {
		return nil, fmt.Errorf("STIG rule not found: %s", stigID)
	}

	// Trace CCI → NIST 800-53
	if nist53Refs, ok := cm.CCItoNIST53[rule.CCIID]; ok {
		if len(nist53Refs) > 0 {
			rule.NIST53Ref = nist53Refs[0]
		}
	}

	// Trace NIST 800-53 → NIST 800-171
	if nist171, ok := cm.NIST53to171[rule.NIST53Ref]; ok {
		rule.NIST171Refs = append(rule.NIST171Refs, nist171)
	}

	// Trace NIST 800-171 → CMMC
	for _, nist171 := range rule.NIST171Refs {
		if cmmc, ok := cm.NIST171toCMMC[nist171]; ok {
			rule.CMMCControls = append(rule.CMMCControls, cmmc)
		}
	}

	return rule, nil
}

// FindSTIGsByPort returns STIG rules relevant to a specific network port
func (cm *ComplianceMapper) FindSTIGsByPort(port int) []*STIGRule {
	var matches []*STIGRule

	// Port-based STIG matching (heuristic)
	portKeywords := map[int][]string{
		22:   {"SSH", "Secure Shell"},
		23:   {"Telnet"},
		80:   {"HTTP", "Web Server"},
		443:  {"HTTPS", "TLS", "SSL"},
		3389: {"RDP", "Remote Desktop"},
		3306: {"MySQL", "Database"},
		5432: {"PostgreSQL", "Database"},
		1433: {"SQL Server", "Database"},
	}

	keywords, ok := portKeywords[port]
	if !ok {
		return matches
	}

	for _, rule := range cm.STIGRules {
		for _, keyword := range keywords {
			if strings.Contains(rule.Title, keyword) || strings.Contains(rule.STIGFile, keyword) {
				matches = append(matches, rule)
				break
			}
		}
	}

	return matches
}

// GenerateCMMCScorecard evaluates real STIG/CCI findings through the full
// mapping chain and produces a per-practice compliance scorecard.
// failedSTIGs is a set of STIG IDs that failed validation.
func (cm *ComplianceMapper) GenerateCMMCScorecard(failedSTIGs map[string]bool) *CMMCScorecard {
	scorecard := &CMMCScorecard{
		Level:          2,
		TotalControls:  110,
		PassingCount:   0,
		FailingCount:   0,
		ControlStatus:  make(map[string]string),
		ControlGaps:    []string{},
		DomainScores:   make(map[string]*DomainScore),
	}

	// 1. Trace failed STIGs → CCI → NIST 800-53 to build the set of failed 800-53 controls
	failedNIST53 := make(map[string]bool)
	for stigID := range failedSTIGs {
		rule, ok := cm.STIGRules[stigID]
		if !ok {
			continue
		}
		if refs, ok := cm.CCItoNIST53[rule.CCIID]; ok {
			for _, ref := range refs {
				failedNIST53[ref] = true
			}
		}
	}

	// 2. For each 800-171 control, check if ANY of its underlying 800-53 refs failed
	for nist171, family := range cm.ControlFamilies {
		cmmcPractice := cm.NIST171toCMMC[nist171]
		if cmmcPractice == "" {
			continue
		}

		domain := CMMCDomainCode[family]
		if domain == "" {
			domain = "GEN"
		}

		// Initialize domain score tracker
		if scorecard.DomainScores[domain] == nil {
			scorecard.DomainScores[domain] = &DomainScore{
				Domain: domain,
				Family: family,
			}
		}
		ds := scorecard.DomainScores[domain]
		ds.Total++

		// Check if this 800-171 control has any failed underlying 800-53 controls
		failed := false
		for nist53, nist171Ref := range cm.NIST53to171 {
			if nist171Ref == nist171 && failedNIST53[nist53] {
				failed = true
				break
			}
		}

		if failed {
			scorecard.ControlStatus[cmmcPractice] = "FAILING"
			scorecard.FailingCount++
			scorecard.ControlGaps = append(scorecard.ControlGaps, fmt.Sprintf("%s (%s)", cmmcPractice, family))
			ds.Failing++
		} else {
			scorecard.ControlStatus[cmmcPractice] = "PASSING"
			scorecard.PassingCount++
			ds.Passing++
		}
	}

	return scorecard
}

// CMMCScorecard represents compliance status across the full CMMC 2.0 practice set.
type CMMCScorecard struct {
	Level         int                       `json:"level"`
	TotalControls int                       `json:"total_controls"`
	PassingCount  int                       `json:"passing_count"`
	FailingCount  int                       `json:"failing_count"`
	ControlStatus map[string]string         `json:"control_status"` // Practice → "PASSING" | "FAILING"
	ControlGaps   []string                  `json:"control_gaps"`
	DomainScores  map[string]*DomainScore   `json:"domain_scores"`
	SPRSScore     int                       `json:"sprs_score"` // Supplier Performance Risk System score (-203 to 110)
}

// SPRS severity weights by domain (CAT I = 5, CAT II = 3, CAT III = 1)
// Access Control and Identification domains carry the heaviest weight.
var SPRSDomainWeight = map[string]int{
	"AC": 5, // Access Control — CAT I
	"IA": 5, // Identification and Authentication — CAT I
	"SC": 5, // System and Communications Protection — CAT I
	"SI": 3, // System and Information Integrity — CAT II
	"AU": 3, // Audit and Accountability — CAT II
	"CM": 3, // Configuration Management — CAT II
	"IR": 3, // Incident Response — CAT II
	"RA": 3, // Risk Assessment — CAT II
	"CA": 3, // Security Assessment — CAT II
	"AT": 1, // Awareness and Training — CAT III
	"MA": 1, // Maintenance — CAT III
	"MP": 1, // Media Protection — CAT III
	"PE": 1, // Physical Protection — CAT III
	"PS": 1, // Personnel Security — CAT III
}

// ComputeSPRS calculates the NIST 800-171 DoD Assessment Methodology score.
// Perfect score is 110 (all 110 controls passing).
// Each failing control subtracts 1, 3, or 5 points depending on severity.
// Minimum possible score is -203.
func (sc *CMMCScorecard) ComputeSPRS() int {
	sc.SPRSScore = 110

	for _, ds := range sc.DomainScores {
		weight := SPRSDomainWeight[ds.Domain]
		if weight == 0 {
			weight = 1
		}
		sc.SPRSScore -= ds.Failing * weight
	}

	// Floor at -203 (theoretical minimum per DoD methodology)
	if sc.SPRSScore < -203 {
		sc.SPRSScore = -203
	}

	return sc.SPRSScore
}

// DomainScore tracks per-domain compliance within the scorecard.
type DomainScore struct {
	Domain  string  `json:"domain"`
	Family  string  `json:"family"`
	Total   int     `json:"total"`
	Passing int     `json:"passing"`
	Failing int     `json:"failing"`
	Score   float64 `json:"score"` // 0–100
}

// ComputeDomainScores calculates percentage scores for each domain.
func (sc *CMMCScorecard) ComputeDomainScores() {
	for _, ds := range sc.DomainScores {
		if ds.Total > 0 {
			ds.Score = float64(ds.Passing) / float64(ds.Total) * 100
		}
	}
}

// FormatScorecard generates markdown table of compliance status
func (sc *CMMCScorecard) FormatScorecard() string {
	sc.ComputeDomainScores()

	evaluated := sc.PassingCount + sc.FailingCount
	if evaluated == 0 {
		evaluated = sc.TotalControls
	}
	passingPct := float64(sc.PassingCount) / float64(evaluated) * 100
	failingPct := float64(sc.FailingCount) / float64(evaluated) * 100

	status := "NOT READY FOR CERTIFICATION"
	if passingPct >= 90 {
		status = "READY FOR CERTIFICATION"
	} else if passingPct >= 75 {
		status = "NEAR COMPLIANCE"
	}

	out := fmt.Sprintf(`### CMMC Level %d Assessment (%d Practices)

| Metric | Value |
|--------|-------|
| **Passing** | %d practices (%.0f%%) |
| **Failing** | %d practices (%.0f%%) |
| **Status** | %s |
| **Score** | %.1f/100 |

#### Domain Breakdown

| Domain | Family | Pass | Fail | Score |
|--------|--------|------|------|-------|
`,
		sc.Level,
		evaluated,
		sc.PassingCount, passingPct,
		sc.FailingCount, failingPct,
		status,
		passingPct,
	)

	for _, ds := range sc.DomainScores {
		out += fmt.Sprintf("| %s | %s | %d | %d | %.0f%% |\n",
			ds.Domain, ds.Family, ds.Passing, ds.Failing, ds.Score)
	}

	return out
}

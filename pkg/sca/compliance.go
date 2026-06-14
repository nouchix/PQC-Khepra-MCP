// Package sca — CMMC / NIST 800-171 Compliance Mapper
//
// Maps SCA vulnerability findings to CMMC control families using the
// CCI → NIST 800-53 → NIST 800-171 crosswalk (docs/CCI_to_NIST53.csv,
// docs/NIST53_to_171.csv, docs/NIST53_to_172.csv).
//
// SCA findings (unpatched vulnerabilities) directly implicate:
//   - RA-5   (Vulnerability Monitoring and Scanning) → NIST 171 3.11.2
//   - SI-2   (Flaw Remediation)                      → NIST 171 3.14.1
//   - CM-8   (System Component Inventory)             → NIST 171 3.4.1
//   - SA-11  (Developer Testing and Evaluation)       — referenced in 172
//   - SI-5   (Security Alerts and Advisories)         → NIST 171 3.14.3

package sca

import (
	"bufio"
	"encoding/csv"
	"io"
	"os"
	"strings"
	"sync"
)

// ──────────────────────────────────────────────────────────────────────────────
// Compliance Mapper
// ──────────────────────────────────────────────────────────────────────────────

// ComplianceMapper maps NIST 800-53 controls to NIST 800-171 requirements
// and CMMC domains, enabling audit-ready compliance tracing from every
// EnrichedFinding back to the applicable control framework.
type ComplianceMapper struct {
	// nist53to171 maps NIST 800-53 control → []NIST 800-171 requirement
	nist53to171 map[string][]string

	// nist53to172 maps NIST 800-53 control → []NIST 800-172 requirement (enhanced)
	nist53to172 map[string][]string

	// nist53toCCI maps NIST 800-53 control → []CCIEntry (CCI ID + definition)
	nist53toCCI map[string][]CCIEntry

	// nist171toDomain maps NIST 800-171 requirement → CMMC domain name
	nist171toDomain map[string]string

	mu sync.RWMutex
}

// CCIEntry represents a single CCI (Control Correlation Identifier) record.
// CCIs link NIST 800-53 controls to specific STIG implementation requirements.
type CCIEntry struct {
	CCIID      string `json:"cci_id"`     // e.g. "CCI-001643"
	Definition string `json:"definition"` // STIG requirement text
}

// SCAControlMapping defines which NIST 800-53 controls are directly implicated
// by SCA findings (vulnerabilities in software dependencies).
var SCAControlMapping = map[string]string{
	"RA-5":    "Vulnerability Monitoring and Scanning",
	"RA-5(2)": "Vulnerability Monitoring and Scanning — Update Vulnerabilities",
	"RA-5(5)": "Vulnerability Monitoring and Scanning — Privileged Access",
	"SI-2":    "Flaw Remediation",
	"SI-3":    "Malicious Code Protection",
	"SI-5":    "Security Alerts, Advisories, and Directives",
	"CM-8":    "System Component Inventory",
	"CM-8(1)": "System Component Inventory — Updates During Installation",
	"CM-4":    "Impact Analyses",
}

// NewComplianceMapper creates a new mapper. Optionally loads CSV crosswalk data.
func NewComplianceMapper() *ComplianceMapper {
	cm := &ComplianceMapper{
		nist53to171:     make(map[string][]string),
		nist53to172:     make(map[string][]string),
		nist53toCCI:     make(map[string][]CCIEntry),
		nist171toDomain: make(map[string]string),
	}
	// Initialize with hardcoded SCA-relevant mappings
	cm.initDefaults()
	return cm
}

// initDefaults loads the SCA-relevant NIST 800-53 → 171 mappings that we know
// apply to every vulnerability finding (so the mapper works even without CSV files).
func (cm *ComplianceMapper) initDefaults() {
	// From docs/NIST53_to_171.csv — SCA-relevant controls only
	defaults := map[string][]nist171Entry{
		"RA-5":    {{"3.11.2", "Risk Assessment"}, {"3.11.3", "Risk Assessment"}},
		"RA-5(2)": {{"3.11.2", "Risk Assessment"}},
		"RA-5(5)": {{"3.11.3", "Risk Assessment"}},
		"RA-3":    {{"3.11.1", "Risk Assessment"}},
		"RA-3(1)": {{"3.11.1", "Risk Assessment"}},
		"SI-2":    {{"3.14.1", "System and Information Integrity"}},
		"SI-3":    {{"3.14.2", "System and Information Integrity"}},
		"SI-3(1)": {{"3.14.2", "System and Information Integrity"}, {"3.14.5", "System and Information Integrity"}},
		"SI-5":    {{"3.14.3", "System and Information Integrity"}},
		"SI-4":    {{"3.14.6", "System and Information Integrity"}, {"3.14.7", "System and Information Integrity"}},
		"SI-6":    {{"3.14.5", "System and Information Integrity"}},
		"CM-8":    {{"3.4.1", "Configuration Management"}},
		"CM-8(1)": {{"3.4.1", "Configuration Management"}},
		"CM-4":    {{"3.4.3", "Configuration Management"}, {"3.4.4", "Configuration Management"}},
		"CM-6":    {{"3.4.2", "Configuration Management"}},
		"CM-7":    {{"3.4.6", "Configuration Management"}},
		"CA-2":    {{"3.12.1", "Security Assessment"}},
		"CA-5":    {{"3.12.2", "Security Assessment"}},
		"CA-7":    {{"3.12.2", "Security Assessment"}, {"3.12.3", "Security Assessment"}},
	}

	for nist53, entries := range defaults {
		for _, e := range entries {
			cm.nist53to171[nist53] = appendIfNew(cm.nist53to171[nist53], e.req)
			cm.nist171toDomain[e.req] = e.domain
		}
	}

	// NIST 800-172 enhanced controls relevant to SCA (from docs/NIST53_to_172.csv)
	defaults172 := map[string][]string{
		"SI-2(7)":  {"3.14.1e"},
		"SI-2(8)":  {"3.14.1e"},
		"RA-5(9)":  {"3.11.2e"},
		"RA-5(11)": {"3.11.2e"},
		"RA-3(1)":  {"3.11.1e"},
		"SI-4(24)": {"3.14.2e"},
		"SI-4(25)": {"3.14.2e"},
		"SI-7(15)": {"3.14.3e"},
		"SI-14":    {"3.14.4e"},
		"SI-14(1)": {"3.14.4e"},
		"CA-2(2)":  {"3.12.1e"},
		"CA-7(4)":  {"3.12.2e"},
		"RA-9":     {"3.11.3e"},
	}
	for nist53, reqs := range defaults172 {
		for _, req := range reqs {
			cm.nist53to172[nist53] = appendIfNew(cm.nist53to172[nist53], req)
		}
	}
}

type nist171Entry struct {
	req    string // e.g. "3.11.2"
	domain string // e.g. "Risk Assessment"
}

// LoadCSV loads the NIST 800-53 → 800-171 crosswalk from a CSV file.
// Expected format: NIST_171_Ref,NIST_53_Ref,Control_Family
func (cm *ComplianceMapper) LoadCSV(path string) error {
	return cm.loadCSVInto(path, false)
}

// LoadCSV172 loads the NIST 800-53 → 800-172 crosswalk from a CSV file.
// Expected format: NIST_172_Ref,NIST_53_Ref,Control_Family
func (cm *ComplianceMapper) LoadCSV172(path string) error {
	return cm.loadCSVInto(path, true)
}

// loadCSVInto is the shared CSV loader for both 171 and 172 mappings.
func (cm *ComplianceMapper) loadCSVInto(path string, is172 bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := csv.NewReader(bufio.NewReader(f))
	// Skip header
	if _, err := reader.Read(); err != nil {
		return err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // skip malformed rows
		}
		if len(record) < 3 {
			continue
		}

		nistReq := strings.TrimSpace(record[0])
		nist53 := strings.TrimSpace(record[1])
		domain := strings.TrimSpace(record[2])

		if is172 {
			cm.nist53to172[nist53] = appendIfNew(cm.nist53to172[nist53], nistReq)
		} else {
			cm.nist53to171[nist53] = appendIfNew(cm.nist53to171[nist53], nistReq)
			cm.nist171toDomain[nistReq] = domain
		}
	}

	return nil
}

// LoadCCICSV loads the CCI → NIST 800-53 crosswalk from a CSV file.
// Expected format: CCI_ID,NIST_53_Ref,Definition
// This builds a reverse index: NIST 53 control → []CCIEntry
func (cm *ComplianceMapper) LoadCCICSV(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := csv.NewReader(bufio.NewReader(f))
	reader.LazyQuotes = true // CCI CSV has complex quoting
	// Skip header
	if _, err := reader.Read(); err != nil {
		return err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	seen := make(map[string]bool) // deduplicate CCI IDs per control

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) < 3 {
			continue
		}

		cciID := strings.TrimSpace(record[0])
		nist53Raw := strings.TrimSpace(record[1])
		definition := strings.TrimSpace(record[2])

		// Normalize NIST 53 ref: "RA-5(2)" stays, "RA-5 a" → "RA-5"
		nist53 := normalizeNIST53Ref(nist53Raw)

		key := nist53 + ":" + cciID
		if seen[key] {
			continue
		}
		seen[key] = true

		cm.nist53toCCI[nist53] = append(cm.nist53toCCI[nist53], CCIEntry{
			CCIID:      cciID,
			Definition: definition,
		})
	}

	return nil
}

// normalizeNIST53Ref normalizes variant NIST 800-53 references.
// "RA-5(2)" → "RA-5(2)", "RA-5 a" → "RA-5", "AC-1 a.1 (a)" → "AC-1"
// "RA-5.1 (ii)" → "RA-5"
func normalizeNIST53Ref(ref string) string {
	ref = strings.TrimSpace(ref)

	// No space and no dot — check for attached parenthetical: "RA-5(2)", "CM-8(1)"
	spaceIdx := strings.IndexByte(ref, ' ')
	dotIdx := strings.IndexByte(ref, '.')
	parenIdx := strings.IndexByte(ref, '(')

	// If parenthetical comes BEFORE any space or dot, it's an enhancement: "RA-5(2)"
	if parenIdx > 0 {
		beforeSpace := spaceIdx < 0 || parenIdx < spaceIdx
		beforeDot := dotIdx < 0 || parenIdx < dotIdx
		if beforeSpace && beforeDot {
			if end := strings.IndexByte(ref[parenIdx:], ')'); end > 0 {
				return ref[:parenIdx+end+1]
			}
		}
	}

	// Find earliest delimiter (space or dot)
	cutIdx := -1
	if spaceIdx > 0 && dotIdx > 0 {
		if spaceIdx < dotIdx {
			cutIdx = spaceIdx
		} else {
			cutIdx = dotIdx
		}
	} else if spaceIdx > 0 {
		cutIdx = spaceIdx
	} else if dotIdx > 0 {
		cutIdx = dotIdx
	}

	if cutIdx > 0 {
		return ref[:cutIdx]
	}

	return ref
}

// ──────────────────────────────────────────────────────────────────────────────
// Mapping API
// ──────────────────────────────────────────────────────────────────────────────

// MapFinding applies CMMC compliance mapping to an EnrichedFinding.
// Every SCA finding (vulnerability in a dependency) maps to at minimum:
//   - RA-5 (vulnerability scanning) → 3.11.2
//   - SI-2 (flaw remediation) → 3.14.1
func (cm *ComplianceMapper) MapFinding(f *EnrichedFinding) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// SCA findings always implicate these NIST 800-53 controls
	scaControls := []string{"RA-5", "SI-2"}

	// If SBOM-generated, also implicate CM-8 (component inventory)
	for _, src := range f.Sources {
		if src == "grype" || src == "syft" {
			scaControls = appendIfNew(scaControls, "CM-8")
			break
		}
	}

	// If threat intel enriched, implicate SI-5 (security alerts)
	if f.InCISAKEV || f.InTheWild || f.EPSSScore > 0 {
		scaControls = appendIfNew(scaControls, "SI-5")
	}

	// Map NIST 800-53 → 800-171
	f.NIST53Controls = scaControls
	nist171 := make([]string, 0)
	nist172 := make([]string, 0)
	var domain string

	for _, ctrl := range scaControls {
		if reqs, ok := cm.nist53to171[ctrl]; ok {
			for _, req := range reqs {
				nist171 = appendIfNew(nist171, req)
				if d, ok := cm.nist171toDomain[req]; ok && domain == "" {
					domain = d
				}
			}
		}
		// Also check enhanced 172 controls
		if reqs, ok := cm.nist53to172[ctrl]; ok {
			for _, req := range reqs {
				nist172 = appendIfNew(nist172, req)
			}
		}
	}

	f.NIST171Controls = nist171
	f.NIST172Controls = nist172
	if domain != "" {
		f.CMMCDomain = domain
	}

	// Map CCI references from the matched NIST 800-53 controls
	var cciRefs []string
	var stigFindings []string
	for _, ctrl := range scaControls {
		if entries, ok := cm.nist53toCCI[ctrl]; ok {
			for _, e := range entries {
				cciRefs = appendIfNew(cciRefs, e.CCIID)
				// Keep first 3 STIG findings max to avoid bloat
				if len(stigFindings) < 3 {
					stigFindings = appendIfNew(stigFindings, e.Definition)
				}
			}
		}
	}
	f.CCIReferences = cciRefs
	f.STIGFindings = stigFindings
}

// MapFindings applies CMMC mapping to a batch of findings.
func (cm *ComplianceMapper) MapFindings(findings []EnrichedFinding) {
	for i := range findings {
		cm.MapFinding(&findings[i])
	}
}

// appendIfNew adds s to slice if not already present.
func appendIfNew(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

// Package stig — cklb_parser.go
//
// Parses STIG Viewer 2.x .cklb (JSON) checklist files.
//
// .cklb is the successor format to .ckl, introduced in DISA STIG Viewer 2.x.
// It is a JSON document with a top-level "STIGCKLB" key containing benchmark
// metadata and a flat "groups" array where each item represents one STIG rule
// with its assessment status and finding details.
//
// This parser handles two structural variants encountered in the wild:
//
//  1. Schema-canonical (per docs/intel-cuops/STIGCKLB.json):
//     { "STIGCKLB": { ..., "groups": [...] } }
//
//  2. Flat (STIG Viewer 2.17+ export):
//     { "title": "...", "stigs": [{ "stig": {...}, "checklist": [...] }] }
//
// Both variants are detected and parsed transparently.
//
// Status mapping (CKLB → stig.Finding.Status):
//
//	not_reviewed   → "Manual Review Required"
//	open           → "Fail"
//	not_a_finding  → "Pass"
//	not_applicable → "Not Applicable"
package stig

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ── Canonical STIGCKLB schema structs (STIGCKLB.json format) ─────────────────

type cklbDocument struct {
	STIGCKLB *cklbRoot `json:"STIGCKLB"`

	// Flat format fields (STIG Viewer 2.17+)
	Title      string        `json:"title"`
	TargetData *cklbTarget   `json:"targetData"`
	STIGs      []cklbStigSet `json:"stigs"`
}

type cklbRoot struct {
	ID          interface{} `json:"id"`
	BenchmarkID string      `json:"benchmarkId"`
	Slug        string      `json:"slug"`
	Status      string      `json:"status"`
	StatusDate  string      `json:"statusDate"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Version     string      `json:"version"`
	Groups      []cklbGroup `json:"groups"`
}

type cklbGroup struct {
	GroupID            string `json:"groupId"`
	RuleID             string `json:"ruleId"`
	RuleWeight         string `json:"ruleWeight"`
	RuleSeverity       string `json:"ruleSeverity"`
	RuleVersion        string `json:"ruleVersion"`
	RuleTitle          string `json:"ruleTitle"`
	RuleVulnDiscussion string `json:"ruleVulnDiscussion"`
	RuleFalsePositives string `json:"ruleFalsePositives"`
	RuleFalseNegatives string `json:"ruleFalseNegatives"`
	RuleDocumentable   string `json:"ruleDocumentable"`
	RuleMitigations    string `json:"ruleMitigations"`
	RuleIdent          string `json:"ruleIdent"` // "CCI-000048 CCI-000052" space-separated
	RuleFixText        string `json:"ruleFixText"`
	RuleFixID          string `json:"ruleFixId"`
	RuleCheckSystem    string `json:"ruleCheckSystem"`
	RuleCheckContent   string `json:"ruleCheckContent"`

	// Assessment fields (present in assessed .cklb files)
	Status               string `json:"status"`
	FindingDetails       string `json:"findingDetails"`
	Comments             string `json:"comments"`
	SeverityOverride     string `json:"severityOverride"`
	SeverityJustification string `json:"severityJustification"`
	CCIRef               []string `json:"cciRef"` // some versions use array
}

// ── Flat format structs (STIG Viewer 2.17+) ───────────────────────────────────

type cklbTarget struct {
	Name      string `json:"name"`
	IPAddress string `json:"ipAddress"`
	FQDN      string `json:"fqdn"`
	Role      string `json:"role"`
}

type cklbStigSet struct {
	Stig      cklbStigInfo      `json:"stig"`
	Checklist []cklbChecklistItem `json:"checklist"`
}

type cklbStigInfo struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	Release     string `json:"release"`
	BenchmarkID string `json:"benchmarkId"`
	FileName    string `json:"filename"`
}

type cklbChecklistItem struct {
	Vuln                  *cklbVulnDetail `json:"vuln"`
	Status                string          `json:"status"`
	FindingDetails        string          `json:"findingDetails"`
	Comments              string          `json:"comments"`
	SeverityOverride      string          `json:"severityOverride"`
	SeverityJustification string          `json:"severityJustification"`
}

type cklbVulnDetail struct {
	RuleID         string   `json:"ruleId"`
	GroupID        string   `json:"groupId"`
	GroupTitle     string   `json:"groupTitle"`
	RuleVersion    string   `json:"ruleVersion"`
	Severity       string   `json:"severity"`
	Weight         string   `json:"weight"`
	RuleTitle      string   `json:"ruleTitle"`
	VulnDiscussion string   `json:"vulnDiscussion"`
	CheckContent   string   `json:"checkContent"`
	FixText        string   `json:"fixText"`
	CCI            []string `json:"cci"`
}

// ── Import result ─────────────────────────────────────────────────────────────

// CKLBImportResult holds findings and metadata parsed from a .cklb file.
type CKLBImportResult struct {
	Hostname    string
	HostIP      string
	STIGTitle   string
	BenchmarkID string
	Version     string
	Findings    []Finding
}

// ── Public API ─────────────────────────────────────────────────────────────────

// ParseCKLBFile parses a STIG Viewer 2.x .cklb file at path.
func ParseCKLBFile(path string) ([]CKLBImportResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseCKLBBytes(data)
}

// ParseCKLBBytes parses .cklb JSON from a byte slice.
func ParseCKLBBytes(data []byte) ([]CKLBImportResult, error) {
	var doc cklbDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse CKLB JSON: %w", err)
	}

	// Detect which format variant we have.
	if doc.STIGCKLB != nil {
		return extractCanonicalCKLB(doc), nil
	}
	if len(doc.STIGs) > 0 {
		return extractFlatCKLB(doc), nil
	}
	return nil, fmt.Errorf("unrecognized CKLB structure: no STIGCKLB root and no stigs[] array")
}

// ── Canonical format extraction ───────────────────────────────────────────────

func extractCanonicalCKLB(doc cklbDocument) []CKLBImportResult {
	root := doc.STIGCKLB
	r := CKLBImportResult{
		STIGTitle:   root.Title,
		BenchmarkID: root.BenchmarkID,
		Version:     root.Version,
	}
	for _, g := range root.Groups {
		r.Findings = append(r.Findings, canonicalGroupToFinding(g))
	}
	return []CKLBImportResult{r}
}

func canonicalGroupToFinding(g cklbGroup) Finding {
	severity := mapCKLSeverity(coalesce(g.SeverityOverride, g.RuleSeverity))
	ccis := parseCKLBCCIs(g.RuleIdent, g.CCIRef)

	return Finding{
		ID:          coalesce(g.RuleID, g.GroupID),
		Title:       g.RuleTitle,
		Description: g.RuleVulnDiscussion,
		Severity:    severity,
		Status:      mapCKLBStatus(g.Status),
		Expected:    g.RuleCheckContent,
		Actual:      strings.TrimSpace(g.FindingDetails),
		Remediation: g.RuleFixText,
		References:  ccis,
		CheckedAt:   time.Now(),
	}
}

// ── Flat format extraction ────────────────────────────────────────────────────

func extractFlatCKLB(doc cklbDocument) []CKLBImportResult {
	var results []CKLBImportResult

	hostname := ""
	hostIP := ""
	if doc.TargetData != nil {
		hostname = strings.TrimSpace(doc.TargetData.Name)
		hostIP = strings.TrimSpace(doc.TargetData.IPAddress)
		if hostIP == "" {
			hostIP = strings.TrimSpace(doc.TargetData.FQDN)
		}
	}

	for _, ss := range doc.STIGs {
		r := CKLBImportResult{
			Hostname:    hostname,
			HostIP:      hostIP,
			STIGTitle:   ss.Stig.Title,
			BenchmarkID: ss.Stig.BenchmarkID,
			Version:     ss.Stig.Version + ss.Stig.Release,
		}
		for _, item := range ss.Checklist {
			r.Findings = append(r.Findings, flatChecklistItemToFinding(item, hostname, hostIP))
		}
		results = append(results, r)
	}
	return results
}

func flatChecklistItemToFinding(item cklbChecklistItem, hostname, hostIP string) Finding {
	v := item.Vuln
	if v == nil {
		return Finding{
			Status:    mapCKLBStatus(item.Status),
			Actual:    strings.TrimSpace(item.FindingDetails),
			CheckedAt: time.Now(),
		}
	}

	severity := mapCKLSeverity(coalesce(item.SeverityOverride, v.Severity))

	actual := strings.TrimSpace(item.FindingDetails)
	if actual == "" && hostname != "" {
		actual = fmt.Sprintf("Assessed on host: %s (%s)", hostname, hostIP)
	}

	return Finding{
		ID:          coalesce(v.RuleID, v.GroupID),
		Title:       v.RuleTitle,
		Description: v.VulnDiscussion,
		Severity:    severity,
		Status:      mapCKLBStatus(item.Status),
		Expected:    v.CheckContent,
		Actual:      actual,
		Remediation: v.FixText,
		References:  v.CCI,
		CheckedAt:   time.Now(),
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// mapCKLBStatus converts STIG Viewer 2.x status strings to stig.Finding.Status.
// CKLB uses lowercase_underscore; CKL uses PascalCase — handled separately.
func mapCKLBStatus(s string) string {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "open":
		return "Fail"
	case "not_a_finding", "notafinding":
		return "Pass"
	case "not_applicable":
		return "Not Applicable"
	case "not_reviewed":
		return "Manual Review Required"
	}
	return "Manual Review Required"
}

// parseCKLBCCIs extracts CCI identifiers from the ruleIdent string (space- or
// comma-separated) and merges with any explicit cciRef array.
func parseCKLBCCIs(ruleIdent string, cciRef []string) []string {
	seen := make(map[string]bool)
	var out []string

	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	// ruleIdent may be "CCI-000048 CCI-000052" or "CCI-000048,CCI-000052"
	for _, raw := range strings.FieldsFunc(ruleIdent, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';'
	}) {
		add(raw)
	}

	for _, c := range cciRef {
		add(c)
	}

	return out
}

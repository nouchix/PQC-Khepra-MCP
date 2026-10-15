// Package stig — ckl_parser.go
//
// Parses STIG Viewer .ckl (XML) checklist files exported by DISA STIG Viewer,
// Evaluate-STIG, or any SCAP-compliant tool that writes the standard DoD
// CHECKLIST XML format.
//
// A single .ckl file can contain one or more iSTIG sections, each covering a
// different STIG benchmark.  This parser extracts every VULN entry across all
// iSTIG sections and converts them to stig.Finding values ready for ingestion
// into ComplianceGraphModel.AddFinding().
//
// Status mapping (DISA → stig.Finding.Status):
//
//	Not_Reviewed → "Manual Review Required"
//	Open         → "Fail"
//	NotAFinding  → "Pass"
//	Not_Applicable → "Not Applicable"
package stig

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"
)

// ── XML schema structs ────────────────────────────────────────────────────────

type cklChecklist struct {
	XMLName xml.Name  `xml:"CHECKLIST"`
	Asset   cklAsset  `xml:"ASSET"`
	STIGs   cklSTIGs  `xml:"STIGS"`
}

type cklAsset struct {
	Role       string `xml:"ROLE"`
	AssetType  string `xml:"ASSET_TYPE"`
	HostName   string `xml:"HOST_NAME"`
	HostIP     string `xml:"HOST_IP"`
	HostMAC    string `xml:"HOST_MAC"`
	HostFQDN   string `xml:"HOST_FQDN"`
	TargetKey  string `xml:"TARGET_KEY"`
}

type cklSTIGs struct {
	ISTIGs []cklISTIG `xml:"iSTIG"`
}

type cklISTIG struct {
	STIGInfo cklSTIGInfo `xml:"STIG_INFO"`
	Vulns    []cklVuln   `xml:"VULN"`
}

type cklSTIGInfo struct {
	SIData []cklSIData `xml:"SI_DATA"`
}

type cklSIData struct {
	Name  string `xml:"SID_NAME"`
	Value string `xml:"SID_DATA"`
}

type cklVuln struct {
	STIGData            []cklSTIGData `xml:"STIG_DATA"`
	Status              string        `xml:"STATUS"`
	FindingDetails      string        `xml:"FINDING_DETAILS"`
	Comments            string        `xml:"COMMENTS"`
	SeverityOverride    string        `xml:"SEVERITY_OVERRIDE"`
}

type cklSTIGData struct {
	Attribute string `xml:"VULN_ATTRIBUTE"`
	Value     string `xml:"ATTRIBUTE_DATA"`
}

// ── CKL import result ─────────────────────────────────────────────────────────

// CKLImportResult holds findings and asset metadata parsed from a .ckl file.
type CKLImportResult struct {
	Hostname  string
	HostIP    string
	AssetType string
	STIGTitle string
	STIGFile  string
	Version   string
	Findings  []Finding
}

// ── Public API ─────────────────────────────────────────────────────────────────

// ParseCKLFile parses a STIG Viewer .ckl file at path and returns all findings
// across all iSTIG sections.  Each section in the .ckl produces its own
// CKLImportResult so the caller can attribute findings to the correct STIG benchmark.
func ParseCKLFile(path string) ([]CKLImportResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseCKLBytes(data)
}

// ParseCKLBytes parses .ckl XML from a byte slice.  Useful for testing.
func ParseCKLBytes(data []byte) ([]CKLImportResult, error) {
	var cl cklChecklist
	if err := xml.Unmarshal(data, &cl); err != nil {
		return nil, fmt.Errorf("parse CKL XML: %w", err)
	}
	return extractCKLResults(cl), nil
}

// ── Extraction ─────────────────────────────────────────────────────────────────

func extractCKLResults(cl cklChecklist) []CKLImportResult {
	var results []CKLImportResult
	for _, istig := range cl.STIGs.ISTIGs {
		info := extractSIData(istig.STIGInfo)
		r := CKLImportResult{
			Hostname:  strings.TrimSpace(cl.Asset.HostName),
			HostIP:    strings.TrimSpace(cl.Asset.HostIP),
			AssetType: strings.TrimSpace(cl.Asset.AssetType),
			STIGTitle: info["title"],
			STIGFile:  info["filename"],
			Version:   info["releaseinfo"],
		}
		for _, v := range istig.Vulns {
			f := extractCKLFinding(v, r.Hostname, r.HostIP)
			r.Findings = append(r.Findings, f)
		}
		results = append(results, r)
	}
	return results
}

// extractSIData converts the flat key-value SI_DATA list into a map.
func extractSIData(info cklSTIGInfo) map[string]string {
	m := make(map[string]string, len(info.SIData))
	for _, d := range info.SIData {
		m[strings.TrimSpace(d.Name)] = strings.TrimSpace(d.Value)
	}
	return m
}

// extractCKLFinding converts one <VULN> element to a stig.Finding.
func extractCKLFinding(v cklVuln, hostname, hostIP string) Finding {
	attrs := make(map[string]string, len(v.STIGData))
	var ccis []string
	for _, sd := range v.STIGData {
		key := strings.TrimSpace(sd.Attribute)
		val := strings.TrimSpace(sd.Value)
		if key == "CCI_REF" {
			ccis = append(ccis, val)
		} else {
			attrs[key] = val
		}
	}

	severity := mapCKLSeverity(coalesce(v.SeverityOverride, attrs["Severity"]))

	finding := Finding{
		ID:          coalesce(attrs["Rule_ID"], attrs["Vuln_Num"]),
		Title:       attrs["Rule_Title"],
		Description: attrs["Vuln_Discuss"],
		Severity:    severity,
		Status:      mapCKLStatus(v.Status),
		Expected:    attrs["Check_Content"],
		Actual:      strings.TrimSpace(v.FindingDetails),
		Remediation: attrs["Fix_Text"],
		References:  ccis,
		CheckedAt:   time.Now(),
	}

	// Append hostname/IP context to the finding details if present.
	if hostname != "" && finding.Actual == "" {
		finding.Actual = fmt.Sprintf("Assessed on host: %s (%s)", hostname, hostIP)
	}

	return finding
}

// ── Status and severity mapping ───────────────────────────────────────────────

// mapCKLStatus converts DISA STIG Viewer status strings to stig.Finding.Status.
func mapCKLStatus(s string) string {
	switch strings.TrimSpace(s) {
	case "Open":
		return "Fail"
	case "NotAFinding":
		return "Pass"
	case "Not_Applicable":
		return "Not Applicable"
	case "Not_Reviewed":
		return "Manual Review Required"
	}
	return "Manual Review Required"
}

// mapCKLSeverity converts .ckl severity strings to stig.Severity.
func mapCKLSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "cat i", "cat_i", "i":
		return SeverityCAT1
	case "medium", "cat ii", "cat_ii", "ii":
		return SeverityCAT2
	case "low", "cat iii", "cat_iii", "iii":
		return SeverityCAT3
	}
	return SeverityCAT2
}

// coalesce returns the first non-empty string.
func coalesce(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

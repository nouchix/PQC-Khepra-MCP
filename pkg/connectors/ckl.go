package connectors

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
)

// Checklist represents a DISA STIG Viewer .ckl file.
type Checklist struct {
	XMLName xml.Name `xml:"CHECKLIST"`
	Stigs   []Stig   `xml:"STIGS>iD"`
}

type Stig struct {
	Title string `xml:"STIG_TITLE"`
	Vulns []Vuln `xml:"VULN"`
}

type Vuln struct {
	StigID    string `xml:"STIG_DATA>VULN_ATTRIBUTE"` // Simplified
	RuleID    string // Typically extracted from attributes
	Status    string `xml:"STATUS"` // NotAFinding, Open
	FindingID string `xml:"FINDING_ID"`
	Comments  string `xml:"COMMENTS"`
}

// ParseCKL reads a DISA Checklist file.
// Note: real CKL parsing is nasty due to the key/value STIG_DATA structure.
// We implement a heuristic parser here for speed.
func ParseCKL(path string) ([]Vuln, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, _ := io.ReadAll(f)
	var cl Checklist
	if err := xml.Unmarshal(data, &cl); err != nil {
		return nil, fmt.Errorf("ckl parse error: %v", err)
	}

	var vulns []Vuln
	for _, stig := range cl.Stigs {
		for _, v := range stig.Vulns {
			// Flatten structure
			// In real usage, we traverse VULN_ATTRIBUTE to find Rule_ID and STIG_ID
			// For this MVP connector, we assume structure is populated or use regex fallback
			if v.Status == "Open" {
				vulns = append(vulns, v)
			}
		}
	}
	return vulns, nil
}

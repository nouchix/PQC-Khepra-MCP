package connectors

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
)

// NessusClientData represents a .nessus XML export.
// Compatible with Tenable.sc, Nessus Pro, and ACAS.
type NessusClientData struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Report  Report   `xml:"Report"`
}

type Report struct {
	Name       string       `xml:"name,attr"`
	ReportHost []ReportHost `xml:"ReportHost"`
}

type ReportHost struct {
	Name       string `xml:"name,attr"`
	ReportItem []ReportItem
}

type ReportItem struct {
	PluginID           string `xml:"pluginID,attr"`
	PluginName         string `xml:"pluginName,attr"`
	PluginFamily       string `xml:"pluginFamily,attr"`
	Severity           string `xml:"severity,attr"` // 0=Info, 1=Low, 2=Med, 3=High, 4=Critical
	Description        string `xml:"description"`
	Compliance         string `xml:"compliance"` // boolean-ish string in some exports
	CmComplianceInfo   string `xml:"cm:compliance-info"`
	CmComplianceActual string `xml:"cm:compliance-actual-value"`
	CmComplianceCheck  string `xml:"cm:compliance-check-id"`
}

// ParseNessus reads a .nessus file (XML).
func ParseNessus(path string) ([]ReportItem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, _ := io.ReadAll(f)
	var ncd NessusClientData
	if err := xml.Unmarshal(data, &ncd); err != nil {
		return nil, fmt.Errorf("nessus parse error: %v", err)
	}

	var items []ReportItem
	for _, rh := range ncd.Report.ReportHost {
		for _, ri := range rh.ReportItem {
			// Filter for Compliance (Audit) or Vulnerability
			// PluginFamily "Policy Compliance" is key for STIGs
			if ri.PluginFamily == "Policy Compliance" || ri.Severity == "3" || ri.Severity == "4" {
				items = append(items, ri)
			}
		}
	}
	return items, nil
}

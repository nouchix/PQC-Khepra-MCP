package arsenal

import (
	"encoding/json"
	"fmt"
	"os"
)

// SARIFReport represents a minimal structure of the Static Analysis Results Interchange Format.
// Supported (heuristically) by: MegaLinter, SpotBugs, CI Fuzz, CodeQL.
type SARIFReport struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleId  string `json:"ruleId"`
			Level   string `json:"level"` // error, warning
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						Uri string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// ParseSARIF parses a standard SARIF file.
// Used for MegaLinter, SpotBugs, CI Fuzz, etc.
func ParseSARIF(path string) (*SARIFReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("invalid SARIF json: %v", err)
	}

	return &report, nil
}

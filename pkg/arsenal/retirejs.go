package arsenal

import (
	"encoding/json"
	"fmt"
	"os"
)

type RetireJSFinding struct {
	File    string `json:"file"`
	Results []struct {
		Component       string `json:"component"`
		Version         string `json:"version"`
		Level           string `json:"level"` // e.g., "high"
		Vulnerabilities []struct {
			Info []string `json:"info"` // URLs often
		} `json:"vulnerabilities"`
	} `json:"results"`
}

// ParseRetireJS reads a Retire.js JSON report.
// Command: retire --outputformat json --outputpath retire.json
func ParseRetireJS(path string) ([]RetireJSFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// RetireJS output is sometimes an array of file objects
	var findings []RetireJSFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("invalid retirejs json: %v", err)
	}

	return findings, nil
}

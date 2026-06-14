package arsenal

import (
	"encoding/json"
	"fmt"
	"os"
)

// GitleaksFinding represents a single secret found by Gitleaks.
type GitleaksFinding struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
}

// ParseGitleaks reads a Gitleaks JSON report.
// Command: gitleaks detect --report=leaks.json -v
func ParseGitleaks(path string) ([]GitleaksFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var findings []GitleaksFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("invalid gitleaks json: %v", err)
	}

	return findings, nil
}

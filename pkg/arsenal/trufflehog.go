package arsenal

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// TruffleHogFinding represents a secret found by TruffleHog.
// Note: TruffleHog output is typically JSONL (newline delimited JSON).
type TruffleHogFinding struct {
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
			} `json:"Filesystem"`
			Git struct {
				File   string `json:"file"`
				Commit string `json:"commit"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`

	DetectorName string `json:"DetectorName"`
	Verified     bool   `json:"Verified"`
	Raw          string `json:"Raw"` // The secret itself
	Redacted     string `json:"Redacted"`
}

// ParseTruffleHog reads a TruffleHog JSON (or JSONL) report.
// Command: trufflehog filesystem . --json
func ParseTruffleHog(path string) ([]TruffleHogFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var findings []TruffleHogFinding

	// Try JSON Case (Array)
	if data[0] == '[' {
		if err := json.Unmarshal(data, &findings); err == nil {
			return findings, nil
		}
	}

	// Try JSONL Case (Line by Line)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var f TruffleHogFinding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 && len(data) > 0 {
		return nil, fmt.Errorf("parsed 0 trufflehog findings from non-empty file")
	}

	return findings, nil
}

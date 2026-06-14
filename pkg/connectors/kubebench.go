package connectors

import (
	"encoding/json"
	"fmt"
	"os"
)

// KubeBenchOutput represents the JSON output from aqua-security/kube-bench
type KubeBenchOutput struct {
	Controls []KubeControl `json:"Controls"`
}

type KubeControl struct {
	ID    string     `json:"id"`
	Tests []KubeTest `json:"tests"`
}

type KubeTest struct {
	Section string       `json:"section"`
	Results []KubeResult `json:"results"`
}

type KubeResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Audit       string `json:"audit"`
	Status      string `json:"status"` // PASS, FAIL, WARN
	ActualValue string `json:"actual_value"`
	IsMultiple  bool   `json:"is_multiple"`
}

// ParseKubeBench reads kube-bench JSON output.
func ParseKubeBench(path string) ([]KubeResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out KubeBenchOutput
	// Kube-bench structure varies wildly by version.
	// Sometimes it's a list, sometimes an object.
	// We handle the object case here.
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("kube-bench parse error: %v", err)
	}

	var failures []KubeResult
	for _, c := range out.Controls {
		for _, t := range c.Tests {
			for _, r := range t.Results {
				if r.Status == "FAIL" || r.Status == "WARN" {
					failures = append(failures, r)
				}
			}
		}
	}
	return failures, nil
}

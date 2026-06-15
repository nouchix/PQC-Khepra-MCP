// Package webapp provides web application scanning capabilities using Nuclei.
// This package is used by integration tests and requires a running test environment
// (docker compose -f docker/testbed/docker-compose.yml up -d).
//
// For integration test usage, see tests/integration/webapp_scan_test.go.
package webapp

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/types"
)

// Scanner runs Nuclei-based web application security scans.
type Scanner struct {
	toolsDir string
}

// ScanOptions configures a web scan run.
type ScanOptions struct {
	Severity []string
	Timeout  interface{} // time.Duration accepted at call sites
}

// New creates a Scanner that looks for Nuclei and other tools in toolsDir.
func New(toolsDir string) (*Scanner, error) {
	nuclei := filepath.Join(toolsDir, "nuclei")
	if _, err := exec.LookPath(nuclei); err != nil {
		// Fall back to PATH.
		if _, err := exec.LookPath("nuclei"); err != nil {
			return nil, fmt.Errorf("nuclei not found in %s or PATH: %w", toolsDir, err)
		}
	}
	return &Scanner{toolsDir: toolsDir}, nil
}

// DefaultScanOptions returns sensible defaults for most web scans.
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		Severity: []string{"critical", "high", "medium", "low", "info"},
	}
}

// NetworkScanOptions returns options for broader network + web scans.
func NetworkScanOptions() ScanOptions {
	return ScanOptions{
		Severity: []string{"critical", "high", "medium", "low"},
	}
}

// Scan executes a Nuclei scan against target and returns findings.
func (s *Scanner) Scan(ctx context.Context, target string, opts ScanOptions) ([]types.WebFinding, error) {
	// Nuclei integration — implementation requires docker testbed.
	// This stub satisfies the package import for go mod tidy;
	// the full implementation is used only during integration tests.
	return nil, fmt.Errorf("webapp.Scanner.Scan: not implemented in stub — run with docker testbed")
}

// UpdateTemplates updates Nuclei templates from the community repository.
func (s *Scanner) UpdateTemplates() {
	exec.Command("nuclei", "-update-templates").Run() //nolint:errcheck
}

// ScanSummary returns a map of severity → count from a slice of findings.
func ScanSummary(findings []types.WebFinding) map[string]int {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

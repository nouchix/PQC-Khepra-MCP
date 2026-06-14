package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/ert"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
)

// ─── ert_scan (Sandboxed) ──────────────────────────────────────────────────────
//
// Runs the full ERT pipeline: Syft (SBOM) → Grype (Vuln matching) → Enrichment
// (EPSS/KEV/InTheWild) → Report generation. This is a sandboxed tool because
// it processes potentially untrusted project files.
//
// Wiring: router → executor (RiskSandboxed) → SandboxManager → ert_scan
//         → Syft/Grype/Enricher → attest.Append() → attest.SignEnvelope()

// ERTScanTool wraps the ERT ScanOrchestrator for MCP exposure.
type ERTScanTool struct {
	orchestrator *ert.ScanOrchestrator
}

// NewERTScanTool creates an ert_scan tool backed by the given orchestrator.
func NewERTScanTool(orch *ert.ScanOrchestrator) *ERTScanTool {
	return &ERTScanTool{orchestrator: orch}
}

// ERTScanResponse is the structured output of the ert_scan tool.
type ERTScanResponse struct {
	ScanID       string                 `json:"scan_id"`
	ProjectPath  string                 `json:"project_path"`
	Duration     string                 `json:"duration"`
	Summary      ERTScanSummary         `json:"summary"`
	Findings     []ERTFindingSummary    `json:"findings,omitempty"`
	Errors       []string               `json:"errors,omitempty"`
	Timestamp    string                 `json:"timestamp"`
}

// ERTScanSummary provides aggregate scan metrics.
type ERTScanSummary struct {
	TotalFindings    int            `json:"total_findings"`
	BySeverity       map[string]int `json:"by_severity"`
	LanesExecuted    int            `json:"lanes_executed"`
	SecretsDetected  int            `json:"secrets_detected"`
}

// ERTFindingSummary is a safe projection of an ERT UnifiedFinding.
type ERTFindingSummary struct {
	ID          string  `json:"id"`
	Scanner     string  `json:"scanner"`
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	Asset       string  `json:"asset,omitempty"`
	CVE         string  `json:"cve,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	FixVersion  string  `json:"fix_version,omitempty"`
}

// Handle implements mcp.ToolHandler for ert_scan.
func (t *ERTScanTool) Handle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if t.orchestrator == nil {
		return nil, nil, fmt.Errorf("ert_scan: orchestrator not initialized")
	}

	// Extract parameters from the MCP tool call.
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}

	// Build a ScanRequest from the MCP args.
	req := ert.ScanRequest{
		TargetPath: projectPath,
		Timeout:    90 * time.Second,
	}

	// Optional: specific lanes.
	if lanesArg, ok := call.Args["lanes"].([]any); ok {
		for _, l := range lanesArg {
			if s, ok := l.(string); ok {
				req.Lanes = append(req.Lanes, ert.ScanLane(s))
			}
		}
	}

	// Optional: compliance framework.
	if fw, ok := call.Args["framework"].(string); ok {
		req.ComplianceFramework = fw
	}

	// Optional: container image ref.
	if imageRef, ok := call.Args["image_ref"].(string); ok && imageRef != "" {
		req.ImageRef = imageRef
		req.TargetPath = "" // Image mode overrides path mode.
	}

	// Execute the orchestrator.
	result, err := t.orchestrator.Execute(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("ert_scan: orchestrator failed: %w", err)
	}

	// Convert UnifiedFindings to safe MCP summaries.
	findings := make([]ERTFindingSummary, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, ERTFindingSummary{
			ID:          f.ID,
			Scanner:     f.Source,
			Category:    string(f.Category),
			Severity:    f.Severity,
			Title:       f.Title,
			Description: truncate(f.Description, 500),
			Asset:       f.Asset,
			CVE:         f.CVEID,
			CVSS:        f.CVSSv3,
			FixVersion:  f.FixedIn,
		})
	}

	// Prepare warnings.
	var warnings []string
	if result.Stats.CriticalCount > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CRITICAL findings detected", result.Stats.CriticalCount))
	}
	if result.Stats.SecretsDetected > 0 {
		warnings = append(warnings, fmt.Sprintf("%d secrets detected — rotate immediately", result.Stats.SecretsDetected))
	}
	if len(result.Errors) > 0 {
		warnings = append(warnings, fmt.Sprintf("%d scan lane errors", len(result.Errors)))
	}

	resp := &ERTScanResponse{
		ScanID:      result.RequestID,
		ProjectPath: projectPath,
		Duration:    result.Duration.String(),
		Summary: ERTScanSummary{
			TotalFindings:   result.Stats.TotalFindings,
			BySeverity:      result.Stats.BySeverity,
			LanesExecuted:   len(result.Lanes),
			SecretsDetected: result.Stats.SecretsDetected,
		},
		Findings:  findings,
		Errors:    result.Errors,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}

	return resp, warnings, nil
}

// truncate limits a string to maxLen characters.
func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

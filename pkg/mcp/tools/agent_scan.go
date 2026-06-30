package tools

// agent_scan.go — MCP tool handler for "agent_scan"
//
// Delivers the full AgentScanner omnipotent scan stack as an MCP tool.
//
// Tool name: agent_scan
// Description: Omnipotent AI agent security scanner. Points at any MCP/OpenAI/
//              LangServe/Ollama/HTTP agent and runs 6 layers of security analysis:
//              network surface, service discovery, Horus static analysis, 27
//              adversarial probes (OWASP LLM Top 10 + MITRE ATLAS), KASA behavioral
//              scoring, and ERT+Sonar multi-lane scanning. All results are absorbed
//              by the Flight Fabric into a signed, DAG-attested evidence chain.
//
// Parameters:
//   url        string  — Agent endpoint (required). e.g. "http://localhost:3000"
//   type       string  — Agent protocol: mcp|openai|langserve|ollama|http|unknown (default: unknown)
//   tier       string  — Scan tier: free|pro|enterprise (default: free)
//              free       → probes A+B (injection + exfiltration)
//              pro        → probes A+B+C+D + Sonar crawler
//              enterprise → all 5 probe categories + full Sonar
//   api_key    string  — Optional bearer token for authenticated scans (never stored)
//   repo_path  string  — Optional local path for Horus static analysis
//   timeout_s  int     — Max scan duration in seconds (default: 300)
//
// Example MCP call (Claude/Cursor):
//   { "method": "tools/call", "params": { "name": "agent_scan",
//     "arguments": { "url": "http://localhost:3000", "tier": "pro" }}}
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/souhimbou"
)

// HandleAgentScan is the MCP tool handler for "agent_scan".
// It instantiates an AgentScanner backed by the process-level Flight Fabric
// and runs the full omnipotent scan against the provided agent URL.
func HandleAgentScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	// ── Parse arguments ───────────────────────────────────────────────────
	url, _ := call.Args["url"].(string)
	if url == "" {
		return nil, nil, fmt.Errorf("agent_scan: 'url' is required (e.g. \"http://localhost:3000\")")
	}

	agentType, _ := call.Args["type"].(string)
	tier, _ := call.Args["tier"].(string)
	apiKey, _ := call.Args["api_key"].(string)
	repoPath, _ := call.Args["repo_path"].(string)

	timeoutSec := 300
	if ts, ok := call.Args["timeout_s"].(float64); ok && ts > 0 {
		timeoutSec = int(ts)
	}

	if tier == "" {
		tier = "free"
	}

	target := souhimbou.AgentTarget{
		URL:         url,
		Type:        souhimbou.AgentType(agentType),
		Tier:        tier,
		APIKey:      apiKey,
		RepoPath:    repoPath,
		MaxDuration: time.Duration(timeoutSec) * time.Second,
	}

	// ── Wire Flight Fabric + DAG Store ────────────────────────────────────
	// Use the process-level DAG store if KHEPRA_STORAGE_PATH is set,
	// otherwise create a no-op store (scan still runs, attestation skipped).
	dagStore := resolveDAGStore()
	fabric := flight.Global()

	// ── Run the scan ──────────────────────────────────────────────────────
	scanner := souhimbou.NewAgentScanner(fabric, dagStore)

	report, err := scanner.Scan(ctx, target)
	if err != nil {
		return nil, nil, fmt.Errorf("agent_scan failed: %w", err)
	}

	// ── Format output ─────────────────────────────────────────────────────
	return formatScanReport(report), formatScanWarnings(report), nil
}

// formatScanReport converts AgentScanReport to a structured MCP response.
func formatScanReport(r *souhimbou.AgentScanReport) any {
	type portRow struct {
		Port    int    `json:"port"`
		Service string `json:"service"`
		Banner  string `json:"banner,omitempty"`
	}
	type findingRow struct {
		ID          string   `json:"id"`
		Layer       string   `json:"layer"`
		Severity    string   `json:"severity"`
		Score       float64  `json:"risk_score"`
		Title       string   `json:"title"`
		Description string   `json:"description,omitempty"`
		Remediation string   `json:"remediation,omitempty"`
		CMMC        []string `json:"cmmc_controls,omitempty"`
		FrameID     string   `json:"frame_id,omitempty"`
	}

	ports := make([]portRow, 0, len(r.OpenPorts))
	for _, p := range r.OpenPorts {
		ports = append(ports, portRow{Port: p.Port, Service: p.Service, Banner: p.Banner})
	}

	findings := make([]findingRow, 0, len(r.Findings))
	for _, f := range r.Findings {
		findings = append(findings, findingRow{
			ID:          f.ID,
			Layer:       f.Layer,
			Severity:    f.Severity,
			Score:       f.RiskScore,
			Title:       f.Title,
			Description: f.Description,
			Remediation: f.Remediation,
			CMMC:        f.CMCCControls,
			FrameID:     f.FrameID,
		})
	}

	return map[string]any{
		// Identity
		"report_id":    r.ReportID,
		"scan_id":      r.ScanID,
		"target":       r.Target,
		"agent_type":   r.AgentType,
		"detected_as":  r.DetectedType,
		"tier":         r.Tier,
		"duration_ms":  r.DurationMs,

		// Risk
		"risk_level":  r.RiskLevel,
		"risk_score":  r.RiskScore,
		"kasa_score":  r.KASAScore,

		// Counts
		"stats": map[string]int{
			"total":    r.Stats.Total,
			"critical": r.Stats.Critical,
			"high":     r.Stats.High,
			"medium":   r.Stats.Medium,
			"low":      r.Stats.Low,
		},

		// Discovery
		"open_ports":   ports,
		"agent_tools":  r.AgentTools,

		// TLS
		"tls": r.TLSInfo,

		// Findings
		"findings": findings,

		// Audit chain
		"dag_node_id": r.DAGNodeID,

		// Summary
		"summary": r.Summary,
		"errors":  r.Errors,
	}
}

// formatScanWarnings converts high/critical findings to MCP warning strings.
func formatScanWarnings(r *souhimbou.AgentScanReport) []string {
	if r == nil {
		return nil
	}
	var warnings []string
	for _, f := range r.Findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			warnings = append(warnings, fmt.Sprintf("[%s] %s — %s", f.Severity, f.Title, f.Remediation))
		}
	}
	return warnings
}

// resolveDAGStore returns the DAG store for the current deployment mode.
// Uses dag.NewStore() which reads KHEPRA_MODE: sovereign/ironbank → PersistentMemory,
// edge/hybrid → in-memory ephemeral.
func resolveDAGStore() dag.Store {
	return dag.NewStore()
}

// ── Tool Schema (JSON Schema for MCP manifest) ────────────────────────────────

// AgentScanSchema is the JSON Schema for the agent_scan MCP tool.
// Returned by the manifest generator for schema pinning.
var AgentScanSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"url": map[string]any{
			"type":        "string",
			"description": "Agent endpoint URL to scan. Required. Example: \"http://localhost:3000\"",
		},
		"type": map[string]any{
			"type":        "string",
			"description": "Agent protocol type. One of: mcp, openai, langserve, ollama, http, unknown",
			"enum":        []string{"mcp", "openai", "langserve", "ollama", "http", "unknown", ""},
			"default":     "unknown",
		},
		"tier": map[string]any{
			"type":        "string",
			"description": "Scan depth tier. free=A+B probes, pro=A-D+crawler, enterprise=full (all 5 probe categories + ERT)",
			"enum":        []string{"free", "pro", "enterprise"},
			"default":     "free",
		},
		"api_key": map[string]any{
			"type":        "string",
			"description": "Optional bearer token for authenticated agent scans. Never stored or logged.",
		},
		"repo_path": map[string]any{
			"type":        "string",
			"description": "Optional local filesystem path to agent source. Enables Horus static analysis (secret scan, CVE scan).",
		},
		"timeout_s": map[string]any{
			"type":        "integer",
			"description": "Maximum scan duration in seconds. Default: 300 (5 minutes).",
			"default":     300,
			"minimum":     10,
			"maximum":     1800,
		},
	},
	"required": []string{"url"},
}

// ── HTTP API handler (used by pkg/apiserver) ──────────────────────────────────

// AgentScanRequest is the JSON body for POST /api/v1/scan/agent
type AgentScanRequest struct {
	URL        string `json:"url"`
	Type       string `json:"type,omitempty"`
	Tier       string `json:"tier,omitempty"`
	APIKey     string `json:"api_key,omitempty"`
	RepoPath   string `json:"repo_path,omitempty"`
	TimeoutSec int    `json:"timeout_s,omitempty"`
}

// RunAgentScanHTTP performs the scan from an HTTP request body.
// Used by pkg/apiserver to implement POST /api/v1/scan/agent.
func RunAgentScanHTTP(ctx context.Context, body []byte) (*souhimbou.AgentScanReport, error) {
	var req AgentScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("invalid request body: %w", err)
	}
	if req.URL == "" {
		return nil, fmt.Errorf("'url' is required")
	}
	if req.Tier == "" {
		req.Tier = "free"
	}
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	target := souhimbou.AgentTarget{
		URL:         req.URL,
		Type:        souhimbou.AgentType(req.Type),
		Tier:        req.Tier,
		APIKey:      req.APIKey,
		RepoPath:    req.RepoPath,
		MaxDuration: timeout,
	}

	dagStore := resolveDAGStore()
	fabric := flight.Global()
	scanner := souhimbou.NewAgentScanner(fabric, dagStore)

	return scanner.Scan(ctx, target)
}

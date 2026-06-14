// Package g0dm0d3 — tools.go implements the KHEPRA native tool panel.
//
// Tools are callable by:
//  1. HTTP GET /api/g0dm0d3/tools/{tool-name}  (frontend panel)
//  2. AI auto-execution when a response contains [TOOL:tool-name]
//
// Tool implementations are pure functions of the DAG state plus optional
// injected callbacks — no mock data, no placeholders.
package g0dm0d3

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ─── Tool Interface ────────────────────────────────────────────────────────────

// Tool is a KHEPRA-native capability that can be invoked by the AI or the UI.
// Implementations must be idempotent and side-effect-free (read-only views).
type Tool interface {
	// Name returns the tool identifier used in [TOOL:xxx] directives and HTTP paths.
	Name() string
	// Execute runs the tool and returns a human-readable result string.
	Execute() (string, error)
}

// ─── Tool Registry ────────────────────────────────────────────────────────────

// RegisterTool adds a tool to the server's panel. Panics on duplicate name.
func (s *G0DM0D3Server) RegisterTool(tool Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tools == nil {
		s.tools = make(map[string]Tool)
	}
	if _, exists := s.tools[tool.Name()]; exists {
		panic(fmt.Sprintf("g0dm0d3: duplicate tool registered: %q", tool.Name()))
	}
	s.tools[tool.Name()] = tool
}

// RegisterDefaultTools registers all built-in KHEPRA tools on the server.
// This must be called after constructing a G0DM0D3Server and before serving.
//
//	eaStatusFn — optional; return current EA EngineStatus JSON; nil disables the tool.
//	licenseDir — directory where the sovereign license file is stored (empty = home dir).
func (s *G0DM0D3Server) RegisterDefaultTools(eaStatusFn func() (string, error), licenseDir string) {
	s.RegisterTool(&dagSummaryTool{srv: s})
	s.RegisterTool(&stigSummaryTool{srv: s})
	s.RegisterTool(&pqcInventoryTool{srv: s})
	s.RegisterTool(&forensicsSummaryTool{srv: s})
	s.RegisterTool(&licenseStatusTool{dir: licenseDir})
	if eaStatusFn != nil {
		s.RegisterTool(&eaStatusTool{statusFn: eaStatusFn})
	}
}

// ─── HTTP Handler ─────────────────────────────────────────────────────────────

// HandleTool serves GET /api/g0dm0d3/tools/{tool-name}.
// Returns JSON: {"tool":"...", "result":"...", "timestamp":"..."} or an error object.
func (s *G0DM0D3Server) HandleTool(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Extract tool name from path: /api/g0dm0d3/tools/{name}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 0 {
		jsonError(w, http.StatusBadRequest, "missing tool name in path")
		return
	}
	toolName := parts[len(parts)-1]

	s.mu.Lock()
	tool, ok := s.tools[toolName]
	s.mu.Unlock()

	if !ok {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("unknown tool: %q", toolName))
		return
	}

	result, err := tool.Execute()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"tool":      toolName,
		"result":    result,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// HandleToolList serves GET /api/g0dm0d3/tools (no trailing name).
// Returns a JSON list of all registered tool names.
func (s *G0DM0D3Server) HandleToolList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Access-Control-Allow-Origin", "*")

	s.mu.Lock()
	names := make([]string, 0, len(s.tools))
	for name := range s.tools {
		names = append(names, name)
	}
	s.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"tools":     names,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ─── [TOOL:xxx] Auto-Execution ────────────────────────────────────────────────

// toolDirectiveRE matches [TOOL:tool-name] directives in AI responses.
var toolDirectiveRE = regexp.MustCompile(`\[TOOL:([a-zA-Z0-9_-]+)\]`)

// executeToolDirectives scans an AI response for [TOOL:xxx] directives,
// executes each registered tool in order, and replaces each directive with
// the tool output enclosed in a code block.  Unknown tools are replaced with
// a not-found notice rather than being silently dropped.
func (s *G0DM0D3Server) executeToolDirectives(response string) string {
	return toolDirectiveRE.ReplaceAllStringFunc(response, func(match string) string {
		sub := toolDirectiveRE.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		toolName := sub[1]

		s.mu.Lock()
		tool, ok := s.tools[toolName]
		s.mu.Unlock()

		if !ok {
			return fmt.Sprintf("[TOOL RESULT: %s — tool not registered]", toolName)
		}

		result, err := tool.Execute()
		if err != nil {
			return fmt.Sprintf("[TOOL RESULT: %s — error: %v]", toolName, err)
		}
		return fmt.Sprintf("\n\n**[%s output]**\n```\n%s\n```\n", toolName, result)
	})
}

// ─── Built-in Tools ────────────────────────────────────────────────────────────

// dagSummaryTool summarises the current DAG state.
type dagSummaryTool struct{ srv *G0DM0D3Server }

func (t *dagSummaryTool) Name() string { return "dag-summary" }
func (t *dagSummaryTool) Execute() (string, error) {
	if t.srv.DAG == nil {
		return "DAG not connected.", nil
	}
	nodes := t.srv.DAG.All()
	if len(nodes) == 0 {
		return "DAG is empty (no nodes recorded yet).", nil
	}

	actionCounts := make(map[string]int)
	for _, n := range nodes {
		prefix := n.Action
		if idx := strings.Index(n.Action, ":"); idx > 0 {
			prefix = n.Action[:idx]
		}
		actionCounts[prefix]++
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "DAG nodes: %d\n", len(nodes))
	for prefix, count := range actionCounts {
		fmt.Fprintf(&sb, "  %-28s %d\n", prefix, count)
	}
	// Most recent node
	last := nodes[len(nodes)-1]
	fmt.Fprintf(&sb, "Latest: %s — %s [%s]", last.Time, last.Action, last.Symbol)
	return sb.String(), nil
}

// stigSummaryTool extracts STIG scan outcomes from DAG nodes.
type stigSummaryTool struct{ srv *G0DM0D3Server }

func (t *stigSummaryTool) Name() string { return "stig-summary" }
func (t *stigSummaryTool) Execute() (string, error) {
	if t.srv.DAG == nil {
		return "DAG not connected — cannot read STIG findings.", nil
	}
	nodes := t.srv.DAG.All()

	stigNodes := 0
	var lastSTIG string
	for _, n := range nodes {
		if strings.HasPrefix(n.Action, "stig") || strings.Contains(n.Action, "STIG") {
			stigNodes++
			lastSTIG = fmt.Sprintf("[%s] %s", n.Time, n.Action)
		}
	}
	if stigNodes == 0 {
		return "No STIG scan nodes found in DAG. Run `adinkhepra scan` to generate findings.", nil
	}
	return fmt.Sprintf("STIG DAG nodes: %d\nLast: %s\nRun `adinkhepra report --stig` for the full CKL report.", stigNodes, lastSTIG), nil
}

// pqcInventoryTool tallies PQC algorithm usage recorded in DAG PQC metadata.
type pqcInventoryTool struct{ srv *G0DM0D3Server }

func (t *pqcInventoryTool) Name() string { return "pqc-inventory" }
func (t *pqcInventoryTool) Execute() (string, error) {
	if t.srv.DAG == nil {
		return "DAG not connected.", nil
	}
	nodes := t.srv.DAG.All()

	schemes := make(map[string]int)
	for _, n := range nodes {
		if scheme, ok := n.PQC["scheme"]; ok && scheme != "" {
			schemes[scheme]++
		}
	}
	if len(schemes) == 0 {
		return "No PQC metadata recorded in DAG yet.", nil
	}

	var sb strings.Builder
	sb.WriteString("PQC algorithm usage (from DAG):\n")
	for scheme, count := range schemes {
		fmt.Fprintf(&sb, "  %-20s %d signatures\n", scheme, count)
	}
	return sb.String(), nil
}

// forensicsSummaryTool reads forensic scan nodes from the DAG.
type forensicsSummaryTool struct{ srv *G0DM0D3Server }

func (t *forensicsSummaryTool) Name() string { return "forensics-summary" }
func (t *forensicsSummaryTool) Execute() (string, error) {
	if t.srv.DAG == nil {
		return "DAG not connected.", nil
	}
	nodes := t.srv.DAG.All()

	var findings []string
	for _, n := range nodes {
		if strings.HasPrefix(n.Action, "forensic") || strings.Contains(n.Action, "threat") {
			findings = append(findings, fmt.Sprintf("[%s] %s — %s", n.Time, n.Action, n.Symbol))
		}
	}
	if len(findings) == 0 {
		return "No forensic nodes in DAG. Run `adinkhepra harden` to start threat monitoring.", nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Forensic events: %d\n", len(findings))
	// Show last 5
	start := len(findings) - 5
	if start < 0 {
		start = 0
	}
	for _, f := range findings[start:] {
		fmt.Fprintf(&sb, "  %s\n", f)
	}
	return sb.String(), nil
}

// licenseStatusTool reads the sovereign license file from disk.
type licenseStatusTool struct{ dir string }

func (t *licenseStatusTool) Name() string { return "license-status" }
func (t *licenseStatusTool) Execute() (string, error) {
	licensePath := t.resolveLicensePath()
	data, err := os.ReadFile(licensePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "No license installed. Run `adinkhepra license request` to begin.", nil
		}
		return "", fmt.Errorf("read license: %w", err)
	}

	// Unmarshal only the non-sensitive fields for display.
	var lic struct {
		LicenseID    string `json:"license_id"`
		Tenant       string `json:"tenant"`
		Tier         string `json:"tier"`
		ExpiresAt    string `json:"expires_at"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(data, &lic); err != nil {
		return "", fmt.Errorf("parse license: %w", err)
	}

	exp, _ := time.Parse(time.RFC3339, lic.ExpiresAt)
	remaining := time.Until(exp).Round(24 * time.Hour)

	var sb strings.Builder
	fmt.Fprintf(&sb, "License ID  : %s\n", lic.LicenseID)
	fmt.Fprintf(&sb, "Tenant      : %s\n", lic.Tenant)
	fmt.Fprintf(&sb, "Tier        : %s\n", lic.Tier)
	fmt.Fprintf(&sb, "Expires     : %s (%s remaining)\n", lic.ExpiresAt, remaining)
	if len(lic.Capabilities) > 0 {
		fmt.Fprintf(&sb, "Capabilities: %s\n", strings.Join(lic.Capabilities, ", "))
	}
	return sb.String(), nil
}

func (t *licenseStatusTool) resolveLicensePath() string {
	if t.dir != "" {
		return filepath.Join(t.dir, "khepra_license.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "khepra_license.json"
	}
	return filepath.Join(home, ".khepra", "khepra_license.json")
}

// eaStatusTool delegates to a caller-supplied status function, allowing the
// EA engine to be wired in without creating an import cycle.
type eaStatusTool struct {
	statusFn func() (string, error)
}

func (t *eaStatusTool) Name() string { return "ea-status" }
func (t *eaStatusTool) Execute() (string, error) {
	return t.statusFn()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}

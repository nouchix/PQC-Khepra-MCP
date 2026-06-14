// package legacy — Natural Language Security Processor
//
// This is the "ChatGPT moment" for cybersecurity operations.
//
// Traditional security tools require:
//   - Learning CLI syntax (nmap -sV -sC -A -p- ...)
//   - Knowing log query languages (KQL, SPL, Lucene)
//   - Understanding STIX/TAXII, CVSS scoring, MITRE ATT&CK notation
//   - Reading dashboards with 50 charts nobody looks at
//
// The NL Processor replaces all of that with:
//
//	"Is my network compromised?"
//	"What happened at 3am yesterday?"
//	"Someone is attacking us right now — what do I do?"
//	"Are we ready for our CMMC assessment next month?"
//	"Generate the board security slide for Friday"
//
// Architecture:
//
//	User (Claude/Cursor/Web UI)
//	     │  Natural Language Query
//	     ▼
//	NLProcessor.Process()
//	     │
//	     ├─ ParseIntent()   — LLM classifies intent + extracts parameters
//	     ├─ PlanChain()     — Determines tool call sequence
//	     ├─ ExecuteChain()  — Runs tools in optimal order (parallel where safe)
//	     └─ Synthesize()    — LLM generates plain-English response from tool outputs
//
// The LLM (pkg/llm) is used TWICE:
//  1. Parse intent → structured tool calls
//  2. Synthesize results → human-readable response
//
// Security note: The NL processor NEVER passes raw LLM output directly to
// execution. Tool parameters are extracted and validated before calling handlers.
// Prompt injection scanning runs on every input via pkg/gateway MCPGateway.
package legacy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// NLQuery is a natural language security query.
type NLQuery struct {
	Text      string            `json:"text"`       // "Is my network compromised?"
	SessionID string            `json:"session_id"` // For conversation context
	Context   map[string]string `json:"context"`    // e.g. {"org_id": "acme", "user": "alice@acme.com"}
	MaxTools  int               `json:"max_tools"`  // Max tool calls (default: 10)
}

// NLResponse is the natural language response.
type NLResponse struct {
	Answer      string           `json:"answer"`       // Plain English response
	ToolsCalled []ToolInvocation `json:"tools_called"` // What was executed
	DAGNodeIDs  []string         `json:"dag_node_ids"` // Audit trail
	Confidence  float64          `json:"confidence"`   // AI confidence in answer
	Suggestions []string         `json:"suggestions"`  // Follow-up questions
	ProcessedAt time.Time        `json:"processed_at"`
	DurationMS  int64            `json:"duration_ms"`
}

// ToolInvocation records a single tool call made during NL processing.
type ToolInvocation struct {
	ToolName   string          `json:"tool_name"`
	Parameters json.RawMessage `json:"parameters"`
	Result     interface{}     `json:"result"`
	DurationMS int64           `json:"duration_ms"`
	Error      string          `json:"error,omitempty"`
}

// LLMProvider matches pkg/llm.Provider interface.
type LLMProvider interface {
	Generate(prompt string, systemPrompt string) (string, error)
	CheckHealth() bool
}

// ToolExecutor executes MCP tool calls.
type ToolExecutor interface {
	Execute(ctx context.Context, toolName string, params json.RawMessage) (*ToolResult, error)
}

// NLProcessor converts natural language security queries into tool chains.
type NLProcessor struct {
	llm      LLMProvider
	executor ToolExecutor
	tools    []Tool
}

// NewNLProcessor creates a new NLProcessor.
// llm: any pkg/llm.Provider (Ollama, Claude, etc.)
// executor: wraps the Server's tool dispatch
func NewNLProcessor(llm LLMProvider, executor ToolExecutor) *NLProcessor {
	return &NLProcessor{
		llm:      llm,
		executor: executor,
		tools:    AllKhepraTools(),
	}
}

// Process converts a natural language security query into actions and a response.
func (p *NLProcessor) Process(ctx context.Context, query NLQuery) (*NLResponse, error) {
	if query.MaxTools == 0 {
		query.MaxTools = 10
	}

	start := time.Now()
	resp := &NLResponse{ProcessedAt: start}

	// Step 1: Parse intent → tool plan
	plan, err := p.parseIntent(ctx, query)
	if err != nil {
		// If LLM unavailable, fall back to keyword matching
		plan = p.keywordFallback(query.Text)
	}

	if len(plan) == 0 {
		resp.Answer = "I understand you have a security question. Could you be more specific? " +
			"For example: 'Is my network compromised?', 'Run a compliance scan', or 'Show me active threats'."
		resp.DurationMS = time.Since(start).Milliseconds()
		return resp, nil
	}

	// Limit tool calls to MaxTools
	if len(plan) > query.MaxTools {
		plan = plan[:query.MaxTools]
	}

	// Step 2: Execute tool chain
	var toolOutputs []string
	for _, invocation := range plan {
		toolStart := time.Now()

		result, execErr := p.executor.Execute(ctx, invocation.ToolName, invocation.Parameters)

		inv := invocation
		inv.DurationMS = time.Since(toolStart).Milliseconds()

		if execErr != nil {
			inv.Error = execErr.Error()
			toolOutputs = append(toolOutputs, fmt.Sprintf("[%s ERROR] %s", invocation.ToolName, execErr.Error()))
		} else if result != nil {
			inv.Result = result
			if len(result.Content) > 0 {
				toolOutputs = append(toolOutputs, fmt.Sprintf("[%s]\n%s", invocation.ToolName, result.Content[0].Text))
			}
			if result.DAGNodeID != "" {
				resp.DAGNodeIDs = append(resp.DAGNodeIDs, result.DAGNodeID)
			}
		}

		resp.ToolsCalled = append(resp.ToolsCalled, inv)
	}

	// Step 3: Synthesize results into plain English
	answer, confidence := p.synthesize(ctx, query.Text, toolOutputs)
	resp.Answer = answer
	resp.Confidence = confidence
	resp.Suggestions = p.generateSuggestions(query.Text, plan)
	resp.DurationMS = time.Since(start).Milliseconds()

	return resp, nil
}

// ─── Intent Parsing ────────────────────────────────────────────────────────────

// intentPlan is a structured tool invocation plan.
type intentPlan = []ToolInvocation

// parseIntent uses the LLM to classify intent and generate a tool invocation plan.
func (p *NLProcessor) parseIntent(ctx context.Context, query NLQuery) (intentPlan, error) {
	if !p.llm.CheckHealth() {
		return nil, fmt.Errorf("LLM unavailable")
	}

	toolList := p.buildToolSummary()
	contextJSON, _ := json.Marshal(query.Context)

	systemPrompt := `You are a security operations AI that converts natural language queries
into structured tool invocation plans for the Khepra Cyber Shield platform.

Available tools:
` + toolList + `

Rules:
1. Select the minimum set of tools needed to answer the query
2. Order tools logically (discover before assess, assess before respond)
3. Extract parameters from the query context
4. Return ONLY valid JSON — no explanation text
5. Never exceed 5 tools unless explicitly handling an incident

Output format (JSON array):
[
  {
    "tool_name": "khepra_xxx",
    "parameters": { ... }
  }
]`

	userPrompt := fmt.Sprintf(
		"Query: %s\nContext: %s\nPlan the minimum tool chain to answer this:",
		query.Text, string(contextJSON),
	)

	response, err := p.llm.Generate(userPrompt, systemPrompt)
	if err != nil {
		return nil, fmt.Errorf("LLM parse failed: %w", err)
	}

	// Extract JSON from LLM response (strip any markdown fences)
	jsonStr := extractJSON(response)

	var plan []struct {
		ToolName   string          `json:"tool_name"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &plan); err != nil {
		return nil, fmt.Errorf("LLM returned invalid JSON: %w", err)
	}

	result := make([]ToolInvocation, 0, len(plan))
	for _, p := range plan {
		if p.ToolName != "" {
			result = append(result, ToolInvocation{
				ToolName:   p.ToolName,
				Parameters: p.Parameters,
			})
		}
	}
	return result, nil
}

// keywordFallback maps keywords to tool plans when LLM is unavailable.
// This is the "no-AI" safety net.
func (p *NLProcessor) keywordFallback(text string) intentPlan {
	lower := strings.ToLower(text)

	type rule struct {
		keywords []string
		tools    []string
	}

	rules := []rule{
		{
			keywords: []string{"compromised", "hacked", "breach", "attack", "intrusion"},
			tools:    []string{"khepra_get_ids_alerts", "khepra_hunt_threats", "khepra_get_security_timeline"},
		},
		{
			keywords: []string{"threat", "threat hunt", "hunting", "lateral movement", "ttp"},
			tools:    []string{"khepra_hunt_threats", "khepra_analyze_iocs"},
		},
		{
			keywords: []string{"incident", "declare", "emergency", "ransomware", "malware"},
			tools:    []string{"khepra_declare_incident", "khepra_collect_forensics"},
		},
		{
			keywords: []string{"compliance", "cmmc", "stig", "nist", "score", "ready"},
			tools:    []string{"khepra_get_compliance_score", "khepra_run_compliance_scan"},
		},
		{
			keywords: []string{"pentest", "penetration test", "vulnerability", "cve", "scan"},
			tools:    []string{"khepra_check_vulnerabilities", "khepra_enumerate_services"},
		},
		{
			keywords: []string{"traffic", "network", "flow", "anomal", "exfil", "beacon"},
			tools:    []string{"khepra_analyze_traffic", "khepra_get_traffic_analysis"},
		},
		{
			keywords: []string{"block", "firewall", "rule", "ban", "ip"},
			tools:    []string{"khepra_create_ips_rule", "khepra_update_firewall_rule"},
		},
		{
			keywords: []string{"report", "dashboard", "posture", "risk", "executive", "board"},
			tools:    []string{"khepra_get_risk_dashboard", "khepra_generate_report"},
		},
		{
			keywords: []string{"backup", "recover", "dr", "failover", "restore", "rto", "rpo"},
			tools:    []string{"khepra_get_rto_rpo", "khepra_test_recovery"},
		},
		{
			keywords: []string{"alert", "ids", "ips", "detection", "alarm"},
			tools:    []string{"khepra_get_ids_alerts", "khepra_correlate_events"},
		},
		{
			keywords: []string{"log", "search", "find", "happened", "history", "timeline"},
			tools:    []string{"khepra_search_logs", "khepra_get_security_timeline"},
		},
		{
			keywords: []string{"attest", "artifact", "c3pao", "audit", "prove", "evidence"},
			tools:    []string{"khepra_export_attestation", "khepra_get_dag_chain"},
		},
	}

	for _, rule := range rules {
		for _, kw := range rule.keywords {
			if strings.Contains(lower, kw) {
				plan := make([]ToolInvocation, 0, len(rule.tools))
				for _, toolName := range rule.tools {
					plan = append(plan, ToolInvocation{
						ToolName:   toolName,
						Parameters: json.RawMessage(`{}`),
					})
				}
				return plan
			}
		}
	}

	// Default: show risk dashboard
	return []ToolInvocation{{
		ToolName:   "khepra_get_risk_dashboard",
		Parameters: json.RawMessage(`{}`),
	}}
}

// ─── Result Synthesis ──────────────────────────────────────────────────────────

// synthesize uses the LLM to convert raw tool outputs into a plain English answer.
func (p *NLProcessor) synthesize(ctx context.Context, query string, toolOutputs []string) (string, float64) {
	if len(toolOutputs) == 0 {
		return "No results found. Try running a scan or check that your agents are connected.", 0.5
	}

	// If LLM is unavailable, return structured output directly
	if !p.llm.CheckHealth() {
		return "Security analysis complete:\n\n" + strings.Join(toolOutputs, "\n\n"), 0.7
	}

	systemPrompt := `You are a cybersecurity expert explaining security findings to a user.
Rules:
- Be direct and actionable
- Start with the most critical information
- Use plain English — avoid jargon unless necessary
- If there are threats, lead with severity and immediate action
- If everything looks good, confirm that clearly
- Keep response under 500 words
- End with 1-2 recommended next steps`

	userPrompt := fmt.Sprintf(
		"Original question: %s\n\nSecurity tool results:\n%s\n\nProvide a clear, actionable summary:",
		query,
		strings.Join(toolOutputs, "\n---\n"),
	)

	response, err := p.llm.Generate(userPrompt, systemPrompt)
	if err != nil {
		return "Security analysis complete:\n\n" + strings.Join(toolOutputs, "\n\n"), 0.7
	}

	return response, 0.85
}

// generateSuggestions creates follow-up question suggestions.
func (p *NLProcessor) generateSuggestions(query string, plan intentPlan) []string {
	lower := strings.ToLower(query)

	// Context-aware follow-ups based on what was just run
	toolNames := make([]string, 0, len(plan))
	for _, inv := range plan {
		toolNames = append(toolNames, inv.ToolName)
	}

	suggestions := []string{}

	if contains(toolNames, "khepra_get_ids_alerts") || contains(toolNames, "khepra_hunt_threats") {
		suggestions = append(suggestions,
			"Tell me more about the highest severity alert",
			"Contain the most critical threat",
			"Show me the attack timeline",
		)
	}
	if contains(toolNames, "khepra_get_compliance_score") || contains(toolNames, "khepra_run_compliance_scan") {
		suggestions = append(suggestions,
			"Export the C3PAO attestation package",
			"Show me the highest priority remediation steps",
			"Generate the executive compliance brief",
		)
	}
	if contains(toolNames, "khepra_check_vulnerabilities") || contains(toolNames, "khepra_enumerate_services") {
		suggestions = append(suggestions,
			"Prioritize vulnerabilities by exploit probability",
			"Run a targeted pentest on the critical assets",
			"Show me the remediation runbook",
		)
	}
	if contains(toolNames, "khepra_declare_incident") || contains(toolNames, "khepra_collect_forensics") {
		suggestions = append(suggestions,
			"Contain the threat immediately",
			"Run the ransomware response playbook",
			"Notify the incident response team",
		)
	}

	// Avoid duplicates with the original query
	_ = lower

	if len(suggestions) == 0 {
		suggestions = []string{
			"Show me the security risk dashboard",
			"Run a compliance scan",
			"Hunt for active threats",
		}
	}

	if len(suggestions) > 3 {
		suggestions = suggestions[:3]
	}
	return suggestions
}

// ─── Utilities ─────────────────────────────────────────────────────────────────

// buildToolSummary creates a compact tool list for LLM context.
func (p *NLProcessor) buildToolSummary() string {
	var sb strings.Builder
	for _, tool := range p.tools {
		sb.WriteString(fmt.Sprintf("- %s: %s\n",
			tool.Name,
			truncate(tool.Description, 120),
		))
	}
	return sb.String()
}

func extractJSON(s string) string {
	// Strip markdown code fences
	s = strings.TrimSpace(s)
	for _, fence := range []string{"```json", "```JSON", "```"} {
		if strings.Contains(s, fence) {
			parts := strings.SplitN(s, fence, 2)
			if len(parts) == 2 {
				rest := parts[1]
				end := strings.LastIndex(rest, "```")
				if end > 0 {
					return strings.TrimSpace(rest[:end])
				}
			}
		}
	}
	// Find first '[' or '{'
	start := strings.IndexAny(s, "[{")
	if start >= 0 {
		return s[start:]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

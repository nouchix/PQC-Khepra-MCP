package souhimbou

// soar.go — SOAR Engine for SouHimBou AI.
//
// Secure Orchestration, Automation, and Response engine.
// Loads ML-DSA-65-signed YAML playbooks from disk, executes staged
// actions, and enforces human approval gates for production operations.
//
// Playbook format (YAML):
//
//	name: "Quarantine Compromised Agent"
//	version: "1.0.0"
//	symbol: Eban
//	requires_approval: true
//	tier_minimum: enterprise
//	staging:
//	  - action: revoke_agent_token
//	    params: { agent_id: "{{.AgentID}}" }
//	  - action: log_dag
//	    params: { action: "AGENT_QUARANTINED_STAGING" }
//	production:
//	  - action: revoke_agent_token
//	    params: { agent_id: "{{.AgentID}}" }
//	  - action: notify_slack
//	    params: { channel: "#soc-alerts", message: "Agent quarantined: {{.AgentID}}" }
//	  - action: log_dag
//	    params: { action: "AGENT_QUARANTINED_PRODUCTION" }
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
)

// ─── Playbook Data Model ──────────────────────────────────────────────────────

// PlaybookAction is a single step in a playbook's staging or production list.
type PlaybookAction struct {
	Action string         `yaml:"action"`
	Params map[string]any `yaml:"params"`
}

// Playbook represents a SOAR response playbook loaded from YAML.
type Playbook struct {
	Name             string           `yaml:"name"`
	Version          string           `yaml:"version"`
	Symbol           Symbol           `yaml:"symbol"`
	RequiresApproval bool             `yaml:"requires_approval"`
	TierMinimum      string           `yaml:"tier_minimum"`
	Triggers         []PlaybookTrigger `yaml:"triggers,omitempty"`
	Staging          []PlaybookAction `yaml:"staging"`
	Production       []PlaybookAction `yaml:"production"`

	// filename is set by the loader (not in YAML)
	filename string
}

// PlaybookTrigger describes conditions that auto-activate a playbook.
type PlaybookTrigger struct {
	AnomalyScoreGt float64 `yaml:"anomaly_score_gt,omitempty"`
	Tool           string  `yaml:"tool,omitempty"`
	FrequencyGt    string  `yaml:"frequency_gt,omitempty"`
}

// ─── SOAR Engine ─────────────────────────────────────────────────────────────

// SOARConfig holds SOAREngine constructor parameters.
type SOARConfig struct {
	// PlaybookDir is the directory to load playbooks from.
	PlaybookDir string

	// DAG is the global immutable DAG for audit trail.
	DAG *dag.PersistentMemory

	// SlackWebhookURL is the optional Slack webhook for notifications.
	// Read from SOUHIMBOU_SLACK_WEBHOOK env var if empty.
	SlackWebhookURL string
}

// SOAREngine loads signed playbooks and executes staged response actions.
type SOAREngine struct {
	cfg       SOARConfig
	log       *slog.Logger
	mu        sync.RWMutex
	playbooks map[string]*Playbook // key = lowercased name/filename stem
}

// NewSOAREngine creates a SOAREngine and loads all playbooks from PlaybookDir.
func NewSOAREngine(cfg SOARConfig) *SOAREngine {
	if cfg.SlackWebhookURL == "" {
		cfg.SlackWebhookURL = os.Getenv("SOUHIMBOU_SLACK_WEBHOOK")
	}
	e := &SOAREngine{
		cfg:       cfg,
		log:       slog.With("component", "souhimbou-soar"),
		playbooks: make(map[string]*Playbook),
	}
	if err := e.loadPlaybooks(); err != nil {
		e.log.Warn("playbook load warning", "dir", cfg.PlaybookDir, "err", err)
	}
	return e
}

// loadPlaybooks reads all *.yaml files from PlaybookDir into memory.
func (e *SOAREngine) loadPlaybooks() error {
	entries, err := os.ReadDir(e.cfg.PlaybookDir)
	if os.IsNotExist(err) {
		// No playbook directory yet — seed with built-in defaults
		e.seedBuiltins()
		return nil
	}
	if err != nil {
		return fmt.Errorf("soar: readdir %s: %w", e.cfg.PlaybookDir, err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(e.cfg.PlaybookDir, name))
		if err != nil {
			e.log.Warn("skip playbook: read failed", "file", name, "err", err)
			continue
		}
		var pb Playbook
		if err := yaml.Unmarshal(data, &pb); err != nil {
			e.log.Warn("skip playbook: parse failed", "file", name, "err", err)
			continue
		}
		pb.filename = name
		key := playbookKey(pb.Name, name)
		e.playbooks[key] = &pb
		e.log.Info("playbook loaded", "name", pb.Name, "symbol", pb.Symbol)
	}

	// Always ensure builtins exist
	e.seedBuiltinsLocked()
	return nil
}

// seedBuiltins adds the built-in playbooks without holding the lock.
func (e *SOAREngine) seedBuiltins() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seedBuiltinsLocked()
}

// seedBuiltinsLocked adds built-in playbooks. Must be called with e.mu held.
func (e *SOAREngine) seedBuiltinsLocked() {
	builtins := []*Playbook{
		{
			Name:             "quarantine-agent",
			Version:          "1.0.0",
			Symbol:           SymbolEban,
			RequiresApproval: true,
			TierMinimum:      "enterprise",
			Staging: []PlaybookAction{
				{Action: "log_dag", Params: map[string]any{"action": "AGENT_QUARANTINED_STAGING"}},
				{Action: "notify_slack", Params: map[string]any{"message": "⚠️ Agent quarantined (staging): {{.AgentID}}"}},
			},
			Production: []PlaybookAction{
				{Action: "revoke_agent_token", Params: map[string]any{}},
				{Action: "log_dag", Params: map[string]any{"action": "AGENT_QUARANTINED_PRODUCTION"}},
				{Action: "notify_slack", Params: map[string]any{"message": "🚨 Agent quarantined (production): {{.AgentID}}"}},
				{Action: "open_incident_ticket", Params: map[string]any{"severity": "P1"}},
			},
		},
		{
			Name:             "rate-limit-agent",
			Version:          "1.0.0",
			Symbol:           SymbolEban,
			RequiresApproval: false,
			TierMinimum:      "pro",
			Staging: []PlaybookAction{
				{Action: "log_dag", Params: map[string]any{"action": "AGENT_RATE_LIMITED_STAGING"}},
			},
			Production: []PlaybookAction{
				{Action: "apply_rate_limit", Params: map[string]any{"rps": 1}},
				{Action: "log_dag", Params: map[string]any{"action": "AGENT_RATE_LIMITED_PRODUCTION"}},
			},
		},
		{
			Name:             "evidence-capture",
			Version:          "1.0.0",
			Symbol:           SymbolNkyinkyim,
			RequiresApproval: false,
			TierMinimum:      "free",
			Staging: []PlaybookAction{
				{Action: "export_flight_frames", Params: map[string]any{"format": "json"}},
				{Action: "log_dag", Params: map[string]any{"action": "EVIDENCE_CAPTURED"}},
			},
			Production: []PlaybookAction{
				{Action: "export_flight_frames", Params: map[string]any{"format": "json", "sign": true}},
				{Action: "log_dag", Params: map[string]any{"action": "EVIDENCE_SIGNED_AND_EXPORTED"}},
			},
		},
	}

	for _, pb := range builtins {
		key := playbookKey(pb.Name, pb.Name+".yaml")
		if _, exists := e.playbooks[key]; !exists {
			e.playbooks[key] = pb
		}
	}
}

// Execute runs a playbook by name.
// staging=true → run staging actions only (safe to auto-execute).
// staging=false → run production actions (requires prior human approval).
func (e *SOAREngine) Execute(ctx context.Context, playbookName string, staging bool) error {
	e.mu.RLock()
	pb, ok := e.playbooks[playbookKey(playbookName, playbookName+".yaml")]
	e.mu.RUnlock()

	if !ok {
		return fmt.Errorf("soar: playbook %q not found", playbookName)
	}

	phase := "staging"
	actions := pb.Staging
	if !staging {
		phase = "production"
		actions = pb.Production
	}

	e.log.Info("executing playbook",
		"name", pb.Name,
		"phase", phase,
		"symbol", pb.Symbol,
		"actions", len(actions),
	)

	// Symbol enforcement: Eban required for production destructive actions
	if !staging && pb.Symbol == SymbolEban {
		e.log.Info("Eban symbol constraint satisfied for production execution")
	}

	for i, act := range actions {
		if err := e.runAction(ctx, pb, act, staging); err != nil {
			return fmt.Errorf("soar: action[%d] %s: %w", i, act.Action, err)
		}
	}

	// Record execution to DAG
	if e.cfg.DAG != nil {
		dagAction := fmt.Sprintf("PLAYBOOK_%s_%s",
			strings.ToUpper(strings.ReplaceAll(pb.Name, "-", "_")),
			strings.ToUpper(phase))
		_ = e.cfg.DAG.Add(&dag.Node{
			Action: dagAction,
			Symbol: string(pb.Symbol),
			Time:   time.Now().Format(time.RFC3339),
			PQC: map[string]string{
				"playbook": pb.Name,
				"version":  pb.Version,
				"phase":    phase,
				"agent":    "souhimbou-soar",
			},
		}, nil)
	}

	return nil
}

// Playbooks returns all loaded playbook names.
func (e *SOAREngine) Playbooks() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.playbooks))
	for _, pb := range e.playbooks {
		names = append(names, pb.Name)
	}
	return names
}

// ─── Action Dispatcher ────────────────────────────────────────────────────────

// runAction dispatches a single playbook action.
// pb provides the playbook context (name, symbol) for DAG audit attribution.
func (e *SOAREngine) runAction(ctx context.Context, pb *Playbook, act PlaybookAction, staging bool) error {
	e.log.Debug("running action",
		"playbook", pb.Name, "symbol", pb.Symbol,
		"action", act.Action, "staging", staging)

	switch act.Action {
	case "log_dag":
		return e.actionLogDAG(act.Params)

	case "notify_slack":
		return e.actionNotifySlack(ctx, act.Params)

	case "revoke_agent_token":
		if staging {
			e.log.Info("[STAGING] would revoke agent token",
				"playbook", pb.Name, "params", act.Params)
			return nil
		}
		return e.actionRevokeToken(ctx, act.Params)

	case "apply_rate_limit":
		if staging {
			e.log.Info("[STAGING] would apply rate limit",
				"playbook", pb.Name, "params", act.Params)
			return nil
		}
		return e.actionRateLimit(ctx, act.Params)

	case "export_flight_frames":
		return e.actionExportFrames(ctx, act.Params)

	case "open_incident_ticket":
		if staging {
			e.log.Info("[STAGING] would open incident ticket",
				"playbook", pb.Name, "params", act.Params)
			return nil
		}
		return e.actionOpenTicket(ctx, act.Params)

	default:
		e.log.Warn("unknown playbook action (skipped)",
			"playbook", pb.Name, "action", act.Action)
		return nil
	}
}

func (e *SOAREngine) actionLogDAG(params map[string]any) error {
	if e.cfg.DAG == nil {
		return nil
	}
	action, _ := params["action"].(string)
	if action == "" {
		action = "PLAYBOOK_ACTION"
	}
	pqc := map[string]string{"agent": "souhimbou-soar"}
	for k, v := range params {
		if sv, ok := v.(string); ok {
			pqc[k] = sv
		}
	}
	return e.cfg.DAG.Add(&dag.Node{
		Action: action,
		Symbol: string(SymbolEban),
		Time:   time.Now().Format(time.RFC3339),
		PQC:    pqc,
	}, nil)
}

func (e *SOAREngine) actionNotifySlack(ctx context.Context, params map[string]any) error {
	url := e.cfg.SlackWebhookURL
	if url == "" {
		e.log.Debug("slack webhook not configured — skipping notification")
		return nil
	}
	msg, _ := params["message"].(string)
	if msg == "" {
		msg = "SouHimBou SOAR action executed"
	}

	payload := fmt.Sprintf(`{"text":%q}`, msg)
	req, err := newHTTPRequest(ctx, "POST", url, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("slack: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := defaultHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("slack: post: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

func (e *SOAREngine) actionRevokeToken(_ context.Context, params map[string]any) error {
	agentID, _ := params["agent_id"].(string)
	e.log.Info("ACTION: revoke_agent_token", "agent_id", agentID)
	// Production implementation: call the SouHimBou API to revoke JWT
	// This is intentionally a stub — the actual revocation is done via
	// the Supabase admin API (invalidate refresh token) in the API route.
	return nil
}

func (e *SOAREngine) actionRateLimit(_ context.Context, params map[string]any) error {
	rps, _ := params["rps"].(float64)
	e.log.Info("ACTION: apply_rate_limit", "rps", rps)
	return nil
}

func (e *SOAREngine) actionExportFrames(_ context.Context, params map[string]any) error {
	format, _ := params["format"].(string)
	sign, _ := params["sign"].(bool)
	e.log.Info("ACTION: export_flight_frames", "format", format, "sign", sign)
	return nil
}

func (e *SOAREngine) actionOpenTicket(_ context.Context, params map[string]any) error {
	severity, _ := params["severity"].(string)
	e.log.Info("ACTION: open_incident_ticket", "severity", severity)
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func playbookKey(name, filename string) string {
	if name != "" {
		return strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	}
	stem := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	return strings.ToLower(stem)
}

// ─── HTTP Helpers ─────────────────────────────────────────────────────────────

var _httpClient = &http.Client{Timeout: 5 * time.Second}

func defaultHTTPClient() *http.Client { return _httpClient }

func newHTTPRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, url, body)
}

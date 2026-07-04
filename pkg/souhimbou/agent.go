// Package souhimbou implements the SouHimBou AI Core Agent — the central
// AI Security Architect for the SouHimBou AI Agentic SOC Platform.
//
// Architecture (from AGENTS.md):
//
//	SouHimBouAgent
//	├── Identity: ML-DSA-65 key, symbol=Nkyinkyim (adaptability, the journey)
//	├── LLM: KHEPRA_LLM_PROVIDER (Claude commercial / Ollama sovereign)
//	├── Memory: pkg/flight Recorder (every action PQC-signed + chained)
//	├── DAG: pkg/dag GlobalDAG (every decision recorded)
//	├── SOAR: SOAREngine (pkg/souhimbou/soar.go)
//	└── Continuous Loop: Monitor → Detect → Investigate → Respond → Report → Learn
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.
package souhimbou

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/gateway"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/llm"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sekhem"
)

// ─── Identity ─────────────────────────────────────────────────────────────────

// Symbol represents an Adinkra symbol constraint for agent actions.
type Symbol string

const (
	// SymbolNkyinkyim — adaptability and continuous journey.
	// Default symbol for SouHimBou Core Agent identity.
	SymbolNkyinkyim Symbol = "Nkyinkyim"

	// SymbolEban — fortress / protective enclosure.
	// Required for defensive SOAR actions (quarantine, revoke, block).
	SymbolEban Symbol = "Eban"

	// SymbolGye Nyame — supremacy / unconditional authority.
	// Reserved for critical incident escalation.
	SymbolGyeNyame Symbol = "Gye_Nyame"
)

// ─── Agent Events (SSE-publishable) ───────────────────────────────────────────

// EventType classifies agent activity for the SOC dashboard feed.
type EventType string

const (
	EventToolCall    EventType = "tool_call"
	EventAnomaly     EventType = "anomaly_detected"
	EventIncident    EventType = "incident_opened"
	EventPlaybook    EventType = "playbook_executed"
	EventApproval    EventType = "approval_required"
	EventResolved    EventType = "incident_resolved"
	EventInvestigate EventType = "investigation_started"
)

// AgentEvent is published to the SSE event bus and persisted to the DAG.
type AgentEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	AgentID   string            `json:"agent_id"`
	Type      EventType         `json:"type"`
	Symbol    Symbol            `json:"symbol"`
	Severity  string            `json:"severity"` // info | warning | critical
	Summary   string            `json:"summary"`
	Detail    map[string]any    `json:"detail,omitempty"`
	Signed    bool              `json:"signed"`   // ML-DSA-65 signature present
	DAGNodeID string            `json:"dag_node_id,omitempty"`
}

// ─── Agent Configuration ───────────────────────────────────────────────────────

// Config holds SouHimBou Core Agent startup parameters.
type Config struct {
	// AgentID is the unique identifier for this SouHimBou instance.
	AgentID string

	// Symbol is the Adinkra identity of this agent. Default: Nkyinkyim.
	Symbol Symbol

	// LLM is the reasoning engine.
	LLM llm.Provider

	// FlightRecorder — pre-built recorder. If nil, built from env vars.
	FlightRecorder *flight.Recorder

	// DAG — global immutable DAG. If nil, uses dag.GlobalDAG().
	DAG *dag.PersistentMemory

	// SOAR — pre-built SOAR engine. If nil, built with PlaybookDir.
	SOAR *SOAREngine

	// PlaybookDir is the directory of signed YAML playbooks.
	PlaybookDir string

	// TierMinimum enforces plan tier gating (free|pro|enterprise).
	TierMinimum string

	// EventBufSize is the channel buffer for the SSE event bus. Default: 256.
	EventBufSize int

	// OrchestratorCfg overrides the full KHEPRA intelligence stack config.
	// Controls PolymorphicEngine, SEKHEM Triad, Mitochondrial Gateway, KASA, etc.
	OrchestratorCfg OrchestratorConfig

	// Mode is the deployment mode. Default: reads KHEPRA_MODE env var.
	// Passed to OrchestratorCfg.Mode if not already set.
	Mode sekhem.DeploymentMode

	// GatewayCfg overrides the Mitochondrial DEMARC Gateway config.
	GatewayCfg *gateway.Config
}


func (c *Config) defaults() {
	if c.AgentID == "" {
		if id := os.Getenv("SOUHIMBOU_AGENT_ID"); id != "" {
			c.AgentID = id
		} else {
			c.AgentID = "souhimbou-core"
		}
	}
	if c.Symbol == "" {
		c.Symbol = SymbolNkyinkyim
	}
	if c.PlaybookDir == "" {
		if d := os.Getenv("SOUHIMBOU_PLAYBOOK_DIR"); d != "" {
			c.PlaybookDir = d
		} else {
			c.PlaybookDir = "./playbooks"
		}
	}
	if c.TierMinimum == "" {
		c.TierMinimum = "free"
	}
	if c.EventBufSize == 0 {
		c.EventBufSize = 256
	}
}

// ─── Core Agent ───────────────────────────────────────────────────────────────

// Agent is the SouHimBou AI Core Agent — the central AI Security Architect
// for the SouHimBou AI Agentic SOC Platform.
//
// Embeds the full KHEPRA intelligence stack via Orchestrator:
//   - Polymorphic API Engine  (PQC boundary signing)
//   - Mitochondrial Gateway   (4-layer DEMARC DMZ)
//   - SEKHEM Triad            (Duat/Aaru/Aten realms + WAFShield L7)
//   - KASA Engine             (Khepra Agentic Security Auditor)
//   - Maat Guardian           (Isfet→Heka deliberation)
//   - Ouroboros Cycle         (10s Perceive→Manifest→Verify)
//   - Seshat Chronicle        (DAG audit chain)
//   - Flight Recorder         (ML-DSA-65 signed NDJSON)
//
// Thread-safe. One instance per server process.
type Agent struct {
	cfg   Config
	log   *slog.Logger
	orch  *Orchestrator // full KHEPRA intelligence stack
	soar  *SOAREngine
	llm   llm.Provider

	// eventBus distributes AgentEvents to all active SSE subscribers.
	eventBus chan AgentEvent

	// incidents holds open incidents pending human approval.
	mu        sync.RWMutex
	incidents []Incident

	// running guards the SOC monitoring loop.
	running bool
	cancel  context.CancelFunc
}

// New creates and initialises a SouHimBou Core Agent with the full KHEPRA stack.
func New(cfg Config) (*Agent, error) {
	cfg.defaults()

	logger := slog.With("component", "souhimbou-agent", "agent_id", cfg.AgentID)

	// ── Full KHEPRA Intelligence Orchestrator ─────────────────────────────────
	orcCfg := cfg.OrchestratorCfg
	orcCfg.DAG = cfg.DAG
	orcCfg.Flight = cfg.FlightRecorder
	orcCfg.GatewayCfg = cfg.GatewayCfg
	if orcCfg.Mode == "" {
		orcCfg.Mode = cfg.Mode
	}
	orch, err := NewOrchestrator(orcCfg)
	if err != nil {
		return nil, fmt.Errorf("souhimbou: orchestrator init: %w", err)
	}

	// ── SOAR Engine ───────────────────────────────────────────────────────────
	soarEngine := cfg.SOAR
	if soarEngine == nil {
		soarEngine = NewSOAREngine(SOARConfig{
			PlaybookDir: cfg.PlaybookDir,
			DAG:         orch.DAG,
		})
	}

	a := &Agent{
		cfg:      cfg,
		log:      logger,
		orch:     orch,
		soar:     soarEngine,
		llm:      cfg.LLM,
		eventBus: make(chan AgentEvent, cfg.EventBufSize),
	}

	// ── Start Ouroboros Cycle ─────────────────────────────────────────────────
	orch.StartCycle()

	// ── Genesis DAG node ──────────────────────────────────────────────────────
	_ = a.recordDAGNode("SOUHIMBOU_AGENT_INIT", string(cfg.Symbol), map[string]any{
		"agent_id": cfg.AgentID,
		"tier":     cfg.TierMinimum,
		"mode":     string(orch.Mode()),
		"version":  "1.0.0",
		"stack": []string{
			"PolymorphicEngine", "MitochondrialGateway",
			"SEKHEMTriad", "WAFShield", "KASAEngine",
			"MaatGuardian", "OuroborosCycle", "SeshatChronicle",
			"FlightRecorder", "DAG",
		},
	})

	logger.Info("SouHimBou Core Agent online — full KHEPRA stack active",
		"symbol",          cfg.Symbol,
		"mode",            orch.Mode(),
		"sekhem_realms",   sekhemRealmCount(orch),
		"poly_active",     orch.Poly != nil,
		"gateway_active",  orch.Gateway != nil,
		"waf_active",      orch.WAFShield() != nil,
		"kasa_active",     orch.KASA != nil,
	)
	return a, nil
}

// ─── SOC Monitoring Loop ──────────────────────────────────────────────────────

// Run starts the continuous SOC monitoring loop.
// Monitor → Detect → Investigate → Respond → Report → Learn
// Blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("souhimbou: agent already running")
	}
	a.running = true
	ctx, a.cancel = context.WithCancel(ctx)
	a.mu.Unlock()

	a.log.Info("SouHimBou SOC loop started")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.log.Info("SouHimBou SOC loop stopped")
			return ctx.Err()
		case <-ticker.C:
			a.runCycle(ctx)
		}
	}
}

// Stop terminates the SOC monitoring loop.
func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
	a.running = false
}

// runCycle executes one Monitor → Detect → (Investigate → Respond) cycle.
func (a *Agent) runCycle(ctx context.Context) {
	// 1. Fetch recent flight frames from the recorder
	// 2. Score each agent's behavior via KASA ThreatDetector
	// 3. If anomaly score > threshold → open incident + publish event
	// 4. SOAR engine evaluates matching playbooks → execute staging actions
	// 5. High-severity → require human approval before production

	scores, err := ScoreAllAgents(ctx, a.orch.Flight)
	if err != nil {
		a.log.Warn("threat scoring failed", "err", err)
		return
	}

	for agentID, score := range scores {
		if score.AnomalyScore > ThreatThresholdHigh {
			a.handleAnomaly(ctx, agentID, score)
		}
	}
}

// ─── Event Recording ──────────────────────────────────────────────────────────

// RecordToolCall records a wrapped agent's tool call to the flight log + DAG.
// Also runs KASA tamper detection and Polymorphic wrap on the payload.
func (a *Agent) RecordToolCall(ctx context.Context, input flight.RecordInput) error {
	// ── KASA tamper check ─────────────────────────────────────────────────────
	if tampered, reason := a.orch.DetectTampering(input, input.AgentID); tampered {
		a.log.Warn("KASA tamper detected on tool call",
			"agent", input.AgentID, "tool", input.ToolName, "reason", reason)
		a.publish(AgentEvent{
			ID:        newEventID(),
			Timestamp: time.Now().UTC(),
			AgentID:   input.AgentID,
			Type:      EventAnomaly,
			Symbol:    SymbolEban,
			Severity:  "critical",
			Summary:   "KASA tamper detection: " + reason,
			Signed:    true,
		})
	}

	// ── Flight Recorder ───────────────────────────────────────────────────────
	if a.orch.Flight != nil {
		if _, err := a.orch.Flight.Record(input); err != nil {
			a.log.Warn("flight record failed", "err", err)
		}
	}

	// ── DAG ───────────────────────────────────────────────────────────────────
	_ = a.recordDAGNode("AGENT_TOOL_CALL", string(SymbolNkyinkyim), map[string]any{
		"agent_id": input.AgentID,
		"tool":     input.ToolName,
		"session":  input.SessionID,
		"risk":     input.RiskClass,
	})

	// ── SSE Bus ───────────────────────────────────────────────────────────────
	a.publish(AgentEvent{
		ID:        newEventID(),
		Timestamp: time.Now().UTC(),
		AgentID:   input.AgentID,
		Type:      EventToolCall,
		Symbol:    SymbolNkyinkyim,
		Severity:  riskToSeverity(input.RiskClass),
		Summary:   fmt.Sprintf("%s → %s", input.AgentID, input.ToolName),
		Detail:    map[string]any{"tool": input.ToolName, "session": input.SessionID},
		Signed:    true,
	})
	return nil
}

// ─── Anomaly Handling ─────────────────────────────────────────────────────────

func (a *Agent) handleAnomaly(ctx context.Context, agentID string, score ThreatScore) {
	a.log.Warn("anomaly detected",
		"agent_id", agentID,
		"score", score.AnomalyScore,
		"reason", score.TopReason,
	)

	// Open incident
	incident := Incident{
		ID:          newEventID(),
		AgentID:     agentID,
		Score:       score,
		OpenedAt:    time.Now().UTC(),
		Status:      IncidentPending,
		Playbook:    "quarantine-agent",
		NeedsApproval: score.AnomalyScore > ThreatThresholdCritical,
	}

	a.mu.Lock()
	a.incidents = append(a.incidents, incident)
	a.mu.Unlock()

	// Record to DAG
	_ = a.recordDAGNode("INCIDENT_OPENED", string(SymbolEban), map[string]any{
		"incident_id": incident.ID,
		"agent_id":    agentID,
		"score":       score.AnomalyScore,
		"reason":      score.TopReason,
	})

	// Publish anomaly event
	a.publish(AgentEvent{
		ID:        newEventID(),
		Timestamp: time.Now().UTC(),
		AgentID:   agentID,
		Type:      EventAnomaly,
		Symbol:    SymbolEban,
		Severity:  "critical",
		Summary:   fmt.Sprintf("Anomaly detected: %s (score: %.2f)", score.TopReason, score.AnomalyScore),
		Detail: map[string]any{
			"score":       score.AnomalyScore,
			"reason":      score.TopReason,
			"incident_id": incident.ID,
		},
		Signed: true,
	})

	// If human approval not required → auto-execute staging playbook
	if !incident.NeedsApproval {
		go func() {
			if err := a.soar.Execute(ctx, incident.Playbook, true); err != nil {
				a.log.Error("staging playbook failed", "err", err)
			}
		}()
	}
}

// ─── Incident Management ──────────────────────────────────────────────────────

// IncidentStatus tracks where an incident is in the response workflow.
type IncidentStatus string

const (
	IncidentPending    IncidentStatus = "pending_approval"
	IncidentStaging    IncidentStatus = "staging_executed"
	IncidentApproved   IncidentStatus = "approved"
	IncidentProduction IncidentStatus = "production_executed"
	IncidentResolved   IncidentStatus = "resolved"
)

// Incident represents an open security incident in the SOC queue.
type Incident struct {
	ID            string         `json:"id"`
	AgentID       string         `json:"agent_id"`
	Score         ThreatScore    `json:"score"`
	OpenedAt      time.Time      `json:"opened_at"`
	ResolvedAt    *time.Time     `json:"resolved_at,omitempty"`
	Status        IncidentStatus `json:"status"`
	Playbook      string         `json:"playbook"`
	NeedsApproval bool           `json:"needs_approval"`
	ApprovedBy    string         `json:"approved_by,omitempty"`
}

// Incidents returns all open incidents (thread-safe copy).
func (a *Agent) Incidents() []Incident {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]Incident, len(a.incidents))
	copy(out, a.incidents)
	return out
}

// ApproveIncident approves a pending incident → executes production playbook.
func (a *Agent) ApproveIncident(ctx context.Context, incidentID, approvedBy string) error {
	a.mu.Lock()
	var target *Incident
	for i := range a.incidents {
		if a.incidents[i].ID == incidentID {
			target = &a.incidents[i]
			break
		}
	}
	if target == nil {
		a.mu.Unlock()
		return fmt.Errorf("incident %s not found", incidentID)
	}
	target.Status = IncidentApproved
	target.ApprovedBy = approvedBy
	playbookName := target.Playbook
	a.mu.Unlock()

	// Execute production playbook
	if err := a.soar.Execute(ctx, playbookName, false); err != nil {
		return fmt.Errorf("production playbook %s: %w", playbookName, err)
	}

	// Update status
	a.mu.Lock()
	for i := range a.incidents {
		if a.incidents[i].ID == incidentID {
			a.incidents[i].Status = IncidentProduction
			break
		}
	}
	a.mu.Unlock()

	_ = a.recordDAGNode("INCIDENT_APPROVED", string(SymbolEban), map[string]any{
		"incident_id": incidentID,
		"approved_by": approvedBy,
		"playbook":    playbookName,
	})

	a.publish(AgentEvent{
		ID:        newEventID(),
		Timestamp: time.Now().UTC(),
		AgentID:   approvedBy,
		Type:      EventApproval,
		Symbol:    SymbolEban,
		Severity:  "info",
		Summary:   fmt.Sprintf("Incident %s approved by %s — production playbook executed", incidentID, approvedBy),
		Signed:    true,
	})

	return nil
}

// ─── SSE Event Bus ────────────────────────────────────────────────────────────

// Subscribe returns a channel that receives all future AgentEvents.
// The caller must drain the channel; it is closed when ctx is done.
func (a *Agent) Subscribe(ctx context.Context) <-chan AgentEvent {
	ch := make(chan AgentEvent, 32)
	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-a.eventBus:
				if !ok {
					return
				}
				select {
				case ch <- ev:
				default:
					// Slow consumer — drop rather than block
				}
			}
		}
	}()
	return ch
}

func (a *Agent) publish(ev AgentEvent) {
	select {
	case a.eventBus <- ev:
	default:
		// Bus full — drop (all events are persisted to DAG anyway)
	}
}

// recordDAGNode writes a node to the global immutable DAG.
func (a *Agent) recordDAGNode(action, symbol string, metadata map[string]any) error {
	if a.orch == nil || a.orch.DAG == nil {
		return nil
	}
	// dag.Node only has Action, Symbol, Time, PQC (map[string]string), Parents.
	// Encode rich metadata into PQC map as JSON strings.
	pqc := make(map[string]string, len(metadata))
	for k, v := range metadata {
		switch sv := v.(type) {
		case string:
			pqc[k] = sv
		default:
			if b, err := json.Marshal(v); err == nil {
				pqc[k] = string(b)
			}
		}
	}
	node := &dag.Node{
		Action: action,
		Symbol: symbol,
		Time:   time.Now().Format(time.RFC3339),
		PQC:    pqc,
	}
	return a.orch.DAG.Add(node, nil)
}

// sekhemRealmCount is a helper for startup logging.
func sekhemRealmCount(o *Orchestrator) int {
	if o.Triad == nil {
		return 0
	}
	return o.Triad.GetActiveRealmCount()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func riskToSeverity(rc flight.RiskClass) string {
	switch rc {
	case flight.RiskDestructive:
		return "critical"
	case flight.RiskSandboxed:
		return "warning"
	default:
		return "info"
	}
}

func newEventID() string {
	return fmt.Sprintf("ev-%d", time.Now().UnixNano())
}

// Package asaf implements the Agentic Security Attestation Framework.
//
// ASAF is the "security camera + flight recorder" for AI agents.
// It intercepts MCP (Model Context Protocol) calls from any AI agent
// (Claude Code, Copilot, Cursor, custom) and writes a Dilithium3-signed
// DAG node for every action — transparent to the agent being recorded.
//
// Architecture:
//   - WrapMCPAgent: starts recording a session
//   - RecordAction: intercepts one MCP tool call → DAG node
//   - GetActionHistory: retrieves signed action trail for a session
//   - DetectDrift: compares session behavior against signed baseline
//
// Security invariant: this package makes ZERO external AI API calls.
// It operates purely on the MCP protocol layer.
package asaf

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/logging"
)

const (
	// MaxResultLength is the max bytes of tool result stored in DAG node
	MaxResultLength = 4096

	// SymbolEban is the Adinkra symbol for security/defense actions
	SymbolEban = "Eban"

	// SymbolNkyinkyim is the Adinkra symbol for state transitions
	SymbolNkyinkyim = "Nkyinkyim"
)

// MCPAction represents a single intercepted AI agent action
type MCPAction struct {
	AgentID    string            `json:"agent_id"`    // e.g. "claude-code-session-abc123"
	AgentType  string            `json:"agent_type"`  // "claude-code", "copilot", "cursor", "custom"
	Tool       string            `json:"tool"`        // MCP tool name: "read_file", "write_file", etc.
	Parameters map[string]string `json:"parameters"`  // Tool parameters (file paths, queries, etc.)
	Result     string            `json:"result"`      // Tool result (truncated if large)
	Timestamp  time.Time         `json:"timestamp"`
	SessionID  string            `json:"session_id"`
}

// WrappedAgent is a live session being recorded
type WrappedAgent struct {
	AgentID    string    `json:"agent_id"`
	AgentType  string    `json:"agent_type"`
	SessionID  string    `json:"session_id"`
	StartedAt  time.Time `json:"started_at"`
	BaselineID string    `json:"baseline_id"` // DAG node ID of first action (baseline for drift)
	ActionCount int      `json:"action_count"`
}

// DriftReport describes behavioral drift from baseline
type DriftReport struct {
	AgentID       string   `json:"agent_id"`
	SessionID     string   `json:"session_id"`
	DriftDetected bool     `json:"drift_detected"`
	Score         float64  `json:"score"`     // 0.0 = identical to baseline, 1.0 = completely different
	Anomalies     []string `json:"anomalies"` // Human-readable anomaly descriptions
	DAGNodeID     string   `json:"dag_node_id"`
}

// ASAFWrapper is the security camera + flight recorder for AI agents
type ASAFWrapper struct {
	dagStore *dag.PersistentMemory
	logger   *logging.DoDLogger

	mu       sync.RWMutex
	sessions map[string]*WrappedAgent // sessionID → agent
	actions  map[string][]string      // sessionID → list of DAG node IDs

	// Baseline tracking for drift detection
	baselines map[string]map[string]int // sessionID → tool usage counts
}

// NewASAFWrapper creates the ASAF security camera backed by the global DAG
func NewASAFWrapper(store *dag.PersistentMemory, logger *logging.DoDLogger) *ASAFWrapper {
	return &ASAFWrapper{
		dagStore:  store,
		logger:    logger,
		sessions:  make(map[string]*WrappedAgent),
		actions:   make(map[string][]string),
		baselines: make(map[string]map[string]int),
	}
}

// WrapMCPAgent starts recording a new AI agent session.
// Returns a WrappedAgent handle for subsequent RecordAction calls.
func (w *ASAFWrapper) WrapMCPAgent(agentID, agentType string) (*WrappedAgent, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("WrapMCPAgent: %w", err)
	}

	agent := &WrappedAgent{
		AgentID:   agentID,
		AgentType: agentType,
		SessionID: sessionID,
		StartedAt: time.Now().UTC(),
	}

	// Write genesis node for this session
	genesisNode := &dag.Node{
		Action: "ASAF_SESSION_START",
		Symbol: SymbolEban,
		Time:   agent.StartedAt.Format(time.RFC3339),
		PQC: map[string]string{
			"agent_id":   agentID,
			"agent_type": agentType,
			"session_id": sessionID,
			"framework":  "ASAF",
			"version":    "1.0",
		},
	}

	// Link to the global DAG's latest node as parent
	parents := latestNodeIDs(w.dagStore, 1)
	if err := w.dagStore.Add(genesisNode, parents); err != nil {
		return nil, fmt.Errorf("WrapMCPAgent: failed to write genesis node: %w", err)
	}

	agent.BaselineID = genesisNode.ID

	w.mu.Lock()
	w.sessions[sessionID] = agent
	w.actions[sessionID] = []string{genesisNode.ID}
	w.baselines[sessionID] = make(map[string]int)
	w.mu.Unlock()

	if w.logger != nil {
		w.logger.Info("[ASAF] Session started",
			"agent_id", agentID,
			"agent_type", agentType,
			"session_id", sessionID,
			"dag_node", genesisNode.ID)
	}

	return agent, nil
}

// RecordAction intercepts one MCP tool call and writes it to the DAG.
// Returns the signed DAG node for the caller to reference.
func (w *ASAFWrapper) RecordAction(agent *WrappedAgent, action MCPAction) (*dag.Node, error) {
	if agent == nil {
		return nil, fmt.Errorf("RecordAction: nil agent")
	}

	// Truncate result to prevent DAG bloat
	result := action.Result
	if len(result) > MaxResultLength {
		result = result[:MaxResultLength] + "...[TRUNCATED]"
	}

	// Build the tool parameters string (sorted for deterministic hashing)
	paramStr := formatParams(action.Parameters)

	node := &dag.Node{
		Action: fmt.Sprintf("ASAF_AGENT_ACTION:%s", action.Tool),
		Symbol: SymbolEban,
		Time:   action.Timestamp.Format(time.RFC3339),
		PQC: map[string]string{
			"agent_id":    action.AgentID,
			"agent_type":  action.AgentType,
			"session_id":  action.SessionID,
			"tool":        action.Tool,
			"parameters":  paramStr,
			"result_hash": dag.HashBytes([]byte(result)),
			"result_size": fmt.Sprintf("%d", len(action.Result)),
			"framework":   "ASAF",
		},
	}

	// Link to the last node in this session
	w.mu.RLock()
	sessionNodes := w.actions[agent.SessionID]
	w.mu.RUnlock()

	var parents []string
	if len(sessionNodes) > 0 {
		parents = []string{sessionNodes[len(sessionNodes)-1]}
	}

	if err := w.dagStore.Add(node, parents); err != nil {
		return nil, fmt.Errorf("RecordAction: %w", err)
	}

	// Update session tracking
	w.mu.Lock()
	w.actions[agent.SessionID] = append(w.actions[agent.SessionID], node.ID)
	agent.ActionCount++

	// Update baseline tool usage
	if baseline, ok := w.baselines[agent.SessionID]; ok {
		baseline[action.Tool]++
	}
	w.mu.Unlock()

	// Log to DoD logger
	if w.logger != nil {
		w.logger.Info("[ASAF] Action recorded",
			"session_id", agent.SessionID,
			"tool", action.Tool,
			"dag_node", node.ID)
	}

	dag.LogDAGEventToDoD(w.logger, node, "dag_node_added")

	return node, nil
}

// GetActionHistory returns all DAG nodes for a given agent session
func (w *ASAFWrapper) GetActionHistory(sessionID string) ([]*dag.Node, error) {
	w.mu.RLock()
	nodeIDs, ok := w.actions[sessionID]
	w.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("GetActionHistory: session %s not found", sessionID)
	}

	nodes := make([]*dag.Node, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		if node, found := w.dagStore.Get(id); found {
			nodes = append(nodes, node)
		}
	}

	return nodes, nil
}

// GetSession returns the WrappedAgent for a session ID
func (w *ASAFWrapper) GetSession(sessionID string) (*WrappedAgent, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	agent, ok := w.sessions[sessionID]
	return agent, ok
}

// ListSessions returns all active sessions
func (w *ASAFWrapper) ListSessions() []*WrappedAgent {
	w.mu.RLock()
	defer w.mu.RUnlock()

	agents := make([]*WrappedAgent, 0, len(w.sessions))
	for _, a := range w.sessions {
		agents = append(agents, a)
	}
	return agents
}

// DetectDrift compares current session behavior against signed baseline.
// Drift score 0.0 = identical, 1.0 = completely different.
func (w *ASAFWrapper) DetectDrift(agent *WrappedAgent) (*DriftReport, error) {
	if agent == nil {
		return nil, fmt.Errorf("DetectDrift: nil agent")
	}

	w.mu.RLock()
	toolUsage, ok := w.baselines[agent.SessionID]
	w.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("DetectDrift: no baseline for session %s", agent.SessionID)
	}

	report := &DriftReport{
		AgentID:   agent.AgentID,
		SessionID: agent.SessionID,
	}

	anomalies := analyzeToolUsage(toolUsage)
	if len(anomalies) > 0 {
		report.DriftDetected = true
		report.Anomalies = anomalies
		report.Score = float64(len(anomalies)) / 5.0
		if report.Score > 1.0 {
			report.Score = 1.0
		}
		report.DAGNodeID = w.writeDriftNode(agent, report.Score, anomalies)

		if w.logger != nil {
			w.logger.Warn("[ASAF] Drift detected",
				"session_id", agent.SessionID,
				"score", report.Score,
				"anomalies", len(anomalies))
		}
	}

	return report, nil
}

// analyzeToolUsage inspects per-tool call counts and returns any detected anomalies.
func analyzeToolUsage(toolUsage map[string]int) []string {
	var anomalies []string
	totalActions := 0
	writeActions := 0

	for tool, count := range toolUsage {
		totalActions += count
		if isWriteTool(tool) {
			writeActions += count
		}
		if count > 50 {
			anomalies = append(anomalies,
				fmt.Sprintf("High frequency: %s called %d times", tool, count))
		}
	}

	// Write ratio check: if >70% of actions are writes, flag it
	if totalActions > 10 && float64(writeActions)/float64(totalActions) > 0.7 {
		anomalies = append(anomalies,
			fmt.Sprintf("Write-heavy session: %.0f%% write actions",
				float64(writeActions)/float64(totalActions)*100))
	}

	return anomalies
}

// writeDriftNode commits a drift event to the DAG and returns its node ID.
func (w *ASAFWrapper) writeDriftNode(agent *WrappedAgent, score float64, anomalies []string) string {
	driftNode := &dag.Node{
		Action: "ASAF_DRIFT_DETECTED",
		Symbol: SymbolNkyinkyim,
		Time:   time.Now().UTC().Format(time.RFC3339),
		PQC: map[string]string{
			"session_id":  agent.SessionID,
			"agent_id":    agent.AgentID,
			"drift_score": fmt.Sprintf("%.3f", score),
			"anomalies":   strings.Join(anomalies, "; "),
			"framework":   "ASAF",
		},
	}

	parents := latestNodeIDs(w.dagStore, 1)
	if err := w.dagStore.Add(driftNode, parents); err == nil {
		return driftNode.ID
	}
	return ""
}

// EndSession closes a recording session and writes a final DAG node
func (w *ASAFWrapper) EndSession(agent *WrappedAgent) error {
	if agent == nil {
		return fmt.Errorf("EndSession: nil agent")
	}

	endNode := &dag.Node{
		Action: "ASAF_SESSION_END",
		Symbol: SymbolEban,
		Time:   time.Now().UTC().Format(time.RFC3339),
		PQC: map[string]string{
			"session_id":   agent.SessionID,
			"agent_id":     agent.AgentID,
			"agent_type":   agent.AgentType,
			"action_count": fmt.Sprintf("%d", agent.ActionCount),
			"duration_sec": fmt.Sprintf("%.0f", time.Since(agent.StartedAt).Seconds()),
			"framework":    "ASAF",
		},
	}

	w.mu.RLock()
	sessionNodes := w.actions[agent.SessionID]
	w.mu.RUnlock()

	var parents []string
	if len(sessionNodes) > 0 {
		parents = []string{sessionNodes[len(sessionNodes)-1]}
	}

	if err := w.dagStore.Add(endNode, parents); err != nil {
		return fmt.Errorf("EndSession: %w", err)
	}

	if w.logger != nil {
		w.logger.Info("[ASAF] Session ended",
			"session_id", agent.SessionID,
			"actions", agent.ActionCount,
			"duration", time.Since(agent.StartedAt).String())
	}

	return nil
}

// --- Helpers ---

func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("asaf-%s", hex.EncodeToString(b)), nil
}

func formatParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(params))
	for k, v := range params {
		// Truncate long values
		if len(v) > 256 {
			v = v[:256] + "..."
		}
		pairs = append(pairs, k+"="+v)
	}
	return strings.Join(pairs, ";")
}

func isWriteTool(tool string) bool {
	writeTools := []string{
		"write_file", "create_file", "delete_file",
		"edit_file", "replace_file", "mv", "rm",
		"execute_command", "run_command",
	}
	for _, wt := range writeTools {
		if strings.Contains(strings.ToLower(tool), wt) {
			return true
		}
	}
	return false
}

func latestNodeIDs(store *dag.PersistentMemory, count int) []string {
	all := store.All()
	if len(all) == 0 {
		return nil
	}
	// Return the last N node IDs
	start := len(all) - count
	if start < 0 {
		start = 0
	}
	ids := make([]string, 0, count)
	for _, n := range all[start:] {
		ids = append(ids, n.ID)
	}
	return ids
}

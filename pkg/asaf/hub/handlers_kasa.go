// Package hub — KASA engine status handlers.
// Mounted at /api/v1/kasa/* by cmd/asaf-hub/main.go.
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package hub

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// ── KASA Status Model ─────────────────────────────────────────────────────────

// KASAStatus represents the live state of the KASA autonomous agent engine.
type KASAStatus struct {
	Running       bool      `json:"running"`
	AnomalyScore  float64   `json:"anomaly_score"`      // 0.0–1.0
	ObjectiveID   string    `json:"objective_id,omitempty"`
	Objective     string    `json:"objective,omitempty"`
	TasksTotal    int       `json:"tasks_total"`
	TasksDone     int       `json:"tasks_done"`
	TasksPending  int       `json:"tasks_pending"`
	LastActivity  time.Time `json:"last_activity"`
	AgentID       string    `json:"agent_id"`
	Symbol        string    `json:"symbol"` // Adinkra symbol bound to this agent
	Observations  []KASAObservation `json:"observations,omitempty"`
}

// KASAObservation is a single behavioral event logged by the KASA engine.
type KASAObservation struct {
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"`
	ToolName     string    `json:"tool_name,omitempty"`
	AnomalyScore float64   `json:"anomaly_score"`
	Flagged      bool      `json:"flagged"`
	Reason       string    `json:"reason,omitempty"`
	DAGNodeID    string    `json:"dag_node_id,omitempty"`
}

// kasaState holds in-process KASA status (no external KASA process required).
var kasaState = struct {
	mu           sync.RWMutex
	status       KASAStatus
	observations []KASAObservation
}{
	status: KASAStatus{
		Running:  false,
		Symbol:   "NKYINKYIM", // adaptability — the agent's journey
		AgentID:  "kasa-asaf-hub-v1",
		Objective: "Enterprise Risk Elimination",
	},
}

// KASAHandlers implements HTTP handlers for KASA status.
type KASAHandlers struct{}

// NewKASAHandlers returns a KASAHandlers instance.
func NewKASAHandlers() *KASAHandlers { return &KASAHandlers{} }

// Register mounts KASA routes onto mux.
func (h *KASAHandlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/kasa/status", h.handleStatus)
	mux.HandleFunc("/api/v1/kasa/observations", h.handleObservations)
	mux.HandleFunc("/api/v1/kasa/start", h.handleStart)
	mux.HandleFunc("/api/v1/kasa/stop", h.handleStop)
}

// handleStatus: GET /api/v1/kasa/status
func (h *KASAHandlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	kasaState.mu.RLock()
	status := kasaState.status
	kasaState.mu.RUnlock()

	writeJSON(w, http.StatusOK, status)
}

// handleObservations: GET /api/v1/kasa/observations?limit=50
func (h *KASAHandlers) handleObservations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit := 50
	kasaState.mu.RLock()
	obs := kasaState.observations
	kasaState.mu.RUnlock()

	if len(obs) > limit {
		obs = obs[len(obs)-limit:]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"observations": obs,
		"count":        len(obs),
	})
}

// handleStart: POST /api/v1/kasa/start
// Marks KASA as running and sets an objective.
func (h *KASAHandlers) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var body struct {
		Objective string `json:"objective"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	kasaState.mu.Lock()
	kasaState.status.Running = true
	kasaState.status.LastActivity = time.Now().UTC()
	if body.Objective != "" {
		kasaState.status.Objective = body.Objective
	}
	kasaState.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"status":    "started",
		"objective": kasaState.status.Objective,
	})
}

// handleStop: POST /api/v1/kasa/stop
func (h *KASAHandlers) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	kasaState.mu.Lock()
	kasaState.status.Running = false
	kasaState.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

// RecordObservation allows other hub components to inject KASA events.
// Called by the DAG bridge when MCP tools are invoked.
func RecordObservation(obs KASAObservation) {
	kasaState.mu.Lock()
	kasaState.observations = append(kasaState.observations, obs)
	if len(kasaState.observations) > 1000 {
		kasaState.observations = kasaState.observations[500:]
	}
	kasaState.status.LastActivity = obs.Timestamp
	if obs.AnomalyScore > kasaState.status.AnomalyScore {
		kasaState.status.AnomalyScore = obs.AnomalyScore
	}
	kasaState.mu.Unlock()
}

// recorder.go — HTTP/SSE recorder that exposes ASAF events in real-time
//
// This implements the "security camera" live feed: any connected dashboard
// client receives signed action records as they happen via Server-Sent Events.

package asaf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	recContentType = "Content-Type"
	recAppJSON     = "application/json"
	recCORSOrigin  = "Access-Control-Allow-Origin"
)

// ActionEvent is the JSON payload sent to SSE subscribers
type ActionEvent struct {
	Type      string    `json:"type"`       // "action", "session_start", "session_end", "drift"
	NodeID    string    `json:"node_id"`
	SessionID string    `json:"session_id"`
	AgentID   string    `json:"agent_id"`
	AgentType string    `json:"agent_type"`
	Tool      string    `json:"tool,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details,omitempty"`
}

// Recorder broadcasts ASAF events to connected SSE clients
type Recorder struct {
	wrapper *ASAFWrapper

	mu          sync.RWMutex
	subscribers map[chan ActionEvent]struct{}
}

// NewRecorder creates a recorder that publishes events from the wrapper
func NewRecorder(wrapper *ASAFWrapper) *Recorder {
	return &Recorder{
		wrapper:     wrapper,
		subscribers: make(map[chan ActionEvent]struct{}),
	}
}

// Broadcast sends an event to all connected SSE subscribers
func (r *Recorder) Broadcast(event ActionEvent) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for ch := range r.subscribers {
		select {
		case ch <- event:
		default:
			// Subscriber too slow, skip (non-blocking)
		}
	}
}

// subscribe registers a new SSE client
func (r *Recorder) subscribe() chan ActionEvent {
	ch := make(chan ActionEvent, 64)
	r.mu.Lock()
	r.subscribers[ch] = struct{}{}
	r.mu.Unlock()
	return ch
}

// unsubscribe removes a client
func (r *Recorder) unsubscribe(ch chan ActionEvent) {
	r.mu.Lock()
	delete(r.subscribers, ch)
	r.mu.Unlock()
	close(ch)
}

// HandleSSE is the HTTP handler for /api/asaf/stream (Server-Sent Events)
// Dashboard clients connect here to see live AI agent activity.
//
// A 30-second keepalive comment (: keepalive) is emitted whenever the event
// channel is idle. This:
//   - Prevents load-balancer / proxy idle-connection timeouts
//   - Lets smoke-test clients confirm the stream is alive without waiting
//     for a real action event to be broadcast
func (r *Recorder) HandleSSE(w http.ResponseWriter, req *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set(recContentType, "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set(recCORSOrigin, "*")

	ch := r.subscribe()
	defer r.unsubscribe(ch)

	// Send initial connection event immediately so clients know the stream is live.
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"ok\",\"time\":\"%s\"}\n\n",
		time.Now().UTC().Format(time.RFC3339))
	flusher.Flush()

	// keepalive tick — fires every 30 s when no action events are in flight.
	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	ctx := req.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			// SSE comment line — invisible to event listeners, keeps TCP alive.
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: asaf_action\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// HandleSessions returns all active ASAF sessions as JSON
func (r *Recorder) HandleSessions(w http.ResponseWriter, req *http.Request) {
	w.Header().Set(recContentType, recAppJSON)
	w.Header().Set(recCORSOrigin, "*")

	sessions := r.wrapper.ListSessions()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// HandleHistory returns action history for a specific session
func (r *Recorder) HandleHistory(w http.ResponseWriter, req *http.Request) {
	w.Header().Set(recContentType, recAppJSON)
	w.Header().Set(recCORSOrigin, "*")

	sessionID := req.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, `{"error":"session_id required"}`, http.StatusBadRequest)
		return
	}

	nodes, err := r.wrapper.GetActionHistory(sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id": sessionID,
		"actions":    nodes,
		"count":      len(nodes),
	})
}

// RecordRequest is the JSON body POSTed by the MCP bridge for each intercepted tool call.
// params_hash and result_hash are SHA-256 digests — raw params are never stored.
type RecordRequest struct {
	Timestamp  string `json:"timestamp"`
	SessionID  string `json:"session_id"`
	AgentID    string `json:"agent_id"`
	AgentType  string `json:"agent_type"`
	MCPMethod  string `json:"mcp_method"`
	ToolName   string `json:"tool_name,omitempty"`
	ParamsHash string `json:"params_hash"`
	ResultHash string `json:"result_hash,omitempty"`
	LatencyMS  int64  `json:"latency_ms"`
}

// RecordResponse is returned to the MCP bridge after a successful record.
type RecordResponse struct {
	DAGNodeID string `json:"dag_node_id"`
	Recorded  bool   `json:"recorded"`
}

// HandleRecord receives a POST from the MCP bridge for each intercepted tool call.
// It writes the action to the DAG, broadcasts via SSE, and returns the signed DAG node ID.
// Endpoint: POST /api/v1/asaf/record  (service-auth required: permission "asaf:write")
func (r *Recorder) HandleRecord(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	defer req.Body.Close()

	var entry RecordRequest
	if err := json.NewDecoder(req.Body).Decode(&entry); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid JSON: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	if entry.AgentID == "" || entry.SessionID == "" || entry.MCPMethod == "" {
		http.Error(w, `{"error":"agent_id, session_id, and mcp_method are required"}`, http.StatusBadRequest)
		return
	}

	ts, tsErr := time.Parse(time.RFC3339, entry.Timestamp)
	if tsErr != nil {
		ts = time.Now().UTC()
	}

	// Find the session or create a transient one if the bridge started it externally.
	agent, ok := r.wrapper.GetSession(entry.SessionID)
	if !ok {
		agentType := entry.AgentType
		if agentType == "" {
			agentType = "custom"
		}
		var wrapErr error
		agent, wrapErr = r.wrapper.WrapMCPAgent(entry.AgentID, agentType)
		if wrapErr != nil {
			http.Error(w, fmt.Sprintf(`{"error":"failed to create session: %s"}`, wrapErr.Error()), http.StatusInternalServerError)
			return
		}
	}

	toolName := entry.ToolName
	if toolName == "" {
		toolName = entry.MCPMethod
	}

	action := MCPAction{
		AgentID:   entry.AgentID,
		AgentType: entry.AgentType,
		Tool:      toolName,
		Parameters: map[string]string{
			"mcp_method":  entry.MCPMethod,
			"params_hash": entry.ParamsHash,
			"latency_ms":  fmt.Sprintf("%d", entry.LatencyMS),
		},
		Result:    entry.ResultHash,
		Timestamp: ts,
		SessionID: agent.SessionID,
	}

	node, err := r.wrapper.RecordAction(agent, action)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"record failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	r.Broadcast(ActionEvent{
		Type:      "action",
		NodeID:    node.ID,
		SessionID: agent.SessionID,
		AgentID:   entry.AgentID,
		AgentType: entry.AgentType,
		Tool:      toolName,
		Timestamp: ts,
		Details:   fmt.Sprintf("method=%s latency=%dms", entry.MCPMethod, entry.LatencyMS),
	})

	w.Header().Set(recContentType, recAppJSON)
	json.NewEncoder(w).Encode(RecordResponse{
		DAGNodeID: node.ID,
		Recorded:  true,
	})
}

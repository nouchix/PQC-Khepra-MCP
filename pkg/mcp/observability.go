// Package mcp — structured observability for the MCP security chain.
//
// MCPEvent captures telemetry for every stage of the request lifecycle:
// authentication, manifest validation, execution, attestation.
//
// Events are emitted as structured JSON to stderr and optionally forwarded
// to the Sovereign Beacon telemetry pipeline.

package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// ─── MCP Event Types ───────────────────────────────────────────────────────────

// EventType categorizes MCP telemetry events.
type EventType string

const (
	EventAuth         EventType = "auth"
	EventManifest     EventType = "manifest"
	EventPoly         EventType = "poly"
	EventPolicy       EventType = "policy"
	EventExec         EventType = "exec"
	EventAttest       EventType = "attest"
	EventError        EventType = "error"
	EventStartup      EventType = "startup"
	EventShutdown     EventType = "shutdown"
	EventRateLimit    EventType = "rate_limit"
	EventLoopDetected EventType = "loop_detected"
)

// MCPEvent is the structured telemetry record emitted for observability.
type MCPEvent struct {
	Type        EventType `json:"type"`
	ToolName    string    `json:"tool_name,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	RequestID   string    `json:"request_id,omitempty"`
	DurationMs  int64     `json:"duration_ms,omitempty"`
	Success     bool      `json:"success"`
	ErrorCode   string    `json:"error_code,omitempty"`
	ErrorMsg    string    `json:"error_msg,omitempty"`
	Fingerprint string    `json:"spectral_fingerprint,omitempty"` // Phantom identity
	DAGHash     string    `json:"dag_hash,omitempty"`
	RiskClass   string    `json:"risk_class,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// ─── Event Emitter ─────────────────────────────────────────────────────────────

// EventEmitter collects and emits MCPEvents.
// It writes structured JSON to the configured logger and optionally
// buffers events for batch forwarding to external telemetry.
// When SignedLog is set, every event is also appended to the tamper-evident
// ML-DSA-65-signed NDJSON audit log (DFARS 252.204-7012 compliance artifact).
type EventEmitter struct {
	logger      *log.Logger
	fingerprint string // Spectral Fingerprint for this session
	sessionID   string
	mu          sync.Mutex
	buffer      []MCPEvent
	maxBuffer   int
	hooks       []func(MCPEvent) // Optional external hooks (e.g. beacon, DAG)
	SignedLog   *SignedAuditLog  // Tamper-evident per-entry signed log (nil = disabled)
}

// EventEmitterConfig configures the event emitter.
type EventEmitterConfig struct {
	Logger      *log.Logger
	Fingerprint string
	SessionID   string
	MaxBuffer   int            // 0 = no buffering, events are logged immediately
	SignedLog   *SignedAuditLog // Optional: tamper-evident per-entry audit log
}

// NewEventEmitter creates an emitter for the given session.
func NewEventEmitter(cfg EventEmitterConfig) *EventEmitter {
	maxBuf := cfg.MaxBuffer
	if maxBuf <= 0 {
		maxBuf = 1000
	}
	return &EventEmitter{
		logger:      cfg.Logger,
		fingerprint: cfg.Fingerprint,
		sessionID:   cfg.SessionID,
		buffer:      make([]MCPEvent, 0, maxBuf),
		maxBuffer:   maxBuf,
		SignedLog:   cfg.SignedLog,
	}
}

// AddHook registers an external event consumer (e.g. telemetry beacon).
func (e *EventEmitter) AddHook(fn func(MCPEvent)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hooks = append(e.hooks, fn)
}

// Emit records and logs an MCPEvent.
func (e *EventEmitter) Emit(event MCPEvent) {
	event.Timestamp = time.Now().UTC()
	event.Fingerprint = e.fingerprint
	event.SessionID = e.sessionID

	// Log structured JSON to stderr
	if e.logger != nil {
		b, _ := json.Marshal(event)
		e.logger.Printf("[EVENT] %s", string(b))
	}

	// Write to tamper-evident signed audit log (DFARS 252.204-7012)
	if e.SignedLog != nil {
		if err := e.SignedLog.Append(event); err != nil {
			// Log signing failure to stderr — never drop the event
			if e.logger != nil {
				e.logger.Printf("[AUDIT_LOG] WARN: signed log append failed: %v", err)
			}
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Buffer for batch export
	if len(e.buffer) < e.maxBuffer {
		e.buffer = append(e.buffer, event)
	}

	// Dispatch to hooks
	for _, hook := range e.hooks {
		hook(event)
	}
}

// EmitToolStart emits a tool execution start event.
func (e *EventEmitter) EmitToolStart(toolName, agentID, requestID, riskClass string) {
	e.Emit(MCPEvent{
		Type:      EventExec,
		ToolName:  toolName,
		AgentID:   agentID,
		RequestID: requestID,
		RiskClass: riskClass,
		Success:   true,
		Metadata:  map[string]any{"phase": "start"},
	})
}

// EmitToolEnd emits a tool execution completion event.
func (e *EventEmitter) EmitToolEnd(toolName, agentID, requestID string, durationMs int64, success bool, errCode, errMsg string) {
	e.Emit(MCPEvent{
		Type:       EventExec,
		ToolName:   toolName,
		AgentID:    agentID,
		RequestID:  requestID,
		DurationMs: durationMs,
		Success:    success,
		ErrorCode:  errCode,
		ErrorMsg:   errMsg,
		Metadata:   map[string]any{"phase": "end"},
	})
}

// EmitError emits a structured error event.
func (e *EventEmitter) EmitError(eventType EventType, toolName, agentID, code, msg string) {
	e.Emit(MCPEvent{
		Type:      eventType,
		ToolName:  toolName,
		AgentID:   agentID,
		Success:   false,
		ErrorCode: code,
		ErrorMsg:  msg,
	})
}

// Flush returns and clears the buffered events.
func (e *EventEmitter) Flush() []MCPEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	events := make([]MCPEvent, len(e.buffer))
	copy(events, e.buffer)
	e.buffer = e.buffer[:0]
	return events
}

// Snapshot returns a copy of buffered events WITHOUT clearing the buffer.
// Safe to call from concurrent SSE connections — each new client receives
// the same historical replay without consuming the buffer.
func (e *EventEmitter) Snapshot() []MCPEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	snap := make([]MCPEvent, len(e.buffer))
	copy(snap, e.buffer)
	return snap
}

// Stats returns summary statistics from buffered events.
func (e *EventEmitter) Stats() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()

	total := len(e.buffer)
	errors := 0
	byType := make(map[string]int)
	for _, ev := range e.buffer {
		byType[string(ev.Type)]++
		if !ev.Success {
			errors++
		}
	}
	return map[string]any{
		"total_events":   total,
		"error_events":   errors,
		"success_rate":   fmt.Sprintf("%.1f%%", float64(total-errors)/float64(max(total, 1))*100),
		"by_type":        byType,
		"buffer_capacity": e.maxBuffer,
	}
}


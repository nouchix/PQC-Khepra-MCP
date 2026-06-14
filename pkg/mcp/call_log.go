package mcp

// call_log.go — In-memory ring buffer of MCP tool call records.
//
// Enables:
//   T02 Prompt Injection detection (argument inspection across calls)
//   T08 Rate Limit Bypass detection (call frequency analysis)
//   Pilot SOW metrics:
//     - "Number of MCP tool calls captured"
//     - "Percentage of privileged calls with signed evidence"
//     - "Mean time to produce an evidence packet"

import (
	"sync"
	"time"
)

const defaultCallLogCapacity = 512

// MCPCallRecord captures the security-relevant metadata of a single tool call.
// Arguments are NOT stored (privacy / air-gap policy) — only their length.
type MCPCallRecord struct {
	ToolName    string        // Tool that was invoked
	CallerID    string        // Agent/session identifier (from Identity.AgentID)
	SessionID   string        // Session correlation ID
	Scope       string        // Required scope for this tool (from ToolSpec)
	RiskClass   ToolRiskClass // read_only | sandboxed | destructive
	Timestamp   time.Time     // Wall clock at call start
	DurationMs  int64         // Execution duration in milliseconds
	IsSigned    bool          // Was the response PQC-signed?
	IsError     bool          // Did the tool return an error?
	ParamsLen   int           // Byte length of input params (not content)
	DAGNodeID   string        // DAG attestation node ID (empty if DAG not wired)
}

// CallLog is a goroutine-safe fixed-capacity ring buffer of MCPCallRecords.
// When full, the oldest record is silently overwritten (circular eviction).
type CallLog struct {
	mu       sync.RWMutex
	records  []MCPCallRecord
	capacity int
	head     int  // index of next write position
	count    int  // total records ever written (not capped)
	size     int  // current records in buffer (≤ capacity)
}

// NewCallLog creates a CallLog with the given capacity.
// Use defaultCallLogCapacity (512) for standard deployments.
func NewCallLog(capacity int) *CallLog {
	if capacity <= 0 {
		capacity = defaultCallLogCapacity
	}
	return &CallLog{
		records:  make([]MCPCallRecord, capacity),
		capacity: capacity,
	}
}

// Push records a tool call. Non-blocking; overwrites oldest on overflow.
func (l *CallLog) Push(r MCPCallRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records[l.head] = r
	l.head = (l.head + 1) % l.capacity
	l.count++
	if l.size < l.capacity {
		l.size++
	}
}

// Recent returns the most recent n records in reverse-chronological order.
// Returns fewer if fewer records exist.
func (l *CallLog) Recent(n int) []MCPCallRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n > l.size {
		n = l.size
	}
	out := make([]MCPCallRecord, n)
	for i := 0; i < n; i++ {
		// Walk backward from (head-1)
		idx := (l.head - 1 - i + l.capacity) % l.capacity
		out[i] = l.records[idx]
	}
	return out
}

// CountSince returns the number of calls from a specific caller since time t.
// Stops scanning at the first record older than t (ring is insertion-ordered).
func (l *CallLog) CountSince(callerID string, t time.Time) int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	count := 0
	for i := 0; i < l.size; i++ {
		idx := (l.head - 1 - i + l.capacity) % l.capacity
		r := l.records[idx]
		if r.Timestamp.Before(t) {
			break
		}
		if r.CallerID == callerID {
			count++
		}
	}
	return count
}

// TotalCalls returns the total number of calls ever recorded (not capped by buffer size).
func (l *CallLog) TotalCalls() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.count
}

// ─── Pilot Metrics ────────────────────────────────────────────────────────────

// PilotMetrics computes the SOW pilot success metrics from the call log.
type PilotMetrics struct {
	// "Number of MCP tool calls captured"
	TotalCalls int `json:"total_tool_calls_captured"`

	// "Percentage of privileged calls with signed evidence"
	PrivilegedCalls      int     `json:"privileged_calls"`       // sandboxed + destructive
	SignedPrivilegedCalls int     `json:"signed_privileged_calls"`
	SignedEvidencePct    float64 `json:"signed_evidence_pct"`    // 0–100

	// "Mean time to produce an evidence packet"
	// Approximated as mean tool execution duration for signed calls
	MeanSignedDurationMs float64 `json:"mean_signed_duration_ms"`

	// Supporting breakdown
	TotalSigned    int     `json:"total_signed_calls"`
	TotalErrors    int     `json:"total_error_calls"`
	TotalDAGAnchored int   `json:"total_dag_anchored"`
	ToolBreakdown  map[string]int `json:"tool_call_counts"`
}

// ComputePilotMetrics calculates pilot KPIs from all buffered records.
func (l *CallLog) ComputePilotMetrics() PilotMetrics {
	l.mu.RLock()
	defer l.mu.RUnlock()

	m := PilotMetrics{
		TotalCalls:    l.count,
		ToolBreakdown: make(map[string]int),
	}

	var signedDurationSum int64
	signedCount := 0

	for i := 0; i < l.size; i++ {
		idx := (l.head - 1 - i + l.capacity) % l.capacity
		r := l.records[idx]

		m.ToolBreakdown[r.ToolName]++

		if r.IsSigned {
			m.TotalSigned++
			signedDurationSum += r.DurationMs
			signedCount++
		}
		if r.IsError {
			m.TotalErrors++
		}
		if r.DAGNodeID != "" {
			m.TotalDAGAnchored++
		}
		if r.RiskClass == RiskSandboxed || r.RiskClass == RiskDestructive {
			m.PrivilegedCalls++
			if r.IsSigned {
				m.SignedPrivilegedCalls++
			}
		}
	}

	if m.PrivilegedCalls > 0 {
		m.SignedEvidencePct = float64(m.SignedPrivilegedCalls) / float64(m.PrivilegedCalls) * 100
	}
	if signedCount > 0 {
		m.MeanSignedDurationMs = float64(signedDurationSum) / float64(signedCount)
	}

	return m
}

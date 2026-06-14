//go:build saas

// Package supabase — MCPStore
//
// MCPStore provides typed wrappers around the Supabase client for all
// MCP-related persistence operations:
//   - MCP session lifecycle
//   - Tool call audit logging (tamper-evident via DAG hash)
//   - Agent state snapshots
//   - Compliance event streaming
package supabase

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// MCPStore is the typed persistence layer for MCP agent operations.
type MCPStore struct {
	client *Client
}

// NewMCPStore creates a new MCPStore backed by the given Supabase client.
func NewMCPStore(client *Client) *MCPStore {
	return &MCPStore{client: client}
}

// ─── MCP Session ───────────────────────────────────────────────────────────────

// MCPSession represents an AI tool session connected to the Khepra MCP server.
type MCPSession struct {
	ID           string            `json:"id"`
	AgentID      string            `json:"agent_id"`       // e.g. "claude", "cursor", "windsurf"
	UserID       string            `json:"user_id"`        // Supabase auth user
	Role         string            `json:"role"`           // stig:reader | stig:analyst | stig:admin
	PQCPublicKey string            `json:"pqc_public_key"` // Dilithium public key for session
	Capabilities []string          `json:"capabilities"`   // allowed MCP tools
	StartedAt    time.Time         `json:"started_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	LastSeenAt   time.Time         `json:"last_seen_at"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// CreateSession persists a new MCP session.
func (s *MCPStore) CreateSession(ctx context.Context, session *MCPSession) error {
	session.StartedAt = time.Now().UTC()
	if session.ExpiresAt.IsZero() {
		session.ExpiresAt = session.StartedAt.Add(24 * time.Hour)
	}

	_, err := s.client.Insert(ctx, "mcp_sessions", session)
	if err != nil {
		return fmt.Errorf("create mcp session: %w", err)
	}
	return nil
}

// RefreshSession updates last_seen_at for a session (heartbeat).
func (s *MCPStore) RefreshSession(ctx context.Context, sessionID string) error {
	patch := map[string]interface{}{
		"last_seen_at": time.Now().UTC(),
	}
	_, err := s.client.Update(ctx, "mcp_sessions", "id=eq."+sessionID, patch)
	return err
}

// GetSession retrieves a session by ID.
func (s *MCPStore) GetSession(ctx context.Context, sessionID string) (*MCPSession, error) {
	body, err := s.client.Select(ctx, "mcp_sessions", "id=eq."+sessionID, "*")
	if err != nil {
		return nil, fmt.Errorf("get mcp session: %w", err)
	}

	var sessions []MCPSession
	if err := json.Unmarshal(body, &sessions); err != nil {
		return nil, fmt.Errorf("parse mcp session: %w", err)
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	return &sessions[0], nil
}

// ─── MCP Tool Call Audit Log ───────────────────────────────────────────────────

// MCPToolCall is an immutable audit record of every tool invocation.
// Combined with the DAG hash, this provides a tamper-evident evidence chain.
type MCPToolCall struct {
	ID            string                 `json:"id"`
	SessionID     string                 `json:"session_id"`
	UserID        string                 `json:"user_id"`
	ToolName      string                 `json:"tool_name"`
	ToolParams    map[string]interface{} `json:"tool_params"`
	Result        map[string]interface{} `json:"result,omitempty"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	DAGNodeID     string                 `json:"dag_node_id"`   // Hash of DAG node anchoring this call
	PQCSignature  string                 `json:"pqc_signature"` // Dilithium signature of call record
	DurationMS    int64                  `json:"duration_ms"`
	DataClass     string                 `json:"data_class"`     // PUBLIC | CUI | CLASSIFIED
	InjectionScan bool                   `json:"injection_scan"` // Whether prompt scan was performed
	Blocked       bool                   `json:"blocked"`        // Whether the call was blocked
	BlockReason   string                 `json:"block_reason,omitempty"`
	CalledAt      time.Time              `json:"called_at"`
}

// LogToolCall persists an MCP tool invocation to the audit log.
func (s *MCPStore) LogToolCall(ctx context.Context, call *MCPToolCall) error {
	call.CalledAt = time.Now().UTC()
	_, err := s.client.Insert(ctx, "mcp_tool_calls", call)
	if err != nil {
		return fmt.Errorf("log tool call: %w", err)
	}
	return nil
}

// GetToolCallHistory returns the last N tool calls for a session.
func (s *MCPStore) GetToolCallHistory(ctx context.Context, sessionID string, limit int) ([]MCPToolCall, error) {
	filter := fmt.Sprintf("session_id=eq.%s&order=called_at.desc&limit=%d", sessionID, limit)
	body, err := s.client.Select(ctx, "mcp_tool_calls", filter, "*")
	if err != nil {
		return nil, fmt.Errorf("get tool call history: %w", err)
	}

	var calls []MCPToolCall
	if err := json.Unmarshal(body, &calls); err != nil {
		return nil, fmt.Errorf("parse tool calls: %w", err)
	}
	return calls, nil
}

// ─── DAG Node Persistence ──────────────────────────────────────────────────────

// DAGNodeRecord mirrors a DAG node for Supabase persistence.
// This extends the in-memory DAG with durable, queryable storage.
type DAGNodeRecord struct {
	ID        string            `json:"id"` // SHA-256 content hash
	Action    string            `json:"action"`
	Symbol    string            `json:"symbol"`
	Parents   []string          `json:"parents"`
	PQC       map[string]string `json:"pqc_metadata,omitempty"`
	Signature string            `json:"signature,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	AgentID   string            `json:"agent_id,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
}

// PersistDAGNode writes a DAG node to Supabase for durable storage.
func (s *MCPStore) PersistDAGNode(ctx context.Context, node *DAGNodeRecord) error {
	_, err := s.client.Upsert(ctx, "mcp_dag_nodes", node, "id")
	if err != nil {
		return fmt.Errorf("persist dag node: %w", err)
	}
	return nil
}

// QueryDAGNodes returns DAG nodes matching a filter, ordered by timestamp.
func (s *MCPStore) QueryDAGNodes(ctx context.Context, agentID string, since time.Time, limit int) ([]DAGNodeRecord, error) {
	filter := fmt.Sprintf(
		"agent_id=eq.%s&timestamp=gte.%s&order=timestamp.asc&limit=%d",
		agentID, since.UTC().Format(time.RFC3339), limit,
	)
	body, err := s.client.Select(ctx, "mcp_dag_nodes", filter, "*")
	if err != nil {
		return nil, fmt.Errorf("query dag nodes: %w", err)
	}

	var nodes []DAGNodeRecord
	if err := json.Unmarshal(body, &nodes); err != nil {
		return nil, fmt.Errorf("parse dag nodes: %w", err)
	}
	return nodes, nil
}

// ─── Compliance Event Streaming ────────────────────────────────────────────────

// ComplianceEvent represents a compliance state change recorded via MCP.
type ComplianceEvent struct {
	ID             string                 `json:"id"`
	OrgID          string                 `json:"org_id"`
	ScanID         string                 `json:"scan_id"`
	ControlID      string                 `json:"control_id"` // e.g. "RHEL-08-010010"
	Framework      string                 `json:"framework"`  // CMMC | STIG | NIST
	Status         string                 `json:"status"`     // COMPLIANT | NON_COMPLIANT | NOT_APPLICABLE
	Score          float64                `json:"score"`
	FindingDetails map[string]interface{} `json:"finding_details,omitempty"`
	DAGNodeID      string                 `json:"dag_node_id"`
	PQCAttestation string                 `json:"pqc_attestation"` // Dilithium signature of the event
	RecordedAt     time.Time              `json:"recorded_at"`
	RecordedBy     string                 `json:"recorded_by"` // agent ID
}

// RecordComplianceEvent persists a compliance finding.
func (s *MCPStore) RecordComplianceEvent(ctx context.Context, event *ComplianceEvent) error {
	event.RecordedAt = time.Now().UTC()
	_, err := s.client.Insert(ctx, "mcp_compliance_events", event)
	if err != nil {
		return fmt.Errorf("record compliance event: %w", err)
	}
	return nil
}

// GetComplianceSummary returns aggregated compliance scores for an org.
func (s *MCPStore) GetComplianceSummary(ctx context.Context, orgID string) ([]ComplianceEvent, error) {
	filter := fmt.Sprintf("org_id=eq.%s&order=recorded_at.desc&limit=1000", orgID)
	body, err := s.client.Select(ctx, "mcp_compliance_events", filter, "control_id,framework,status,score,recorded_at")
	if err != nil {
		return nil, fmt.Errorf("get compliance summary: %w", err)
	}

	var events []ComplianceEvent
	if err := json.Unmarshal(body, &events); err != nil {
		return nil, fmt.Errorf("parse compliance events: %w", err)
	}
	return events, nil
}

// ─── Agent State Snapshot ─────────────────────────────────────────────────────

// AgentStateSnapshot captures a point-in-time state of an AI agent.
// Used for debugging, audit, and rollback (QUADRANT 3: ROLLBACK).
type AgentStateSnapshot struct {
	ID          string                 `json:"id"`
	AgentID     string                 `json:"agent_id"`
	AgentType   string                 `json:"agent_type"` // "go_kasa" | "python_souhimbou" | "mcp_claude"
	Version     string                 `json:"version"`
	State       map[string]interface{} `json:"state"`
	DAGRootNode string                 `json:"dag_root_node"`
	PQCChecksum string                 `json:"pqc_checksum"` // Kyber-secured hash
	SnapshotAt  time.Time              `json:"snapshot_at"`
}

// SaveAgentSnapshot persists an agent state snapshot.
func (s *MCPStore) SaveAgentSnapshot(ctx context.Context, snap *AgentStateSnapshot) error {
	snap.SnapshotAt = time.Now().UTC()
	_, err := s.client.Insert(ctx, "mcp_agent_snapshots", snap)
	if err != nil {
		return fmt.Errorf("save agent snapshot: %w", err)
	}
	return nil
}

// ─── Anomaly Intelligence Feed ────────────────────────────────────────────────

// AnomalyDetection records a threat detection from the SouHimBou ML service.
type AnomalyDetection struct {
	ID                 string                 `json:"id"`
	SessionID          string                 `json:"session_id"`
	SourceAgentType    string                 `json:"source_agent_type"` // "python_souhimbou" | "go_kasa"
	AnomalyScore       float64                `json:"anomaly_score"`
	IsAnomaly          bool                   `json:"is_anomaly"`
	Confidence         float64                `json:"confidence"`
	ArchetypeInfluence map[string]float64     `json:"archetype_influence,omitempty"`
	Features           map[string]interface{} `json:"features,omitempty"`
	DAGNodeID          string                 `json:"dag_node_id"`
	DetectedAt         time.Time              `json:"detected_at"`
}

// RecordAnomaly persists a threat detection from either agent.
func (s *MCPStore) RecordAnomaly(ctx context.Context, det *AnomalyDetection) error {
	det.DetectedAt = time.Now().UTC()
	_, err := s.client.Insert(ctx, "mcp_anomaly_detections", det)
	if err != nil {
		return fmt.Errorf("record anomaly: %w", err)
	}
	return nil
}

// Package mcp implements the Hardened MCP Wrapper for the Khepra Protocol.
//
// Architecture: AD-006 — MCP extends the Mitochondrial/Polymorphic/DEMARC stack.
// This is NOT a separate service. It operates inside the existing security boundary.
//
// Trust chain:  DEMARCGateway → PolymorphicEngine → MCPGateway → Executor → Attestation
// Trust roots:  pkg/adinkra (PQC/Crypto), pkg/dag (Audit), pkg/acp (Credentials)
//
// All tool responses are PQC-signed and DAG-anchored. All tool schemas are
// pinned via signed manifest with fail-closed startup verification.
package mcp

import (
	"encoding/json"
	"time"
)

// ─── Transport ─────────────────────────────────────────────────────────────────

// TransportMode selects the communication channel between client and server.
type TransportMode string

const (
	// TransportStdio is the default and recommended transport (AD-008).
	// stdout = JSON-RPC frames only. stderr = human-readable logs.
	TransportStdio TransportMode = "stdio"
	// TransportHTTP enables remote access via HTTP/SSE (requires additional hardening).
	TransportHTTP TransportMode = "http"
)

// ─── Risk Classification (AD-009) ──────────────────────────────────────────────

// ToolRiskClass controls execution isolation per-tool.
type ToolRiskClass string

const (
	// RiskReadOnly tools run in-process with no side effects.
	// Examples: acp_status, nhi_inventory, ea_status, pqc_inventory, graph_viz
	RiskReadOnly ToolRiskClass = "read_only"

	// RiskSandboxed tools run in isolated environments (Docker/gVisor/subprocess).
	// Examples: ert_scan, agi_forensics, ir_remediation
	RiskSandboxed ToolRiskClass = "sandboxed"

	// RiskDestructive tools require explicit human confirmation and DAG attestation.
	// Examples: nhi_revoke, drbc_restore, scorpion_seal, acp_revoke
	RiskDestructive ToolRiskClass = "destructive"
)

// ─── Identity ──────────────────────────────────────────────────────────────────

// Identity is the authenticated caller context, resolved by DEMARCGateway.
// It is carried through the entire router chain and attached to attestation records.
type Identity struct {
	Subject   string   `json:"subject"`              // Unique principal ID
	Issuer    string   `json:"issuer"`               // Auth issuer (e.g. "acp", "demarc")
	Audience  string   `json:"audience"`             // Intended audience
	Scopes    []string `json:"scopes"`               // JIT-scoped permissions (e.g. "ert:scan", "nhi:view")
	AgentID   string   `json:"agent_id"`             // External agent identifier
	SessionID string   `json:"session_id"`           // Session correlation ID
	Roles     []string `json:"roles,omitempty"`       // Optional RBAC roles
	LicenseID string   `json:"license_id,omitempty"` // License tier (khepri/ra/atum/osiris)
}

// HasScope returns true if the identity has been granted the given scope.
func (id Identity) HasScope(scope string) bool {
	for _, s := range id.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// ─── Tool Specification ────────────────────────────────────────────────────────

// ToolSpec defines a single MCP tool. All fields are populated from the signed manifest.
// Schema and description are cryptographically pinned — tool-rug attacks are impossible
// if the manifest signature verifies.
type ToolSpec struct {
	Name           string         `json:"name"`                    // Unique tool name (e.g. "ert_scan")
	Description    string         `json:"description"`             // Human-readable description
	RiskClass      ToolRiskClass  `json:"risk_class"`              // Execution isolation class
	Scope          string         `json:"scope"`                   // Required permission scope
	SchemaVersion  string         `json:"schema_version"`          // Semantic version of the tool schema
	SchemaHash     string         `json:"schema_hash"`             // SHA-256 of canonical schema bytes
	AllowedBackend string         `json:"allowed_backend"`         // "in-process", "local-sandbox", "docker"
	TimeoutMs      int            `json:"timeout_ms"`              // Maximum execution time
	NetworkAllowed bool           `json:"network_allowed"`         // Whether tool may access network
	Destructive    bool           `json:"destructive"`             // Requires explicit confirmation
	ArgsSchema     map[string]any `json:"args_schema,omitempty"`   // JSON Schema for tool arguments
	Meta           map[string]any `json:"meta,omitempty"`          // Arbitrary metadata
	// CapabilityMounts lists the exact host directories this tool is allowed to read
	// inside the sandbox. Replaces the generic /project mount with per-tool scoping.
	// ASD/CISA confused-deputy defense: ert_scan on RHEL-9 may only access
	// /etc, /var/log, and /opt/stig-db — not the entire filesystem.
	CapabilityMounts []string `json:"capability_mounts,omitempty"` // e.g. ["/etc", "/var/log"]
	// MaxPrivilege declares the maximum privilege level this tool requires.
	// "none" | "read-only" | "stig-db-read" | "network-read"
	MaxPrivilege string `json:"max_privilege,omitempty"`
}

// ─── Signed Tool Manifest (AD-007) ─────────────────────────────────────────────

// SignedToolManifest is the cryptographically sealed tool registry.
// Loaded and verified at startup — the server refuses to start if verification fails.
type SignedToolManifest struct {
	Version       string     `json:"version"`        // Manifest format version
	Revision      string     `json:"revision"`       // Deployment revision/date
	GeneratedAt   time.Time  `json:"generated_at"`   // When this manifest was signed
	HashAlgorithm string     `json:"hash_algorithm"` // "SHA-256"
	PublicKeyID   string     `json:"public_key_id"`  // Key ID for PQC verification
	Signature     string     `json:"signature"`      // ML-DSA-65 or Dilithium3 signature
	Tools         []ToolSpec `json:"tools"`          // Pinned tool definitions
}

// ─── MCP Tool Call ─────────────────────────────────────────────────────────────

// MCPToolCall represents an incoming tool invocation request.
type MCPToolCall struct {
	RequestID        string           `json:"request_id"`        // Correlation ID (idempotency key)
	ToolName         string           `json:"tool_name"`         // Must match a registered ToolSpec.Name
	Args             map[string]any   `json:"args"`              // Tool arguments (validated against ArgsSchema)
	RawPayload       json.RawMessage  `json:"raw_payload"`       // Original JSON-RPC params (for signing)
	Identity         Identity         `json:"identity"`          // Populated after DEMARC authentication
	Transport        TransportMode    `json:"transport"`         // Transport that received this call
	SubmittedAt      time.Time        `json:"submitted_at"`      // Server-side reception timestamp
	// InvocationToken is the short-lived (5min TTL), HMAC-signed per-invocation
	// capability token issued by the router. Encodes permitted scan profile,
	// target, and calling agent identity. ASD/CISA ephemeral credential requirement.
	InvocationToken  *InvocationToken `json:"invocation_token,omitempty"`
}

// ─── Secure Envelope ───────────────────────────────────────────────────────────

// SecureEnvelope wraps every tool response with PQC attestation.
// This is an APPLICATION-layer construct, distinct from the MCP wire protocol.
type SecureEnvelope struct {
	RequestID     string    `json:"request_id"`               // Links to MCPToolCall.RequestID
	ToolName      string    `json:"tool_name"`                // Tool that produced this result
	Result        any       `json:"result"`                   // The actual tool output
	AttestationID string    `json:"attestation_id"`           // DAG node ID proving execution
	Signature     string    `json:"signature"`                // PQC signature over result
	CreatedAt     time.Time `json:"created_at"`               // When this envelope was sealed
	SchemaVersion string    `json:"schema_version"`           // Tool schema version at execution time
	Provenance    string    `json:"provenance,omitempty"`     // Optional provenance chain
}

// ─── MCP Tool Response ─────────────────────────────────────────────────────────

// MCPToolResponse is the final response returned to the MCP client.
type MCPToolResponse struct {
	Envelope     SecureEnvelope `json:"envelope"`
	Warnings     []string       `json:"warnings,omitempty"`
	IsError      bool           `json:"is_error,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	// KhepraSign is the ML-DSA-65 signature of SHA3-256(JSON body excluding this field).
	// Surface at the MCP wire level so any client can verify message integrity
	// without parsing the nested SecureEnvelope structure.
	// NSA MCP Security Design Considerations: unsigned JSON-RPC responses are the
	// primary attack surface. This field provides cryptographic proof the response
	// was not tampered with in transit.
	KhepraSign   string         `json:"_khepra_sig,omitempty"`
}

// ─── Structured Tool Result (Error-as-Data) ────────────────────────────────────

// HardenedToolResult is the structured output of every hardened tool execution.
// Errors are returned as DATA, not exceptions, so the agent/router can
// recover or escalate gracefully.
// Named "Hardened" to avoid collision with legacy ToolResult alias in compat.go.
type HardenedToolResult struct {
	Success     bool     `json:"success"`
	Data        any      `json:"data,omitempty"`
	Error       string   `json:"error,omitempty"`
	IsError     bool     `json:"is_error"`
	Recoverable bool     `json:"recoverable"`          // false = fatal, stop chain
	Code        string   `json:"code,omitempty"`        // e.g. "PATH_TRAVERSAL", "TIMEOUT"
	Warnings    []string `json:"warnings,omitempty"`
}

// NewSuccessResult creates a successful HardenedToolResult.
func NewSuccessResult(data any, warnings ...string) *HardenedToolResult {
	return &HardenedToolResult{
		Success:  true,
		Data:     data,
		Warnings: warnings,
	}
}

// NewErrorResult creates a recoverable error HardenedToolResult.
func NewErrorResult(code, msg string) *HardenedToolResult {
	return &HardenedToolResult{
		IsError:     true,
		Recoverable: true,
		Error:       msg,
		Code:        code,
	}
}

// NewFatalResult creates a non-recoverable error HardenedToolResult.
func NewFatalResult(code, msg string) *HardenedToolResult {
	return &HardenedToolResult{
		IsError:     false,
		Recoverable: false,
		Error:       msg,
		Code:        code,
	}
}

// ─── JSON-RPC 2.0 Wire Types ──────────────────────────────────────────────────

// JSONRPCRequest is the standard JSON-RPC 2.0 request envelope.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is the standard JSON-RPC 2.0 response envelope.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError is the standard JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603

	// Khepra-specific error codes (application domain).
	ErrCodeAuthFailed     = -32000
	ErrCodePolicyDenied   = -32001
	ErrCodeManifestFailed = -32002
	ErrCodeSandboxFailed  = -32003
	ErrCodeAttestFailed   = -32004
	ErrCodeToolTimeout    = -32005
	// ErrCodeRateLimitExceeded is the standard MCP backpressure code for prompt-storm defense.
	// NSA MCP Security Design Considerations: servers MUST signal rate exhaustion
	// via a well-known code so agents can back off instead of retrying immediately.
	ErrCodeRateLimitExceeded = -32006
)

// ─── Server Capabilities ───────────────────────────────────────────────────────

// InitializeResult is the top-level response for the MCP `initialize` method.
// Per MCP spec: protocolVersion + capabilities + serverInfo (nested).
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
}

// ServerInfo identifies the MCP server (nested inside InitializeResult).
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Capabilities advertises what the server supports.
type Capabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
}

// ToolsCapability advertises tool support.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability advertises resource support.
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

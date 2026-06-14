package apiserver

import (
	"time"
)

// ScanRequest represents a request to trigger a new scan
type ScanRequest struct {
	TargetURL   string            `json:"target_url" binding:"required"`
	ScanType    string            `json:"scan_type" binding:"required"` // "crypto", "stig", "full"
	Priority    int               `json:"priority"`                     // 1-10, higher = more urgent
	Metadata    map[string]string `json:"metadata"`
	CallbackURL string            `json:"callback_url,omitempty"`
	Profile     string            `json:"profile,omitempty"` // "", "nemoclaw"
}

// ScanResponse represents the response after triggering a scan
type ScanResponse struct {
	ScanID       string    `json:"scan_id"`
	Status       string    `json:"status"` // "queued", "running", "completed", "failed"
	TargetURL    string    `json:"target_url"`
	ScanType     string    `json:"scan_type"`
	QueuedAt     time.Time `json:"queued_at"`
	EstimatedAt  time.Time `json:"estimated_completion,omitempty"`
	WebSocketURL string    `json:"websocket_url"`
}

// ScanFindingItem is a short finding for product UI (onboarding, dashboards).
type ScanFindingItem struct {
	Severity string `json:"severity"`
	Text     string `json:"text"`
}

// ScanStatus represents the current status of a scan
type ScanStatus struct {
	ScanID       string                 `json:"scan_id"`
	Status       string                 `json:"status"`
	Progress     float64                `json:"progress"` // 0.0 - 1.0
	StartedAt    *time.Time             `json:"started_at,omitempty"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Results      map[string]interface{} `json:"results,omitempty"`
	Errors       []string               `json:"errors,omitempty"`
	ArtifactsURL string                 `json:"artifacts_url,omitempty"`
	Platform     string                 `json:"platform,omitempty"`  // e.g. "nemoclaw", "generic"
	Certified    bool                   `json:"certified,omitempty"` // true when ADINKHEPRA issued
	// Onboarding / ASAF product API (matches web client expectations)
	RiskScore         int               `json:"risk_score,omitempty"`
	Exposed           bool              `json:"exposed,omitempty"`
	AuthWeakness      bool              `json:"auth_weakness,omitempty"`
	OpenIntegrations  int               `json:"open_integrations,omitempty"`
	Findings          []ScanFindingItem `json:"findings,omitempty"`
}

// DAGNodeResponse represents a node in the Living Trust Constellation
type DAGNodeResponse struct {
	NodeID       string                 `json:"node_id"`
	Type         string                 `json:"type"` // "scan", "finding", "remediation", "attestation"
	Timestamp    time.Time              `json:"timestamp"`
	Data         map[string]interface{} `json:"data"`
	Parents      []string               `json:"parents"`       // Parent node IDs
	Children     []string               `json:"children"`      // Child node IDs
	PQCSignature string                 `json:"pqc_signature"` // ML-DSA-65 signature
	Verified     bool                   `json:"verified"`
}

// DAGGraphResponse represents the entire DAG graph
type DAGGraphResponse struct {
	Nodes       []DAGNodeResponse `json:"nodes"`
	TotalNodes  int               `json:"total_nodes"`
	RootNodes   []string          `json:"root_nodes"`
	LatestNode  string            `json:"latest_node"`
	LastUpdated time.Time         `json:"last_updated"`
}

// STIGValidationRequest represents a STIG compliance validation request
type STIGValidationRequest struct {
	STIGVersion    string            `json:"stig_version" binding:"required"` // e.g., "RHEL9"
	TargetHost     string            `json:"target_host" binding:"required"`
	OrganizationID string            `json:"organization_id,omitempty"`
	Credentials    map[string]string `json:"credentials,omitempty"`
	Controls       []string          `json:"controls,omitempty"` // Specific STIG IDs to check
}

// STIGValidationResponse represents STIG validation results
type STIGValidationResponse struct {
	ValidationID  string            `json:"validation_id"`
	STIGVersion   string            `json:"stig_version"`
	TargetHost    string            `json:"target_host"`
	TotalChecks   int               `json:"total_checks"`
	Passed        int               `json:"passed"`
	Failed        int               `json:"failed"`
	NotApplicable int               `json:"not_applicable"`
	Score         float64           `json:"score"` // 0.0 - 100.0
	Results       []STIGCheckResult `json:"results"`
	Timestamp     time.Time         `json:"timestamp"`
}

// STIGCheckResult represents a single STIG check result
type STIGCheckResult struct {
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"` // "high", "medium", "low"
	Status      string `json:"status"`   // "pass", "fail", "not_applicable"
	Finding     string `json:"finding,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// ERTRequest represents an Evidence Recording Token generation request
type ERTRequest struct {
	EventType   string                 `json:"event_type" binding:"required"` // "scan", "finding", "remediation"
	EventData   map[string]interface{} `json:"event_data" binding:"required"`
	Timestamp   time.Time              `json:"timestamp"`
	Attestation string                 `json:"attestation,omitempty"`
}

// ERTResponse represents an ERT generation response
type ERTResponse struct {
	TokenID      string    `json:"token_id"`
	EventType    string    `json:"event_type"`
	PQCSignature string    `json:"pqc_signature"` // ML-DSA-65 signature
	DAGNodeID    string    `json:"dag_node_id"`
	IssuedAt     time.Time `json:"issued_at"`
	VerifyURL    string    `json:"verify_url"`
}

// LicenseStatus represents the current license status
type LicenseStatus struct {
	LicenseID     string     `json:"license_id"`
	MachineID     string     `json:"machine_id"`
	Organization  string     `json:"organization"`
	LicenseTier   string     `json:"license_tier"`
	Features      []string   `json:"features"`
	IssuedAt      time.Time  `json:"issued_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	IsValid       bool       `json:"is_valid"`
	DaysRemaining int        `json:"days_remaining"`
	Revoked       bool       `json:"revoked"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status     string            `json:"status"` // "healthy", "degraded", "unhealthy"
	Version    string            `json:"version"`
	Uptime     float64           `json:"uptime_seconds"`
	DAGNodes   int               `json:"dag_nodes"`
	License    string            `json:"license_status"`
	Components map[string]string `json:"components"`
	Timestamp  time.Time         `json:"timestamp"`
}

// STIGRemediationRequest represents a request to fix security controls
type STIGRemediationRequest struct {
	ControlIDs     []string `json:"control_ids" binding:"required"`
	TargetHost     string   `json:"target_host" binding:"required"`
	OrganizationID string   `json:"organization_id,omitempty"`
}

// STIGRemediationResponse represents the outcome of automated fixes
type STIGRemediationResponse struct {
	BatchID   string              `json:"batch_id"`
	Results   []RemediationResult `json:"results"`
	Summary   string              `json:"summary"`
	Status    string              `json:"status"` // "completed", "partial", "failed"
	Timestamp time.Time           `json:"timestamp"`
}

// RemediationResult represents the outcome of a single fix
type RemediationResult struct {
	ControlID string    `json:"control_id"`
	Status    string    `json:"status"` // "success", "failed", "requires_manual"
	Command   string    `json:"command"`
	Output    string    `json:"output"`
	Timestamp time.Time `json:"timestamp"`
}

// WebSocketMessage represents a generic WebSocket message
type WebSocketMessage struct {
	Type      string                 `json:"type"` // "scan_update", "dag_update", "license_update"
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

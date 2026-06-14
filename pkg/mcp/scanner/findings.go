package scanner

// findings.go — MCPFinding type, Severity scale, and compliance gap bridge.
//
// Threat classes T01–T16 follow the OWASP LLM Top 10 + NSA MCP Security
// threat model from pkg/mcp/docs/CSI_MCP_SECURITY.

import "time"

// Severity represents the urgency of an MCP security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL" // Immediate action required — block deployment
	SeverityHigh     Severity = "HIGH"     // Remediate within 24 hours
	SeverityMedium   Severity = "MEDIUM"   // Remediate within 7 days
	SeverityLow      Severity = "LOW"      // Remediate within 30 days
	SeverityInfo     Severity = "INFO"     // Informational — no action required
)

// Threat class constants T01–T16 (OWASP LLM + NSA MCP threat model).
const (
	T01ToolPoisoning    = "T01" // Malicious tool descriptions injecting instructions
	T02PromptInjection  = "T02" // Prompt injection via tool arguments
	T03ManifestRugPull  = "T03" // Tool registry mutation between calls
	T04ConfusedDeputy   = "T04" // Cross-tool privilege escalation
	T05ScopeCreep       = "T05" // Tool exceeding declared permission scope
	T06UnsignedResponse = "T06" // Tool responses without PQC integrity seals
	T07DAGGap           = "T07" // Tool calls not anchored in immutable audit trail
	T08RateLimitBypass  = "T08" // Abnormal call frequency indicating automation abuse
	T09SSEExposure      = "T09" // Server-Sent Events / HTTP exposure on air-gapped node
	T10SchemaDrift      = "T10" // Tool schema mutations post-manifest-pin
	T11StaleCredential  = "T11" // Expired or near-expiry ACP credentials in flight
	T12UnauthorizedDisc = "T12" // Unauthorized tool discovery / schema exfiltration
	T13SandboxEgress    = "T13" // Sandboxed tool making outbound network calls
	T14SSRF             = "T14" // Server-Side Request Forgery via tool arguments
	T15ToolShadowing    = "T15" // Ambiguous tool names enabling shadowing attacks
	T16PQCDowngrade     = "T16" // PQC algorithm downgrade / wrong key size
)

// MCPFinding represents a single security threat detected during an MCP scan.
type MCPFinding struct {
	ID          string    `json:"id"`           // Unique finding ID (e.g. "T01-001")
	ThreatClass string    `json:"threat_class"` // T01–T16
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	Control     string    `json:"control"`    // NIST / CMMC control reference
	Framework   string    `json:"framework"`  // "NIST 800-53" | "CMMC 2.0"
	DetectedAt  time.Time `json:"detected_at"`
	Remediated  bool      `json:"remediated"`
}

// ComplianceGapFields extracts structured fields for ert.ComplianceGap without
// importing pkg/ert (avoids import cycle). The caller wraps these into a gap struct.
func (f *MCPFinding) ComplianceGapFields() (framework, control, description, severity string) {
	return f.Framework,
		f.Control,
		"[MCP-" + f.ThreatClass + "] " + f.Title + ": " + f.Detail,
		string(f.Severity)
}

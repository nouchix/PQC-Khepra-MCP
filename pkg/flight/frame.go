package flight

// frame.go — FlightFrame: the atomic unit of the SouHimBou AI flight recorder.
//
// Aviation analogy:
//   - Cockpit Voice Recorder → agent intent + policy decisions
//   - Flight Data Recorder   → tool execution metrics + outcome
//   - Black Box              → tamper-evident chain (ML-DSA-65 signed)
//
// Each FlightFrame is a complete, self-contained semantic record of one
// agent action. Unlike the low-level MCPEvent (which records protocol-layer
// events), a FlightFrame answers the audit question:
//
//   "What did the agent try to do, was it permitted, what happened,
//    and which CMMC controls does this execution evidence?"
//
// CMMC relevance:
//   AU.3.045 — Review and update logged events
//   AU.3.046 — Alert on audit log failure
//   AU.2.041 — Ensure actions of individual users can be uniquely traced
//   AC.2.006 — Use non-privileged accounts when accessing non-security functions

import "time"

// Outcome represents the result of an agent tool-call attempt.
type Outcome string

const (
	OutcomeSuccess    Outcome = "success"    // Tool executed successfully
	OutcomeError      Outcome = "error"      // Tool executed but returned an error
	OutcomeBlocked    Outcome = "blocked"    // Policy gate rejected the call
	OutcomeRateLimit  Outcome = "rate_limit" // Rate limit or concurrency cap hit
	OutcomeLoopDetect Outcome = "loop_detect" // Repetition / mistake loop detected
	OutcomeAuthFailed Outcome = "auth_failed" // DEMARC authentication failure
)

// RiskClass mirrors mcp.ToolRiskClass without importing pkg/mcp (avoids cycle).
type RiskClass string

const (
	RiskReadOnly    RiskClass = "read_only"
	RiskSandboxed   RiskClass = "sandboxed"
	RiskDestructive RiskClass = "destructive"
)

// PolicyDecision records whether a single security gate permitted or blocked the call.
// Together, the decisions tell the story of the full DEMARC → Exec chain.
type PolicyDecision struct {
	Step      string `json:"step"`      // "demarc_auth" | "cidr_check" | "rate_limit" | "input_validation" | "scope_taxonomy" | "license_tier" | "loop_detect" | "manifest_lookup" | "schema_pin" | "poly_wrap" | "rbac" | "injection_scan" | "concurrency" | "execution" | "output_filter" | "attestation" | "signing"
	Permitted bool   `json:"permitted"` // true = passed, false = blocked
	Reason    string `json:"reason,omitempty"` // non-empty only when blocked
}

// ControlMapping records a NIST 800-171 / CMMC control evidenced by this call.
type ControlMapping struct {
	Framework string `json:"framework"` // "NIST SP 800-171 Rev 2" | "CMMC 2.0 L2"
	ControlID string `json:"control_id"` // "3.3.1" | "AU.3.045"
	How       string `json:"how"`        // Brief description of how this call evidences the control
}

// FlightFrame is a single signed, chained record in the SouHimBou AI flight log.
// Persisted as a line in an NDJSON file. Each frame is ML-DSA-65 signed and
// cryptographically chained to the previous frame.
type FlightFrame struct {
	// ── Identity ────────────────────────────────────────────────────────────
	FrameID   string `json:"frame_id"`   // UUID-like content-addressed ID
	Seq       uint64 `json:"seq"`        // Monotonic sequence (restart-persistent)
	SessionID string `json:"session_id"` // Groups frames into agent sessions
	AgentID   string `json:"agent_id"`   // Which agent (from ACP identity)
	Subject   string `json:"subject"`    // ACP principal subject

	// ── Timing ──────────────────────────────────────────────────────────────
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`

	// ── Tool Call Context ────────────────────────────────────────────────────
	ToolName  string    `json:"tool_name"`
	ToolScope string    `json:"tool_scope"`
	RiskClass RiskClass `json:"risk_class"`

	// ── Intent Capture (sanitized — no raw CUI) ─────────────────────────────
	// Raw arguments are NEVER stored. Only their hash and length.
	// This satisfies CUI minimization requirements while enabling audit replay.
	IntentSummary string `json:"intent_summary"` // Human-readable: "STIG compliance scan of /opt/app"
	ParamsHash    string `json:"params_hash"`    // SHA3-256 of raw params bytes
	ParamsLen     int    `json:"params_len"`     // Byte length

	// ── Policy Decisions (the CMMC evidence core) ────────────────────────────
	// Every security gate that evaluated this call is recorded.
	// An auditor can reconstruct whether KHEPRA enforced policy correctly.
	PolicyDecisions []PolicyDecision `json:"policy_decisions"`

	// ── Execution Outcome ────────────────────────────────────────────────────
	Outcome      Outcome  `json:"outcome"`
	ErrorSummary string   `json:"error_summary,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`

	// ── Evidence Anchors ─────────────────────────────────────────────────────
	DAGNodeID     string `json:"dag_node_id,omitempty"` // Immutable DAG anchor (pkg/dag)
	IsSigned      bool   `json:"is_signed"`
	SignatureAlgo string `json:"signature_algo,omitempty"` // "ML-DSA-65"

	// ── CMMC Control Mappings ────────────────────────────────────────────────
	// Which NIST 800-171 / CMMC controls does this execution evidence?
	// Auto-populated from the tool's scope taxonomy.
	ControlsMapped []ControlMapping `json:"controls_mapped,omitempty"`

	// ── Tamper-Evident Chain ─────────────────────────────────────────────────
	// Chain: PrevFrameHash = SHA3-256(raw bytes of previous NDJSON line).
	// Signature: ML-DSA-65(privKey, SHA3-256(canonical frame JSON excl. Signature)).
	PrevFrameHash string `json:"prev_frame_hash"` // "genesis" for frame 0
	FrameHash     string `json:"frame_hash"`      // SHA3-256(canonical excl. Signature)
	Signature     string `json:"signature,omitempty"` // ML-DSA-65 hex
	PublicKeyHex  string `json:"public_key,omitempty"` // For offline verification
	Algorithm     string `json:"algorithm"`           // "ML-DSA-65" | "unsigned"
}

// ── CMMC Control Map ─────────────────────────────────────────────────────────

// scopeToControls maps tool scopes to the CMMC / NIST 800-171 controls they evidence.
// Populated by evidence-mapping exercise against NIST SP 800-171A assessment procedures.
var scopeToControls = map[string][]ControlMapping{
	"ert:scan": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.11.1", How: "System scan identifies vulnerabilities and misconfigurations"},
		{Framework: "CMMC 2.0 L2", ControlID: "CA.2.157", How: "Periodic assessment of organizational systems"},
	},
	"ert:compliance": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.12.1", How: "Compliance assessment evidences security requirement satisfaction"},
		{Framework: "CMMC 2.0 L2", ControlID: "CA.2.157", How: "Periodic assessment of security controls"},
	},
	"ert:supply-chain": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.14.1", How: "SBOM + CVE scan identifies software vulnerabilities"},
		{Framework: "CMMC 2.0 L2", ControlID: "SI.2.214", How: "Software and firmware vulnerability scanning"},
	},
	"ert:pqc": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.13.10", How: "Cryptographic key establishment and management assessment"},
		{Framework: "CMMC 2.0 L2", ControlID: "SC.3.187", How: "Cryptographic mechanisms protect CUI during transmission"},
	},
	"stig:read": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.4.1", How: "STIG check establishes and maintains configuration baselines"},
		{Framework: "CMMC 2.0 L2", ControlID: "CM.2.061", How: "System configuration established, maintained, and enforced"},
	},
	"compliance:read": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.12.3", How: "Monitor security controls on ongoing basis"},
		{Framework: "CMMC 2.0 L2", ControlID: "CA.2.157", How: "Periodic organizational security assessments"},
	},
	"compliance:attest": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.12.4", How: "Develop, document, and periodically update SSP"},
		{Framework: "CMMC 2.0 L2", ControlID: "CA.3.162", How: "Employ independent assessors for periodic assessments"},
	},
	"compliance:poam": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.12.2", How: "POA&M developed and updated for corrective actions"},
		{Framework: "CMMC 2.0 L2", ControlID: "CA.2.158", How: "Develop and implement plans of action to correct deficiencies"},
	},
	"compliance:report": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.12.1", How: "Compliance report provides periodic assessment evidence"},
		{Framework: "CMMC 2.0 L2", ControlID: "CA.2.157", How: "Periodic assessment of organizational systems"},
	},
	"audit:write": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.3.1", How: "Audit log records agent actions for individual traceability"},
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.3.2", How: "Audit processes and actions uniquely traced to users"},
		{Framework: "CMMC 2.0 L2", ControlID: "AU.2.041", How: "Unique traceability of individual user actions"},
		{Framework: "CMMC 2.0 L2", ControlID: "AU.3.045", How: "Review and update logged events"},
	},
	"dag:read": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.3.1", How: "DAG chain export provides tamper-evident audit evidence"},
		{Framework: "CMMC 2.0 L2", ControlID: "AU.3.045", How: "Audit log review for compliance verification"},
	},
	"threat:read": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.14.6", How: "Threat intelligence supports monitoring of organizational systems"},
		{Framework: "CMMC 2.0 L2", ControlID: "SI.3.218", How: "Threat hunting to detect active adversarial behavior"},
	},
	"acp:read": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.5.1", How: "Identity and credential status review supports IA controls"},
		{Framework: "CMMC 2.0 L2", ControlID: "IA.3.083", How: "Management of identifiers for users, processes, and devices"},
	},
	"acp:write": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.5.2", How: "Credential issuance and revocation enforces authenticator management"},
		{Framework: "CMMC 2.0 L2", ControlID: "IA.3.083", How: "Authenticator management for devices and non-person entities"},
	},
	"nhi:read": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.1.5", How: "NHI inventory supports least privilege enforcement"},
		{Framework: "CMMC 2.0 L2", ControlID: "AC.2.007", How: "Employ least privilege for non-human identities"},
	},
	"compliance:monitor": {
		{Framework: "NIST SP 800-171 Rev 2", ControlID: "3.12.3", How: "Continuous monitoring of security controls"},
		{Framework: "CMMC 2.0 L2", ControlID: "CA.3.161", How: "Continuous monitoring of security posture"},
	},
}

// ControlsForScope returns the CMMC / NIST 800-171 controls evidenced by a tool scope.
func ControlsForScope(scope string) []ControlMapping {
	if mappings, ok := scopeToControls[scope]; ok {
		return mappings
	}
	return nil
}

// AllScopesControlCount returns the total number of unique CMMC controls
// that KHEPRA can evidence across all tool scopes.
func AllScopesControlCount() int {
	seen := make(map[string]bool)
	for _, mappings := range scopeToControls {
		for _, m := range mappings {
			seen[m.Framework+":"+m.ControlID] = true
		}
	}
	return len(seen)
}

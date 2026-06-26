package scanner

// findings.go — MCPFinding type, Severity scale, and compliance gap bridge.
//
// Threat classes T01–T16 follow the OWASP LLM Top 10 + NSA MCP Security
// threat model from pkg/mcp/docs/CSI_MCP_SECURITY.
//
// OWASP MCP Top 10 tags (OWASP-MCP-01..10) are co-emitted on each finding so
// auditors, CI pipelines, and dashboards can report coverage without parsing the
// internal T-class taxonomy.

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

// ── OWASP MCP Top 10 Tags (https://owasp.org/www-project-mcp-top-10/) ──────────
//
// Every MCPFinding that maps to an OWASP MCP Top 10 category carries one of
// these tags. Used by downstream tooling (CI, dashboards, auditors) to report
// OWASP coverage without parsing our internal T-class taxonomy.
const (
	OWASPMCPTop10_01_PromptInjection      = "OWASP-MCP-01" // Prompt Injection
	OWASPMCPTop10_02_InsecureAccess       = "OWASP-MCP-02" // Insecure Access / Path Traversal / SSRF
	OWASPMCPTop10_03_ToolPoisoning        = "OWASP-MCP-03" // Tool Poisoning / Typosquatting / Shadowing
	OWASPMCPTop10_04_CommandInjection     = "OWASP-MCP-04" // Command Injection / Secrets Exposure
	OWASPMCPTop10_05_UnsanitizedResponse  = "OWASP-MCP-05" // Unsanitized Response / Secret Leakage
	OWASPMCPTop10_06_MissingValidation    = "OWASP-MCP-06" // Missing Input Validation
	OWASPMCPTop10_07_MissingAuth          = "OWASP-MCP-07" // Missing Auth (HTTP/SSE)
	OWASPMCPTop10_08_Typosquatting        = "OWASP-MCP-08" // Typosquatting / Rug Pull
	OWASPMCPTop10_09_DataInjection        = "OWASP-MCP-09" // Data Injection / Hidden Instructions
	OWASPMCPTop10_10_LoggingAuditFailures = "OWASP-MCP-10" // Insufficient Logging & Audit
)

// ── OWASP Agentic AI Top 10 2026 Tags ───────────────────────────────────────────
//
// Maps to OWASP ASI-01..ASI-10 (Agentic Security Initiative).
// Emitted alongside OWASP-MCP tags for AI-specific risk coverage.
const (
	OWASPASI01_AgentMemoryPoisoning  = "ASI-01"
	OWASPASI02_ToolHijacking         = "ASI-02"
	OWASPASI03_CredentialTheft       = "ASI-03"
	OWASPASI04_LoopExploitation      = "ASI-04"
	OWASPASI05_UnsignedAttestation   = "ASI-05"
	OWASPASI06_ModelManipulation     = "ASI-06"
	OWASPASI07_MissingApprovalGate   = "ASI-07"
	OWASPASI08_ShadowMCPServer       = "ASI-08"
	OWASPASI09_OverpermissionedAgent = "ASI-09"
	OWASPASI10_AuditGap              = "ASI-10"
)

// MCPFinding represents a single security threat detected during an MCP scan.
type MCPFinding struct {
	ID          string    `json:"id"`                  // Unique finding ID (e.g. "T01-001")
	ThreatClass string    `json:"threat_class"`        // T01–T16
	OWASPTag    string    `json:"owasp_tag,omitempty"` // OWASP-MCP-01..10
	ASITag      string    `json:"asi_tag,omitempty"`   // ASI-01..10
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	Control     string    `json:"control"`   // NIST / CMMC control reference
	Framework   string    `json:"framework"` // "NIST 800-53" | "CMMC 2.0"
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

// ── MCPSecurityScore — Weighted security score (0–100, grade A–F) ─────────────
//
// Scoring model mirrors kern-sight-mcp's methodology:
//
//	Guard Coverage  40% — scanner checks always active (1.0 when toolCount > 0)
//	InputValidation 25% — server has ValidateToolArgs wired into the router
//	RuleCompliance  20% — penalty per critical (−20) / high (−10) / medium (−5) finding
//	AuthPosture     15% — PQC signing (0.5) + DAG attestation (0.5) configured
//
// Grade: A ≥ 90 / B ≥ 75 / C ≥ 60 / D ≥ 40 / F < 40
type MCPSecurityScore struct {
	Overall        int     `json:"overall"`         // 0–100
	Grade          string  `json:"grade"`           // "A"–"F"
	GuardCoverage  float64 `json:"guard_coverage"`  // 0.0–1.0
	InputValidated bool    `json:"input_validated"`
	AuthPosture    float64 `json:"auth_posture"` // 0.0–1.0 (PQC + DAG)
	FindingPenalty int     `json:"finding_penalty"`
	CriticalCount  int     `json:"critical_count"`
	HighCount      int     `json:"high_count"`
	MediumCount    int     `json:"medium_count"`
}

// ComputeScore derives a weighted MCPSecurityScore from a findings slice and
// server posture flags. toolCount is the total number of registered tools.
func ComputeScore(findings []MCPFinding, toolCount int, hasPQC, hasDAG, hasInputValidation bool) MCPSecurityScore {
	var crit, high, med int
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			crit++
		case SeverityHigh:
			high++
		case SeverityMedium:
			med++
		}
	}

	// Auth posture: 0.5 per axis (PQC signing, DAG attestation)
	authPosture := 0.0
	if hasPQC {
		authPosture += 0.5
	}
	if hasDAG {
		authPosture += 0.5
	}

	// Guard coverage: full credit when tools are registered (scanner is always active).
	guardCoverage := 1.0
	if toolCount == 0 {
		guardCoverage = 0.0
	}

	// Input validation: binary
	inputScore := 0.0
	if hasInputValidation {
		inputScore = 1.0
	}

	// Rule compliance penalty (capped at 20 pts to avoid negative totals)
	penalty := (crit * 20) + (high * 10) + (med * 5)

	// Weighted sum
	complianceComponent := 20.0 - minF(float64(penalty), 20.0)
	raw := (guardCoverage * 40.0) + (inputScore * 25.0) + (authPosture * 15.0) + complianceComponent

	overall := maxI(0, minI(100, int(raw)))

	grade := "F"
	switch {
	case overall >= 90:
		grade = "A"
	case overall >= 75:
		grade = "B"
	case overall >= 60:
		grade = "C"
	case overall >= 40:
		grade = "D"
	}

	return MCPSecurityScore{
		Overall:        overall,
		Grade:          grade,
		GuardCoverage:  guardCoverage,
		InputValidated: hasInputValidation,
		AuthPosture:    authPosture,
		FindingPenalty: penalty,
		CriticalCount:  crit,
		HighCount:      high,
		MediumCount:    med,
	}
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── Secret Leakage Patterns (GitLeaks-derived, top 50) ───────────────────────
//
// Used by ScanOutputSecrets() in checks.go to detect credential and PII leakage
// in tool responses before they reach the LLM context.
//
// Pattern corpus derived from github.com/gitleaks/gitleaks (MIT License).
// Maps to: OWASP-MCP-04 (Secrets Exposure) + OWASP-MCP-05 (Unsanitized Response)
var SecretPatterns = []SecretPattern{
	{Name: "aws-access-key-id", Pattern: `(?i)(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`, Severity: SeverityCritical},
	{Name: "aws-secret-key", Pattern: `(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[=:]\s*['"]?[A-Za-z0-9/+]{40}`, Severity: SeverityCritical},
	{Name: "github-pat", Pattern: `(?i)ghp_[A-Za-z0-9]{36}`, Severity: SeverityCritical},
	{Name: "github-oauth", Pattern: `(?i)gho_[A-Za-z0-9]{36}`, Severity: SeverityCritical},
	{Name: "github-app-token", Pattern: `(?i)(?:ghu|ghs)_[A-Za-z0-9]{36}`, Severity: SeverityHigh},
	{Name: "github-refresh-token", Pattern: `(?i)ghr_[A-Za-z0-9]{76}`, Severity: SeverityHigh},
	{Name: "stripe-secret-key", Pattern: `(?i)sk_live_[0-9a-zA-Z]{24,}`, Severity: SeverityCritical},
	{Name: "stripe-publishable-key", Pattern: `(?i)pk_live_[0-9a-zA-Z]{24,}`, Severity: SeverityMedium},
	{Name: "stripe-restricted-key", Pattern: `(?i)rk_live_[0-9a-zA-Z]{24,}`, Severity: SeverityCritical},
	{Name: "gcp-service-account", Pattern: `(?i)"type"\s*:\s*"service_account"`, Severity: SeverityCritical},
	{Name: "google-api-key", Pattern: `(?i)AIza[0-9A-Za-z_\-]{35}`, Severity: SeverityHigh},
	{Name: "slack-token", Pattern: `(?i)xox[baprs]-[0-9a-zA-Z]{10,48}`, Severity: SeverityCritical},
	{Name: "slack-webhook", Pattern: `(?i)https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`, Severity: SeverityHigh},
	{Name: "discord-token", Pattern: `(?i)[MNO][A-Za-z0-9\-_]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}`, Severity: SeverityCritical},
	{Name: "discord-webhook", Pattern: `(?i)https://(?:canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9\-_]{60,68}`, Severity: SeverityHigh},
	{Name: "twilio-api-key", Pattern: `(?i)SK[0-9a-fA-F]{32}`, Severity: SeverityHigh},
	{Name: "sendgrid-api-key", Pattern: `(?i)SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`, Severity: SeverityCritical},
	{Name: "mailgun-api-key", Pattern: `(?i)key-[0-9a-zA-Z]{32}`, Severity: SeverityHigh},
	{Name: "mailchimp-api-key", Pattern: `(?i)[0-9a-f]{32}-us[0-9]{1,2}`, Severity: SeverityHigh},
	{Name: "generic-jwt", Pattern: `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`, Severity: SeverityHigh},
	{Name: "private-key-pem", Pattern: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY`, Severity: SeverityCritical},
	{Name: "azure-client-secret", Pattern: `(?i)(?:client[_\-\.]?secret|AZURE[_\-\.]?CLIENT[_\-\.]?SECRET)\s*[=:]\s*['"]?[A-Za-z0-9~.\-_]{34,40}`, Severity: SeverityCritical},
	{Name: "azure-storage-key", Pattern: `(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==`, Severity: SeverityCritical},
	{Name: "openai-api-key", Pattern: `(?i)sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`, Severity: SeverityCritical},
	{Name: "anthropic-api-key", Pattern: `(?i)sk-ant-api03-[A-Za-z0-9\-_]{93}`, Severity: SeverityCritical},
	{Name: "hugging-face-token", Pattern: `(?i)hf_[A-Za-z0-9]{37}`, Severity: SeverityHigh},
	{Name: "npm-access-token", Pattern: `(?i)npm_[A-Za-z0-9]{36}`, Severity: SeverityHigh},
	{Name: "docker-hub-pat", Pattern: `(?i)dckr_pat_[A-Za-z0-9_\-]{27}`, Severity: SeverityHigh},
	{Name: "postgres-dsn", Pattern: `(?i)postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\S+`, Severity: SeverityHigh},
	{Name: "mysql-dsn", Pattern: `(?i)mysql://[^:]+:[^@]+@[^/]+/\S+`, Severity: SeverityHigh},
	{Name: "mongodb-dsn", Pattern: `(?i)mongodb(?:\+srv)?://[^:]+:[^@]+@\S+`, Severity: SeverityHigh},
	{Name: "generic-password-field", Pattern: `(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{8,}`, Severity: SeverityHigh},
	{Name: "generic-api-key", Pattern: `(?i)(?:api[_\-\.]?key|apikey|api_token)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}`, Severity: SeverityHigh},
	{Name: "bearer-token", Pattern: `(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_.~+/]+=*`, Severity: SeverityHigh},
	{Name: "basic-auth-header", Pattern: `(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/]+=*`, Severity: SeverityHigh},
	{Name: "hashicorp-vault-token", Pattern: `(?i)(?:hvs\.|s\.)[A-Za-z0-9]{24}`, Severity: SeverityCritical},
	{Name: "terraform-api-token", Pattern: `(?i)[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}`, Severity: SeverityHigh},
	{Name: "age-secret-key", Pattern: `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`, Severity: SeverityCritical},
	{Name: "khepra-license-key", Pattern: `(?i)KHEPRA[_\-]LICENSE[_\-]KEY\s*[=:]\s*\S+`, Severity: SeverityCritical},
	{Name: "ssh-private-key", Pattern: `-----BEGIN OPENSSH PRIVATE KEY-----`, Severity: SeverityCritical},
	{Name: "pgp-private-key", Pattern: `-----BEGIN PGP PRIVATE KEY BLOCK-----`, Severity: SeverityCritical},
	{Name: "twitch-oauth", Pattern: `(?i)oauth:[A-Za-z0-9]+`, Severity: SeverityHigh},
	{Name: "paypal-braintree-token", Pattern: `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`, Severity: SeverityCritical},
	{Name: "pii-ssn", Pattern: `\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b`, Severity: SeverityCritical},
	{Name: "pii-credit-card", Pattern: `\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b`, Severity: SeverityCritical},
}

// SecretPattern is a named regex + severity for output secret scanning.
type SecretPattern struct {
	Name     string
	Pattern  string
	Severity Severity
}

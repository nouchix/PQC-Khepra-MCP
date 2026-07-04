package scanner

// checks.go — Threat check implementations (T01–T16) + output secret scanner.
//
// Each structural check is a method on *Scanner returning ([]MCPFinding, error).
// All checks are read-only — no mutations to the server state.
//
// Active checks:    T01, T03, T06, T07, T10, T11, T16
// Output scanner:   ScanOutputSecrets() — GitLeaks-derived 50-pattern corpus
// Pending checks:   T02/T08 (require CallLog wired into handleToolsCall)
//                   T04, T05, T09, T12, T13, T14, T15 (future work)
//
// Every finding is tagged with OWASPTag (OWASP-MCP-01..10) and, where
// applicable, ASITag (ASI-01..10) for auditor-friendly coverage reporting.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// ── T01: Tool Poisoning ───────────────────────────────────────────────────────
//
// Detects malicious instructions embedded in tool descriptions.
// NIST 800-53 SI-3 (Malicious Code Protection)
// Severity: CRITICAL for hidden chars, HIGH for keyword matches.

var injectionPatterns = []string{
	"ignore previous",
	"ignore prior",
	"disregard all",
	"you are now",
	"system prompt",
	"jailbreak",
	"override instructions",
}

func (s *Scanner) checkToolPoisoning(_ context.Context) ([]MCPFinding, error) {
	var findings []MCPFinding
	specs := s.router.ListToolSpecs()

	for i, t := range specs {
		descLower := strings.ToLower(t.Description)

		// Check for injection keyword patterns
		for _, pattern := range injectionPatterns {
			if strings.Contains(descLower, pattern) {
				findings = append(findings, MCPFinding{
					ID:          fmt.Sprintf("T01-%03d", i*10+1),
					ThreatClass: T01ToolPoisoning,
					OWASPTag:    OWASPMCPTop10_03_ToolPoisoning,
					ASITag:      OWASPASI01_AgentMemoryPoisoning,
					Severity:    SeverityHigh,
					Title:       "Tool description contains injection pattern",
					Detail:      fmt.Sprintf("Tool %q description matches pattern %q — possible prompt injection vector", t.Name, pattern),
					Control:     "SI-3",
					Framework:   "NIST 800-53",
					DetectedAt:  time.Now(),
				})
			}
		}

		// Check for non-printable / hidden control characters (CRITICAL)
		hasHidden := false
		for _, r := range t.Description {
			if r != '\n' && r != '\t' && r != '\r' && !unicode.IsPrint(r) {
				hasHidden = true
				break
			}
		}
		if hasHidden {
			findings = append(findings, MCPFinding{
				ID:          fmt.Sprintf("T01-%03d", i*10+2),
				ThreatClass: T01ToolPoisoning,
				OWASPTag:    OWASPMCPTop10_09_DataInjection,
				ASITag:      OWASPASI01_AgentMemoryPoisoning,
				Severity:    SeverityCritical,
				Title:       "Tool description contains hidden control characters",
				Detail:      fmt.Sprintf("Tool %q description contains non-printable characters — classic hidden injection vector. Quarantine and audit immediately.", t.Name),
				Control:     "SI-3",
				Framework:   "NIST 800-53",
				DetectedAt:  time.Now(),
			})
		}
	}
	return findings, nil
}

// ── T03: Manifest Rug Pull ────────────────────────────────────────────────────
//
// Detects changes to the tool registry after baseline was captured.
// NIST 800-53 CM-3 (Configuration Change Control)

func (s *Scanner) checkManifestRugPull(_ context.Context) ([]MCPFinding, error) {
	if s.baseline == nil {
		return nil, nil // No baseline — skip (T10 will report this)
	}

	current := s.computeSnapshot()
	added, removed, changed := diffSnapshots(s.baseline, current)

	var findings []MCPFinding
	seq := 0

	for _, name := range added {
		seq++
		findings = append(findings, MCPFinding{
			ID:          fmt.Sprintf("T03-%03d", seq),
			ThreatClass: T03ManifestRugPull,
			OWASPTag:    OWASPMCPTop10_08_Typosquatting,
			ASITag:      OWASPASI08_ShadowMCPServer,
			Severity:    SeverityHigh,
			Title:       "Tool added after baseline capture",
			Detail:      fmt.Sprintf("Tool %q was not present at baseline — rug pull or unauthorized injection", name),
			Control:     "CM-3",
			Framework:   "NIST 800-53",
			DetectedAt:  time.Now(),
		})
	}

	for _, name := range removed {
		seq++
		findings = append(findings, MCPFinding{
			ID:          fmt.Sprintf("T03-%03d", seq),
			ThreatClass: T03ManifestRugPull,
			OWASPTag:    OWASPMCPTop10_08_Typosquatting,
			ASITag:      OWASPASI08_ShadowMCPServer,
			Severity:    SeverityHigh,
			Title:       "Tool removed after baseline capture",
			Detail:      fmt.Sprintf("Tool %q was present at baseline but is now missing — possible rug pull", name),
			Control:     "CM-3",
			Framework:   "NIST 800-53",
			DetectedAt:  time.Now(),
		})
	}

	for _, name := range changed {
		seq++
		findings = append(findings, MCPFinding{
			ID:          fmt.Sprintf("T10-%03d", seq),
			ThreatClass: T10SchemaDrift,
			OWASPTag:    OWASPMCPTop10_08_Typosquatting,
			Severity:    SeverityMedium,
			Title:       "Tool schema mutated after baseline",
			Detail:      fmt.Sprintf("Tool %q name/description/schema hash changed since baseline — possible schema mutation attack", name),
			Control:     "CM-6",
			Framework:   "NIST 800-53",
			DetectedAt:  time.Now(),
		})
	}

	return findings, nil
}

// ── T06: Unsigned Response ────────────────────────────────────────────────────
//
// No Dilithium signing key = zero response integrity guarantees.
// CMMC SC.3.177 (Cryptographic Protection)

func (s *Scanner) checkUnsignedResponse(_ context.Context) ([]MCPFinding, error) {
	if s.router.HasPQCSigning() {
		return nil, nil
	}
	return []MCPFinding{{
		ID:          "T06-001",
		ThreatClass: T06UnsignedResponse,
		OWASPTag:    OWASPMCPTop10_07_MissingAuth,
		ASITag:      OWASPASI05_UnsignedAttestation,
		Severity:    SeverityCritical,
		Title:       "MCP server has no PQC signing key — tool responses are unsigned",
		Detail:      "No ML-DSA-65 (Dilithium) private key is configured. All tool responses lack cryptographic integrity seals. An adversary can tamper with responses without detection. Set KHEPRA_LICENSE_KEY or configure a signing key.",
		Control:     "SC.3.177",
		Framework:   "CMMC 2.0",
		DetectedAt:  time.Now(),
	}}, nil
}

// ── T07: DAG Gap ──────────────────────────────────────────────────────────────
//
// Tool calls not recorded in immutable audit trail.
// CMMC AU.3.045 (Review and Update Logged Events)

func (s *Scanner) checkDAGGap(_ context.Context) ([]MCPFinding, error) {
	if s.router.HasAuditLogger() {
		return nil, nil
	}
	return []MCPFinding{{
		ID:          "T07-001",
		ThreatClass: T07DAGGap,
		OWASPTag:    OWASPMCPTop10_10_LoggingAuditFailures,
		ASITag:      OWASPASI10_AuditGap,
		Severity:    SeverityHigh,
		Title:       "MCP server has no DAG audit logger — tool calls are not immutably recorded",
		Detail:      "No DAG attestation store is wired to the server. Tool call provenance cannot be verified post-hoc. Configure pkg/dag.Store + DAGAttestor to close this gap. Required for DFARS 252.204-7012 and CMMC AU.3.045 compliance.",
		Control:     "AU.3.045",
		Framework:   "CMMC 2.0",
		DetectedAt:  time.Now(),
	}}, nil
}

// ── T10: Schema Drift ─────────────────────────────────────────────────────────
//
// No baseline captured = drift detection is unconfigured.
// NIST 800-53 CM-6 (Configuration Settings)

func (s *Scanner) checkSchemaDrift(_ context.Context) ([]MCPFinding, error) {
	if s.baseline != nil {
		return nil, nil // Drift checked in T03 via diffSnapshots
	}
	return []MCPFinding{{
		ID:          "T10-001",
		ThreatClass: T10SchemaDrift,
		OWASPTag:    OWASPMCPTop10_08_Typosquatting,
		Severity:    SeverityMedium,
		Title:       "Schema drift detection unconfigured — no baseline captured",
		Detail:      "CaptureBaseline() was not called after tool registration. Without a baseline, manifest rug pull (T03) and schema mutation (T10) attacks cannot be detected. Call sc.CaptureBaseline() immediately after RegisterTool() calls complete.",
		Control:     "CM-6",
		Framework:   "NIST 800-53",
		DetectedAt:  time.Now(),
	}}, nil
}

// ── T11: Stale Credential ─────────────────────────────────────────────────────
//
// ACP credentials within 300 seconds of expiry are flagged.
// NIST 800-53 IA-5 (Authenticator Management)

const staleCredentialThreshold = 300 * time.Second // 5 minutes

func (s *Scanner) checkStaleCredential(_ context.Context) ([]MCPFinding, error) {
	if s.acp == nil {
		return []MCPFinding{{
			ID:          "T11-000",
			ThreatClass: T11StaleCredential,
			Severity:    SeverityInfo,
			Title:       "ACP plane not configured — stale credential check skipped",
			Detail:      "Pass an ACPInspector to scanner.New() to enable T11 checks.",
			Control:     "IA-5",
			Framework:   "NIST 800-53",
			DetectedAt:  time.Now(),
		}}, nil
	}

	creds := s.acp.ListCredentials()
	var findings []MCPFinding
	now := time.Now()

	for i, cred := range creds {
		ttl := cred.ExpiresAt.Sub(now)
		if ttl > 0 && ttl < staleCredentialThreshold {
			findings = append(findings, MCPFinding{
				ID:          fmt.Sprintf("T11-%03d", i+1),
				ThreatClass: T11StaleCredential,
				Severity:    SeverityMedium,
				Title:       "ACP credential expiring soon",
				Detail:      fmt.Sprintf("Credential %q (subject: %s) expires in %.0f seconds — below the 300s safety threshold. Rotate immediately to prevent mid-session authentication failure.", cred.ID, cred.Subject, ttl.Seconds()),
				Control:     "IA-5",
				Framework:   "NIST 800-53",
				DetectedAt:  now,
			})
		} else if ttl <= 0 {
			findings = append(findings, MCPFinding{
				ID:          fmt.Sprintf("T11-%03d", i+1),
				ThreatClass: T11StaleCredential,
				Severity:    SeverityHigh,
				Title:       "ACP credential already expired",
				Detail:      fmt.Sprintf("Credential %q (subject: %s) expired %.0f seconds ago. Revoke and re-issue immediately.", cred.ID, cred.Subject, (-ttl).Seconds()),
				Control:     "IA-5",
				Framework:   "NIST 800-53",
				DetectedAt:  now,
			})
		}
	}
	return findings, nil
}

// ── T16: PQC Algorithm Downgrade ─────────────────────────────────────────────
//
// Detects wrong key sizes (not ML-DSA-65 = 4,000-byte private key).
// ML-DSA-65 private key: exactly 4,032 bytes (NIST FIPS 204).
// We use a ±200 byte tolerance for library preamble differences.
// CMMC SC.3.177

const (
	mlDSA65PrivKeyMin = 3900 // bytes — ML-DSA-65 lower bound (FIPS 204) // gitleaks:allow
	mlDSA65PrivKeyMax = 4200 // bytes — ML-DSA-65 upper bound (FIPS 204) // gitleaks:allow
)

func (s *Scanner) checkPQCDowngrade(_ context.Context) ([]MCPFinding, error) {
	keyLen := s.router.SigningKeyLen()

	if keyLen == 0 {
		// No signing key — T06 already catches this
		return nil, nil
	}

	if keyLen >= mlDSA65PrivKeyMin && keyLen <= mlDSA65PrivKeyMax {
		return nil, nil // Correct algorithm
	}

	severity := SeverityCritical
	detail := fmt.Sprintf(
		"Signing key length is %d bytes — outside the ML-DSA-65 expected range [%d–%d]. "+
			"This indicates a non-CNSA-2.0-compliant algorithm (RSA, ECDSA, or weak Dilithium variant). "+
			"Reconfigure with an ML-DSA-65 private key (NIST FIPS 204). "+
			"Current key may provide no quantum resistance.",
		keyLen, mlDSA65PrivKeyMin, mlDSA65PrivKeyMax,
	)

	return []MCPFinding{{
		ID:          "T16-001",
		ThreatClass: T16PQCDowngrade,
		OWASPTag:    OWASPMCPTop10_07_MissingAuth,
		ASITag:      OWASPASI05_UnsignedAttestation,
		Severity:    severity,
		Title:       "PQC signing key is not ML-DSA-65 — algorithm downgrade detected",
		Detail:      detail,
		Control:     "SC.3.177",
		Framework:   "CMMC 2.0",
		DetectedAt:  time.Now(),
	}}, nil
}

// ── ScanOutputSecrets — GitLeaks-style output secret scanner ─────────────────
//
// Scans serialized tool output for secrets and PII before it reaches the LLM.
// Returns MCPFindings tagged OWASP-MCP-04 / OWASP-MCP-05.
// Called from router.go Step 5.5 (non-fatal: appends to warnings, does not block).
//
// compiledPatterns is lazily initialized on first call via init().
var compiledSecretPatterns []*compiledSecretPattern

type compiledSecretPattern struct {
	Name     string
	Re       *regexp.Regexp
	Severity Severity
}

func init() {
	for _, p := range SecretPatterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			// Malformed pattern — skip silently (should never happen)
			continue
		}
		compiledSecretPatterns = append(compiledSecretPatterns, &compiledSecretPattern{
			Name:     p.Name,
			Re:       re,
			Severity: p.Severity,
		})
	}
}

// ScanOutputSecrets scans raw bytes (serialized tool response) for secret patterns.
// Returns findings tagged with OWASP-MCP-04 and OWASP-MCP-05.
// Non-blocking: caller logs findings as warnings, does not halt execution.
func ScanOutputSecrets(output []byte, toolName string) []MCPFinding {
	text := string(output)
	var findings []MCPFinding
	seen := make(map[string]bool) // deduplicate by pattern name

	for _, cp := range compiledSecretPatterns {
		if seen[cp.Name] {
			continue
		}
		if cp.Re.MatchString(text) {
			seen[cp.Name] = true
			owaspTag := OWASPMCPTop10_04_CommandInjection
			if strings.HasPrefix(cp.Name, "pii-") {
				owaspTag = OWASPMCPTop10_05_UnsanitizedResponse
			}
			findings = append(findings, MCPFinding{
				ID:          fmt.Sprintf("SEC-%s-%s", toolName, cp.Name),
				ThreatClass: T06UnsignedResponse, // closest structural class
				OWASPTag:    owaspTag,
				ASITag:      OWASPASI03_CredentialTheft,
				Severity:    cp.Severity,
				Title:       fmt.Sprintf("Secret pattern detected in tool output: %s", cp.Name),
				Detail:      fmt.Sprintf("Tool %q response matches secret pattern %q. The LLM may inadvertently include this credential in its context window or subsequent outputs. Review and redact.", toolName, cp.Name),
				Control:     "SC-28",
				Framework:   "NIST 800-53",
				DetectedAt:  time.Now(),
			})
		}
	}
	return findings
}

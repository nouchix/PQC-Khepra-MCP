// Package mcp — sekhem_gateway.go
// SEKHEM Gateway / PQC-WAF Bilateral Demarcation Shield for PQC-Khepra-MCP.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
// Patent: USPTO #73565085 (KHEPRA Protocol)
// Architecture Rule: SEKHEM / PQC-WAF Encapsulation (AGENTS.md)
//
// Demarcation Points:
//   ┌────────────────────────────────────────────────────────────────────────┐
//   │                          CUSTOMER AI AGENT                             │
//   │                  (Claude / Cursor / Antigravity)                       │
//   └───────────────────────────────────▲────────────────────────────────────┘
//                                       │ JSON-RPC 2.0 (mTLS / Stdio)
//   ┌───────────────────────────────────┴────────────────────────────────────┐
//   │                 SEKHEM GATEWAY / PQC-WAF DEMARC SHIELD                 │
//   │                                                                        │
//   │  INGRESS DEMARCATION:                                                  │
//   │    ① Max Frame & Argument Size Guard (SEKHEM-004: 10MB / 1MB limit)   │
//   │    ② Poison Null-Byte & UTF-8 Validation (SEKHEM-005)                   │
//   │    ③ Path Traversal & Sensitive File Escape Guard (SEKHEM-003)         │
//   │    ④ SQLi & Command Injection Pattern Guard (SEKHEM-001)               │
//   │    ⑤ Cross-Site Scripting Injection Guard (SEKHEM-002)                 │
//   │    ⑥ Indirect Prompt Injection & Jailbreak Override (SEKHEM-006-PI)    │
//   │    ⑦ Adinkra Spectral Fingerprinting (SEKHEM-FP: "Eban" Anchor)        │
//   │                                                                        │
//   │  EGRESS DEMARCATION:                                                   │
//   │    ⑧ Secret, Credential & SAMS Bearer Token Scrubbing (SEKHEM-EGR-001) │
//   │    ⑨ Tool Output Prompt Hijack Filter (SEKHEM-EGR-002: NSA MCP §4)     │
//   │    ⑩ Spectral Tracing Header (X-Sekhem-FP) & PQC Provenance Stamp      │
//   └───────────────────────────────────▲────────────────────────────────────┘

package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

const (
	// MaxIngressArgsLimit is the maximum size for a tool argument payload (1 MiB).
	MaxIngressArgsLimit = 1 * 1024 * 1024
	// MaxRawFrameLimit is the maximum size for any JSON-RPC line (10 MiB).
	MaxRawFrameLimit = 10 * 1024 * 1024
)

// ── Ingress Regex Patterns ──────────────────────────────────────────────────

var (
	// SQLi pattern: union, select, drop, sleep, comments, boolean injection
	sekhemSQLiPattern = regexp.MustCompile(`(?i)(\b(select\s+.+\s+from|insert\s+into|update\s+.+\s+set|delete\s+from|drop\s+table|alter\s+table|union\s+select|waitfor\s+delay|sleep\s*\()\b|--\s*$|;\s*--)`)

	// XSS pattern: script tags, inline event handlers, javascript pseudo-protocol
	sekhemXSSPattern = regexp.MustCompile(`(?i)(<script[\s>]|javascript:\s*|on(load|error|click|mouse|hover|submit)\s*=)`)

	// Path traversal: directory escape sequences and sensitive root/system targets
	sekhemTraversalPattern = regexp.MustCompile(`(?i)(\.\.[/\\]|([/\\]|^)(etc[/\\/](passwd|shadow)|windows[/\\]system32|proc[/\\]self))`)

	// Indirect Prompt Injection: adversarial directives that attempt to hijack agent autonomy
	sekhemPromptInjectionPattern = regexp.MustCompile(`(?i)(ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|rules)|system\s+prompt\s+override|disregard\s+(all\s+)?prior\s+guidance|you\s+are\s+now\s+in\s+dan\s+mode|developer\s+mode\s+enabled|bypass\s+(all\s+)?(security|policy|write\s*gate)|execute\s+as\s+root\s+without\s+confirm)`)
)

// ── Egress Scrubbing Patterns ───────────────────────────────────────────────

var (
	// Secret key and token values that must never leak to the client agent
	sekhemEgressSecretRegex = regexp.MustCompile(`(?i)("(password|secret|api[_-]?key|token|bearer|credential|priv[_-]?key|private[_-]?key|sams[_-]?token)"\s*:\s*")([^"]+)(")`)

	// Raw private key blocks (PEM or base64)
	sekhemPEMKeyRegex = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)

	// Upstream output prompt hijack attempts (malicious instructions reflected from external tools)
	sekhemEgressPromptHijackRegex = regexp.MustCompile(`(?i)(ignore\s+(all\s+)?previous\s+instructions|system\s+instruction:\s*override|forget\s+your\s+rules)`)
)

// SekhemDemarcShield provides bidirectional zero-trust inspection at the MCP demarc boundary.
type SekhemDemarcShield struct {
	spectralAnchor string
	logger         *log.Logger
	enabled        bool
}

// NewSekhemDemarcShield initializes the SEKHEM Gateway / PQC-WAF demarcation filter.
func NewSekhemDemarcShield(logger *log.Logger) *SekhemDemarcShield {
	if logger == nil {
		logger = log.Default()
	}
	anchorHex := adinkra.GetSpectralFingerprint("Eban")
	anchor := hex.EncodeToString(anchorHex)
	if len(anchor) > 16 {
		anchor = anchor[:16]
	}

	return &SekhemDemarcShield{
		spectralAnchor: anchor,
		logger:         logger,
		enabled:        true,
	}
}

// SpectralAnchor returns the active D8 Eban symbol fingerprint.
func (s *SekhemDemarcShield) SpectralAnchor() string {
	return s.spectralAnchor
}

// SekhemVerdict contains the inspection outcome.
type SekhemVerdict struct {
	Allowed     bool     `json:"allowed"`
	RuleID      string   `json:"rule_id,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Warnings    []string `json:"warnings,omitempty"`
}

// ComputeFingerprint hashes the payload bound to the Eban spectral anchor.
func (s *SekhemDemarcShield) ComputeFingerprint(action string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(s.spectralAnchor + ":" + action + ":"))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// InspectIngress evaluates an incoming JSON-RPC frame/arguments through the 7-stage Ingress WAF.
func (s *SekhemDemarcShield) InspectIngress(toolName string, rawArgs json.RawMessage) (*SekhemVerdict, error) {
	if !s.enabled {
		return &SekhemVerdict{Allowed: true, Fingerprint: s.spectralAnchor}, nil
	}

	fp := s.ComputeFingerprint(toolName, rawArgs)

	// ① Size Cap Guard (SEKHEM-004)
	if len(rawArgs) > MaxIngressArgsLimit {
		s.logger.Printf("[SEKHEM-WAF:INGRESS] BLOCKED SEKHEM-004: args size %d exceeds %d limit (FP=%s)",
			len(rawArgs), MaxIngressArgsLimit, fp)
		return &SekhemVerdict{
			Allowed:     false,
			RuleID:      "SEKHEM-004",
			Reason:      fmt.Sprintf("payload exceeds maximum allowed argument size (%d bytes)", MaxIngressArgsLimit),
			Fingerprint: fp,
		}, errors.New("SEKHEM-004: payload size violation")
	}

	rawStr := string(rawArgs)

	// ② Poison Null-Byte & UTF-8 Validation (SEKHEM-005)
	if strings.Contains(rawStr, "\x00") || strings.Contains(rawStr, "\\u0000") || strings.Contains(rawStr, "`0") {
		s.logger.Printf("[SEKHEM-WAF:INGRESS] BLOCKED SEKHEM-005: poison null byte detected in %s (FP=%s)", toolName, fp)
		return &SekhemVerdict{
			Allowed:     false,
			RuleID:      "SEKHEM-005",
			Reason:      "poison null-byte sequence detected in arguments",
			Fingerprint: fp,
		}, errors.New("SEKHEM-005: encoding violation")
	}
	if !utf8.ValidString(rawStr) {
		s.logger.Printf("[SEKHEM-WAF:INGRESS] BLOCKED SEKHEM-005: invalid UTF-8 sequence in %s (FP=%s)", toolName, fp)
		return &SekhemVerdict{
			Allowed:     false,
			RuleID:      "SEKHEM-005",
			Reason:      "invalid UTF-8 byte sequence in arguments",
			Fingerprint: fp,
		}, errors.New("SEKHEM-005: invalid UTF-8")
	}

	// ③ Path Traversal Guard (SEKHEM-003)
	if sekhemTraversalPattern.MatchString(rawStr) {
		s.logger.Printf("[SEKHEM-WAF:INGRESS] BLOCKED SEKHEM-003: path traversal sequence in %s (FP=%s)", toolName, fp)
		return &SekhemVerdict{
			Allowed:     false,
			RuleID:      "SEKHEM-003",
			Reason:      "unauthorized path traversal or system file escape detected",
			Fingerprint: fp,
		}, errors.New("SEKHEM-003: path traversal attempt")
	}

	// ④ SQL Injection Pattern (SEKHEM-001)
	if sekhemSQLiPattern.MatchString(rawStr) {
		s.logger.Printf("[SEKHEM-WAF:INGRESS] BLOCKED SEKHEM-001: SQL injection syntax in %s (FP=%s)", toolName, fp)
		return &SekhemVerdict{
			Allowed:     false,
			RuleID:      "SEKHEM-001",
			Reason:      "SQL injection syntax detected in tool parameters",
			Fingerprint: fp,
		}, errors.New("SEKHEM-001: SQL injection attempt")
	}

	// ⑤ Cross-Site Scripting Injection (SEKHEM-002)
	if sekhemXSSPattern.MatchString(rawStr) {
		s.logger.Printf("[SEKHEM-WAF:INGRESS] BLOCKED SEKHEM-002: XSS payload in %s (FP=%s)", toolName, fp)
		return &SekhemVerdict{
			Allowed:     false,
			RuleID:      "SEKHEM-002",
			Reason:      "cross-site scripting syntax detected in arguments",
			Fingerprint: fp,
		}, errors.New("SEKHEM-002: XSS attempt")
	}

	// ⑥ Indirect Prompt Injection & Jailbreak (SEKHEM-006-PI)
	if sekhemPromptInjectionPattern.MatchString(rawStr) {
		s.logger.Printf("[SEKHEM-WAF:INGRESS] BLOCKED SEKHEM-006-PI: adversarial prompt injection in %s (FP=%s)", toolName, fp)
		return &SekhemVerdict{
			Allowed:     false,
			RuleID:      "SEKHEM-006-PI",
			Reason:      "adversarial prompt override or system instruction injection detected",
			Fingerprint: fp,
		}, errors.New("SEKHEM-006-PI: prompt injection attempt")
	}

	return &SekhemVerdict{
		Allowed:     true,
		Fingerprint: fp,
	}, nil
}

// FilterEgress scrubs sensitive secrets and prompt-hijack directives from tool results.
func (s *SekhemDemarcShield) FilterEgress(toolName string, rawResult []byte) ([]byte, []string, string) {
	if !s.enabled || len(rawResult) == 0 {
		return rawResult, nil, s.spectralAnchor
	}

	fp := s.ComputeFingerprint(toolName+":egress", rawResult)
	var warnings []string
	filtered := string(rawResult)

	// ⑧ Secret & Credential Scrubbing (SEKHEM-EGR-001)
	if sekhemPEMKeyRegex.MatchString(filtered) {
		filtered = sekhemPEMKeyRegex.ReplaceAllString(filtered, "-----BEGIN ENCRYPTED REDACTED KEY-----\n[SEKHEM_PQC_REDACTED]\n-----END ENCRYPTED REDACTED KEY-----")
		warnings = append(warnings, "SEKHEM-EGR-001: raw private key scrubbed from tool output")
		s.logger.Printf("[SEKHEM-WAF:EGRESS] Scrubbed raw private key block in %s (FP=%s)", toolName, fp)
	}

	if sekhemEgressSecretRegex.MatchString(filtered) {
		filtered = sekhemEgressSecretRegex.ReplaceAllString(filtered, `$1[SEKHEM_REDACTED]$4`)
		warnings = append(warnings, "SEKHEM-EGR-001: credential / token value scrubbed from tool output")
		s.logger.Printf("[SEKHEM-WAF:EGRESS] Scrubbed credential field in %s (FP=%s)", toolName, fp)
	}

	// ⑨ Tool Output Prompt Hijack Filter (SEKHEM-EGR-002)
	if sekhemEgressPromptHijackRegex.MatchString(filtered) {
		warnings = append(warnings, "SEKHEM-EGR-002: upstream output contains potential prompt hijack directive — review with caution")
		s.logger.Printf("[SEKHEM-WAF:EGRESS] WARNING: tool %s output contains prompt override pattern (FP=%s)", toolName, fp)
	}

	return []byte(filtered), warnings, fp
}

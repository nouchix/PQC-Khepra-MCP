// Package logging provides security-aware log helpers for the KHEPRA protocol.
//
// SanitizeForLog MUST be applied to ALL user-controlled values before embedding
// in log messages to prevent log injection attacks (CWE-117 / NIST 800-53 AU-3).
package logging

import "strings"

// SanitizeForLog removes newline, carriage return, tab, and NUL characters from
// user-controlled strings before logging to prevent log injection attacks
// (CWE-117 / CodeQL go/log-injection / NIST 800-53 AU-3).
//
// Apply this to ALL user-supplied values before embedding in log.Printf() or
// similar calls. The DoD dual-tap logger (pkg/logging/dod_logger.go) applies
// its own redaction patterns on top of this sanitization.
//
// Example:
//
//	log.Printf("[MCP] tool=%q agent=%q", SanitizeForLog(toolName), SanitizeForLog(agentID))
func SanitizeForLog(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', '\x00':
			return ' '
		default:
			return r
		}
	}, s)
}

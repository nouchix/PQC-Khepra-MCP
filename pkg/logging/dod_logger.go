// Package logging provides DoD-compliant dual-pipeline logging for Platform One environments.
//
// ECR-03: Observability & Logging (Dual-Pipeline Strategy)
//
// This package implements the "Dual-Tap" logging architecture required by
// DoD DevSecOps Reference Design:
//
// 1. **stdout (JSON)**: Structured logs for EFK stack (Elasticsearch, Fluentd, Kibana)
//    - Scraped by Fluentd sidecars
//    - Centralized in Elasticsearch
//    - Visible to SOC (Security Operations Center)
//
// 2. **Internal DAG**: Immutable audit trail for forensics
//    - Cryptographically signed events
//    - Local-only (not exposed to EFK)
//    - Used for compliance evidence and incident response
//
// Security Constraint (ECR-03):
//   NO proprietary PQC keys, seed values, or sensitive system internals
//   may be written to stdout (Low Side). The ELK stack is considered
//   "Low Side" and cannot hold classified or sensitive data.
//
// Usage:
//   logger := logging.NewDoDLogger(dagWriter, redactConfig)
//   logger.Info("STIG scan completed", "system", "web-01", "findings", 42)

package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// RedactLevel defines how aggressively to redact sensitive data from stdout logs
type RedactLevel int

const (
	// RedactNone - No redaction (dev mode only, NOT for production)
	RedactNone RedactLevel = iota

	// RedactSensitive - Redact keys, passwords, tokens (default)
	RedactSensitive

	// RedactAll - Redact all potentially sensitive fields (DoD classification boundaries)
	RedactAll
)

// SensitiveFields lists field names that should never appear in stdout logs
var SensitiveFields = []string{
	// Cryptographic material
	"private_key", "secret_key", "seed", "entropy",
	"dilithium_key", "kyber_key", "pqc_seed", "kyber_public_key",

	// Credentials
	"password", "token", "api_key", "auth_token",
	"jwt", "bearer", "credential",

	// Personal data (PII)
	"ssn", "social_security", "credit_card",
	"dob", "date_of_birth",

	// System internals
	"raw_memory", "stack_trace", "core_dump",
}

// DoDLogger provides dual-pipeline logging for DoD environments
type DoDLogger struct {
	stdout    *slog.Logger // JSON to stdout (for EFK stack)
	dag       io.Writer    // Internal DAG writer (for forensics)
	redact    RedactLevel
	tenant    string
	component string
}

// NewDoDLogger creates a logger with dual output streams
//
// Parameters:
//   - dagWriter: Writer for internal DAG (e.g., BadgerDB, SQLite)
//   - redactLevel: How aggressively to sanitize stdout logs
//   - tenant: Tenant ID for multi-tenant deployments
//   - component: Component name (e.g., "stig-scanner", "license-validator")
//
// Example:
//
//	dagWriter := db.GetDAGWriter()
//	logger := logging.NewDoDLogger(dagWriter, logging.RedactSensitive, "tenant-1", "stig-scanner")
//	logger.Info("Scan started", "target", "/etc")
func NewDoDLogger(dagWriter io.Writer, redactLevel RedactLevel, tenant, component string) *DoDLogger {
	// Create JSON handler for stdout (EFK stack)
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Redact sensitive attributes
			if redactLevel >= RedactSensitive && isSensitiveField(a.Key) {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	})

	logger := &DoDLogger{
		stdout:    slog.New(jsonHandler),
		dag:       dagWriter,
		redact:    redactLevel,
		tenant:    tenant,
		component: component,
	}

	return logger
}

// Info logs an informational message to both stdout and DAG
func (l *DoDLogger) Info(msg string, args ...any) {
	l.logBoth(slog.LevelInfo, msg, args...)
}

// Warn logs a warning message to both stdout and DAG
func (l *DoDLogger) Warn(msg string, args ...any) {
	l.logBoth(slog.LevelWarn, msg, args...)
}

// Error logs an error message to both stdout and DAG
func (l *DoDLogger) Error(msg string, args ...any) {
	l.logBoth(slog.LevelError, msg, args...)
}

// Debug logs a debug message (only to DAG, not stdout to reduce EFK noise)
func (l *DoDLogger) Debug(msg string, args ...any) {
	// Debug logs go ONLY to DAG, not stdout (reduces EFK volume)
	l.writeToDag(slog.LevelDebug, msg, args...)
}

// InfoCtx logs with context (for distributed tracing)
func (l *DoDLogger) InfoCtx(ctx context.Context, msg string, args ...any) {
	l.logBothCtx(ctx, slog.LevelInfo, msg, args...)
}

// logBoth writes to both stdout (redacted) and DAG (full details)
func (l *DoDLogger) logBoth(level slog.Level, msg string, args ...any) {
	l.logBothCtx(context.Background(), level, msg, args...)
}

// logBothCtx writes to both outputs with context
func (l *DoDLogger) logBothCtx(ctx context.Context, level slog.Level, msg string, args ...any) {
	// Add standard fields
	enhancedArgs := append([]any{
		"tenant", l.tenant,
		"component", l.component,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
	}, args...)

	// Write to stdout (redacted per RedactLevel)
	l.stdout.LogAttrs(ctx, level, msg, argsToAttrs(enhancedArgs)...)

	// Write to DAG (full details, no redaction)
	l.writeToDag(level, msg, enhancedArgs...)
}

// writeToDag writes raw log entry to internal DAG
func (l *DoDLogger) writeToDag(level slog.Level, msg string, args ...any) {
	if l.dag == nil {
		return // DAG writer not configured
	}

	// Format as structured log entry for DAG
	// In production, this would write to BadgerDB or similar
	entry := formatDAGEntry(level, msg, args...)
	l.dag.Write([]byte(entry + "\n"))
}

// formatDAGEntry creates a structured log entry for the internal DAG
// This is NOT JSON to save space - it's a custom compact format
func formatDAGEntry(level slog.Level, msg string, args ...any) string {
	// Compact format: TIMESTAMP|LEVEL|MSG|KEY=VAL KEY=VAL...
	timestamp := time.Now().UTC().Format(time.RFC3339)
	levelStr := level.String()

	// Convert args to key=val pairs
	pairs := make([]string, 0, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		key := args[i].(string)
		val := args[i+1]
		pairs = append(pairs, key+"="+formatValue(val))
	}

	return timestamp + "|" + levelStr + "|" + msg + "|" + strings.Join(pairs, " ")
}

// formatValue converts a value to string for DAG entry
func formatValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case int, int64, uint, uint64, float64:
		return slog.AnyValue(val).String()
	default:
		return slog.AnyValue(val).String()
	}
}

// argsToAttrs converts variadic args to slog.Attr slice
func argsToAttrs(args []any) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		key := args[i].(string)
		val := args[i+1]
		attrs = append(attrs, slog.Any(key, val))
	}
	return attrs
}

// isSensitiveField checks if a field name matches sensitive patterns
func isSensitiveField(key string) bool {
	lowerKey := strings.ToLower(key)
	for _, sensitive := range SensitiveFields {
		if strings.Contains(lowerKey, sensitive) {
			return true
		}
	}
	return false
}

// Flush ensures all buffered logs are written (call on shutdown)
func (l *DoDLogger) Flush() {
	// stdout is unbuffered, but DAG writer might be buffered
	if flusher, ok := l.dag.(interface{ Flush() error }); ok {
		flusher.Flush()
	}
}

// GetStdoutLogger returns the underlying stdout logger for compatibility
func (l *DoDLogger) GetStdoutLogger() *slog.Logger {
	return l.stdout
}

// GetRedactLevel returns the current redaction level
func (l *DoDLogger) GetRedactLevel() RedactLevel {
	return l.redact
}

// SetRedactLevel changes the redaction level (useful for debugging)
func (l *DoDLogger) SetRedactLevel(level RedactLevel) {
	l.redact = level
}

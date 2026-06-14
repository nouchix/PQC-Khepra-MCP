// Package mcp — input validation and security hardening for tool arguments.
//
// Every tool call passes through these validators before execution.
// Implements:
//   - Path traversal prevention
//   - Command injection detection
//   - Argument size limits
//   - Schema type validation
//   - Loop / mistake detection

package mcp

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ─── Error Codes ───────────────────────────────────────────────────────────────

const (
	ErrCodePathTraversal    = "PATH_TRAVERSAL"
	ErrCodeCommandInjection = "COMMAND_INJECTION"
	ErrCodeInputTooLarge    = "INPUT_TOO_LARGE"
	ErrCodeInvalidArg       = "INVALID_ARG"
	ErrCodeLoopDetected     = "LOOP_DETECTED"
	ErrCodeMistakeLimit     = "MISTAKE_LIMIT"
	ErrCodeRateLimit        = "RATE_LIMIT"
	ErrCodeTimeout          = "TIMEOUT"
	// ErrCodeConcurrencyLimit fires when a session exceeds maxConcurrent parallel tool calls.
	// Maps to NSA MCP prompt-storm defense and standard MCP backpressure signalling.
	ErrCodeConcurrencyLimit = "CONCURRENCY_LIMIT"
)

// ─── Validation Error ──────────────────────────────────────────────────────────

// ValidationError is a structured error from input validation.
type ValidationError struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Field, e.Message)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// ─── Input Validators ──────────────────────────────────────────────────────────

// MaxArgSize is the maximum size of a single argument value in bytes.
const MaxArgSize = 1 << 20 // 1MB

// dangerousPatterns detects common command injection vectors.
var dangerousPatterns = regexp.MustCompile(
	`(?i)` +
		`(\$\(.*\))` + // $() subshell
		`|(\x60.*\x60)` + // backtick subshell
		`|(;\s*(rm|dd|mkfs|wget|curl|nc|bash|sh|python|perl|ruby|php)\b)` + // semicolon-chained commands
		`|(\|\s*(bash|sh|nc|python)\b)` + // pipe to shell
		`|(&&\s*(rm|dd|wget|curl)\b)` + // && chained destructive
		`|(\beval\s*\()` + // eval()
		`|(__import__|exec\s*\(|os\.system)`, // Python injection
)

// ValidateToolArgs validates all arguments for a tool call.
// It runs path traversal, injection, and size checks on every string value.
func ValidateToolArgs(args map[string]any) *ValidationError {
	for key, val := range args {
		if err := validateArgValue(key, val, 0); err != nil {
			return err
		}
	}
	return nil
}

// validateArgValue recursively validates a single argument value.
func validateArgValue(key string, val any, depth int) *ValidationError {
	if depth > 10 {
		return &ValidationError{Code: ErrCodeInvalidArg, Field: key, Message: "nested too deep"}
	}

	switch v := val.(type) {
	case string:
		return validateStringArg(key, v)
	case []any:
		for i, item := range v {
			if err := validateArgValue(fmt.Sprintf("%s[%d]", key, i), item, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, item := range v {
			if err := validateArgValue(key+"."+k, item, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateStringArg checks a single string argument for threats.
func validateStringArg(key, val string) *ValidationError {
	// Size check
	if len(val) > MaxArgSize {
		return &ValidationError{
			Code:    ErrCodeInputTooLarge,
			Field:   key,
			Message: fmt.Sprintf("value exceeds %d bytes", MaxArgSize),
		}
	}

	// UTF-8 validity
	if !utf8.ValidString(val) {
		return &ValidationError{
			Code:    ErrCodeInvalidArg,
			Field:   key,
			Message: "invalid UTF-8 encoding",
		}
	}

	// Path traversal detection (applies to path-like fields)
	if isPathField(key) {
		if err := validatePath(key, val); err != nil {
			return err
		}
	}

	// Command injection detection
	if dangerousPatterns.MatchString(val) {
		return &ValidationError{
			Code:    ErrCodeCommandInjection,
			Field:   key,
			Message: "potential command injection detected",
		}
	}

	return nil
}

// isPathField returns true if the field name suggests it contains a file path.
func isPathField(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "path") ||
		strings.Contains(lower, "file") ||
		strings.Contains(lower, "dir") ||
		strings.Contains(lower, "directory") ||
		strings.Contains(lower, "target")
}

// validatePath checks for path traversal attacks.
func validatePath(key, val string) *ValidationError {
	// Clean the path
	cleaned := filepath.Clean(val)

	// Block absolute paths (tools should operate on relative paths)
	if filepath.IsAbs(cleaned) && cleaned != "." && cleaned != "/" {
		return &ValidationError{
			Code:    ErrCodePathTraversal,
			Field:   key,
			Message: "absolute paths are not allowed",
		}
	}

	// Block parent directory traversal
	if strings.Contains(cleaned, "..") {
		return &ValidationError{
			Code:    ErrCodePathTraversal,
			Field:   key,
			Message: "path traversal (..) blocked",
		}
	}

	// Block /etc, /proc, /sys, /dev access
	dangerousPrefixes := []string{"/etc/", "/proc/", "/sys/", "/dev/", "/root/", "/var/run/"}
	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(cleaned, prefix) {
			return &ValidationError{
				Code:    ErrCodePathTraversal,
				Field:   key,
				Message: fmt.Sprintf("access to %s is blocked", prefix),
			}
		}
	}

	return nil
}

// ─── Mistake / Loop Detection ──────────────────────────────────────────────────

// MistakeTracker tracks consecutive errors per agent session to detect
// error loops and runaway agent behavior.
type MistakeTracker struct {
	mu              sync.Mutex
	consecutiveErrs map[string]int       // agentID → consecutive error count
	recentCalls     map[string][]callRecord // agentID → recent call history
	maxConsecutive  int                   // max consecutive recoverable errors before cutoff
	loopWindow      int                   // number of recent calls to check for loops
	loopThreshold   int                   // identical calls within window = loop
}

type callRecord struct {
	toolName string
	argsHash string // crude hash of arguments for comparison
	at       time.Time
}

// MistakeTrackerConfig configures mistake/loop detection.
type MistakeTrackerConfig struct {
	MaxConsecutiveErrors int // Default: 5
	LoopWindow           int // Default: 10 (last N calls to scan)
	LoopThreshold        int // Default: 3 (identical calls in window = loop)
}

// NewMistakeTracker creates a mistake tracker with the given limits.
func NewMistakeTracker(cfg MistakeTrackerConfig) *MistakeTracker {
	if cfg.MaxConsecutiveErrors <= 0 {
		cfg.MaxConsecutiveErrors = 5
	}
	if cfg.LoopWindow <= 0 {
		cfg.LoopWindow = 10
	}
	if cfg.LoopThreshold <= 0 {
		cfg.LoopThreshold = 3
	}
	return &MistakeTracker{
		consecutiveErrs: make(map[string]int),
		recentCalls:     make(map[string][]callRecord),
		maxConsecutive:  cfg.MaxConsecutiveErrors,
		loopWindow:      cfg.LoopWindow,
		loopThreshold:   cfg.LoopThreshold,
	}
}

// RecordSuccess resets the consecutive error count for an agent.
func (mt *MistakeTracker) RecordSuccess(agentID string) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.consecutiveErrs[agentID] = 0
}

// RecordError increments the consecutive error count.
// Returns a ValidationError if the mistake limit is exceeded.
func (mt *MistakeTracker) RecordError(agentID string) *ValidationError {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	mt.consecutiveErrs[agentID]++
	count := mt.consecutiveErrs[agentID]

	if count >= mt.maxConsecutive {
		return &ValidationError{
			Code:    ErrCodeMistakeLimit,
			Message: fmt.Sprintf("agent %s has %d consecutive errors — session paused", agentID, count),
		}
	}
	return nil
}

// CheckLoop detects if the agent is calling the same tool with the same
// arguments in a tight loop (suggests stuck agent behavior).
func (mt *MistakeTracker) CheckLoop(agentID, toolName, argsFingerprint string) *ValidationError {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	rec := callRecord{
		toolName: toolName,
		argsHash: argsFingerprint,
		at:       time.Now(),
	}

	history := mt.recentCalls[agentID]
	history = append(history, rec)

	// Keep only the last loopWindow entries
	if len(history) > mt.loopWindow {
		history = history[len(history)-mt.loopWindow:]
	}
	mt.recentCalls[agentID] = history

	// Count identical calls in the window
	identical := 0
	for _, h := range history {
		if h.toolName == toolName && h.argsHash == argsFingerprint {
			identical++
		}
	}

	if identical >= mt.loopThreshold {
		return &ValidationError{
			Code:    ErrCodeLoopDetected,
			Message: fmt.Sprintf("loop detected: tool %s called %d times with same args", toolName, identical),
		}
	}

	return nil
}

// ResetAgent clears all tracking for an agent (e.g. on session end).
func (mt *MistakeTracker) ResetAgent(agentID string) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	delete(mt.consecutiveErrs, agentID)
	delete(mt.recentCalls, agentID)
}

// ─── Rate Limiter ──────────────────────────────────────────────────────────────

// RateLimiter enforces per-agent request rate limits.
type RateLimiter struct {
	mu          sync.Mutex
	windowMs    int64
	maxRequests int
	windows     map[string][]int64 // agentID → request timestamps
}

// NewRateLimiter creates a rate limiter.
// windowMs: time window in milliseconds. maxRequests: max requests per window.
func NewRateLimiter(windowMs int64, maxRequests int) *RateLimiter {
	return &RateLimiter{
		windowMs:    windowMs,
		maxRequests: maxRequests,
		windows:     make(map[string][]int64),
	}
}

// Allow checks if a request from the given agent is within rate limits.
func (rl *RateLimiter) Allow(agentID string) *ValidationError {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UnixMilli()
	cutoff := now - rl.windowMs

	// Prune expired entries
	existing := rl.windows[agentID]
	pruned := make([]int64, 0, len(existing))
	for _, ts := range existing {
		if ts > cutoff {
			pruned = append(pruned, ts)
		}
	}

	if len(pruned) >= rl.maxRequests {
		return &ValidationError{
			Code:    ErrCodeRateLimit,
			Message: fmt.Sprintf("rate limit exceeded: %d requests in %dms window", rl.maxRequests, rl.windowMs),
		}
	}

	pruned = append(pruned, now)
	rl.windows[agentID] = pruned
	return nil
}

// ─── Concurrency Limiter (NSA Prompt-Storm Defense) ────────────────────────
//
// Caps the number of simultaneous tool calls per agent session.
// Prevents resource exhaustion from rapid concurrent invocations
// ("prompt storms") and protects the khepra-daemon scan queue.

// ConcurrencyLimiter tracks and limits concurrent tool calls per agent.
type ConcurrencyLimiter struct {
	mu            sync.Mutex
	active        map[string]int // agentID → active concurrent calls
	maxConcurrent int
}

// NewConcurrencyLimiter creates a limiter allowing at most maxConcurrent
// simultaneous tool calls per agent. Default: 5 if maxConcurrent <= 0.
func NewConcurrencyLimiter(maxConcurrent int) *ConcurrencyLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 5
	}
	return &ConcurrencyLimiter{
		active:        make(map[string]int),
		maxConcurrent: maxConcurrent,
	}
}

// Acquire attempts to start a new concurrent call for agentID.
// Returns a ValidationError if the concurrency cap is reached.
// The caller MUST call Release() when the tool call completes.
func (cl *ConcurrencyLimiter) Acquire(agentID string) *ValidationError {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.active[agentID] >= cl.maxConcurrent {
		return &ValidationError{
			Code:    ErrCodeConcurrencyLimit,
			Message: fmt.Sprintf("concurrency limit: agent %q already has %d active tool calls (max %d) — backpressure engaged", agentID, cl.active[agentID], cl.maxConcurrent),
		}
	}
	cl.active[agentID]++
	return nil
}

// Release decrements the active call counter for agentID.
// Safe to call even if agentID has no tracked calls.
func (cl *ConcurrencyLimiter) Release(agentID string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.active[agentID] > 0 {
		cl.active[agentID]--
	}
	if cl.active[agentID] == 0 {
		delete(cl.active, agentID)
	}
}

// ActiveCalls returns the number of active concurrent calls for agentID.
func (cl *ConcurrencyLimiter) ActiveCalls(agentID string) int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.active[agentID]
}

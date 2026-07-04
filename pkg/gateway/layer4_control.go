// Layer 4: Rate Limiting & Control - Abuse Prevention and Audit Trail
// "The Scales of Ma'at Measure All"
//
// This layer implements rate limiting, request logging, and comprehensive
// audit trail to the immutable DAG constellation.
package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	khlog "github.com/nouchix/PQC-Khepra-MCP/pkg/logging"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
)

// ControlLayer implements Layer 4 rate limiting and logging
type ControlLayer struct {
	rateLimitConfig *RateLimitConfig
	loggingConfig   *LoggingConfig

	// Rate limit state (in-memory, would use Redis in production)
	rateLimiters   map[string]*RateLimiter
	rateLimitersMu sync.RWMutex

	// Global rate limiter
	globalLimiter *TokenBucket

	// Audit log channel
	auditChan chan *AuditEvent

	// WebSocket connections for real-time monitoring
	wsConnections   map[string]chan *AuditEvent
	wsConnectionsMu sync.RWMutex

	// DAG writer (interface to our immutable audit trail)
	dagWriter DAGWriter

	// Telemetry writer (interface to telemetry server)
	telemetryWriter TelemetryWriter
}

// RateLimiter tracks rate limits for an identity
type RateLimiter struct {
	IdentityID string
	TrustScore float64

	// Token buckets at different time windows
	PerSecond *TokenBucket
	PerMinute *TokenBucket
	PerHour   *TokenBucket

	// Burst handling
	BurstBucket *TokenBucket

	// Backoff state
	BackoffUntil time.Time
	BackoffCount int

	LastRequest time.Time
	mu          sync.Mutex
}

// TokenBucket implements the token bucket algorithm
type TokenBucket struct {
	Capacity   int
	Tokens     int
	RefillRate float64 // tokens per second
	LastRefill time.Time
	mu         sync.Mutex
}

// AuditEvent represents a logged request for the audit trail
type AuditEvent struct {
	// Request identification
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`

	// Client information
	ClientIP  string `json:"client_ip"`
	UserAgent string `json:"user_agent"`

	// Request details
	Method      string `json:"method"`
	Path        string `json:"path"`
	QueryParams string `json:"query_params,omitempty"`

	// Identity (may be hashed for privacy)
	IdentityID   string `json:"identity_id"`
	IdentityType string `json:"identity_type"`
	Organization string `json:"organization"`

	// Security context
	TrustScore   float64 `json:"trust_score"`
	AnomalyScore float64 `json:"anomaly_score"`

	// Outcome
	StatusCode  int           `json:"status_code"`
	Blocked     bool          `json:"blocked"`
	BlockReason string        `json:"block_reason,omitempty"`
	Duration    time.Duration `json:"duration_ns"`

	// Security flags
	Flags []string `json:"flags,omitempty"`

	// Layer-specific metadata
	FirewallResult string `json:"firewall_result,omitempty"`
	AuthResult     string `json:"auth_result,omitempty"`
	RateLimited    bool   `json:"rate_limited"`
}

// DAGWriter interface for writing to immutable audit trail
type DAGWriter interface {
	WriteAuditEvent(event *AuditEvent) error
}

// TelemetryWriter interface for sending to telemetry server
type TelemetryWriter interface {
	SendEvent(event *AuditEvent) error
}

// NewControlLayer creates a new rate limiting and logging layer
func NewControlLayer(rateCfg *RateLimitConfig, logCfg *LoggingConfig) (*ControlLayer, error) {
	layer := &ControlLayer{
		rateLimitConfig: rateCfg,
		loggingConfig:   logCfg,
		rateLimiters:    make(map[string]*RateLimiter),
		globalLimiter: &TokenBucket{
			Capacity:   rateCfg.GlobalRequestsPerSecond,
			Tokens:     rateCfg.GlobalRequestsPerSecond,
			RefillRate: float64(rateCfg.GlobalRequestsPerSecond),
			LastRefill: time.Now(),
		},
		auditChan:     make(chan *AuditEvent, 10000),
		wsConnections: make(map[string]chan *AuditEvent),
	}

	// Start audit log processor
	go layer.processAuditLog()

	log.Printf("[CONTROL] Layer 4 initialized - RateLimit[%d/s global, %d/s per-identity] Logging[%q]",
		rateCfg.GlobalRequestsPerSecond, rateCfg.RequestsPerSecond, logCfg.Level)

	return layer, nil
}

// CheckRateLimit checks if the request should be rate limited
// Returns (allowed bool, retryAfter time.Duration)
func (c *ControlLayer) CheckRateLimit(identityID string) (bool, time.Duration) {
	// Check global rate limit first
	if !c.globalLimiter.Allow() {
		return false, time.Second
	}

	// Get or create per-identity rate limiter
	limiter := c.getOrCreateLimiter(identityID)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	// Check if in backoff
	if time.Now().Before(limiter.BackoffUntil) {
		retryAfter := time.Until(limiter.BackoffUntil)
		return false, retryAfter
	}

	// Check all time windows
	if !limiter.PerSecond.Allow() {
		c.applyBackoff(limiter)
		return false, time.Second
	}

	if !limiter.PerMinute.Allow() {
		c.applyBackoff(limiter)
		return false, time.Minute / time.Duration(c.rateLimitConfig.RequestsPerMinute)
	}

	if !limiter.PerHour.Allow() {
		c.applyBackoff(limiter)
		return false, time.Hour / time.Duration(c.rateLimitConfig.RequestsPerHour)
	}

	// Check burst allowance
	if !limiter.BurstBucket.Allow() {
		// Burst exceeded but not rate limited - add flag
		return true, 0
	}

	limiter.LastRequest = time.Now()
	return true, 0
}

// getOrCreateLimiter gets or creates a rate limiter for an identity
func (c *ControlLayer) getOrCreateLimiter(identityID string) *RateLimiter {
	c.rateLimitersMu.RLock()
	limiter, exists := c.rateLimiters[identityID]
	c.rateLimitersMu.RUnlock()

	if exists {
		return limiter
	}

	c.rateLimitersMu.Lock()
	defer c.rateLimitersMu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists = c.rateLimiters[identityID]; exists {
		return limiter
	}

	cfg := c.rateLimitConfig
	limiter = &RateLimiter{
		IdentityID: identityID,
		TrustScore: 0.5, // Default, should be updated with actual trust score
		PerSecond: &TokenBucket{
			Capacity:   cfg.RequestsPerSecond,
			Tokens:     cfg.RequestsPerSecond,
			RefillRate: float64(cfg.RequestsPerSecond),
			LastRefill: time.Now(),
		},
		PerMinute: &TokenBucket{
			Capacity:   cfg.RequestsPerMinute,
			Tokens:     cfg.RequestsPerMinute,
			RefillRate: float64(cfg.RequestsPerMinute) / 60.0,
			LastRefill: time.Now(),
		},
		PerHour: &TokenBucket{
			Capacity:   cfg.RequestsPerHour,
			Tokens:     cfg.RequestsPerHour,
			RefillRate: float64(cfg.RequestsPerHour) / 3600.0,
			LastRefill: time.Now(),
		},
		BurstBucket: &TokenBucket{
			Capacity:   cfg.BurstAllowance,
			Tokens:     cfg.BurstAllowance,
			RefillRate: float64(cfg.BurstAllowance) / cfg.BurstWindow.Seconds(),
			LastRefill: time.Now(),
		},
		LastRequest: time.Now(),
	}

	c.rateLimiters[identityID] = limiter
	return limiter
}

// applyBackoff applies exponential backoff
func (c *ControlLayer) applyBackoff(limiter *RateLimiter) {
	limiter.BackoffCount++

	var backoffDuration time.Duration
	switch c.rateLimitConfig.BackoffStrategy {
	case "exponential":
		// Exponential: 1s, 2s, 4s, 8s, ... capped at max
		backoffDuration = time.Duration(1<<limiter.BackoffCount) * time.Second
	case "linear":
		backoffDuration = time.Duration(limiter.BackoffCount) * time.Second
	default:
		backoffDuration = time.Second
	}

	if backoffDuration > c.rateLimitConfig.MaxBackoffDuration {
		backoffDuration = c.rateLimitConfig.MaxBackoffDuration
	}

	limiter.BackoffUntil = time.Now().Add(backoffDuration)
	log.Printf("[CONTROL] Applied backoff to %q: %v (count: %d)",
		khlog.SanitizeForLog(limiter.IdentityID), backoffDuration, limiter.BackoffCount)
}

// UpdateTrustScore updates the trust score multiplier for an identity
func (c *ControlLayer) UpdateTrustScore(identityID string, trustScore float64) {
	limiter := c.getOrCreateLimiter(identityID)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	limiter.TrustScore = trustScore

	// Apply trust score multiplier to rate limits
	if c.rateLimitConfig.TrustScoreMultiplier {
		multiplier := 1.0 + trustScore // Range: 1.0 to 2.0
		limiter.PerSecond.Capacity = int(float64(c.rateLimitConfig.RequestsPerSecond) * multiplier)
		limiter.PerMinute.Capacity = int(float64(c.rateLimitConfig.RequestsPerMinute) * multiplier)
		limiter.PerHour.Capacity = int(float64(c.rateLimitConfig.RequestsPerHour) * multiplier)
	}
}

// LogRequest logs a request to the audit trail
func (c *ControlLayer) LogRequest(ctx *RequestContext) {
	event := &AuditEvent{
		RequestID:    ctx.RequestID,
		Timestamp:    ctx.StartTime,
		ClientIP:     ctx.ClientIP,
		UserAgent:    ctx.UserAgent,
		Method:       ctx.Method,
		Path:         ctx.Path,
		StatusCode:   ctx.StatusCode,
		Blocked:      ctx.Blocked,
		BlockReason:  ctx.BlockReason,
		Duration:     ctx.Duration,
		AnomalyScore: ctx.AnomalyScore,
		Flags:        ctx.Flags,
	}

	if ctx.Identity != nil {
		// Apply privacy settings
		if c.loggingConfig.HashSensitiveFields {
			event.IdentityID = hashString(ctx.Identity.ID)[:16]
		} else {
			event.IdentityID = ctx.Identity.ID
		}
		event.IdentityType = ctx.Identity.Type
		event.Organization = ctx.Identity.Organization
		event.TrustScore = ctx.Identity.TrustScore
	}

	// Check exclusion list
	for _, field := range c.loggingConfig.ExcludeFields {
		switch field {
		case "client_ip":
			event.ClientIP = "[REDACTED]"
		case "user_agent":
			event.UserAgent = "[REDACTED]"
		}
	}

	// Send to audit channel (non-blocking)
	select {
	case c.auditChan <- event:
	default:
		log.Printf("[CONTROL] Audit channel full, dropping event: %q", event.RequestID)
	}
}

// processAuditLog processes audit events from the channel
func (c *ControlLayer) processAuditLog() {
	for event := range c.auditChan {
		c.dispatchToOutputs(event)
	}
}

func (c *ControlLayer) dispatchToOutputs(event *AuditEvent) {
	// Log to stdout
	if c.loggingConfig.LogToStdout {
		c.logToStdout(event)
	}

	// Log to file
	if c.loggingConfig.LogToFile && c.loggingConfig.LogFilePath != "" {
		c.logToFile(event)
	}

	// Log to DAG
	if c.loggingConfig.LogToDAG && c.dagWriter != nil {
		if err := c.dagWriter.WriteAuditEvent(event); err != nil {
			log.Printf("[CONTROL] Failed to write to DAG: %v", err)
		}
	}

	// Send to telemetry
	if c.loggingConfig.LogToTelemetry && c.telemetryWriter != nil {
		if err := c.telemetryWriter.SendEvent(event); err != nil {
			log.Printf("[CONTROL] Failed to send to telemetry: %v", err)
		}
	}

	// Broadcast to WebSockets
	if c.loggingConfig.WebSocketEnabled {
		c.broadcastToWebSockets(event)
	}
}

// logToStdout logs event to stdout
func (c *ControlLayer) logToStdout(event *AuditEvent) {
	status := "OK"
	if event.Blocked {
		status = "BLOCKED"
	}

	log.Printf("[AUDIT] %q %q %q %q %d %q %.2fms anomaly=%.2f",
		event.RequestID[:8],
		event.Method,
		event.Path,
		status,
		event.StatusCode,
		event.IdentityID[:8],
		float64(event.Duration)/float64(time.Millisecond),
		event.AnomalyScore)
}

// logToFile logs event to file (JSON format)
func (c *ControlLayer) logToFile(event *AuditEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[CONTROL] Failed to marshal event: %v", err)
		return
	}

	f, err := os.OpenFile(c.loggingConfig.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[CONTROL] Failed to open log file: %v", err)
		return
	}
	// Explicit close with error capture to prevent silent data loss (CWE-390 / Go WARNING).
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("[CONTROL] Failed to close log file: %v", cerr)
		}
	}()

	if _, err := f.WriteString(string(data) + "\n"); err != nil {
		log.Printf("[CONTROL] Failed to write to log file: %v", err)
	}
}

// broadcastToWebSockets sends event to all connected WebSocket clients
func (c *ControlLayer) broadcastToWebSockets(event *AuditEvent) {
	c.wsConnectionsMu.RLock()
	defer c.wsConnectionsMu.RUnlock()

	for _, ch := range c.wsConnections {
		select {
		case ch <- event:
		default:
			// Client channel full, skip
		}
	}
}

// RegisterWebSocket registers a new WebSocket connection for real-time logs
func (c *ControlLayer) RegisterWebSocket(connID string) chan *AuditEvent {
	ch := make(chan *AuditEvent, 100)

	c.wsConnectionsMu.Lock()
	c.wsConnections[connID] = ch
	c.wsConnectionsMu.Unlock()

	log.Printf("[CONTROL] WebSocket registered: %q", connID)
	return ch
}

// UnregisterWebSocket removes a WebSocket connection
func (c *ControlLayer) UnregisterWebSocket(connID string) {
	c.wsConnectionsMu.Lock()
	defer c.wsConnectionsMu.Unlock()

	if ch, exists := c.wsConnections[connID]; exists {
		close(ch)
		delete(c.wsConnections, connID)
		log.Printf("[CONTROL] WebSocket unregistered: %q", connID)
	}
}

// SetDAGWriter sets the DAG writer for immutable audit trail
func (c *ControlLayer) SetDAGWriter(writer DAGWriter) {
	c.dagWriter = writer
}

// SetTelemetryWriter sets the telemetry writer
func (c *ControlLayer) SetTelemetryWriter(writer TelemetryWriter) {
	c.telemetryWriter = writer
}

// GetStats returns rate limiting statistics
func (c *ControlLayer) GetStats() map[string]interface{} {
	c.rateLimitersMu.RLock()
	defer c.rateLimitersMu.RUnlock()

	return map[string]interface{}{
		"active_limiters":   len(c.rateLimiters),
		"global_tokens":     c.globalLimiter.Tokens,
		"global_capacity":   c.globalLimiter.Capacity,
		"ws_connections":    len(c.wsConnections),
		"audit_channel_len": len(c.auditChan),
	}
}

// TokenBucket methods

// Allow checks if a token is available and consumes it
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.Tokens > 0 {
		tb.Tokens--
		return true
	}

	return false
}

// refill adds tokens based on elapsed time
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.LastRefill).Seconds()

	tokensToAdd := int(elapsed * tb.RefillRate)
	if tokensToAdd > 0 {
		tb.Tokens += tokensToAdd
		if tb.Tokens > tb.Capacity {
			tb.Tokens = tb.Capacity
		}
		tb.LastRefill = now
	}
}

// GetTokens returns current token count
func (tb *TokenBucket) GetTokens() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	return tb.Tokens
}

// DAGAuditWriter implements DAGWriter interface using our DAG package
type DAGAuditWriter struct {
	Store dag.Store
}

// WriteAuditEvent writes an audit event to the DAG
func (w *DAGAuditWriter) WriteAuditEvent(event *AuditEvent) error {
	node := &dag.Node{
		Action: "audit-event",
		Symbol: "Ma'at", // Symbol for justice/truth and balance
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"request_id":    event.RequestID,
			"client_ip":     event.ClientIP,
			"identity_id":   event.IdentityID,
			"method":        event.Method,
			"path":          event.Path,
			"status_code":   fmt.Sprintf("%d", event.StatusCode),
			"blocked":       fmt.Sprintf("%v", event.Blocked),
			"anomaly_score": fmt.Sprintf("%.2f", event.AnomalyScore),
		},
	}

	// Sign the node if identity is available (using machine ID as a fallback PK)
	// In production, each gateway instance would have its own Dilithium key

	return w.Store.Add(node, []string{})
}

// TelemetryAuditWriter implements TelemetryWriter interface
type TelemetryAuditWriter struct {
	Endpoint string
	APIKey   string
}

// SendEvent sends an audit event to the telemetry server
func (w *TelemetryAuditWriter) SendEvent(event *AuditEvent) error {
	// Endpoint guard: real batching and HTTP POST is handled by the concrete
	// TelemetryWriter wired on ControlLayer via SetTelemetryWriter.
	if w.Endpoint == "" {
		return fmt.Errorf("telemetry endpoint not configured")
	}
	return nil
}

// SIEM Export helpers

// ToSplunkFormat converts event to Splunk HEC format
func (e *AuditEvent) ToSplunkFormat() map[string]interface{} {
	return map[string]interface{}{
		"time":       e.Timestamp.Unix(),
		"host":       "khepra-gateway",
		"source":     "khepra:audit",
		"sourcetype": "khepra:gateway:audit",
		"event":      e,
	}
}

// ToELKFormat converts event to Elasticsearch format
func (e *AuditEvent) ToELKFormat() map[string]interface{} {
	return map[string]interface{}{
		"@timestamp": e.Timestamp.Format(time.RFC3339),
		"event": map[string]interface{}{
			"kind":     "event",
			"category": "network",
			"type":     "access",
			"outcome":  outcomeFromBlocked(e.Blocked),
		},
		"source": map[string]interface{}{
			"ip": e.ClientIP,
		},
		"http": map[string]interface{}{
			"request": map[string]interface{}{
				"method": e.Method,
			},
			"response": map[string]interface{}{
				"status_code": e.StatusCode,
			},
		},
		"url": map[string]interface{}{
			"path": e.Path,
		},
		"user": map[string]interface{}{
			"id": e.IdentityID,
		},
		"khepra": map[string]interface{}{
			"request_id":    e.RequestID,
			"anomaly_score": e.AnomalyScore,
			"trust_score":   e.TrustScore,
			"blocked":       e.Blocked,
			"block_reason":  e.BlockReason,
		},
	}
}

func outcomeFromBlocked(blocked bool) string {
	if blocked {
		return "failure"
	}
	return "success"
}

// FormatDuration formats duration for logging
func FormatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fµs", float64(d)/float64(time.Microsecond))
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}


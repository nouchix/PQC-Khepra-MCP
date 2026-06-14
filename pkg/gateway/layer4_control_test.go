package gateway

import (
	"testing"
	"time"
)

func TestControlLayer_RateLimiting(t *testing.T) {
	cfg := &RateLimitConfig{
		GlobalRequestsPerSecond: 1000,
		RequestsPerSecond:       5,
		RequestsPerMinute:       100,
		RequestsPerHour:         1000,
		BurstAllowance:          10,
		BurstWindow:             5 * time.Second,
		BackoffStrategy:         "exponential",
		MaxBackoffDuration:      5 * time.Minute,
	}

	logCfg := &LoggingConfig{
		LogToStdout: false,
		Level:       "info",
	}

	control, err := NewControlLayer(cfg, logCfg)
	if err != nil {
		t.Fatalf("Failed to create control layer: %v", err)
	}

	identityID := "rate-limit-test-user"

	// First few requests should be allowed
	for i := 0; i < 5; i++ {
		allowed, _ := control.CheckRateLimit(identityID)
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// After hitting per-second limit, should be blocked
	allowed, retryAfter := control.CheckRateLimit(identityID)
	if allowed {
		t.Error("Request should be blocked after hitting rate limit")
	}
	if retryAfter <= 0 {
		t.Error("Retry-After should be positive")
	}
}

func TestControlLayer_GlobalRateLimit(t *testing.T) {
	cfg := &RateLimitConfig{
		GlobalRequestsPerSecond: 10,
		RequestsPerSecond:       100, // High per-identity to not hit it
		RequestsPerMinute:       10000,
		RequestsPerHour:         100000,
		BurstAllowance:          100,
		BurstWindow:             5 * time.Second,
	}

	logCfg := &LoggingConfig{
		LogToStdout: false,
	}

	control, _ := NewControlLayer(cfg, logCfg)

	// Exhaust global limit with different identities
	for i := 0; i < 10; i++ {
		identityID := "global-test-" + string(rune('a'+i))
		allowed, _ := control.CheckRateLimit(identityID)
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// Next request should hit global limit
	allowed, _ := control.CheckRateLimit("global-test-overflow")
	if allowed {
		t.Error("Should hit global rate limit")
	}
}

func TestControlLayer_TrustScoreMultiplier(t *testing.T) {
	cfg := &RateLimitConfig{
		GlobalRequestsPerSecond: 10000,
		RequestsPerSecond:       10,
		RequestsPerMinute:       100,
		RequestsPerHour:         1000,
		BurstAllowance:          20,
		BurstWindow:             5 * time.Second,
		TrustScoreMultiplier:    true,
	}

	logCfg := &LoggingConfig{
		LogToStdout: false,
	}

	control, _ := NewControlLayer(cfg, logCfg)

	identityID := "trust-score-test"

	// Get the limiter first
	control.CheckRateLimit(identityID)

	// Update trust score to high value
	control.UpdateTrustScore(identityID, 1.0) // Max trust

	// With trust score multiplier, capacity should be increased
	// 10 * (1.0 + 1.0) = 20 requests per second
	control.rateLimitersMu.RLock()
	limiter := control.rateLimiters[identityID]
	control.rateLimitersMu.RUnlock()

	if limiter.PerSecond.Capacity != 20 {
		t.Errorf("Expected capacity 20 with trust multiplier, got %d", limiter.PerSecond.Capacity)
	}
}

func TestControlLayer_ExponentialBackoff(t *testing.T) {
	cfg := &RateLimitConfig{
		GlobalRequestsPerSecond: 10000,
		RequestsPerSecond:       2,
		RequestsPerMinute:       10000,
		RequestsPerHour:         100000,
		BurstAllowance:          2,
		BurstWindow:             time.Second,
		BackoffStrategy:         "exponential",
		MaxBackoffDuration:      10 * time.Second,
	}

	logCfg := &LoggingConfig{
		LogToStdout: false,
	}

	control, _ := NewControlLayer(cfg, logCfg)

	identityID := "backoff-test"

	// Exhaust rate limit
	for i := 0; i < 3; i++ {
		control.CheckRateLimit(identityID)
	}

	// Check backoff is applied
	control.rateLimitersMu.RLock()
	limiter := control.rateLimiters[identityID]
	control.rateLimitersMu.RUnlock()

	if limiter.BackoffCount == 0 {
		t.Error("Expected backoff count > 0")
	}

	// Backoff should be exponential
	if limiter.BackoffUntil.Before(time.Now()) {
		t.Error("Expected backoff time to be in the future")
	}
}

func TestTokenBucket_Basic(t *testing.T) {
	bucket := &TokenBucket{
		Capacity:   10,
		Tokens:     10,
		RefillRate: 1.0, // 1 token per second
		LastRefill: time.Now(),
	}

	// Should allow 10 requests
	for i := 0; i < 10; i++ {
		if !bucket.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 11th request should be blocked
	if bucket.Allow() {
		t.Error("11th request should be blocked")
	}

	// Wait for refill
	time.Sleep(1100 * time.Millisecond)

	// Should allow 1 more request after refill
	if !bucket.Allow() {
		t.Error("Should allow request after refill")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	bucket := &TokenBucket{
		Capacity:   100,
		Tokens:     0, // Start empty
		RefillRate: 10.0, // 10 tokens per second
		LastRefill: time.Now().Add(-1 * time.Second), // 1 second ago
	}

	// After 1 second with 10 tokens/sec, should have ~10 tokens
	tokens := bucket.GetTokens()
	if tokens < 9 || tokens > 11 {
		t.Errorf("Expected ~10 tokens after 1 second, got %d", tokens)
	}
}

func TestTokenBucket_CapacityLimit(t *testing.T) {
	bucket := &TokenBucket{
		Capacity:   10,
		Tokens:     10,
		RefillRate: 100.0, // Very high refill rate
		LastRefill: time.Now().Add(-10 * time.Second), // Long time ago
	}

	// Even with high refill over long time, should cap at capacity
	tokens := bucket.GetTokens()
	if tokens > 10 {
		t.Errorf("Tokens should be capped at capacity 10, got %d", tokens)
	}
}

func TestControlLayer_AuditLogging(t *testing.T) {
	cfg := &RateLimitConfig{
		GlobalRequestsPerSecond: 1000,
		RequestsPerSecond:       100,
		RequestsPerMinute:       1000,
		RequestsPerHour:         10000,
		BurstAllowance:          50,
		BurstWindow:             5 * time.Second,
	}

	logCfg := &LoggingConfig{
		LogToStdout: false,
		Level:       "debug",
	}

	control, _ := NewControlLayer(cfg, logCfg)

	// Create a request context
	ctx := &RequestContext{
		RequestID:    "test-request-123",
		StartTime:    time.Now(),
		ClientIP:     "192.168.1.100",
		Method:       "GET",
		Path:         "/api/users",
		StatusCode:   200,
		Blocked:      false,
		AnomalyScore: 0.1,
		Identity: &Identity{
			ID:           "test-user",
			Type:         "api_key",
			Organization: "test-org",
			TrustScore:   0.8,
		},
	}

	// Log should not panic
	control.LogRequest(ctx)

	// Test blocked request logging
	blockedCtx := &RequestContext{
		RequestID:   "blocked-request",
		StartTime:   time.Now(),
		ClientIP:    "10.0.0.1",
		Method:      "POST",
		Path:        "/api/admin",
		StatusCode:  403,
		Blocked:     true,
		BlockReason: "firewall: SQL injection detected",
	}

	control.LogRequest(blockedCtx)
}

func TestControlLayer_WebSocketRegistration(t *testing.T) {
	cfg := &RateLimitConfig{
		GlobalRequestsPerSecond: 1000,
		RequestsPerSecond:       100,
		RequestsPerMinute:       1000,
		RequestsPerHour:         10000,
	}

	logCfg := &LoggingConfig{
		WebSocketEnabled: true,
		WebSocketPath:    "/ws/audit",
	}

	control, _ := NewControlLayer(cfg, logCfg)

	// Register WebSocket
	connID := "ws-test-123"
	ch := control.RegisterWebSocket(connID)

	if ch == nil {
		t.Fatal("Expected channel from WebSocket registration")
	}

	// Verify stats
	stats := control.GetStats()
	if stats["ws_connections"].(int) != 1 {
		t.Errorf("Expected 1 WebSocket connection, got %d", stats["ws_connections"])
	}

	// Unregister
	control.UnregisterWebSocket(connID)

	stats = control.GetStats()
	if stats["ws_connections"].(int) != 0 {
		t.Errorf("Expected 0 WebSocket connections after unregister, got %d", stats["ws_connections"])
	}
}

func TestControlLayer_GetStats(t *testing.T) {
	cfg := &RateLimitConfig{
		GlobalRequestsPerSecond: 1000,
		RequestsPerSecond:       100,
		RequestsPerMinute:       1000,
		RequestsPerHour:         10000,
		BurstAllowance:          50,
		BurstWindow:             5 * time.Second,
	}

	logCfg := &LoggingConfig{
		LogToStdout: false,
	}

	control, _ := NewControlLayer(cfg, logCfg)

	// Create some rate limiters
	for i := 0; i < 5; i++ {
		control.CheckRateLimit("stats-test-" + string(rune('a'+i)))
	}

	stats := control.GetStats()

	if stats["active_limiters"].(int) != 5 {
		t.Errorf("Expected 5 active limiters, got %d", stats["active_limiters"])
	}

	if stats["global_capacity"].(int) != 1000 {
		t.Errorf("Expected global capacity 1000, got %d", stats["global_capacity"])
	}
}

func TestAuditEvent_SplunkFormat(t *testing.T) {
	event := &AuditEvent{
		RequestID:    "test-123",
		Timestamp:    time.Now(),
		ClientIP:     "192.168.1.1",
		Method:       "GET",
		Path:         "/api/test",
		StatusCode:   200,
		Blocked:      false,
		AnomalyScore: 0.1,
		IdentityID:   "user-abc",
	}

	splunk := event.ToSplunkFormat()

	if splunk["source"] != "khepra:audit" {
		t.Errorf("Expected source 'khepra:audit', got '%v'", splunk["source"])
	}

	if splunk["sourcetype"] != "khepra:gateway:audit" {
		t.Errorf("Expected sourcetype 'khepra:gateway:audit', got '%v'", splunk["sourcetype"])
	}

	if splunk["event"] == nil {
		t.Error("Expected event data")
	}
}

func TestAuditEvent_ELKFormat(t *testing.T) {
	event := &AuditEvent{
		RequestID:    "test-123",
		Timestamp:    time.Now(),
		ClientIP:     "192.168.1.1",
		Method:       "POST",
		Path:         "/api/users",
		StatusCode:   403,
		Blocked:      true,
		BlockReason:  "rate_limit",
		AnomalyScore: 0.8,
		IdentityID:   "user-xyz",
	}

	elk := event.ToELKFormat()

	// Verify ECS-compliant structure
	eventData := elk["event"].(map[string]interface{})
	if eventData["outcome"] != "failure" {
		t.Errorf("Expected outcome 'failure' for blocked request, got '%v'", eventData["outcome"])
	}

	httpData := elk["http"].(map[string]interface{})
	reqData := httpData["request"].(map[string]interface{})
	if reqData["method"] != "POST" {
		t.Errorf("Expected method 'POST', got '%v'", reqData["method"])
	}

	khepraData := elk["khepra"].(map[string]interface{})
	if khepraData["blocked"] != true {
		t.Error("Expected blocked=true in khepra data")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		contains string
	}{
		{500 * time.Microsecond, "µs"},
		{5 * time.Millisecond, "ms"},
		{2 * time.Second, "s"},
	}

	for _, tt := range tests {
		result := FormatDuration(tt.duration)
		if len(result) == 0 {
			t.Errorf("FormatDuration(%v) returned empty string", tt.duration)
		}
	}
}

func BenchmarkRateLimitCheck(b *testing.B) {
	cfg := &RateLimitConfig{
		GlobalRequestsPerSecond: 100000,
		RequestsPerSecond:       1000,
		RequestsPerMinute:       10000,
		RequestsPerHour:         100000,
		BurstAllowance:          100,
		BurstWindow:             5 * time.Second,
	}

	logCfg := &LoggingConfig{
		LogToStdout: false,
	}

	control, _ := NewControlLayer(cfg, logCfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		control.CheckRateLimit("bench-user")
	}
}

func BenchmarkTokenBucketAllow(b *testing.B) {
	bucket := &TokenBucket{
		Capacity:   1000000,
		Tokens:     1000000,
		RefillRate: 1000000,
		LastRefill: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bucket.Allow()
	}
}

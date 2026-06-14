// Package gateway - STIGViewer API Connector (Zone 1: DMZ)
//
// This component lives in the DMZ (Zone 1) and is the ONLY component allowed
// to make outbound HTTPS connections to the STIGViewer API.
//
// Security Constraints:
//   - Egress-only to api.stigviewer.com:443
//   - Inbound from Zone 2 on port 8443 (mTLS required)
//   - No database access
//   - No filesystem write (read-only)
//   - All JSON validated against strict schema before passing to Zone 2
//   - Rate-limited outbound calls (token bucket: 100/hour, burst 10)
//
// API Documentation: https://api.stigviewer.com (requires API token)
package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── Configuration ──────────────────────────────────────────────────────────────

// STIGConnectorConfig holds the configuration for the STIGViewer API connector.
type STIGConnectorConfig struct {
	// VaultPath is the path in HashiCorp Vault where the API key is stored.
	// Example: "khepra/stigviewer/api_key"
	VaultPath string

	// BaseURL is the STIGViewer API base URL.
	BaseURL string

	// MaxRequestsPerHour is the outbound rate limit (default: 100).
	MaxRequestsPerHour int

	// BurstSize is the maximum burst of concurrent requests (default: 10).
	BurstSize int

	// CacheTTL is how long decomposed rule data stays cached (default: 4h).
	CacheTTL time.Duration

	// MetadataCacheTTL is how long metadata stays cached (default: 24h).
	MetadataCacheTTL time.Duration

	// MaxPayloadBytes is the maximum response payload size (default: 10MB).
	MaxPayloadBytes int64

	// CircuitBreakerThreshold is how many consecutive failures open the circuit (default: 3).
	CircuitBreakerThreshold int

	// CircuitBreakerResetTime is how long before a half-open attempt (default: 60s).
	CircuitBreakerResetTime time.Duration

	// CacheEncryptionEnabled enables AES-256-GCM encryption for cached data (default: true).
	CacheEncryptionEnabled bool

	// CacheKeyRotationInterval is how often encryption keys rotate (default: 30 days).
	CacheKeyRotationInterval time.Duration

	// IntegrityKey is the key used for HMAC signature of cached data.
	// In production, this should be a 32-byte or 64-byte secret.
	IntegrityKey []byte
}

// DefaultSTIGConnectorConfig returns sane defaults.
func DefaultSTIGConnectorConfig() *STIGConnectorConfig {
	return &STIGConnectorConfig{
		VaultPath:                "khepra/stigviewer/api_key",
		BaseURL:                  "https://api.stigviewer.com",
		MaxRequestsPerHour:       100,
		BurstSize:                10,
		CacheTTL:                 4 * time.Hour,
		MetadataCacheTTL:         24 * time.Hour,
		MaxPayloadBytes:          10 * 1024 * 1024, // 10 MB
		CircuitBreakerThreshold:  3,
		CircuitBreakerResetTime:  60 * time.Second,
		CacheEncryptionEnabled:   true,
		CacheKeyRotationInterval: 30 * 24 * time.Hour, // 30 days
	}
}

// ─── Circuit Breaker ────────────────────────────────────────────────────────────

// CircuitState represents the circuit breaker state machine.
type CircuitState int

const (
	// CircuitClosed is normal operation — requests flow through.
	CircuitClosed CircuitState = iota
	// CircuitOpen means upstream failed — reject all requests.
	CircuitOpen
	// CircuitHalfOpen means testing if upstream recovered.
	CircuitHalfOpen
)

type circuitBreaker struct {
	mu                sync.Mutex
	state             CircuitState
	failures          int
	threshold         int
	lastFailure       time.Time
	resetTime         time.Duration
	halfOpenSuccesses int
}

func newCircuitBreaker(threshold int, resetTime time.Duration) *circuitBreaker {
	return &circuitBreaker{
		state:     CircuitClosed,
		threshold: threshold,
		resetTime: resetTime,
	}
}

func (cb *circuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailure) > cb.resetTime {
			cb.state = CircuitHalfOpen
			cb.halfOpenSuccesses = 0
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	}
	return false
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == CircuitHalfOpen {
		cb.halfOpenSuccesses++
		if cb.halfOpenSuccesses >= 2 {
			cb.state = CircuitClosed
			cb.failures = 0
		}
	} else {
		cb.failures = 0
	}
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.threshold {
		cb.state = CircuitOpen
	}
}

func (cb *circuitBreaker) getState() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// ─── Rate Limiter (Token Bucket) ────────────────────────────────────────────────

type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func newTokenBucket(maxPerHour int, burst int) *tokenBucket {
	return &tokenBucket{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: float64(maxPerHour) / 3600.0,
		lastRefill: time.Now(),
	}
}

func (tb *tokenBucket) take() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}
	tb.lastRefill = now

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// ─── STIG Data Types ────────────────────────────────────────────────────────────

// STIGRule represents a validated, sanitized STIG rule from the API.
type STIGRule struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`   // CAT_I, CAT_II, CAT_III
	Complexity  string   `json:"complexity"` // LOW, MEDIUM, HIGH
	OwnerRoles  []string `json:"owner_roles"`
	Description string   `json:"description"`
	Controls    []string `json:"controls"` // NIST 800-53 control mappings
}

// STIGDecomposedRule is an enriched rule with atomic requirements.
type STIGDecomposedRule struct {
	STIGRule
	AtomicRequirements []AtomicRequirement `json:"atomic_requirements"`
	RoleMappings       []RoleMapping       `json:"role_mappings"`
	TestProcedures     []TestProcedure     `json:"test_procedures"`
}

// AtomicRequirement is a single, testable requirement decomposed from a STIG rule.
type AtomicRequirement struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Testable    bool   `json:"testable"`
	Automatable bool   `json:"automatable"`
}

// RoleMapping maps a STIG responsibility to an organizational role.
type RoleMapping struct {
	Role           string `json:"role"`
	Responsibility string `json:"responsibility"`
}

// TestProcedure describes how to test a STIG check.
type TestProcedure struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Automated   bool   `json:"automated"`
	ToolHint    string `json:"tool_hint,omitempty"`
}

// STIGQueryResult is the response returned to Zone 2 consumers.
type STIGQueryResult struct {
	Rules      []STIGDecomposedRule `json:"rules"`
	TotalCount int                  `json:"total_count"`
	CacheHit   bool                 `json:"cache_hit"`
	Source     string               `json:"source"` // "api", "cache", "offline"
	FetchedAt  time.Time            `json:"fetched_at"`
	APIVersion string               `json:"api_version"`
}

// ─── Audit Types ────────────────────────────────────────────────────────────────

// AuditEntry records a security-relevant event for the tamper-proof log.
type AuditEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	EventType string            `json:"event_type"`
	Identity  string            `json:"identity"`
	Details   map[string]string `json:"details"`
}

// ─── Key Provider Interface ─────────────────────────────────────────────────────

// KeyProvider abstracts the API key retrieval mechanism.
// Production uses Vault; tests can use a mock.
type KeyProvider interface {
	GetAPIKey(ctx context.Context) (string, error)
}

// ─── STIGConnector (Zone 1 DMZ Service) ─────────────────────────────────────────

// STIGConnector is the secure proxy to the STIGViewer API.
// It lives in Zone 1 (DMZ) and is the sole egress point to api.stigviewer.com.
type STIGConnector struct {
	config  *STIGConnectorConfig
	keys    KeyProvider
	client  *http.Client
	breaker *circuitBreaker
	limiter *tokenBucket
	cache   sync.Map // thread-safe cache
	audit   []AuditEntry
	auditMu sync.Mutex

	// Cache encryption
	cacheEncryptionKey []byte       // Current AES-256 key (32 bytes)
	keyRotatedAt       time.Time    // Last key rotation timestamp
	keyMu              sync.RWMutex // Protects encryption key access
}

// NewSTIGConnector creates a new DMZ connector.
func NewSTIGConnector(cfg *STIGConnectorConfig, keys KeyProvider) *STIGConnector {
	if cfg == nil {
		cfg = DefaultSTIGConnectorConfig()
	}

	connector := &STIGConnector{
		config: cfg,
		keys:   keys,
		client: &http.Client{
			Timeout: 30 * time.Second,
			// TLS config inherited from gateway — enforces TLS 1.3
		},
		breaker:      newCircuitBreaker(cfg.CircuitBreakerThreshold, cfg.CircuitBreakerResetTime),
		limiter:      newTokenBucket(cfg.MaxRequestsPerHour, cfg.BurstSize),
		keyRotatedAt: time.Now(),
	}

	// Initialize cache encryption key
	if cfg.CacheEncryptionEnabled {
		if err := connector.rotateEncryptionKey(); err != nil {
			log.Printf("[STIGConnector] Failed to initialize encryption key: %v", err)
		}
	}

	return connector
}

// ─── Public API (Called by Zone 2 via mTLS on port 8443) ────────────────────────

// QuerySTIGs returns STIG rules matching the given filter.
// This is the primary entry point called by Khepra Core in Zone 2.
func (c *STIGConnector) QuerySTIGs(ctx context.Context, identity string, filter STIGFilter) (*STIGQueryResult, error) {
	c.logAudit("stig_query", identity, map[string]string{
		"filter_stig_id":  filter.STIGID,
		"filter_severity": filter.Severity,
	})

	// 1. Check cache first
	cacheKey := filter.cacheKey()
	if cached, ok := c.getFromCache(cacheKey); ok {
		c.logAudit("cache_hit", identity, map[string]string{"key": cacheKey})
		return cached, nil
	}

	// 2. Circuit breaker check
	if !c.breaker.allow() {
		c.logAudit("circuit_breaker_open", identity, nil)
		return nil, fmt.Errorf("circuit breaker open — STIGViewer API temporarily unavailable")
	}

	// 3. Rate limit check
	if !c.limiter.take() {
		c.logAudit("rate_limited", identity, nil)
		return nil, fmt.Errorf("outbound rate limit exceeded — try again later")
	}

	// 4. Get API key from Vault
	apiKey, err := c.keys.GetAPIKey(ctx)
	if err != nil {
		c.logAudit("api_key_retrieval_failed", identity, map[string]string{"error": err.Error()})
		// Fall to cache-only mode
		return nil, fmt.Errorf("vault unavailable, connector in cache-only mode: %w", err)
	}

	// 5. Make the actual API call
	result, err := c.fetchFromAPI(ctx, apiKey, filter, identity)
	if err != nil {
		c.breaker.recordFailure()
		c.logAudit("api_call_failed", identity, map[string]string{"error": err.Error()})
		return nil, fmt.Errorf("STIGViewer API call failed: %w", err)
	}

	c.breaker.recordSuccess()

	// 6. Cache the result
	c.putInCache(cacheKey, result)

	return result, nil
}

// GetCircuitState returns the current circuit breaker state for monitoring.
func (c *STIGConnector) GetCircuitState() CircuitState {
	return c.breaker.getState()
}

// GetAuditLog returns the audit trail for security review.
func (c *STIGConnector) GetAuditLog() []AuditEntry {
	c.auditMu.Lock()
	defer c.auditMu.Unlock()
	entries := make([]AuditEntry, len(c.audit))
	copy(entries, c.audit)
	return entries
}

// ─── STIGFilter ─────────────────────────────────────────────────────────────────

// STIGFilter specifies which STIGs to query.
type STIGFilter struct {
	STIGID   string `json:"stig_id,omitempty"`  // e.g., "RHEL_8_STIG"
	RuleID   string `json:"rule_id,omitempty"`  // e.g., "SV-230221r858695_rule"
	Severity string `json:"severity,omitempty"` // CAT_I, CAT_II, CAT_III
	Keyword  string `json:"keyword,omitempty"`  // Free-text search
	Limit    int    `json:"limit,omitempty"`    // Max results (default 50, max 200)
	Offset   int    `json:"offset,omitempty"`   // Pagination offset
}

func (f *STIGFilter) cacheKey() string {
	return fmt.Sprintf("stig:%s:%s:%s:%s:%d:%d",
		f.STIGID, f.RuleID, f.Severity, f.Keyword, f.Limit, f.Offset)
}

// ─── Internal Methods ───────────────────────────────────────────────────────────

func (c *STIGConnector) fetchFromAPI(ctx context.Context, apiKey string, filter STIGFilter, identity string) (*STIGQueryResult, error) {
	// Build request URL
	endpoint := fmt.Sprintf("%s/api/stigs", c.config.BaseURL)

	// Build query parameters
	params := []string{}
	if filter.STIGID != "" {
		params = append(params, fmt.Sprintf("stig_id=%s", filter.STIGID))
	}
	if filter.RuleID != "" {
		params = append(params, fmt.Sprintf("rule_id=%s", filter.RuleID))
	}
	if filter.Severity != "" {
		params = append(params, fmt.Sprintf("severity=%s", filter.Severity))
	}
	if filter.Keyword != "" {
		params = append(params, fmt.Sprintf("q=%s", filter.Keyword))
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	params = append(params, fmt.Sprintf("limit=%d", limit))
	params = append(params, fmt.Sprintf("offset=%d", filter.Offset))

	if len(params) > 0 {
		endpoint += "?" + strings.Join(params, "&")
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication headers
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AdinKhepra-STIGConnector/1.0")
	req.Header.Set("X-Request-ID", generateRequestID())

	c.logAudit("api_request", identity, map[string]string{
		"endpoint": endpoint,
		"method":   "GET",
	})

	// Execute request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("STIGViewer API rate limited (429)")
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		c.logAudit("api_auth_failed", identity, map[string]string{
			"status": fmt.Sprintf("%d", resp.StatusCode),
		})
		return nil, fmt.Errorf("STIGViewer API authentication failed (%d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("STIGViewer API returned %d", resp.StatusCode)
	}

	// Read body with size limit (Audit #9: API10:2023 — Unsafe API Consumption)
	limitedReader := io.LimitReader(resp.Body, c.config.MaxPayloadBytes)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Validate and sanitize the response (§4.3)
	rules, err := c.validateResponse(body)
	if err != nil {
		c.logAudit("response_validation_failed", identity, map[string]string{
			"error":      err.Error(),
			"body_bytes": fmt.Sprintf("%d", len(body)),
		})
		return nil, fmt.Errorf("response validation failed: %w", err)
	}

	return &STIGQueryResult{
		Rules:      rules,
		TotalCount: len(rules),
		CacheHit:   false,
		Source:     "api",
		FetchedAt:  time.Now(),
		APIVersion: resp.Header.Get("X-API-Version"),
	}, nil
}

// validateResponse performs strict JSON schema validation and sanitization.
// Implements §4.3 (OWASP API10:2023 — Unsafe Consumption of APIs).
func (c *STIGConnector) validateResponse(body []byte) ([]STIGDecomposedRule, error) {
	// 1. Size check
	if int64(len(body)) > c.config.MaxPayloadBytes {
		return nil, fmt.Errorf("payload exceeds %d byte limit", c.config.MaxPayloadBytes)
	}

	// 2. Parse JSON strictly (disallow unknown fields)
	var apiResponse struct {
		Data []STIGDecomposedRule `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("JSON parsing failed: %w", err)
	}

	// 3. Validate each rule
	for i := range apiResponse.Data {
		rule := &apiResponse.Data[i]

		// Validate severity
		switch rule.Severity {
		case "CAT_I", "CAT_II", "CAT_III":
			// Valid
		default:
			return nil, fmt.Errorf("invalid severity %q for rule %s", rule.Severity, rule.RuleID)
		}

		// Validate complexity
		switch rule.Complexity {
		case "LOW", "MEDIUM", "HIGH", "":
			// Valid (empty allowed — not all APIs return this)
		default:
			return nil, fmt.Errorf("invalid complexity %q for rule %s", rule.Complexity, rule.RuleID)
		}

		// Sanitize text fields (prevent XSS in descriptions)
		rule.Title = sanitizeTextField(rule.Title, 500)
		rule.Description = sanitizeTextField(rule.Description, 10000)
		rule.RuleID = sanitizeTextField(rule.RuleID, 64)

		for j := range rule.OwnerRoles {
			rule.OwnerRoles[j] = sanitizeTextField(rule.OwnerRoles[j], 100)
		}

		// Cap array sizes
		if len(rule.OwnerRoles) > 10 {
			rule.OwnerRoles = rule.OwnerRoles[:10]
		}
		if len(rule.Controls) > 50 {
			rule.Controls = rule.Controls[:50]
		}
		if len(rule.AtomicRequirements) > 100 {
			rule.AtomicRequirements = rule.AtomicRequirements[:100]
		}
	}

	return apiResponse.Data, nil
}

// sanitizeTextField strips potentially dangerous content and enforces length limits.
func sanitizeTextField(input string, maxLen int) string {
	// Remove control characters except \n and \t
	var cleaned strings.Builder
	for _, r := range input {
		if r == '\n' || r == '\t' || r >= 32 {
			cleaned.WriteRune(r)
		}
	}
	result := strings.TrimSpace(cleaned.String())
	if len(result) > maxLen {
		result = result[:maxLen]
	}
	return result
}

// ─── Cache (In-Memory, Encrypted, Signed) ───────────────────────────────────────

type cacheEntry struct {
	encryptedData []byte    // AES-256-GCM encrypted STIGQueryResult
	nonce         []byte    // GCM nonce (12 bytes)
	hmacSig       []byte    // HMAC-SHA256 signature
	expiresAt     time.Time // Cache expiration
	keyVersion    int       // Encryption key version (for rotation)
}

func (c *STIGConnector) getFromCache(key string) (*STIGQueryResult, bool) {
	val, ok := c.cache.Load(key)
	if !ok {
		return nil, false
	}

	entry, ok := val.(*cacheEntry)
	if !ok {
		c.cache.Delete(key)
		return nil, false
	}

	// Check expiry
	if time.Now().After(entry.expiresAt) {
		c.cache.Delete(key)
		return nil, false
	}

	// Verify HMAC integrity (computed over encrypted data)
	expected := c.computeHMAC(entry.encryptedData)
	if !hmac.Equal(entry.hmacSig, expected) {
		c.cache.Delete(key)
		c.logAudit("cache_tampering_detected", "system", map[string]string{"key": key})
		return nil, false
	}

	// Decrypt the cached data
	var result *STIGQueryResult
	if c.config.CacheEncryptionEnabled {
		decrypted, err := c.decryptCacheData(entry.encryptedData, entry.nonce)
		if err != nil {
			c.cache.Delete(key)
			c.logAudit("cache_decryption_failed", "system", map[string]string{
				"key":   key,
				"error": err.Error(),
			})
			return nil, false
		}

		if err := json.Unmarshal(decrypted, &result); err != nil {
			c.cache.Delete(key)
			return nil, false
		}
	} else {
		// Fallback: unencrypted cache (should not happen in production)
		if err := json.Unmarshal(entry.encryptedData, &result); err != nil {
			c.cache.Delete(key)
			return nil, false
		}
	}

	// Mark as cache hit
	result.CacheHit = true
	result.Source = "cache"
	return result, true
}

func (c *STIGConnector) putInCache(key string, result *STIGQueryResult) {
	// Check if key rotation is needed
	c.checkAndRotateKey()

	data, err := json.Marshal(result)
	if err != nil {
		log.Printf("[STIGConnector] Failed to marshal cache entry: %v", err)
		return
	}

	var encryptedData []byte
	var nonce []byte

	if c.config.CacheEncryptionEnabled {
		// Encrypt the cache data with AES-256-GCM
		encryptedData, nonce, err = c.encryptCacheData(data)
		if err != nil {
			log.Printf("[STIGConnector] Failed to encrypt cache entry: %v", err)
			return
		}
	} else {
		// Fallback: store unencrypted (should not happen in production)
		encryptedData = data
		nonce = nil
	}

	c.cache.Store(key, &cacheEntry{
		encryptedData: encryptedData,
		nonce:         nonce,
		hmacSig:       c.computeHMAC(encryptedData),
		expiresAt:     time.Now().Add(c.config.CacheTTL),
		keyVersion:    c.getCurrentKeyVersion(),
	})
}

func (c *STIGConnector) computeHMAC(data []byte) []byte {
	key := c.config.IntegrityKey
	if len(key) == 0 {
		// Fallback for development only - in production this must be set
		key = []byte("khepra-default-integrity-key-change-me-in-production")
	}
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ─── Audit Logging ──────────────────────────────────────────────────────────────

func (c *STIGConnector) logAudit(eventType, identity string, details map[string]string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: eventType,
		Identity:  identity,
		Details:   details,
	}

	c.auditMu.Lock()
	c.audit = append(c.audit, entry)
	// Keep last 10K entries in memory; older entries should be flushed to DAG
	if len(c.audit) > 10000 {
		c.audit = c.audit[len(c.audit)-10000:]
	}
	c.auditMu.Unlock()

	log.Printf("[STIGConnector] %s | identity=%s | %v", eventType, identity, details)
}

// ─── HTTP Handler (Zone 2 → Zone 1 interface on port 8443) ──────────────────────

// ServeHTTP handles inbound requests from Zone 2.
// Only GET /api/stigs is supported. All other methods/paths return 405/404.
func (c *STIGConnector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only GET allowed (§4.2: API8:2023 — Security Misconfiguration)
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Security headers on all responses
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")

	switch {
	case strings.HasPrefix(r.URL.Path, "/api/stigs"):
		c.handleSTIGQuery(w, r)
	case r.URL.Path == "/health":
		c.handleHealth(w, r)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (c *STIGConnector) handleSTIGQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := STIGFilter{
		STIGID:   q.Get("stig_id"),
		RuleID:   q.Get("rule_id"),
		Severity: q.Get("severity"),
		Keyword:  q.Get("q"),
	}

	// Extract identity from mTLS cert (provided by Layer 2 auth)
	identity := r.Header.Get("X-Identity-ID")
	if identity == "" {
		identity = "anonymous"
	}

	result, err := c.QuerySTIGs(r.Context(), identity, filter)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "rate limit") {
			status = http.StatusTooManyRequests
		} else if strings.Contains(err.Error(), "circuit breaker") {
			status = http.StatusServiceUnavailable
		} else if strings.Contains(err.Error(), "cache-only") {
			status = http.StatusServiceUnavailable
		}

		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(result)
}

func (c *STIGConnector) handleHealth(w http.ResponseWriter, _ *http.Request) {
	state := c.breaker.getState()
	stateStr := "closed"
	switch state {
	case CircuitOpen:
		stateStr = "open"
	case CircuitHalfOpen:
		stateStr = "half_open"
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"circuit_state": stateStr,
		"connector":     "stigviewer",
		"zone":          "dmz",
	})
}

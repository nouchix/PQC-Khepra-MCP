// Package gateway implements the Khepra Secure Gateway - the DEMARC point
// between customer environments and the Khepra/SouHimBou.AI ecosystem.
//
// "The Scarab Guards the Threshold"
package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	HeaderContentType     = "Content-Type"
	HeaderXForwardedFor   = "X-Forwarded-For"
	HeaderXRealIP         = "X-Real-IP"
	HeaderWWWAuthenticate = "WWW-Authenticate"
	HeaderRetryAfter      = "Retry-After"
	MIMEApplicationJSON   = "application/json"
)

// Gateway is the main secure gateway server implementing zero-trust architecture
type Gateway struct {
	config *Config

	// Security Layers
	firewall *FirewallLayer
	auth     *AuthLayer
	anomaly  *AnomalyLayer
	control  *ControlLayer

	// Internal state
	httpServer *http.Server
	tlsConfig  *tls.Config
	mu         sync.RWMutex
	running    bool

	// Metrics
	metrics *GatewayMetrics
}

// GatewayMetrics tracks gateway performance and security metrics
type GatewayMetrics struct {
	RequestsTotal     int64
	RequestsBlocked   int64
	RequestsAllowed   int64
	AuthFailures      int64
	AnomaliesDetected int64
	RateLimitHits     int64
	AverageLatencyMs  float64
	LastUpdated       time.Time
	mu                sync.RWMutex
}

// New creates a new Khepra Secure Gateway with the given configuration
func New(cfg *Config) (*Gateway, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	g := &Gateway{
		config:  cfg,
		metrics: &GatewayMetrics{},
	}

	// Initialize Layer 1: Firewall
	firewall, err := NewFirewallLayer(&cfg.Firewall)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize firewall layer: %w", err)
	}
	g.firewall = firewall

	// Initialize Layer 2: Authentication
	auth, err := NewAuthLayer(&cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth layer: %w", err)
	}
	g.auth = auth

	// Initialize Layer 3: Anomaly Detection
	anomaly, err := NewAnomalyLayer(&cfg.Anomaly)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize anomaly layer: %w", err)
	}
	g.anomaly = anomaly

	// Initialize Layer 4: Rate Limiting & Control
	control, err := NewControlLayer(&cfg.RateLimit, &cfg.Logging)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize control layer: %w", err)
	}
	g.control = control

	// Configure TLS
	if err := g.configureTLS(); err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}

	return g, nil
}

// configureTLS sets up TLS with secure defaults
func (g *Gateway) configureTLS() error {
	minVersion := tls.VersionTLS12
	if g.config.Firewall.MinTLSVersion == "1.3" {
		minVersion = tls.VersionTLS13
	}

	g.tlsConfig = &tls.Config{
		MinVersion: uint16(minVersion),
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites (automatically selected when TLS 1.3)
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			// TLS 1.2 cipher suites (AEAD only)
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
		},
	}

	// Configure mTLS if required
	if g.config.Auth.RequireMTLS && g.config.Auth.ClientCAFile != "" {
		// Client CA will be loaded by the auth layer
		g.tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return nil
}

// Handler returns the main HTTP handler with all security layers applied
func (g *Gateway) Handler(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		reqCtx := g.initRequestContext(r, startTime)
		r = r.WithContext(context.WithValue(r.Context(), requestContextKey, reqCtx))

		if g.runSecurityChecks(w, r, reqCtx) {
			return
		}

		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		upstream.ServeHTTP(wrapped, r)

		g.finalizeRequest(reqCtx, wrapped.statusCode, startTime)
	})
}

func (g *Gateway) initRequestContext(r *http.Request, start time.Time) *RequestContext {
	g.metrics.mu.Lock()
	g.metrics.RequestsTotal++
	g.metrics.mu.Unlock()

	return &RequestContext{
		RequestID:   generateRequestID(),
		StartTime:   start,
		ClientIP:    getClientIP(r),
		Method:      r.Method,
		Path:        r.URL.Path,
		UserAgent:   r.UserAgent(),
		ContentType: r.Header.Get(HeaderContentType),
	}
}

func (g *Gateway) runSecurityChecks(w http.ResponseWriter, r *http.Request, reqCtx *RequestContext) bool {
	if blocked, reason := g.firewall.Check(r); blocked {
		g.handleBlocked(w, r, reqCtx, "firewall", reason)
		return true
	}

	identity, err := g.auth.Authenticate(r)
	if err != nil {
		g.handleAuthFailure(w, r, reqCtx, err)
		return true
	}
	reqCtx.Identity = identity

	if g.config.Anomaly.Enabled && g.checkAnomaly(w, r, reqCtx, identity) {
		return true
	}

	if allowed, retryAfter := g.control.CheckRateLimit(identity.ID); !allowed {
		g.handleRateLimited(w, r, reqCtx, retryAfter)
		return true
	}

	return false
}

func (g *Gateway) checkAnomaly(w http.ResponseWriter, r *http.Request, reqCtx *RequestContext, id *Identity) bool {
	score, err := g.anomaly.Analyze(r, id)
	if err != nil {
		if g.config.FailSecure.MLServiceFallback == "deny" {
			g.handleBlocked(w, r, reqCtx, "anomaly", "ML service unavailable")
			return true
		}
		return false
	}

	reqCtx.AnomalyScore = score
	if score >= g.config.Anomaly.BlockThreshold {
		g.handleBlocked(w, r, reqCtx, "anomaly", fmt.Sprintf("anomaly score %.2f", score))
		return true
	}
	return false
}

func (g *Gateway) finalizeRequest(reqCtx *RequestContext, status int, start time.Time) {
	reqCtx.StatusCode = status
	reqCtx.Duration = time.Since(start)

	g.metrics.mu.Lock()
	g.metrics.RequestsAllowed++
	g.metrics.mu.Unlock()

	g.control.LogRequest(reqCtx)
}

// handleBlocked handles blocked requests
func (g *Gateway) handleBlocked(w http.ResponseWriter, _ *http.Request, ctx *RequestContext, layer, reason string) {
	ctx.Blocked = true
	ctx.BlockReason = fmt.Sprintf("%s: %s", layer, reason)
	ctx.StatusCode = http.StatusForbidden

	g.metrics.mu.Lock()
	g.metrics.RequestsBlocked++
	g.metrics.mu.Unlock()

	// Log the blocked request
	g.control.LogRequest(ctx)

	// Return minimal error response (don't leak info)
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"request_denied","code":"KHEPRA_BLOCK"}`))
}

// handleAuthFailure handles authentication failures
func (g *Gateway) handleAuthFailure(w http.ResponseWriter, _ *http.Request, ctx *RequestContext, err error) {
	ctx.Blocked = true
	ctx.BlockReason = fmt.Sprintf("auth: %v", err)
	ctx.StatusCode = http.StatusUnauthorized

	g.metrics.mu.Lock()
	g.metrics.AuthFailures++
	g.metrics.RequestsBlocked++
	g.metrics.mu.Unlock()

	g.control.LogRequest(ctx)

	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	w.Header().Set(HeaderWWWAuthenticate, `Khepra realm="secure-gateway"`)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"authentication_required","code":"KHEPRA_AUTH"}`))
}

// handleRateLimited handles rate limited requests
func (g *Gateway) handleRateLimited(w http.ResponseWriter, _ *http.Request, ctx *RequestContext, retryAfter time.Duration) {
	ctx.Blocked = true
	ctx.BlockReason = "rate_limit_exceeded"
	ctx.StatusCode = http.StatusTooManyRequests

	g.metrics.mu.Lock()
	g.metrics.RateLimitHits++
	g.metrics.RequestsBlocked++
	g.metrics.mu.Unlock()

	g.control.LogRequest(ctx)

	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	w.Header().Set(HeaderRetryAfter, fmt.Sprintf("%d", int(retryAfter.Seconds())))
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte(`{"error":"rate_limit_exceeded","code":"KHEPRA_RATE"}`))
}

// Start starts the gateway server
func (g *Gateway) Start() error {
	g.mu.Lock()
	if g.running {
		g.mu.Unlock()
		return fmt.Errorf("gateway already running")
	}
	g.running = true
	g.mu.Unlock()

	// Create HTTP server
	g.httpServer = &http.Server{
		Addr:         g.config.ListenAddr,
		ReadTimeout:  g.config.ReadTimeout,
		WriteTimeout: g.config.WriteTimeout,
		TLSConfig:    g.tlsConfig,
	}

	log.Printf("[GATEWAY] Khepra Secure Gateway starting on %s", g.config.ListenAddr)
	log.Printf("[GATEWAY] Security Layers: Firewall[ON] Auth[ON] Anomaly[%v] RateLimit[ON]",
		g.config.Anomaly.Enabled)

	// Start with TLS if configured
	if g.config.TLSCertFile != "" && g.config.TLSKeyFile != "" {
		return g.httpServer.ListenAndServeTLS(g.config.TLSCertFile, g.config.TLSKeyFile)
	}

	// Fallback to HTTP (development only!)
	log.Printf("[GATEWAY] WARNING: Running without TLS - development mode only!")
	return g.httpServer.ListenAndServe()
}

// Stop gracefully stops the gateway
func (g *Gateway) Stop(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.running {
		return nil
	}

	g.running = false
	log.Printf("[GATEWAY] Shutting down Khepra Secure Gateway...")

	return g.httpServer.Shutdown(ctx)
}

// GetMetrics returns current gateway metrics
func (g *Gateway) GetMetrics() GatewayMetrics {
	g.metrics.mu.RLock()
	defer g.metrics.mu.RUnlock()

	return GatewayMetrics{
		RequestsTotal:     g.metrics.RequestsTotal,
		RequestsBlocked:   g.metrics.RequestsBlocked,
		RequestsAllowed:   g.metrics.RequestsAllowed,
		AuthFailures:      g.metrics.AuthFailures,
		AnomaliesDetected: g.metrics.AnomaliesDetected,
		RateLimitHits:     g.metrics.RateLimitHits,
		AverageLatencyMs:  g.metrics.AverageLatencyMs,
		LastUpdated:       time.Now(),
	}
}

// RequestContext holds context for a single request through the gateway
type RequestContext struct {
	RequestID    string
	StartTime    time.Time
	Duration     time.Duration
	ClientIP     string
	Method       string
	Path         string
	UserAgent    string
	ContentType  string
	Identity     *Identity
	AnomalyScore float64
	Blocked      bool
	BlockReason  string
	StatusCode   int
	Flags        []string
}

// Identity represents an authenticated identity
type Identity struct {
	ID                 string
	Type               string // "api_key", "mtls", "jwt"
	Organization       string
	TrustScore         float64
	Permissions        []string
	Metadata           map[string]string
	Role               STIGRole           // RBAC role (from MCP)
	DataClassification DataClassification // Max data classification this identity can access
	Name               string             // Display name
	Source             string             // "mcp_agent", "api_key", "user_session"
	IssuedAt           time.Time
	ExpiresAt          time.Time
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Context key for request context
type contextKey string

const requestContextKey contextKey = "khepra_request_context"

// Helper functions
func generateRequestID() string {
	// Use timestamp + random suffix for unique ID
	return fmt.Sprintf("khp-%d", time.Now().UnixNano())
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (if behind proxy)
	if xff := r.Header.Get(HeaderXForwardedFor); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get(HeaderXRealIP); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	// Strip port if present
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

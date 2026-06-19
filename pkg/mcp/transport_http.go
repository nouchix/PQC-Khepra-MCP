// Package mcp — HTTP transport for the MCP server.
//
// Implements TransportHTTP mode for remote MCP clients. Provides:
//   - POST /mcp        — JSON-RPC endpoint (Smithery-compatible alias)
//   - POST /mcp/v1/rpc — JSON-RPC endpoint (internal)
//   - GET  /sse        — Server-Sent Events handshake (Smithery-compatible)
//   - GET  /mcp/v1/health — Health check
//   - Mutual TLS support (optional)
//   - CORS enforcement (no wildcards)
//   - Security headers (HSTS, CSP, nosniff, X-Frame-Options)
//   - Bearer token authentication forwarding to DEMARC
//   - SSE connection cap + idle timeout + ping keepalive
//   - token-expiring SSE event for client-side token refresh
//
// Bilateral security middleware chain (request → response):
//
//	secureHeaders → cors → SEKHEM WAF (ingress scan → mux → egress scrub)
//
// The SEKHEM WAF layer (pkg/sekhem.HTTPMiddleware) runs on BOTH the inbound
// request AND the outbound response, providing:
//   - Inbound:  8 WAF rules (SQLi/XSS/PathTraversal/UTF8/Host/Rate/UA) + spectral FP
//   - Outbound: secret scrubbing (removes key material from JSON bodies) + FP header

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/gateway"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sekhem"
)

// SSEConfig configures Server-Sent Events connection behaviour.
type SSEConfig struct {
	// MaxConns is the maximum number of concurrent SSE connections (default: 50).
	// Exceeding this returns 429 Too Many Requests.
	MaxConns int

	// IdleTimeout is the maximum SSE stream lifetime (default: 60 min).
	// After this duration the stream is closed, forcing token refresh.
	IdleTimeout time.Duration

	// PingInterval is how often a keepalive ping event is sent (default: 30s).
	PingInterval time.Duration
}

// HTTPTransportConfig configures the HTTP transport layer.
type HTTPTransportConfig struct {
	// ListenAddr is the bind address (e.g. ":8443", "127.0.0.1:9090").
	ListenAddr string

	// MaxRequestSize limits the incoming request body (default: 4MB).
	MaxRequestSize int64

	// ReadTimeout is the HTTP read timeout (default: 30s).
	ReadTimeout time.Duration

	// WriteTimeout is the HTTP write timeout.
	// IMPORTANT: set to 0 when SSE is enabled — SSE streams must not time out.
	WriteTimeout time.Duration

	// AllowedOrigins for CORS. Empty slice = no CORS headers.
	// Wildcard "*" is explicitly prohibited; pass explicit origins only.
	AllowedOrigins []string

	// TLSCertFile and TLSKeyFile for mutual TLS (optional).
	TLSCertFile string
	TLSKeyFile  string

	// EnableSecureHeaders adds OWASP-recommended security response headers.
	// Always enable in production.
	EnableSecureHeaders bool

	// WAF is the SEKHEM WAFShield instance for bilateral security.
	// When non-nil, it is applied as the innermost middleware layer:
	//   secureHeaders → cors → Gateway → WAF (ingress scan → handler → egress scrub)
	// When nil, the WAF layer is skipped (not recommended for production).
	WAF *sekhem.WAFShield

	// Gateway is the 4-layer Khepra Secure Gateway (Firewall → Auth → Anomaly → RateLimit).
	// When non-nil, it is applied OUTSIDE the SEKHEM WAF layer:
	//   secureHeaders → cors → Gateway → SEKHEM WAF → mux
	// Ordering rationale: cheap IP/auth rejections happen before expensive WAF content scanning.
	// When nil, the gateway layer is skipped — only SEKHEM WAF applies.
	Gateway *gateway.Gateway

	// SSE controls Server-Sent Events behaviour.
	SSE SSEConfig
}

// httpTransport implements the HTTP/SSE transport for the MCP server.
type httpTransport struct {
	router      *Router
	cred        any
	logger      *log.Logger
	config      HTTPTransportConfig
	httpServer  *http.Server
	sseConns    atomic.Int32 // active SSE connections
	sseEventSeq atomic.Int64 // monotonic SSE event-id counter
}

// newHTTPTransport creates an HTTP transport wired to the given router.
func newHTTPTransport(router *Router, cred any, logger *log.Logger, cfg HTTPTransportConfig) *httpTransport {
	if cfg.MaxRequestSize <= 0 {
		cfg.MaxRequestSize = 4 << 20 // 4MB
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":9443"
	}
	if cfg.SSE.MaxConns <= 0 {
		cfg.SSE.MaxConns = 50
	}
	if cfg.SSE.IdleTimeout <= 0 {
		cfg.SSE.IdleTimeout = 60 * time.Minute
	}
	if cfg.SSE.PingInterval <= 0 {
		cfg.SSE.PingInterval = 30 * time.Second
	}
	return &httpTransport{
		router: router,
		cred:   cred,
		logger: logger,
		config: cfg,
	}
}

// Serve starts the HTTP server and blocks until the context is cancelled.
func (t *httpTransport) Serve(ctx context.Context) error {
	mux := http.NewServeMux()

	// Smithery-compatible routes (primary)
	mux.HandleFunc("/mcp", t.handleRPC)        // POST /mcp — Smithery JSON-RPC
	mux.HandleFunc("/sse", t.handleSSE)        // GET  /sse — Smithery SSE handshake

	// Internal / legacy routes
	mux.HandleFunc("/mcp/v1/rpc", t.handleRPC)
	mux.HandleFunc("/mcp/v1/health", t.handleHealth)

	// ── Bilateral security middleware chain (outer → inner = first-called → last-called) ──
	//
	//   ① secureHeadersMiddleware — OWASP response headers              (outermost)
	//   ② corsMiddleware          — strict origin enforcement (no wildcards)
	//   ③ gateway.Middleware      — 4-layer bilateral gateway:
	//        L1 Firewall:  IP blocklist, geo-block, WAF (SQLi/XSS/LFI/RCE)
	//        L2 Auth:      ML-DSA-65 ASAF attestation, mTLS, Bearer JWT
	//        L3 Anomaly:   KASA behavioral scoring + block threshold
	//        L4 Control:   per-identity rate limiting + DAG audit log
	//   ④ sekhem.HTTPMiddleware   — SEKHEM WAF bilateral:
	//        INGRESS: 8 rule set (SQLi/XSS/PathTraversal/UTF8/Host/Rate/UA) + Kyber FP
	//        EGRESS:  secret scrubbing + X-Sekhem-FP header               (innermost)
	//   ⑤ mux                    — route handlers
	//
	// Ordering rationale:
	//   Gateway (③) is outside SEKHEM WAF (④) so cheap IP/auth rejections happen first,
	//   before expensive regex content scanning. WAF runs only on gateway-cleared traffic.
	var handler http.Handler = mux
	if t.config.WAF != nil {
		handler = sekhem.HTTPMiddleware(t.config.WAF)(handler)
		t.logger.Printf("[MCP:HTTP] ④ SEKHEM WAF bilateral: ACTIVE (%d rules)",
			len(t.config.WAF.Rules()))
	} else {
		t.logger.Printf("[MCP:HTTP] ④ SEKHEM WAF bilateral: DISABLED")
	}
	if t.config.Gateway != nil {
		handler = gateway.Middleware(t.config.Gateway)(handler)
		t.logger.Printf("[MCP:HTTP] ③ Khepra Gateway 4-layer: ACTIVE (Firewall+Auth+Anomaly+RateLimit)")
	} else {
		t.logger.Printf("[MCP:HTTP] ③ Khepra Gateway 4-layer: DISABLED")
	}
	handler = t.corsMiddleware(handler)
	if t.config.EnableSecureHeaders {
		handler = secureHeadersMiddleware(handler)
	}

	t.httpServer = &http.Server{
		Addr:         t.config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  t.config.ReadTimeout,
		WriteTimeout: t.config.WriteTimeout, // 0 = no write deadline (required for SSE)
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
	}

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.httpServer.Shutdown(shutCtx) //nolint:errcheck // best-effort shutdown
	}()

	t.logger.Printf("[MCP:HTTP] listening on %s", t.config.ListenAddr)
	t.logger.Printf("[MCP:HTTP] routes: POST /mcp, GET /sse, POST /mcp/v1/rpc, GET /mcp/v1/health")

	var err error
	if t.config.TLSCertFile != "" && t.config.TLSKeyFile != "" {
		t.logger.Printf("[MCP:HTTP] TLS enabled (cert=%s)", t.config.TLSCertFile)
		err = t.httpServer.ListenAndServeTLS(t.config.TLSCertFile, t.config.TLSKeyFile)
	} else {
		err = t.httpServer.ListenAndServe()
	}

	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// handleSSE implements the GET /sse endpoint.
//
// Protocol:
//  1. Validate origin (CORS) and auth token.
//  2. Enforce connection cap (MaxConns → 429).
//  3. Send "connected" event immediately.
//  4. Send "ping" event every PingInterval (dead-client detection).
//  5. Send "token-expiring" event at IdleTimeout - 5 min (client should refresh).
//  6. Close stream at IdleTimeout (force reconnect + token rotation).
func (t *httpTransport) handleSSE(w http.ResponseWriter, r *http.Request) {
	// SSE is GET only
	if r.Method != http.MethodGet {
		http.Error(w, "SSE requires GET", http.StatusMethodNotAllowed)
		return
	}

	// Verify http.Flusher support (required for SSE)
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported by server", http.StatusInternalServerError)
		return
	}

	// Enforce connection cap
	current := t.sseConns.Add(1)
	defer t.sseConns.Add(-1)
	if int(current) > t.config.SSE.MaxConns {
		http.Error(w, `{"error":"too many SSE connections"}`, http.StatusTooManyRequests)
		return
	}

	// SSE response headers — no compression, no caching, no buffering
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx proxy buffering
	w.Header().Set("Vary", "Accept, Origin")

	// Remove write deadline for this SSE stream (set at http.Server level to 0)
	// The idle timeout is enforced by our context deadline below.
	streamCtx, cancel := context.WithTimeout(r.Context(), t.config.SSE.IdleTimeout)
	defer cancel()

	// Helper: write one SSE event
	writeEvent := func(eventType, data string) bool {
		seq := t.sseEventSeq.Add(1)
		_, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", seq, eventType, data)
		if err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// 1. Connected event
	if !writeEvent("connected", fmt.Sprintf(`{"server":"khepra-mcp","version":"%s","sse_max_age_s":%d}`,
		HardenedServerVersion, int(t.config.SSE.IdleTimeout.Seconds()))) {
		return
	}

	t.logger.Printf("[MCP:SSE] stream opened — active=%d/%d remote=%s",
		int(current), t.config.SSE.MaxConns, sanitizeForLog(extractRemoteAddr(r)))

	pingTick := time.NewTicker(t.config.SSE.PingInterval)
	defer pingTick.Stop()

	// token-expiring warning fires 5 minutes before stream closes
	tokenWarnDelay := t.config.SSE.IdleTimeout - 5*time.Minute
	if tokenWarnDelay <= 0 {
		tokenWarnDelay = t.config.SSE.IdleTimeout / 2
	}
	tokenWarnTimer := time.NewTimer(tokenWarnDelay)
	defer tokenWarnTimer.Stop()

	for {
		select {
		case <-streamCtx.Done():
			// Stream lifetime expired — close gracefully
			writeEvent("stream-closed", `{"reason":"idle_timeout","reconnect":true}`) //nolint:errcheck
			t.logger.Printf("[MCP:SSE] stream closed (timeout) — remote=%s",
				sanitizeForLog(extractRemoteAddr(r)))
			return

		case <-pingTick.C:
			if !writeEvent("ping", `{}`) {
				t.logger.Printf("[MCP:SSE] stream closed (client disconnect) — remote=%s",
					sanitizeForLog(extractRemoteAddr(r)))
				return
			}

		case <-tokenWarnTimer.C:
			// Warn client: token will expire soon; reconnect to refresh
			writeEvent("token-expiring", `{"action":"reconnect_and_refresh_token"}`) //nolint:errcheck
		}
	}
}

// handleRPC processes a JSON-RPC request over HTTP.
func (t *httpTransport) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		t.writeJSONError(w, nil, ErrCodeInvalidRequest, "only POST is supported")
		return
	}

	// Enforce request size limit
	body := http.MaxBytesReader(w, r.Body, t.config.MaxRequestSize)
	defer body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		t.writeJSONError(w, nil, ErrCodeParseError, "request body too large or unreadable")
		return
	}

	// Parse JSON-RPC request
	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		t.writeJSONError(w, nil, ErrCodeParseError, "parse error: "+err.Error())
		return
	}

	// Extract credential from Authorization header
	cred := t.extractCredential(r)

	// Extract remote address for CIDR checks
	remoteAddr := extractRemoteAddr(r)

	// Dispatch based on method
	var resp JSONRPCResponse
	switch req.Method {
	case "initialize":
		resp = t.handleInitialize(req)
	case "ping":
		resp = JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mustMarshal(map[string]string{"status": "pong"})}
	case "tools/list":
		tools := t.router.ListTools()
		resp = JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mustMarshal(map[string]any{"tools": tools})}
	case "tools/call":
		resp = t.handleToolsCall(r.Context(), req, cred, remoteAddr)
	default:
		resp = JSONRPCResponse{
			JSONRPC: "2.0", ID: req.ID,
			Error: &JSONRPCError{Code: ErrCodeMethodNotFound, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// handleInitialize returns server info over HTTP.
func (t *httpTransport) handleInitialize(req JSONRPCRequest) JSONRPCResponse {
	result := InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities: Capabilities{
			Tools: &ToolsCapability{ListChanged: false},
		},
		ServerInfo: ServerInfo{
			Name:    HardenedServerName,
			Version: HardenedServerVersion,
		},
	}
	return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mustMarshal(result)}
}

// handleToolsCall routes a tool call through the full security chain.
func (t *httpTransport) handleToolsCall(ctx context.Context, req JSONRPCRequest, cred any, remoteAddr string) JSONRPCResponse {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0", ID: req.ID,
			Error: &JSONRPCError{Code: ErrCodeInvalidParams, Message: "invalid params: " + err.Error()},
		}
	}

	call := MCPToolCall{
		RequestID:   fmt.Sprintf("http-%d", time.Now().UnixNano()),
		ToolName:    params.Name,
		Args:        params.Arguments,
		RawPayload:  req.Params,
		Transport:   TransportHTTP,
		SubmittedAt: time.Now().UTC(),
	}

	resp, err := t.router.HandleToolCall(ctx, call, cred, remoteAddr)
	if err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0", ID: req.ID,
			Error: &JSONRPCError{Code: ErrCodeInternal, Message: err.Error()},
		}
	}

	return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mustMarshal(resp)}
}

// handleHealth returns a basic health check response.
func (t *httpTransport) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"status":        "healthy",
		"server":        HardenedServerName,
		"version":       HardenedServerVersion,
		"time":          time.Now().UTC().Format(time.RFC3339),
		"sse_active":    t.sseConns.Load(),
		"sse_max_conns": t.config.SSE.MaxConns,
	})
}

// corsMiddleware enforces strict CORS — no wildcards ever.
// Origins not in AllowedOrigins receive no CORS headers (browser blocks them).
func (t *httpTransport) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(t.config.AllowedOrigins) > 0 {
			origin := r.Header.Get("Origin")
			for _, allowed := range t.config.AllowedOrigins {
				if allowed == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept")
					w.Header().Set("Access-Control-Max-Age", "86400")
					// Vary header required for correct CDN caching of CORS responses
					w.Header().Add("Vary", "Origin")
					break
				}
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// secureHeadersMiddleware adds OWASP-recommended HTTP security headers.
// These mirror the middleware.SecureHeaders() package but operate as
// a net/http handler wrapper so they don't require importing the Gin middleware.
func secureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Prevent MIME-type sniffing
		h.Set("X-Content-Type-Options", "nosniff")
		// Deny framing (clickjacking)
		h.Set("X-Frame-Options", "DENY")
		// Disable browser XSS auditor reflection
		h.Set("X-XSS-Protection", "0")
		// Strict-Transport-Security (1 year, includeSubDomains)
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Referrer policy
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Content-Security-Policy: tight — no inline scripts, no external loads
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// Permissions-Policy: disable all browser features
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// Remove server identification
		h.Set("Server", "khepra")
		next.ServeHTTP(w, r)
	})
}

// extractCredential extracts the authentication credential from the HTTP request.
func (t *httpTransport) extractCredential(r *http.Request) any {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return t.cred // fallback to default
	}
	// Bearer token
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return auth
}

// extractRemoteAddr extracts the client's real IP address.
func extractRemoteAddr(r *http.Request) string {
	// Check X-Forwarded-For (trusted reverse proxy only)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fallback to connection address
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sanitizeForLog strips newlines and tabs from user-controlled strings
// before logging to prevent log injection (CWE-117).
func sanitizeForLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}

// writeJSONError writes a JSON-RPC error response.
func (t *httpTransport) writeJSONError(w http.ResponseWriter, id any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{ //nolint:errcheck
		JSONRPC: "2.0",
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: msg},
	})
}


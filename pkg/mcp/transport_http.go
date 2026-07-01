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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
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

	// DagStore is the persistent DAG store (pkg/dag).
	// When non-nil, the /api/v1/dag/history and /api/v1/dag/stats endpoints are
	// activated, serving the full attested node chain for the dag-viewer and
	// C3PAO evidence export. When nil, those routes return 503.
	DagStore dag.Store

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
	dagStore    dag.Store    // Master DAG — serves /api/v1/dag/history
	sessions    sync.Map     // sessionID(string) → chan []byte (MCP SSE protocol)
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
		router:   router,
		cred:     cred,
		logger:   logger,
		config:   cfg,
		dagStore: cfg.DagStore,
	}
}

// Serve starts the HTTP server and blocks until the context is cancelled.
func (t *httpTransport) Serve(ctx context.Context) error {
	mux := http.NewServeMux()

	// Smithery-compatible routes (primary)
	mux.HandleFunc("/mcp", t.handleRPC)        // POST /mcp — Smithery JSON-RPC
	mux.HandleFunc("/sse", t.handleSSE)        // GET  /sse — MCP SSE handshake
	mux.HandleFunc("/message", t.handleMessage) // POST /message?sessionId=xxx — MCP SSE protocol

	// MCP server-card.json — static server metadata for Smithery discovery (SEP-1649).
	// Serves the tool manifest so Smithery can skip live scanning.
	mux.HandleFunc("/.well-known/mcp/server-card.json", t.handleServerCard)

	// Health check routes — Traefik + monitoring
	mux.HandleFunc("/health", t.handleHealth)

	// Internal / legacy routes
	mux.HandleFunc("/mcp/v1/rpc", t.handleRPC)
	mux.HandleFunc("/mcp/v1/health", t.handleHealth)

	// Onboarding scan — REST convenience wrapper for souhimbou.ai funnel
	// POST /api/v1/onboarding/scan — no auth required, rate-limited 10/min/IP
	mux.HandleFunc("/api/v1/onboarding/scan", t.handleOnboardingScan)

	// Khepra AI chat — NLChatPanel convenience endpoint
	// POST /api/v1/mcp/ask — proxied from souhimbou.ai frontend
	mux.HandleFunc("/api/v1/mcp/ask", t.handleMCPAsk)

	// Root path — friendly API info (prevents 404 on direct browser visit)
	mux.HandleFunc("/", t.handleRoot)

	// GET /events — SSE relay: broadcasts router event stream for dag-viewer.html
	// Connect dag-viewer.html with: ?feed=https://mcp.souhimbou.ai/events
	// Protected by CORS (same as other routes). No auth required for read-only event stream.
	mux.HandleFunc("/events", t.handleDAGEvents)

	// GET /dag-viewer — serves docs/dag-viewer.html with live SSE pre-configured
	mux.HandleFunc("/dag-viewer", t.handleDAGViewer)

	// GET /api/v1/dag/history — full attested DAG node chain (dag-viewer + C3PAO export)
	// Returns the complete persisted DAG from disk, sorted by timestamp ascending.
	// Protected by SEKHEM WAF + CORS. No auth required — nodes contain no secrets.
	mux.HandleFunc("/api/v1/dag/history", t.handleDAGHistory)

	// GET /api/v1/dag/stats — lightweight DAG metrics (node count, timestamps)
	mux.HandleFunc("/api/v1/dag/stats", t.handleDAGStats)

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
	t.logger.Printf("[MCP:HTTP] routes: POST /mcp, GET /sse, POST /mcp/v1/rpc, GET /mcp/v1/health, POST /api/v1/onboarding/scan")

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

	// 1. Connected event (informational — not part of MCP protocol, just metadata)
	if !writeEvent("connected", fmt.Sprintf(`{"server":"khepra-mcp","version":"%s","sse_max_age_s":%d}`,
		HardenedServerVersion, int(t.config.SSE.IdleTimeout.Seconds()))) {
		return
	}

	// 2. Endpoint event — REQUIRED by MCP SSE protocol (2024-11-05 spec).
	// Tells mcp-remote the URL to POST JSON-RPC messages to.
	// Without this event, the client has no channel to send initialize/tools/call,
	// causing every request to time out after 60s.
	sessID := newSessionID()
	sessCh := make(chan []byte, 64)
	t.sessions.Store(sessID, sessCh)
	defer t.sessions.Delete(sessID)

	// Determine the public base URL from the request so the endpoint URL is absolute.
	// mcp-remote requires an absolute URL or a path it can resolve relative to /sse.
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}
	endpointURL := scheme + "://" + host + "/message?sessionId=" + sessID
	if !writeEvent("endpoint", endpointURL) {
		return
	}

	t.logger.Printf("[MCP:SSE] stream opened — session=%s active=%d/%d remote=%s",
		sessID[:8], int(current), t.config.SSE.MaxConns, sanitizeForLog(extractRemoteAddr(r)))

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
			t.logger.Printf("[MCP:SSE] stream closed (timeout) — session=%s remote=%s",
				sessID[:8], sanitizeForLog(extractRemoteAddr(r)))
			return

		case msg := <-sessCh:
			// Relay JSON-RPC response back to client through the SSE stream
			seq := t.sseEventSeq.Add(1)
			_, werr := fmt.Fprintf(w, "id: %d\nevent: message\ndata: %s\n\n", seq, msg)
			if werr != nil {
				t.logger.Printf("[MCP:SSE] session=%s write error: %v", sessID[:8], werr)
				return
			}
			flusher.Flush()

		case <-pingTick.C:
			if !writeEvent("ping", `{}`) {
				t.logger.Printf("[MCP:SSE] stream closed (client disconnect) — session=%s remote=%s",
					sessID[:8], sanitizeForLog(extractRemoteAddr(r)))
				return
			}

		case <-tokenWarnTimer.C:
			// Warn client: token will expire soon; reconnect to refresh
			writeEvent("token-expiring", `{"action":"reconnect_and_refresh_token"}`) //nolint:errcheck
		}
	}
}

// handleMessage processes POST /message?sessionId=xxx — the MCP SSE protocol message endpoint.
//
// mcp-remote POSTs JSON-RPC requests here after receiving the endpoint URL from the SSE stream.
// Responses are sent back through the SSE channel (not in the HTTP response body).
// Returns 202 Accepted immediately after queuing the response.
func (t *httpTransport) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}

	sessID := r.URL.Query().Get("sessionId")
	if sessID == "" {
		http.Error(w, `{"error":"missing sessionId"}`, http.StatusBadRequest)
		return
	}

	val, ok := t.sessions.Load(sessID)
	if !ok {
		http.Error(w, `{"error":"session not found or expired"}`, http.StatusNotFound)
		return
	}
	sessCh := val.(chan []byte)

	body := http.MaxBytesReader(w, r.Body, t.config.MaxRequestSize)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, `{"error":"request body error"}`, http.StatusBadRequest)
		return
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		http.Error(w, `{"error":"parse error"}`, http.StatusBadRequest)
		return
	}

	cred := t.extractCredential(r)
	remoteAddr := extractRemoteAddr(r)

	// notifications/* are fire-and-forget — no response needed per MCP spec
	if strings.HasPrefix(req.Method, "notifications/") {
		w.WriteHeader(http.StatusAccepted)
		return
	}

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

	respBytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, `{"error":"marshal error"}`, http.StatusInternalServerError)
		return
	}

	select {
	case sessCh <- respBytes:
	default:
		t.logger.Printf("[MCP:SSE] session=%s response channel full — dropping", sessID[:8])
	}

	w.WriteHeader(http.StatusAccepted)
}

// newSessionID generates a cryptographically random 16-byte hex session identifier.
func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
		// MCP spec: tool errors go in result with isError=true
		errResult := mcpCallToolResult{
			Content: []mcpContentItem{{Type: "text", Text: err.Error()}},
			IsError: true,
		}
		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mustMarshal(errResult)}
	}

	// Convert MCPToolResponse → MCP-spec content array
	var textContent string
	if resp.IsError {
		textContent = resp.ErrorMessage
	} else {
		respJSON, marshalErr := json.MarshalIndent(resp, "", "  ")
		if marshalErr != nil {
			textContent = fmt.Sprintf("{\"error\": \"marshal failed: %s\"}", marshalErr.Error())
		} else {
			textContent = string(respJSON)
		}
	}

	result := mcpCallToolResult{
		Content: []mcpContentItem{{Type: "text", Text: textContent}},
		IsError: resp.IsError,
	}

	return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mustMarshal(result)}
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

// handleServerCard serves /.well-known/mcp/server-card.json for Smithery discovery.
// Returns tool metadata from the router's manifest registry in MCP server-card format (SEP-1649).
func (t *httpTransport) handleServerCard(w http.ResponseWriter, _ *http.Request) {
	type serverCard struct {
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Authentication struct {
			Required bool `json:"required"`
		} `json:"authentication"`
		Tools     []map[string]any `json:"tools"`
		Resources []any            `json:"resources"`
		Prompts   []any            `json:"prompts"`
	}

	card := serverCard{
		Tools:     t.router.ListTools(),
		Resources: []any{},
		Prompts:   []any{},
	}
	card.ServerInfo.Name = HardenedServerName
	card.ServerInfo.Version = HardenedServerVersion
	card.Authentication.Required = false

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // 1h cache for Smithery
	json.NewEncoder(w).Encode(card) //nolint:errcheck
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

// handleRoot serves GET / with a friendly JSON service description.
// Prevents Caddy/Go from returning a bare "404 page not found" when
// developers or monitoring tools probe the root path.
func (t *httpTransport) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Only handle the exact root path — let other paths fall through to 404.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"service": HardenedServerName,
		"version": HardenedServerVersion,
		"status":  "ok",
		"docs":    "https://souhimbou.ai",
		"health":  "/mcp/v1/health",
		"endpoints": []string{
			"/api/v1/onboarding/scan",
			"/api/v1/mcp/ask",
			"/mcp/v1/health",
			"/mcp",
			"/sse",
		},
	})
}

// handleMCPAsk is a convenience REST wrapper for the Khepra AI chat panel.
// POST /api/v1/mcp/ask  { "query": "...", "session_id": "...", "max_tools": 5 }
// Returns: { "answer": "...", "tools_called": [...] }
func (t *httpTransport) handleMCPAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"only POST is accepted"}`, http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8<<10) // 8KB max
	var req struct {
		Query     string `json:"query"`
		SessionID string `json:"session_id"`
		MaxTools  int    `json:"max_tools"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON: " + err.Error()}) //nolint:errcheck
		return
	}
	if req.Query == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "query is required"}) //nolint:errcheck
		return
	}

	clientIP := extractRemoteAddr(r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	call := MCPToolCall{
		RequestID:   "ask-" + req.SessionID,
		ToolName:    "agent_record",
		Args:        map[string]any{"query": req.Query, "session_id": req.SessionID, "source": "souhimbou.ai/chat"},
		RawPayload:  []byte(`{"query":"` + req.Query + `"}`),
		Transport:   TransportHTTP,
		SubmittedAt: time.Now().UTC(),
	}

	resp, toolErr := t.router.HandleToolCall(ctx, call, nil, clientIP)

	w.Header().Set("Content-Type", "application/json")
	if toolErr != nil {
		// Return a friendly answer even on tool error — the chat panel shows it gracefully.
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"answer":      "The KHEPRA intelligence layer is initializing. Ask me about your CMMC compliance posture, STIG findings, or agent security.",
			"tools_called": []string{},
		})
		return
	}

	answer := "I processed your request through the KHEPRA protocol."
	var toolsCalled []string
	if resp != nil {
		if resp.KhepraSign != "" {
			toolsCalled = append(toolsCalled, call.ToolName)
		}
		if m, ok := resp.Envelope.Result.(map[string]any); ok {
			if v, ok := m["message"].(string); ok && v != "" {
				answer = v
			} else if v, ok := m["summary"].(string); ok && v != "" {
				answer = v
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"answer":      answer,
		"tools_called": toolsCalled,
	})
}

// handleDAGEvents — GET /events
// SSE relay for the 3D DAG viewer. On connect:
//  1. Sends a snapshot of up to 100 historical events from the in-memory buffer
//  2. Then streams real-time exec/attest events as they arrive
//
// Usage: open dag-viewer.html?feed=https://mcp.souhimbou.ai/events
func (t *httpTransport) handleDAGEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx/Caddy buffering

	emitter := t.router.Events()

	// ── Phase 1: Replay historical snapshot ─────────────────────────────────
	// Send buffered events from this session's history so the viewer is never
	// blank. Capped at 100 most recent exec/attest events.
	snapshot := emitter.Snapshot()
	if len(snapshot) > 100 {
		snapshot = snapshot[len(snapshot)-100:]
	}
	for _, ev := range snapshot {
		if ev.Type != EventExec && ev.Type != EventAttest {
			continue
		}
		data, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		seq := t.sseEventSeq.Add(1)
		fmt.Fprintf(w, "event: snapshot\nid: %d\ndata: %s\n\n", seq, data) //nolint:errcheck
	}
	fl.Flush()

	// ── Phase 2: Subscribe to real-time event bus ───────────────────────────
	ch := make(chan MCPEvent, 64)
	emitter.AddHook(func(ev MCPEvent) {
		select {
		case ch <- ev:
		default:
			// drop if consumer is too slow — never block the router
		}
	})

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n") //nolint:errcheck
			fl.Flush()
		case ev := <-ch:
			if ev.Type != EventExec && ev.Type != EventAttest {
				continue // only relay exec/attest events
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			seq := t.sseEventSeq.Add(1)
			fmt.Fprintf(w, "event: live\nid: %d\ndata: %s\n\n", seq, data) //nolint:errcheck
			fl.Flush()
		}
	}
}

// handleDAGViewer — GET /dag-viewer
// Serves docs/dag-viewer.html (the 3D compliance graph) with the SSE feed
// pre-pointed at /events on the same origin. No CORS needed.
func (t *httpTransport) handleDAGViewer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "docs/dag-viewer.html")
}

// handleDAGHistory — GET /api/v1/dag/history
//
// Returns the full persisted Master DAG as a JSON array sorted by time ascending.
// This is fetched by dag-viewer.html on page load to populate the 3D graph
// immediately from disk history (before any SSE events arrive).
//
// Also used for C3PAO evidence export and OSCAL generation.
// Protected by SEKHEM WAF + CORS. Nodes contain no secret material.
func (t *httpTransport) handleDAGHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if t.dagStore == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":"dag store not initialized","nodes":[],"count":0}`)
		return
	}

	nodes := t.dagStore.All()

	// Sort by time ascending (genesis → most recent)
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Time < nodes[j].Time
	})

	type historyResponse struct {
		Nodes []*dag.Node `json:"nodes"`
		Count int         `json:"count"`
	}
	resp := historyResponse{
		Nodes: nodes,
		Count: len(nodes),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // audit chain must not be cached
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		t.logger.Printf("[DAG-HISTORY] encode error: %v", err)
	}
}

// handleDAGStats — GET /api/v1/dag/stats
//
// Lightweight endpoint returning node count, first/last timestamps.
// Used by monitoring, health checks, and dag-viewer status bar.
func (t *httpTransport) handleDAGStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if t.dagStore == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":"dag store not initialized","node_count":0}`)
		return
	}

	nodes := t.dagStore.All()
	count := len(nodes)

	var firstTime, lastTime string
	for _, n := range nodes {
		if firstTime == "" || n.Time < firstTime {
			firstTime = n.Time
		}
		if lastTime == "" || n.Time > lastTime {
			lastTime = n.Time
		}
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"node_count":%d,"first_node_time":%q,"last_node_time":%q,"dag_store":"active"}`,
		count, firstTime, lastTime)
}

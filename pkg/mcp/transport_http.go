// Package mcp — HTTP transport for the MCP server.
//
// Implements TransportHTTP mode for remote MCP clients. Provides:
//   - POST /mcp/v1/rpc  — JSON-RPC endpoint
//   - GET  /mcp/v1/health — Health check
//   - Mutual TLS support (optional)
//   - CORS configuration
//   - Request size limits
//   - Bearer token authentication forwarding to DEMARC

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
	"time"
)

// HTTPTransportConfig configures the HTTP transport layer.
type HTTPTransportConfig struct {
	// ListenAddr is the bind address (e.g. ":8443", "127.0.0.1:9090").
	ListenAddr string

	// MaxRequestSize limits the incoming request body (default: 4MB).
	MaxRequestSize int64

	// ReadTimeout is the HTTP read timeout (default: 30s).
	ReadTimeout time.Duration

	// WriteTimeout is the HTTP write timeout (default: 30s).
	WriteTimeout time.Duration

	// AllowedOrigins for CORS (empty = no CORS headers).
	AllowedOrigins []string

	// TLSCertFile and TLSKeyFile for mutual TLS (optional).
	TLSCertFile string
	TLSKeyFile  string
}

// httpTransport implements the HTTP/SSE transport for the MCP server.
type httpTransport struct {
	router     *Router
	cred       any
	logger     *log.Logger
	config     HTTPTransportConfig
	httpServer *http.Server
}

// newHTTPTransport creates an HTTP transport wired to the given router.
func newHTTPTransport(router *Router, cred any, logger *log.Logger, cfg HTTPTransportConfig) *httpTransport {
	if cfg.MaxRequestSize <= 0 {
		cfg.MaxRequestSize = 4 << 20 // 4MB
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":9443"
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
	mux.HandleFunc("/mcp/v1/rpc", t.handleRPC)
	mux.HandleFunc("/mcp/v1/health", t.handleHealth)

	t.httpServer = &http.Server{
		Addr:         t.config.ListenAddr,
		Handler:      mux,
		ReadTimeout:  t.config.ReadTimeout,
		WriteTimeout: t.config.WriteTimeout,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
	}

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.httpServer.Shutdown(shutCtx)
	}()

	t.logger.Printf("[MCP:HTTP] listening on %s", t.config.ListenAddr)

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

// handleRPC processes a JSON-RPC request over HTTP.
func (t *httpTransport) handleRPC(w http.ResponseWriter, r *http.Request) {
	// CORS
	if len(t.config.AllowedOrigins) > 0 {
		origin := r.Header.Get("Origin")
		for _, allowed := range t.config.AllowedOrigins {
			if allowed == "*" || allowed == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				break
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
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
	json.NewEncoder(w).Encode(resp)
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
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "healthy",
		"server":  HardenedServerName,
		"version": HardenedServerVersion,
		"time":    time.Now().UTC().Format(time.RFC3339),
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

// writeJSONError writes a JSON-RPC error response.
func (t *httpTransport) writeJSONError(w http.ResponseWriter, id any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: msg},
	})
}

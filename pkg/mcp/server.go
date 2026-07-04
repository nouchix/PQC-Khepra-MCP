package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

// ─── MCP HardenedServer (AD-008: stdio default) ────────────────────────────────
//
// The HardenedServer owns transport ONLY. It reads JSON-RPC requests from stdin,
// dispatches them through the Router, and writes JSON-RPC responses to stdout.
//
// CRITICAL: stdout = JSON-RPC frames ONLY. stderr = human-readable logs.
// Any non-JSON output on stdout breaks MCP interoperability.

const (
	// HardenedServerName identifies this server in the MCP `initialize` response.
	HardenedServerName = "khepra-mcp"
	// HardenedServerVersion is the current server version.
	HardenedServerVersion = "1.0.0"
	// ProtocolVersion is the latest MCP protocol version we implement.
	ProtocolVersion = "2024-11-05"
	// ProtocolVersionLatest is the most recent version we fully support.
	// We negotiate down to what the client requests when possible.
	ProtocolVersionLatest = "2025-11-25"
)

// HardenedServer is the new MCP transport layer (AD-008).
// Use NewHardenedServer to construct.
type HardenedServer struct {
	mode     TransportMode
	router   *Router
	logger   *log.Logger
	running  atomic.Bool
	cred     any    // Default credential for stdio sessions (e.g. ACP token)
	addr     string // Remote address — "local" for stdio

	// Transport config
	httpConfig HTTPTransportConfig

	// Production hardening
	shutdownHooks []func() // Cleanup functions run on shutdown
}

// HardenedServerConfig configures the hardened MCP server.
type HardenedServerConfig struct {
	Mode       TransportMode // Default: TransportStdio
	Router     *Router
	Logger     *log.Logger
	Credential any    // Default session credential (for stdio: pre-authenticated)
	HTTPConfig HTTPTransportConfig // Used when Mode = TransportHTTP
}

// NewHardenedServer creates a new hardened MCP server.
func NewHardenedServer(cfg HardenedServerConfig) (*HardenedServer, error) {
	if cfg.Router == nil {
		return nil, fmt.Errorf("mcp/server: Router is required")
	}
	mode := cfg.Mode
	if mode == "" {
		mode = TransportStdio
	}
	logger := cfg.Logger
	if logger == nil {
		// CRITICAL: Server logs go to stderr, never stdout.
		logger = log.New(os.Stderr, "[MCP] ", log.LstdFlags|log.Lmicroseconds)
	}
	return &HardenedServer{
		mode:       mode,
		router:     cfg.Router,
		logger:     logger,
		cred:       cfg.Credential,
		addr:       "local",
		httpConfig: cfg.HTTPConfig,
	}, nil
}

// OnShutdown registers a cleanup function to run when the server shuts down.
// Use this for key destruction, telemetry flush, resource cleanup, etc.
func (s *HardenedServer) OnShutdown(fn func()) {
	s.shutdownHooks = append(s.shutdownHooks, fn)
}

// Shutdown performs graceful shutdown: runs all registered hooks.
func (s *HardenedServer) Shutdown(ctx context.Context) error {
	s.logger.Println("running shutdown hooks...")
	for i, hook := range s.shutdownHooks {
		s.logger.Printf("shutdown hook %d/%d", i+1, len(s.shutdownHooks))
		hook()
	}
	s.running.Store(false)
	s.logger.Println("shutdown complete")
	return nil
}

// Run starts the server on the configured transport.
// It blocks until the context is cancelled or a shutdown signal is received.
func (s *HardenedServer) Run(ctx context.Context) error {
	s.running.Store(true)
	defer s.running.Store(false)

	switch s.mode {
	case TransportStdio:
		return s.runStdio(ctx)
	case TransportHTTP:
		ht := newHTTPTransport(s.router, s.cred, s.logger, s.httpConfig)
		s.logger.Println("starting MCP server on HTTP")
		return ht.Serve(ctx)
	default:
		return fmt.Errorf("mcp/server: unsupported transport: %s", s.mode)
	}
}

// ─── stdio Transport ───────────────────────────────────────────────────────────

func (s *HardenedServer) runStdio(ctx context.Context) error {
	s.logger.Println("starting MCP server on stdio")

	// Set up signal handling for graceful shutdown.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	// Strip UTF-8 BOM if present on Windows (PowerShell and some terminals
	// inject \xEF\xBB\xBF before the first JSON line). Silently discard it.
	bomLine, err := reader.Peek(3)
	if err == nil && len(bomLine) >= 3 && bomLine[0] == 0xEF && bomLine[1] == 0xBB && bomLine[2] == 0xBF {
		_, _ = reader.Discard(3)
		s.logger.Println("[WARN] UTF-8 BOM stripped from stdin (Windows tool artifact)")
	}

	for {
		select {
		case <-ctx.Done():
			s.logger.Println("shutting down (context cancelled)")
			return nil
		default:
		}

		// Read one JSON-RPC request per line from stdin.
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				s.logger.Println("stdin closed — shutting down")
				return nil
			}
			s.logger.Printf("read error: %v", err)
			continue
		}

		// Parse JSON-RPC request.
		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error: &JSONRPCError{
					Code:    ErrCodeParseError,
					Message: "parse error: " + err.Error(),
				},
			}
			_ = encoder.Encode(resp)
			continue
		}

		// Dispatch based on method.
		resp := s.handleRequest(ctx, req)
		if resp == nil {
			continue // Notification — no response
		}
		if err := encoder.Encode(*resp); err != nil {
			s.logger.Printf("write error: %v", err)
		}
	}
}

// ─── Method Dispatch ───────────────────────────────────────────────────────────

func (s *HardenedServer) handleRequest(ctx context.Context, req JSONRPCRequest) *JSONRPCResponse {
	if req.JSONRPC != "2.0" {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    ErrCodeInvalidRequest,
				Message: "invalid jsonrpc version",
			},
		}
	}

	switch req.Method {
	case "initialize":
		r := s.handleInitialize(req)
		return &r
	case "ping":
		r := s.handlePing(req)
		return &r
	case "tools/list":
		r := s.handleToolsList(req)
		return &r
	case "tools/call":
		r := s.handleToolsCall(ctx, req)
		return &r
	case "notifications/initialized":
		// JSON-RPC 2.0: notifications have no id — MUST NOT send a response.
		s.logger.Println("client initialized notification received")
		return nil
	default:
		// Ignore unknown notifications (method starts with "notifications/")
		if len(req.Method) > 14 && req.Method[:14] == "notifications/" {
			s.logger.Printf("ignoring unknown notification: %s", req.Method)
			return nil
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    ErrCodeMethodNotFound,
				Message: fmt.Sprintf("method not found: %s", req.Method),
			},
		}
	}
}

// ─── initialize ────────────────────────────────────────────────────────────────

func (s *HardenedServer) handleInitialize(req JSONRPCRequest) JSONRPCResponse {
	// Negotiate protocol version: parse the client's requested version and echo
	// it back if we support it. MCP spec: server MUST NOT return a version the
	// client did not request, or the client will abort the handshake.
	negotiatedVersion := ProtocolVersion // default (2024-11-05, most widely supported)
	if len(req.Params) > 0 {
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if err := json.Unmarshal(req.Params, &params); err == nil && params.ProtocolVersion != "" {
			clientVersion := params.ProtocolVersion
			// Accept the client's version if it's one we understand.
			switch clientVersion {
			case "2024-11-05", "2025-03-26", "2025-11-25":
				negotiatedVersion = clientVersion
			default:
				// Unknown future version — fall back to our latest.
				s.logger.Printf("[MCP:INIT] unknown client protocolVersion=%q, negotiating to %s",
					clientVersion, ProtocolVersionLatest)
				negotiatedVersion = ProtocolVersionLatest
			}
		}
	}
	s.logger.Printf("[MCP:INIT] protocol negotiated: %s", negotiatedVersion)

	result := InitializeResult{
		ProtocolVersion: negotiatedVersion,
		Capabilities: Capabilities{
			Tools: &ToolsCapability{
				ListChanged: false,
			},
		},
		ServerInfo: ServerInfo{
			Name:    HardenedServerName,
			Version: HardenedServerVersion,
		},
	}
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  mustMarshal(result),
	}
}

// ─── ping ──────────────────────────────────────────────────────────────────────

func (s *HardenedServer) handlePing(req JSONRPCRequest) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  mustMarshal(map[string]string{"status": "pong"}),
	}
}

// ─── tools/list ────────────────────────────────────────────────────────────────

func (s *HardenedServer) handleToolsList(req JSONRPCRequest) JSONRPCResponse {
	tools := s.router.ListTools()
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  mustMarshal(map[string]any{"tools": tools}),
	}
}

// ─── tools/call ────────────────────────────────────────────────────────────────

// mcpContentItem is a single content block in the MCP tools/call result.
// MCP spec: content is an array of {type: "text", text: "..."} objects.
type mcpContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// mcpCallToolResult is the MCP-spec-compliant result for tools/call.
// MCP clients (Claude Desktop, Antigravity, Cursor) expect exactly this shape.
type mcpCallToolResult struct {
	Content []mcpContentItem `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

func (s *HardenedServer) handleToolsCall(ctx context.Context, req JSONRPCRequest) JSONRPCResponse {
	// Parse tool call parameters.
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    ErrCodeInvalidParams,
				Message: "invalid tool call params: " + err.Error(),
			},
		}
	}

	// Build MCPToolCall.
	call := MCPToolCall{
		RequestID:   fmt.Sprintf("req-%d", time.Now().UnixNano()),
		ToolName:    params.Name,
		Args:        params.Arguments,
		RawPayload:  req.Params,
		Transport:   s.mode,
		SubmittedAt: time.Now().UTC(),
	}

	// Route through the full security chain.
	resp, err := s.router.HandleToolCall(ctx, call, s.cred, s.addr)
	if err != nil {
		// MCP spec: tool errors go in the result with isError=true,
		// NOT in the JSON-RPC error field (which is for protocol errors only).
		errResult := mcpCallToolResult{
			Content: []mcpContentItem{{Type: "text", Text: err.Error()}},
			IsError: true,
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  mustMarshal(errResult),
		}
	}

	// Convert MCPToolResponse → MCP-spec content array.
	// The full envelope (PQC signature, attestation, warnings) is serialized
	// as JSON text inside the content block. MCP clients render content[0].text.
	var textContent string
	if resp.IsError {
		textContent = resp.ErrorMessage
	} else {
		// Serialize the full response (envelope + warnings + _khepra_sig)
		// so clients get the PQC attestation chain in a parseable format.
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

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  mustMarshal(result),
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		// This should never happen with known types.
		return json.RawMessage(`{"error":"marshal failed"}`)
	}
	return b
}

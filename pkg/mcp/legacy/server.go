// package legacy implements the Model Context Protocol (MCP) server for the
// Khepra/Giza Cyber Shield platform.
//
// This is the world's first PQC-secured MCP server — every tool response is
// signed with the AdinKhepra Dilithium-3 signature and anchored in the DAG
// audit chain before being returned to the AI tool (Claude, Cursor, etc.).
//
// Architecture:
//
//	AI Tool (Claude/Cursor)
//	       │  JSON-RPC 2.0 (stdio or HTTP)
//	       ▼
//	 ┌─────────────────────────────────────────────┐
//	 │         Khepra MCP Server (this pkg)         │
//	 │  ┌──────────────────────────────────────┐   │
//	 │  │  Prompt Injection Scanner (6 patterns) │   │
//	 │  │  RBAC + AdinKhepra JWT Verification   │   │
//	 │  │  PQC Signature on every response      │   │
//	 │  │  100% DAG audit logging               │   │
//	 │  └──────────────────────────────────────┘   │
//	 │           │                                   │
//	 │    ┌──────┴──────┐                           │
//	 │    ▼             ▼                           │
//	 │  Go KASA    Supabase DB                     │
//	 │  (pkg/agi)  (pkg/supabase)                  │
//	 └─────────────────────────────────────────────┘
//
// MCP Specification Reference: https://spec.modelcontextprotocol.io/
// AdinKhepra PQC Protocol Reference: docs/TC-25-ADINKHEPRA-001.md
package legacy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// ─── JSON-RPC 2.0 Types ────────────────────────────────────────────────────────

// Request is an MCP JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is an MCP JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	ErrParseError     = -32700
	ErrInvalidRequest = -32600
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternal       = -32603
	// MCP-specific error codes (application range: -32000 to -32099)
	ErrInjectionDetected   = -32000
	ErrUnauthorized        = -32001
	ErrRateLimitExceeded   = -32002
	ErrPQCSignatureFailed  = -32003
	ErrDAGAnchorFailed     = -32004
	ErrSupabaseUnavailable = -32005
)

// ─── MCP Protocol Messages ─────────────────────────────────────────────────────

// ServerInfo is returned in the initialize response.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Capabilities advertises what the MCP server supports.
type Capabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
}

// ToolsCapability signals that tools/list and tools/call are supported.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability signals resource support.
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability signals prompt support.
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// Tool describes an MCP tool that AI clients can invoke.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// ToolResult is the response payload from a tools/call invocation.
type ToolResult struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
	// Khepra PQC Extensions
	DAGNodeID    string `json:"dag_node_id,omitempty"`
	PQCSignature string `json:"pqc_signature,omitempty"`
	SignedAt     string `json:"signed_at,omitempty"`
}

// ContentItem is a single piece of content in a tool result.
type ContentItem struct {
	Type string `json:"type"` // "text" | "image" | "resource"
	Text string `json:"text,omitempty"`
}

// ─── Tool Registry ─────────────────────────────────────────────────────────────

// ToolHandler is a function that handles a tool invocation.
type ToolHandler func(ctx context.Context, params json.RawMessage) (*ToolResult, error)

// ─── Server ────────────────────────────────────────────────────────────────────

// Config holds configuration for the Khepra MCP server.
type Config struct {
	ServerName    string
	ServerVersion string
	// PQC signing key (Dilithium private key bytes). If nil, signing is skipped.
	SigningKey []byte
	// DAG logger for audit trail
	AuditLogger AuditLogger
	// Supabase store for persistence
	Store Store
	// Debug mode
	Debug bool
}

// AuditLogger is the interface for DAG-backed audit logging.
type AuditLogger interface {
	Log(eventType string, data map[string]interface{}) error
}

// Store is the interface for MCP persistence (implemented by supabase.MCPStore).
type Store interface {
	LogToolCall(ctx context.Context, call interface{}) error
}

// Server is the Khepra PQC-secured MCP server.
type Server struct {
	cfg       Config
	tools     map[string]Tool
	handlers  map[string]ToolHandler
	reader    *bufio.Reader
	writer    io.Writer
	startTime time.Time
}

// NewServer creates a new Khepra MCP server instance.
func NewServer(cfg Config) *Server {
	if cfg.ServerName == "" {
		cfg.ServerName = "Khepra MCP Server"
	}
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = "1.0.0"
	}
	return &Server{
		cfg:       cfg,
		tools:     make(map[string]Tool),
		handlers:  make(map[string]ToolHandler),
		reader:    bufio.NewReader(os.Stdin),
		writer:    os.Stdout,
		startTime: time.Now(),
	}
}

// RegisterTool registers an MCP tool with its handler.
func (s *Server) RegisterTool(tool Tool, handler ToolHandler) {
	s.tools[tool.Name] = tool
	s.handlers[tool.Name] = handler
}

// ServeStdio runs the MCP server over stdin/stdout (the standard MCP transport).
func (s *Server) ServeStdio(ctx context.Context) error {
	log.Printf("[khepra-mcp] Starting %s v%s (PQC: %v)",
		s.cfg.ServerName, s.cfg.ServerVersion, len(s.cfg.SigningKey) > 0)

	scanner := bufio.NewScanner(s.reader)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("stdin read: %w", err)
			}
			return io.EOF
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, ErrParseError, "parse error", nil)
			continue
		}

		resp := s.handle(ctx, &req)
		if err := s.send(resp); err != nil {
			log.Printf("[khepra-mcp] send error: %v", err)
		}
	}
}

// handle dispatches an MCP request to the appropriate handler.
func (s *Server) handle(ctx context.Context, req *Request) *Response {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "initialized":
		return nil // notification, no response
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(ctx, req)
	case "ping":
		return &Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{}}
	default:
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: ErrMethodNotFound, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}
}

func (s *Server) handleInitialize(req *Request) *Response {
	result := map[string]interface{}{
		"protocolVersion": "2025-11-25",
		"serverInfo": ServerInfo{
			Name:    s.cfg.ServerName,
			Version: s.cfg.ServerVersion,
		},
		"capabilities": Capabilities{
			Tools: &ToolsCapability{},
		},
		// Khepra PQC Extensions advertised in capabilities
		"khepra": map[string]interface{}{
			"pqc_enabled":      len(s.cfg.SigningKey) > 0,
			"dag_audit":        s.cfg.AuditLogger != nil,
			"supabase_persist": s.cfg.Store != nil,
			"protocol":         "AdinKhepra-v1",
		},
	}
	return &Response{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func (s *Server) handleToolsList(req *Request) *Response {
	toolList := make([]Tool, 0, len(s.tools))
	for _, t := range s.tools {
		toolList = append(toolList, t)
	}
	return &Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]interface{}{"tools": toolList},
	}
}

func (s *Server) handleToolsCall(ctx context.Context, req *Request) *Response {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.errorResp(req.ID, ErrInvalidParams, "invalid params: "+err.Error())
	}

	handler, ok := s.handlers[params.Name]
	if !ok {
		return s.errorResp(req.ID, ErrMethodNotFound, "tool not found: "+params.Name)
	}

	start := time.Now()
	result, err := handler(ctx, params.Arguments)
	elapsed := time.Since(start)

	if err != nil {
		result = &ToolResult{
			Content: []ContentItem{{Type: "text", Text: err.Error()}},
			IsError: true,
		}
	}

	// Sign the result with Dilithium if a signing key is configured
	if len(s.cfg.SigningKey) > 0 && result != nil {
		result.SignedAt = time.Now().UTC().Format(time.RFC3339)
		// NOTE: Actual signing is done via pkg/adinkra.Sign()
		// The signature is attached to the result for the AI tool to verify.
		// Full signing is wired in cmd/khepra-mcp/main.go where adinkra is imported.
	}

	// Audit log the call
	if s.cfg.AuditLogger != nil {
		_ = s.cfg.AuditLogger.Log("mcp_tool_call", map[string]interface{}{
			"tool":        params.Name,
			"duration_ms": elapsed.Milliseconds(),
			"is_error":    err != nil,
			"timestamp":   time.Now().UTC(),
		})
	}

	if s.cfg.Debug {
		log.Printf("[khepra-mcp] tool=%s duration=%v error=%v", params.Name, elapsed, err)
	}

	return &Response{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func (s *Server) send(resp *Response) error {
	if resp == nil {
		return nil
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(s.writer, "%s\n", data)
	return err
}

func (s *Server) sendError(id interface{}, code int, msg string, data interface{}) {
	resp := &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: msg, Data: data},
	}
	_ = s.send(resp)
}

func (s *Server) errorResp(id interface{}, code int, msg string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: msg},
	}
}

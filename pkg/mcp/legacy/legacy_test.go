package legacy

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// ─── KhepraTools ────────────────────────────────────────────────────────────

func TestKhepraTools_NonEmpty(t *testing.T) {
	tools := KhepraTools()
	if len(tools) == 0 {
		t.Fatal("KhepraTools should return at least one tool")
	}
}

func TestKhepraTools_AllHaveNames(t *testing.T) {
	for i, tool := range KhepraTools() {
		if tool.Name == "" {
			t.Errorf("tool[%d] has empty Name", i)
		}
		if tool.Description == "" {
			t.Errorf("tool[%d] (%s) has empty Description", i, tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool[%d] (%s) has nil InputSchema", i, tool.Name)
		}
	}
}

func TestKhepraTools_UniqueNames(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range KhepraTools() {
		if seen[tool.Name] {
			t.Errorf("duplicate tool name: %s", tool.Name)
		}
		seen[tool.Name] = true
	}
}

func TestKhepraTools_KnownToolsPresent(t *testing.T) {
	tools := KhepraTools()
	names := make(map[string]bool, len(tools))
	for _, t := range tools {
		names[t.Name] = true
	}

	required := []string{
		"khepra_discover_endpoints",
		"khepra_run_compliance_scan",
		"khepra_query_stig",
		"khepra_export_attestation",
		"khepra_get_dag_chain",
	}
	for _, req := range required {
		if !names[req] {
			t.Errorf("required tool %q not registered", req)
		}
	}
}

// ─── NewServer ───────────────────────────────────────────────────────────────

func TestNewServer_Defaults(t *testing.T) {
	s := NewServer(Config{})
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.cfg.ServerName == "" {
		t.Error("ServerName should have a default")
	}
	if s.cfg.ServerVersion == "" {
		t.Error("ServerVersion should have a default")
	}
}

func TestNewServer_ExplicitConfig(t *testing.T) {
	cfg := Config{
		ServerName:    "Khepra-Test",
		ServerVersion: "2.0.0",
		Debug:         true,
	}
	s := NewServer(cfg)
	if s.cfg.ServerName != "Khepra-Test" {
		t.Errorf("expected Khepra-Test, got %s", s.cfg.ServerName)
	}
	if s.cfg.ServerVersion != "2.0.0" {
		t.Errorf("expected 2.0.0, got %s", s.cfg.ServerVersion)
	}
}

// ─── RegisterTool + handle ───────────────────────────────────────────────────

func TestRegisterTool_ToolsListReturnsIt(t *testing.T) {
	var buf bytes.Buffer
	s := NewServer(Config{Debug: false})
	s.writer = &buf

	s.RegisterTool(Tool{Name: "test_tool", Description: "a test tool", InputSchema: map[string]interface{}{}},
		func(ctx context.Context, params json.RawMessage) (*ToolResult, error) {
			return &ToolResult{Content: []ContentItem{{Type: "text", Text: "ok"}}}, nil
		},
	)

	req := &Request{JSONRPC: "2.0", ID: 1, Method: "tools/list"}
	resp := s.handle(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	data, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(data), "test_tool") {
		t.Errorf("expected test_tool in tools/list, got: %s", data)
	}
}

func TestHandle_UnknownMethod(t *testing.T) {
	s := NewServer(Config{})
	req := &Request{JSONRPC: "2.0", ID: 99, Method: "nonexistent/method"}
	resp := s.handle(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != ErrMethodNotFound {
		t.Errorf("expected code %d, got %d", ErrMethodNotFound, resp.Error.Code)
	}
}

func TestHandle_Initialize(t *testing.T) {
	s := NewServer(Config{ServerName: "Khepra", ServerVersion: "1.0"})
	req := &Request{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	resp := s.handle(context.Background(), req)
	if resp == nil {
		t.Fatal("expected response for initialize")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	// Result should include server info
	data, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(data), "Khepra") {
		t.Errorf("expected server name in initialize result, got: %s", data)
	}
}

func TestHandle_Ping(t *testing.T) {
	s := NewServer(Config{})
	req := &Request{JSONRPC: "2.0", ID: 2, Method: "ping"}
	resp := s.handle(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("ping should not error: %+v", resp.Error)
	}
}

func TestHandle_ToolsCall_UnknownTool(t *testing.T) {
	s := NewServer(Config{})
	params, _ := json.Marshal(map[string]interface{}{"name": "no_such_tool", "arguments": map[string]interface{}{}})
	req := &Request{JSONRPC: "2.0", ID: 3, Method: "tools/call", Params: params}
	resp := s.handle(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for unknown tool call")
	}
}

// ─── Error codes ─────────────────────────────────────────────────────────────

func TestErrorCodeConstants(t *testing.T) {
	codes := map[string]int{
		"ErrParseError":     ErrParseError,
		"ErrInvalidRequest": ErrInvalidRequest,
		"ErrMethodNotFound": ErrMethodNotFound,
		"ErrInvalidParams":  ErrInvalidParams,
		"ErrInternal":       ErrInternal,
	}
	// All standard JSON-RPC codes must be negative
	for name, code := range codes {
		if code >= 0 {
			t.Errorf("%s should be negative, got %d", name, code)
		}
	}
}

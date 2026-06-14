// Package mcp — integration tests for the hardened MCP security chain.
//
// Tests validate the full Router chain:
//   DEMARC → RateLimit → Validate → Manifest → Polymorphic → MCPGateway → Executor → Attestation
//
// All tests use mock implementations to avoid heavy crypto/Docker dependencies.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// ─── Test Mocks ────────────────────────────────────────────────────────────────

// mockDemarc implements DemarcGateway for testing.
type mockDemarc struct {
	identity Identity
	authErr  error
	cidrErr  error
}

func (m *mockDemarc) Authenticate(_ context.Context, _ any) (Identity, error) {
	return m.identity, m.authErr
}
func (m *mockDemarc) CheckCIDR(_ context.Context, _ Identity, _ string) error {
	return m.cidrErr
}

// mockPoly implements PolymorphicEngine for testing.
type mockPoly struct {
	wrapReqErr    error
	verifyReqErr  error
	wrapRespErr   error
	verifyRespErr error
}

func (m *mockPoly) WrapRequest(payload []byte, _ string) ([]byte, error) {
	if m.wrapReqErr != nil {
		return nil, m.wrapReqErr
	}
	env := map[string]any{"payload": string(payload), "agent_id": "test"}
	b, _ := json.Marshal(env)
	return b, nil
}
func (m *mockPoly) VerifyRequest(_ []byte) error  { return m.verifyReqErr }
func (m *mockPoly) WrapResponse(result any, reqID string) (SecureEnvelope, error) {
	if m.wrapRespErr != nil {
		return SecureEnvelope{}, m.wrapRespErr
	}
	return SecureEnvelope{
		RequestID: reqID,
		Result:    result,
		CreatedAt: time.Now().UTC(),
		Signature: "mock-sig",
	}, nil
}
func (m *mockPoly) VerifyResponse(_ SecureEnvelope) error { return m.verifyRespErr }

// mockGateway implements MCPGateway for testing.
type mockGateway struct {
	permErr      error
	injectionErr error
}

func (m *mockGateway) CheckPermission(_ Identity, _ string) error { return m.permErr }
func (m *mockGateway) ScanForInjection(_ string) error            { return m.injectionErr }

// mockAttestor implements Attestor for testing.
type mockAttestor struct {
	appendErr error
	signErr   error
	nodeID    string
}

func (m *mockAttestor) Append(_ context.Context, _ string, _, _ []byte) (string, error) {
	if m.appendErr != nil {
		return "", m.appendErr
	}
	id := m.nodeID
	if id == "" {
		id = fmt.Sprintf("dag-%d", time.Now().UnixNano())
	}
	return id, nil
}
func (m *mockAttestor) SignEnvelope(_ context.Context, env SecureEnvelope) (SecureEnvelope, error) {
	if m.signErr != nil {
		return env, m.signErr
	}
	env.Signature = "mock-pqc-sig"
	return env, nil
}

// mockDispatcher implements ToolDispatcher for testing.
type mockDispatcher struct {
	result   any
	warnings []string
	err      error
}

func (m *mockDispatcher) Execute(_ context.Context, _ ToolSpec, _ MCPToolCall) (any, []string, error) {
	return m.result, m.warnings, m.err
}

// ─── Test Helpers ──────────────────────────────────────────────────────────────

func testIdentity() Identity {
	return Identity{
		Subject:   "test-subject",
		Issuer:    "test",
		AgentID:   "agent-001",
		SessionID: "sess-001",
		Scopes:    []string{"ert:scan", "nhi:view", "acp:status"},
	}
}

func testToolSpec() ToolSpec {
	return ToolSpec{
		Name:           "ert_scan",
		Description:    "Run ERT vulnerability scan",
		RiskClass:      RiskReadOnly,
		Scope:          "ert:scan",
		SchemaVersion:  "1.0.0",
		SchemaHash:     "abc123",
		AllowedBackend: "in-process",
		TimeoutMs:      30000,
	}
}

func testRegistry(t *testing.T, tools ...ToolSpec) *ManifestRegistry {
	t.Helper()
	r := &ManifestRegistry{
		manifest: &SignedToolManifest{Version: "1.0.0", Revision: "test"},
		byName:   make(map[string]ToolSpec, len(tools)),
	}
	for _, tool := range tools {
		r.byName[tool.Name] = tool
	}
	return r
}

func testRouter(t *testing.T, opts ...func(*RouterConfig)) *Router {
	t.Helper()
	spec := testToolSpec()
	cfg := RouterConfig{
		Demarc:   &mockDemarc{identity: testIdentity()},
		Poly:     &mockPoly{},
		Gateway:  &mockGateway{},
		Registry: testRegistry(t, spec),
		Executor: &mockDispatcher{result: map[string]any{"status": "ok"}},
		Attestor: &mockAttestor{nodeID: "dag-test-001"},
		RateMax:  1000,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	r, err := NewRouter(cfg)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return r
}

func testCall(toolName string) MCPToolCall {
	return MCPToolCall{
		RequestID:   "req-test-001",
		ToolName:    toolName,
		// "local" is in knownOSTargets; "CMMC-L2" is in knownFrameworks.
		// Using taxonomy-valid values so Step 1.6a (scope validator) passes.
		Args:        map[string]any{"target": "local", "scope": "CMMC-L2"},
		SubmittedAt: time.Now().UTC(),
	}
}

// ─── Router Construction Tests ─────────────────────────────────────────────────

func TestNewRouter_RequiresDemarc(t *testing.T) {
	_, err := NewRouter(RouterConfig{})
	if err == nil {
		t.Fatal("expected error for missing DemarcGateway")
	}
}

func TestNewRouter_RequiresAllComponents(t *testing.T) {
	cases := []struct {
		name string
		cfg  RouterConfig
		want string
	}{
		{"no demarc", RouterConfig{}, "DemarcGateway"},
		{"no poly", RouterConfig{Demarc: &mockDemarc{}}, "PolymorphicEngine"},
		{"no gateway", RouterConfig{Demarc: &mockDemarc{}, Poly: &mockPoly{}}, "MCPGateway"},
		{"no registry", RouterConfig{Demarc: &mockDemarc{}, Poly: &mockPoly{}, Gateway: &mockGateway{}}, "ManifestRegistry"},
		{"no executor", RouterConfig{Demarc: &mockDemarc{}, Poly: &mockPoly{}, Gateway: &mockGateway{}, Registry: &ManifestRegistry{}}, "ToolDispatcher"},
		{"no attestor", RouterConfig{Demarc: &mockDemarc{}, Poly: &mockPoly{}, Gateway: &mockGateway{}, Registry: &ManifestRegistry{}, Executor: &mockDispatcher{}}, "Attestor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRouter(tc.cfg)
			if err == nil {
				t.Fatalf("expected error mentioning %q", tc.want)
			}
		})
	}
}

func TestNewRouter_Success(t *testing.T) {
	r := testRouter(t)
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

// ─── Happy Path: Full Security Chain ───────────────────────────────────────────

func TestHandleToolCall_HappyPath(t *testing.T) {
	r := testRouter(t)
	call := testCall("ert_scan")

	resp, err := r.HandleToolCall(context.Background(), call, nil, "local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError {
		t.Fatalf("unexpected error response: %s", resp.ErrorMessage)
	}
	if resp.Envelope.AttestationID == "" {
		t.Error("expected attestation ID in envelope")
	}
	if resp.Envelope.Signature == "" {
		t.Error("expected PQC signature in envelope")
	}
	if resp.Envelope.RequestID != call.RequestID {
		t.Errorf("request ID mismatch: got %q want %q", resp.Envelope.RequestID, call.RequestID)
	}
}

// ─── DEMARC Boundary Tests ─────────────────────────────────────────────────────

func TestHandleToolCall_AuthFailure(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Demarc = &mockDemarc{authErr: fmt.Errorf("invalid token")}
	})
	_, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "local")
	if err == nil {
		t.Fatal("expected auth error")
	}
}

func TestHandleToolCall_CIDRDenied(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Demarc = &mockDemarc{
			identity: testIdentity(),
			cidrErr:  fmt.Errorf("CIDR denied"),
		}
	})
	_, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "10.0.0.1")
	if err == nil {
		t.Fatal("expected CIDR error")
	}
}

// ─── Rate Limiting Tests ───────────────────────────────────────────────────────

func TestHandleToolCall_RateLimited(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.RateMax = 2
		cfg.RateWindow = 60000
	})
	call := testCall("ert_scan")

	// First two should pass
	for i := 0; i < 2; i++ {
		resp, err := r.HandleToolCall(context.Background(), call, nil, "local")
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i+1, err)
		}
		if resp.IsError {
			t.Fatalf("request %d: unexpected rate limit on early request", i+1)
		}
	}

	// Third should be rate limited
	resp, err := r.HandleToolCall(context.Background(), call, nil, "local")
	if err != nil {
		t.Fatalf("request 3: unexpected hard error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected rate limit error response")
	}
}

// ─── Input Validation Tests ────────────────────────────────────────────────────

func TestHandleToolCall_PathTraversal(t *testing.T) {
	r := testRouter(t)
	call := testCall("ert_scan")
	call.Args = map[string]any{"file_path": "../../etc/passwd"}

	resp, err := r.HandleToolCall(context.Background(), call, nil, "local")
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected validation error for path traversal")
	}
}

func TestHandleToolCall_CommandInjection(t *testing.T) {
	r := testRouter(t)
	call := testCall("ert_scan")
	call.Args = map[string]any{"target": "example.com; rm -rf /"}

	resp, err := r.HandleToolCall(context.Background(), call, nil, "local")
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected validation error for command injection")
	}
}

// ─── Manifest Tests ────────────────────────────────────────────────────────────

func TestHandleToolCall_UnknownTool(t *testing.T) {
	r := testRouter(t)
	call := testCall("nonexistent_tool")

	_, err := r.HandleToolCall(context.Background(), call, nil, "local")
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

// ─── Gateway Policy Tests ──────────────────────────────────────────────────────

func TestHandleToolCall_PermissionDenied(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Gateway = &mockGateway{permErr: fmt.Errorf("no scope")}
	})
	_, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "local")
	if err == nil {
		t.Fatal("expected permission error")
	}
}

func TestHandleToolCall_InjectionDetected(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Gateway = &mockGateway{injectionErr: fmt.Errorf("injection")}
	})
	_, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "local")
	if err == nil {
		t.Fatal("expected injection error")
	}
}

// ─── Execution Tests ───────────────────────────────────────────────────────────

func TestHandleToolCall_ExecutionError(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Executor = &mockDispatcher{err: fmt.Errorf("scan failed")}
	})
	resp, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "local")
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error response from execution failure")
	}
}

func TestHandleToolCall_ExecutionWarnings(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Executor = &mockDispatcher{
			result:   map[string]any{"status": "partial"},
			warnings: []string{"incomplete scan"},
		}
	})
	resp, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Warnings) == 0 {
		t.Error("expected warnings in response")
	}
}

// ─── Attestation Tests ─────────────────────────────────────────────────────────

func TestHandleToolCall_AttestationFailure(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Attestor = &mockAttestor{appendErr: fmt.Errorf("DAG full")}
	})
	_, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "local")
	if err == nil {
		t.Fatal("expected attestation error")
	}
}

func TestHandleToolCall_SigningFailure(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Attestor = &mockAttestor{
			nodeID:  "dag-ok",
			signErr: fmt.Errorf("key expired"),
		}
	})
	_, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "local")
	if err == nil {
		t.Fatal("expected signing error")
	}
}

// ─── Polymorphic Tests ─────────────────────────────────────────────────────────

func TestHandleToolCall_PolyWrapFailed(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Poly = &mockPoly{wrapReqErr: fmt.Errorf("wrap error")}
	})
	_, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "local")
	if err == nil {
		t.Fatal("expected poly wrap error")
	}
}

func TestHandleToolCall_PolyVerifyFailed(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.Poly = &mockPoly{verifyReqErr: fmt.Errorf("verify error")}
	})
	_, err := r.HandleToolCall(context.Background(), testCall("ert_scan"), nil, "local")
	if err == nil {
		t.Fatal("expected poly verify error")
	}
}

// ─── ListTools Tests ───────────────────────────────────────────────────────────

func TestListTools(t *testing.T) {
	r := testRouter(t)
	tools := r.ListTools()
	if len(tools) == 0 {
		t.Fatal("expected at least one tool")
	}
	found := false
	for _, tool := range tools {
		if tool["name"] == "ert_scan" {
			found = true
			if tool["description"] == nil || tool["description"] == "" {
				t.Error("expected description for ert_scan")
			}
		}
	}
	if !found {
		t.Error("ert_scan not found in listed tools")
	}
}

// ─── Loop Detection Tests ──────────────────────────────────────────────────────

func TestHandleToolCall_LoopDetection(t *testing.T) {
	r := testRouter(t, func(cfg *RouterConfig) {
		cfg.MistakeConfig = MistakeTrackerConfig{
			LoopWindow:    5,
			LoopThreshold: 3,
		}
		cfg.RateMax = 100
	})

	call := testCall("ert_scan")
	// Same tool + same args should trigger loop detection after threshold
	for i := 0; i < 3; i++ {
		resp, err := r.HandleToolCall(context.Background(), call, nil, "local")
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if i < 2 && resp.IsError {
			t.Fatalf("iteration %d: unexpected early loop detection", i)
		}
	}
}

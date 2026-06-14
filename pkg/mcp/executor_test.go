package mcp

import (
	"context"
	"fmt"
	"testing"
)

// ─── Executor Tests ────────────────────────────────────────────────────────────

func TestExecutor_ReadOnly(t *testing.T) {
	exec := NewExecutor(ExecutorConfig{})
	exec.RegisterFunc("test_read", func(_ context.Context, _ MCPToolCall) (any, []string, error) {
		return map[string]string{"ok": "true"}, nil, nil
	})

	spec := ToolSpec{Name: "test_read", RiskClass: RiskReadOnly, TimeoutMs: 5000}
	call := MCPToolCall{Identity: testIdentity()}

	result, _, err := exec.Execute(context.Background(), spec, call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := result.(map[string]string)
	if !ok || m["ok"] != "true" {
		t.Error("unexpected result")
	}
}

func TestExecutor_ReadOnly_NoHandler(t *testing.T) {
	exec := NewExecutor(ExecutorConfig{})
	spec := ToolSpec{Name: "missing", RiskClass: RiskReadOnly, TimeoutMs: 5000}
	_, _, err := exec.Execute(context.Background(), spec, MCPToolCall{})
	if err == nil {
		t.Fatal("expected error for missing handler")
	}
}

func TestExecutor_Sandboxed_FallsBackInProcess(t *testing.T) {
	exec := NewExecutor(ExecutorConfig{}) // no sandbox configured
	exec.RegisterFunc("scan_tool", func(_ context.Context, _ MCPToolCall) (any, []string, error) {
		return "scan_result", nil, nil
	})

	spec := ToolSpec{Name: "scan_tool", RiskClass: RiskSandboxed, AllowedBackend: "in-process", TimeoutMs: 5000}
	result, warnings, err := exec.Execute(context.Background(), spec, MCPToolCall{Identity: testIdentity()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "scan_result" {
		t.Error("expected fallback result")
	}
	if len(warnings) == 0 {
		t.Error("expected sandbox fallback warning")
	}
}

func TestExecutor_Destructive_RequiresConfirmation(t *testing.T) {
	exec := NewExecutor(ExecutorConfig{}) // no confirmation gate
	spec := ToolSpec{Name: "nhi_revoke", RiskClass: RiskDestructive, TimeoutMs: 5000}
	_, _, err := exec.Execute(context.Background(), spec, MCPToolCall{Identity: testIdentity()})
	if err == nil {
		t.Fatal("expected error — no ConfirmationGate configured")
	}
}

type mockConfirmGate struct{ deny bool }

func (m *mockConfirmGate) Confirm(_ context.Context, _ ToolSpec, _ MCPToolCall) error {
	if m.deny {
		return fmt.Errorf("denied by operator")
	}
	return nil
}

func TestExecutor_Destructive_Approved(t *testing.T) {
	exec := NewExecutor(ExecutorConfig{Confirm: &mockConfirmGate{deny: false}})
	exec.RegisterFunc("nhi_revoke", func(_ context.Context, _ MCPToolCall) (any, []string, error) {
		return "revoked", nil, nil
	})
	spec := ToolSpec{Name: "nhi_revoke", RiskClass: RiskDestructive, TimeoutMs: 5000}
	result, _, err := exec.Execute(context.Background(), spec, MCPToolCall{Identity: testIdentity()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "revoked" {
		t.Error("expected revoked result")
	}
}

func TestExecutor_Destructive_Denied(t *testing.T) {
	exec := NewExecutor(ExecutorConfig{Confirm: &mockConfirmGate{deny: true}})
	exec.RegisterFunc("nhi_revoke", func(_ context.Context, _ MCPToolCall) (any, []string, error) {
		return "should not reach", nil, nil
	})
	spec := ToolSpec{Name: "nhi_revoke", RiskClass: RiskDestructive, TimeoutMs: 5000}
	_, _, err := exec.Execute(context.Background(), spec, MCPToolCall{Identity: testIdentity()})
	if err == nil {
		t.Fatal("expected denial error")
	}
}

func TestExecutor_UnknownRiskClass(t *testing.T) {
	exec := NewExecutor(ExecutorConfig{})
	spec := ToolSpec{Name: "x", RiskClass: "unknown", TimeoutMs: 5000}
	_, _, err := exec.Execute(context.Background(), spec, MCPToolCall{})
	if err == nil {
		t.Fatal("expected error for unknown risk class")
	}
}

// ─── Sandbox Policy Tests ──────────────────────────────────────────────────────

func TestValidateSandboxPolicy_EmptyName(t *testing.T) {
	err := validateSandboxPolicy(ToolSpec{}, DefaultSandboxConfig())
	if err == nil {
		t.Fatal("expected error for empty tool name")
	}
}

func TestValidateSandboxPolicy_ExcessiveMemory(t *testing.T) {
	cfg := DefaultSandboxConfig()
	cfg.MemLimitMB = 16384
	err := validateSandboxPolicy(ToolSpec{Name: "test"}, cfg)
	if err == nil {
		t.Fatal("expected error for excessive memory")
	}
}

func TestValidateSandboxPolicy_ReadOnlyWritable(t *testing.T) {
	cfg := DefaultSandboxConfig()
	cfg.ReadOnly = false
	err := validateSandboxPolicy(ToolSpec{Name: "test", RiskClass: RiskReadOnly}, cfg)
	if err == nil {
		t.Fatal("expected error for read-only tool with writable sandbox")
	}
}

// ─── Observability Tests ───────────────────────────────────────────────────────

func TestEventEmitter_BufferAndFlush(t *testing.T) {
	em := NewEventEmitter(EventEmitterConfig{MaxBuffer: 10})
	em.Emit(MCPEvent{Type: EventExec, Success: true})
	em.Emit(MCPEvent{Type: EventAuth, Success: false})

	events := em.Flush()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	// Second flush should be empty
	if len(em.Flush()) != 0 {
		t.Error("expected empty buffer after flush")
	}
}

func TestEventEmitter_Hook(t *testing.T) {
	em := NewEventEmitter(EventEmitterConfig{})
	var captured MCPEvent
	em.AddHook(func(e MCPEvent) { captured = e })

	em.Emit(MCPEvent{Type: EventStartup, Success: true})
	if captured.Type != EventStartup {
		t.Error("hook should have captured the event")
	}
}

func TestEventEmitter_Stats(t *testing.T) {
	em := NewEventEmitter(EventEmitterConfig{})
	em.Emit(MCPEvent{Type: EventExec, Success: true})
	em.Emit(MCPEvent{Type: EventExec, Success: true})
	em.Emit(MCPEvent{Type: EventError, Success: false})

	stats := em.Stats()
	if stats["total_events"] != 3 {
		t.Errorf("expected 3 total events, got %v", stats["total_events"])
	}
	if stats["error_events"] != 1 {
		t.Errorf("expected 1 error event, got %v", stats["error_events"])
	}
}

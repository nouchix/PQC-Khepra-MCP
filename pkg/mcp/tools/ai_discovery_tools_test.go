package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

func TestHandleScanShadowAI(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "scan_shadow_ai",
		Args: map[string]any{
			"targets": []any{"192.168.1.1"},
		},
	}

	res, warnings, err := HandleScanShadowAI(ctx, call)
	if err != nil {
		t.Fatalf("HandleScanShadowAI failed: %v", err)
	}

	resultMap, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", res)
	}

	targets, ok := resultMap["targets"].([]string)
	if !ok || len(targets) != 1 || targets[0] != "192.168.1.1" {
		t.Errorf("unexpected targets: %v", resultMap["targets"])
	}

	if len(warnings) == 0 {
		t.Errorf("expected warnings/logs, got none")
	}
}

func TestHandleAttestAIPolicy(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "attest_ai_policy",
		Args: map[string]any{
			"policy": map[string]any{"allow_ollama": true},
			"findings": []any{
				map[string]any{"service": "Ollama", "port": 11434},
			},
		},
	}

	res, _, err := HandleAttestAIPolicy(ctx, call)
	if err != nil {
		t.Fatalf("HandleAttestAIPolicy failed: %v", err)
	}

	resultMap, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", res)
	}

	posture, ok := resultMap["suggested_posture"].(string)
	if !ok || posture == "" {
		t.Errorf("expected suggested_posture string, got %v", resultMap["suggested_posture"])
	}
}

func TestHandleAuditPlugin4Shell(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	pluginDir := filepath.Join(tempDir, "sample-plugin")
	_ = os.MkdirAll(pluginDir, 0755)

	manifestPath := filepath.Join(pluginDir, "plugin.json")
	_ = os.WriteFile(manifestPath, []byte(`{"name": "sample-plugin"}`), 0644)

	// Test 1: Unpinned detection
	call := mcp.MCPToolCall{
		ToolName: "audit_plugin4shell",
		Args: map[string]any{
			"search_roots": []any{tempDir},
			"auto_pin":     false,
		},
	}

	res, warnings, err := HandleAuditPlugin4Shell(ctx, call)
	if err != nil {
		t.Fatalf("HandleAuditPlugin4Shell failed: %v", err)
	}
	resMap, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", res)
	}
	if resMap["compliance_status"] != "FAIL" {
		t.Errorf("expected FAIL, got %v", resMap["compliance_status"])
	}
	if len(warnings) == 0 {
		t.Errorf("expected warnings")
	}

	// Test 2: Auto-pin remediation
	callPin := mcp.MCPToolCall{
		ToolName: "audit_plugin4shell",
		Args: map[string]any{
			"search_roots": []any{tempDir},
			"auto_pin":     true,
		},
	}
	resPin, _, err := HandleAuditPlugin4Shell(ctx, callPin)
	if err != nil {
		t.Fatalf("auto-pin call failed: %v", err)
	}
	resPinMap := resPin.(map[string]any)
	if resPinMap["compliance_status"] != "PASS" {
		t.Errorf("expected PASS after auto-pin, got %v", resPinMap["compliance_status"])
	}
}

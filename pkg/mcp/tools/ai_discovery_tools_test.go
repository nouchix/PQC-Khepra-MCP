package tools

import (
	"context"
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

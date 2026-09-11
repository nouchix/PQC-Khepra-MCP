package tools

import (
	"context"
	"testing"

	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

func TestStripSensitiveArgs(t *testing.T) {
	input := map[string]any{
		"amount":          1000,
		"currency":        "usd",
		"description":     "Standard Plan",
		"license_key":     "should-be-stripped",
		"my_pqc_key":      "should-be-stripped",
		"signing_key_id":  "should-be-stripped",
		"private_token":   "should-be-stripped",
		"customer_id":     "should-be-stripped",
		"cui_data":        "should-be-stripped",
		"classified_info": "should-be-stripped",
		"secret_key":      "should-be-stripped",
		"dag_node_ref":    "should-be-stripped",
	}

	sanitized := stripSensitiveArgs(input)

	if len(sanitized) != 3 {
		t.Fatalf("expected 3 safe fields, got %d: %+v", len(sanitized), sanitized)
	}

	if sanitized["amount"] != 1000 || sanitized["currency"] != "usd" || sanitized["description"] != "Standard Plan" {
		t.Errorf("safe parameters corrupted: %+v", sanitized)
	}

	for k := range sanitized {
		for _, pat := range sensitiveArgPatterns {
			if pat == k {
				t.Errorf("sensitive key %q leaked into sanitized map", k)
			}
		}
	}
}

func TestMCPGatewayAllowlistRejection(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		Args: map[string]any{
			"upstream": "unauthorized-evil-mcp",
			"tool":     "steal_data",
		},
	}

	_, _, err := HandleMCPGateway(ctx, call)
	if err == nil {
		t.Fatal("expected error for non-allowlisted upstream, got nil")
	}
}

func TestStripeCallRequiresTool(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		Args: map[string]any{},
	}

	_, _, err := HandleStripeCall(ctx, call)
	if err == nil {
		t.Fatal("expected error when 'tool' argument is missing, got nil")
	}
}

package mcp

import (
	"context"
	"testing"
)

func TestOperatorPolicyGate(t *testing.T) {
	g := NewOperatorPolicyGate(nil, []string{"dag_write", " acp_issue ", "*", "all", ""})
	ctx := context.Background()
	if err := g.Confirm(ctx, ToolSpec{Name: "dag_write"}, MCPToolCall{}); err != nil {
		t.Fatalf("approved tool refused: %v", err)
	}
	if err := g.Confirm(ctx, ToolSpec{Name: "acp_issue"}, MCPToolCall{}); err != nil {
		t.Fatalf("approved tool (with spaces) refused: %v", err)
	}
	for _, name := range []string{"drbc_restore", "khepra_edge_exec", "*", "all"} {
		if err := g.Confirm(ctx, ToolSpec{Name: name}, MCPToolCall{}); err == nil {
			t.Fatalf("%q approved without being listed", name)
		}
	}
}

func TestOperatorPolicyGateDefaultDenies(t *testing.T) {
	t.Setenv(ApprovedDestructiveToolsEnv, "")
	g := NewOperatorPolicyGateFromEnv(nil)
	if err := g.Confirm(context.Background(), ToolSpec{Name: "acp_revoke"}, MCPToolCall{}); err == nil {
		t.Fatal("destructive tool approved with no operator policy")
	}
}

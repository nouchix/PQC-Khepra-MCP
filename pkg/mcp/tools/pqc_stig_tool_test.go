package tools

import (
	"context"
	"testing"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

func TestHandlePQCSTIG(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "pqc_stig",
		Args: map[string]any{
			"scan_path": ".",
			"profile":   "full",
		},
	}

	res, warnings, err := HandlePQCSTIG(ctx, call)
	if err != nil {
		t.Fatalf("HandlePQCSTIG failed: %v", err)
	}

	resp, ok := res.(*PQCSTIGResponse)
	if !ok {
		t.Fatalf("expected *PQCSTIGResponse, got %T", res)
	}

	if resp.Standard != "PQC-01-STIG-V1R1" {
		t.Errorf("unexpected standard: %v", resp.Standard)
	}

	if len(warnings) == 0 {
		t.Errorf("expected warnings/logs, got none")
	}
}

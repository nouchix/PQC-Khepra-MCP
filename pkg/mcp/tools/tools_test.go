package tools

import (
	"context"
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/nhi"
)

// ─── newWiredOrchestrator ────────────────────────────────────────────────────

func TestNewWiredOrchestrator_NotNil(t *testing.T) {
	o := newWiredOrchestrator()
	if o == nil {
		t.Fatal("newWiredOrchestrator returned nil")
	}
}

func TestNewWiredOrchestrator_HasLanes(t *testing.T) {
	o := newWiredOrchestrator()
	lanes := o.RegisteredLanes()
	if len(lanes) == 0 {
		t.Error("wired orchestrator should have at least one lane registered")
	}
}

// ─── getNHI ──────────────────────────────────────────────────────────────────

func TestGetNHI_NotNil(t *testing.T) {
	tracker := getNHI()
	if tracker == nil {
		t.Error("getNHI should return a non-nil NHITracker")
	}
}

func TestGetNHI_Singleton(t *testing.T) {
	t1 := getNHI()
	t2 := getNHI()
	if t1 != t2 {
		t.Error("getNHI should return the same singleton instance")
	}
}

// ─── NHI Tool constructors ───────────────────────────────────────────────────

func TestNewNHIInventoryTool_NotNil(t *testing.T) {
	tracker := nhi.NewNHITracker()
	tool := NewNHIInventoryTool(tracker)
	if tool == nil {
		t.Fatal("NewNHIInventoryTool returned nil")
	}
}

func TestNewNHIOrphansTool_NotNil(t *testing.T) {
	tracker := nhi.NewNHITracker()
	tool := NewNHIOrphansTool(tracker)
	if tool == nil {
		t.Fatal("NewNHIOrphansTool returned nil")
	}
}

// ─── NIST map tool ───────────────────────────────────────────────────────────

func TestNewControlIndex_NotNil(t *testing.T) {
	idx := NewControlIndex()
	if idx == nil {
		t.Fatal("NewControlIndex returned nil")
	}
}

func TestNewNistMapTool_NotNil(t *testing.T) {
	tool := NewNistMapTool()
	if tool == nil {
		t.Fatal("NewNistMapTool returned nil")
	}
}

// ─── ERTScanTool ─────────────────────────────────────────────────────────────

func TestNewERTScanTool_NotNil(t *testing.T) {
	orch := newWiredOrchestrator()
	tool := NewERTScanTool(orch)
	if tool == nil {
		t.Fatal("NewERTScanTool returned nil")
	}
}

// ─── HandleERTScan ───────────────────────────────────────────────────────────

func TestHandleERTScan_EmptyTarget(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "ert_scan",
		Args:     map[string]any{"target": ""},
	}
	result, _, err := HandleERTScan(ctx, call)
	if err == nil && result == nil {
		t.Error("expected either error or result for empty target")
	}
}

func TestHandleERTReadinessMCP_Returns(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{ToolName: "ert_readiness", Args: map[string]any{}}
	// Should not panic; may return an error result but should not Go-panic
	result, _, _ := HandleERTReadinessMCP(ctx, call)
	_ = result // result may be nil on error path
}

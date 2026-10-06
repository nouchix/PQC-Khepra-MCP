package mcp

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Every tool in the published manifest has a maturity entry, and every entry
// names a published tool.
func TestMaturityCoversManifest(t *testing.T) {
	data, err := os.ReadFile("../../manifest.json")
	if err != nil {
		t.Skipf("manifest.json not available: %v", err)
	}
	var m struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	published := map[string]bool{}
	for _, tool := range m.Tools {
		published[tool.Name] = true
		if _, ok := MaturityOf(tool.Name); !ok {
			t.Errorf("manifest tool %q has no maturity entry", tool.Name)
		}
	}
	extra := map[string]bool{"attest_export": true, "agent_scan": true, "stripe_call": true, "mcp_gateway": true}
	for name := range toolMaturity {
		if !published[name] && !extra[name] {
			t.Errorf("maturity entry %q is not a published tool", name)
		}
	}
}

// The executor refuses in_progress tools whether or not a handler exists.
func TestExecutorRefusesInProgressTools(t *testing.T) {
	e := NewExecutor(ExecutorConfig{})
	e.RegisterFunc("drift_detect", func(context.Context, MCPToolCall) (any, []string, error) {
		return map[string]any{"drift_found": false}, nil, nil
	})
	for name, m := range toolMaturity {
		if m.Status != MaturityInProgress {
			continue
		}
		res, _, err := e.Execute(context.Background(), ToolSpec{Name: name, RiskClass: RiskReadOnly}, MCPToolCall{ToolName: name})
		if err == nil || !strings.Contains(err.Error(), "implementation in progress") {
			t.Errorf("%s: expected an implementation-in-progress error, got res=%v err=%v", name, res, err)
		}
	}
}

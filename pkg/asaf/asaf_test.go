package asaf

import (
	"testing"
)

// ─── ComputeDriftScore ──────────────────────────────────────────────────────

func TestComputeDriftScore_ZeroInputs(t *testing.T) {
	score := ComputeDriftScore(nil, nil)
	if score != 0.0 {
		t.Errorf("expected 0.0 for nil inputs, got %f", score)
	}
}

func TestComputeDriftScore_EmptyObserved(t *testing.T) {
	baseline := DefaultBaselines["claude-code"]
	score := ComputeDriftScore(map[string]int{}, baseline)
	if score != 0.0 {
		t.Errorf("expected 0.0 for empty observed, got %f", score)
	}
}

func TestComputeDriftScore_IdenticalToBaseline(t *testing.T) {
	// Observed tool distribution matches the claude-code baseline exactly.
	observed := map[string]int{
		"read_file":   35,
		"write_file":  20,
		"list_dir":    15,
		"search":      10,
		"run_command": 10,
		"edit_file":   10,
	}
	baseline := DefaultBaselines["claude-code"]
	score := ComputeDriftScore(observed, baseline)
	// Cosine distance of identical vectors should be near 0
	if score > 0.05 {
		t.Errorf("expected near-zero drift for identical distribution, got %f", score)
	}
}

func TestComputeDriftScore_MaxDrift(t *testing.T) {
	// Observed only uses tools NOT in the baseline — maximal drift
	observed := map[string]int{
		"unknown_exotic_tool_xyz": 100,
	}
	baseline := DefaultBaselines["claude-code"]
	score := ComputeDriftScore(observed, baseline)
	// Orthogonal vectors → distance should be close to 1.0
	if score < 0.9 {
		t.Errorf("expected near-maximum drift for completely different tools, got %f", score)
	}
}

func TestComputeDriftScore_WriteHeavy(t *testing.T) {
	// Write-heavy agent that doesn't read at all
	observed := map[string]int{
		"write_file":  80,
		"edit_file":   20,
	}
	baseline := DefaultBaselines["claude-code"]
	heavy := ComputeDriftScore(observed, baseline)

	normal := map[string]int{
		"read_file":   35,
		"write_file":  20,
		"list_dir":    15,
		"search":      10,
		"run_command": 10,
		"edit_file":   10,
	}
	normalScore := ComputeDriftScore(normal, baseline)

	if heavy <= normalScore {
		t.Errorf("write-heavy session (score=%f) should drift more than normal (score=%f)", heavy, normalScore)
	}
}

// ─── DefaultBaselines ──────────────────────────────────────────────────────

func TestDefaultBaselines_AllDefined(t *testing.T) {
	agents := []string{"claude-code", "copilot", "cursor"}
	for _, agent := range agents {
		bp, ok := DefaultBaselines[agent]
		if !ok {
			t.Errorf("missing baseline for agent: %s", agent)
			continue
		}
		if bp.AgentType != agent {
			t.Errorf("baseline AgentType mismatch: want %s got %s", agent, bp.AgentType)
		}
		if len(bp.ToolFrequencies) == 0 {
			t.Errorf("baseline for %s has no tool frequencies", agent)
		}
		total := 0.0
		for _, f := range bp.ToolFrequencies {
			total += f
		}
		if total < 0.9 || total > 1.1 {
			t.Errorf("baseline for %s tool frequencies should sum to ~1.0, got %f", agent, total)
		}
	}
}

// ─── normalizeToolName ──────────────────────────────────────────────────────

func TestNormalizeToolName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"read_file", "read_file"},
		{"ReadFile", "read_file"},
		{"write_to_file", "write_file"},
		{"replace_file_content", "edit_file"},
		{"multi_replace_file_content", "edit_file"},
		{"list_dir", "list_dir"},
		{"grep_search", "search"},
		{"find_files", "search"},
		{"run_command", "run_command"},
		{"exec_script", "run_command"},
		{"something_exotic", "something_exotic"},
	}
	for _, tc := range cases {
		got := normalizeToolName(tc.input)
		if got != tc.want {
			t.Errorf("normalizeToolName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// drift.go — Behavioral drift detection for AI agent sessions
//
// Compares current session tool usage against a signed baseline.
// When an agent starts behaving differently (new tools, unusual frequency,
// write-heavy patterns), ASAF flags it and writes a signed drift event to the DAG.

package asaf

import (
	"math"
	"sort"
	"strings"
)

// BaselineProfile captures the expected behavior pattern for an agent type
type BaselineProfile struct {
	AgentType       string             `json:"agent_type"`
	ToolFrequencies map[string]float64 `json:"tool_frequencies"` // normalized 0-1
	AvgSessionLen   int                `json:"avg_session_len"`
	WriteRatio      float64            `json:"write_ratio"`
}

// DefaultBaselines provides expected behavior patterns for known agent types.
// These are starting points — real baselines are built from actual session data.
var DefaultBaselines = map[string]*BaselineProfile{
	"claude-code": {
		AgentType: "claude-code",
		ToolFrequencies: map[string]float64{
			"read_file":    0.35,
			"write_file":   0.20,
			"list_dir":     0.15,
			"search":       0.10,
			"run_command":  0.10,
			"edit_file":    0.10,
		},
		AvgSessionLen: 25,
		WriteRatio:    0.30,
	},
	"copilot": {
		AgentType: "copilot",
		ToolFrequencies: map[string]float64{
			"read_file":        0.40,
			"write_file":       0.30,
			"completion":       0.20,
			"inline_suggest":   0.10,
		},
		AvgSessionLen: 40,
		WriteRatio:    0.40,
	},
	"cursor": {
		AgentType: "cursor",
		ToolFrequencies: map[string]float64{
			"read_file":    0.30,
			"edit_file":    0.25,
			"write_file":   0.15,
			"run_command":  0.15,
			"search":       0.15,
		},
		AvgSessionLen: 30,
		WriteRatio:    0.40,
	},
}

// ComputeDriftScore calculates cosine distance between observed and baseline tool usage
func ComputeDriftScore(observed map[string]int, baseline *BaselineProfile) float64 {
	if baseline == nil || len(observed) == 0 {
		return 0.0
	}

	// Normalize observed to frequency distribution
	total := 0
	for _, count := range observed {
		total += count
	}
	if total == 0 {
		return 0.0
	}

	obsFreq := make(map[string]float64)
	for tool, count := range observed {
		obsFreq[normalizeToolName(tool)] = float64(count) / float64(total)
	}

	// Collect all tool names from both sets
	allTools := make(map[string]bool)
	for t := range obsFreq {
		allTools[t] = true
	}
	for t := range baseline.ToolFrequencies {
		allTools[t] = true
	}

	// Sort for deterministic computation
	tools := make([]string, 0, len(allTools))
	for t := range allTools {
		tools = append(tools, t)
	}
	sort.Strings(tools)

	// Compute cosine similarity
	var dotProduct, magA, magB float64
	for _, t := range tools {
		a := obsFreq[t]
		b := baseline.ToolFrequencies[t]
		dotProduct += a * b
		magA += a * a
		magB += b * b
	}

	if magA == 0 || magB == 0 {
		return 1.0 // Maximum drift if one vector is zero
	}

	cosineSimilarity := dotProduct / (math.Sqrt(magA) * math.Sqrt(magB))

	// Convert similarity (0-1) to distance (0-1)
	// 0 = identical, 1 = completely different
	return 1.0 - cosineSimilarity
}

// normalizeToolName maps variant tool names to canonical forms
func normalizeToolName(tool string) string {
	lower := strings.ToLower(tool)

	// Map common variants
	switch {
	case strings.Contains(lower, "read"):
		return "read_file"
	case strings.Contains(lower, "write") || strings.Contains(lower, "create"):
		return "write_file"
	case strings.Contains(lower, "edit") || strings.Contains(lower, "replace"):
		return "edit_file"
	case strings.Contains(lower, "list") || strings.Contains(lower, "dir"):
		return "list_dir"
	case strings.Contains(lower, "search") || strings.Contains(lower, "grep") || strings.Contains(lower, "find"):
		return "search"
	case strings.Contains(lower, "command") || strings.Contains(lower, "exec") || strings.Contains(lower, "run"):
		return "run_command"
	default:
		return lower
	}
}

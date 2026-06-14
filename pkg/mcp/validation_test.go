package mcp

import (
	"strings"
	"testing"
)

// ─── ValidateToolArgs Tests ────────────────────────────────────────────────────

func TestValidateToolArgs_Clean(t *testing.T) {
	args := map[string]any{
		"target": "example.com",
		"port":   float64(443),
		"verbose": true,
	}
	if err := ValidateToolArgs(args); err != nil {
		t.Fatalf("expected clean args to pass: %v", err)
	}
}

func TestValidateToolArgs_PathTraversal(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
	}{
		{"dotdot in path", map[string]any{"file_path": "../../etc/shadow"}},
		{"dotdot in dir", map[string]any{"directory": "../../../root"}},
		{"dotdot in target", map[string]any{"target_path": "foo/../../../bar"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateToolArgs(tc.args)
			if err == nil {
				t.Fatal("expected path traversal error")
			}
			if err.Code != ErrCodePathTraversal {
				t.Errorf("expected code %s, got %s", ErrCodePathTraversal, err.Code)
			}
		})
	}
}

func TestValidateToolArgs_CommandInjection(t *testing.T) {
	cases := []struct {
		name string
		val  string
	}{
		{"subshell", "$(rm -rf /)"},
		{"backtick", "`whoami`"},
		{"semicolon rm", "; rm -rf /"},
		{"pipe to bash", "| bash -c 'echo pwned'"},
		{"eval", "eval(malicious)"},
		{"python import", "__import__('os').system('id')"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateToolArgs(map[string]any{"input": tc.val})
			if err == nil {
				t.Fatalf("expected injection error for: %s", tc.val)
			}
			if err.Code != ErrCodeCommandInjection {
				t.Errorf("expected code %s, got %s", ErrCodeCommandInjection, err.Code)
			}
		})
	}
}

func TestValidateToolArgs_InputTooLarge(t *testing.T) {
	large := strings.Repeat("A", MaxArgSize+1)
	err := ValidateToolArgs(map[string]any{"data": large})
	if err == nil {
		t.Fatal("expected size limit error")
	}
	if err.Code != ErrCodeInputTooLarge {
		t.Errorf("expected code %s, got %s", ErrCodeInputTooLarge, err.Code)
	}
}

func TestValidateToolArgs_NestedArgs(t *testing.T) {
	args := map[string]any{
		"config": map[string]any{
			"nested": map[string]any{
				"file_path": "../../etc/passwd",
			},
		},
	}
	err := ValidateToolArgs(args)
	if err == nil {
		t.Fatal("expected nested path traversal error")
	}
}

func TestValidateToolArgs_ArrayArgs(t *testing.T) {
	args := map[string]any{
		"targets": []any{"safe.com", "$(rm -rf /)"},
	}
	err := ValidateToolArgs(args)
	if err == nil {
		t.Fatal("expected injection error in array")
	}
}

// ─── Rate Limiter Tests ────────────────────────────────────────────────────────

func TestRateLimiter_AllowsWithinLimit(t *testing.T) {
	rl := NewRateLimiter(60000, 5)
	for i := 0; i < 5; i++ {
		if err := rl.Allow("agent-1"); err != nil {
			t.Fatalf("request %d should be allowed: %v", i+1, err)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(60000, 3)
	for i := 0; i < 3; i++ {
		rl.Allow("agent-1")
	}
	if err := rl.Allow("agent-1"); err == nil {
		t.Fatal("expected rate limit error")
	}
}

func TestRateLimiter_IndependentAgents(t *testing.T) {
	rl := NewRateLimiter(60000, 2)
	rl.Allow("agent-1")
	rl.Allow("agent-1")
	// agent-2 should not be affected by agent-1
	if err := rl.Allow("agent-2"); err != nil {
		t.Fatalf("agent-2 should be allowed: %v", err)
	}
}

// ─── Mistake Tracker Tests ─────────────────────────────────────────────────────

func TestMistakeTracker_RecordSuccess(t *testing.T) {
	mt := NewMistakeTracker(MistakeTrackerConfig{MaxConsecutiveErrors: 3})
	mt.RecordError("agent-1")
	mt.RecordError("agent-1")
	mt.RecordSuccess("agent-1") // should reset
	if err := mt.RecordError("agent-1"); err != nil {
		t.Fatalf("should be allowed after reset: %v", err)
	}
}

func TestMistakeTracker_ExceedsLimit(t *testing.T) {
	mt := NewMistakeTracker(MistakeTrackerConfig{MaxConsecutiveErrors: 3})
	for i := 0; i < 2; i++ {
		if err := mt.RecordError("agent-1"); err != nil {
			t.Fatalf("error %d should be within limit", i+1)
		}
	}
	if err := mt.RecordError("agent-1"); err == nil {
		t.Fatal("expected mistake limit error")
	}
}

func TestMistakeTracker_LoopDetection(t *testing.T) {
	mt := NewMistakeTracker(MistakeTrackerConfig{
		LoopWindow:    5,
		LoopThreshold: 3,
	})
	for i := 0; i < 2; i++ {
		if err := mt.CheckLoop("agent-1", "scan", "same-args"); err != nil {
			t.Fatalf("loop %d should be allowed", i+1)
		}
	}
	if err := mt.CheckLoop("agent-1", "scan", "same-args"); err == nil {
		t.Fatal("expected loop detection")
	}
}

func TestMistakeTracker_ResetAgent(t *testing.T) {
	mt := NewMistakeTracker(MistakeTrackerConfig{MaxConsecutiveErrors: 3})
	mt.RecordError("agent-1")
	mt.RecordError("agent-1")
	mt.ResetAgent("agent-1")
	if err := mt.RecordError("agent-1"); err != nil {
		t.Fatal("should be allowed after reset")
	}
}

// ─── Identity Tests ────────────────────────────────────────────────────────────

func TestIdentity_HasScope(t *testing.T) {
	id := Identity{Scopes: []string{"ert:scan", "nhi:view"}}
	if !id.HasScope("ert:scan") {
		t.Error("should have ert:scan")
	}
	if id.HasScope("acp:revoke") {
		t.Error("should not have acp:revoke")
	}
}

func TestIdentity_WildcardScope(t *testing.T) {
	id := Identity{Scopes: []string{"*"}}
	if !id.HasScope("anything") {
		t.Error("wildcard should match anything")
	}
}

// ─── Manifest Registry Tests ───────────────────────────────────────────────────

func TestManifestRegistry_GetTool(t *testing.T) {
	spec := testToolSpec()
	reg := &ManifestRegistry{
		byName: map[string]ToolSpec{spec.Name: spec},
	}
	got, ok := reg.GetTool("ert_scan")
	if !ok {
		t.Fatal("should find ert_scan")
	}
	if got.Name != spec.Name {
		t.Errorf("name mismatch: got %q want %q", got.Name, spec.Name)
	}
}

func TestManifestRegistry_ValidatePinnedSchema(t *testing.T) {
	spec := testToolSpec()
	reg := &ManifestRegistry{
		byName: map[string]ToolSpec{spec.Name: spec},
	}
	if err := reg.ValidatePinnedSchema("ert_scan", "1.0.0", "abc123"); err != nil {
		t.Fatalf("valid schema should pass: %v", err)
	}
	if err := reg.ValidatePinnedSchema("ert_scan", "2.0.0", "abc123"); err == nil {
		t.Fatal("version mismatch should fail")
	}
	if err := reg.ValidatePinnedSchema("ert_scan", "1.0.0", "wrong"); err == nil {
		t.Fatal("hash mismatch should fail")
	}
}

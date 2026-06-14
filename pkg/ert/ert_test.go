package ert

import (
	"testing"
)

func TestNewEngine(t *testing.T) {
	// Simple smoke test
	engine, err := NewEngine(".", "test-tenant", nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
}

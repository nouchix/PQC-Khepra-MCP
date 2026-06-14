package webui

import (
	"testing"
)

func TestNewMockDAGProvider(t *testing.T) {
	provider := NewMockDAGProvider()
	if provider == nil {
		t.Fatal("NewMockDAGProvider returned nil")
	}

	nodes, err := provider.GetAllNodes()
	if err != nil {
		t.Fatalf("GetAllNodes returned error: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("Mock provider should assume some initial nodes")
	}
}

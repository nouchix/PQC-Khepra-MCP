package dag

import (
	"testing"
	"time"
)

func TestMemoryStore(t *testing.T) {
	m := NewMemory()

	// Genesis
	n1 := &Node{Symbol: "test1", Time: time.Now().Format(time.RFC3339)}
	if err := m.Add(n1, nil); err != nil {
		t.Fatalf("Failed to add genesis node: %v", err)
	}

	// Child
	n2 := &Node{Symbol: "test2", Time: time.Now().Format(time.RFC3339)}
	if err := m.Add(n2, []string{n1.ID}); err != nil {
		t.Fatalf("Failed to add child node: %v", err)
	}

	// Invalid Parent
	n3 := &Node{ID: "n3", Symbol: "test3", Time: time.Now().Format(time.RFC3339)}
	if err := m.Add(n3, []string{"ghost"}); err == nil {
		t.Fatal("Expected error adding node with non-existent parent, got nil")
	}

	// State check
	all := m.All()
	if len(all) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(all))
	}
}

package scanner

import (
	"testing"
)

func TestNewScannerDefaults(t *testing.T) {
	s := New()
	if s.Concurrency != 1000 {
		t.Errorf("Expected Default Concurrency 1000, got %d", s.Concurrency)
	}
	if len(s.Ports) < 1 {
		t.Error("Expected default ports to be loaded")
	}
}

func TestFocusPorts(t *testing.T) {
	s := New()
	// Reset ports for deterministic test
	s.Ports = []int{80, 443, 22}

	intel := []int{8080, 22, 9000} // Includes new (8080, 9000) and existing (22)

	s.FocusPorts(intel)

	// Expected Order: [8080, 22, 9000, 80, 443] (Intel first, then remaining sorted)
	// Note: The logic in tcp.go appends `remaining` which is `unique` map keys.
	// Map iteration order is random, wait.
	// Looking at tcp.go:82 `sort.Ints(remaining)` -> So the tail is sorted.
	// Head is `intel` in order.

	expectedHead := []int{8080, 22, 9000}
	if len(s.Ports) != 5 {
		t.Fatalf("Expected 5 ports, got %d", len(s.Ports))
	}

	// Check Head
	for i, p := range expectedHead {
		if s.Ports[i] != p {
			t.Errorf("Index %d: Expected %d, got %d", i, p, s.Ports[i])
		}
	}

	// Check Tail (Sorted)
	// Remaining: 80, 443. Sorted: 80, 443.
	if s.Ports[3] != 80 || s.Ports[4] != 443 {
		t.Errorf("Tail not sorted correctly: %v", s.Ports[3:])
	}
}

func TestIdentifyService(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{80, "HTTP"},
		{443, "HTTPS"},
		{22, "SSH"},
		{1337, "Unknown"},
	}

	for _, tt := range tests {
		got := identifyService(tt.port)
		if got != tt.expected {
			t.Errorf("Port %d: Expected %s, got %s", tt.port, tt.expected, got)
		}
	}
}

func TestSetFullScan(t *testing.T) {
	s := New()
	s.SetFullScan()
	if len(s.Ports) != 65535 {
		t.Errorf("Expected 65535 ports, got %d", len(s.Ports))
	}
	if s.Ports[0] != 1 || s.Ports[65534] != 65535 {
		t.Error("Full scan range mismatch")
	}
}

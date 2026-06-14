package sonar

import (
	"context"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

func TestUnifiedScanRequest(t *testing.T) {
	req := UnifiedScanRequest{
		Target:    "127.0.0.1",
		ScanTypes: []ScanType{ScanTypePort},
		Ports:     []int{22, 80, 443},
		Timeout:   30 * time.Second,
	}

	if req.Target == "" {
		t.Error("Target should not be empty")
	}

	if len(req.ScanTypes) != 1 {
		t.Errorf("Expected 1 scan type, got %d", len(req.ScanTypes))
	}

	if len(req.Ports) != 3 {
		t.Errorf("Expected 3 ports, got %d", len(req.Ports))
	}
}

func TestScanTypeConstants(t *testing.T) {
	types := []ScanType{
		ScanTypePort,
		ScanTypeCrawler,
		ScanTypeFull,
	}

	for _, st := range types {
		if st == "" {
			t.Error("Scan type should not be empty")
		}
	}

	if ScanTypePort != "port_scan" {
		t.Errorf("Expected 'port_scan', got '%s'", ScanTypePort)
	}

	// ScanTypeOSINT was permanently removed (OSINT/Shodan/Censys telemetry eliminated).
}

func TestNewUnifiedOrchestrator(t *testing.T) {
	store := dag.GlobalDAG()
	orch := NewUnifiedOrchestrator(nil, store, nil)

	if orch == nil {
		t.Fatal("Expected non-nil orchestrator")
	}

	if orch.store == nil {
		t.Error("Store should be set")
	}

	if orch.running == nil {
		t.Error("Running map should be initialized")
	}
}

func TestUnifiedOrchestrator_GetRunningScans(t *testing.T) {
	store := dag.GlobalDAG()
	orch := NewUnifiedOrchestrator(nil, store, nil)

	// Initially empty
	running := orch.GetRunningScans()
	if len(running) != 0 {
		t.Errorf("Expected 0 running scans, got %d", len(running))
	}
}

func TestUnifiedScanResult(t *testing.T) {
	result := &UnifiedScanResult{
		RequestID: "test-scan-001",
		Target:    "127.0.0.1",
		StartTime: time.Now().UTC(),
	}

	if result.RequestID == "" {
		t.Error("RequestID should not be empty")
	}

	if result.Target == "" {
		t.Error("Target should not be empty")
	}

	if result.StartTime.IsZero() {
		t.Error("StartTime should not be zero")
	}
}

func TestContainsHelper(t *testing.T) {
	// ScanTypeOSINT was permanently removed (OSINT/Shodan/Censys telemetry eliminated).
	// Test only existing constants.
	types := []ScanType{ScanTypePort, ScanTypeCrawler}

	if !contains(types, ScanTypePort) {
		t.Error("Should contain ScanTypePort")
	}

	if !contains(types, ScanTypeCrawler) {
		t.Error("Should contain ScanTypeCrawler")
	}

	if contains(types, ScanTypeFull) {
		t.Error("Should not contain ScanTypeFull")
	}
}

func TestUnifiedOrchestrator_ConcurrentScanPrevention(t *testing.T) {
	store := dag.GlobalDAG()
	orch := NewUnifiedOrchestrator(nil, store, nil)

	// Simulate a running scan
	orch.mu.Lock()
	orch.running["192.168.1.1"] = true
	orch.mu.Unlock()

	// Try to start another scan for the same target
	ctx := context.Background()
	req := UnifiedScanRequest{
		Target:    "192.168.1.1",
		ScanTypes: []ScanType{ScanTypePort},
		Timeout:   1 * time.Second,
	}

	_, err := orch.ExecuteScan(ctx, req)
	if err == nil {
		t.Error("Expected error for duplicate scan")
	}

	// Clean up
	orch.mu.Lock()
	delete(orch.running, "192.168.1.1")
	orch.mu.Unlock()
}

func TestUnifiedScanResult_Duration(t *testing.T) {
	start := time.Now().UTC()
	time.Sleep(10 * time.Millisecond)
	end := time.Now().UTC()

	result := &UnifiedScanResult{
		StartTime: start,
		EndTime:   end,
		Duration:  end.Sub(start),
	}

	if result.Duration < 10*time.Millisecond {
		t.Error("Duration should be at least 10ms")
	}
}

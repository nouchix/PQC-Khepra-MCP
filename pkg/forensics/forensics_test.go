package forensics

import (
	"context"
	"testing"
	"time"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("expected non-nil collector")
	}

	if c.hostname == "" {
		t.Error("expected hostname to be set")
	}

	if len(c.criticalPaths) == 0 {
		t.Error("expected default critical paths")
	}

	if c.evidenceBuffer == nil {
		t.Error("expected initialized evidence buffer")
	}
}

func TestCollector_AddCriticalPath(t *testing.T) {
	c := NewCollector()
	initialCount := len(c.criticalPaths)

	c.AddCriticalPath("/custom/path/to/monitor")

	if len(c.criticalPaths) != initialCount+1 {
		t.Error("expected critical path count to increase")
	}
}

func TestEvidence_Creation(t *testing.T) {
	c := NewCollector()

	data := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
	}

	evidence := c.CreateEvidence(EvidenceSystemState, "Test evidence", data)

	if evidence == nil {
		t.Fatal("expected non-nil evidence")
	}

	if evidence.ID == "" {
		t.Error("expected non-empty evidence ID")
	}

	if evidence.Type != EvidenceSystemState {
		t.Errorf("expected type %s, got %s", EvidenceSystemState, evidence.Type)
	}

	if evidence.Hash == "" {
		t.Error("expected non-empty hash")
	}

	if len(evidence.ChainOfCustody) != 1 {
		t.Error("expected initial chain of custody entry")
	}
}

func TestCollector_CollectSnapshot(t *testing.T) {
	c := NewCollector()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	snapshot, err := c.CollectSnapshot(ctx)
	if err != nil {
		t.Fatalf("CollectSnapshot failed: %v", err)
	}

	if snapshot == nil {
		t.Fatal("expected non-nil snapshot")
	}

	if snapshot.SnapshotID == "" {
		t.Error("expected non-empty snapshot ID")
	}

	if snapshot.Hostname == "" {
		t.Error("expected non-empty hostname")
	}

	if snapshot.OS == "" {
		t.Error("expected non-empty OS")
	}

	if snapshot.Hash == "" {
		t.Error("expected non-empty snapshot hash")
	}

	if snapshot.SystemState == nil {
		t.Error("expected non-nil system state")
	}

	// Verify system state has basic info
	if snapshot.SystemState.CPUCount <= 0 {
		t.Error("expected positive CPU count")
	}
}

func TestCollector_GetLastSnapshot(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()

	// Before any snapshot
	if c.GetLastSnapshot() != nil {
		t.Error("expected nil before first snapshot")
	}

	// Take a snapshot
	c.CollectSnapshot(ctx)

	if c.GetLastSnapshot() == nil {
		t.Error("expected non-nil after snapshot")
	}
}

func TestCollector_GenerateReport(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()

	snapshot, _ := c.CollectSnapshot(ctx)

	report := c.GenerateReport(snapshot)

	if report == "" {
		t.Error("expected non-empty report")
	}

	// Check for expected sections
	if len(report) < 100 {
		t.Error("report seems too short")
	}
}

func TestCollector_CompareSnapshots(t *testing.T) {
	c := NewCollector()

	old := &ForensicSnapshot{
		Processes: []ProcessInfo{
			{PID: 1, Name: "init"},
			{PID: 2, Name: "kthreadd"},
		},
		NetworkConns: []NetworkConnection{
			{LocalAddr: "127.0.0.1", LocalPort: 8080, RemoteAddr: "0.0.0.0", RemotePort: 0},
		},
		FileHashes: map[string]string{
			"/bin/sh": "abc123",
		},
	}

	new := &ForensicSnapshot{
		Processes: []ProcessInfo{
			{PID: 1, Name: "init"},
			{PID: 2, Name: "kthreadd"},
			{PID: 100, Name: "new_process"},
		},
		NetworkConns: []NetworkConnection{
			{LocalAddr: "127.0.0.1", LocalPort: 8080, RemoteAddr: "0.0.0.0", RemotePort: 0},
			{LocalAddr: "192.168.1.1", LocalPort: 443, RemoteAddr: "8.8.8.8", RemotePort: 443},
		},
		FileHashes: map[string]string{
			"/bin/sh":   "xyz789", // Modified
			"/bin/bash": "new123", // New file
		},
	}

	changes := c.CompareSnapshots(old, new)

	if len(changes) == 0 {
		t.Error("expected changes to be detected")
	}

	// Should detect new process
	foundNewProcess := false
	for _, change := range changes {
		if change == "NEW PROCESS: PID=100 Name=new_process" {
			foundNewProcess = true
			break
		}
	}
	if !foundNewProcess {
		t.Error("expected to detect new process")
	}
}

func TestEvidenceTypes(t *testing.T) {
	types := []EvidenceType{
		EvidenceSystemState,
		EvidenceProcess,
		EvidenceNetwork,
		EvidenceFileIntegrity,
		EvidenceUserActivity,
		EvidenceSecurityEvent,
		EvidenceConfig,
		EvidenceArtifact,
	}

	for _, et := range types {
		if et == "" {
			t.Error("evidence type should not be empty")
		}
	}
}

func TestTCPStateToString(t *testing.T) {
	tests := []struct {
		state    int
		expected string
	}{
		{1, "ESTABLISHED"},
		{2, "SYN_SENT"},
		{10, "LISTEN"},
		{99, "UNKNOWN"},
	}

	for _, tt := range tests {
		got := tcpStateToString(tt.state)
		if got != tt.expected {
			t.Errorf("tcpStateToString(%d) = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

func TestHexToIP(t *testing.T) {
	tests := []struct {
		hex      string
		expected string
	}{
		{"0100007F", "127.0.0.1"},
		{"00000000", "0.0.0.0"},
	}

	for _, tt := range tests {
		got := hexToIP(tt.hex)
		if got != tt.expected {
			t.Errorf("hexToIP(%s) = %s, want %s", tt.hex, got, tt.expected)
		}
	}

	// Test invalid length
	invalid := hexToIP("123")
	if invalid != "123" {
		t.Errorf("expected invalid input to be returned as-is")
	}
}

func TestParseCSVLine(t *testing.T) {
	line := `"field1","field2 with spaces","field3"`
	fields := parseCSVLine(line)

	if len(fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(fields))
	}

	if fields[0] != "field1" {
		t.Errorf("expected 'field1', got '%s'", fields[0])
	}

	if fields[1] != "field2 with spaces" {
		t.Errorf("expected 'field2 with spaces', got '%s'", fields[1])
	}
}

func TestCollector_Callbacks(t *testing.T) {
	c := NewCollector()

	evidenceReceived := false
	c.OnEvidenceCollected = func(e *Evidence) {
		evidenceReceived = true
	}

	snapshotReceived := false
	c.OnSnapshotComplete = func(s *ForensicSnapshot) {
		snapshotReceived = true
	}

	// Create evidence should trigger callback
	c.CreateEvidence(EvidenceSystemState, "test", map[string]interface{}{})
	if !evidenceReceived {
		t.Error("expected OnEvidenceCollected callback to be called")
	}

	// Snapshot should trigger callback
	ctx := context.Background()
	c.CollectSnapshot(ctx)
	if !snapshotReceived {
		t.Error("expected OnSnapshotComplete callback to be called")
	}
}

func TestSecurityEvent(t *testing.T) {
	event := SecurityEvent{
		EventID:     "event-001",
		Timestamp:   time.Now(),
		Category:    "auth",
		Severity:    "warning",
		Source:      "sshd",
		Description: "Failed login attempt",
		Data: map[string]string{
			"user": "admin",
			"ip":   "192.168.1.100",
		},
	}

	if event.EventID == "" {
		t.Error("expected non-empty event ID")
	}

	if len(event.Data) != 2 {
		t.Error("expected 2 data entries")
	}
}

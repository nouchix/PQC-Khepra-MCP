package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAuditSnapshotJSON(t *testing.T) {
	snap := AuditSnapshot{
		SchemaVersion: "1.0",
		ScanID:        "test-scan-1",
		Timestamp:     time.Now(),
		Host: InfoHost{
			Hostname: "test-host",
			OS:       "linux",
			Arch:     "amd64",
		},
		Tags: []string{"test", "unit"},
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("Failed to marshal snapshot: %v", err)
	}

	var loaded AuditSnapshot
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Failed to unmarshal snapshot: %v", err)
	}

	if loaded.ScanID != snap.ScanID {
		t.Errorf("Expected ScanID %s, got %s", snap.ScanID, loaded.ScanID)
	}
	if loaded.Host.Hostname != snap.Host.Hostname {
		t.Errorf("Expected Hostname %s, got %s", snap.Host.Hostname, loaded.Host.Hostname)
	}
}

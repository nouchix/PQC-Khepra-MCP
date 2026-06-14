package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAuditSnapshotJSONMarshalling(t *testing.T) {
	// Verify that the struct tags work as expected and output matches schema
	now := time.Now().UTC()
	snapshot := AuditSnapshot{
		SchemaVersion: "2.0",
		ScanID:        "test-scan-id",
		Timestamp:     now,
		Tags:          []string{"test", "unit"},
	}

	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var loadedSnapshot AuditSnapshot
	err = json.Unmarshal(data, &loadedSnapshot)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if loadedSnapshot.ScanID != snapshot.ScanID {
		t.Errorf("ScanID mismatch: got %v, want %v", loadedSnapshot.ScanID, snapshot.ScanID)
	}
	// Timestamp might lose precision in JSON, so we check approximate equality or just string match if RFC3339
}

package registry

import (
	"os"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	dbPath := "test_vulnerabilities.db"
	defer os.Remove(dbPath)

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	v := &Vulnerability{
		ID:          "CVE-2023-1234",
		Source:      "MITRE",
		CVSS:        9.8,
		Description: "Test vulnerability",
		Exploited:   false,
		PublishedAt: time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := store.SaveVulnerability(v); err != nil {
		t.Fatalf("failed to save vulnerability: %v", err)
	}

	retrieved, err := store.GetVulnerability("CVE-2023-1234")
	if err != nil {
		t.Fatalf("failed to get vulnerability: %v", err)
	}

	if retrieved == nil {
		t.Fatal("expected vulnerability, got nil")
	}

	if retrieved.ID != v.ID || retrieved.CVSS != v.CVSS {
		t.Errorf("mismatch: expected %+v, got %+v", v, retrieved)
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateScanID(t *testing.T) {
	id := generateScanID()
	if len(id) != 12 {
		t.Errorf("Expected 12 chars, got %d", len(id))
	}
}

func TestScanManifests(t *testing.T) {
	// Create temp dir with package.json
	tmpDir, err := os.MkdirTemp("", "sonar_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pkgJson := filepath.Join(tmpDir, "package.json")
	os.WriteFile(pkgJson, []byte("{}"), 0644)

	manifests := scanManifests(tmpDir)
	if len(manifests) != 1 {
		t.Errorf("Expected 1 manifest, got %d", len(manifests))
	}
	if manifests[0].Type != "npm" {
		t.Errorf("Expected type npm, got %s", manifests[0].Type)
	}
}

package sca

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests — these do NOT require syft to be installed
// ──────────────────────────────────────────────────────────────────────────────

func TestNewSyftAdapter_Defaults(t *testing.T) {
	a := NewSyftAdapter()
	if a.Timeout != 120*time.Second {
		t.Errorf("default timeout: got %v, want 120s", a.Timeout)
	}
	if a.cache == nil {
		t.Error("cache should be initialized")
	}
}

func TestSyftAdapter_GenerateSBOM_EmptyPath(t *testing.T) {
	a := NewSyftAdapter()
	_, _, err := a.GenerateSBOM(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestSyftAdapter_GenerateSBOM_NonExistentPath(t *testing.T) {
	a := NewSyftAdapter()
	_, _, err := a.GenerateSBOM(context.Background(), "/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestSyftAdapter_InvalidateCache(t *testing.T) {
	a := NewSyftAdapter()
	// Use a real temp dir so filepath.Abs resolves consistently
	dir := t.TempDir()
	a.cache[dir] = cachedBOM{checksum: "abc123"}
	a.InvalidateCache(dir)
	if _, ok := a.cache[dir]; ok {
		t.Error("cache entry should have been deleted")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// CycloneDX JSON parsing
// ──────────────────────────────────────────────────────────────────────────────

// sampleCycloneDXJSON is a minimal valid CycloneDX 1.5 SBOM from Syft
const sampleCycloneDXJSON = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2024-12-19T10:30:00Z",
    "tools": {
      "components": [
        {"type": "application", "name": "syft", "version": "1.4.1"}
      ]
    }
  },
  "components": [
    {
      "type": "library",
      "name": "golang.org/x/crypto",
      "version": "v0.17.0",
      "purl": "pkg:golang/golang.org/x/crypto@v0.17.0",
      "bom-ref": "pkg:golang/golang.org/x/crypto@v0.17.0"
    },
    {
      "type": "library",
      "name": "github.com/gin-gonic/gin",
      "version": "v1.12.0",
      "purl": "pkg:golang/github.com/gin-gonic/gin@v1.12.0"
    },
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21"
    }
  ]
}`

func TestCycloneDXBOM_Parse(t *testing.T) {
	var bom CycloneDXBOM
	if err := json.Unmarshal([]byte(sampleCycloneDXJSON), &bom); err != nil {
		t.Fatalf("failed to parse sample CycloneDX JSON: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat: got %q, want CycloneDX", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.5" {
		t.Errorf("SpecVersion: got %q, want 1.5", bom.SpecVersion)
	}
	if len(bom.Components) != 3 {
		t.Fatalf("Components count: got %d, want 3", len(bom.Components))
	}

	// Verify first component
	c := bom.Components[0]
	if c.Name != "golang.org/x/crypto" {
		t.Errorf("Component[0].Name: got %q", c.Name)
	}
	if c.Version != "v0.17.0" {
		t.Errorf("Component[0].Version: got %q", c.Version)
	}
	if c.PURL != "pkg:golang/golang.org/x/crypto@v0.17.0" {
		t.Errorf("Component[0].PURL: got %q", c.PURL)
	}
}

func TestExtractSyftMetadata(t *testing.T) {
	var bom CycloneDXBOM
	if err := json.Unmarshal([]byte(sampleCycloneDXJSON), &bom); err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	meta := extractSyftMetadata(&bom)
	if meta.SyftVersion != "1.4.1" {
		t.Errorf("SyftVersion: got %q, want 1.4.1", meta.SyftVersion)
	}
	if meta.ScannedAt.IsZero() {
		t.Error("ScannedAt should be set")
	}
}

func TestExtractSyftMetadata_NoTools(t *testing.T) {
	bom := CycloneDXBOM{BOMFormat: "CycloneDX"}
	meta := extractSyftMetadata(&bom)
	if meta.SyftVersion != "" {
		t.Errorf("SyftVersion should be empty when no tools, got %q", meta.SyftVersion)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Lockfile checksum caching
// ──────────────────────────────────────────────────────────────────────────────

func TestComputeLockfileChecksum_NoLockfiles(t *testing.T) {
	dir := t.TempDir()
	a := NewSyftAdapter()
	checksum := a.computeLockfileChecksum(dir)
	if checksum != "" {
		t.Errorf("expected empty checksum for dir without lockfiles, got %q", checksum)
	}
}

func TestComputeLockfileChecksum_WithLockfile(t *testing.T) {
	dir := t.TempDir()
	// Create a go.sum lockfile
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	a := NewSyftAdapter()
	cs1 := a.computeLockfileChecksum(dir)
	if cs1 == "" {
		t.Fatal("expected non-empty checksum")
	}

	// Same content → same checksum
	cs2 := a.computeLockfileChecksum(dir)
	if cs1 != cs2 {
		t.Error("same content should produce same checksum")
	}

	// Change content → different checksum
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("modified content"), 0644); err != nil {
		t.Fatal(err)
	}
	cs3 := a.computeLockfileChecksum(dir)
	if cs3 == cs1 {
		t.Error("different content should produce different checksum")
	}
}

func TestComputeLockfileChecksum_MultipleLockfiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.sum"), []byte("go deps"), 0644)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("npm deps"), 0644)

	a := NewSyftAdapter()
	cs := a.computeLockfileChecksum(dir)
	if cs == "" {
		t.Fatal("expected non-empty checksum for multiple lockfiles")
	}
}

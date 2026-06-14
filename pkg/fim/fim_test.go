package fim

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFIMBaselineCycle(t *testing.T) {
	// 1. Setup Temp Directory
	tmpDir, err := os.MkdirTemp("", "fim_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// 2. Create Dummy Critical File
	critFile := filepath.Join(tmpDir, "critical.txt")
	content := []byte("confidential_data")
	if err := os.WriteFile(critFile, content, 0600); err != nil {
		t.Fatalf("Failed to write critical file: %v", err)
	}

	// 3. Initialize Watcher
	paths := []string{critFile}
	watcher, err := NewFIMWatcher(paths)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	// 4. Establish Baseline
	if err := watcher.EstablishBaseline(); err != nil {
		t.Fatalf("Failed to establish baseline: %v", err)
	}

	// Verify Hash
	hash, exists := watcher.GetBaselineHash(critFile)
	if !exists {
		t.Fatalf("Baseline missing for %s", critFile)
	}
	if len(hash) != 64 { // SHA256 hex length
		t.Errorf("Invalid hash length: %d", len(hash))
	}

	// 5. Export Baseline
	exportPath := filepath.Join(tmpDir, "baseline.json")
	if err := watcher.ExportBaseline(exportPath); err != nil {
		t.Fatalf("Failed to export baseline: %v", err)
	}

	// 6. Verify Export File Exists
	if _, err := os.Stat(exportPath); os.IsNotExist(err) {
		t.Fatalf("Export file not created")
	}

	// 7. Verify Import
	// Create fresh watcher
	newWatcher, _ := NewFIMWatcher(nil)
	if err := newWatcher.ImportBaseline(exportPath); err != nil {
		t.Fatalf("Failed to import baseline: %v", err)
	}

	importedHash, exists := newWatcher.GetBaselineHash(critFile)
	if !exists {
		t.Fatalf("Import failed to load hash for %s", critFile)
	}
	if importedHash != hash {
		t.Errorf("Hash mismatch. Original: %s, Imported: %s", hash, importedHash)
	}
}

func TestFIMStats(t *testing.T) {
	watcher, _ := NewFIMWatcher([]string{"/tmp/fake"})
	stats := watcher.Stats()

	if stats["status"] != "running" {
		t.Errorf("Expected status 'running', got %v", stats["status"])
	}
	if stats["monitored_files"] != 0 {
		t.Errorf("Expected 0 monitored files, got %v", stats["monitored_files"])
	}
}

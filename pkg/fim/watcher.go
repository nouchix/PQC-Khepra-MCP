package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FIMEvent represents a file integrity violation
type FIMEvent struct {
	FilePath     string    `json:"file_path"`
	EventType    string    `json:"event_type"` // WRITE, CHMOD, REMOVE, CREATE
	ExpectedHash string    `json:"expected_hash,omitempty"`
	ActualHash   string    `json:"actual_hash,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	Severity     string    `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	STIGControl  string    `json:"stig_control,omitempty"`
	Description  string    `json:"description"`
}

// FIMWatcher monitors critical files for unauthorized modifications
type FIMWatcher struct {
	watcher   *fsnotify.Watcher
	baselines map[string]string // filepath -> SHA256 hash
	critical  []string          // Paths to monitor
	events    chan FIMEvent
	errors    chan error
	stopCh    chan struct{}
	mu        sync.RWMutex
}

// DefaultCriticalPathsLinux returns default critical files for Linux systems
var DefaultCriticalPathsLinux = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/etc/ssh/ssh_host_*_key",
	"/etc/crontab",
	"/etc/cron.d/*",
	"/etc/hosts",
	"/etc/hosts.allow",
	"/etc/hosts.deny",
	"/boot/grub/grub.cfg",
	"/etc/fstab",
	"/etc/pam.d/*",
	"/etc/security/*",
}

// DefaultCriticalPathsWindows returns default critical files for Windows systems
var DefaultCriticalPathsWindows = []string{
	`C:\Windows\System32\config\SAM`,
	`C:\Windows\System32\config\SYSTEM`,
	`C:\Windows\System32\config\SECURITY`,
	`C:\Windows\System32\drivers\etc\hosts`,
	`C:\Windows\System32\config\SOFTWARE`,
	`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*`,
}

// NewFIMWatcher creates a new file integrity monitoring watcher
func NewFIMWatcher(criticalPaths []string) (*FIMWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	fw := &FIMWatcher{
		watcher:   watcher,
		baselines: make(map[string]string),
		critical:  criticalPaths,
		events:    make(chan FIMEvent, 100),
		errors:    make(chan error, 10),
		stopCh:    make(chan struct{}),
	}

	return fw, nil
}

// EstablishBaseline computes SHA256 hashes for all monitored files
func (fw *FIMWatcher) EstablishBaseline() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	for _, pattern := range fw.critical {
		// Expand glob patterns
		matches, err := filepath.Glob(pattern)
		if err != nil {
			fw.errors <- fmt.Errorf("glob pattern error for %s: %w", pattern, err)
			continue
		}

		// Handle exact paths (no glob match)
		if len(matches) == 0 {
			if _, err := os.Stat(pattern); err == nil {
				matches = []string{pattern}
			}
		}

		for _, path := range matches {
			// Skip directories
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if info.IsDir() {
				continue
			}

			// Compute baseline hash
			hash, err := fw.computeFileHash(path)
			if err != nil {
				fw.errors <- fmt.Errorf("failed to hash %s: %w", path, err)
				continue
			}

			fw.baselines[path] = hash

			// Add to fsnotify watcher
			if err := fw.watcher.Add(path); err != nil {
				fw.errors <- fmt.Errorf("failed to watch %s: %w", path, err)
			}
		}
	}

	return nil
}

// computeFileHash calculates SHA256 hash of a file
func (fw *FIMWatcher) computeFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Start begins monitoring for file integrity violations
func (fw *FIMWatcher) Start() {
	go fw.watchLoop()
}

// watchLoop monitors fsnotify events and generates FIM violations
func (fw *FIMWatcher) watchLoop() {
	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}
			fw.handleEvent(event)

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			fw.errors <- err

		case <-fw.stopCh:
			return
		}
	}
}

// handleEvent processes a single fsnotify event
func (fw *FIMWatcher) handleEvent(event fsnotify.Event) {
	fw.mu.RLock()
	expectedHash, exists := fw.baselines[event.Name]
	fw.mu.RUnlock()

	if !exists {
		return // Not a monitored file
	}

	fimEvent := FIMEvent{
		FilePath:  event.Name,
		Timestamp: time.Now(),
		Severity:  fw.determineSeverity(event.Name),
	}

	switch {
	case event.Op&fsnotify.Write == fsnotify.Write:
		fimEvent.EventType = "WRITE"
		fimEvent.Description = "Unauthorized file modification detected"

		// Verify hash changed
		actualHash, err := fw.computeFileHash(event.Name)
		if err != nil {
			fw.errors <- fmt.Errorf("failed to verify hash for %s: %w", event.Name, err)
			return
		}

		if actualHash != expectedHash {
			fimEvent.ExpectedHash = expectedHash
			fimEvent.ActualHash = actualHash
			fimEvent.STIGControl = fw.mapToSTIG(event.Name)
			fw.events <- fimEvent

			// Update baseline (optional - comment out for strict immutability)
			// fw.mu.Lock()
			// fw.baselines[event.Name] = actualHash
			// fw.mu.Unlock()
		}

	case event.Op&fsnotify.Chmod == fsnotify.Chmod:
		fimEvent.EventType = "CHMOD"
		fimEvent.Description = "File permissions changed"
		fimEvent.STIGControl = fw.mapToSTIG(event.Name)
		fw.events <- fimEvent

	case event.Op&fsnotify.Remove == fsnotify.Remove:
		fimEvent.EventType = "REMOVE"
		fimEvent.Description = "Critical file deleted"
		fimEvent.Severity = "CRITICAL" // Deletion is always critical
		fimEvent.STIGControl = fw.mapToSTIG(event.Name)
		fw.events <- fimEvent

	case event.Op&fsnotify.Rename == fsnotify.Rename:
		fimEvent.EventType = "RENAME"
		fimEvent.Description = "Critical file renamed/moved"
		fimEvent.Severity = "HIGH"
		fimEvent.STIGControl = fw.mapToSTIG(event.Name)
		fw.events <- fimEvent

	case event.Op&fsnotify.Create == fsnotify.Create:
		fimEvent.EventType = "CREATE"
		fimEvent.Description = "Unexpected file created in monitored directory"
		fimEvent.Severity = "MEDIUM"
		fw.events <- fimEvent
	}
}

// determineSeverity assigns severity based on file path
func (fw *FIMWatcher) determineSeverity(path string) string {
	// Critical system files
	critical := []string{
		"/etc/shadow",
		"/etc/sudoers",
		"SAM",
		"SYSTEM",
		"SECURITY",
	}

	for _, pattern := range critical {
		if contains(path, pattern) {
			return "CRITICAL"
		}
	}

	// High priority files
	high := []string{
		"/etc/passwd",
		"/etc/ssh",
		"/etc/pam.d",
		"sshd_config",
	}

	for _, pattern := range high {
		if contains(path, pattern) {
			return "HIGH"
		}
	}

	return "MEDIUM"
}

// mapToSTIG maps file paths to STIG control IDs
func (fw *FIMWatcher) mapToSTIG(path string) string {
	stigMap := map[string]string{
		"/etc/passwd":       "RHEL-08-010210", // Passwords must be restricted
		"/etc/shadow":       "RHEL-08-010160", // Shadow file permissions
		"/etc/sudoers":      "RHEL-08-010380", // Sudoers configuration
		"/etc/ssh/sshd_config": "RHEL-08-040300", // SSH configuration
		"SAM":               "WIN10-CC-000050", // Windows SAM protection
		"SYSTEM":            "WIN10-CC-000051", // Windows registry protection
	}

	for pattern, stig := range stigMap {
		if contains(path, pattern) {
			return stig
		}
	}

	return "GENERIC-FILE-INTEGRITY"
}

// Events returns the channel for FIM events
func (fw *FIMWatcher) Events() <-chan FIMEvent {
	return fw.events
}

// Errors returns the channel for errors
func (fw *FIMWatcher) Errors() <-chan error {
	return fw.errors
}

// Stop halts the FIM watcher
func (fw *FIMWatcher) Stop() error {
	close(fw.stopCh)
	return fw.watcher.Close()
}

// ExportBaseline saves the current baseline to a JSON file
func (fw *FIMWatcher) ExportBaseline(outputPath string) error {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	data, err := json.MarshalIndent(fw.baselines, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write baseline file: %w", err)
	}

	return nil
}

// ImportBaseline loads a previously saved baseline
func (fw *FIMWatcher) ImportBaseline(inputPath string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read baseline file: %w", err)
	}

	baselines := make(map[string]string)
	if err := json.Unmarshal(data, &baselines); err != nil {
		return fmt.Errorf("failed to unmarshal baseline: %w", err)
	}

	fw.baselines = baselines
	return nil
}

// GetBaselineHash returns the expected hash for a file
func (fw *FIMWatcher) GetBaselineHash(path string) (string, bool) {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	hash, exists := fw.baselines[path]
	return hash, exists
}

// UpdateBaseline manually updates the baseline for a file (use after authorized changes)
func (fw *FIMWatcher) UpdateBaseline(path string) error {
	hash, err := fw.computeFileHash(path)
	if err != nil {
		return fmt.Errorf("failed to compute new hash for %s: %w", path, err)
	}

	fw.mu.Lock()
	fw.baselines[path] = hash
	fw.mu.Unlock()

	return nil
}

// contains is a helper function for substring matching
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && s[len(s)-len(substr):] == substr || len(s) > len(substr) && s[:len(substr)] == substr)
}

// Stats returns statistics about monitored files
func (fw *FIMWatcher) Stats() map[string]interface{} {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	return map[string]interface{}{
		"monitored_files": len(fw.baselines),
		"patterns":        len(fw.critical),
		"status":          "running",
	}
}

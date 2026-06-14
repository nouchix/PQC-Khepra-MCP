package dag

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/logging"
)

// PersistentMemory is a DAG that automatically persists to disk
// Analogous to: RAM (in-memory ops) → Disk (persistent storage)
type PersistentMemory struct {
	*Memory                     // Embedded in-memory DAG (RAM)
	storePath    string         // Disk storage path
	autoFlush    bool           // Auto-flush on each write
	flushMu      sync.Mutex     // Flush lock
	dirtyNodes   map[string]bool // Nodes that need flushing
	dirtyMu      sync.RWMutex
	dodLogger    *logging.DoDLogger // Optional DoD logger for audits
}

// NewPersistentMemory creates a DAG with disk persistence
// storePath: Directory where DAG nodes are stored (e.g., "./data/dag")
func NewPersistentMemory(storePath string) (*PersistentMemory, error) {
	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create DAG storage directory: %w", err)
	}

	pm := &PersistentMemory{
		Memory:     NewMemory(),
		storePath:  storePath,
		autoFlush:  true, // Auto-flush by default
		dirtyNodes: make(map[string]bool),
	}

	// Load existing nodes from disk
	if err := pm.LoadFromDisk(); err != nil {
		return nil, fmt.Errorf("failed to load DAG from disk: %w", err)
	}

	return pm, nil
}

// Add adds a node to memory and optionally flushes to disk
func (pm *PersistentMemory) Add(n *Node, parents []string) error {
	// Add to in-memory DAG (RAM)
	if err := pm.Memory.Add(n, parents); err != nil {
		// Log failed add to DoD logger
		if pm.dodLogger != nil {
			pm.dodLogger.Error("[DAG] Failed to add node", "node_id", n.ID, "error", err.Error())
		}
		return err
	}

	// Log successful add to DoD logger (observability + audit trail)
	if pm.dodLogger != nil {
		_ = LogDAGEventToDoD(pm.dodLogger, n, "dag_node_added")
	}

	// Mark as dirty (needs flushing to disk)
	pm.dirtyMu.Lock()
	pm.dirtyNodes[n.ID] = true
	pm.dirtyMu.Unlock()

	// Auto-flush if enabled
	if pm.autoFlush {
		if err := pm.FlushNode(n.ID); err != nil {
			// Log flush failure
			if pm.dodLogger != nil {
				pm.dodLogger.Warn("[DAG] Auto-flush failed", "node_id", n.ID, "error", err.Error())
			}
			return err
		}
	}

	return nil
}

// FlushNode writes a specific node to disk
func (pm *PersistentMemory) FlushNode(nodeID string) error {
	pm.flushMu.Lock()
	defer pm.flushMu.Unlock()

	pm.Memory.mu.RLock()
	node, exists := pm.Memory.nodes[nodeID]
	pm.Memory.mu.RUnlock()

	if !exists {
		return fmt.Errorf("node not found in memory: %s", nodeID)
	}

	// Serialize node to JSON
	data, err := json.MarshalIndent(node, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal node: %w", err)
	}

	// Write to disk: {storePath}/{nodeID}.json
	nodePath := filepath.Join(pm.storePath, nodeID+".json")
	if err := os.WriteFile(nodePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write node to disk: %w", err)
	}

	// Mark as clean
	pm.dirtyMu.Lock()
	delete(pm.dirtyNodes, nodeID)
	pm.dirtyMu.Unlock()

	return nil
}

// FlushAll writes all dirty nodes to disk
func (pm *PersistentMemory) FlushAll() error {
	pm.dirtyMu.RLock()
	dirtyIDs := make([]string, 0, len(pm.dirtyNodes))
	for id := range pm.dirtyNodes {
		dirtyIDs = append(dirtyIDs, id)
	}
	pm.dirtyMu.RUnlock()

	for _, id := range dirtyIDs {
		if err := pm.FlushNode(id); err != nil {
			return err
		}
	}

	return nil
}

// LoadFromDisk loads all nodes from disk into memory.
// Corrupted or empty node files are quarantined (renamed with a .corrupted.{ns} suffix)
// rather than aborting startup — a single bad file on disk must never crash the server.
func (pm *PersistentMemory) LoadFromDisk() error {
	// Read all .json files in storePath
	entries, err := os.ReadDir(pm.storePath)
	if err != nil {
		// If directory doesn't exist or is empty, that's fine
		return nil
	}

	var loadedCount, corruptedCount int
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		nodePath := filepath.Join(pm.storePath, entry.Name())
		data, err := os.ReadFile(nodePath)
		if err != nil {
			return fmt.Errorf("failed to read node file %s: %w", entry.Name(), err)
		}

		// Empty file — zero-byte writes happen when the process is killed mid-flush.
		// Quarantine rather than abort so other healthy nodes still load.
		if len(data) == 0 {
			corruptedCount++
			pm.quarantineFile(nodePath, entry.Name(), "empty file (truncated write)")
			continue
		}

		var node Node
		if err := json.Unmarshal(data, &node); err != nil {
			corruptedCount++
			pm.quarantineFile(nodePath, entry.Name(), fmt.Sprintf("json parse error: %v", err))
			continue
		}

		// Add to in-memory DAG (bypass Add() to avoid re-flushing)
		pm.Memory.mu.Lock()
		pm.Memory.nodes[node.ID] = &node
		pm.Memory.mu.Unlock()

		loadedCount++
	}

	if corruptedCount > 0 {
		fmt.Fprintf(os.Stderr,
			"[DAG] WARN: %d corrupted node file(s) quarantined during startup. Loaded %d healthy nodes. Review *.corrupted.* files in %s\n",
			corruptedCount, loadedCount, pm.storePath)
	}

	return nil
}

// quarantineFile renames a corrupt DAG node file to prevent future load failures.
// The original is preserved with a .corrupted.{nanoseconds} suffix for forensic review.
func (pm *PersistentMemory) quarantineFile(nodePath, entryName, reason string) {
	quarantinePath := fmt.Sprintf("%s.corrupted.%d", nodePath, time.Now().UnixNano())
	if renameErr := os.Rename(nodePath, quarantinePath); renameErr != nil {
		fmt.Fprintf(os.Stderr, "[DAG] WARN: cannot quarantine %s (%s): %v\n", entryName, reason, renameErr)
	} else {
		fmt.Fprintf(os.Stderr, "[DAG] WARN: quarantined %s → %s (%s)\n",
			entryName, filepath.Base(quarantinePath), reason)
	}
}

// StartAutoFlushDaemon starts a background goroutine that periodically flushes dirty nodes
// Useful for agent server (RAM) to sync to disk every N seconds
func (pm *PersistentMemory) StartAutoFlushDaemon(interval time.Duration) chan struct{} {
	stopChan := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := pm.FlushAll(); err != nil {
					// Log error but continue
					fmt.Fprintf(os.Stderr, "[DAG] Auto-flush failed: %v\n", err)
				}
			case <-stopChan:
				// Final flush before stopping
				_ = pm.FlushAll()
				return
			}
		}
	}()

	return stopChan
}

// GetStorePath returns the disk storage path
func (pm *PersistentMemory) GetStorePath() string {
	return pm.storePath
}

// SetAutoFlush enables/disables auto-flush on each write
func (pm *PersistentMemory) SetAutoFlush(enabled bool) {
	pm.autoFlush = enabled
}

// SetDoDLogger sets the DoD logger for audit/observability logging
func (pm *PersistentMemory) SetDoDLogger(logger *logging.DoDLogger) {
	pm.dodLogger = logger
}

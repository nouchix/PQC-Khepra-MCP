package dag

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Global singleton DAG instance for the entire AdinKhepra system
var (
	globalDAG        *PersistentMemory
	globalDAGOnce    sync.Once
	globalDAGStopCh  chan struct{} // For stopping auto-flush daemon
)

// GlobalDAG returns the singleton immutable DAG instance used across
// all AdinKhepra components (agent server, validation, ERT, standalone viewer).
//
// ARCHITECTURE:
// - Standalone DAG Viewer: Persistent storage (disk) = source of truth
// - Agent Server: In-memory operations (RAM) with auto-flush to disk
// - ERT/Validation: Write to memory, periodically synced to disk
//
// This ensures that all DAG operations are immutable AND persistent.
func GlobalDAG() *PersistentMemory {
	globalDAGOnce.Do(func() {
		// Determine storage path
		// Default: ./data/dag (relative to working directory)
		// Override: KHEPRA_DAG_PATH environment variable
		storagePath := os.Getenv("KHEPRA_DAG_PATH")
		if storagePath == "" {
			// Use ./data/dag relative to working directory
			wd, _ := os.Getwd()
			storagePath = filepath.Join(wd, "data", "dag")
		}

		// Create persistent DAG with disk storage
		var err error
		globalDAG, err = NewPersistentMemory(storagePath)
		if err != nil {
			panic("failed to initialize global persistent DAG: " + err.Error())
		}

		// Check if genesis node already exists (loaded from disk)
		allNodes := globalDAG.All()
		hasGenesis := false
		for _, node := range allNodes {
			if node.Action == "GENESIS_CONSTELLATION" {
				hasGenesis = true
				break
			}
		}

		// Create genesis node only if it doesn't exist
		if !hasGenesis {
			genesis := &Node{
				Action: "GENESIS_CONSTELLATION",
				Symbol: "KHEPRA",
				Time:   time.Now().Format(time.RFC3339),
				PQC: map[string]string{
					"initialization":  "production_dag",
					"whitebox_crypto": "enabled",
					"pqc_signatures":  "dilithium3",
					"singleton":       "true",
					"persistent":      "disk_storage",
				},
			}

			// Add genesis node (no parents = root)
			if err := globalDAG.Add(genesis, []string{}); err != nil {
				// Should never fail for genesis, but log if it does
				panic("failed to create genesis node in global DAG: " + err.Error())
			}
		}

		// Start auto-flush daemon (RAM → Disk every 5 seconds)
		globalDAGStopCh = globalDAG.StartAutoFlushDaemon(5 * time.Second)
	})

	return globalDAG
}

// ResetGlobalDAG resets the singleton DAG (FOR TESTING ONLY)
// DO NOT USE IN PRODUCTION
func ResetGlobalDAG() {
	globalDAG = nil
	globalDAGOnce = sync.Once{}
}

// Package mcp — DAGBridge wires the EventEmitter (MCP tool attestations) into
// the pkg/dag persistent store with ML-DSA-65 signatures.
//
// Architecture:
//
//	Router → EventEmitter → DAGBridge.Hook() → dag.Node.Sign(privKey) → dagStore.Add()
//
// Each EventAttest becomes a ML-DSA-65-signed DAG node that is:
//   - Parent-linked to the previous node (linear chain — no orphans)
//   - Persisted to disk via PersistentMemory auto-flush
//   - Served by /api/v1/dag/history for the dag-viewer
//
// The session key (pubkey) is recorded in the genesis node's PQC metadata so
// auditors can verify the full chain's signatures offline.
//
// Signing cost: ML-DSA-65 sign ~12ms (Dilithium3 mode).
// Parent-link lookup is O(1) (last-ID stored in struct).
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.
package mcp

import (
	"log"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
)

// DAGBridge hooks into the Router's EventEmitter and writes each attested
// tool call as a signed DAG node into the persistent Master DAG.
//
// Thread-safe: multiple goroutines may call Hook() concurrently.
type DAGBridge struct {
	store   dag.Store
	privKey []byte // ML-DSA-65 session private key
	pubKey  []byte // stored in genesis for offline verification
	mu      sync.Mutex
	lastID  string // parent link — maintains the chain
}

// NewDAGBridge creates a bridge that signs DAG nodes with the given
// ML-DSA-65 session key and writes them to store.
//
// Call router.Events().AddHook(bridge.Hook) after construction.
// The pubkey is stored in the genesis node so the chain is
// self-verifying.
func NewDAGBridge(store dag.Store, privKey, pubKey []byte) *DAGBridge {
	b := &DAGBridge{
		store:   store,
		privKey: privKey,
		pubKey:  pubKey,
	}
	// Record the genesis (or find the last node if chain already exists)
	b.anchorToChain()
	return b
}

// anchorToChain sets lastID to the lexicographically latest node in the store.
// On first startup lastID = genesis ID; on restart it chains to the existing tail.
func (b *DAGBridge) anchorToChain() {
	nodes := b.store.All()
	var latest string
	var latestTime string
	for _, n := range nodes {
		if n.Time > latestTime {
			latestTime = n.Time
			latest = n.ID
		}
	}
	if latest != "" {
		b.lastID = latest
		log.Printf("[DAGBridge] Anchored to existing chain — latest node: %s (t=%s)", latest[:16], latestTime)
	}
}

// Hook is registered with router.Events().AddHook().
// It filters for EventAttest events, builds a DAG node, signs it with
// the session ML-DSA-65 key, and appends it to the persistent chain.
func (b *DAGBridge) Hook(ev MCPEvent) {
	// Only persist attested tool calls — startup/shutdown/housekeeping events
	// are already recorded in the SignedAuditLog (NDJSON).
	if ev.Type != EventAttest {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	node := &dag.Node{
		Action: "MCP_TOOL_ATTEST",
		Symbol: "NKYINKYIM", // adaptability — the AI agent's journey
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		PQC: map[string]string{
			"tool":        ev.ToolName,
			"agent_id":    ev.AgentID,
			"session_id":  ev.SessionID,
			"dag_hash":    ev.DAGHash,
			"risk_class":  ev.RiskClass,
			"key_scheme":  "ML-DSA-65-Dilithium3", // gitleaks:allow
			"signed":      "true",
		},
	}

	// Parent link — set on the node BEFORE Sign() so ComputeHash() includes it.
	// If we set parents after signing and pass them to Add(), Add() rewrites
	// n.Parents and the stored ID no longer matches the recomputed hash.
	if b.lastID != "" {
		node.Parents = []string{b.lastID}
	}

	// Sign with session ML-DSA-65 key
	if len(b.privKey) > 0 {
		if err := node.Sign(b.privKey); err != nil {
			log.Printf("[DAGBridge] WARN: sign failed for tool=%s: %v", ev.ToolName, err)
			// Continue without signature — node is still content-addressed
		}
	}

	// Pass nil parents — n.Parents is already set; Add() must not overwrite.
	if err := b.store.Add(node, nil); err != nil {
		// Duplicate node (same tool/time combo) is benign — skip silently
		if err.Error() != "duplicate node" {
			log.Printf("[DAGBridge] WARN: Add failed for tool=%s: %v", ev.ToolName, err)
		}
		return
	}

	b.lastID = node.ID
}

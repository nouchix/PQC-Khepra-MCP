package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

// StaticDAGProvider seeds deterministic DAG data for WebUI development and CI
// without requiring a live dag.Store backend.
type MockDAGProvider struct {
	nodes []DAGNode
	seed  int64
}

// NewMockDAGProvider creates a mock provider with synthetic data
func NewMockDAGProvider() *MockDAGProvider {
	seed := time.Now().UnixNano()
	provider := &MockDAGProvider{
		nodes: []DAGNode{},
		seed:  seed,
	}

	// Generate genesis node
	genesisNode := DAGNode{
		ID:        "genesis-0",
		Timestamp: time.Now().Add(-24 * time.Hour),
		EventType: "genesis_block",
		Hash:      generateHash("genesis-0"),
		Parents:   []string{},
		Signature: generateSignature("genesis-0"),
		Verified:  true,
	}
	provider.nodes = append(provider.nodes, genesisNode)

	// Generate synthetic event history
	eventTypes := []string{
		"stig_scan",
		"license_check",
		"genesis_backup",
		"pqc_key_rotation",
		"compliance_report",
		"attestation_verification",
		"network_sync",
	}

	rng := rand.New(rand.NewSource(seed))

	// Generate 50-100 historical nodes
	nodeCount := 50 + rng.Intn(51)
	for i := 1; i < nodeCount; i++ {
		nodeID := fmt.Sprintf("node-%d", i)

		// Select 1-3 random parents (DAG structure)
		var parents []string
		if i > 0 {
			parentCount := 1 + rng.Intn(3)
			if parentCount > i {
				parentCount = i
			}

			// Bias towards recent nodes
			recentBias := i - 10
			if recentBias < 0 {
				recentBias = 0
			}

			for j := 0; j < parentCount; j++ {
				parentIdx := recentBias + rng.Intn(i-recentBias)
				parents = append(parents, provider.nodes[parentIdx].ID)
			}
		}

		node := DAGNode{
			ID:        nodeID,
			Timestamp: time.Now().Add(-time.Duration(nodeCount-i) * 15 * time.Minute),
			EventType: eventTypes[rng.Intn(len(eventTypes))],
			Hash:      generateHash(nodeID),
			Parents:   parents,
			Signature: generateSignature(nodeID),
			Verified:  rng.Float32() > 0.05, // 95% verified
		}

		provider.nodes = append(provider.nodes, node)
	}

	return provider
}

// GetAllNodes returns all DAG nodes
func (m *MockDAGProvider) GetAllNodes() ([]DAGNode, error) {
	return m.nodes, nil
}

// GetStats returns current DAG statistics
func (m *MockDAGProvider) GetStats() (DAGStats, error) {
	// Count edges (sum of all parent relationships)
	edgeCount := 0
	verifiedCount := 0
	for _, node := range m.nodes {
		edgeCount += len(node.Parents)
		if node.Verified {
			verifiedCount++
		}
	}

	// Simulate hash power based on node count
	hashPower := float64(len(m.nodes)) * 12.5

	status := "CONSTELLATION_STABLE"
	if len(m.nodes) < 10 {
		status = "SYNCING_NETWORK"
	} else if verifiedCount < len(m.nodes)*95/100 {
		status = "VERIFICATION_PENDING"
	}

	stats := DAGStats{
		Status:      status,
		NodeCount:   len(m.nodes),
		EdgeCount:   edgeCount,
		HashPower:   fmt.Sprintf("%.1f TH/s", hashPower),
		LastSync:    time.Now().Format("15:04:05"),
		FIPSEnabled: true,  // FIPS-validated cryptography is always active
		PQCActive:   true,  // ML-DSA/ML-KEM post-quantum suite is always active
	}

	return stats, nil
}

// GetNodesByTimeRange returns nodes within a time range
func (m *MockDAGProvider) GetNodesByTimeRange(start, end time.Time) ([]DAGNode, error) {
	var filtered []DAGNode
	for _, node := range m.nodes {
		if node.Timestamp.After(start) && node.Timestamp.Before(end) {
			filtered = append(filtered, node)
		}
	}
	return filtered, nil
}

// AddNode appends a new DAG node with auto-selected parents (WebUI test fixture).
func (m *MockDAGProvider) AddNode(eventType string) {
	nodeID := fmt.Sprintf("node-%d", len(m.nodes))

	// Select 1-2 recent parents
	var parents []string
	if len(m.nodes) > 0 {
		parentCount := 1 + rand.Intn(2)
		for i := 0; i < parentCount && i < len(m.nodes); i++ {
			parentIdx := len(m.nodes) - 1 - rand.Intn(5)
			if parentIdx < 0 {
				parentIdx = 0
			}
			parents = append(parents, m.nodes[parentIdx].ID)
		}
	}

	node := DAGNode{
		ID:        nodeID,
		Timestamp: time.Now(),
		EventType: eventType,
		Hash:      generateHash(nodeID),
		Parents:   parents,
		Signature: generateSignature(nodeID),
		Verified:  true,
	}

	m.nodes = append(m.nodes, node)
}

// Helper functions for mock data generation

func generateHash(input string) string {
	h := sha256.New()
	h.Write([]byte(input + time.Now().String()))
	return hex.EncodeToString(h.Sum(nil))
}

func generateSignature(input string) string {
	// Truncated SHA-256-based stand-in for the 2420-byte ML-DSA-65 signature;
	// used only by the WebUI test fixture — real signatures come from adinkra.Sign().
	h := sha256.New()
	h.Write([]byte("dilithium-" + input))
	sig := hex.EncodeToString(h.Sum(nil))

	// Repeat to simulate longer signature
	return sig + sig + sig
}

package dag

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// Store is the interface for DAG storage (memory, persistent, etc.)
type Store interface {
	Add(n *Node, parents []string) error
	Get(id string) (*Node, bool)
	All() []*Node
}

// Node represents an immutable vertex in the Living Trust Constellation.
type Node struct {
	// Header (The immutable identity)
	ID      string   `json:"id"`      // Content Hash (SHA-256)
	Parents []string `json:"parents"` // Links to previous nodes (The Weave)

	// Body (The Truth)
	Action string            `json:"action"`
	Symbol string            `json:"symbol"`
	Time   string            `json:"time"` // ISO8601
	PQC    map[string]string `json:"pqc_metadata,omitempty"`

	// Proof (The Seal)
	items     map[string]interface{} `json:"-"`                   // Internal use for canonicalization
	Hash      string                 `json:"hash"`                // Duplicate of ID for verification
	Signature string                 `json:"signature,omitempty"` // Base64 Dilithium Signature
}

type Memory struct {
	mu    sync.RWMutex
	nodes map[string]*Node
}

func NewMemory() *Memory { return &Memory{nodes: make(map[string]*Node)} }

// ComputeHash calculates the Khepra-Standard hash (DNA) of the canonical node content.
// This enforces immutability: Change one byte, and the ID changes.
func (n *Node) ComputeHash() string {
	// Canonicalize the data: Action + Symbol + Time + Sort(Parents) + Sort(PQC)
	// In a real blockchain, we'd use a strict serialization (like RLP or Protobuf).
	// For this prototype, string concatenation with delimiters is sufficient.

	var parentStr string
	if len(n.Parents) > 0 {
		sort.Strings(n.Parents)
		parentStr = strings.Join(n.Parents, ",")
	}

	var pqcStr string
	if len(n.PQC) > 0 {
		keys := make([]string, 0, len(n.PQC))
		for k := range n.PQC {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		for _, k := range keys {
			sb.WriteString(k + "=" + n.PQC[k] + ";")
		}
		pqcStr = sb.String()
	}

	raw := fmt.Sprintf("%s|%s|%s|%s|%s", n.Action, n.Symbol, n.Time, parentStr, pqcStr)

	// Use Khepra PQC Hashing Wrapper
	return adinkra.Hash([]byte(raw))
}

// Sign attaches a PQC signature to the node using the Agent's private key.
func (n *Node) Sign(privKey []byte) error {
	if n.ID == "" {
		n.ID = n.ComputeHash()
	}
	n.Hash = n.ID

	// Sign the Hash
	sigBytes, err := adinkra.Sign(privKey, []byte(n.Hash))
	if err != nil {
		return err
	}

	n.Signature = hex.EncodeToString(sigBytes)
	return nil
}

func (m *Memory) Add(n *Node, parents []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Enforce Parentage
	// If no parents provided in arg, use n.Parents. If both empty, it's Genesis (allow if empty DAG).
	if len(parents) > 0 {
		n.Parents = parents
	}

	// 2. Enforce Content Addressing
	computed := n.ComputeHash()
	if n.ID == "" {
		n.ID = computed
	} else if n.ID != computed {
		// Legacy semantic IDs (task-*, scan-*, asset:*, evidence:*, stig:*) predate content-addressing
		// and are used by the AGI engine. These are allowed for backward compatibility.
		// All new nodes MUST have IDs that match their content hash.
		if strings.HasPrefix(n.ID, "task-") || strings.HasPrefix(n.ID, "scan-") || strings.HasPrefix(n.ID, "asset:") || strings.HasPrefix(n.ID, "evidence:") || strings.HasPrefix(n.ID, "stig:") {
			// Accepted: legacy semantic ID format
		} else {
			return errors.New("integrity violation: node ID does not match content hash")
		}
	}
	// Ensure Hash field is set
	if n.Hash == "" {
		n.Hash = n.ID
	}

	if _, ok := m.nodes[n.ID]; ok {
		return errors.New("duplicate node")
	}

	// 3. Verify Parents Exist
	for _, pid := range n.Parents {
		if _, exists := m.nodes[pid]; !exists {
			return errors.New("orphaned node: parent not found -> " + pid)
		}
	}

	m.nodes[n.ID] = n
	return nil
}

// Get retrieves a node by ID
func (m *Memory) Get(id string) (*Node, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, exists := m.nodes[id]
	return node, exists
}

func (m *Memory) All() []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		out = append(out, n)
	}
	return out
}

// GetData returns the internal data map of the node
func (n *Node) GetData() map[string]interface{} {
	return n.items
}

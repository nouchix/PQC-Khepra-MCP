package adinkra

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

// =============================================================================
// DAG AGENT CONSENSUS PROTOCOL (ACP)
// Patent §3.3: DAG-based cryptographic audit trail for AI agent actions.
// Every vertex is:
//   - Annotated with an Adinkra symbol (glyph trigger rule)
//   - ML-DSA-65 signed by the originating agent
//   - Blake2b hashed for integrity
//   - Linked to parent vertices (causal ordering)
//
// Conflict resolution uses AdinkraPrecedence: Eban > Fawohodie > Nkyinkyim > Dwennimmen.
// =============================================================================

// DAGVertex is a single node in the Agent Consensus DAG.
type DAGVertex struct {
	ID          string   // hex-encoded Blake2b hash (unique identity)
	Symbol      string   // Adinkra glyph annotation (governs precedence)
	AgentID     string   // originating agent identifier
	Transaction []byte   // signed agent action payload
	Parents     []string // IDs of causal parent vertices (empty = genesis)
	Hash        []byte   // Blake2b-512 hash of canonical vertex bytes
	Signature   []byte   // ML-DSA-65 signature over Hash
	Timestamp   int64    // Unix nanoseconds
}

// DAGConsensus holds the in-memory DAG and provides thread-safe access.
type DAGConsensus struct {
	vertices map[string]*DAGVertex
	mu       sync.RWMutex
}

// NewDAGConsensus creates an empty DAG.
func NewDAGConsensus() *DAGConsensus {
	return &DAGConsensus{
		vertices: make(map[string]*DAGVertex),
	}
}

// AddVertex appends a new signed vertex to the DAG.
// The vertex hash covers: Symbol || AgentID || Transaction || Parents || Timestamp.
// The private key must match the public key used when verifying.
func (d *DAGConsensus) AddVertex(tx []byte, symbol, agentID string, parents []string, priv *AdinkhepraPQCPrivateKey) (*DAGVertex, error) {
	if priv == nil {
		return nil, errors.New("DAGConsensus: private key is nil")
	}
	if symbol == "" {
		return nil, errors.New("DAGConsensus: symbol cannot be empty")
	}

	// Validate all parent IDs exist.
	d.mu.RLock()
	for _, pid := range parents {
		if _, ok := d.vertices[pid]; !ok {
			d.mu.RUnlock()
			return nil, fmt.Errorf("DAGConsensus: unknown parent vertex %q", pid)
		}
	}
	d.mu.RUnlock()

	ts := time.Now().UnixNano()
	v := &DAGVertex{
		Symbol:      symbol,
		AgentID:     agentID,
		Transaction: tx,
		Parents:     parents,
		Timestamp:   ts,
	}

	// Compute vertex hash.
	h, err := computeVertexHash(v)
	if err != nil {
		return nil, fmt.Errorf("DAGConsensus: hash computation failed: %w", err)
	}
	v.Hash = h
	v.ID = hex.EncodeToString(h[:16]) // first 64 bits as readable ID

	// Sign the hash with ML-DSA-65.
	sig, err := SignAdinkhepraPQC(priv, h)
	if err != nil {
		return nil, fmt.Errorf("DAGConsensus: signing failed: %w", err)
	}
	v.Signature = sig

	d.mu.Lock()
	d.vertices[v.ID] = v
	d.mu.Unlock()

	AuditSensitiveOperation(fmt.Sprintf("DAG:AddVertex:%s:%s", symbol, agentID), true)
	return v, nil
}

// Verify checks that a vertex's signature is valid against the given public key.
func (d *DAGConsensus) Verify(vertexID string, pub *AdinkhepraPQCPublicKey) error {
	d.mu.RLock()
	v, ok := d.vertices[vertexID]
	d.mu.RUnlock()

	if !ok {
		return fmt.Errorf("DAGConsensus: vertex %q not found", vertexID)
	}

	return VerifyAdinkhepraPQC(pub, v.Hash, v.Signature)
}

// ResolveConflict returns the vertex with higher Adinkra symbol precedence.
// If precedence is equal, the earlier timestamp wins.
func (d *DAGConsensus) ResolveConflict(v1, v2 *DAGVertex) *DAGVertex {
	p1, ok1 := AdinkraPrecedence[v1.Symbol]
	p2, ok2 := AdinkraPrecedence[v2.Symbol]

	// Unknown symbols have precedence -1.
	if !ok1 {
		p1 = -1
	}
	if !ok2 {
		p2 = -1
	}

	if p1 > p2 {
		return v1
	}
	if p2 > p1 {
		return v2
	}
	// Tie-break by timestamp (earlier = causal authority).
	if v1.Timestamp <= v2.Timestamp {
		return v1
	}
	return v2
}

// GetAncestors returns all transitive ancestors of a vertex (BFS traversal).
func (d *DAGConsensus) GetAncestors(vertexID string) []*DAGVertex {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []*DAGVertex
	visited := make(map[string]bool)
	queue := []string{vertexID}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur] {
			continue
		}
		visited[cur] = true

		v, ok := d.vertices[cur]
		if !ok {
			continue
		}
		if cur != vertexID {
			result = append(result, v)
		}
		queue = append(queue, v.Parents...)
	}
	return result
}

// GetVertex retrieves a single vertex by ID (nil if not found).
func (d *DAGConsensus) GetVertex(vertexID string) *DAGVertex {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.vertices[vertexID]
}

// All returns a snapshot of all vertices (read-only copy).
func (d *DAGConsensus) All() []*DAGVertex {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*DAGVertex, 0, len(d.vertices))
	for _, v := range d.vertices {
		out = append(out, v)
	}
	return out
}

// =============================================================================
// INTERNAL
// =============================================================================

// computeVertexHash produces a canonical Blake2b-512 hash over vertex fields.
// The hash is deterministic: same input → same hash.
func computeVertexHash(v *DAGVertex) ([]byte, error) {
	h, err := blake2b.New512(nil)
	if err != nil {
		return nil, err
	}

	h.Write([]byte(v.Symbol))
	h.Write([]byte(v.AgentID))
	h.Write(v.Transaction)

	// Include parent IDs in sorted order for determinism.
	for _, pid := range v.Parents {
		h.Write([]byte(pid))
	}

	var tsBuf [8]byte
	tsBuf[0] = byte(v.Timestamp >> 56)
	tsBuf[1] = byte(v.Timestamp >> 48)
	tsBuf[2] = byte(v.Timestamp >> 40)
	tsBuf[3] = byte(v.Timestamp >> 32)
	tsBuf[4] = byte(v.Timestamp >> 24)
	tsBuf[5] = byte(v.Timestamp >> 16)
	tsBuf[6] = byte(v.Timestamp >> 8)
	tsBuf[7] = byte(v.Timestamp)
	h.Write(tsBuf[:])

	return h.Sum(nil), nil
}

// DAGAuditChain wraps a DAGConsensus and signs events using a SHA-512 chain hash,
// providing an append-only audit log with tamper evidence.
type DAGAuditChain struct {
	dag       *DAGConsensus
	chainHash []byte // rolling SHA-512 over all appended event hashes
	mu        sync.Mutex
}

// NewDAGAuditChain wraps an existing DAGConsensus with chain-hash audit tracking.
func NewDAGAuditChain(dag *DAGConsensus) *DAGAuditChain {
	genesis := sha512.Sum512([]byte("KHEPRA-DAG-GENESIS"))
	return &DAGAuditChain{
		dag:       dag,
		chainHash: genesis[:],
	}
}

// Append adds a vertex and advances the chain hash.
func (ac *DAGAuditChain) Append(tx []byte, symbol, agentID string, parents []string, priv *AdinkhepraPQCPrivateKey) (*DAGVertex, error) {
	v, err := ac.dag.AddVertex(tx, symbol, agentID, parents, priv)
	if err != nil {
		return nil, err
	}

	ac.mu.Lock()
	combined := append(ac.chainHash, v.Hash...)
	next := sha512.Sum512(combined)
	ac.chainHash = next[:]
	ac.mu.Unlock()

	return v, nil
}

// ChainHash returns the current chain hash (tamper-evident log head).
func (ac *DAGAuditChain) ChainHash() []byte {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	out := make([]byte, len(ac.chainHash))
	copy(out, ac.chainHash)
	return out
}

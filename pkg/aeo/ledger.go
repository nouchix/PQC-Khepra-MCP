package aeo

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
)

// DAGAction is the action label AEO anchor nodes carry in the KHEPRA DAG.
const DAGAction = "AEO_RECORDED"

// DAGSymbol is the Adinkra symbol for agent evidence: Akoma Ntoso —
// "linked hearts", agreement and accountability between entities.
const DAGSymbol = "AKOMA_NTOSO"

// Ledger stores an agent population's AEOs and anchors each one into the
// immutable KHEPRA DAG. It answers the Catch-22 question — "who verifies the
// verifier?" — with a cryptographically anchored evidence fabric: every
// object is self-verifying (ML-DSA-65 + content address) and cross-anchored
// (DAG parentage), so no single trusted observer is required.
type Ledger struct {
	mu      sync.RWMutex
	byHash  map[string]*EvidenceObject
	byAgent map[string][]*EvidenceObject // insertion order per agent

	store       dag.Store
	signKey     []byte            // ledger's own ML-DSA-65 key for DAG anchor nodes
	lastAnchors map[string]string // agentID -> last DAG anchor node ID
}

// NewLedger creates a ledger anchoring into the given DAG store. signKey is
// the ledger's ML-DSA-65 private key used to sign anchor nodes; pass nil to
// record unanchored (verification still works, anchoring is skipped).
func NewLedger(store dag.Store, signKey []byte) *Ledger {
	return &Ledger{
		byHash:      make(map[string]*EvidenceObject),
		byAgent:     make(map[string][]*EvidenceObject),
		store:       store,
		signKey:     signKey,
		lastAnchors: make(map[string]string),
	}
}

// Append verifies an AEO, enforces the parent chain for its agent, and
// anchors it in the DAG. Rejects tampered, mis-chained, or duplicate objects.
func (l *Ledger) Append(obj *EvidenceObject) error {
	if err := obj.Verify(); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, dup := l.byHash[obj.Hash]; dup {
		return errors.New("aeo: duplicate evidence object")
	}

	history := l.byAgent[obj.AgentID]
	if len(history) == 0 {
		if obj.ParentEvent != "" {
			return errors.New("aeo: chain violation: genesis event must have empty parent")
		}
	} else {
		tip := history[len(history)-1]
		if obj.ParentEvent != tip.Hash {
			return fmt.Errorf("aeo: chain violation: parent %s is not the agent's tip %s",
				obj.ParentEvent, tip.Hash)
		}
	}

	if err := l.anchor(obj); err != nil {
		return err
	}

	l.byHash[obj.Hash] = obj
	l.byAgent[obj.AgentID] = append(history, obj)
	return nil
}

// anchor writes a signed DAG node referencing the AEO. The node's parent is
// the agent's previous anchor, mirroring the AEO chain inside the DAG.
func (l *Ledger) anchor(obj *EvidenceObject) error {
	if l.store == nil {
		return nil
	}

	node := &dag.Node{
		Action: DAGAction,
		Symbol: DAGSymbol,
		Time:   obj.Timestamp.Format(time.RFC3339Nano),
		PQC: map[string]string{
			"aeo_hash":     obj.Hash,
			"agent_id":     obj.AgentID,
			"task":         obj.Task,
			"intent_hash":  obj.IntentHash,
			"parent_event": obj.ParentEvent,
			"algorithm":    AttestAlgorithm,
		},
	}

	// Parents must be set before hashing: the node's content address
	// covers its parentage, and dag.Store.Add re-verifies it.
	if prev, ok := l.lastAnchors[obj.AgentID]; ok {
		node.Parents = []string{prev}
	}

	if l.signKey != nil {
		if err := node.Sign(l.signKey); err != nil {
			return fmt.Errorf("aeo: anchor signing failed: %w", err)
		}
	} else {
		node.ID = node.ComputeHash()
		node.Hash = node.ID
	}

	if err := l.store.Add(node, nil); err != nil {
		return fmt.Errorf("aeo: DAG anchoring failed: %w", err)
	}
	l.lastAnchors[obj.AgentID] = node.ID
	return nil
}

// Get returns an AEO by content hash.
func (l *Ledger) Get(hash string) (*EvidenceObject, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	obj, ok := l.byHash[hash]
	return obj, ok
}

// History returns the agent's AEOs in chain order.
func (l *Ledger) History(agentID string) []*EvidenceObject {
	l.mu.RLock()
	defer l.mu.RUnlock()
	history := l.byAgent[agentID]
	out := make([]*EvidenceObject, len(history))
	copy(out, history)
	return out
}

// Replay is the forensic reconstruction of an agent's operational history —
// the "anti-action". It re-verifies every AEO and every chain link from
// genesis to tip and returns the ordered history if and only if the entire
// state transition sequence S(t0) -> ... -> S(tn) is provable from evidence.
func (l *Ledger) Replay(agentID string) ([]*EvidenceObject, error) {
	history := l.History(agentID)
	if len(history) == 0 {
		return nil, fmt.Errorf("aeo: no history for agent %s", agentID)
	}

	prevHash := ""
	var prevTime time.Time
	for i, obj := range history {
		if err := obj.Verify(); err != nil {
			return nil, fmt.Errorf("aeo: replay failed at event %d: %w", i, err)
		}
		if obj.ParentEvent != prevHash {
			return nil, fmt.Errorf("aeo: replay failed at event %d: broken chain link", i)
		}
		if i > 0 && obj.Timestamp.Before(prevTime) {
			return nil, fmt.Errorf("aeo: replay failed at event %d: non-monotonic timestamp", i)
		}
		prevHash = obj.Hash
		prevTime = obj.Timestamp
	}
	return history, nil
}

package seshat

import (
	"fmt"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

// Chronicle maintains state awareness
// Seshat: Egyptian goddess of writing, records, and measurement
type Chronicle struct {
	DAGStore dag.Store
	Signer   *Signer // Simplified signer
	Papyrus  []Inscription
}

// Signer holds a private key for signing
type Signer struct {
	PrivateKey []byte
}

// Inscription represents a recorded event
type Inscription struct {
	Time   time.Time
	Symbol string
	Data   map[string]any
	NodeID string
}

// NewChronicle creates a new chronicle
func NewChronicle(dagStore dag.Store, signer *Signer) *Chronicle {
	return &Chronicle{
		DAGStore: dagStore,
		Signer:   signer,
		Papyrus:  []Inscription{},
	}
}

// Inscribe records an event to the DAG
func (c *Chronicle) Inscribe(symbol string, data map[string]any) error {
	// Create DAG node
	node := &dag.Node{
		Action: "seshat-inscription",
		Symbol: symbol,
		Time:   time.Now().Format(time.RFC3339),
	}
	// Store data in PQC field if it's string-compatible.
	// Non-string-representable types are omitted; callers should
	// pre-serialize complex data to a JSON string before inscribing.
	if len(data) > 0 {
		// Convert to JSON string for PQC field
		jsonData := fmt.Sprintf("%v", data)
		node.PQC = map[string]string{"data": jsonData}
	}

	// Compute hash
	node.ComputeHash()

	// Sign with Dilithium if signer available
	if c.Signer != nil && len(c.Signer.PrivateKey) > 0 {
		err := node.Sign(c.Signer.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to sign inscription: %w", err)
		}
	}

	// Write to DAG (immutable)
	err := c.DAGStore.Add(node, []string{})
	if err != nil {
		return fmt.Errorf("failed to write to DAG: %w", err)
	}

	// Cache in memory
	c.Papyrus = append(c.Papyrus, Inscription{
		Time:   time.Now(),
		Symbol: symbol,
		Data:   data,
		NodeID: node.ID,
	})

	return nil
}

// ReadPapyrus retrieves recent inscriptions
func (c *Chronicle) ReadPapyrus(limit int) []Inscription {
	if limit > len(c.Papyrus) {
		limit = len(c.Papyrus)
	}

	if limit == 0 {
		return []Inscription{}
	}

	return c.Papyrus[len(c.Papyrus)-limit:]
}

// ReadAll returns all inscriptions
func (c *Chronicle) ReadAll() []Inscription {
	return c.Papyrus
}

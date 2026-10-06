package playbooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/nouchix/khepra-pqc/sign"
)

// Playbook represents a PQC-signed compliance skill or playbook.
type Playbook struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Frameworks  []string `json:"frameworks"` // e.g., ["NIST-800-171", "CMMC-L2"]
	Steps       []Step   `json:"steps"`
	Signature   []byte   `json:"signature"` // ML-DSA-87 signature over SigningBytes
}

// Step represents a single actionable item in a playbook.
type Step struct {
	Action string            `json:"action"`
	Params map[string]string `json:"params"`
}

// playbookContext is the FIPS 204 context for playbook signatures.
var playbookContext = func() sign.Context {
	c, err := sign.ContextManifest.WithLabel("playbook")
	if err != nil {
		panic(err)
	}
	return c
}()

// SigningBytes returns the canonical bytes a playbook signature covers: the
// JSON encoding of every field except Signature.
func (pb *Playbook) SigningBytes() ([]byte, error) {
	unsigned := *pb
	unsigned.Signature = nil
	return json.Marshal(&unsigned)
}

// Sign signs pb with an ML-DSA-87 key and sets pb.Signature.
func Sign(pb *Playbook, key *sign.PrivateKey) error {
	msg, err := pb.SigningBytes()
	if err != nil {
		return fmt.Errorf("playbook: encode: %w", err)
	}
	sig, err := key.Sign(playbookContext, msg)
	if err != nil {
		return fmt.Errorf("playbook: sign: %w", err)
	}
	pb.Signature = sig
	return nil
}

// Verify checks pb's ML-DSA-87 signature against pubKey.
func Verify(pb *Playbook, pubKey *sign.PublicKey) error {
	if pubKey == nil {
		return errors.New("playbook: no verification key")
	}
	if len(pb.Signature) == 0 {
		return errors.New("playbook: missing PQC signature")
	}
	msg, err := pb.SigningBytes()
	if err != nil {
		return fmt.Errorf("playbook: encode: %w", err)
	}
	if err := pubKey.Verify(playbookContext, msg, pb.Signature); err != nil {
		return fmt.Errorf("playbook: invalid signature: %w", err)
	}
	return nil
}

// LoadAndVerify loads a playbook from disk and verifies its ML-DSA-87
// signature. A playbook that does not verify is never returned.
func LoadAndVerify(path string, pubKey *sign.PublicKey) (*Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read playbook %s: %w", path, err)
	}

	var pb Playbook
	if err := json.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("failed to parse playbook JSON: %w", err)
	}

	if err := Verify(&pb, pubKey); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &pb, nil
}

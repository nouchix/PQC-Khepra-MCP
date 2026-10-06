package playbooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nouchix/khepra-pqc/sign"
)

func TestLoadAndVerify(t *testing.T) {
	sk, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pb := &Playbook{
		ID:      "pb-1",
		Name:    "Quarantine Compromised Agent",
		Version: "1.0.0",
		Steps:   []Step{{Action: "revoke_agent_token", Params: map[string]string{"agent_id": "a-1"}}},
	}
	if err := Sign(pb, sk); err != nil {
		t.Fatal(err)
	}

	write := func(p *Playbook) string {
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "pb.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if _, err := LoadAndVerify(write(pb), sk.PublicKey()); err != nil {
		t.Fatalf("signed playbook rejected: %v", err)
	}

	// Changing any step invalidates the signature.
	tampered := *pb
	tampered.Steps = []Step{{Action: "delete_everything"}}
	if _, err := LoadAndVerify(write(&tampered), sk.PublicKey()); err == nil {
		t.Error("tampered playbook accepted")
	}

	other, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAndVerify(write(pb), other.PublicKey()); err == nil {
		t.Error("playbook accepted under a different key")
	}
	if _, err := LoadAndVerify(write(pb), nil); err == nil {
		t.Error("playbook accepted with no verification key")
	}

	unsigned := *pb
	unsigned.Signature = nil
	if _, err := LoadAndVerify(write(&unsigned), sk.PublicKey()); err == nil {
		t.Error("unsigned playbook accepted")
	}
}

package adinkra

import (
	"testing"
	"time"
)

func TestNonceCache(t *testing.T) {
	nc := NewNonceCache()

	nonce := "unique-nonce-123"
	expiry := time.Now().Add(5 * time.Minute)

	// First use should succeed
	if !nc.CheckAndMark(nonce, expiry) {
		t.Error("First use of nonce should succeed")
	}

	// Second use should fail (Replay)
	if nc.CheckAndMark(nonce, expiry) {
		t.Error("Second use of nonce should fail")
	}

	// Different nonce should succeed
	if !nc.CheckAndMark("other-nonce", expiry) {
		t.Error("Different nonce should succeed")
	}
}

func TestSecureCommandCreation(t *testing.T) {
	cmd, err := NewSecureCommand("test_action", 1*time.Minute, "sender-1")
	if err != nil {
		t.Fatalf("Failed to create command: %v", err)
	}

	if len(cmd.Nonce) == 0 {
		t.Error("Nonce should be populated")
	}
	if cmd.Command != "test_action" {
		t.Error("Command payload mismatch")
	}
}

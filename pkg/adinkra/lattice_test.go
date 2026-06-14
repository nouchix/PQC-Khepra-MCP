package adinkra

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSacredMerkabaSeal(t *testing.T) {
	seed := []byte("12345678901234567890123456789012") // 32 bytes
	data := []byte("HELLO WORLD KHEPRA")               // 18 bytes

	m := NewMerkaba(seed)
	sealed, err := m.Seal(data)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// t.Logf("Sealed: %s", sealed)

	unsealed, err := m.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(data, unsealed) {
		t.Errorf("Mismatch!")
		t.Errorf("Input:    %s (%d)", hex.EncodeToString(data), len(data))
		t.Errorf("Unsealed: %s (%d)", hex.EncodeToString(unsealed), len(unsealed))
	}
}

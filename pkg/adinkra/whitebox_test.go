package adinkra

import (
	"bytes"
	"testing"
)

// TestWhiteBoxSystem verifies the full Kuntinkantan -> Sankofa roundtrip
// using the Merkaba White Box Engine.
func TestWhiteBoxSystem(t *testing.T) {
	// 1. Generate Okyeame Keys (Kyber-1024)
	pk, sk, err := GenerateKyberKey()
	if err != nil {
		t.Fatalf("Failed to generate Kyber keys: %v", err)
	}

	// 2. Define a test message
	originalMessage := []byte("The secret of the Scarab is Rebirth.")

	// 3. Encrypt (Kuntinkantan) - White Box Seal
	artifact, err := Kuntinkantan(pk, originalMessage)
	if err != nil {
		t.Fatalf("Kuntinkantan failed: %v", err)
	}

	t.Logf("Artifact Length: %d bytes", len(artifact))

	// 4. Decrypt (Sankofa) - White Box Unseal
	plaintext, err := Sankofa(sk, artifact)
	if err != nil {
		t.Fatalf("Sankofa failed: %v", err)
	}

	// 5. Verify Integrity
	if !bytes.Equal(originalMessage, plaintext) {
		t.Errorf("Roundtrip failed.\nExpected: %s\nGot: %s", originalMessage, plaintext)
	} else {
		t.Log("White Box System Roundtrip: SUCCESS")
	}
}

// TestMerkabaEngine verifies the lower-level Lattice/Merkaba logic
func TestMerkabaEngine(t *testing.T) {
	seed := make([]byte, 32)
	// Zero seed for determinism in this test, but in prod it's random
	mk := NewMerkaba(seed)

	data := []byte("Test Vector 1234")

	// Seal
	sealed, err := mk.Seal(data)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	t.Logf("Sealed (Sacred Runes): %s", sealed)

	// Unseal
	unsealed, err := mk.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(data, unsealed) {
		t.Errorf("Merkaba Roundtrip failed.")
	}
}

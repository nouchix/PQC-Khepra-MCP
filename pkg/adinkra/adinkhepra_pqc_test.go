package adinkra

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

func TestAdinkhepraPQCSignVerify(t *testing.T) {
	// 1. Setup
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	symbol := "Eban"

	// 2. KeyGen
	pub, priv, err := GenerateAdinkhepraPQCKeyPair(seed, symbol)
	if err != nil {
		t.Fatalf("KeyPair generation failed: %v", err)
	}

	// 3. Message
	msg := []byte("The fortress protects the spirit.")
	h := sha512.Sum512(msg)

	// 4. Sign
	sig, err := SignAdinkhepraPQC(priv, h[:])
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// 5. Verify
	if err := VerifyAdinkhepraPQC(pub, h[:], sig); err != nil {
		t.Errorf("Verification failed: %v", err)
	}

	// 6. Tamper test
	h[0] ^= 0xFF
	if err := VerifyAdinkhepraPQC(pub, h[:], sig); err == nil {
		t.Error("Verification should have failed for tampered hash")
	}
}

func TestAdinkhepraASAF(t *testing.T) {
	seed := make([]byte, 32)
	copy(seed, []byte("asaf-testing-seed-00000000000000"))

	pub, priv, _ := GenerateAdinkhepraPQCKeyPair(seed, "Fawohodie")

	agentID := "agent-delta"
	actionID := "action-42"
	symbol := "Fawohodie"
	trustScore := 88
	context := "Admin Access"

	// Sign Action
	attestation, err := SignAgentAction(priv, agentID, actionID, symbol, trustScore, context)
	if err != nil {
		t.Fatalf("SignAgentAction failed: %v", err)
	}

	// Verify Action
	if err := VerifyAgentAction(pub, attestation); err != nil {
		t.Errorf("VerifyAgentAction failed: %v", err)
	}

	// Check Compliance Mapping
	compliance := MapSymbolToCompliance(symbol)
	found := false
	for _, c := range compliance {
		if c == "CMMC" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Symbol %s should map to CMMC, got %v", symbol, compliance)
	}
}

func TestAdinkhepraPQCDeterminism(t *testing.T) {
	seed := []byte("deterministic-seed-test-12345678")
	symbol := "Nkyinkyim"

	pub1, priv1, _ := GenerateAdinkhepraPQCKeyPair(seed, symbol)
	pub2, priv2, _ := GenerateAdinkhepraPQCKeyPair(seed, symbol)

	// Seeds must match
	if !bytes.Equal(pub1.Seed[:], pub2.Seed[:]) {
		t.Error("Public key seeds do not match")
	}

	// Raw public key bytes must match (deterministic from same seed)
	if !bytes.Equal(pub1.Raw, pub2.Raw) {
		t.Error("Public key Raw bytes do not match for same seed")
	}

	// Raw private key bytes must match (deterministic from same seed)
	if !bytes.Equal(priv1.Raw, priv2.Raw) {
		t.Error("Private key Raw bytes do not match for same seed")
	}
}

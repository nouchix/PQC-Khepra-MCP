package crypto

import (
	"bytes"
	"testing"
)

func TestCryptoBackendInterface(t *testing.T) {
	// Ensure we have a backend
	backend := GetBackend()
	if backend == nil {
		t.Fatal("GetBackend() returned nil")
	}

	t.Logf("Testing backend: %s (Premium: %v, HSM: %v)",
		backend.BackendName(), backend.IsPremium(), backend.IsHSM())

	// Test Dilithium3
	pk, sk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("Identity Theft is not a joke, Jim!")
	sig, err := Sign(sk, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !Verify(pk, message, sig) {
		t.Error("Verify failed for valid signature")
	}

	// Test Key Encapsulation (Kyber1024)
	kemPK, kemSK, err := GenerateKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateKEMKeyPair failed: %v", err)
	}

	ct, ssEncap, err := Encapsulate(kemPK)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	ssDecap, err := Decapsulate(kemSK, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(ssEncap, ssDecap) {
		t.Error("Shared secrets do not match")
	}
}

func TestInitBackend(t *testing.T) {
	// Test initialization
	// Note: We can't easily test features switching without mock build tags,
	// but we can ensure InitBackend(nil) doesn't crash and returns valid backend.
	err := InitBackend(nil)
	if err != nil {
		t.Errorf("InitBackend failed: %v", err)
	}

	if GetBackend() == nil {
		t.Error("Backend is nil after InitBackend")
	}
}

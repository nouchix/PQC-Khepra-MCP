//go:build !hsm

package crypto

import (
	"bytes"
	"testing"

	"github.com/nouchix/khepra-pqc/sign"
)

func TestCryptoBackendInterface(t *testing.T) {
	backend := GetBackend()
	if backend == nil {
		t.Fatal("GetBackend() returned nil")
	}
	t.Logf("Testing backend: %s (HSM: %v)", backend.BackendName(), backend.IsHSM())

	// ML-DSA-87
	pk, sk, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair failed: %v", err)
	}
	if len(pk) != 2592 || len(sk) != 32 {
		t.Fatalf("key sizes = %d/%d, want 2592/32", len(pk), len(sk))
	}

	message := []byte("backend round trip")
	sig, err := Sign(sign.ContextAttest, sk, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !Verify(sign.ContextAttest, pk, message, sig) {
		t.Error("Verify failed for valid signature")
	}
	if Verify(sign.ContextDAG, pk, message, sig) {
		t.Error("Verify accepted a signature under the wrong context")
	}
	tampered := append([]byte(nil), message...)
	tampered[0] ^= 1
	if Verify(sign.ContextAttest, pk, tampered, sig) {
		t.Error("Verify accepted a tampered message")
	}

	// ML-KEM-1024
	ek, dk, err := GenerateKEMKeyPair()
	if err != nil {
		t.Fatalf("GenerateKEMKeyPair failed: %v", err)
	}
	if len(ek) != 1568 || len(dk) != 64 {
		t.Fatalf("KEM key sizes = %d/%d, want 1568/64", len(ek), len(dk))
	}

	ct, ssEncap, err := Encapsulate(ek)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}
	ssDecap, err := Decapsulate(dk, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if !bytes.Equal(ssEncap, ssDecap) {
		t.Error("Shared secrets do not match")
	}
}

func TestInitBackend(t *testing.T) {
	if err := InitBackend(); err != nil {
		t.Errorf("InitBackend failed: %v", err)
	}
	if GetBackend() == nil {
		t.Error("Backend is nil after InitBackend")
	}
}

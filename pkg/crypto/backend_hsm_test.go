//go:build hsm

package crypto

import (
	"errors"
	"testing"

	"github.com/nouchix/khepra-pqc/sign"
)

// TestHSMFailsClosed checks that an hsm build never falls back to software keys.
func TestHSMFailsClosed(t *testing.T) {
	if err := InitBackend(); !errors.Is(err, ErrNoHSM) {
		t.Fatalf("InitBackend() = %v, want ErrNoHSM", err)
	}
	if !GetBackend().IsHSM() {
		t.Fatal("hsm build installed a non-HSM backend")
	}
	if _, _, err := GenerateSigningKeyPair(); !errors.Is(err, ErrNoHSM) {
		t.Errorf("GenerateSigningKeyPair() = %v, want ErrNoHSM", err)
	}
	if _, err := Sign(sign.ContextAttest, make([]byte, 32), []byte("m")); !errors.Is(err, ErrNoHSM) {
		t.Errorf("Sign() = %v, want ErrNoHSM", err)
	}
	if Verify(sign.ContextAttest, make([]byte, 2592), []byte("m"), make([]byte, 4627)) {
		t.Error("Verify() returned true in hsm build")
	}
	if _, _, err := GenerateKEMKeyPair(); !errors.Is(err, ErrNoHSM) {
		t.Errorf("GenerateKEMKeyPair() = %v, want ErrNoHSM", err)
	}
	if _, _, err := Encapsulate(make([]byte, 1568)); !errors.Is(err, ErrNoHSM) {
		t.Errorf("Encapsulate() = %v, want ErrNoHSM", err)
	}
	if _, err := Decapsulate(make([]byte, 64), make([]byte, 1568)); !errors.Is(err, ErrNoHSM) {
		t.Errorf("Decapsulate() = %v, want ErrNoHSM", err)
	}
}

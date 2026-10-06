package adinkra

import (
	"bytes"
	"testing"
)

func newHybrid(t *testing.T, purpose, symbol string) *HybridKeyPair {
	t.Helper()
	kp, err := GenerateHybridKeyPair(purpose, symbol, 12)
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	return kp
}

func TestHybridKeySizes(t *testing.T) {
	kp := newHybrid(t, "test", "Eban")
	if err := ValidateKeyPairIntegrity(kp); err != nil {
		t.Fatalf("fresh key pair fails validation: %v", err)
	}
	other := newHybrid(t, "test", "Eban")
	if bytes.Equal(kp.KEMPrivate, other.KEMPrivate) || kp.KeyID == other.KeyID {
		t.Fatal("two generated key pairs collide")
	}
}

func TestHybridCryptoFlow(t *testing.T) {
	sender := newHybrid(t, "sender", "Nkyinkyim")
	recipient := newHybrid(t, "recipient", "Nkyinkyim")
	message := []byte("ATTACK AT DAWN - SECTOR 7")

	signed, err := sender.SignArtifact(message)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}
	if err := VerifyArtifact(signed, sender); err != nil {
		t.Errorf("VerifyArtifact: %v", err)
	}

	enc, err := EncryptForRecipient(message, recipient)
	if err != nil {
		t.Fatalf("EncryptForRecipient: %v", err)
	}
	got, err := DecryptEnvelope(enc, recipient)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	if !bytes.Equal(got, message) {
		t.Fatal("decryption mismatch")
	}
}

func TestVerifyArtifactRejectsTampering(t *testing.T) {
	kp := newHybrid(t, "signer", "Eban")
	env, _ := kp.SignArtifact([]byte("original"))

	mod := *env
	mod.EncryptedData = []byte("modified")
	if err := VerifyArtifact(&mod, kp); err == nil {
		t.Error("modified data verified")
	}
	mod = *env
	mod.SignerKeyID = "KHEPRA-FORGED"
	if err := VerifyArtifact(&mod, kp); err == nil {
		t.Error("modified signer key ID verified")
	}
	mod = *env
	mod.Timestamp++
	if err := VerifyArtifact(&mod, kp); err == nil {
		t.Error("modified timestamp verified")
	}
	if err := VerifyArtifact(env, newHybrid(t, "other", "Eban")); err == nil {
		t.Error("signature verified under a different key")
	}
}

// There is no classical fallback: only the recipient's ML-KEM key opens an
// envelope.
func TestDecryptEnvelopeWrongRecipient(t *testing.T) {
	enc, _ := EncryptForRecipient([]byte("secret"), newHybrid(t, "a", "Eban"))
	if _, err := DecryptEnvelope(enc, newHybrid(t, "b", "Eban")); err == nil {
		t.Fatal("envelope opened with the wrong recipient key")
	}
}

func TestASAFVerification(t *testing.T) {
	agent := newHybrid(t, "agent", "Eban")
	attestation, err := SignAgentAction(agent.AdinkhepraPQCPrivate, "agent-007", "action-x-99", "Eban", 95, "Terminal Access")
	if err != nil {
		t.Fatalf("SignAgentAction: %v", err)
	}
	if err := VerifyAgentAction(agent.AdinkhepraPQCPublic, attestation); err != nil {
		t.Errorf("VerifyAgentAction: %v", err)
	}
}

func TestBackupRoundTrip(t *testing.T) {
	payload := map[string]string{"key": "value"}
	backup, err := EncryptBackup(payload, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptBackup(backup, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"key":"value"}` {
		t.Fatalf("got %s", got)
	}
	if _, err := DecryptBackup(backup, "wrong passphrase"); err == nil {
		t.Error("wrong passphrase accepted")
	}
	backup.Header.Algorithm = "tampered"
	if _, err := DecryptBackup(backup, "correct horse battery staple"); err == nil {
		t.Error("modified header accepted")
	}
}

// A fleet attestation must not verify for a different encrypted payload.

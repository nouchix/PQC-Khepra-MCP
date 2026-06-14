package adinkra

import (
	"bytes"
	"testing"
)

func TestDilithiumSignVerify(t *testing.T) {
	pub, priv, err := GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("Failed to generate Dilithium keys: %v", err)
	}

	msg := []byte("The prompt is the program.")

	// Sign
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify
	valid, err := Verify(pub, msg, sig)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed for valid signature")
	}

	// Tamper test
	msg[0] ^= 0xFF
	valid, err = Verify(pub, msg, sig)
	if err == nil && valid {
		t.Error("Signature verification succeeded for tampered message")
	}
}

func TestKyberKuntinkantanSankofa(t *testing.T) {
	// 1. Setup Identities
	okyeamePub, okyeamePriv, err := GenerateKyberKey()
	if err != nil {
		t.Fatalf("Failed to generate Kyber keys: %v", err)
	}

	// 2. The Matter (Message)
	plaintext := []byte("The root of all security is trust. The root of trust is mathematics.")

	// 3. Kuntinkantan (Encrypt)
	artifact, err := Kuntinkantan(okyeamePub, plaintext)
	if err != nil {
		t.Fatalf("Kuntinkantan failed: %v", err)
	}

	t.Logf("Artifact Size: %d bytes", len(artifact))

	// 4. Sankofa (Decrypt)
	restored, err := Sankofa(okyeamePriv, artifact)
	if err != nil {
		t.Fatalf("Sankofa failed: %v", err)
	}

	// 5. Build Verification
	if !bytes.Equal(plaintext, restored) {
		t.Errorf("Decryption mismatch.\nExpected: %s\nGot:      %s", plaintext, restored)
	}
}

func TestKuntinkantanIntegrity(t *testing.T) {
	pub, priv, _ := GenerateKyberKey()
	msg := []byte("Integrity Check")
	artifact, _ := Kuntinkantan(pub, msg)

	// Corrupt the Artifact (Flip a bit in the woven matter)
	// Artifact structure: [Capsule | Nonce | Ciphertext]
	// Flip last byte
	artifact[len(artifact)-1] ^= 0xFF

	_, err := Sankofa(priv, artifact)
	if err == nil {
		t.Error("Sankofa should have failed on corrupted artifact (Auth Tag check failure expected)")
	} else {
		t.Logf("Correctly caught integrity violation: %v", err)
	}
}

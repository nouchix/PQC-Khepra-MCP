package adinkra

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestMLDSASignVerify(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-87 keys: %v", err)
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

func TestKuntinkantanSankofa(t *testing.T) {
	// 1. Setup Identities
	okyeamePub, okyeamePriv, err := GenerateKEMKey()
	if err != nil {
		t.Fatalf("Failed to generate ML-KEM-1024 keys: %v", err)
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
	pub, priv, _ := GenerateKEMKey()
	msg := []byte("Integrity Check")
	artifact, _ := Kuntinkantan(pub, msg)

	// Corrupt the artifact (a KHQ3 envelope): flip the last byte of the tag.
	artifact[len(artifact)-1] ^= 0xFF

	_, err := Sankofa(priv, artifact)
	if err == nil {
		t.Error("Sankofa should have failed on corrupted artifact (Auth Tag check failure expected)")
	} else {
		t.Logf("Correctly caught integrity violation: %v", err)
	}
}

// Historical ML-DSA-65 signatures (made before the move to ML-DSA-87, with an
// empty context) must still verify through Verify.
func TestVerifyAcceptsHistoricalMLDSA65(t *testing.T) {
	pk, sk, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("signed before the migration")
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
		t.Fatal(err)
	}
	pub, _ := pk.MarshalBinary()
	ok, err := Verify(pub, msg, sig)
	if err != nil || !ok {
		t.Fatalf("historical ML-DSA-65 signature rejected: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify(pub, []byte("other"), sig); ok {
		t.Fatal("historical signature verified for a different message")
	}
}

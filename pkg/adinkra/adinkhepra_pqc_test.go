package adinkra

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

func TestAdinkhepraPQCSignVerify(t *testing.T) {
	pub, priv, err := GenerateAdinkhepraPQCKeyPair("Eban")
	if err != nil {
		t.Fatalf("KeyPair generation failed: %v", err)
	}
	if len(pub.Raw) != SigningPublicKeySize || len(priv.Raw) != SigningPrivateKeySize {
		t.Fatalf("unexpected key sizes: pub=%d priv=%d", len(pub.Raw), len(priv.Raw))
	}

	h := sha512.Sum384([]byte("The fortress protects the spirit."))
	sig, err := SignAdinkhepraPQC(priv, h[:])
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}
	if err := VerifyAdinkhepraPQC(pub, h[:], sig); err != nil {
		t.Errorf("Verification failed: %v", err)
	}

	h[0] ^= 0xFF
	if err := VerifyAdinkhepraPQC(pub, h[:], sig); err == nil {
		t.Error("Verification should have failed for tampered hash")
	}
}

func TestAdinkhepraASAF(t *testing.T) {
	pub, priv, err := GenerateAdinkhepraPQCKeyPair("Fawohodie")
	if err != nil {
		t.Fatal(err)
	}

	attestation, err := SignAgentAction(priv, "agent-delta", "action-42", "Fawohodie", 88, "Admin Access")
	if err != nil {
		t.Fatalf("SignAgentAction failed: %v", err)
	}
	if err := VerifyAgentAction(pub, attestation); err != nil {
		t.Errorf("VerifyAgentAction failed: %v", err)
	}

	found := false
	for _, c := range MapSymbolToCompliance("Fawohodie") {
		if c == "CMMC" {
			found = true
		}
	}
	if !found {
		t.Error("Fawohodie should map to CMMC")
	}
}

// Keys come from the module's random bit generator: the same symbol must
// never produce the same key twice, and the public key must not carry any
// private material.
func TestAdinkhepraPQCKeysAreRandom(t *testing.T) {
	pub1, priv1, _ := GenerateAdinkhepraPQCKeyPair("Nkyinkyim")
	pub2, priv2, _ := GenerateAdinkhepraPQCKeyPair("Nkyinkyim")
	if bytes.Equal(pub1.Raw, pub2.Raw) || bytes.Equal(priv1.Raw, priv2.Raw) {
		t.Fatal("two keys generated for the same symbol are identical")
	}
	if bytes.Contains(pub1.Raw, priv1.Raw) {
		t.Fatal("public key bytes contain the private seed")
	}
}

// A signature from the agent API must not verify as a signature from the
// generic Sign API, and vice versa (FIPS 204 context separation).
func TestAgentAndGenericSignaturesAreSeparate(t *testing.T) {
	pub, priv, _ := GenerateAdinkhepraPQCKeyPair("Eban")
	msg := []byte("same message")
	agentSig, _ := SignAdinkhepraPQC(priv, msg)
	if ok, _ := Verify(pub.Raw, msg, agentSig); ok {
		t.Fatal("agent signature verified through the generic Verify API")
	}
	genericSig, _ := Sign(priv.Raw, msg)
	if err := VerifyAdinkhepraPQC(pub, msg, genericSig); err == nil {
		t.Fatal("generic signature verified through the agent API")
	}
}

func TestPrivateKeyPublic(t *testing.T) {
	pub, priv, _ := GenerateAdinkhepraPQCKeyPair("Dwennimmen")
	derived, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived.Raw, pub.Raw) || derived.Symbol != "Dwennimmen" {
		t.Fatal("Public() does not reproduce the generated public key")
	}
}

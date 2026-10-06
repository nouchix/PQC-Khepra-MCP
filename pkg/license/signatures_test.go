package license

import (
	"crypto/mldsa"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/nouchix/khepra-pqc/sign"
)

func TestSignaturesRoundTrip(t *testing.T) {
	sk, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := sk.PublicKey().Bytes()
	msg := []byte(`{"license_id":"lic-1","tier":"pilot"}`)

	sig, err := signWith(licenseContext, sk.Bytes(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWithRoot(licenseContext, pub, msg, sig); err != nil {
		t.Fatalf("valid license signature rejected: %v", err)
	}

	// A signature made for one object kind must not verify as another.
	for _, ctx := range []sign.Context{revocationContext, capsuleContext, deviceContext} {
		if err := verifyWithRoot(ctx, pub, msg, sig); err == nil {
			t.Errorf("license signature verified under context %q", ctx)
		}
	}

	tampered := append([]byte(nil), msg...)
	tampered[len(tampered)-2] ^= 1
	if err := verifyWithRoot(licenseContext, pub, tampered, sig); err == nil {
		t.Error("tampered message verified")
	}

	devSig, err := signWith(deviceContext, sk.Bytes(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDevice(pub, msg, devSig); err != nil {
		t.Fatalf("device signature rejected: %v", err)
	}
	if err := verifyDevice(pub, msg, sig); err == nil {
		t.Error("license signature accepted as a device signature")
	}
}

// TestHistoricalMLDSA65Root checks that licenses signed by the pre-ceremony
// ML-DSA-65 root (empty context) still verify, and that nothing here can sign
// with an expanded ML-DSA-65 key.
func TestHistoricalMLDSA65Root(t *testing.T) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"license_id":"historical"}`)
	sig, err := sk.Sign(nil, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := sk.PublicKey().Bytes()
	if len(pub) != legacyMLDSA65PublicKeySize {
		t.Fatalf("ML-DSA-65 public key is %d bytes", len(pub))
	}
	if err := verifyWithRoot(licenseContext, pub, msg, sig); err != nil {
		t.Fatalf("historical root signature rejected: %v", err)
	}
	if err := verifyWithRoot(licenseContext, pub, []byte("other"), sig); err == nil {
		t.Error("historical root accepted a signature over a different message")
	}

	if _, err := signWith(licenseContext, make([]byte, legacyMLDSA65PrivateKeySize), msg); !errors.Is(err, errRetiredSigningKey) {
		t.Errorf("signing with an expanded ML-DSA-65 key: got %v, want errRetiredSigningKey", err)
	}
	if err := verifyWithRoot(licenseContext, make([]byte, 1312), msg, sig); err == nil {
		t.Error("accepted a public key of an unsupported size")
	}
}

func TestDeviceMessageBinding(t *testing.T) {
	sk, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	lc := &LicenseClient{MachineID: "m-1", PrivateKey: hexString(sk.Bytes())}
	sigHex, err := lc.signData(deviceMessage("validate", "m-1", 1700000000))
	if err != nil {
		t.Fatal(err)
	}
	sig := mustHex(t, sigHex)
	pub := sk.PublicKey().Bytes()
	if err := verifyDevice(pub, deviceMessage("validate", "m-1", 1700000000), sig); err != nil {
		t.Fatalf("device signature rejected: %v", err)
	}
	for _, m := range [][]byte{
		deviceMessage("heartbeat", "m-1", 1700000000),
		deviceMessage("validate", "m-2", 1700000000),
		deviceMessage("validate", "m-1", 1700000001),
	} {
		if err := verifyDevice(pub, m, sig); err == nil {
			t.Errorf("signature verified for a different message %q", m)
		}
	}
	pubHex, err := lc.devicePublicKeyHex()
	if err != nil || pubHex != hexString(pub) {
		t.Fatalf("devicePublicKeyHex = %q, %v", pubHex, err)
	}
}

func hexString(b []byte) string { return hex.EncodeToString(b) }

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

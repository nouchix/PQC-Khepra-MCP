package license

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nouchix/khepra-pqc/sign"
)

func TestSignedCRL(t *testing.T) {
	authority, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := authority.PublicKey().Bytes()

	db := NewRevocationDatabase()
	db.Add(RevocationEntry{LicenseID: "lic-revoked", Reason: "key disclosed", RevokedAt: time.Now().UTC()})
	data, err := db.Export(authority.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if err := crlRevokes(data, "lic-revoked", pub); !errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("revoked license: got %v, want ErrLicenseRevoked", err)
	}
	if err := crlRevokes(data, "lic-good", pub); err != nil {
		t.Fatalf("unrevoked license: %v", err)
	}

	// A CRL from any other key is not trusted.
	other, _ := sign.GenerateKey()
	if err := crlRevokes(data, "lic-good", other.PublicKey().Bytes()); err == nil || errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("CRL verified under the wrong key: %v", err)
	}

	// Removing an entry after signing breaks the signature.
	var sc signedCRL
	if err := json.Unmarshal(data, &sc); err != nil {
		t.Fatal(err)
	}
	empty, _ := json.Marshal(map[string]any{"schema": "x", "entries": []any{}})
	sc.CRL = empty
	tampered, _ := json.Marshal(sc)
	if err := crlRevokes(tampered, "lic-revoked", pub); err == nil || errors.Is(err, ErrLicenseRevoked) {
		t.Fatalf("tampered CRL accepted: %v", err)
	}

	// The old unreadable format is not a CRL.
	if err := crlRevokes([]byte{1, 2, 3}, "lic-revoked", pub); err == nil {
		t.Fatal("garbage accepted as a CRL")
	}
}

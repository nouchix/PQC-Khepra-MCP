package adinkra

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/nouchix/khepra-pqc/keyfile"
	"github.com/nouchix/khepra-pqc/sign"
)

func TestReadKeyFile(t *testing.T) {
	dir := t.TempDir()
	sk, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "id_mldsa87")
	pubPath := privPath + ".pub"
	if err := keyfile.WriteSigningKey(privPath, sk); err != nil {
		t.Fatal(err)
	}
	if err := keyfile.WriteVerifyingKey(pubPath, sk.PublicKey()); err != nil {
		t.Fatal(err)
	}

	priv, err := ReadKeyFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ReadKeyFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv, sk.Bytes()) || !bytes.Equal(pub, sk.PublicKey().Bytes()) {
		t.Fatal("ReadKeyFile returned different key bytes")
	}
	sig, err := Sign(priv, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify(pub, []byte("m"), sig); err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}

	rawPath := filepath.Join(dir, "raw")
	if err := os.WriteFile(rawPath, sk.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadKeyFile(rawPath); err != nil || !bytes.Equal(raw, sk.Bytes()) {
		t.Fatalf("raw key: %v", err)
	}

	otherPath := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(otherPath, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(otherPath); err == nil {
		t.Fatal("ReadKeyFile accepted a non-KHEPRA PEM block")
	}
}

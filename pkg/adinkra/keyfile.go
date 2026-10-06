package adinkra

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/nouchix/khepra-pqc/keyfile"
)

// ReadKeyFile reads a key written by the khepra-pqc keyfile package (PEM with
// a KHEPRA ML-KEM-1024 / ML-DSA-87 block type) and returns the raw key bytes
// that the functions in this package take. Files without a PEM header are
// returned as-is, so raw seeds and public keys keep working.
func ReadKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		return data, nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("read key %s: malformed PEM", path)
	}
	switch block.Type {
	case keyfile.TypeKEMPrivateKey, keyfile.TypeKEMPublicKey,
		keyfile.TypeSignPrivateKey, keyfile.TypeSignPublicKey:
		return block.Bytes, nil
	}
	return nil, fmt.Errorf("read key %s: unsupported PEM block %q", path, block.Type)
}

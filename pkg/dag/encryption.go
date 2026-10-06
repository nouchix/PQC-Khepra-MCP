package dag

import (
	"crypto/fips140"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

// EncryptedNode wraps a DAG node encrypted at rest with AES-256-GCM.
type EncryptedNode struct {
	ID             string `json:"id"`             // Plaintext ID (content hash)
	EncryptedData  string `json:"encrypted_data"` // hex(nonce | ciphertext | tag)
	PQCSignature   string `json:"pqc_signature"`  // The node's ML-DSA signature, preserved
	EncryptionMeta struct {
		Algorithm     string `json:"algorithm"`      // "AES-256-GCM"
		KeyDerivation string `json:"key_derivation"` // "PBKDF2-HMAC-SHA-384"
		FIPSMode      bool   `json:"fips_mode"`      // whether the Go FIPS 140-3 module was in FIPS mode
	} `json:"encryption_meta"`
}

// EncryptNode encrypts a DAG node with AES-256-GCM. The nonce is generated
// inside the Go Cryptographic Module and stored with the ciphertext.
func EncryptNode(node *Node, key []byte) (*EncryptedNode, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (AES-256), got %d", len(key))
	}
	plaintext, err := json.Marshal(node)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node: %w", err)
	}
	ciphertext, err := adinkra.EncryptAESGCM(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt node: %w", err)
	}

	encrypted := &EncryptedNode{
		ID:            node.ID,
		EncryptedData: hex.EncodeToString(ciphertext),
		PQCSignature:  node.Signature,
	}
	encrypted.EncryptionMeta.Algorithm = "AES-256-GCM"
	encrypted.EncryptionMeta.KeyDerivation = "PBKDF2-HMAC-SHA-384"
	encrypted.EncryptionMeta.FIPSMode = fips140.Enabled()
	return encrypted, nil
}

// DecryptNode decrypts a node produced by EncryptNode.
func DecryptNode(encrypted *EncryptedNode, key []byte) (*Node, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("decryption key must be 32 bytes (AES-256), got %d", len(key))
	}
	ciphertext, err := hex.DecodeString(encrypted.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}
	plaintext, err := adinkra.DecryptAESGCM(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt node: %w", err)
	}
	var node Node
	if err := json.Unmarshal(plaintext, &node); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted node: %w", err)
	}
	return &node, nil
}

// DeriveDAGEncryptionKey derives a 32-byte AES key from a passphrase
// with PBKDF2-HMAC-SHA-384 (SP 800-132).
func DeriveDAGEncryptionKey(passphrase []byte, salt []byte) ([]byte, error) {
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes, got %d", len(salt))
	}

	key, err := adinkra.DeriveKey(passphrase, salt, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	return key, nil
}

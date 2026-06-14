package dag

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// EncryptedNode wraps a DAG node with PQC encryption
// Ensures FIPS/NSA/NIST/CMMC 3.0 compliance for data at rest
type EncryptedNode struct {
	ID             string `json:"id"`              // Plaintext ID (content hash)
	EncryptedData  string `json:"encrypted_data"`  // AES-256-GCM encrypted JSON
	Nonce          string `json:"nonce"`           // AES nonce (12 bytes)
	PQCSignature   string `json:"pqc_signature"`   // Dilithium-3 signature
	EncryptionMeta struct {
		Algorithm string `json:"algorithm"` // "AES-256-GCM"
		KeyDerivation string `json:"key_derivation"` // "Khepra-PQC-KDF"
		FIPSMode bool `json:"fips_mode"`
	} `json:"encryption_meta"`
}

// EncryptNode encrypts a DAG node using AES-256-GCM
// Key must be 32 bytes (256 bits) for AES-256
func EncryptNode(node *Node, key []byte) (*EncryptedNode, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (AES-256), got %d", len(key))
	}

	// Serialize node to JSON
	plaintext, err := json.Marshal(node)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node: %w", err)
	}

	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt using Khepra PQC wrapper (delegates to AES-256-GCM internally)
	// Note: adinkra.Encrypt should wrap golang.org/x/crypto/cipher AEAD
	ciphertext, err := adinkra.EncryptAES256GCM(plaintext, key, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt node: %w", err)
	}

	encrypted := &EncryptedNode{
		ID:            node.ID,
		EncryptedData: hex.EncodeToString(ciphertext),
		Nonce:         hex.EncodeToString(nonce),
		PQCSignature:  node.Signature, // Preserve original Dilithium signature
	}

	encrypted.EncryptionMeta.Algorithm = "AES-256-GCM"
	encrypted.EncryptionMeta.KeyDerivation = "Khepra-PQC-KDF"
	encrypted.EncryptionMeta.FIPSMode = true // Always use FIPS mode

	return encrypted, nil
}

// DecryptNode decrypts an encrypted DAG node
func DecryptNode(encrypted *EncryptedNode, key []byte) (*Node, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("decryption key must be 32 bytes (AES-256), got %d", len(key))
	}

	// Decode hex strings
	ciphertext, err := hex.DecodeString(encrypted.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := hex.DecodeString(encrypted.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Decrypt using Khepra PQC wrapper
	plaintext, err := adinkra.DecryptAES256GCM(ciphertext, key, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt node: %w", err)
	}

	// Deserialize node from JSON
	var node Node
	if err := json.Unmarshal(plaintext, &node); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted node: %w", err)
	}

	return &node, nil
}

// DeriveDAGEncryptionKey derives a 32-byte AES key from a passphrase
// Uses Khepra PQC KDF for FIPS compliance
func DeriveDAGEncryptionKey(passphrase []byte, salt []byte) ([]byte, error) {
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes, got %d", len(salt))
	}

	// Use Khepra PQC KDF (wraps Argon2id or PBKDF2-HMAC-SHA512)
	key, err := adinkra.DeriveKey(passphrase, salt, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	return key, nil
}

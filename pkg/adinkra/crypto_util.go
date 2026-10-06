package adinkra

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/nouchix/khepra-pqc/kdf"
)

// GenerateSalt creates a random salt for KDF.
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// EncryptAESGCM encrypts plaintext with AES-256-GCM. The 96-bit nonce is
// generated inside the Go Cryptographic Module (SP 800-38D §8.2.2) and
// prepended to the output: [nonce | ciphertext | tag].
func EncryptAESGCM(key, plaintext []byte) ([]byte, error) {
	aead, err := newRandomNonceGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, plaintext, nil), nil
}

// DecryptAESGCM decrypts data produced by EncryptAESGCM.
func DecryptAESGCM(key, data []byte) ([]byte, error) {
	aead, err := newRandomNonceGCM(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aead.Overhead() {
		return nil, io.ErrUnexpectedEOF
	}
	return aead.Open(nil, nil, data, nil)
}

func newRandomNonceGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256-GCM key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// DeriveKey derives a key from a passphrase with PBKDF2-HMAC-SHA-384
// (SP 800-132). Used for DAG encryption key derivation.
func DeriveKey(passphrase, salt []byte, keyLen uint32) ([]byte, error) {
	return kdf.PassphraseKey(string(passphrase), salt, int(keyLen))
}

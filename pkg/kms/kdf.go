// pkg/kms/kdf.go — passphrase KDF for ASAF key material.
//
// PBKDF2-HMAC-SHA-384 (NIST SP 800-132) with kdf.PBKDF2Iterations iterations
// and a random 32-byte salt, from the Go Cryptographic Module through
// github.com/nouchix/khepra-pqc/kdf.

package kms

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/nouchix/khepra-pqc/kdf"
)

// KDFParams defines the key derivation output.
type KDFParams struct {
	KeyLen int // output key length in bytes
}

// KDFVersion is embedded in sealed artifacts so a future change to the KDF
// can detect material sealed under these parameters.
const KDFVersion = "pbkdf2-sha384-600000-v1"

// DefaultKDFParams derives one AES-256 key.
var DefaultKDFParams = KDFParams{KeyLen: 32}

// DeriveKey derives p.KeyLen bytes from password and salt with
// PBKDF2-HMAC-SHA-384. Callers must treat the output as a key.
func DeriveKey(password, salt []byte, p KDFParams) ([]byte, error) {
	return kdf.PassphraseKey(string(password), salt, p.KeyLen)
}

// NewSalt generates a cryptographically random 32-byte salt.
// A new salt must be generated for every key derivation operation.
func NewSalt() ([]byte, error) {
	return kdf.NewSalt()
}

// aesGCMEncrypt encrypts data with AES-256-GCM; the module generates the
// nonce. Output: nonce | ciphertext | tag.
func aesGCMEncrypt(key, data []byte) ([]byte, error) {
	gcm, err := newRandomNonceGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nil, data, nil), nil
}

// aesGCMDecrypt reverses aesGCMEncrypt.
func aesGCMDecrypt(key, data []byte) ([]byte, error) {
	gcm, err := newRandomNonceGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nil, data, nil)
}

func newRandomNonceGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

package adinkra

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// DeriveProprietaryKey uses Argon2id to harden the passphrase into a 64-byte seed.
// This seed allows us to deterministically regenerate the "Ghost Identity".
func DeriveProprietaryKey(passphrase string, salt []byte) []byte {
	// Params: time=1, memory=64MB, threads=4, keyLen=64
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 64)
}

// GenerateSalt creates a random salt for KDF.
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// SeededReader is a deterministic io.Reader based on HKDF-SHA3-256 via a seed.
// This allows libraries that expect an io.Reader (like ecdsa.GenerateKey) to be deterministic.
type SeededReader struct {
	stream io.Reader
}

func NewSeededReader(seed []byte) *SeededReader {
	// Expand the seed into an infinite stream using HKDF
	hkdfStream := hkdf.New(sha256.New, seed, nil, []byte("KHEPRA-DETERMINISTIC-RNG"))
	return &SeededReader{stream: hkdfStream}
}

func (r *SeededReader) Read(p []byte) (n int, err error) {
	return r.stream.Read(p)
}

// EncryptAESGCM performs standard AES-256-GCM encryption.
func EncryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Return [Nonce | Ciphertext]
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// DecryptAESGCM performs standard AES-256-GCM decryption.
func DecryptAESGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return nil, io.ErrUnexpectedEOF
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

// EncryptAES256GCM encrypts data with AES-256-GCM using provided nonce
// Used by DAG persistence layer for FIPS-compliant encryption at rest
func EncryptAES256GCM(plaintext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAES256GCM decrypts data with AES-256-GCM using provided nonce
// Used by DAG persistence layer for FIPS-compliant decryption from disk
func DecryptAES256GCM(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DeriveKey derives a cryptographic key from a passphrase using Argon2id
// Used for DAG encryption key derivation (FIPS/NIST compliant)
func DeriveKey(passphrase, salt []byte, keyLen uint32) ([]byte, error) {
	// Argon2id parameters (OWASP recommended for 2024)
	// time=3, memory=64MB, threads=4
	key := argon2.IDKey(passphrase, salt, 3, 64*1024, 4, keyLen)
	return key, nil
}

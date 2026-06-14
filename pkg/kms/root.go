package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"golang.org/x/crypto/argon2"
)

// argon2ID parameters (NIST SP 800-63B / OWASP recommended minimums).
// time=3 memory=64MiB parallelism=4 — memory-hard, GPU/ASIC resistant.
// Upgrade from PBKDF2-SHA512 which is vulnerable to GPU bruteforce attacks.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 96 // 3 × 32-byte AES-256 keys
)

// Tier0Result represents the output of a Root of Trust ceremony
type Tier0Result struct {
	// SealedArtifact is the "Poetically Obfuscated" string containing the triple-encrypted seed
	SealedArtifact string    `json:"sealed_artifact"`
	Salt           string    `json:"salt"` // 32-byte hex encoded random salt
	CreatedAt      time.Time `json:"created_at"`
	Fingerprint    string    `json:"fingerprint"`
	EntropySource  string    `json:"entropy_source"`
}

// BootstrapTier0 performs the Root of Trust ceremony
func BootstrapTier0(entropySource, password string) (*Tier0Result, error) {
	if password == "" {
		return nil, errors.New("master password required for Tier 0 ceremony")
	}

	// 1. Collect Entropy (Master Seed)
	seed := make([]byte, 64) // 512 bits
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("insufficient entropy: %w", err)
	}

	// 2. Generate Random Salt for this ceremony
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt generation failed: %w", err)
	}

	// 3. Compute Identity Fingerprint (SHA-512)
	hash := sha512.Sum512(seed)
	fingerprint := hex.EncodeToString(hash[:8])

	// 4. Triple Encrypt & Obfuscate
	sealed, err := tripleEncryptAndseal(seed, password, salt)
	if err != nil {
		return nil, fmt.Errorf("sealing failed: %w", err)
	}

	result := &Tier0Result{
		SealedArtifact: sealed,
		Salt:           hex.EncodeToString(salt),
		CreatedAt:      time.Now().UTC(),
		Fingerprint:    fmt.Sprintf("KHEPRA-ROOT-%s", fingerprint),
		EntropySource:  entropySource,
	}

	return result, nil
}

// EncodeTier0 saves the result to path, creating parent directories as needed.
// This ensures the default ~/.asaf/keys/ directory is created automatically
// even on a fresh install with no prior key material.
func EncodeTier0(result *Tier0Result, path string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create keys dir %s: %w", dir, err)
		}
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadMasterSeed unlocks the Tier 0 seed using the password
func LoadMasterSeed(path, password string) ([]byte, error) {
	// 1. Read the sealed artifact
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var result Tier0Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid artifact structure: %v", err)
	}

	// 2. Decode Salt
	salt, err := hex.DecodeString(result.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt encoding")
	}

	// 3. Decode and Decrypt
	seed, err := tripleDecryptAndUnseal(result.SealedArtifact, password, salt)
	if err != nil {
		return nil, fmt.Errorf("ACCESS DENIED: %v", err)
	}

	return seed, nil
}

// =============================================================================
// INTERNAL SECURITY LOGIC
// =============================================================================

// tripleEncryptAndseal applies 3 layers of AES-256-GCM with derived keys,
// then encodes using the "Khepra Lattice" alphabet (Poetic Obfuscation).
func tripleEncryptAndseal(plaintext []byte, password string, salt []byte) (string, error) {
	// Key Derivation: Use PBKDF2 to derive 3 keys from password and random salt
	// We derive 96 bytes (32 * 3)
	keyMaterial := deriveKeys(password, salt)
	key1 := keyMaterial[0:32]
	key2 := keyMaterial[32:64]
	key3 := keyMaterial[64:96]

	// Layer 1: Encrypt
	c1, err := aesGCMEncrypt(key1, plaintext)
	if err != nil {
		return "", err
	}

	// Layer 2: Encrypt
	c2, err := aesGCMEncrypt(key2, c1)
	if err != nil {
		return "", err
	}

	// Layer 3: Encrypt
	c3, err := aesGCMEncrypt(key3, c2)
	if err != nil {
		return "", err
	}

	// 4. Encapsulate in Sacred Encrypted Geometric Merkaba (AdinKhepra Lattice)
	// We use the full Layer 1 Key as part of the Geometry Seed for additional entropy.
	h1 := sha512.Sum512(key1)
	merkaba := adinkra.NewMerkaba(h1[:])
	return merkaba.Seal(c3)
}

// tripleDecryptAndUnseal reverses the process
func tripleDecryptAndUnseal(sealed string, password string, salt []byte) ([]byte, error) {
	// Re-derive Keys
	keyMaterial := deriveKeys(password, salt)
	key1 := keyMaterial[0:32]
	key2 := keyMaterial[32:64]
	key3 := keyMaterial[64:96]

	// 1. Unseal the Sacred Encrypted Geometric Merkaba
	h1 := sha512.Sum512(key1)
	merkaba := adinkra.NewMerkaba(h1[:])
	ciphertext3, err := merkaba.Unseal(sealed)
	if err != nil {
		return nil, fmt.Errorf("Merkaba lattice breach: %v", err)
	}

	// Layer 3: Decrypt
	c2, err := aesGCMDecrypt(key3, ciphertext3)
	if err != nil {
		return nil, errors.New("layer 3 breach failed")
	}

	// Layer 2: Decrypt
	c1, err := aesGCMDecrypt(key2, c2)
	if err != nil {
		return nil, errors.New("layer 2 breach failed")
	}

	// Layer 1: Decrypt
	seed, err := aesGCMDecrypt(key1, c1)
	if err != nil {
		return nil, errors.New("root layer breach failed")
	}

	return seed, nil
}

// deriveKeys derives 96 bytes of key material from a password and salt
// using Argon2id (NIST SP 800-63B, memory-hard, GPU/ASIC resistant).
//
// Parameters are chosen per OWASP Argon2id recommendations:
//   - time=3 iterations
//   - memory=64 MiB (forces 64MB RAM per guess — kills GPU parallelism)
//   - parallelism=4
//
// Output is 3 × 32-byte AES-256 keys for the triple-encryption layers.
//
// Migration note: sealed artifacts created with the old PBKDF2 KDF must be
// re-sealed using `asaf keys migrate` before the next rotation cycle.
func deriveKeys(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)
}

func aesGCMEncrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal: Nonce + Ciphertext + Tag
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func aesGCMDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

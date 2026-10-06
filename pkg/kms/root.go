package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// tier0Version identifies the sealing format: the 64-byte seed is encrypted
// once with AES-256-GCM under a key derived from the passphrase with
// PBKDF2-HMAC-SHA-384 (see DeriveKey). Version and salt are authenticated.
const tier0Version = "tier0-v3-" + KDFVersion + "-aes256gcm"

// Tier0Result represents the output of a Root of Trust ceremony
type Tier0Result struct {
	Version string `json:"version"`
	// SealedArtifact is base64(nonce | ciphertext | tag)
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
	salt, err := NewSalt()
	if err != nil {
		return nil, fmt.Errorf("salt generation failed: %w", err)
	}

	// 3. Compute Identity Fingerprint (SHA-512)
	hash := sha512.Sum512(seed)
	fingerprint := hex.EncodeToString(hash[:8])

	// 4. Seal
	sealed, err := sealTier0(seed, password, salt)
	if err != nil {
		return nil, fmt.Errorf("sealing failed: %w", err)
	}

	result := &Tier0Result{
		Version:        tier0Version,
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

	if result.Version != tier0Version {
		return nil, fmt.Errorf("artifact format %q is not supported; re-run the Tier 0 ceremony", result.Version)
	}

	// 2. Decode Salt
	salt, err := hex.DecodeString(result.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt encoding")
	}

	// 3. Decode and Decrypt
	seed, err := unsealTier0(result.SealedArtifact, password, salt)
	if err != nil {
		return nil, fmt.Errorf("ACCESS DENIED: %v", err)
	}

	return seed, nil
}

// =============================================================================
// INTERNAL SECURITY LOGIC
// =============================================================================

// tier0AEAD derives the sealing key and returns AES-256-GCM with
// module-generated nonces.
func tier0AEAD(password string, salt []byte) (cipher.AEAD, error) {
	key, err := DeriveKey([]byte(password), salt, DefaultKDFParams)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func tier0AAD(salt []byte) []byte {
	return append([]byte(tier0Version+"\x00"), salt...)
}

// sealTier0 encrypts the seed and returns base64(nonce | ciphertext | tag).
func sealTier0(plaintext []byte, password string, salt []byte) (string, error) {
	gcm, err := tier0AEAD(password, salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nil, nil, plaintext, tier0AAD(salt))), nil
}

// unsealTier0 reverses sealTier0.
func unsealTier0(sealed string, password string, salt []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, errors.New("invalid sealed artifact encoding")
	}
	gcm, err := tier0AEAD(password, salt)
	if err != nil {
		return nil, err
	}
	seed, err := gcm.Open(nil, nil, data, tier0AAD(salt))
	if err != nil {
		return nil, errors.New("incorrect password or corrupted artifact")
	}
	return seed, nil
}

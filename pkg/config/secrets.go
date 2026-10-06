package config

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"
)

// SecretBundle uses []byte to allow for explicit memory wiping.
// We avoid 'string' because they are immutable and hard to clear from RAM.
type SecretBundle struct {
	ShodanKey     []byte `json:"shodan"`
	CensysID      []byte `json:"censys_id"`
	CensysSecret  []byte `json:"censys_secret"`
	VirusTotalKey []byte `json:"vt"`
}

// LoadEncryptedSecrets decrypts the bundle using the ephemeral khepraKey.
// It returns a SecretBundle that MUST be Wiped() after use.
func LoadEncryptedSecrets(bundlePath string, khepraKey []byte) (*SecretBundle, error) {
	ciphertext, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret bundle: %v", err)
	}

	block, err := aes.NewCipher(khepraKey)
	if err != nil {
		return nil, fmt.Errorf("cipher init failed: %v", err)
	}

	// Bundle layout: nonce(12) | ciphertext | tag(16).
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init failed: %w", err)
	}

	if len(ciphertext) < 12+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	plaintext, err := gcm.Open(nil, nil, ciphertext, nil)
	if err != nil {
		// Audit Log: This is a high-severity integrity failure
		return nil, fmt.Errorf("decryption failed (potential tampering): %v", err)
	}

	var bundle SecretBundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return nil, fmt.Errorf("bundle parsing failed: %v", err)
	}

	// OpSec: Overwrite the intermediate plaintext buffer immediately.
	// While the GC might eventually collect it, we don't want it lingering.
	for i := range plaintext {
		plaintext[i] = 0
	}

	return &bundle, nil
}

// Wipe explicitly zeros out the memory of the keys.
// This is critical for "Mission Assurance" and memory forensics defense.
func (s *SecretBundle) Wipe() {
	if s == nil {
		return
	}
	wipeBytes(s.ShodanKey)
	wipeBytes(s.CensysID)
	wipeBytes(s.CensysSecret)
	wipeBytes(s.VirusTotalKey)
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

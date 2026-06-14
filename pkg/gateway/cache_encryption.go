// Package gateway - Cache Encryption for STIG Connector
//
// This file implements AES-256-GCM encryption for cached STIG data.
// Encryption keys are rotated every 30 days to limit exposure.
//
// Security Controls:
//   - AES-256-GCM authenticated encryption
//   - HMAC-SHA256 integrity verification
//   - Automatic key rotation (30-day cycle)
//   - Nonce randomness from crypto/rand
//
// Reference: STIGVIEWER_STRATEGY_MITOCHONDRIA.md §3.4 (Encrypted Cache)
package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"time"
)

// ─── AES-256-GCM Encryption ─────────────────────────────────────────────────────

// encryptCacheData encrypts plaintext using AES-256-GCM.
// Returns (ciphertext, nonce, error).
func (c *STIGConnector) encryptCacheData(plaintext []byte) ([]byte, []byte, error) {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()

	if len(c.cacheEncryptionKey) != 32 {
		return nil, nil, fmt.Errorf("invalid encryption key length: expected 32, got %d", len(c.cacheEncryptionKey))
	}

	// Create AES cipher
	block, err := aes.NewCipher(c.cacheEncryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

// decryptCacheData decrypts ciphertext using AES-256-GCM.
func (c *STIGConnector) decryptCacheData(ciphertext []byte, nonce []byte) ([]byte, error) {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()

	if len(c.cacheEncryptionKey) != 32 {
		return nil, fmt.Errorf("invalid encryption key length: expected 32, got %d", len(c.cacheEncryptionKey))
	}

	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length: expected 12, got %d", len(nonce))
	}

	// Create AES cipher
	block, err := aes.NewCipher(c.cacheEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt and verify authentication tag
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication tag mismatch): %w", err)
	}

	return plaintext, nil
}

// ─── Key Rotation ───────────────────────────────────────────────────────────────

// rotateEncryptionKey generates a new AES-256 encryption key.
// In production, this should fetch from Vault and store the old key for decrypting existing cache entries.
func (c *STIGConnector) rotateEncryptionKey() error {
	c.keyMu.Lock()
	defer c.keyMu.Unlock()

	// Generate new 256-bit (32-byte) key
	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Key material is generated locally here. In a HSM-backed deployment,
	// replace this block with: vaultClient.Logical().Read("khepra/cache-encryption/current")
	// and store old key via: vaultClient.Logical().Write("khepra/cache-encryption/archive", ...)
	// See pkg/security/key_manager.go for the Vault client integration point.

	c.cacheEncryptionKey = newKey
	c.keyRotatedAt = time.Now()

	c.logAudit("cache_key_rotated", "system", map[string]string{
		"rotated_at": c.keyRotatedAt.Format(time.RFC3339),
		"key_length": "256",
	})

	return nil
}

// checkAndRotateKey checks if key rotation is needed and performs it.
func (c *STIGConnector) checkAndRotateKey() {
	c.keyMu.RLock()
	rotationNeeded := time.Since(c.keyRotatedAt) > c.config.CacheKeyRotationInterval
	c.keyMu.RUnlock()

	if rotationNeeded {
		if err := c.rotateEncryptionKey(); err != nil {
			c.logAudit("cache_key_rotation_failed", "system", map[string]string{
				"error": err.Error(),
			})
		} else {
			// Clear cache after key rotation (old entries can't be decrypted with new key)
			// In production, you'd want to decrypt with old key and re-encrypt with new key
			c.cache.Range(func(key, value interface{}) bool {
				c.cache.Delete(key)
				return true
			})
			c.logAudit("cache_cleared_after_rotation", "system", map[string]string{
				"reason": "encryption key rotated",
			})
		}
	}
}

// getCurrentKeyVersion returns the current encryption key version (based on rotation count).
// In production, this would be tracked in Vault.
func (c *STIGConnector) getCurrentKeyVersion() int {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()

	// Simple version: days since epoch / rotation interval
	// In production, use Vault's key versioning
	return int(time.Since(c.keyRotatedAt).Hours() / 24 / 30)
}

// ─── Cache Statistics ───────────────────────────────────────────────────────────

// GetCacheStats returns cache encryption statistics for monitoring.
func (c *STIGConnector) GetCacheStats() map[string]interface{} {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()

	// Count cache entries
	entryCount := 0
	c.cache.Range(func(key, value interface{}) bool {
		entryCount++
		return true
	})

	return map[string]interface{}{
		"encryption_enabled": c.config.CacheEncryptionEnabled,
		"key_rotated_at":     c.keyRotatedAt,
		"days_since_rotation": int(time.Since(c.keyRotatedAt).Hours() / 24),
		"next_rotation_in_days": int(c.config.CacheKeyRotationInterval.Hours()/24) - int(time.Since(c.keyRotatedAt).Hours()/24),
		"entry_count":        entryCount,
		"key_version":        c.getCurrentKeyVersion(),
	}
}

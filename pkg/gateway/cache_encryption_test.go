package gateway

import (
	"testing"
	"time"
)

// TestEncryptDecryptCacheData verifies AES-256-GCM encryption/decryption
func TestEncryptDecryptCacheData(t *testing.T) {
	cfg := DefaultSTIGConnectorConfig()
	cfg.CacheEncryptionEnabled = true

	connector := NewSTIGConnector(cfg, nil)

	plaintext := []byte("test STIG data for encryption")

	// Encrypt
	ciphertext, nonce, err := connector.encryptCacheData(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if len(nonce) != 12 {
		t.Errorf("Expected nonce length 12, got %d", len(nonce))
	}

	if len(ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}

	// Verify ciphertext is different from plaintext
	if string(ciphertext) == string(plaintext) {
		t.Error("Ciphertext matches plaintext (encryption didn't work)")
	}

	// Decrypt
	decrypted, err := connector.decryptCacheData(ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decrypted matches original
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// TestEncryptionWithWrongKey verifies that decryption fails with wrong key
func TestEncryptionWithWrongKey(t *testing.T) {
	cfg := DefaultSTIGConnectorConfig()
	cfg.CacheEncryptionEnabled = true

	connector := NewSTIGConnector(cfg, nil)

	plaintext := []byte("secret STIG data")

	// Encrypt with original key
	ciphertext, nonce, err := connector.encryptCacheData(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Rotate key (changes encryption key)
	if err := connector.rotateEncryptionKey(); err != nil {
		t.Fatalf("Key rotation failed: %v", err)
	}

	// Attempt to decrypt with new key (should fail)
	_, err = connector.decryptCacheData(ciphertext, nonce)
	if err == nil {
		t.Error("Decryption should have failed with wrong key, but succeeded")
	}
}

// TestKeyRotation verifies encryption key rotation
func TestKeyRotation(t *testing.T) {
	cfg := DefaultSTIGConnectorConfig()
	cfg.CacheEncryptionEnabled = true
	cfg.CacheKeyRotationInterval = 1 * time.Second // Fast rotation for testing

	connector := NewSTIGConnector(cfg, nil)

	// Get original key (copy it)
	originalKey := make([]byte, 32)
	copy(originalKey, connector.cacheEncryptionKey)

	// Wait for rotation interval
	time.Sleep(2 * time.Second)

	// Trigger rotation check
	connector.checkAndRotateKey()

	// Verify key changed
	if string(connector.cacheEncryptionKey) == string(originalKey) {
		t.Error("Encryption key should have rotated but didn't")
	}
}

// TestCacheStats verifies cache statistics reporting
func TestCacheStats(t *testing.T) {
	cfg := DefaultSTIGConnectorConfig()
	cfg.CacheEncryptionEnabled = true

	connector := NewSTIGConnector(cfg, nil)

	stats := connector.GetCacheStats()

	// Verify stats structure
	if stats["encryption_enabled"] != true {
		t.Error("encryption_enabled should be true")
	}

	if stats["key_version"] == nil {
		t.Error("key_version should be present")
	}

	if stats["entry_count"] != 0 {
		t.Errorf("Expected entry_count 0, got %v", stats["entry_count"])
	}
}

// TestHMACIntegrity verifies HMAC prevents cache tampering
func TestHMACIntegrity(t *testing.T) {
	cfg := DefaultSTIGConnectorConfig()
	cfg.CacheEncryptionEnabled = true

	connector := NewSTIGConnector(cfg, nil)

	// Create a cache entry
	result := &STIGQueryResult{
		Rules:      []STIGDecomposedRule{},
		TotalCount: 0,
		Source:     "test",
	}

	cacheKey := "test:stig:001"
	connector.putInCache(cacheKey, result)

	// Tamper with cached data
	val, ok := connector.cache.Load(cacheKey)
	if !ok {
		t.Fatal("Cache entry not found")
	}

	entry := val.(*cacheEntry)
	// Flip a bit in encrypted data (tamper)
	if len(entry.encryptedData) > 0 {
		entry.encryptedData[0] ^= 0xFF
	}

	// Attempt to retrieve (should fail HMAC check)
	retrieved, found := connector.getFromCache(cacheKey)
	if found {
		t.Error("Cache retrieval should have failed due to HMAC mismatch, but succeeded")
	}
	if retrieved != nil {
		t.Error("Retrieved data should be nil after tampering detected")
	}
}

// BenchmarkEncryption measures encryption performance
func BenchmarkEncryption(b *testing.B) {
	cfg := DefaultSTIGConnectorConfig()
	cfg.CacheEncryptionEnabled = true

	connector := NewSTIGConnector(cfg, nil)
	plaintext := []byte("benchmark STIG data that is reasonably sized for testing encryption performance")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := connector.encryptCacheData(plaintext)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkDecryption measures decryption performance
func BenchmarkDecryption(b *testing.B) {
	cfg := DefaultSTIGConnectorConfig()
	cfg.CacheEncryptionEnabled = true

	connector := NewSTIGConnector(cfg, nil)
	plaintext := []byte("benchmark STIG data that is reasonably sized for testing decryption performance")

	ciphertext, nonce, err := connector.encryptCacheData(plaintext)
	if err != nil {
		b.Fatalf("Encryption setup failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := connector.decryptCacheData(ciphertext, nonce)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

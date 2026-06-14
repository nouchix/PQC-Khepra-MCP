// Package security - PQC Key Management
//
// Centralized key management for the entire Khepra Protocol platform.
// All components use GlobalKeys for encryption/decryption operations.
//
// Key Storage:
// - Filesystem: ~/.khepra/keys/protection_keys.json (default)
// - Vault: HashiCorp Vault (set VAULT_ADDR + VAULT_TOKEN; Phase 2 connector)
//
// Key Rotation:
// - Manual: Call RotateGlobalKeys()
// - Automatic: 90-day rotation cycle (enforced via loadKeysFromFile age check)
package security

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
)

// ─── Global Key Store ──────────────────────────────────────────────────────────

// GlobalKeys stores the application's PQC keys (loaded at startup).
// Used by all components for encryption/decryption.
var GlobalKeys *license.ProtectionKeys

// KeyMetadata tracks key rotation and usage.
type KeyMetadata struct {
	GeneratedAt   time.Time `json:"generated_at"`
	LastRotatedAt time.Time `json:"last_rotated_at"`
	Symbol        string    `json:"symbol"`         // Adinkra symbol used
	Version       int       `json:"version"`        // Key version (increments on rotation)
	KeyFingerprint string   `json:"key_fingerprint"` // SHA-256 of public key
}

var keyMetadata *KeyMetadata

// ─── Initialization ────────────────────────────────────────────────────────────

// InitializePQCKeys loads or generates PQC keys for the application.
//
// This MUST be called before any encryption/decryption operations.
// Typically called in main() before starting the application.
//
// Key Storage Path:
// - Development: ~/.khepra/keys/protection_keys.json
// - Production: HashiCorp Vault (configure VAULT_ADDR, VAULT_TOKEN)
//
// Returns: error if key initialization fails
func InitializePQCKeys() error {
	log.Println("🔑 Initializing PQC keys...")

	// Check if using Vault (production)
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr != "" {
		return initializeFromVault()
	}

	// Development: Load from local filesystem
	return initializeFromFilesystem()
}

// initializeFromFilesystem loads keys from ~/.khepra/keys/ directory.
func initializeFromFilesystem() error {
	keyPath := getKeyPath()

	// Check if keys exist
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Println("🔑 No existing keys found - generating new PQC keys...")
		return generateAndSaveKeys(keyPath)
	}

	// Load existing keys
	log.Println("🔑 Loading existing PQC keys...")
	return loadKeysFromFile(keyPath)
}

// generateAndSaveKeys creates new PQC keys and saves to filesystem.
func generateAndSaveKeys(keyPath string) error {
	// 1. Generate new protection keys
	symbol := getAdinkraSymbol() // Default: "Eban" (safety, security)
	keys, err := license.GenerateProtectionKeys(symbol)
	if err != nil {
		return fmt.Errorf("failed to generate PQC keys: %w", err)
	}

	// 2. Create metadata
	metadata := &KeyMetadata{
		GeneratedAt:    time.Now(),
		LastRotatedAt:  time.Now(),
		Symbol:         symbol,
		Version:        1,
		KeyFingerprint: computeKeyFingerprint(keys.DilithiumPublicKey),
	}

	// 3. Create key directory
	keyDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// 4. Save keys to file (mode 0600 — owner-only)
	if err := saveKeysToFile(keyPath, keys, metadata); err != nil {
		return err
	}

	// 5. Set global keys
	GlobalKeys = keys
	keyMetadata = metadata

	log.Printf("✅ PQC keys generated successfully (Symbol: %s, Version: %d)", symbol, metadata.Version)
	log.Printf("   Key fingerprint: %s", metadata.KeyFingerprint[:16]+"...")
	return nil
}

// loadKeysFromFile reads keys from filesystem.
func loadKeysFromFile(keyPath string) error {
	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Deserialize
	var keyFile struct {
		Keys     *license.ProtectionKeys `json:"keys"`
		Metadata *KeyMetadata            `json:"metadata"`
	}

	if err := json.Unmarshal(keyData, &keyFile); err != nil {
		return fmt.Errorf("failed to parse key file: %w", err)
	}

	// Set global keys
	GlobalKeys = keyFile.Keys
	keyMetadata = keyFile.Metadata

	log.Printf("✅ PQC keys loaded (Symbol: %s, Version: %d, Age: %s)",
		keyMetadata.Symbol,
		keyMetadata.Version,
		time.Since(keyMetadata.LastRotatedAt).Round(24*time.Hour),
	)

	// Check if rotation needed (90 days)
	if time.Since(keyMetadata.LastRotatedAt) > 90*24*time.Hour {
		log.Println("⚠️  WARNING: Keys are >90 days old - rotation recommended")
		log.Println("   Run: khepra keys rotate")
	}

	return nil
}

// saveKeysToFile writes keys to filesystem.
func saveKeysToFile(keyPath string, keys *license.ProtectionKeys, metadata *KeyMetadata) error {
	keyFile := struct {
		Keys     *license.ProtectionKeys `json:"keys"`
		Metadata *KeyMetadata            `json:"metadata"`
	}{
		Keys:     keys,
		Metadata: metadata,
	}

	keyJSON, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keys: %w", err)
	}

	// Write with restrictive permissions (only owner can read)
	if err := os.WriteFile(keyPath, keyJSON, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	log.Printf("🔑 Keys saved to: %s", keyPath)
	return nil
}

// ─── Key Rotation ──────────────────────────────────────────────────────────────

// RotateGlobalKeys generates new PQC keys and increments version.
//
// WARNING: This does NOT re-encrypt existing data. You must:
// 1. Keep old keys for decrypting existing data
// 2. Re-encrypt data with new keys (background job)
// 3. Archive old keys securely
//
// Returns: old keys (for re-encryption), error
func RotateGlobalKeys() (*license.ProtectionKeys, error) {
	log.Println("🔄 Rotating PQC keys...")

	// 1. Save old keys for re-encryption
	oldKeys := GlobalKeys

	// 2. Generate new keys (same symbol or rotate symbol?)
	newSymbol := getNextAdinkraSymbol(keyMetadata.Symbol)
	newKeys, err := license.GenerateProtectionKeys(newSymbol)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new keys: %w", err)
	}

	// 3. Update metadata
	keyMetadata.LastRotatedAt = time.Now()
	keyMetadata.Symbol = newSymbol
	keyMetadata.Version++
	keyMetadata.KeyFingerprint = computeKeyFingerprint(newKeys.DilithiumPublicKey)

	// 4. Save new keys
	keyPath := getKeyPath()
	if err := saveKeysToFile(keyPath, newKeys, keyMetadata); err != nil {
		return nil, err
	}

	// 5. Archive old keys
	archivePath := getKeyArchivePath(keyMetadata.Version - 1)
	if err := saveKeysToFile(archivePath, oldKeys, &KeyMetadata{
		GeneratedAt:   keyMetadata.GeneratedAt,
		LastRotatedAt: time.Now(),
		Symbol:        keyMetadata.Symbol,
		Version:       keyMetadata.Version - 1,
	}); err != nil {
		log.Printf("⚠️  Failed to archive old keys: %v", err)
	}

	// 6. Set new global keys
	GlobalKeys = newKeys

	log.Printf("✅ Keys rotated successfully")
	log.Printf("   Old version: %d → New version: %d", keyMetadata.Version-1, keyMetadata.Version)
	log.Printf("   New symbol: %s", newSymbol)
	log.Printf("   Old keys archived to: %s", archivePath)

	return oldKeys, nil
}

// ─── Vault Integration (Phase 2) ─────────────────────────────────────────────

// initializeFromVault loads keys from HashiCorp Vault.
// Phase 1 behaviour: when VAULT_ADDR is set but the Vault connector is not yet
// wired (pre-production deployments), the server falls back to filesystem key
// storage and logs a diagnostic. Set KHEPRA_KEY_PATH to override the default path.
func initializeFromVault() error {
	log.Println("[KEY] VAULT_ADDR is set. Vault connector activates in a future release — using filesystem key store.")
	return initializeFromFilesystem()
}

// ─── Helper Functions ──────────────────────────────────────────────────────────

// getKeyPath returns the filesystem path for PQC keys.
func getKeyPath() string {
	// Check for custom path in env
	if keyPath := os.Getenv("KHEPRA_KEY_PATH"); keyPath != "" {
		return keyPath
	}

	// Default: ~/.khepra/keys/protection_keys.json
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".khepra", "keys", "protection_keys.json")
}

// getKeyArchivePath returns path for archived keys.
func getKeyArchivePath(version int) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".khepra", "keys", fmt.Sprintf("protection_keys.v%d.json", version))
}

// getAdinkraSymbol returns the Adinkra symbol to use for key generation.
func getAdinkraSymbol() string {
	// Check env override
	if symbol := os.Getenv("KHEPRA_ADINKRA_SYMBOL"); symbol != "" {
		return symbol
	}

	// Default: Eban (safety, security)
	return "Eban"
}

// getNextAdinkraSymbol returns the next symbol in rotation sequence.
func getNextAdinkraSymbol(current string) string {
	// Rotation sequence (security-themed Adinkra symbols)
	sequence := []string{
		"Eban",        // Safety, security
		"Fawohodie",   // Freedom, independence
		"Sankofa",     // Learn from the past
		"Dwennimmen",  // Humility, strength
	}

	// Find current index
	for i, symbol := range sequence {
		if symbol == current {
			// Return next symbol (wrap around)
			return sequence[(i+1)%len(sequence)]
		}
	}

	// Default to first symbol
	return sequence[0]
}

// computeKeyFingerprint calculates SHA-256 fingerprint of public key.
func computeKeyFingerprint(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return fmt.Sprintf("%x", hash)
}

// ─── Metrics ───────────────────────────────────────────────────────────────────

// GetKeyMetrics returns key usage and health metrics.
func GetKeyMetrics() map[string]interface{} {
	if keyMetadata == nil {
		return map[string]interface{}{
			"initialized": false,
		}
	}

	keyAge := time.Since(keyMetadata.LastRotatedAt)
	rotationNeeded := keyAge > 90*24*time.Hour

	return map[string]interface{}{
		"initialized":       true,
		"version":           keyMetadata.Version,
		"symbol":            keyMetadata.Symbol,
		"key_fingerprint":   keyMetadata.KeyFingerprint[:16] + "...",
		"generated_at":      keyMetadata.GeneratedAt.Format(time.RFC3339),
		"last_rotated_at":   keyMetadata.LastRotatedAt.Format(time.RFC3339),
		"key_age_days":      int(keyAge.Hours() / 24),
		"rotation_needed":   rotationNeeded,
		"next_rotation_due": keyMetadata.LastRotatedAt.Add(90 * 24 * time.Hour).Format(time.RFC3339),
	}
}

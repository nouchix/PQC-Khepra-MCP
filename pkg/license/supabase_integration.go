//go:build saas

// Package license - Supabase PQC Integration
//
// This module provides helper functions for encrypting/decrypting data
// stored in Supabase (PostgreSQL) using the 4-layer PQC protection.
//
// Use Cases:
//   - User profiles (sensitive PII)
//   - Platform configuration
//   - API keys and credentials
//   - Application state
//   - Any other Supabase table data
//
// Example Usage:
//
//	// Protect user data before INSERT
//	protectedUser := license.ProtectSupabaseRecord(userData, "user_profile", keys)
//	supabase.From("users").Insert(protectedUser.ToSupabaseRow())
//
//	// Unprotect user data after SELECT
//	var row SupabaseEncryptedRow
//	supabase.From("users").Select("*").Eq("id", userID).Single().ExecuteTo(&row)
//	userData := license.UnprotectSupabaseRecord(&row, keys)
package license

import (
	"encoding/json"
	"fmt"
	"time"
)

// ─── Supabase Integration Structures ──────────────────────────────────────────

// SupabaseEncryptedRow represents an encrypted row in Supabase.
// Map this to your table columns for encrypted storage.
type SupabaseEncryptedRow struct {
	// Plaintext fields (for indexing/querying)
	ID        string    `json:"id"`         // Primary key (plaintext)
	DataType  string    `json:"data_type"`  // Record type (plaintext, for filtering)
	CreatedAt time.Time `json:"created_at"` // Creation timestamp (plaintext)
	ExpiresAt time.Time `json:"expires_at"` // Expiration (plaintext, for cleanup)

	// Encrypted fields (protected data)
	EncryptedPayload   []byte `json:"encrypted_payload"`    // AES-GCM ciphertext
	Nonce              []byte `json:"nonce"`                // GCM nonce (12 bytes)
	AEADTag            []byte `json:"aead_tag"`             // GCM authentication tag
	KyberCapsule       []byte `json:"kyber_capsule"`        // Kyber encapsulated key (optional)
	DilithiumSignature []byte `json:"dilithium_signature"`  // ML-DSA-65 signature
	LatticeHash        string `json:"lattice_hash"`         // Adinkhepra lattice hash
	LatticeSymbol      string `json:"lattice_symbol"`       // Adinkra symbol used
	EncryptionScheme   string `json:"encryption_scheme"`    // Always "ADINKHEPRA_AES256GCM_KYBER1024_MLDSA65"
}

// ─── Supabase Protection Functions ────────────────────────────────────────────

// ProtectSupabaseRecord encrypts any data structure for Supabase storage.
//
// Parameters:
//   - data: Any Go struct or map to protect
//   - dataType: Type of data (e.g., "user_profile", "config", "api_key")
//   - keys: Protection keys (use same keys for same data type)
//   - expiresAt: Optional expiration (zero value for no expiration)
//
// Returns: SupabaseEncryptedRow ready for INSERT/UPSERT
func ProtectSupabaseRecord(data interface{}, dataType string, keys *ProtectionKeys, expiresAt time.Time) (*SupabaseEncryptedRow, error) {
	// Protect data using 4-layer PQC
	protected, err := ProtectData(data, dataType, ContextAtRest, keys, nil, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to protect data: %w", err)
	}

	// Convert to Supabase row format
	return &SupabaseEncryptedRow{
		ID:                 protected.DataID,
		DataType:           dataType,
		CreatedAt:          protected.CreatedAt,
		ExpiresAt:          protected.ExpiresAt,
		EncryptedPayload:   protected.EncryptedPayload,
		Nonce:              protected.Nonce,
		AEADTag:            protected.AEADTag,
		KyberCapsule:       protected.KyberCapsule,
		DilithiumSignature: protected.DilithiumSignature,
		LatticeHash:        protected.LatticeHash,
		LatticeSymbol:      protected.LatticeSymbol,
		EncryptionScheme:   protected.EncryptionScheme,
	}, nil
}

// UnprotectSupabaseRecord decrypts a Supabase row back to original data.
//
// Parameters:
//   - row: Encrypted row from Supabase SELECT query
//   - keys: Protection keys (must match keys used for encryption)
//
// Returns: Decrypted data as map[string]interface{} (convert to your struct)
func UnprotectSupabaseRecord(row *SupabaseEncryptedRow, keys *ProtectionKeys) (map[string]interface{}, error) {
	// Convert Supabase row to ProtectedData
	protected := &ProtectedData{
		DataID:             row.ID,
		DataType:           row.DataType,
		Context:            ContextAtRest,
		CreatedAt:          row.CreatedAt,
		ExpiresAt:          row.ExpiresAt,
		LatticeSymbol:      row.LatticeSymbol,
		LatticeHash:        row.LatticeHash,
		EncryptedPayload:   row.EncryptedPayload,
		Nonce:              row.Nonce,
		AEADTag:            row.AEADTag,
		KyberCapsule:       row.KyberCapsule,
		DilithiumSignature: row.DilithiumSignature,
		EncryptionScheme:   row.EncryptionScheme,
		Version:            "1.0.0",
	}

	// Unprotect using 4-layer PQC
	return UnprotectData(protected, keys, nil)
}

// ─── Supabase User Profile Protection ─────────────────────────────────────────

// UserProfileData represents sensitive user data to be encrypted.
type UserProfileData struct {
	Email       string                 `json:"email"`
	FullName    string                 `json:"full_name"`
	PhoneNumber string                 `json:"phone_number"`
	Address     string                 `json:"address"`
	SSN         string                 `json:"ssn"`          // Highly sensitive
	Metadata    map[string]interface{} `json:"metadata"`     // Custom fields
	Preferences map[string]interface{} `json:"preferences"`  // User preferences
}

// ProtectUserProfile encrypts user profile data for Supabase storage.
func ProtectUserProfile(profile *UserProfileData, keys *ProtectionKeys) (*SupabaseEncryptedRow, error) {
	return ProtectSupabaseRecord(profile, "user_profile", keys, time.Time{})
}

// UnprotectUserProfile decrypts user profile data from Supabase.
func UnprotectUserProfile(row *SupabaseEncryptedRow, keys *ProtectionKeys) (*UserProfileData, error) {
	plaintext, err := UnprotectSupabaseRecord(row, keys)
	if err != nil {
		return nil, err
	}

	// Convert map to UserProfileData
	profileJSON, _ := json.Marshal(plaintext)
	var profile UserProfileData
	if err := json.Unmarshal(profileJSON, &profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

// ─── Supabase Configuration Protection ────────────────────────────────────────

// ConfigData represents platform configuration data.
type ConfigData struct {
	APIKey          string                 `json:"api_key"`
	DatabaseURL     string                 `json:"database_url"`
	SecretKey       string                 `json:"secret_key"`
	FeatureFlags    map[string]bool        `json:"feature_flags"`
	ServiceConfig   map[string]interface{} `json:"service_config"`
	IntegrationKeys map[string]string      `json:"integration_keys"`
}

// ProtectConfig encrypts configuration data for Supabase storage.
func ProtectConfigData(config *ConfigData, keys *ProtectionKeys) (*SupabaseEncryptedRow, error) {
	return ProtectSupabaseRecord(config, "platform_config", keys, time.Time{})
}

// UnprotectConfigData decrypts configuration data from Supabase.
func UnprotectConfigData(row *SupabaseEncryptedRow, keys *ProtectionKeys) (*ConfigData, error) {
	plaintext, err := UnprotectSupabaseRecord(row, keys)
	if err != nil {
		return nil, err
	}

	// Convert map to ConfigData
	configJSON, _ := json.Marshal(plaintext)
	var config ConfigData
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// ─── Generic Data Transport Protection ────────────────────────────────────────

// TransportEnvelope wraps any data for secure transit between systems.
type TransportEnvelope struct {
	SenderID    string                 `json:"sender_id"`
	RecipientID string                 `json:"recipient_id"`
	MessageType string                 `json:"message_type"`
	Payload     map[string]interface{} `json:"payload"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ProtectForHTTPTransport encrypts data for HTTP/API transit with recipient's public key.
//
// Use Case: Encrypting API responses, WebSocket messages, or any data leaving the system.
//
// Example:
//
//	envelope := &TransportEnvelope{
//	    SenderID:    "api-server-001",
//	    RecipientID: "client-app-123",
//	    MessageType: "scan_result",
//	    Payload:     scanResultMap,
//	    Timestamp:   time.Now(),
//	}
//	protected := ProtectForHTTPTransport(envelope, senderKeys, recipientKyberPubKey)
func ProtectForHTTPTransport(envelope *TransportEnvelope, senderKeys *ProtectionKeys, recipientKyberPubKey []byte) (*ProtectedData, error) {
	// Set timestamp
	envelope.Timestamp = time.Now()

	// Protect with 1-hour TTL (standard for HTTP requests)
	expiresAt := time.Now().Add(1 * time.Hour)
	return ProtectData(envelope, "transport", ContextInTransit, senderKeys, recipientKyberPubKey, expiresAt)
}

// UnprotectFromHTTPTransport decrypts data received via HTTP/API.
//
// Parameters:
//   - protected: Encrypted data from HTTP request/response
//   - recipientKeys: Recipient's keys (for Kyber decryption)
//   - senderDilithiumPubKey: Sender's public key (for signature verification)
func UnprotectFromHTTPTransport(protected *ProtectedData, recipientKeys *ProtectionKeys, senderDilithiumPubKey []byte) (*TransportEnvelope, error) {
	plaintext, err := UnprotectData(protected, recipientKeys, senderDilithiumPubKey)
	if err != nil {
		return nil, err
	}

	// Convert to TransportEnvelope
	envelopeJSON, _ := json.Marshal(plaintext)
	var envelope TransportEnvelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, err
	}

	return &envelope, nil
}

// ─── Batch Operations ──────────────────────────────────────────────────────────

// ProtectSupabaseBatch encrypts multiple records in parallel for bulk INSERT.
//
// Example:
//
//	users := []UserProfileData{user1, user2, user3}
//	protectedRows, errors := ProtectSupabaseBatch(users, "user_profile", keys)
//	supabase.From("users").Insert(protectedRows)
func ProtectSupabaseBatch(records []interface{}, dataType string, keys *ProtectionKeys) ([]*SupabaseEncryptedRow, []error) {
	results := make([]*SupabaseEncryptedRow, len(records))
	errors := make([]error, len(records))

	// Process in parallel (optional: add goroutine pool for very large batches)
	for i, record := range records {
		row, err := ProtectSupabaseRecord(record, dataType, keys, time.Time{})
		results[i] = row
		errors[i] = err
	}

	return results, errors
}

// UnprotectSupabaseBatch decrypts multiple records in parallel for bulk SELECT.
func UnprotectSupabaseBatch(rows []*SupabaseEncryptedRow, keys *ProtectionKeys) ([]map[string]interface{}, []error) {
	results := make([]map[string]interface{}, len(rows))
	errors := make([]error, len(rows))

	for i, row := range rows {
		plaintext, err := UnprotectSupabaseRecord(row, keys)
		results[i] = plaintext
		errors[i] = err
	}

	return results, errors
}

// ─── Migration Helpers ─────────────────────────────────────────────────────────

// GenerateSupabaseSchema generates SQL DDL for encrypted table schema.
//
// Example:
//
//	sql := GenerateSupabaseSchema("users_encrypted", "user_profile")
//	// Execute this SQL in Supabase SQL editor to create the table
func GenerateSupabaseSchema(tableName string, dataType string) string {
	return fmt.Sprintf(`
-- PQC-protected table: %s
-- Data type: %s
-- Schema version: 1.0.0

CREATE TABLE IF NOT EXISTS %s (
    -- Plaintext columns (for indexing and querying)
    id                  TEXT PRIMARY KEY,
    data_type           TEXT NOT NULL DEFAULT '%s',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ, -- NULL = never expires

    -- Encrypted columns (4-layer PQC protection)
    encrypted_payload   BYTEA NOT NULL,
    nonce               BYTEA NOT NULL,       -- 12 bytes
    aead_tag            BYTEA NOT NULL,       -- 16 bytes
    kyber_capsule       BYTEA,                -- 1568 bytes (nullable for non-transit data)
    dilithium_signature BYTEA NOT NULL,       -- ~3309 bytes
    lattice_hash        TEXT NOT NULL,
    lattice_symbol      TEXT NOT NULL,
    encryption_scheme   TEXT NOT NULL DEFAULT 'ADINKHEPRA_AES256GCM_KYBER1024_MLDSA65',

    -- Constraints
    CONSTRAINT chk_encryption_scheme CHECK (encryption_scheme = 'ADINKHEPRA_AES256GCM_KYBER1024_MLDSA65')
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_%s_data_type ON %s(data_type);
CREATE INDEX IF NOT EXISTS idx_%s_created_at ON %s(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_%s_expires_at ON %s(expires_at) WHERE expires_at IS NOT NULL;

-- Cleanup expired rows (run daily via pg_cron)
-- DELETE FROM %s WHERE expires_at IS NOT NULL AND expires_at < NOW();

-- Row-Level Security (RLS) - Example policy
ALTER TABLE %s ENABLE ROW LEVEL SECURITY;

-- Allow service role to access all rows
CREATE POLICY service_role_all ON %s
    FOR ALL USING (auth.role() = 'service_role');

-- Allow authenticated users to access their own data (if user_id column exists)
-- CREATE POLICY user_own_data ON %s
--     FOR SELECT USING (auth.uid()::text = user_id);

COMMENT ON TABLE %s IS 'PQC-protected table with 4-layer encryption (Adinkhepra + AES-256-GCM + Kyber-1024 + ML-DSA-65)';
`, tableName, dataType, tableName, dataType,
		tableName, tableName,
		tableName, tableName,
		tableName, tableName,
		tableName,
		tableName,
		tableName,
		tableName,
		tableName)
}

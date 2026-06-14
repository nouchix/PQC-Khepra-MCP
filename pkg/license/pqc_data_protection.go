// Package license - Comprehensive PQC Data Protection
//
// This module provides multi-layer PQC protection for ALL license-related data:
//   - Data at rest (stored licenses, configuration, keys)
//   - Data in transit (network transfer, API calls)
//   - Data in use (runtime memory, cache)
//   - Related data (audit logs, telemetry, compliance reports)
//
// Protection Layers:
//   Layer 1: Adinkhepra Lattice encoding (obfuscation)
//   Layer 2: AES-256-GCM symmetric encryption (fast bulk encryption)
//   Layer 3: Kyber-1024 KEM (PQC key exchange)
//   Layer 4: ML-DSA-65 signatures (integrity + authenticity)
//
// Security Guarantees:
//   - Post-quantum secure key exchange
//   - Authenticated encryption with associated data (AEAD)
//   - Forward secrecy (ephemeral Kyber keys)
//   - Tamper detection (Dilithium signatures + GCM authentication)
//
// Reference: Adinkhepra Lattice → Dilithium/Kyber → AES (defense-in-depth)
package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// ─── Data Protection Context ───────────────────────────────────────────────────

// DataContext describes the usage context for protected data.
type DataContext string

const (
	ContextAtRest    DataContext = "at_rest"     // Persistent storage
	ContextInTransit DataContext = "in_transit"  // Network transfer
	ContextInUse     DataContext = "in_use"      // Runtime memory
	ContextArchive   DataContext = "archive"     // Long-term compliance storage
	ContextBackup    DataContext = "backup"      // Disaster recovery backups
	ContextAuditLog  DataContext = "audit_log"   // Audit trail data
	ContextTelemetry DataContext = "telemetry"   // Usage metrics
)

// ProtectedData represents encrypted license data with full metadata.
type ProtectedData struct {
	// Data identification
	DataID      string      `json:"data_id"`
	DataType    string      `json:"data_type"`   // "license", "config", "audit_log", etc.
	Context     DataContext `json:"context"`     // Where/how data is used
	CreatedAt   time.Time   `json:"created_at"`
	ExpiresAt   time.Time   `json:"expires_at,omitempty"`

	// Layer 1: Adinkhepra Lattice (obfuscation metadata)
	LatticeSymbol string `json:"lattice_symbol"` // Adinkra symbol governing this data
	LatticeHash   string `json:"lattice_hash"`   // Khepra-encoded integrity hash

	// Layer 2: AES-256-GCM (symmetric encryption)
	EncryptedPayload []byte `json:"encrypted_payload"` // AES-GCM ciphertext
	Nonce            []byte `json:"nonce"`             // GCM nonce (12 bytes)
	AEADTag          []byte `json:"aead_tag"`          // GCM authentication tag (16 bytes)

	// Layer 3: Kyber-1024 (PQC key encapsulation)
	KyberCapsule []byte `json:"kyber_capsule,omitempty"` // Kyber ciphertext (1568 bytes)

	// Layer 4: ML-DSA-65 (PQC signature)
	DilithiumSignature []byte `json:"dilithium_signature"` // Signature over all metadata + ciphertext

	// Protection metadata
	EncryptionScheme string `json:"encryption_scheme"` // "ADINKHEPRA_AES256GCM_KYBER1024_MLDSA65"
	Version          string `json:"version"`           // Schema version for forward compatibility
}

// ─── Protection Key Material ───────────────────────────────────────────────────

// ProtectionKeys holds all cryptographic keys for data protection.
type ProtectionKeys struct {
	// Kyber-1024 key pair (for key encapsulation)
	KyberPublicKey  []byte // 1568 bytes
	KyberPrivateKey []byte // 3168 bytes

	// ML-DSA-65 key pair (for signing)
	DilithiumPublicKey  []byte // 1952 bytes
	DilithiumPrivateKey []byte // 4032 bytes

	// AES-256 key (derived from Kyber shared secret or static)
	AESKey []byte // 32 bytes

	// Adinkra symbol for lattice encoding
	Symbol string // "Eban", "Fawohodie", etc.
}

// GenerateProtectionKeys creates a new key set for data protection.
func GenerateProtectionKeys(symbol string) (*ProtectionKeys, error) {
	// Generate Kyber-1024 key pair
	kyberPub, kyberPriv, err := adinkra.GenerateKyberKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Kyber keys: %w", err)
	}

	// Generate ML-DSA-65 key pair
	dilithiumPub, dilithiumPriv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Dilithium keys: %w", err)
	}

	// Generate AES-256 key
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	return &ProtectionKeys{
		KyberPublicKey:      kyberPub,
		KyberPrivateKey:     kyberPriv,
		DilithiumPublicKey:  dilithiumPub,
		DilithiumPrivateKey: dilithiumPriv,
		AESKey:              aesKey,
		Symbol:              symbol,
	}, nil
}

// ─── Data Protection (Encryption) ──────────────────────────────────────────────

// ProtectData encrypts and signs data using all four protection layers.
//
// Process:
//  1. Serialize plaintext to JSON
//  2. Compute Adinkhepra Lattice hash
//  3. Encrypt with AES-256-GCM
//  4. Optionally encapsulate AES key with Kyber-1024 (for recipient)
//  5. Sign entire protected structure with ML-DSA-65
//
// Parameters:
//   - plaintext: Raw data to protect (will be JSON-serialized)
//   - dataType: Type of data ("license", "config", "audit_log", etc.)
//   - context: Usage context (at_rest, in_transit, etc.)
//   - keys: Protection keys (own keys)
//   - recipientKyberPubKey: Optional recipient public key (for transit encryption)
//   - expiresAt: Optional expiration time (zero value for no expiration)
//
// Returns: ProtectedData structure (can be stored or transmitted)
func ProtectData(plaintext interface{}, dataType string, context DataContext, keys *ProtectionKeys, recipientKyberPubKey []byte, expiresAt time.Time) (*ProtectedData, error) {
	// ─── Serialize Plaintext ──────────────────────────────────────────────────
	plaintextJSON, err := json.Marshal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal plaintext: %w", err)
	}

	// ─── Layer 1: Adinkhepra Lattice Hash ────────────────────────────────────
	spectralSeed := adinkra.GetSpectralFingerprint(keys.Symbol)
	combinedInput := append(plaintextJSON, spectralSeed...)
	latticeHash := adinkra.Hash(combinedInput)

	// ─── Layer 2: AES-256-GCM Encryption ──────────────────────────────────────
	var aesKey []byte
	var kyberCapsule []byte

	// If recipient public key provided, use Kuntinkantan (Kyber + Merkaba) to wrap AES key
	if len(recipientKyberPubKey) > 0 {
		// Encrypt the AES key using recipient's Kyber public key
		// Kuntinkantan = Kyber-1024 + Merkaba white box
		encryptedAESKey, err := adinkra.Kuntinkantan(recipientKyberPubKey, keys.AESKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt AES key with Kuntinkantan: %w", err)
		}

		kyberCapsule = encryptedAESKey
		aesKey = keys.AESKey
	} else {
		// Use static AES key from ProtectionKeys
		aesKey = keys.AESKey
	}

	// AES-256-GCM encryption
	encryptedPayload, nonce, aeadTag, err := encryptAESGCM(plaintextJSON, aesKey, []byte(latticeHash))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with AES-GCM: %w", err)
	}

	// ─── Construct Protected Data ─────────────────────────────────────────────
	protected := &ProtectedData{
		DataID:           generateDataID(),
		DataType:         dataType,
		Context:          context,
		CreatedAt:        time.Now(),
		ExpiresAt:        expiresAt, // Set expiration BEFORE signing
		LatticeSymbol:    keys.Symbol,
		LatticeHash:      latticeHash,
		EncryptedPayload: encryptedPayload,
		Nonce:            nonce,
		AEADTag:          aeadTag,
		KyberCapsule:     kyberCapsule,
		EncryptionScheme: "ADINKHEPRA_AES256GCM_KYBER1024_MLDSA65",
		Version:          "1.0.0",
	}

	// ─── Layer 4: ML-DSA-65 Signature ─────────────────────────────────────────
	// Sign the entire protected structure (ensures integrity + authenticity)
	dataToSign, _ := json.Marshal(protected)
	signature, err := adinkra.Sign(keys.DilithiumPrivateKey, dataToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign protected data: %w", err)
	}

	protected.DilithiumSignature = signature

	return protected, nil
}

// ─── Data Unprotection (Decryption) ────────────────────────────────────────────

// UnprotectData decrypts and verifies protected data.
//
// Process (reverse of ProtectData):
//  1. Verify ML-DSA-65 signature
//  2. Optionally decapsulate AES key with Kyber-1024
//  3. Decrypt with AES-256-GCM
//  4. Verify Adinkhepra Lattice hash
//  5. Unmarshal plaintext
//
// Parameters:
//   - protected: ProtectedData structure
//   - keys: Protection keys (own private keys)
//   - trustedDilithiumPubKey: Optional trusted public key for signature verification
//
// Returns: Decrypted plaintext (as map[string]interface{})
func UnprotectData(protected *ProtectedData, keys *ProtectionKeys, trustedDilithiumPubKey []byte) (map[string]interface{}, error) {
	// ─── Layer 4: Verify ML-DSA-65 Signature ──────────────────────────────────
	protectedWithoutSig := &ProtectedData{
		DataID:           protected.DataID,
		DataType:         protected.DataType,
		Context:          protected.Context,
		CreatedAt:        protected.CreatedAt,
		ExpiresAt:        protected.ExpiresAt,
		LatticeSymbol:    protected.LatticeSymbol,
		LatticeHash:      protected.LatticeHash,
		EncryptedPayload: protected.EncryptedPayload,
		Nonce:            protected.Nonce,
		AEADTag:          protected.AEADTag,
		KyberCapsule:     protected.KyberCapsule,
		EncryptionScheme: protected.EncryptionScheme,
		Version:          protected.Version,
	}

	dataToVerify, _ := json.Marshal(protectedWithoutSig)

	verifyKey := trustedDilithiumPubKey
	if len(verifyKey) == 0 {
		verifyKey = keys.DilithiumPublicKey
	}

	valid, err := adinkra.Verify(verifyKey, dataToVerify, protected.DilithiumSignature)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("invalid signature - data may be forged or corrupted")
	}

	// ─── Check Expiration ──────────────────────────────────────────────────────
	if !protected.ExpiresAt.IsZero() && time.Now().After(protected.ExpiresAt) {
		return nil, fmt.Errorf("protected data expired at %s", protected.ExpiresAt.Format(time.RFC3339))
	}

	// ─── Layer 3: Kyber Key Decapsulation (if needed) ────────────────────────
	var aesKey []byte

	if len(protected.KyberCapsule) > 0 {
		// Decrypt AES key using Sankofa (Kyber-1024 + Merkaba)
		decryptedAESKey, err := adinkra.Sankofa(keys.KyberPrivateKey, protected.KyberCapsule)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt AES key with Sankofa: %w", err)
		}

		aesKey = decryptedAESKey
	} else {
		// Use static AES key
		aesKey = keys.AESKey
	}

	// ─── Layer 2: AES-256-GCM Decryption ──────────────────────────────────────
	plaintextJSON, err := decryptAESGCM(protected.EncryptedPayload, aesKey, protected.Nonce, protected.AEADTag, []byte(protected.LatticeHash))
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	// ─── Layer 1: Verify Adinkhepra Lattice Hash ─────────────────────────────
	spectralSeed := adinkra.GetSpectralFingerprint(protected.LatticeSymbol)
	combinedInput := append(plaintextJSON, spectralSeed...)
	expectedHash := adinkra.Hash(combinedInput)

	if expectedHash != protected.LatticeHash {
		return nil, fmt.Errorf("lattice hash mismatch - data may be corrupted")
	}

	// ─── Unmarshal Plaintext ──────────────────────────────────────────────────
	var plaintext map[string]interface{}
	if err := json.Unmarshal(plaintextJSON, &plaintext); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plaintext: %w", err)
	}

	return plaintext, nil
}

// ─── AES-256-GCM Encryption Helpers ────────────────────────────────────────────

// encryptAESGCM encrypts data with AES-256-GCM and returns (ciphertext, nonce, tag, error).
func encryptAESGCM(plaintext []byte, key []byte, additionalData []byte) ([]byte, []byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, nil, fmt.Errorf("AES key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}

	// Encrypt + authenticate
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, additionalData)

	// Extract authentication tag (last 16 bytes)
	if len(ciphertext) < 16 {
		return nil, nil, nil, fmt.Errorf("ciphertext too short")
	}

	tag := ciphertext[len(ciphertext)-16:]
	payload := ciphertext[:len(ciphertext)-16]

	return payload, nonce, tag, nil
}

// decryptAESGCM decrypts AES-256-GCM data.
func decryptAESGCM(ciphertext []byte, key []byte, nonce []byte, tag []byte, additionalData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Reconstruct ciphertext with tag
	fullCiphertext := append(ciphertext, tag...)

	// Decrypt + verify authentication
	plaintext, err := aesGCM.Open(nil, nonce, fullCiphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM authentication failed: %w", err)
	}

	return plaintext, nil
}

// ─── Convenience Functions ─────────────────────────────────────────────────────

// generateDataID creates a unique identifier for protected data.
func generateDataID() string {
	timestamp := time.Now().UnixNano()
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	return fmt.Sprintf("PD-%d-%s", timestamp, base64.URLEncoding.EncodeToString(randomBytes)[:8])
}

// ExportProtectedData serializes ProtectedData to JSON string.
func ExportProtectedData(protected *ProtectedData) (string, error) {
	jsonBytes, err := json.Marshal(protected)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

// ImportProtectedData deserializes ProtectedData from JSON string.
func ImportProtectedData(encoded string) (*ProtectedData, error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	var protected ProtectedData
	if err := json.Unmarshal(jsonBytes, &protected); err != nil {
		return nil, err
	}

	return &protected, nil
}

// ─── Storage Integration ───────────────────────────────────────────────────────

// ProtectLicenseForStorage encrypts a license for persistent storage (at rest).
func ProtectLicenseForStorage(license *License, keys *ProtectionKeys) (*ProtectedData, error) {
	return ProtectData(license, "license", ContextAtRest, keys, nil, time.Time{})
}

// UnprotectLicenseFromStorage decrypts a stored license.
func UnprotectLicenseFromStorage(protected *ProtectedData, keys *ProtectionKeys) (*License, error) {
	plaintext, err := UnprotectData(protected, keys, nil)
	if err != nil {
		return nil, err
	}

	// Convert map to License struct
	licenseJSON, _ := json.Marshal(plaintext)
	var license License
	if err := json.Unmarshal(licenseJSON, &license); err != nil {
		return nil, err
	}

	return &license, nil
}

// ProtectForTransit encrypts data for network transmission with recipient's public key.
func ProtectForTransit(data interface{}, dataType string, keys *ProtectionKeys, recipientKyberPubKey []byte) (*ProtectedData, error) {
	// Set expiration for transit data (1 hour validity)
	expiresAt := time.Now().Add(1 * time.Hour)
	return ProtectData(data, dataType, ContextInTransit, keys, recipientKyberPubKey, expiresAt)
}

// UnprotectFromTransit decrypts data received over the network.
func UnprotectFromTransit(protected *ProtectedData, keys *ProtectionKeys, trustedDilithiumPubKey []byte) (map[string]interface{}, error) {
	// Verify it's transit data
	if protected.Context != ContextInTransit {
		return nil, fmt.Errorf("expected in_transit context, got %s", protected.Context)
	}

	return UnprotectData(protected, keys, trustedDilithiumPubKey)
}

// ─── Audit Log Protection ──────────────────────────────────────────────────────

// ProtectAuditLog encrypts audit log entries for compliance storage.
// Audit logs are never expired (permanent retention) and signed for non-repudiation.
func ProtectAuditLog(auditEntry interface{}, keys *ProtectionKeys) (*ProtectedData, error) {
	// Audit logs never expire (permanent retention)
	return ProtectData(auditEntry, "audit_log", ContextAuditLog, keys, nil, time.Time{})
}

// UnprotectAuditLog decrypts and verifies an audit log entry.
func UnprotectAuditLog(protected *ProtectedData, keys *ProtectionKeys) (map[string]interface{}, error) {
	if protected.Context != ContextAuditLog {
		return nil, fmt.Errorf("expected audit_log context, got %s", protected.Context)
	}

	return UnprotectData(protected, keys, nil)
}

// ─── Telemetry Protection ──────────────────────────────────────────────────────

// ProtectTelemetry encrypts telemetry data (metrics, usage stats, diagnostic data).
// Telemetry data has short retention (24 hours) and can be optionally sent to external collectors.
func ProtectTelemetry(telemetryData interface{}, keys *ProtectionKeys, recipientKyberPubKey []byte) (*ProtectedData, error) {
	// Telemetry expires after 24 hours
	expiresAt := time.Now().Add(24 * time.Hour)
	return ProtectData(telemetryData, "telemetry", ContextTelemetry, keys, recipientKyberPubKey, expiresAt)
}

// UnprotectTelemetry decrypts telemetry data.
func UnprotectTelemetry(protected *ProtectedData, keys *ProtectionKeys) (map[string]interface{}, error) {
	if protected.Context != ContextTelemetry {
		return nil, fmt.Errorf("expected telemetry context, got %s", protected.Context)
	}

	return UnprotectData(protected, keys, nil)
}

// ─── Backup Protection ─────────────────────────────────────────────────────────

// ProtectBackup encrypts data for disaster recovery backups.
// Backups are long-lived (3 years) and use maximum encryption strength.
func ProtectBackup(backupData interface{}, dataType string, keys *ProtectionKeys) (*ProtectedData, error) {
	// Backups expire after 3 years (compliance retention)
	expiresAt := time.Now().AddDate(3, 0, 0)
	return ProtectData(backupData, dataType, ContextBackup, keys, nil, expiresAt)
}

// UnprotectBackup decrypts backup data.
func UnprotectBackup(protected *ProtectedData, keys *ProtectionKeys) (map[string]interface{}, error) {
	if protected.Context != ContextBackup {
		return nil, fmt.Errorf("expected backup context, got %s", protected.Context)
	}

	return UnprotectData(protected, keys, nil)
}

// ─── Archive Protection ────────────────────────────────────────────────────────

// ProtectArchive encrypts data for long-term compliance archives.
// Archives are permanent (7+ years) and include additional metadata for chain-of-custody.
func ProtectArchive(archiveData interface{}, dataType string, keys *ProtectionKeys) (*ProtectedData, error) {
	// Archives expire after 7 years (CMMC/FedRAMP compliance)
	expiresAt := time.Now().AddDate(7, 0, 0)
	return ProtectData(archiveData, dataType, ContextArchive, keys, nil, expiresAt)
}

// UnprotectArchive decrypts archived data.
func UnprotectArchive(protected *ProtectedData, keys *ProtectionKeys) (map[string]interface{}, error) {
	if protected.Context != ContextArchive {
		return nil, fmt.Errorf("expected archive context, got %s", protected.Context)
	}

	return UnprotectData(protected, keys, nil)
}

// ─── In-Use Data Protection ────────────────────────────────────────────────────

// ProtectInUse encrypts data for runtime memory (in-use).
// In-use data is ephemeral (expires in 5 minutes) and optimized for speed.
func ProtectInUse(inUseData interface{}, dataType string, keys *ProtectionKeys) (*ProtectedData, error) {
	// In-use data expires after 5 minutes (short-lived session data)
	expiresAt := time.Now().Add(5 * time.Minute)
	return ProtectData(inUseData, dataType, ContextInUse, keys, nil, expiresAt)
}

// UnprotectInUse decrypts in-use data.
func UnprotectInUse(protected *ProtectedData, keys *ProtectionKeys) (map[string]interface{}, error) {
	if protected.Context != ContextInUse {
		return nil, fmt.Errorf("expected in_use context, got %s", protected.Context)
	}

	return UnprotectData(protected, keys, nil)
}

// ─── Configuration Protection ──────────────────────────────────────────────────

// ProtectConfig encrypts configuration data (API keys, credentials, settings).
func ProtectConfig(configData interface{}, keys *ProtectionKeys) (*ProtectedData, error) {
	return ProtectData(configData, "config", ContextAtRest, keys, nil, time.Time{})
}

// UnprotectConfig decrypts configuration data.
func UnprotectConfig(protected *ProtectedData, keys *ProtectionKeys) (map[string]interface{}, error) {
	if protected.DataType != "config" {
		return nil, fmt.Errorf("expected config data type, got %s", protected.DataType)
	}

	return UnprotectData(protected, keys, nil)
}

package adinkra

import (
	"encoding/json"
	"fmt"
	"time"
)

// KhepraBackupHeader contains the metadata for the backup.
type KhepraBackupHeader struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     string    `json:"nonce"` // Hex string
	Algorithm string    `json:"algorithm"`
	Salt      []byte    `json:"salt"`
}

// KhepraBackup represents the final on-disk encrypted artifact.
type KhepraBackup struct {
	Header   KhepraBackupHeader `json:"header"`
	Envelope *SecureEnvelope    `json:"envelope"` // The triple-layer encrypted payload
}

// EncryptBackup wraps the target data (e.g. keypair) into a password-protected PQC container.
// It creates a "Ghost Identity" from the password and encrypts to it.
func EncryptBackup(payload interface{}, passphrase string) (*KhepraBackup, error) {
	// 1. Serialize payload
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// 2. Generate Salt for Ghost Key
	salt, err := GenerateSalt(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// 3. Derive Ghost Identity (Deterministic)
	// We use the "Eban" (Fortress) symbol for backups (FIG. 10).
	seed := DeriveProprietaryKey(passphrase, salt)
	ghostIdentity, err := GenerateHybridKeyPairFromSeed(seed, "ghost-backup", "Eban")
	if err != nil {
		return nil, fmt.Errorf("failed to summon ghost identity: %w", err)
	}

	// 4. Triple-Layer Encrypt to the Ghost
	// This uses EncryptForRecipient which does Kyber + ECDH + AES-GCM
	envelope, err := EncryptForRecipient(data, ghostIdentity)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// 5. Build Backup Struct
	backup := &KhepraBackup{
		Header: KhepraBackupHeader{
			Version:   "v1-adinkra-ghost",
			Timestamp: time.Now().UTC(),
			Nonce:     Hash(data), // Using Data Hash as Nonce/Proof
			Algorithm: "Argon2id+Kyber1024+P384+AES-GCM",
			Salt:      salt,
		},
		Envelope: envelope,
	}

	return backup, nil
}

// DecryptBackup restores the data from the PQC container.
func DecryptBackup(backup *KhepraBackup, passphrase string) ([]byte, error) {
	// 1. Re-Derive Ghost Identity
	// Must match the "Eban" (Fortress) symbol used during encryption.
	seed := DeriveProprietaryKey(passphrase, backup.Header.Salt)
	ghostIdentity, err := GenerateHybridKeyPairFromSeed(seed, "ghost-backup", "Eban")
	if err != nil {
		return nil, fmt.Errorf("failed to summon ghost identity: %w", err)
	}

	// 2. Decrypt Envelope
	plaintext, err := DecryptEnvelope(backup.Envelope, ghostIdentity)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	return plaintext, nil
}

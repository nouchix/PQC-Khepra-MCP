package adinkra

import (
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nouchix/khepra-pqc/kdf"
)

// BackupVersion identifies the current passphrase-protected backup format.
const BackupVersion = "v3-pbkdf2-aes256gcm"

// KhepraBackupHeader contains the metadata for the backup.
type KhepraBackupHeader struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Algorithm string    `json:"algorithm"`
	Salt      []byte    `json:"salt"`
}

// KhepraBackup is the on-disk passphrase-protected artifact.
type KhepraBackup struct {
	Header     KhepraBackupHeader `json:"header"`
	Ciphertext []byte             `json:"ciphertext"` // AES-256-GCM: nonce | ciphertext | tag
}

// EncryptBackup protects payload with a passphrase: PBKDF2-HMAC-SHA-384
// (SP 800-132) derives an AES-256-GCM key from the passphrase and a fresh
// salt. The header is bound to the ciphertext as additional data, so it
// cannot be altered without detection.
func EncryptBackup(payload interface{}, passphrase string) (*KhepraBackup, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	salt, err := kdf.NewSalt()
	if err != nil {
		return nil, err
	}
	backup := &KhepraBackup{Header: KhepraBackupHeader{
		Version:   BackupVersion,
		Timestamp: time.Now().UTC(),
		Algorithm: "PBKDF2-HMAC-SHA-384+AES-256-GCM",
		Salt:      salt,
	}}
	aead, aad, err := backupAEAD(passphrase, backup.Header)
	if err != nil {
		return nil, err
	}
	backup.Ciphertext = aead.Seal(nil, nil, data, aad)
	return backup, nil
}

// DecryptBackup restores the data from a backup made by EncryptBackup.
func DecryptBackup(backup *KhepraBackup, passphrase string) ([]byte, error) {
	if backup == nil {
		return nil, fmt.Errorf("backup is nil")
	}
	if backup.Header.Version != BackupVersion {
		return nil, fmt.Errorf("unsupported backup version %q (this build reads %q)", backup.Header.Version, BackupVersion)
	}
	aead, aad, err := backupAEAD(passphrase, backup.Header)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nil, backup.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase or modified backup)")
	}
	return plaintext, nil
}

func backupAEAD(passphrase string, header KhepraBackupHeader) (cipher.AEAD, []byte, error) {
	key, err := kdf.PassphraseKey(passphrase, header.Salt, 32)
	if err != nil {
		return nil, nil, err
	}
	aead, err := newRandomNonceGCM(key)
	if err != nil {
		return nil, nil, err
	}
	aad, err := json.Marshal(header)
	if err != nil {
		return nil, nil, err
	}
	return aead, aad, nil
}

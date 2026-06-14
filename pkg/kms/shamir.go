// pkg/kms/shamir.go — Shamir Secret Sharing for root key backup/recovery
//
// Each shard is individually encrypted under its own Argon2id-derived key
// before being written to disk. Stealing N files means nothing without N
// passphrases — the shard data is worthless without its encryption key.
//
// Uses the local GF(2^8) Shamir implementation in shamir_gf256.go —
// no external dependencies required.

package kms

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// KeyShard represents one shard of a Shamir-split root seed.
// The ShardData field is AES-256-GCM encrypted under a per-shard Argon2id key —
// each shard requires its own passphrase to decrypt.
type KeyShard struct {
	Index          int       `json:"index"`
	Total          int       `json:"total"`
	Threshold      int       `json:"threshold"`
	EncryptedShard []byte    `json:"encrypted_shard"` // AES-GCM ciphertext of the raw shard
	Salt           []byte    `json:"salt"`            // Argon2id salt (unique per shard)
	KDFAlgorithm   string    `json:"kdf_algorithm"`   // "argon2id"
	CreatedAt      time.Time `json:"created_at"`
	RootFingerprint string   `json:"root_fingerprint"`
}

// SplitAndEncrypt divides the root seed into `total` shards where any
// `threshold` can reconstruct it. Each shard is encrypted independently
// under a passphrase provided interactively, making shard theft non-trivial.
//
// promptFn is the caller-supplied passphrase prompt (allows testing without stdin).
func SplitAndEncrypt(rootSeed []byte, threshold, total int, outDir string, promptFn func(prompt string) (string, error)) error {
	if threshold < 2 || threshold > total {
		return fmt.Errorf("threshold must be 2 ≤ threshold ≤ total, got %d-of-%d", threshold, total)
	}
	if len(rootSeed) == 0 {
		return fmt.Errorf("root seed is empty")
	}

	shards, err := shamirSplit(rootSeed, threshold, total)
	if err != nil {
		return fmt.Errorf("shamir split: %w", err)
	}

	fp := shardFingerprint(rootSeed)
	fmt.Printf("\n  Root fingerprint: KHEPRA-ROOT-%s\n", fp[:16])
	fmt.Printf("  Splitting into %d shards (any %d reconstruct the key)\n\n", total, threshold)

	if err := os.MkdirAll(outDir, 0700); err != nil {
		return fmt.Errorf("create output dir %s: %w", outDir, err)
	}

	for i, shard := range shards {
		if err := encryptAndWriteShard(i, shard, total, threshold, fp, outDir, promptFn); err != nil {
			return err
		}
	}

	fmt.Printf("\n  ⚠️  Store each shard file on a separate encrypted USB or offline location.\n")
	fmt.Printf("  Any %d of %d passphrases + shard files can reconstruct your root key.\n", threshold, total)
	return nil
}

// encryptAndWriteShard encrypts a single Shamir shard and writes it to disk.
func encryptAndWriteShard(i int, shard []byte, total, threshold int, fp, outDir string, promptFn func(string) (string, error)) error {
	passphrase, err := promptFn(fmt.Sprintf("Enter passphrase for shard %d/%d: ", i+1, total))
	if err != nil {
		return fmt.Errorf("passphrase prompt for shard %d: %w", i+1, err)
	}
	if passphrase == "" {
		return fmt.Errorf("shard %d passphrase cannot be empty", i+1)
	}

	salt, err := NewSalt()
	if err != nil {
		return fmt.Errorf("salt generation for shard %d: %w", i+1, err)
	}
	shardKey := DeriveKey([]byte(passphrase), salt, DefaultKDFParams)

	encryptedShard, err := aesGCMEncrypt(shardKey[:32], shard)
	if err != nil {
		return fmt.Errorf("encrypt shard %d: %w", i+1, err)
	}

	ks := KeyShard{
		Index:           i + 1,
		Total:           total,
		Threshold:       threshold,
		EncryptedShard:  encryptedShard,
		Salt:            salt,
		KDFAlgorithm:    "argon2id",
		CreatedAt:       time.Now().UTC(),
		RootFingerprint: fp,
	}

	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal shard %d: %w", i+1, err)
	}

	path := filepath.Join(outDir, fmt.Sprintf("shard-%d-of-%d.json", i+1, total))
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write shard %d to %d: %w", i+1, total, err)
	}
	fmt.Printf("  ✓ Shard %d/%d → %s\n", i+1, total, path)
	return nil
}

// RecoverKey reconstructs the root seed from shard files.
// The caller must supply passphrases for each shard via promptFn.
func RecoverKey(shardPaths []string, promptFn func(prompt string) (string, error)) ([]byte, error) {
	if len(shardPaths) < 2 {
		return nil, fmt.Errorf("need at least 2 shard files, got %d", len(shardPaths))
	}

	var rawShards [][]byte
	for _, path := range shardPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read shard file %s: %w", path, err)
		}

		var ks KeyShard
		if err := json.Unmarshal(data, &ks); err != nil {
			return nil, fmt.Errorf("parse shard file %s: %w", path, err)
		}

		passphrase, err := promptFn(fmt.Sprintf("Enter passphrase for shard %d/%d: ", ks.Index, ks.Total))
		if err != nil {
			return nil, fmt.Errorf("passphrase prompt: %w", err)
		}

		// Re-derive the shard encryption key
		shardKey := DeriveKey([]byte(passphrase), ks.Salt, DefaultKDFParams)

		rawShard, err := aesGCMDecrypt(shardKey[:32], ks.EncryptedShard)
		if err != nil {
			return nil, fmt.Errorf("decrypt shard %d: incorrect passphrase or corrupted shard", ks.Index)
		}
		rawShards = append(rawShards, rawShard)
	}

	seed, err := shamirCombine(rawShards)
	if err != nil {
		return nil, fmt.Errorf("shamir combine: %w — ensure you have the correct threshold of shards", err)
	}
	return seed, nil
}

// shardFingerprint returns a short hex fingerprint of the root seed.
// Used to link all shards to the same key without revealing the seed.
func shardFingerprint(seed []byte) string {
	h := sha256.Sum256(seed)
	return fmt.Sprintf("%x", h[:8])
}

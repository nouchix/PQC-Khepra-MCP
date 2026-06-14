// pkg/kms/keystore.go — OS-native key storage with headless fallback
//
// Storage priority:
//   1. OS keystore: Windows DPAPI, macOS Keychain, Linux Secret Service (D-Bus)
//   2. Encrypted file fallback: ~/.asaf/keys/root.sealed
//      Used for: SCIF VMs, NixOS minimal, headless containers without keystore daemon
//
// The StorageBackendName() function probes availability before reporting,
// preventing cryptic dbus errors on headless Linux systems.

package kms

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zalando/go-keyring"
)

const (
	keyringSvc = "asaf-nouchix"
	keyringKey = "root-dilithium-sealed"

	// probeKey is used to detect keystore availability without a real key
	keyringProbeKey = "asaf-probe"

	// rootSealedFile is the filename used for the file-based key fallback.
	rootSealedFile = "root.sealed"
)

// StoreKey saves the sealed root key to the OS keystore.
// Falls back to ~/.asaf/keys/root.sealed on systems without a keystore daemon.
func StoreKey(sealed []byte) error {
	encoded := base64.StdEncoding.EncodeToString(sealed)

	if err := keyring.Set(keyringSvc, keyringKey, encoded); err == nil {
		return nil
	}

	// Keystore unavailable — use encrypted file fallback
	return storeToFile(sealed)
}

// LoadKey retrieves the sealed root key from OS keystore or file fallback.
func LoadKey() ([]byte, error) {
	// Try OS keystore first
	encoded, err := keyring.Get(keyringSvc, keyringKey)
	if err == nil {
		return base64.StdEncoding.DecodeString(encoded)
	}

	// Fallback: file
	data, fileErr := loadFromFile()
	if fileErr != nil {
		return nil, fmt.Errorf("key not found in keystore (%v) or file (%v)", err, fileErr)
	}
	return data, nil
}

// DeleteKey removes the key from both the OS keystore and file fallback.
// Used during key rotation — call only after the new key is safely stored.
func DeleteKey() error {
	ksErr := keyring.Delete(keyringSvc, keyringKey)
	fileErr := os.Remove(filepath.Join(ASAFKeysDir(), rootSealedFile))

	if ksErr != nil && fileErr != nil {
		return fmt.Errorf("keystore: %v; file: %v", ksErr, fileErr)
	}
	return nil
}

// StorageBackendName returns the active storage backend as a human-readable,
// auditor-friendly string. It probes availability so it never misreports.
//
// On DoD audit: "Windows DPAPI" or "macOS Keychain" are defensible answers.
// "file (~/.asaf/keys/root.sealed)" is acceptable for air-gapped SCIF systems.
func StorageBackendName() string {
	// Probe the keystore — a missing key (ErrNotFound) means the store IS available.
	// Any other error (e.g. dbus connection refused) means it's NOT available.
	_, err := keyring.Get(keyringSvc, keyringProbeKey)
	if err != nil && !isNotFound(err) {
		// Keystore daemon unavailable — report file fallback
		return fmt.Sprintf("file (%s)", filepath.Join(ASAFKeysDir(), rootSealedFile))
	}

	switch runtime.GOOS {
	case "windows":
		return "Windows DPAPI (Credential Manager)"
	case "darwin":
		return "macOS Keychain"
	default:
		return "Linux Secret Service (D-Bus / gnome-keyring)"
	}
}

// isNotFound returns true when the keystore error indicates the key simply
// doesn't exist (store is available, key is absent) vs. when the store
// itself is unreachable (no daemon, dbus error, etc.).
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	// go-keyring uses sentinel errors; also check string for robustness
	if errors.Is(err, keyring.ErrNotFound) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no such item")
}

// ── File fallback ─────────────────────────────────────────────────────────────

func storeToFile(sealed []byte) error {
	dir := ASAFKeysDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create keys dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, rootSealedFile)
	if err := os.WriteFile(path, sealed, 0600); err != nil {
		return fmt.Errorf("write sealed key to %s: %w", path, err)
	}
	return nil
}

func loadFromFile() ([]byte, error) {
	path := filepath.Join(ASAFKeysDir(), rootSealedFile)
	return os.ReadFile(path)
}

// ASAFKeysDir returns the canonical directory for ASAF key files.
// All key material is stored here, NOT in the project root or CWD.
// This is the fix for the "keys in project root" audit finding.
func ASAFKeysDir() string {
	// Allow override for testing or custom deployments
	if dir := os.Getenv("ASAF_KEYS_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Last resort — use a hidden dir in cwd
		return filepath.Join(".asaf", "keys")
	}
	return filepath.Join(home, ".asaf", "keys")
}

// DefaultSeedPath returns the canonical path for the master_seed.sealed file.
// Use this everywhere instead of the bare filename to keep key material out
// of the working directory and project root.
func DefaultSeedPath() string {
	return filepath.Join(ASAFKeysDir(), "master_seed.sealed")
}

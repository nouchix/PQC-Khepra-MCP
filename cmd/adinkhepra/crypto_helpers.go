// cmd/adinkhepra/crypto_helpers.go — AES-256-GCM helpers for cmd layer
// These are thin wrappers so cmd_keys.go doesn't import pkg/kms internals directly.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// aesGCMEncryptCmd encrypts plaintext with AES-256-GCM.
// Returns nonce || ciphertext || tag (standard GCM format).
func aesGCMEncryptCmd(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Output: nonce | ciphertext | tag, nonce generated inside the module.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nil, plaintext, nil), nil
}

// aesGCMDecryptCmd decrypts ciphertext produced by aesGCMEncryptCmd.
func aesGCMDecryptCmd(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	if len(data) < 12+gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, nil, data, nil)
}

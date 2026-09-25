// cmd/adinkhepra/crypto_helpers.go — AES-256-GCM helpers for cmd layer
// These are thin wrappers so cmd_keys.go doesn't import pkg/kms internals directly.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// aesGCMEncryptCmd encrypts plaintext with AES-256-GCM.
// Returns nonce || ciphertext || tag (standard GCM format).
func aesGCMEncryptCmd(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// aesGCMDecryptCmd decrypts ciphertext produced by aesGCMEncryptCmd.
func aesGCMDecryptCmd(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

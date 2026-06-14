package adinkra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ECIES (Elliptic Curve Integrated Encryption Scheme) with P-384
// Envelope: [EphemeralPublicKey(97 bytes) || EncryptedData || GCM-Tag]

// encryptECDH implements ECIES encryption using P-384 ECDH + AES-256-GCM
func encryptECDH(pub *ecdsa.PublicKey, sessionKey []byte) ([]byte, error) {
	// 1. Generate ephemeral ECDH key pair
	ephemeralPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// 2. Compute ECDH shared secret
	sharedX, _ := pub.Curve.ScalarMult(pub.X, pub.Y, ephemeralPriv.D.Bytes())
	if sharedX == nil {
		return nil, errors.New("ECDH key exchange failed")
	}

	// 3. Derive AES key from shared secret using HKDF-SHA512
	sharedSecret := sharedX.Bytes()
	kdf := hkdf.New(sha512.New, sharedSecret, nil, []byte("KHEPRA-ECIES-P384-V2"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, aesKey); err != nil {
		return nil, fmt.Errorf("KDF failed: %w", err)
	}

	// 4. Encrypt session key with AES-256-GCM
	encryptedKey, err := EncryptAESGCM(aesKey, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encryption failed: %w", err)
	}

	// 5. Serialize ephemeral public key (uncompressed format: 0x04 || X || Y)
	ephemeralPubBytes := elliptic.Marshal(elliptic.P384(), ephemeralPriv.PublicKey.X, ephemeralPriv.PublicKey.Y)

	// 6. Return [EphemeralPubKey || EncryptedSessionKey]
	result := make([]byte, 0, len(ephemeralPubBytes)+len(encryptedKey))
	result = append(result, ephemeralPubBytes...)
	result = append(result, encryptedKey...)

	return result, nil
}

// decryptECDH implements ECIES decryption using P-384 ECDH + AES-256-GCM
func decryptECDH(priv *ecdsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	// P-384 uncompressed public key is 97 bytes (0x04 || 48 bytes X || 48 bytes Y)
	const p384PubKeySize = 97

	if len(ciphertext) < p384PubKeySize {
		return nil, errors.New("ciphertext too short for ECIES")
	}

	// 1. Extract ephemeral public key
	ephemeralPubBytes := ciphertext[:p384PubKeySize]
	encryptedKey := ciphertext[p384PubKeySize:]

	// 2. Unmarshal ephemeral public key
	ephemeralX, ephemeralY := elliptic.Unmarshal(elliptic.P384(), ephemeralPubBytes)
	if ephemeralX == nil {
		return nil, errors.New("invalid ephemeral public key")
	}

	// 3. Compute ECDH shared secret
	sharedX, _ := priv.Curve.ScalarMult(ephemeralX, ephemeralY, priv.D.Bytes())
	if sharedX == nil {
		return nil, errors.New("ECDH key exchange failed")
	}

	// 4. Derive AES key from shared secret using HKDF-SHA512
	sharedSecret := sharedX.Bytes()
	kdf := hkdf.New(sha512.New, sharedSecret, nil, []byte("KHEPRA-ECIES-P384-V2"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, aesKey); err != nil {
		return nil, fmt.Errorf("KDF failed: %w", err)
	}

	// 5. Decrypt session key with AES-256-GCM
	sessionKey, err := DecryptAESGCM(aesKey, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return sessionKey, nil
}

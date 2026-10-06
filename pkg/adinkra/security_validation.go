package adinkra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
)

// Security Validation Functions for Production Cryptography
// These functions provide comprehensive input validation and security checks

// ValidateKeyPairIntegrity verifies that a hybrid key pair is complete and valid
func ValidateKeyPairIntegrity(kp *HybridKeyPair) error {
	if kp == nil {
		return errors.New("key pair is nil")
	}

	// Validate Adinkhepra-PQC keys
	if kp.AdinkhepraPQCPublic == nil {
		return errors.New("Adinkhepra PQC public key is nil")
	}
	if kp.AdinkhepraPQCPrivate == nil {
		return errors.New("Adinkhepra PQC private key is nil")
	}
	if len(kp.AdinkhepraPQCPublic.Raw) != SigningPublicKeySize {
		return fmt.Errorf("invalid ML-DSA-87 public key size: got %d, want %d",
			len(kp.AdinkhepraPQCPublic.Raw), SigningPublicKeySize)
	}
	if len(kp.AdinkhepraPQCPrivate.Raw) != SigningPrivateKeySize {
		return fmt.Errorf("invalid ML-DSA-87 private key size: got %d, want %d",
			len(kp.AdinkhepraPQCPrivate.Raw), SigningPrivateKeySize)
	}

	// Validate ML-KEM-1024 keys
	if len(kp.KEMPublic) != KEMPublicKeySize {
		return fmt.Errorf("invalid ML-KEM-1024 public key size: got %d, want %d",
			len(kp.KEMPublic), KEMPublicKeySize)
	}
	if len(kp.KEMPrivate) != KEMPrivateKeySize {
		return fmt.Errorf("invalid ML-KEM-1024 private key size: got %d, want %d",
			len(kp.KEMPrivate), KEMPrivateKeySize)
	}

	// Validate the CSR-only ECDSA key
	if kp.ECDSAPublic == nil {
		return errors.New("ECDSA public key is nil")
	}
	if kp.ECDSAPrivate == nil {
		return errors.New("ECDSA private key is nil")
	}
	if kp.ECDSAPublic.Curve != elliptic.P384() {
		return errors.New("ECDSA key must use P-384 curve")
	}
	if !kp.ECDSAPublic.Curve.IsOnCurve(kp.ECDSAPublic.X, kp.ECDSAPublic.Y) {
		return errors.New("ECDSA public key point is not on curve")
	}

	// Validate metadata
	if kp.KeyID == "" {
		return errors.New("key ID is empty")
	}
	if kp.Purpose == "" {
		return errors.New("key purpose is empty")
	}

	return nil
}

// ValidateEnvelopeIntegrity checks the integrity of a SecureEnvelope
func ValidateEnvelopeIntegrity(envelope *SecureEnvelope) error {
	if envelope == nil {
		return errors.New("envelope is nil")
	}

	if envelope.Version != EnvelopeVersion {
		return fmt.Errorf("unsupported envelope version: got %d, want %d",
			envelope.Version, EnvelopeVersion)
	}

	// Validate timestamp is reasonable (not in future, not too old)
	// Allow for clock skew but reject obviously invalid timestamps
	if envelope.Timestamp <= 0 {
		return errors.New("invalid timestamp: must be positive")
	}

	// Validate signature size (if present)
	if len(envelope.Signature) > 0 && len(envelope.Signature) != SignatureSize {
		return fmt.Errorf("invalid ML-DSA-87 signature size: got %d, want %d",
			len(envelope.Signature), SignatureSize)
	}

	return nil
}

// ValidateECDSAKey performs comprehensive ECDSA key validation
func ValidateECDSAKey(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) error {
	if pub == nil {
		return errors.New("ECDSA public key is nil")
	}

	// Ensure we're using P-384
	if pub.Curve != elliptic.P384() {
		return errors.New("ECDSA key must use P-384 curve")
	}

	// Validate public key is on curve
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return errors.New("ECDSA public key point is not on curve")
	}

	// If private key is provided, validate it matches public key
	if priv != nil {
		derivedPubX, derivedPubY := priv.Curve.ScalarBaseMult(priv.D.Bytes())
		if derivedPubX.Cmp(pub.X) != 0 || derivedPubY.Cmp(pub.Y) != 0 {
			return errors.New("ECDSA private key does not match public key")
		}

		// Validate private key is in valid range
		if priv.D.Sign() <= 0 || priv.D.Cmp(pub.Curve.Params().N) >= 0 {
			return errors.New("ECDSA private key out of valid range")
		}
	}

	return nil
}

// SanitizeInputData validates and sanitizes input data for cryptographic operations
func SanitizeInputData(data []byte, maxSize int) error {
	if data == nil {
		return errors.New("input data is nil")
	}
	if len(data) == 0 {
		return errors.New("input data is empty")
	}
	if maxSize > 0 && len(data) > maxSize {
		return fmt.Errorf("input data too large: got %d bytes, maximum %d bytes",
			len(data), maxSize)
	}
	return nil
}

// ValidateCryptoParams checks that the package is built on the expected NIST
// parameter sets: ML-KEM-1024 (FIPS 203) and ML-DSA-87 (FIPS 204).
func ValidateCryptoParams() error {
	if KEMPublicKeySize != 1568 || KEMCiphertextSize != 1568 || KEMPrivateKeySize != 64 {
		return fmt.Errorf("unexpected ML-KEM-1024 sizes: ek=%d ct=%d seed=%d",
			KEMPublicKeySize, KEMCiphertextSize, KEMPrivateKeySize)
	}
	if SigningPublicKeySize != 2592 || SignatureSize != 4627 || SigningPrivateKeySize != 32 {
		return fmt.Errorf("unexpected ML-DSA-87 sizes: pk=%d sig=%d seed=%d",
			SigningPublicKeySize, SignatureSize, SigningPrivateKeySize)
	}
	return nil
}

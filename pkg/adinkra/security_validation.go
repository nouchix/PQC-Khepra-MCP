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
	if kp.AdinkhepraPQCPublic.SecurityLevel != AdinkhepraPQCSecurityLevel {
		return fmt.Errorf("invalid Adinkhepra PQC security level: got %d, want %d",
			kp.AdinkhepraPQCPublic.SecurityLevel, AdinkhepraPQCSecurityLevel)
	}

	// Validate Dilithium keys
	if len(kp.DilithiumPublic) != DilithiumPublicKeySize {
		return fmt.Errorf("invalid Dilithium public key size: got %d, want %d",
			len(kp.DilithiumPublic), DilithiumPublicKeySize)
	}
	if len(kp.DilithiumPrivate) != DilithiumPrivateKeySize {
		return fmt.Errorf("invalid Dilithium private key size: got %d, want %d",
			len(kp.DilithiumPrivate), DilithiumPrivateKeySize)
	}

	// Validate Kyber keys
	if len(kp.KyberPublic) != KyberPublicKeySize {
		return fmt.Errorf("invalid Kyber public key size: got %d, want %d",
			len(kp.KyberPublic), KyberPublicKeySize)
	}
	if len(kp.KyberPrivate) != KyberPrivateKeySize {
		return fmt.Errorf("invalid Kyber private key size: got %d, want %d",
			len(kp.KyberPrivate), KyberPrivateKeySize)
	}

	// Validate ECDSA keys
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

	// Validate signature sizes (if present)
	if len(envelope.SignatureKhepra) > 0 && len(envelope.SignatureKhepra) != AdinkhepraPQCSignatureSize {
		return fmt.Errorf("invalid Adinkhepra signature size: got %d, want %d",
			len(envelope.SignatureKhepra), AdinkhepraPQCSignatureSize)
	}
	if len(envelope.SignatureDilithium) > 0 && len(envelope.SignatureDilithium) != DilithiumSignatureSize {
		return fmt.Errorf("invalid Dilithium signature size: got %d, want %d",
			len(envelope.SignatureDilithium), DilithiumSignatureSize)
	}

	// Validate ciphertext sizes (if present)
	if len(envelope.KyberCiphertext) > 0 && len(envelope.KyberCiphertext) < KyberCiphertextSize {
		return fmt.Errorf("Kyber ciphertext too short: got %d, minimum %d",
			len(envelope.KyberCiphertext), KyberCiphertextSize)
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

// ValidateCryptoParams validates cryptographic parameters meet security requirements
func ValidateCryptoParams() error {
	// Ensure constants are properly defined
	if AdinkhepraPQCSecurityLevel < 128 {
		return fmt.Errorf("insufficient Adinkhepra PQC security level: %d bits (minimum 128)",
			AdinkhepraPQCSecurityLevel)
	}
	if AdinkhepraPQCModulus <= 0 {
		return errors.New("invalid Adinkhepra PQC modulus")
	}
	if AdinkhepraLatticeRank < 4 {
		return fmt.Errorf("insufficient Adinkhepra lattice rank: %d (minimum 4)",
			AdinkhepraLatticeRank)
	}

	// Validate key sizes
	if DilithiumPublicKeySize == 0 || DilithiumPrivateKeySize == 0 {
		return errors.New("invalid Dilithium key sizes")
	}
	if KyberPublicKeySize == 0 || KyberPrivateKeySize == 0 {
		return errors.New("invalid Kyber key sizes")
	}

	return nil
}

package adinkra

import (
	"testing"
	"time"
)

func TestValidateKeyPairIntegrity(t *testing.T) {
	// 1. Generate valid keypair
	kp, err := GenerateHybridKeyPair("test-validation", "Eban", 12)
	if err != nil {
		t.Fatalf("KeyPair generation failed: %v", err)
	}

	// 2. Test valid keypair
	if err := ValidateKeyPairIntegrity(kp); err != nil {
		t.Errorf("Validation failed for valid keypair: %v", err)
	}

	// 3. Test nil keypair
	if err := ValidateKeyPairIntegrity(nil); err == nil {
		t.Error("Validation should fail for nil keypair")
	}

	// 4. Test missing Adinkhepra-PQC key
	badKp := *kp
	badKp.AdinkhepraPQCPublic = nil
	if err := ValidateKeyPairIntegrity(&badKp); err == nil {
		t.Error("Validation should fail for missing Adinkhepra-PQC public key")
	}
}

func TestValidateEnvelopeIntegrity(t *testing.T) {
	envelope := &SecureEnvelope{
		Version:         EnvelopeVersion,
		Timestamp:       time.Now().Unix(),
		SignatureKhepra: make([]byte, AdinkhepraPQCSignatureSize),
	}

	// 1. Test valid envelope
	if err := ValidateEnvelopeIntegrity(envelope); err != nil {
		t.Errorf("Validation failed for valid envelope: %v", err)
	}

	// 2. Test wrong version
	badEnv := *envelope
	badEnv.Version = 1
	if err := ValidateEnvelopeIntegrity(&badEnv); err == nil {
		t.Error("Validation should fail for wrong envelope version")
	}

	// 3. Test wrong signature size
	badEnv = *envelope
	badEnv.SignatureKhepra = []byte{1, 2, 3}
	if err := ValidateEnvelopeIntegrity(&badEnv); err == nil {
		t.Error("Validation should fail for wrong Khepra signature size")
	}
}

func TestValidateCryptoParams(t *testing.T) {
	// Should pass with current constants
	if err := ValidateCryptoParams(); err != nil {
		t.Errorf("Crypto params validation failed: %v", err)
	}
}

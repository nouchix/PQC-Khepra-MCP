//go:build !hsm

package crypto

import (
	"fmt"

	"github.com/nouchix/khepra-pqc/kem"
	"github.com/nouchix/khepra-pqc/sign"
)

// SoftwareBackend implements CryptoBackend on the Go Cryptographic Module.
type SoftwareBackend struct{}

func initBackendImpl() error {
	Backend = &SoftwareBackend{}
	return nil
}

// GenerateSigningKey generates an ML-DSA-87 key pair.
func (SoftwareBackend) GenerateSigningKey() (publicKey, privateKey []byte, err error) {
	sk, err := sign.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("ML-DSA-87 keygen: %w", err)
	}
	return sk.PublicKey().Bytes(), sk.Bytes(), nil
}

// Sign signs message with ML-DSA-87.
func (SoftwareBackend) Sign(ctx sign.Context, privateKey, message []byte) ([]byte, error) {
	sk, err := sign.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA-87 private key: %w", err)
	}
	sig, err := sk.Sign(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA-87 sign: %w", err)
	}
	return sig, nil
}

// Verify verifies an ML-DSA-87 signature.
func (SoftwareBackend) Verify(ctx sign.Context, publicKey, message, signature []byte) bool {
	pk, err := sign.NewPublicKey(publicKey)
	if err != nil {
		return false
	}
	return pk.Verify(ctx, message, signature) == nil
}

// GenerateKEMKey generates an ML-KEM-1024 key pair.
func (SoftwareBackend) GenerateKEMKey() (encapsulationKey, decapsulationKey []byte, err error) {
	dk, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM-1024 keygen: %w", err)
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
}

// Encapsulate generates a shared secret and its ciphertext.
func (SoftwareBackend) Encapsulate(encapsulationKey []byte) (ciphertext, sharedSecret []byte, err error) {
	ek, err := kem.NewEncapsulationKey(encapsulationKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-KEM-1024 encapsulation key: %w", err)
	}
	sharedSecret, ciphertext = ek.Encapsulate()
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from a ciphertext.
func (SoftwareBackend) Decapsulate(decapsulationKey, ciphertext []byte) ([]byte, error) {
	dk, err := kem.NewDecapsulationKey(decapsulationKey)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM-1024 decapsulation key: %w", err)
	}
	ss, err := dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM-1024 decapsulate: %w", err)
	}
	return ss, nil
}

// BackendName returns the backend identifier.
func (SoftwareBackend) BackendName() string {
	return "Go Cryptographic Module (software)"
}

// IsHSM returns false.
func (SoftwareBackend) IsHSM() bool {
	return false
}

// Version returns the algorithm suite.
func (SoftwareBackend) Version() string {
	return "ML-KEM-1024 (FIPS 203) + ML-DSA-87 (FIPS 204)"
}

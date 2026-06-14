// +build community

package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// CommunityBackend implements CryptoBackend using Cloudflare CIRCL
// NIST-standard post-quantum cryptography (open-source, MIT licensed)
type CommunityBackend struct{}

// newCommunityBackend creates a new Community Edition crypto backend
func newCommunityBackend() *CommunityBackend {
	return &CommunityBackend{}
}

// initBackendImpl initializes the Community Edition backend
// License validation is not required for community edition
func initBackendImpl(licensedFeatures []string) error {
	Backend = newCommunityBackend()
	return nil
}

// GenerateDilithiumKey generates a Dilithium3 (ML-DSA-65) key pair
func (c *CommunityBackend) GenerateDilithiumKey() (publicKey, privateKey []byte, err error) {
	pk, sk, err := mode3.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("dilithium3 keygen failed: %w", err)
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return pkBytes, skBytes, nil
}

// SignDilithium signs a message with Dilithium3
func (c *CommunityBackend) SignDilithium(privateKey, message []byte) (signature []byte, err error) {
	// Unmarshal private key
	sk := new(mode3.PrivateKey)
	if err := sk.UnmarshalBinary(privateKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	// Sign message
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, message, sig)
	return sig, nil
}

// VerifyDilithium verifies a Dilithium3 signature
func (c *CommunityBackend) VerifyDilithium(publicKey, message, signature []byte) bool {
	// Unmarshal public key
	pk := new(mode3.PublicKey)
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return false
	}

	// Verify signature
	return mode3.Verify(pk, message, signature)
}

// GenerateKyberKey generates a Kyber1024 (ML-KEM-1024) key pair
func (c *CommunityBackend) GenerateKyberKey() (publicKey, privateKey []byte, err error) {
	scheme := kyber1024.Scheme()
	pk, sk, genErr := scheme.GenerateKeyPair()
	if genErr != nil {
		return nil, nil, fmt.Errorf("kyber keygen failed: %w", genErr)
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal kyber public key: %w", err)
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal kyber private key: %w", err)
	}

	return pkBytes, skBytes, nil
}

// EncapsulateKyber generates a shared secret and encapsulates it
func (c *CommunityBackend) EncapsulateKyber(publicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	scheme := kyber1024.Scheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal kyber public key: %w", err)
	}

	// Encapsulate
	ct, ss, err := scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("kyber encapsulation failed: %w", err)
	}

	return ct, ss, nil
}

// DecapsulateKyber recovers the shared secret from a ciphertext
func (c *CommunityBackend) DecapsulateKyber(privateKey, ciphertext []byte) (sharedSecret []byte, err error) {
	scheme := kyber1024.Scheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal kyber private key: %w", err)
	}

	// Decapsulate
	ss, err := scheme.Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("kyber decapsulation failed: %w", err)
	}

	return ss, nil
}

// BackendName returns the backend identifier
func (c *CommunityBackend) BackendName() string {
	return "Cloudflare CIRCL"
}

// IsPremium returns false for community edition
func (c *CommunityBackend) IsPremium() bool {
	return false
}

// IsHSM returns false for community edition
func (c *CommunityBackend) IsHSM() bool {
	return false
}

// Version returns the backend version
func (c *CommunityBackend) Version() string {
	return "1.0.0 (NIST-standard PQC)"
}

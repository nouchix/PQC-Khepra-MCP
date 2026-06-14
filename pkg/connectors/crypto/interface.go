// Package crypto provides a unified interface for post-quantum cryptographic operations
// with multiple backend implementations based on build tags.
//
// Build Tags:
//   - community: Uses Cloudflare CIRCL (NIST-standard PQC, open-source)
//   - premium:   Uses proprietary pkg/adinkra algorithms ($45M R&D investment)
//   - hsm:       Adds HSM integration (YubiHSM 2 or AWS CloudHSM)
package crypto

// CryptoBackend defines the interface for post-quantum cryptographic operations.
// All editions (Community, Premium, Premium+HSM) implement this interface,
// allowing transparent backend switching based on build tags and license validation.
type CryptoBackend interface {
	// Dilithium3 (ML-DSA-65) - Post-Quantum Digital Signatures
	GenerateDilithiumKey() (publicKey, privateKey []byte, err error)
	SignDilithium(privateKey, message []byte) (signature []byte, err error)
	VerifyDilithium(publicKey, message, signature []byte) bool

	// Kyber1024 (ML-KEM-1024) - Post-Quantum Key Encapsulation
	GenerateKyberKey() (publicKey, privateKey []byte, err error)
	EncapsulateKyber(publicKey []byte) (ciphertext, sharedSecret []byte, err error)
	DecapsulateKyber(privateKey, ciphertext []byte) (sharedSecret []byte, err error)

	// Metadata
	BackendName() string  // "Cloudflare CIRCL", "AdinKhepra Premium", "YubiHSM 2"
	IsPremium() bool      // true for Premium/HSM editions
	IsHSM() bool          // true for HSM edition
	Version() string      // Backend version
}

// Global backend instance (initialized based on build tags and license validation)
var Backend CryptoBackend

// InitBackend initializes the appropriate crypto backend based on:
// 1. Build tags (community/premium/hsm)
// 2. License validation status (for premium/hsm)
// 3. HSM availability (for hsm edition)
//
// Returns error if initialization fails. On failure, falls back to community backend.
func InitBackend(licensedFeatures []string) error {
	// Implementation varies by build tag:
	// - community: Always uses CommunityBackend
	// - premium:   Uses PremiumBackend if licensed, else CommunityBackend
	// - hsm:       Uses HSMBackend if licensed + HSM available, else PremiumBackend or CommunityBackend
	return initBackendImpl(licensedFeatures)
}

// GetBackend returns the currently active crypto backend.
// Safe to call after InitBackend().
func GetBackend() CryptoBackend {
	if Backend == nil {
		// Defensive fallback - should never happen if InitBackend was called
		Backend = newCommunityBackend()
	}
	return Backend
}

// Helper functions for common operations

// GenerateKeyPair generates a Dilithium3 key pair using the active backend
func GenerateKeyPair() (publicKey, privateKey []byte, err error) {
	return GetBackend().GenerateDilithiumKey()
}

// Sign signs a message with Dilithium3 using the active backend
func Sign(privateKey, message []byte) (signature []byte, err error) {
	return GetBackend().SignDilithium(privateKey, message)
}

// Verify verifies a Dilithium3 signature using the active backend
func Verify(publicKey, message, signature []byte) bool {
	return GetBackend().VerifyDilithium(publicKey, message, signature)
}

// GenerateKEMKeyPair generates a Kyber1024 key pair using the active backend
func GenerateKEMKeyPair() (publicKey, privateKey []byte, err error) {
	return GetBackend().GenerateKyberKey()
}

// Encapsulate generates a shared secret and ciphertext using Kyber1024
func Encapsulate(publicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	return GetBackend().EncapsulateKyber(publicKey)
}

// Decapsulate recovers a shared secret from a Kyber1024 ciphertext
func Decapsulate(privateKey, ciphertext []byte) (sharedSecret []byte, err error) {
	return GetBackend().DecapsulateKyber(privateKey, ciphertext)
}

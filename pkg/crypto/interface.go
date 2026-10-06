// Package crypto provides a backend-neutral interface for the NIST
// post-quantum primitives used across AdinKhepra: ML-DSA-87 (FIPS 204)
// signatures and ML-KEM-1024 (FIPS 203) key encapsulation.
//
// Build tags:
//   - default: software backend on the Go Cryptographic Module, through
//     github.com/nouchix/khepra-pqc.
//   - hsm: hardware backend. This build has no PKCS#11 driver yet, so every
//     operation fails closed instead of falling back to software keys.
//
// Key encodings follow FIPS 203/204 seed form: ML-DSA-87 private keys are the
// 32-byte seed ξ and ML-KEM-1024 decapsulation keys are the 64-byte seed d‖z.
package crypto

import "github.com/nouchix/khepra-pqc/sign"

// CryptoBackend is implemented by each backend selected at build time.
type CryptoBackend interface {
	// ML-DSA-87 signatures. ctx is the FIPS 204 context string.
	GenerateSigningKey() (publicKey, privateKey []byte, err error)
	Sign(ctx sign.Context, privateKey, message []byte) (signature []byte, err error)
	Verify(ctx sign.Context, publicKey, message, signature []byte) bool

	// ML-KEM-1024 key encapsulation.
	GenerateKEMKey() (encapsulationKey, decapsulationKey []byte, err error)
	Encapsulate(encapsulationKey []byte) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(decapsulationKey, ciphertext []byte) (sharedSecret []byte, err error)

	// Metadata
	BackendName() string
	IsHSM() bool
	Version() string
}

// Backend is the active backend. InitBackend sets it.
var Backend CryptoBackend

// InitBackend selects the backend compiled into this binary. In hsm builds it
// returns an error when no hardware module is available, and the installed
// backend refuses every operation.
func InitBackend() error {
	return initBackendImpl()
}

// GetBackend returns the active backend, initializing it on first use.
func GetBackend() CryptoBackend {
	if Backend == nil {
		_ = InitBackend()
	}
	return Backend
}

// GenerateSigningKeyPair generates an ML-DSA-87 key pair.
func GenerateSigningKeyPair() (publicKey, privateKey []byte, err error) {
	return GetBackend().GenerateSigningKey()
}

// Sign signs message with ML-DSA-87 under the FIPS 204 context ctx.
func Sign(ctx sign.Context, privateKey, message []byte) (signature []byte, err error) {
	return GetBackend().Sign(ctx, privateKey, message)
}

// Verify reports whether signature is a valid ML-DSA-87 signature of message
// under ctx.
func Verify(ctx sign.Context, publicKey, message, signature []byte) bool {
	return GetBackend().Verify(ctx, publicKey, message, signature)
}

// GenerateKEMKeyPair generates an ML-KEM-1024 key pair.
func GenerateKEMKeyPair() (encapsulationKey, decapsulationKey []byte, err error) {
	return GetBackend().GenerateKEMKey()
}

// Encapsulate generates a shared secret and its ML-KEM-1024 ciphertext.
func Encapsulate(encapsulationKey []byte) (ciphertext, sharedSecret []byte, err error) {
	return GetBackend().Encapsulate(encapsulationKey)
}

// Decapsulate recovers the shared secret from an ML-KEM-1024 ciphertext.
func Decapsulate(decapsulationKey, ciphertext []byte) (sharedSecret []byte, err error) {
	return GetBackend().Decapsulate(decapsulationKey, ciphertext)
}

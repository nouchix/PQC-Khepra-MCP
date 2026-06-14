// Package mobile provides gomobile-compatible bindings for Phantom Network
// This package exports Adinkhepra-PQC cryptographic functions for Android/iOS
package mobile

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// =============================================================================
// PHANTOM NODE STATE (Mobile-friendly wrapper)
// =============================================================================

// PhantomState holds the node state in a mobile-compatible format
type PhantomState struct {
	publicKey  *adinkra.AdinkhepraPQCPublicKey
	privateKey *adinkra.AdinkhepraPQCPrivateKey
	merkaba    *adinkra.Merkaba
	spectral   []byte
	symbol     string
}

var currentState *PhantomState

// =============================================================================
// INITIALIZATION
// =============================================================================

// InitPhantom initializes the Phantom node with the given Adinkra symbol
// Returns the public key ID on success, or an error string
func InitPhantom(symbol string) (string, error) {
	// Get Spectral Fingerprint
	spectral := adinkra.GetSpectralFingerprint(symbol)

	// Generate entropy seed
	seed := make([]byte, 64)
	copy(seed, spectral)
	binary.BigEndian.PutUint64(seed[32:], uint64(time.Now().UnixNano()))
	h := sha256.Sum256(seed)

	// Initialize Merkaba
	merkaba := adinkra.NewMerkaba(h[:])

	// Generate PQC key pair
	publicKey, privateKey, err := adinkra.GenerateAdinkhepraPQCKeyPair(h[:], symbol)
	if err != nil {
		return "", err
	}

	// Store state
	currentState = &PhantomState{
		publicKey:  publicKey,
		privateKey: privateKey,
		merkaba:    merkaba,
		spectral:   spectral,
		symbol:     symbol,
	}

	// Return public key ID
	keyID := sha256.Sum256(publicKey.Seed[:])
	return hex.EncodeToString(keyID[:8]), nil
}

// =============================================================================
// CRYPTOGRAPHIC OPERATIONS
// =============================================================================

// SignMessage signs a message with Adinkhepra-PQC (Dilithium3)
// Returns hex-encoded signature
func SignMessage(message string) (string, error) {
	if currentState == nil {
		return "", errNotInitialized
	}

	// Hash the message
	msgHash := sha256.Sum256([]byte(message))
	fullHash := make([]byte, 64)
	copy(fullHash, msgHash[:])
	copy(fullHash[32:], msgHash[:])

	// Sign with PQC
	signature, err := adinkra.SignAdinkhepraPQC(currentState.privateKey, fullHash)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(signature), nil
}

// VerifySignature verifies a hex-encoded signature against a message
// Returns true if valid, false otherwise
func VerifySignature(message, signatureHex string) (bool, error) {
	if currentState == nil {
		return false, errNotInitialized
	}

	// Decode signature
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, err
	}

	// Hash the message
	msgHash := sha256.Sum256([]byte(message))
	fullHash := make([]byte, 64)
	copy(fullHash, msgHash[:])
	copy(fullHash[32:], msgHash[:])

	// Verify
	err = adinkra.VerifyAdinkhepraPQC(currentState.publicKey, fullHash, signature)
	return err == nil, nil
}

// SealData encrypts data using Merkaba White Box encryption
// Returns sacred rune-encoded ciphertext
func SealData(plaintext string) (string, error) {
	if currentState == nil {
		return "", errNotInitialized
	}

	sealed, err := currentState.merkaba.Seal([]byte(plaintext))
	if err != nil {
		return "", err
	}

	return sealed, nil
}

// UnsealData decrypts sacred rune-encoded ciphertext
// Returns original plaintext
func UnsealData(sacred string) (string, error) {
	if currentState == nil {
		return "", errNotInitialized
	}

	unsealed, err := currentState.merkaba.Unseal(sacred)
	if err != nil {
		return "", err
	}

	return string(unsealed), nil
}

// =============================================================================
// ADDRESS DERIVATION
// =============================================================================

// GetPhantomAddress returns the current ephemeral IPv6 address
func GetPhantomAddress() (string, error) {
	if currentState == nil {
		return "", errNotInitialized
	}

	// Time window (5 minute rotation)
	timeWindow := time.Now().Unix() / 300

	h := sha256.New()
	h.Write(currentState.spectral)
	h.Write([]byte("PHANTOM_NETWORK_ADDRESS"))

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timeWindow))
	h.Write(timeBytes)

	hash := h.Sum(nil)

	// Create IPv6 in fc00::/8 range
	ipv6 := make(net.IP, 16)
	ipv6[0] = 0xfc
	ipv6[1] = 0x00
	copy(ipv6[2:], hash[:14])

	return ipv6.String(), nil
}

// GetSpectralFingerprint returns the hex-encoded spectral fingerprint for a symbol
func GetSpectralFingerprint(symbol string) string {
	spectral := adinkra.GetSpectralFingerprint(symbol)
	return hex.EncodeToString(spectral)
}

// =============================================================================
// STATUS & INFO
// =============================================================================

// GetStatus returns JSON status of the Phantom node
func GetStatus() (string, error) {
	if currentState == nil {
		return "", errNotInitialized
	}

	address, _ := GetPhantomAddress()
	keyID := sha256.Sum256(currentState.publicKey.Seed[:])
	compliance := adinkra.MapSymbolToCompliance(currentState.symbol)

	status := map[string]interface{}{
		"symbol":     currentState.symbol,
		"address":    address,
		"key_id":     hex.EncodeToString(keyID[:8]),
		"compliance": compliance,
		"signing":    "dilithium3",
		"encryption": "merkaba-whitebox",
	}

	data, err := json.Marshal(status)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// GetComplianceMapping returns compliance frameworks for the current symbol
func GetComplianceMapping() (string, error) {
	if currentState == nil {
		return "", errNotInitialized
	}

	compliance := adinkra.MapSymbolToCompliance(currentState.symbol)
	data, err := json.Marshal(compliance)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// GetSymbol returns the current Adinkra symbol
func GetSymbol() (string, error) {
	if currentState == nil {
		return "", errNotInitialized
	}
	return currentState.symbol, nil
}

// =============================================================================
// KEY ROTATION
// =============================================================================

// RotateKeys generates new Adinkhepra-PQC keys
// Returns new public key ID
func RotateKeys() (string, error) {
	if currentState == nil {
		return "", errNotInitialized
	}

	// Securely destroy old private key
	if currentState.privateKey != nil {
		currentState.privateKey.DestroyPrivateKey()
	}

	// Generate new key pair
	seed := make([]byte, 64)
	copy(seed, currentState.spectral)
	binary.BigEndian.PutUint64(seed[32:], uint64(time.Now().UnixNano()))
	h := sha256.Sum256(seed)

	publicKey, privateKey, err := adinkra.GenerateAdinkhepraPQCKeyPair(h[:], currentState.symbol)
	if err != nil {
		return "", err
	}

	currentState.publicKey = publicKey
	currentState.privateKey = privateKey

	// Return new key ID
	keyID := sha256.Sum256(publicKey.Seed[:])
	return hex.EncodeToString(keyID[:8]), nil
}

// Destroy securely zeroizes all key material
func Destroy() {
	if currentState != nil && currentState.privateKey != nil {
		currentState.privateKey.DestroyPrivateKey()
	}
	currentState = nil
}

// =============================================================================
// ERROR TYPES
// =============================================================================

type phantomError string

func (e phantomError) Error() string { return string(e) }

const errNotInitialized = phantomError("phantom not initialized - call InitPhantom first")
